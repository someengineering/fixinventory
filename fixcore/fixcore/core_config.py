import logging
import os
import re
import subprocess
from argparse import Namespace
from contextlib import suppress
from copy import deepcopy
from datetime import timedelta
from functools import lru_cache
from pathlib import Path
from typing import Optional, List, ClassVar, Dict, Union, cast, Callable

from arango.database import StandardDatabase
from attrs import define, field
from cerberus import schema_registry

from fixcore.ids import ConfigId
from fixcore.model.model import Kind, Model, ComplexKind
from fixcore.model.typed_model import from_js, to_js
from fixcore.types import Json, JsonElement
from fixcore.util import set_value_in_path, value_in_path, del_value_in_path
from fixcore.validator import Validator, schema_name
from fixlib.core.model_export import dataclasses_to_fixcore_model
from fixlib.utils import replace_env_vars, is_env_var_string, merge_json_elements

log = logging.getLogger(__name__)

# ids used in the config store
FixCoreConfigId = ConfigId("fix.core")
FixCoreCommandsConfigId = ConfigId("fix.core.commands")
FixCoreSnapshotsConfigId = ConfigId("fix.core.snapshots")

# root note of the configuration value
FixCoreRoot = "fixcore"
FixCoreCommandsRoot = "custom_commands"
FixCoreSnapshotsRoot = "snapshots"

FixCoreRootRE = re.compile(r"^fixcore[.]")

# created by the docker build process
GitHashFile = "/usr/local/etc/git-commit.HEAD"


@lru_cache(maxsize=1)
def current_git_hash() -> Optional[str]:
    """
    Returns the git hash either from the file created by the docker build,
    or it tries to get it from git directly.
    If both fails, it returns None.
    """
    with suppress(Exception):
        path = Path(GitHashFile)
        if path.exists():
            return path.read_text("utf-8").strip()
        return subprocess.check_output(["git", "rev-parse", "HEAD"]).strip().decode("utf-8")
    return None


def inside_docker() -> bool:
    """
    Try to detect if we are running inside a docker container.
    """
    return (
        # environment variables have to be set explicitly
        os.environ.get("INSIDE_DOCKER", "false").lower() in ("true", "yes", "1")
        or os.environ.get("INSIDE_KUBERNETES", "false").lower() in ("true", "yes", "1")
        # this file is available in the created docker container
        or Path(GitHashFile).exists()
    )


def inside_kubernetes() -> bool:
    """
    Try to detect if we are running on kubernetes.
    """
    # environment variables have to be set explicitly
    return "HELM_VERSION" in os.environ or any(True for x in os.environ if x.startswith("KUBERNETES_"))


def helm_installation() -> bool:
    """
    Try to detect if we were installed via helm chart.
    """
    # environment variables have to be set explicitly
    return "HELM_VERSION" in os.environ


def default_hosts() -> List[str]:
    return ["0.0.0.0"] if inside_docker() else ["localhost"]


def validate_config(config: Json, clazz: type) -> Optional[Json]:
    def strip_env_vars_paths(config: JsonElement) -> JsonElement:
        """
        Recursively strips all values that contain an env var string
        """
        if isinstance(config, dict):
            return {k: strip_env_vars_paths(v) for k, v in config.items() if not is_env_var_string(v)}
        elif isinstance(config, list):
            return [strip_env_vars_paths(v) for v in config if not is_env_var_string(v)]
        else:
            return config

    schema = schema_name(clazz)
    v = Validator(schema=schema, allow_unknown=True)
    # cerberus is too inflexible to allow us to validate the config without resolving the env vars
    # so we have to strip strings with the env vars before validating
    without_env_vars = strip_env_vars_paths(config)
    result = v.validate(without_env_vars, normalize=False)
    return None if result else v.errors


class ConfigObject:
    def validate(self) -> Optional[Json]:
        return validate_config(to_js(self), type(self))


@define()
class CertificateConfig(ConfigObject):
    kind: ClassVar[str] = f"{FixCoreRoot}_certificate_config"
    common_name: str = field(default="some.engineering", metadata={"description": "The common name of the certificate"})
    include_loopback: bool = field(default=True, metadata={"description": "Include loopback in certificate"})
    san_dns_names: List[str] = field(factory=list, metadata={"description": "List of DNS names to include in CSR"})
    san_ip_addresses: List[str] = field(
        factory=list, metadata={"description": "List of IP addresses to include in CSR"}
    )


@define()
class ApiConfig(ConfigObject):
    kind: ClassVar[str] = f"{FixCoreRoot}_api_config"

    web_hosts: List[str] = field(
        factory=default_hosts, metadata={"description": f"TCP host(s) to bind on (default: {default_hosts()})"}
    )
    https_port: Optional[int] = field(
        default=8900, metadata={"description": "TCP port to bind on for TLS encrypted connections (default: 8900)"}
    )
    http_port: Optional[int] = field(
        default=8980, metadata={"description": "TCP port to bind on for plain HTTP connections (default: 8980)"}
    )
    web_path: str = field(
        default="/",
        metadata={
            "description": "Web path root (default: /).\n"
            "This should only be required, if you are running a proxy server, that is not able to handle a sub-path."
        },
    )
    tsdb_proxy_url: Optional[str] = field(
        default=None,
        metadata={"description": "The url to the time series database. This path will be served under /tsdb/."},
    )
    max_request_size: Optional[int] = field(
        default=1024**2 * 5, metadata={"description": "The maximum size of a request in bytes (default: 5MB)"}
    )
    host_certificate: CertificateConfig = field(
        factory=CertificateConfig, metadata={"description": "The certificate configuration for this server."}
    )
    access_token_expiration_seconds: int = field(
        default=3600, metadata={"description": "The expiration time of the access token in seconds (default: 1h)"}
    )

    def access_token_expiration(self) -> timedelta:
        return timedelta(seconds=self.access_token_expiration_seconds)


# Define rules to validate this config
schema_registry.add(
    schema_name(ApiConfig),
    dict(
        http_port={"type": "integer", "min": 1, "max": 65535, "nullable": True},
        https_port={"type": "integer", "min": 1, "max": 65535, "nullable": True},
        tsdb_proxy_url={"type": "string", "nullable": True, "is_url": True},
        max_request_size={"type": "integer", "nullable": True, "min": 1024**2},
    ),
)


@define()
class TimeSeriesBucketConfig(ConfigObject):
    kind: ClassVar[str] = f"{FixCoreRoot}_timeseries_bucket_config"
    start: int = field(metadata={"description": "Start of the bucket in seconds."})
    resolution: int = field(metadata={"description": "Resolution of the bucket in seconds."})


@define()
class DatabaseConfig(ConfigObject):
    kind: ClassVar[str] = f"{FixCoreRoot}_database_config"
    server: str = field(
        default="http://localhost:8529",
        metadata={"description": "Graph database server (default: http://localhost:8529)"},
    )
    database: str = field(default="fix", metadata={"description": "Graph database name (default: fix)"})
    username: str = field(default="fix", metadata={"description": "Graph database login (default: fix)"})
    password: str = field(default="", metadata={"description": 'Graph database password (default: "")'})
    root_password: str = field(
        default="",
        metadata={"description": "Graph root database password used for creating user and database if not existent."},
    )
    bootstrap_do_not_secure: bool = field(
        default=False, metadata={"description": "Leave an empty root password during system setup process."}
    )
    no_ssl_verify: bool = field(
        default=False, metadata={"description": "If the connection should not be verified (default: False)"}
    )
    request_timeout: int = field(default=900, metadata={"description": "Request timeout in seconds (default: 900)"})


@define(order=True, hash=True, frozen=True)
class AliasTemplateParameterConfig(ConfigObject):
    kind: ClassVar[str] = f"{FixCoreRoot}_cli_alias_template_parameter"
    name: str = field(metadata=dict(description="The name of the parameter."))
    description: str = field(metadata=dict(description="The intent of this parameter."))
    default: Optional[JsonElement] = field(
        default=None,
        metadata=dict(
            description="The optional default value.\n"
            "In case a default value exists, it does not need to be provided by the user."
        ),
    )


@define(order=True, hash=True, frozen=True)
class AliasTemplateConfig(ConfigObject):
    kind: ClassVar[str] = f"{FixCoreRoot}_cli_alias_template"
    name: str = field(metadata=dict(description="The name of the alias to execute."))
    info: str = field(metadata=dict(description="A one line sentence that describes the effect of this command."))
    template: str = field(metadata=dict(description="The command to execute which can have template parameters."))
    parameters: List[AliasTemplateParameterConfig] = field(
        factory=list, metadata=dict(description="All template parameters.")
    )
    description: Optional[str] = field(metadata=dict(description="A longer description of the command."), default=None)
    allowed_in_source_position: Optional[bool] = field(
        metadata=dict(
            description="true if this alias can be executed directly, false if it expects input from another command."
        ),
        default=False,
    )


def alias_templates() -> List[AliasTemplateConfig]:
    return [
        AliasTemplateConfig(
            name="jira",
            info="Send the result of a search to Jira",
            description=(
                "Perform a search and send the result to Jira.\n\n"
                "If your search result is larger than 25 items, only the first 25 items will be added to the ticket, "
                "and the remaining items will be dropped.\n\n"
                "Note that invoking this command will always create a new ticket since JIRA does not have any "
                "deduplication functionality.\n\n"
                "We recommend to define the URL, username and token as part of the command configuration. "
                "This way you do not need to provide it every time you execute the command."
            ),
            template=(
                # defines the fields to show in the message
                'head 26 | jq ({{key}} + ": " + {{value}}) | chunk 26 | '
                'jq \'((.[:25] | join("\\n")) + (if .[25] then "\\n... (results truncated)" else "" end))\' | '
                # define the Jira webhook json
                "jq {fields: { "
                'summary: "{{title}}", '
                'issuetype: {id: "10001"}, '
                'description: ("{{message}}" + "\\n\\n" + . + "\\n\\n" + "Issue created by Fix"), '
                'project: {id: "{{project_id}}"}, '
                'reporter: {id: "{{reporter_id}}"}, '
                'labels: ["created-by-fix"]'
                "}}"
                # call the api
                '| http --auth "{{username}}:{{token}}" POST {{url}}/rest/api/2/issue'
            ),
            parameters=[
                AliasTemplateParameterConfig("key", "Resource field to show as key", ".kind"),
                AliasTemplateParameterConfig("value", "Resource field to show as value", ".name"),
                AliasTemplateParameterConfig("message", "Alert message", ""),
                AliasTemplateParameterConfig("title", "Alert title"),
                AliasTemplateParameterConfig("url", "Jira URL"),
                AliasTemplateParameterConfig("username", "Jira username"),
                AliasTemplateParameterConfig("token", "Jira API token"),
                AliasTemplateParameterConfig("project_id", "Jira project ID"),
                AliasTemplateParameterConfig("reporter_id", "Jira reporter user ID"),
            ],
            allowed_in_source_position=False,
        ),
        AliasTemplateConfig(
            name="alertmanager",
            info="Create an alert in alertmanager from a search.",
            description=(
                "Perform a search and send the result to alertmanager.\n\n"
                "No resource specific data will be sent to alertmanager - only the count of matching resources. "
                "The alert will be created in alertmanager and will be active for the specified duration.\n\n"
                "The name of the alert is visible in alertmanager and used as deduplication key. "
                "This way the same alert can be fired multiple times.\n\n"
                "We recommend to define the URL as part of the command configuration. "
                "This way you do not need to provide it every time you execute the command."
            ),
            template=(
                "aggregate sum(1) as count | "
                # do not send an alert in case of 0 violations
                'jq --no-rewrite "if (.count // 0)==0 then [] else [.count | tostring] end" | flatten | '
                # defines the fields to show in the message
                "jq --no-rewrite [{"
                'status: "firing", '
                'labels: {alertname: "{{name}}", issued_by: "Fix"}, '
                'annotations: {summary: ("Found "+.+ " violations!"), '
                '"description": "{{description}}"}{{#duration}}, '
                'startAt:"@utc@", '
                'endsAt:"{{duration.from_now}}"{{/duration}}}] | '
                # call the api
                "http POST {{alertmanager_url}}/api/v1/alerts"
            ),
            parameters=[
                AliasTemplateParameterConfig("name", "The globally unique name of this alert."),
                AliasTemplateParameterConfig("description", "User defined message of the post.", "Fix Alert"),
                AliasTemplateParameterConfig("duration", "The duration of this alert in alertmanager.", "3h"),
                AliasTemplateParameterConfig("alertmanager_url", "The complete url to alertmanager."),
            ],
            allowed_in_source_position=False,
        ),
        AliasTemplateConfig(
            name="pagerduty",
            info="Create an alert in pagerduty from a search.",
            description=(
                "Perform a search and send the result to pagerduty.\n\n"
                "A call to this command will only send the first 100 occurrences to the incident, the rest is dropped. "
                "The `summary` should explain why this alert is triggered, so that the user can take action.\n"
                "The `dedup_key` is used to identify an alert uniquely. "
                "You can fire the same alert multiple times by using the same dedup_key.\n\n"
                "We recommend to define the `routing_key` as part of the command configuration. "
                "This way you do not need to provide it every time you execute the command."
            ),
            template=(
                # aggregate the result by cloud -> account -> region -> resource
                # resulting structure looks like this:
                # {"aws": {"account1": {"region1": {"id1": {"id": "xxx", "name": "yyy", "kind": "zzz" }}}}}
                # note: Pagerduty is able to render JSON objects in their webUI, but not arrays.
                "head 100 | chunk 100 | jq --no-rewrite '"
                "{{#group_resources}}"
                '[group_by(.ancestors.cloud.reported.name) | .[] | {(.[0].ancestors.cloud.reported.name // "no-cloud"): '  # noqa: E501
                '[group_by(.ancestors.account.reported.name) | .[] | {(.[0].ancestors.account.reported.name // "no-account"): '  # noqa: E501
                '[group_by(.ancestors.region.reported.name) | .[] | {(.[0].ancestors.region.reported.name // "no-region"): '  # noqa: E501
                "{{/group_resources}}"
                "[.[] | {({{resource_id}}): { {{#resource_properties.as_list.with_index}}{{key}}: {{value}}{{^last}},{{/last}}{{/resource_properties.as_list.with_index}} }}] | add "  # noqa: E501
                "{{#group_resources}}}] | add }] | add }] | add {{/group_resources}}'"
                "| jq --no-rewrite '{payload: "
                '{summary: "{{summary}}", '
                'timestamp: "@utc@", '
                'source:"{{source}}", '
                'severity: "{{severity}}", '
                'component: "{{component}}", '
                "custom_details: .}, "
                'routing_key: "{{routing_key}}", '
                'dedup_key: "{{dedup_key}}", '
                'images:[{src: "https://cdn.some.engineering/assets/fix-illustrations/small/fix-alert.png", href:'
                ' "https://inventory.fix.security/", alt: "Fix Home Page"}], '
                "links:[], "
                'event_action: "{{event_action}}", '
                'client: "Fix Service", '
                'client_url: "https://inventory.fix.security"}\''
                # send the event to pagerduty
                ' | http {{webhook_url}} "Content-Type:application/json"'
            ),
            parameters=[
                AliasTemplateParameterConfig("summary", "The summary of this alert."),
                AliasTemplateParameterConfig(
                    "severity",
                    "The perceived severity of the status the event is describing withrespect to the affected system. "
                    "One of: `critical`, `error`, `warning` or `info`.",
                    "warning",
                ),
                AliasTemplateParameterConfig(
                    "source", "The unique location of the affected system, preferably a hostname or FQDN.", "Fix"
                ),
                AliasTemplateParameterConfig(
                    "component", "Component of the source machine that is responsible for the event.", "Fix"
                ),
                AliasTemplateParameterConfig(
                    "routing_key",
                    "The GUID of one of your Events API V2 integrations. "
                    'This is the "Integration Key" listed on the Events API V2 integration\'s detail page.',
                ),
                AliasTemplateParameterConfig(
                    "event_action", "The type of event. Can be `trigger`, `acknowledge` or `resolve`.", "trigger"
                ),
                AliasTemplateParameterConfig("dedup_key", "Identifies the alert to trigger."),
                AliasTemplateParameterConfig(
                    "client", "The name of the monitoring client that is triggering this event.", "Fix"
                ),
                AliasTemplateParameterConfig(
                    "client_url",
                    "The URL of the monitoring client that is triggering this event.",
                    "https://inventory.fix.security",
                ),
                AliasTemplateParameterConfig(
                    "webhook_url",
                    "The complete url of the pagerduty events API.",
                    "https://events.pagerduty.com/v2/enqueue",
                ),
                AliasTemplateParameterConfig(
                    "group_resources",
                    "Group Resource by cloud, account, and region.",
                    True,
                ),
                AliasTemplateParameterConfig(
                    "resource_id",
                    "Property to show as resource identifier.",
                    ".id",
                ),
                AliasTemplateParameterConfig(
                    "resource_properties",
                    "Dictionary of properties to show.",
                    dict(id=".reported.id", name=".reported.name", kind=".reported.kind"),
                ),
            ],
            allowed_in_source_position=False,
        ),
    ]


@define()
class CLIConfig(ConfigObject):
    kind: ClassVar[str] = f"{FixCoreRoot}_cli_config"
    default_graph: str = field(
        default="fix",
        metadata={"description": "Use this graph for CLI actions, if no graph is specified explicitly."},
    )
    default_section: str = field(
        default="reported",
        metadata={
            "description": "Use this graph section by default, if no section is specified.\n"
            "Relative paths will be interpreted with respect to this section."
        },
    )


# Define rules to validate this config
schema_registry.add(schema_name(CLIConfig), {})


@define()
class CustomCommandsConfig(ConfigObject):
    kind: ClassVar[str] = FixCoreCommandsRoot
    commands: List[AliasTemplateConfig] = field(
        factory=alias_templates,
        metadata={"description": "Here you can define all custom commands for the CLI."},
    )

    def json(self) -> Json:
        return {FixCoreCommandsRoot: to_js(self, strip_attr="kind")}


# Define rules to validate this config
schema_registry.add(schema_name(CustomCommandsConfig), {})


SnapshotLabel = str


@define
class SnapshotSchedule(ConfigObject):
    kind: ClassVar[str] = f"{FixCoreSnapshotsRoot}_schedule"
    schedule: str = field(
        metadata={
            "description": "The schedule in cron format.\n"
            "Example: `0 0 * * *` will create a snapshot every day at midnight.\n"
            "See https://en.wikipedia.org/wiki/Cron for more information.",
        }
    )
    retain: int = field(
        metadata={
            "description": "How many snapshots should be retained.\n"
            "If the number of snapshots exceeds this value, the oldest snapshots will be deleted.\n"
        }
    )


@define()
class SnapshotsScheduleConfig(ConfigObject):
    kind: ClassVar[str] = FixCoreSnapshotsRoot
    snapshots: Dict[SnapshotLabel, SnapshotSchedule] = field(
        default={
            "hourly": SnapshotSchedule(schedule="0 * * * *", retain=24),
            "daily": SnapshotSchedule(schedule="0 0 * * *", retain=7),
            "weekly": SnapshotSchedule(schedule="0 0 * * 0", retain=4),
            "monthly": SnapshotSchedule(schedule="0 0 1 * *", retain=12),
            "yearly": SnapshotSchedule(schedule="0 0 1 1 *", retain=10),
        },
        metadata={
            "description": "Here you can define all snapshot schedules.\n"
            "The key is the label of the snapshot schedule.\n"
            "The value is the schedule configuration.",
        },
    )

    def json(self) -> Json:
        return to_js(self, strip_attr="kind")


@define()
class GraphUpdateConfig(ConfigObject):
    kind: ClassVar[str] = f"{FixCoreRoot}_graph_update_config"
    merge_max_wait_time_seconds: int = field(
        default=3600, metadata={"description": "Max waiting time to complete a merge graph action."}
    )
    abort_after_seconds: int = field(
        default=4 * 3600,
        metadata={"description": "If a graph update takes longer than this duration, the update is aborted."},
    )
    keep_history: bool = field(
        default=True,
        metadata={"description": "If true, changes of the graph are stored and are available via history."},
    )
    keep_history_for_days: int = field(
        default=180,
        metadata={"description": "Duration to keep history entries in days. (default: 180)"},
    )
    parallel_imports: int = field(
        default=5,
        metadata={"description": "Number of parallel graph merge requests handled in parallel."},
    )

    def merge_max_wait_time(self) -> timedelta:
        return timedelta(seconds=self.merge_max_wait_time_seconds)

    def abort_after(self) -> timedelta:
        return timedelta(seconds=self.abort_after_seconds)


# Define rules to validate this config
schema_registry.add(
    schema_name(GraphUpdateConfig),
    dict(
        merge_max_wait_time_seconds={"type": "integer", "min": 60},
        abort_after_seconds={"type": "integer", "min": 60},
    ),
)


@define()
class RuntimeConfig(ConfigObject):
    kind: ClassVar[str] = f"{FixCoreRoot}_runtime_config"
    debug: bool = field(default=False, metadata={"description": "Enable debug logging and exception tracing."})
    log_level: str = field(default="info", metadata={"description": "Log level (default: info)"})
    plantuml_server: str = field(
        default="https://plantuml.fix.org",
        metadata={"description": "PlantUML server URI for UML image rendering."},
    )
    start_collect_on_subscriber_connect: bool = field(
        default=False,
        metadata={"description": "Start the collect workflow, when the first handling actor connects to the system."},
    )
    usage_metrics: bool = field(
        default=True,
        metadata={
            "description": "Usage metrics provide information like errors and bugs, "
            "which we rely on to improve Fix with every release.\n"
            "All metrics are anonymous. "
            "See https://inventory.fix.security/docs/edge/reference/telemetry for more information.\n"
            "Please help us by leaving this setting turned on."
        },
    )


# Define rules to validate this config
schema_registry.add(
    schema_name(RuntimeConfig),
    dict(log_level={"type": "string", "allowed": ["critical", "fatal", "error", "warn", "warning", "info", "debug"]}),
)


@define()
class WorkflowConfig(ConfigObject):
    kind: ClassVar[str] = f"{FixCoreRoot}_workflow_config"
    schedule: str = field(metadata={"description": "Cron expression as schedule for the workflow to run."})


schema_registry.add(
    schema_name(WorkflowConfig),
    dict(schedule={"type": "string", "is_cron": True}),
)


@define()
class RunConfig(ConfigObject):
    temp_dir: Path = Path("/tmp")  # set to random temp directory during start of process
    verify: Union[bool, str, None] = None


@define
class TimeSeriesConfig(ConfigObject):
    kind: ClassVar[str] = f"{FixCoreRoot}_timeseries_config"

    buckets: List[TimeSeriesBucketConfig] = field(
        factory=lambda: [
            TimeSeriesBucketConfig(
                start=int(timedelta(days=2).total_seconds()), resolution=int(timedelta(hours=4).total_seconds())
            ),
            TimeSeriesBucketConfig(
                start=int(timedelta(days=30).total_seconds()), resolution=int(timedelta(days=1).total_seconds())
            ),
            TimeSeriesBucketConfig(
                start=int(timedelta(days=180).total_seconds()), resolution=int(timedelta(days=3).total_seconds())
            ),
        ],
        metadata={"description": "List of time series buckets."},
    )


@define()
class CoreConfig(ConfigObject):
    api: ApiConfig
    cli: CLIConfig
    graph_update: GraphUpdateConfig
    runtime: RuntimeConfig
    db: DatabaseConfig
    workflows: Dict[str, WorkflowConfig]
    custom_commands: CustomCommandsConfig
    snapshots: SnapshotsScheduleConfig
    args: Namespace
    run: RunConfig
    timeseries: TimeSeriesConfig

    @property
    def multi_tenant_setup(self) -> bool:
        return cast(bool, self.args.multi_tenant_setup)

    @property
    def no_scheduling(self) -> bool:
        return cast(bool, self.args.no_scheduling)

    @property
    def editable(self) -> "EditableConfig":
        return EditableConfig(self.api, self.cli, self.graph_update, self.runtime, self.workflows, self.timeseries)

    def json(self) -> Json:
        return {FixCoreRoot: to_js(self.editable, strip_attr="kind")}

    def validate(self) -> Optional[Json]:
        return self.editable.validate()


@define()
class EditableConfig(ConfigObject):
    kind: ClassVar[str] = FixCoreRoot
    api: ApiConfig = field(
        factory=ApiConfig,
        metadata={"description": "API related properties."},
    )
    cli: CLIConfig = field(
        factory=CLIConfig,
        metadata={"description": "CLI related properties."},
    )
    graph_update: GraphUpdateConfig = field(
        factory=GraphUpdateConfig,
        metadata={"description": "Properties for updating the graph."},
    )
    runtime: RuntimeConfig = field(
        factory=RuntimeConfig,
        metadata={"description": "Runtime related properties."},
    )
    workflows: Dict[str, WorkflowConfig] = field(
        factory=lambda: {"collect_and_cleanup": WorkflowConfig(schedule="0 * * * *")},
        metadata={"description": "Workflow related properties."},
    )
    timeseries: TimeSeriesConfig = field(
        factory=TimeSeriesConfig,
        metadata={"description": "Time series related properties."},
    )


def config_model() -> List[Json]:
    config_classes = {EditableConfig, CustomCommandsConfig}
    return dataclasses_to_fixcore_model(config_classes, use_optional_as_required=True)


# Define rules to validate this config
# Note: since validation rules do not cover all attributes, we allow unknown properties explicitly.
schema_registry.add(
    schema_name(EditableConfig),
    dict(
        api={"schema": schema_name(ApiConfig), "allow_unknown": True},
        cli={"schema": schema_name(CLIConfig), "allow_unknown": True},
        graph_update={"schema": schema_name(GraphUpdateConfig), "allow_unknown": True},
        runtime={"schema": schema_name(RuntimeConfig), "allow_unknown": True},
        workflows={
            "type": "dict",
            "keysrules": {"type": "string"},
            "valuesrules": {"schema": schema_name(WorkflowConfig)},
        },
    ),
)


def parse_config(
    args: Namespace,
    core_config: Json,
    get_core_overrides: Callable[[], Optional[Json]],
    command_templates: Optional[Json] = None,
    snapshot_schedule: Optional[Json] = None,
) -> CoreConfig:
    db = DatabaseConfig(
        server=args.graphdb_server,
        database=args.graphdb_database,
        username=args.graphdb_username,
        password=args.graphdb_password,
        root_password=args.graphdb_root_password,
        bootstrap_do_not_secure=args.graphdb_bootstrap_do_not_secure,
        no_ssl_verify=args.graphdb_no_ssl_verify,
        request_timeout=args.graphdb_request_timeout,
    )
    # take command line options and translate it to the config model
    set_from_cmd_line = {
        "api.ui_path": args.ui_path,
        "runtime.debug": args.debug,
        "runtime.usage_metrics": not args.analytics_opt_out if args.analytics_opt_out is not None else None,
    }

    # take config overrides and adjust the configuration
    for key, value in args.config_override:
        set_from_cmd_line[FixCoreRootRE.sub("", key, 1)] = value

    # set the relevant value in the json config model
    migrated = migrate_core_config(core_config)
    adjusted = migrated.get(FixCoreRoot) or {}
    for path, value in set_from_cmd_line.items():
        if value is not None:
            adjusted = set_value_in_path(value, path, adjusted)

    # here we only care about the fixcore overrides
    core_config_overrides = (get_core_overrides() or {}).get(FixCoreRoot)
    # merge the file overrides into the adjusted config
    if core_config_overrides:
        adjusted = merge_json_elements(adjusted, core_config_overrides)

    # replacing the env vars and removing them in case they are not resolved
    adjusted = replace_env_vars(adjusted, os.environ, keep_unresolved=False)

    # coerce the resulting json to the config model
    try:
        model = Model.from_kinds(from_js(config_model(), List[Kind]))
        root = model.get(FixCoreRoot)
        if isinstance(root, ComplexKind):
            adjusted = root.coerce(adjusted)
    except Exception as e:
        log.warning(f"Can not adjust configuration: {e}", exc_info=e)

    try:
        # replace all env vars
        ed = from_js(adjusted, EditableConfig)
    except Exception as e:
        # only here as last resort - should never be required
        log.error("Final configuration can not be parsed! Fall back to default configuration.", exc_info=e)
        ed = EditableConfig()

    commands_config = CustomCommandsConfig()
    if command_templates:
        try:
            migrated_commands = migrate_command_config(command_templates)
            cmd_cfg_to_parse = migrated_commands or command_templates
            commands_config = from_js(cmd_cfg_to_parse.get(FixCoreCommandsRoot), CustomCommandsConfig)
        except Exception as e:
            log.error(f"Can not parse command templates. Fall back to defaults. Reason: {e}", exc_info=e)

    snapshots_config = SnapshotsScheduleConfig()
    if snapshot_schedule:
        try:
            snapshots_config = from_js(snapshot_schedule.get(FixCoreSnapshotsRoot), SnapshotsScheduleConfig)
        except Exception as e:
            log.error(f"Can not parse snapshot schedule. Fall back to defaults. Reason: {e}", exc_info=e)

    return CoreConfig(
        api=ed.api,
        args=args,
        cli=ed.cli,
        custom_commands=commands_config,
        snapshots=snapshots_config,
        db=db,
        graph_update=ed.graph_update,
        runtime=ed.runtime,
        workflows=ed.workflows,
        run=RunConfig(),  # overridden for each run
        timeseries=ed.timeseries,
    )


def migrate_core_config(config: Json) -> Json:
    """
    :param config: The core configuration
    :return: the migrated json.
    """
    cfg = config.get(FixCoreRoot) or {}
    adapted = deepcopy(cfg)

    # 2.2 -> 2.3: rename and toggle `analytics_opt_out` -> `usage_metrics`
    opt_out = value_in_path(cfg, "runtime.analytics_opt_out")
    usage = value_in_path(cfg, "runtime.usage_metrics")
    if opt_out is not None and usage is None:
        set_value_in_path(not opt_out, "runtime.usage_metrics", adapted)
    del_value_in_path(adapted, "runtime.analytics_opt_out")

    # 3.0 -> 3.1: delete `api.ui_path`
    del_value_in_path(adapted, "api.ui_path")

    # 3.5 -> 3.6: web_port -> https_port
    if web_port := value_in_path(cfg, "api.web_port"):
        set_value_in_path(web_port, "api.https_port", adapted)
        del_value_in_path(adapted, "api.web_port")

    if value_in_path(cfg, "runtime.plantuml_server") == "http://plantuml.fix.org:8080":
        set_value_in_path("https://plantuml.fix.org", "runtime.plantuml_server", adapted)

    return {FixCoreRoot: adapted}


def migrate_command_config(cmd_config: Json) -> Optional[Json]:
    config = from_js(cmd_config.get(FixCoreCommandsRoot), CustomCommandsConfig)
    existing_commands = {tpl.name: tpl for tpl in config.commands}
    adjusted = False
    for command in alias_templates():
        if command.name not in existing_commands:
            config.commands.append(command)
            adjusted = True
    return config.json() if adjusted else None


def config_from_db(
    args: Namespace,
    db: StandardDatabase,
    get_core_overrides: Callable[[], Optional[Json]],
    collection_name: str = "configs",
) -> CoreConfig:
    if configs := db.collection(collection_name) if db.has_collection(collection_name) else None:
        if config_entity := cast(Optional[Json], configs.get(FixCoreConfigId)):
            if config := config_entity.get("config"):
                command_config_entity = cast(Optional[Json], configs.get(FixCoreCommandsConfigId))
                command_config = command_config_entity.get("config") if command_config_entity else None

                snapshots_config_entity = cast(Optional[Json], configs.get(FixCoreSnapshotsConfigId))
                snapshots_config = snapshots_config_entity.get("config") if snapshots_config_entity else None

                return parse_config(args, config, get_core_overrides, command_config, snapshots_config)
    return parse_config(args, {}, get_core_overrides)
