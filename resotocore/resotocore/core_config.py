import logging
import os
import re
from argparse import Namespace
from contextlib import suppress
from copy import deepcopy
from attrs import define, field
from datetime import timedelta
from pathlib import Path
from typing import Optional, List, ClassVar, Dict, Union

from arango.database import StandardDatabase
from cerberus import schema_registry
from resotolib.core.model_export import dataclasses_to_resotocore_model

from resotocore.model.model import Kind, Model, ComplexKind
from resotocore.model.typed_model import from_js, to_js
from resotocore.types import Json, JsonElement
from resotocore.util import set_value_in_path, value_in_path, del_value_in_path
from resotocore.validator import Validator, schema_name
from resotocore.ids import ConfigId


log = logging.getLogger(__name__)

# ids used in the config store
ResotoCoreConfigId = ConfigId("resoto.core")
ResotoCoreCommandsConfigId = ConfigId("resoto.core.commands")

# root note of the configuration value
ResotoCoreRoot = "resotocore"
ResotoCoreCommandsRoot = "custom_commands"

ResotoCoreRootRE = re.compile(r"^resotocore[.]")

# created by the docker build process
GitHashFile = "/usr/local/etc/git-commit.HEAD"


def git_hash_from_file() -> Optional[str]:
    """
    Returns the git hash from the file created by the docker build.
    In case we do not run inside a docker container, this method returns None.
    """
    with suppress(Exception):
        path = Path(GitHashFile)
        if path.exists():
            return path.read_text("utf-8").strip()
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
        or git_hash_from_file() is not None
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
    schema = schema_name(clazz)
    v = Validator(schema=schema, allow_unknown=True)
    result = v.validate(config, normalize=False)
    return None if result else v.errors


class ConfigObject:
    def validate(self) -> Optional[Json]:
        return validate_config(to_js(self), type(self))


@define()
class CertificateConfig(ConfigObject):
    kind: ClassVar[str] = f"{ResotoCoreRoot}_certificate_config"
    common_name: str = field(default="some.engineering", metadata={"description": "The common name of the certificate"})
    include_loopback: bool = field(default=True, metadata={"description": "Include loopback in certificate"})
    san_dns_names: List[str] = field(factory=list, metadata={"description": "List of DNS names to include in CSR"})
    san_ip_addresses: List[str] = field(
        factory=list, metadata={"description": "List of IP addresses to include in CSR"}
    )


@define()
class ApiConfig(ConfigObject):
    kind: ClassVar[str] = f"{ResotoCoreRoot}_api_config"

    web_hosts: List[str] = field(
        factory=default_hosts, metadata={"description": f"TCP host(s) to bind on (default: {default_hosts()})"}
    )
    web_port: int = field(default=8900, metadata={"description": "TCP port to bind on (default: 8900)"})
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
    ui_path: Optional[str] = field(
        default=None,
        metadata={"description": "The directory where the UI is installed. This directory will be served under "},
    )
    host_certificate: CertificateConfig = field(
        factory=CertificateConfig, metadata={"description": "The certificate configuration for this server."}
    )


# Define rules to validate this config
schema_registry.add(
    schema_name(ApiConfig),
    dict(
        tsdb_proxy_url={"type": "string", "nullable": True, "is_url": True},
        ui_path={"type": "string", "nullable": True, "path_exists": True},
    ),
)


@define()
class DatabaseConfig(ConfigObject):
    kind: ClassVar[str] = f"{ResotoCoreRoot}_database_config"
    server: str = field(
        default="http://localhost:8529",
        metadata={"description": "Graph database server (default: http://localhost:8529)"},
    )
    database: str = field(default="resoto", metadata={"description": "Graph database name (default: resoto)"})
    username: str = field(default="resoto", metadata={"description": "Graph database login (default: resoto)"})
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
    kind: ClassVar[str] = f"{ResotoCoreRoot}_cli_alias_template_parameter"
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
    kind: ClassVar[str] = f"{ResotoCoreRoot}_cli_alias_template"
    name: str = field(metadata=dict(description="The name of the alias to execute."))
    info: str = field(metadata=dict(description="A one line sentence that describes the effect of this command."))
    template: str = field(metadata=dict(description="The command to execute which can have template parameters."))
    parameters: List[AliasTemplateParameterConfig] = field(
        factory=list, metadata=dict(description="All template parameters.")
    )
    description: Optional[str] = field(metadata=dict(description="A longer description of the command."), default=None)


def alias_templates() -> List[AliasTemplateConfig]:
    return [
        AliasTemplateConfig(
            "discord",
            "Send the result of a search to Discord",
            # define the fields to show in the message
            "jq {name:{{key}}, value:{{value}}} | "
            # Discord limit: https://discord.com/developers/docs/resources/channel#embed-object-embed-limits
            "chunk 25 | "
            # define the Discord webhook JSON
            'jq {embeds: [{type: "rich", title: "{{title}}", {{#message}}description: "{{message}}",{{/message}} '
            'fields:., footer:{text: "Message created by Resoto"}}]} | '
            # call the API
            "http POST {{webhook}}",
            [
                AliasTemplateParameterConfig("key", "Resource field to show as key", ".kind"),
                AliasTemplateParameterConfig("value", "Resource field to show as value", ".name"),
                AliasTemplateParameterConfig("message", "Alert message", ""),
                AliasTemplateParameterConfig("title", "Alert title"),
                AliasTemplateParameterConfig("webhook", "Discord webhook URL"),
            ],
        ),
        AliasTemplateConfig(
            "slack",
            "Send the result of a search to Slack",
            # define the fields to show in the message
            'jq {type: "mrkdwn", text: ("*" + {{key}} + "*\n" + {{value}})} | '
            # Slack limit: https://api.slack.com/reference/block-kit/blocks#actions
            "chunk 25 | "
            # define the Slack webhook JSON
            "jq { blocks: ["
            '{ type: "header", text: { type: "plain_text", text: "{{title}}" } }, '
            '{{#message}}{ type: "section", text: { type: "mrkdwn", text: "{{message}}" } }, {{/message}}'
            '{ type: "section", fields: . }, '
            '{ type: "context", elements: [ { type: "mrkdwn", text: "Message created by Resoto" } ] } '
            "] } | "
            # call the API
            "http POST {{webhook}}",
            [
                AliasTemplateParameterConfig("key", "Resource field to show as key", ".kind"),
                AliasTemplateParameterConfig("value", "Resource field to show as value", ".name"),
                AliasTemplateParameterConfig("message", "Alert message", ""),
                AliasTemplateParameterConfig("title", "Alert title"),
                AliasTemplateParameterConfig("webhook", "Slack webhook URL"),
            ],
        ),
        AliasTemplateConfig(
            "jira",
            "Send the result of a search to Jira",
            # defines the fields to show in the message
            'jq ({{key}} + ": " + {{value}}) | head 26 | chunk 26 | '
            'jq "((.[:25] | join("\n")) + (if .[25] then "\n... (results truncated)" else "" end))" | '
            # define the Jira webhook json
            "jq {fields: { "
            'summary: "{{title}}", '
            'issuetype: {id: "10001"}, '
            'description: ("{{message}}" + "\n\n" + . + "\n\n" + "Issue created by Resoto"), '
            'project: {id: "{{project_id}}"}, '
            'reporter: {id: "{{reporter_id}}"}, '
            'labels: ["created-by-resoto"]'
            "} } | "
            # call the api
            'http --auth "{{username}}:{{token}}" POST {{url}}/rest/api/2/issue',
            [
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
        ),
    ]


@define()
class CLIConfig(ConfigObject):
    kind: ClassVar[str] = f"{ResotoCoreRoot}_cli_config"
    default_graph: str = field(
        default="resoto",
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
    kind: ClassVar[str] = ResotoCoreCommandsRoot
    commands: List[AliasTemplateConfig] = field(
        factory=alias_templates,
        metadata={"description": "Here you can define all custom commands for the CLI."},
    )

    def json(self) -> Json:
        return {ResotoCoreCommandsRoot: to_js(self, strip_attr="kind")}


# Define rules to validate this config
schema_registry.add(schema_name(CustomCommandsConfig), {})


@define()
class GraphUpdateConfig(ConfigObject):
    kind: ClassVar[str] = f"{ResotoCoreRoot}_graph_update_config"
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
    kind: ClassVar[str] = f"{ResotoCoreRoot}_runtime_config"
    debug: bool = field(default=False, metadata={"description": "Enable debug logging and exception tracing."})
    log_level: str = field(default="info", metadata={"description": "Log level (default: info)"})
    plantuml_server: str = field(
        default="http://plantuml.resoto.org:8080",
        metadata={"description": "PlantUML server URI for UML image rendering."},
    )
    start_collect_on_subscriber_connect: bool = field(
        default=False,
        metadata={"description": "Start the collect workflow, when the first handling actor connects to the system."},
    )
    usage_metrics: bool = field(
        default=True,
        metadata={
            "description": "Help us improving Resoto by collecting usage metrics.\n"
            "See https://resoto.com/docs/reference/telemetry for more information.\n"
            "This data is anonymous. No personally identifiable information is captured or stored."
        },
    )


# Define rules to validate this config
schema_registry.add(
    schema_name(RuntimeConfig),
    dict(log_level={"type": "string", "allowed": ["critical", "fatal", "error", "warn", "warning", "info", "debug"]}),
)


@define()
class WorkflowConfig(ConfigObject):
    kind: ClassVar[str] = f"{ResotoCoreRoot}_workflow_config"
    schedule: str = field(metadata={"description": "Cron expression as schedule for the workflow to run."})


schema_registry.add(
    schema_name(WorkflowConfig),
    dict(schedule={"type": "string", "is_cron": True}),
)


@define()
class RunConfig(ConfigObject):
    temp_dir: Path = Path("/tmp")  # set to random temp directory during start of process
    verify: Union[bool, str, None] = None


@define()
class CoreConfig(ConfigObject):
    api: ApiConfig
    cli: CLIConfig
    graph_update: GraphUpdateConfig
    runtime: RuntimeConfig
    db: DatabaseConfig
    workflows: Dict[str, WorkflowConfig]
    custom_commands: CustomCommandsConfig
    args: Namespace
    run: RunConfig

    @property
    def editable(self) -> "EditableConfig":
        return EditableConfig(self.api, self.cli, self.graph_update, self.runtime, self.workflows)

    def json(self) -> Json:
        return {ResotoCoreRoot: to_js(self.editable, strip_attr="kind")}

    def validate(self) -> Optional[Json]:
        return self.editable.validate()


@define()
class EditableConfig(ConfigObject):
    kind: ClassVar[str] = ResotoCoreRoot
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


def config_model() -> List[Json]:
    config_classes = {EditableConfig, CustomCommandsConfig}
    return dataclasses_to_resotocore_model(config_classes, allow_unknown_props=False)


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


def parse_config(args: Namespace, core_config: Json, command_templates: Optional[Json] = None) -> CoreConfig:
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
        set_from_cmd_line[ResotoCoreRootRE.sub("", key, 1)] = value

    # set the relevant value in the json config model
    migrated = migrate_config(core_config)
    adjusted = migrated.get(ResotoCoreRoot) or {}
    for path, value in set_from_cmd_line.items():
        if value is not None:
            adjusted = set_value_in_path(value, path, adjusted)

    # coerce the resulting json to the config model
    try:
        model = Model.from_kinds(from_js(config_model(), List[Kind]))
        root = model.get(ResotoCoreRoot)
        if isinstance(root, ComplexKind):
            adjusted = root.coerce(adjusted)
    except Exception as e:
        log.warning(f"Can not adjust configuration: {e}", exc_info=e)

    try:
        ed = from_js(adjusted, EditableConfig)
    except Exception as e:
        # only here as last resort - should never be required
        log.error("Final configuration can not be parsed! Fall back to default configuration.", exc_info=e)
        ed = EditableConfig()

    commands_config = CustomCommandsConfig()
    if command_templates:
        try:
            commands_config = from_js(command_templates.get(ResotoCoreCommandsRoot), CustomCommandsConfig)
        except Exception as e:
            log.error(f"Can not parse command templates. Fall back to defaults. Reason: {e}", exc_info=e)

    return CoreConfig(
        api=ed.api,
        args=args,
        cli=ed.cli,
        custom_commands=commands_config,
        db=db,
        graph_update=ed.graph_update,
        runtime=ed.runtime,
        workflows=ed.workflows,
        run=RunConfig(),  # overridden for each run
    )


def migrate_config(config: Json) -> Json:
    """
    :param config: The core configuration
    :return: the migrated json.
    """
    cfg = config.get(ResotoCoreRoot) or {}
    adapted = deepcopy(cfg)

    # 2.2 -> 2.3: rename and toggle `analytics_opt_out` -> `usage_metrics`
    opt_out = value_in_path(cfg, "runtime.analytics_opt_out")
    usage = value_in_path(cfg, "runtime.usage_metrics")
    if opt_out is not None and usage is None:
        set_value_in_path(not opt_out, "runtime.usage_metrics", adapted)
    del_value_in_path(adapted, "runtime.analytics_opt_out")
    return {ResotoCoreRoot: adapted}


def config_from_db(args: Namespace, db: StandardDatabase, collection_name: str = "configs") -> CoreConfig:
    configs = db.collection(collection_name) if db.has_collection(collection_name) else None
    config_entity = configs.get(ResotoCoreConfigId) if configs else None
    config = config_entity.get("config") if config_entity else None  # ConfigEntity.config
    if config:
        command_config = configs.get(ResotoCoreCommandsConfigId)
        command_config = command_config.get("config") if command_config else None
        return parse_config(args, config, command_config)
    else:
        return parse_config(args, {})
