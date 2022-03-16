from argparse import Namespace
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Optional, List, ClassVar

from arango.database import StandardDatabase
from resotolib.graph import dataclasses_to_resotocore_model

from resotocore.model.typed_model import from_js, to_js
from resotocore.types import Json
from resotocore.util import set_value_in_path

ResotoCoreConfigId = "resoto.core"
ResotoCoreRoot = "resotocore"


@dataclass()
class ApiConfig:
    kind: ClassVar[str] = f"{ResotoCoreRoot}_api_config"

    hosts: List[str] = field(
        default_factory=lambda: ["localhost"], metadata={"description": "TCP host(s) to bind on (default: localhost)"}
    )
    port: int = field(default=8900, metadata={"description": "TCP port to bind on (default: 8900)"})
    tsdb_proxy_url: Optional[str] = field(
        default=None,
        metadata={"description": "The url to the time series database. This path will be served under /tsdb/."},
    )
    ui_path: Optional[str] = field(
        default=None,
        metadata={"description": "The directory where the UI is installed. This directory will be served under "},
    )
    psk: Optional[str] = field(default=None, metadata={"description": "The pre-shared key to use."})


@dataclass()
class DatabaseConfig:
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


@dataclass()
class CLIConfig:
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


@dataclass()
class GraphUpdateConfig:
    kind: ClassVar[str] = f"{ResotoCoreRoot}_graph_update_config"
    merge_max_wait_time_seconds: int = field(
        default=3600, metadata={"description": "Max waiting time to complete a merge graph action."}
    )
    abort_after_seconds: int = field(
        default=4 * 3600,
        metadata={"description": "If a graph update takes longer than this duration, the update is aborted."},
    )

    def merge_max_wait_time(self) -> timedelta:
        return timedelta(seconds=self.merge_max_wait_time_seconds)

    def abort_after(self) -> timedelta:
        return timedelta(seconds=self.abort_after_seconds)


@dataclass()
class RuntimeConfig:
    kind: ClassVar[str] = f"{ResotoCoreRoot}_runtime_config"
    analytics_opt_out: bool = field(default=False, metadata={"description": "Stop collecting analytics data."})
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


@dataclass()
class CoreConfig:
    api: ApiConfig
    cli: CLIConfig
    graph_update: GraphUpdateConfig
    runtime: RuntimeConfig
    db: DatabaseConfig
    args: Namespace

    @property
    def editable(self) -> "EditableConfig":
        return EditableConfig(self.api, self.cli, self.graph_update, self.runtime)

    def json(self) -> Json:
        return {ResotoCoreRoot: to_js(self.editable, strip_attr="kind")}


@dataclass()
class EditableConfig:
    kind: ClassVar[str] = ResotoCoreRoot
    api: ApiConfig = field(
        default_factory=ApiConfig,
        metadata={"description": "API related properties."},
    )
    cli: CLIConfig = field(
        default_factory=CLIConfig,
        metadata={"description": "CLI related properties."},
    )
    graph_update: GraphUpdateConfig = field(
        default_factory=GraphUpdateConfig,
        metadata={"description": "Properties for updating the graph."},
    )
    runtime: RuntimeConfig = field(
        default_factory=RuntimeConfig,
        metadata={"description": "Runtime related properties."},
    )


def config_model() -> List[Json]:
    return dataclasses_to_resotocore_model({EditableConfig})  # type: ignore


def parse_config(args: Namespace, json_config: Json) -> CoreConfig:
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
        "api.hosts": args.host,
        "api.port": args.port,
        "api.psk": args.psk,
        "api.tsdb_proxy_url": args.tsdb_proxy_url,
        "api.ui_path": args.ui_path,
        "cli.default_graph": args.cli_default_graph,
        "cli.default_section": args.cli_default_section,
        "graph_update.abort_after_seconds": args.graph_update_abort_after.total_seconds()
        if args.graph_update_abort_after
        else None,
        "graph_update.merge_max_wait_time_seconds": args.merge_max_wait_time_seconds,
        "runtime.analytics_opt_out": args.analytics_opt_out,
        "runtime.debug": args.debug,
        "runtime.log_level": args.log_level,
        "runtime.start_collect_on_subscriber_connect": args.start_collect_on_subscriber_connect,
    }

    # take config overrides and adjust the configuration
    for key, value in args.config_override:
        set_from_cmd_line[key] = value

    adjusted = json_config.get(ResotoCoreRoot)
    for path, value in set_from_cmd_line.items():
        if value is not None:
            adjusted = set_value_in_path(value, path, adjusted)
    ed = from_js(adjusted, EditableConfig)
    return CoreConfig(api=ed.api, cli=ed.cli, db=db, graph_update=ed.graph_update, runtime=ed.runtime, args=args)


def config_from_db(args: Namespace, db: StandardDatabase, collection_name: str = "configs") -> CoreConfig:
    config_entity = db.collection("configs").get(ResotoCoreConfigId) if db.has_collection(collection_name) else None
    config = config_entity.get("config")  # ConfigEntity.config
    if config:
        return parse_config(args, config)
    else:
        return parse_config(args, {})
