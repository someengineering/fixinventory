from resotolib.config import Config
from dataclasses import dataclass, field
from typing import ClassVar, Optional


def add_config(config: Config) -> None:
    config.add_config(ResotoWorkerConfig)
    config.add_config(WebServerConfig)


@dataclass
class ResotoWorkerConfig:
    kind: ClassVar[str] = "resotoworker"
    graph: Optional[str] = field(
        default="resoto", metadata={"description": "Name of the graph to use"}
    )
    timeout: Optional[int] = field(
        default=10800, metadata={"description": "Collection/cleanup Timeout in seconds"}
    )
    pool_size: Optional[int] = field(
        default=5, metadata={"description": "Collector thread/process pool size"}
    )
    fork: Optional[bool] = field(
        default=False, metadata={"description": "Use forked process instead of threads"}
    )
    graph_merge_kind: Optional[str] = field(
        default="cloud", metadata={"description": "Resource kind to merge graph at"}
    )
    debug_dump_json: Optional[bool] = field(
        default=False, metadata={"description": "Dump the generated JSON data"}
    )
    tempdir: Optional[str] = field(
        default=None, metadata={"description": "Directory to create temporary files in"}
    )
    cleanup: Optional[bool] = field(
        default=False, metadata={"description": "Enable cleanup of resources"}
    )
    cleanup_pool_size: Optional[int] = field(
        default=10, metadata={"description": "Cleanup thread pool size"}
    )
    cleanup_dry_run: Optional[bool] = field(
        default=True, metadata={"description": "Dry run cleanup"}
    )


@dataclass
class WebServerConfig:
    kind: ClassVar[str] = "webserver"
    web_host: Optional[str] = field(
        default="::", metadata={"description": "IP to bind to"}
    )
    web_port: Optional[int] = field(default=9956, metadata={"description": "Web Port"})
