from resotolib.graph import GraphMergeKind
from resotolib.config import Config
from resotolib.proc import num_default_threads
from attrs import define, field
from typing import ClassVar, Optional, List


def add_config(config: Config) -> None:
    config.add_config(ResotoWorkerConfig)


@define
class ResotoWorkerConfig:
    kind: ClassVar[str] = "resotoworker"
    collector: List[str] = field(
        factory=lambda: ["example"],
        metadata={"description": "List of collectors to run", "restart_required": True},
    )
    graph: str = field(
        default="resoto",
        metadata={"description": "Name of the graph to import data into and run searches on"},
    )
    timeout: int = field(default=10800, metadata={"description": "Collection/cleanup timeout in seconds"})
    pool_size: int = field(default=5, metadata={"description": "Collector thread/process pool size"})
    fork_process: bool = field(default=True, metadata={"description": "Use forked process instead of threads"})
    graph_merge_kind: GraphMergeKind = field(
        default=GraphMergeKind.cloud,
        metadata={"description": "Resource kind to merge graph at (cloud or account)"},
    )
    debug_dump_json: bool = field(default=False, metadata={"description": "Dump the generated JSON data to disk"})
    tempdir: Optional[str] = field(default=None, metadata={"description": "Directory to create temporary files in"})
    cleanup: bool = field(default=False, metadata={"description": "Enable cleanup of resources"})
    cleanup_pool_size: int = field(
        factory=lambda: num_default_threads() * 2,
        metadata={"description": "How many cleanup threads to run in parallel"},
    )
    cleanup_dry_run: bool = field(
        default=True,
        metadata={"description": "Do not actually cleanup resources, just create log messages"},
    )
    no_tls: bool = field(
        default=False,
        metadata={
            "description": "Disable TLS for the web server, even if Resoto Core uses TLS.",
            "restart_required": True,
        },
    )
    web_host: str = field(
        default="::",
        metadata={
            "description": "IP address to bind the web server to",
            "restart_required": True,
        },
    )
    web_port: int = field(
        default=9956,
        metadata={
            "description": "Web server tcp port to listen on",
            "restart_required": True,
        },
    )
    web_path: str = field(
        default="/",
        metadata={
            "description": "Web root in browser (change if running behind an ingress proxy)",
            "restart_required": True,
        },
    )
