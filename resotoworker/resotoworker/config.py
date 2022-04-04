from resotolib.graph import GraphMergeKind
from resotolib.config import Config
from resotolib.utils import num_default_threads
from dataclasses import dataclass, field
from typing import ClassVar, Optional, List


def add_config(config: Config) -> None:
    config.add_config(ResotoWorkerConfig)


@dataclass
class ResotoWorkerConfig:
    kind: ClassVar[str] = "resotoworker"
    collector: Optional[List[str]] = field(
        default_factory=lambda: ["example"],
        metadata={"description": "List of collectors to run"},
    )
    graph: Optional[str] = field(
        default="resoto",
        metadata={
            "description": "Name of the graph to import data into and run searches on"
        },
    )
    timeout: Optional[int] = field(
        default=10800, metadata={"description": "Collection/cleanup timeout in seconds"}
    )
    pool_size: Optional[int] = field(
        default=5, metadata={"description": "Collector thread/process pool size"}
    )
    fork: Optional[bool] = field(
        default=True, metadata={"description": "Use forked process instead of threads"}
    )
    graph_merge_kind: Optional[GraphMergeKind] = field(
        default=GraphMergeKind.cloud,
        metadata={"description": "Resource kind to merge graph at (cloud or account)"},
    )
    debug_dump_json: Optional[bool] = field(
        default=False, metadata={"description": "Dump the generated JSON data to disk"}
    )
    tempdir: Optional[str] = field(
        default=None, metadata={"description": "Directory to create temporary files in"}
    )
    cleanup: Optional[bool] = field(
        default=False, metadata={"description": "Enable cleanup of resources"}
    )
    cleanup_pool_size: Optional[int] = field(
        default_factory=lambda: num_default_threads() * 2,
        metadata={"description": "How many cleanup threads to run in parallel"},
    )
    cleanup_dry_run: Optional[bool] = field(
        default=True,
        metadata={
            "description": "Do not actually cleanup resources, just create log messages"
        },
    )
    web_host: Optional[str] = field(
        default="::",
        metadata={
            "description": "IP address to bind the web server to",
            "restart_required": True,
        },
    )
    web_port: Optional[int] = field(
        default=9956,
        metadata={
            "description": "Web server tcp port to listen on",
            "restart_required": True,
        },
    )
    web_path: Optional[str] = field(
        default="/",
        metadata={
            "description": "Web root in browser (change if running behind an ingress proxy)",
            "restart_required": True,
        },
    )
