from dataclasses import dataclass, field
from typing import List, ClassVar


@dataclass
class GcpConfig:
    kind: ClassVar[str] = "gcp"
    service_account: List[str] = field(
        default_factory=list, metadata={"description": "GCP service account file(s)"}
    )
    project: List[str] = field(
        default_factory=list, metadata={"description": "GCP project(s)"}
    )
    collect: List[str] = field(
        default_factory=list,
        metadata={"description": "GCP services to collect (default: all)"},
    )
    no_collect: List[str] = field(
        default_factory=list,
        metadata={"description": "GCP services to exclude (default: none)"},
    )
    project_pool_size: int = field(
        default=5, metadata={"description": "GCP project thread/process pool size"}
    )
    fork: bool = field(
        default=True,
        metadata={"description": "Fork collector process instead of using threads"},
    )
