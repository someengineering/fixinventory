from dataclasses import dataclass, field
from typing import List, ClassVar


@dataclass
class GcpConfig:
    kind: ClassVar[str] = "gcp"
    service_account: List[str] = field(
        default_factory=list, metadata={"description": "GCP Service Account File(s)"}
    )
    project: List[str] = field(
        default_factory=list, metadata={"description": "GCP Project(s)"}
    )
    collect: List[str] = field(
        default_factory=list,
        metadata={"description": "GCP Services to collect (default: all)"},
    )
    no_collect: List[str] = field(
        default_factory=list,
        metadata={"description": "GCP Services to exclude (default: none)"},
    )
    project_pool_size: int = field(
        default=5, metadata={"description": "GCP Project thread/process pool size"}
    )
    fork: bool = field(
        default=False,
        metadata={"description": "Fork collector process instead of using threads"},
    )
