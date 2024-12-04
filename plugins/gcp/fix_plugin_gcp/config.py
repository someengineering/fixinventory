from attrs import define, field
from typing import List, ClassVar, Optional


@define
class GcpConfig:
    kind: ClassVar[str] = "gcp"
    service_account: List[str] = field(factory=list, metadata={"description": "GCP service account file(s)"})
    project: List[str] = field(factory=list, metadata={"description": "GCP project(s)"})
    collect: List[str] = field(
        factory=list,
        metadata={"description": "GCP services to collect (default: all)"},
    )
    no_collect: List[str] = field(
        factory=list,
        metadata={"description": "GCP services to exclude (default: none)"},
    )
    project_pool_size: int = field(
        default=64,
        metadata={"description": "GCP project thread/process pool size"},
    )
    fork_process: bool = field(
        default=True,
        metadata={"description": "Fork collector process instead of using threads"},
    )
    discard_account_on_resource_error: bool = field(
        default=False,
        metadata={
            "description": "Fail the whole account if collecting a resource fails. "
            "If false, the error is logged and the resource is skipped."
        },
    )
    collect_usage_metrics: Optional[bool] = field(
        default=True,
        metadata={"description": "Collect resource usage metrics via GCP Monitoring, enabled by default"},
    )

    def should_collect(self, name: str) -> bool:
        if self.collect:
            return name in self.collect
        if self.no_collect:
            return name not in self.no_collect
        return True
