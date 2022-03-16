import os
from dataclasses import dataclass, field
from typing import Dict, ClassVar, Optional
from urllib.parse import urlparse
from yaml import load

try:
    from yaml import CLoader as Loader
except ImportError:
    from yaml import Loader


def _load_default_metrics():
    default_metrics = {}
    local_path = os.path.abspath(os.path.dirname(__file__))
    default_metrics_file = f"{local_path}/default_metrics.yaml"
    if not os.path.isfile(default_metrics_file):
        raise RuntimeError(
            f"Could not find default metrics file {default_metrics_file}"
        )
    with open(default_metrics_file, "r") as f:
        default_metrics = load(f, Loader=Loader)
    return default_metrics


@dataclass
class Metric:
    kind: ClassVar[str] = "metric"
    help: str = field(metadata={"description": "Metric help text"})
    search: str = field(metadata={"description": "Aggregation search to run"})
    type: str = field(metadata={"description": "Type of metric"})


@dataclass
class ResotoMetricsConfig:
    kind: ClassVar[str] = "resotometrics"
    resotocore_uri: Optional[str] = field(
        default="http://localhost:8900", metadata={"description": "Resotocore URI"}
    )
    resotocore_graph: Optional[str] = field(
        default="resoto", metadata={"description": "Resotocore graph"}
    )
    timeout: Optional[int] = field(
        default=300, metadata={"description": "Metrics generation timeout in seconds"}
    )
    metrics: Optional[Dict[str, Metric]] = field(
        default_factory=_load_default_metrics,
        metadata={"description": "Metrics config"},
    )

    @property
    def resotocore_http_uri(self) -> str:
        o = urlparse(self.resotocore_uri)
        return f"http://{o.netloc}"

    @property
    def resotocore_https_uri(self) -> str:
        o = urlparse(self.resotocore_uri)
        return f"https://{o.netloc}"

    @property
    def resotocore_ws_uri(self) -> str:
        o = urlparse(self.resotocore_uri)
        return f"ws://{o.netloc}"

    @property
    def resotocore_wss_uri(self) -> str:
        o = urlparse(self.resotocore_uri)
        return f"wss://{o.netloc}"
