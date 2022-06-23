import os
from dataclasses import dataclass, field
from typing import Dict, ClassVar, Optional

import jsons
from yaml import load
from enum import Enum


try:
    from yaml import CLoader as Loader
except ImportError:
    from yaml import Loader


class MetricType(Enum):
    gauge = "gauge"
    counter = "counter"


@dataclass
class Metric:
    kind: ClassVar[str] = "metric"
    help: str = field(metadata={"description": "Metric help text"})
    search: str = field(metadata={"description": "Aggregation search to run"})
    type: MetricType = field(default=MetricType.gauge, metadata={"description": "Type of metric (gauge or counter)"})


def _load_default_metrics() -> Dict[str, Metric]:
    local_path = os.path.abspath(os.path.dirname(__file__))
    default_metrics_file = f"{local_path}/default_metrics.yaml"
    if not os.path.isfile(default_metrics_file):
        raise RuntimeError(f"Could not find default metrics file {default_metrics_file}")
    with open(default_metrics_file, "r") as f:
        default_metrics = load(f, Loader=Loader)
    return {metric_name: jsons.load(metric_data, Metric) for metric_name, metric_data in default_metrics.items()}


@dataclass
class ResotoMetricsConfig:
    kind: ClassVar[str] = "resotometrics"
    graph: Optional[str] = field(
        default="resoto",
        metadata={"description": "Name of the graph to run aggregation searches on"},
    )
    timeout: Optional[int] = field(default=300, metadata={"description": "Metrics generation timeout in seconds"})
    metrics: Optional[Dict[str, Metric]] = field(
        default_factory=_load_default_metrics,
        metadata={
            "description": ("Metrics config\n" "See https://resoto.com/docs/reference/cli/aggregate for syntax details")
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
        default=9955,
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
