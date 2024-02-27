from fixlib.args import ArgumentParser
from fixlib.core import fixcore, add_args
from fixmetrics.config import _load_default_metrics, MetricType


def test_args():
    arg_parser = ArgumentParser(description="fix metrics exporter", env_args_prefix="fixMETRICS_")
    add_args(arg_parser)
    arg_parser.parse_args()
    assert fixcore.http_uri == "https://localhost:8900"
    assert fixcore.ws_uri == "wss://localhost:8900"


def test_default_config() -> None:
    metrics = _load_default_metrics()
    assert len(metrics) > 1
    first = next(iter(metrics.values()))
    assert isinstance(first.type, MetricType)
