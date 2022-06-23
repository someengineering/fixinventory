from resotolib.args import ArgumentParser
from resotolib.core import resotocore, add_args
from resotometrics.config import _load_default_metrics, MetricType


def test_args():
    arg_parser = ArgumentParser(description="resoto metrics exporter", env_args_prefix="RESOTOMETRICS_")
    add_args(arg_parser)
    arg_parser.parse_args()
    assert resotocore.http_uri == "https://localhost:8900"
    assert resotocore.ws_uri == "wss://localhost:8900"


def test_default_config() -> None:
    metrics = _load_default_metrics()
    assert len(metrics) > 1
    first = next(iter(metrics.values()))
    assert isinstance(first.type, MetricType)
