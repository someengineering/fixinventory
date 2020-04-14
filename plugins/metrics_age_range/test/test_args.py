from cloudkeeper.args import get_arg_parser, ArgumentParser
from cloudkeeper_plugin_metrics_age_range import MetricsAgeRangePlugin


def test_args():
    arg_parser = get_arg_parser()
    MetricsAgeRangePlugin.add_args(arg_parser)
    arg_parser.parse_args()
    assert ArgumentParser.args.metrics_age_range is False
