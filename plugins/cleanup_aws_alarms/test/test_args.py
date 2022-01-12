from resotolib.args import get_arg_parser, ArgumentParser
from cloudkeeper_plugin_cleanup_aws_alarms import CleanupAWSAlarmsPlugin


def test_args():
    arg_parser = get_arg_parser()
    CleanupAWSAlarmsPlugin.add_args(arg_parser)
    arg_parser.parse_args()
    assert ArgumentParser.args.cleanup_aws_alarms is False
    assert ArgumentParser.args.cleanup_aws_alarms_config is None
