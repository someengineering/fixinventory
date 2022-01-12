from resotolib.args import get_arg_parser, ArgumentParser
from resoto_plugin_cleanup_aws_vpcs import CleanupAWSVPCsPlugin


def test_args():
    arg_parser = get_arg_parser()
    CleanupAWSVPCsPlugin.add_args(arg_parser)
    arg_parser.parse_args()
    assert ArgumentParser.args.cleanup_aws_vpcs is False
    assert ArgumentParser.args.cleanup_aws_vpcs_config is None
