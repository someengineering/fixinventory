from cklib.args import get_arg_parser, ArgumentParser
from cloudkeeper_plugin_cleanup_aws_loadbalancers import CleanupAWSLoadbalancersPlugin


def test_args():
    arg_parser = get_arg_parser()
    CleanupAWSLoadbalancersPlugin.add_args(arg_parser)
    arg_parser.parse_args()
    assert ArgumentParser.args.cleanup_aws_loadbalancers is False
    assert ArgumentParser.args.cleanup_aws_loadbalancers_age == "7 days"
