from cloudkeeper.args import get_arg_parser, ArgumentParser
from cloudkeeper_plugin_gcp import GCPCollectorPlugin


def test_args():
    arg_parser = get_arg_parser()
    GCPCollectorPlugin.add_args(arg_parser)
    arg_parser.parse_args()
    assert ArgumentParser.args.gcp_region is None
