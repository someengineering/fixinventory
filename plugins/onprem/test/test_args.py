from cloudkeeper.args import get_arg_parser, ArgumentParser
from cloudkeeper_plugin_onprem import OnpremCollectorPlugin


def test_args():
    arg_parser = get_arg_parser()
    OnpremCollectorPlugin.add_args(arg_parser)
    arg_parser.parse_args()
    assert ArgumentParser.args.onprem_region is None
