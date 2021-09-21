from cklib.args import get_arg_parser, ArgumentParser
from cloudkeeper_plugin_keepercore import KeepercorePlugin


def test_args():
    arg_parser = get_arg_parser()
    KeepercorePlugin.add_args(arg_parser)
    arg_parser.parse_args()
    assert ArgumentParser.args.keepercore_uri is None
