from cklib.args import get_arg_parser, ArgumentParser
from cloudkeeper_plugin_ckcore import CkCorePlugin


def test_args():
    arg_parser = get_arg_parser()
    CkCorePlugin.add_args(arg_parser)
    arg_parser.parse_args()
    assert ArgumentParser.args.ckcore_uri is None
