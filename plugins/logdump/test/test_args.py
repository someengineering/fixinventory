from cklib.args import get_arg_parser, ArgumentParser
from cloudkeeper_plugin_logdump import LogDumpPlugin


def test_args():
    arg_parser = get_arg_parser()
    LogDumpPlugin.add_args(arg_parser)
    arg_parser.parse_args()
    assert ArgumentParser.args.logdump_path is None
