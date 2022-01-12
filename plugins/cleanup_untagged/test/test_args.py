from resotolib.args import get_arg_parser, ArgumentParser
from cloudkeeper_plugin_cleanup_untagged import CleanupUntaggedPlugin


def test_args():
    arg_parser = get_arg_parser()
    CleanupUntaggedPlugin.add_args(arg_parser)
    arg_parser.parse_args()
    assert ArgumentParser.args.cleanup_untagged_config is None
