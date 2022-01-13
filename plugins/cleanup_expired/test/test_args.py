from resotolib.args import get_arg_parser, ArgumentParser
from resoto_plugin_cleanup_expired import CleanupExpiredPlugin


def test_args():
    arg_parser = get_arg_parser()
    CleanupExpiredPlugin.add_args(arg_parser)
    arg_parser.parse_args()
    assert ArgumentParser.args.cleanup_expired is False
