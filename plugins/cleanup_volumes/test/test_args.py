from cloudkeeper.args import get_arg_parser, ArgumentParser
from cloudkeeper_plugin_cleanup_volumes import CleanupVolumesPlugin


def test_args():
    arg_parser = get_arg_parser()
    CleanupVolumesPlugin.add_args(arg_parser)
    arg_parser.parse_args()
    assert ArgumentParser.args.cleanup_volumes is False
    assert ArgumentParser.args.cleanup_volumes_age == '14 days'
