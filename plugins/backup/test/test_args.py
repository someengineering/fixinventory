from cklib.args import get_arg_parser, ArgumentParser
from cloudkeeper_plugin_backup import BackupPlugin


def test_args():
    arg_parser = get_arg_parser()
    BackupPlugin.add_args(arg_parser)
    arg_parser.parse_args()
    assert ArgumentParser.args.backup_to is None
