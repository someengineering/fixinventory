from cloudkeeper.args import get_arg_parser
from cloudkeeper_plugin_cli_debug import CliDebugPlugin


def test_args():
    arg_parser = get_arg_parser()
    CliDebugPlugin.add_args(arg_parser)
    arg_parser.parse_args()
