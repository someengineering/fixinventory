from cloudkeeper.args import get_arg_parser
from cloudkeeper_plugin_cli_jq import CliJqPlugin


def test_args():
    arg_parser = get_arg_parser()
    CliJqPlugin.add_args(arg_parser)
    arg_parser.parse_args()
