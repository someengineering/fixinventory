from cloudkeeper.args import get_arg_parser
from cloudkeeper_plugin_cli_edgestats import CliEdgestatsPlugin


def test_args():
    arg_parser = get_arg_parser()
    CliEdgestatsPlugin.add_args(arg_parser)
    arg_parser.parse_args()
