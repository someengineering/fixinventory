from resotolib.args import get_arg_parser, ArgumentParser
from cloudkeeper_plugin_protect_snowflakes import ProtectSnowflakesPlugin


def test_args():
    arg_parser = get_arg_parser()
    ProtectSnowflakesPlugin.add_args(arg_parser)
    arg_parser.parse_args()
    assert ArgumentParser.args.protect_snowflakes_config is None
