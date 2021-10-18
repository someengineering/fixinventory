from cklib.args import get_arg_parser, ArgumentParser
from cloudkeeper_plugin_example_cli import ExampleCliPlugin


def test_args():
    arg_parser = get_arg_parser()
    ExampleCliPlugin.add_args(arg_parser)
    arg_parser.parse_args()
    assert ArgumentParser.args.example_cli_arg is None
