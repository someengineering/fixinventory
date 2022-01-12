from resotolib.args import get_arg_parser, ArgumentParser
from cloudkeeper_plugin_example_collector import ExampleCollectorPlugin


def test_args():
    arg_parser = get_arg_parser()
    ExampleCollectorPlugin.add_args(arg_parser)
    arg_parser.parse_args()
    assert ArgumentParser.args.example_region is None
