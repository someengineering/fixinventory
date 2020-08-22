from cloudkeeper.args import get_arg_parser, ArgumentParser
from cloudkeeper_plugin_example_persistent import ExamplePersistentPlugin


def test_args():
    arg_parser = get_arg_parser()
    ExamplePersistentPlugin.add_args(arg_parser)
    arg_parser.parse_args()
    assert ArgumentParser.args.example_arg is None
