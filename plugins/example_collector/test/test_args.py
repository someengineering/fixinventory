from resotolib.args import get_arg_parser
from resoto_plugin_example_collector import ExampleCollectorPlugin

# from resotolib.args import ArgumentParser


def test_args():
    arg_parser = get_arg_parser()
    ExampleCollectorPlugin.add_args(arg_parser)
    arg_parser.parse_args()


#    assert ArgumentParser.args.example_arg is None
