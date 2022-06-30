from resotolib.args import get_arg_parser
from resoto_plugin_random import RandomCollectorPlugin

# from resotolib.args import ArgumentParser


def test_args():
    arg_parser = get_arg_parser()
    RandomCollectorPlugin.add_args(arg_parser)
    arg_parser.parse_args()


#    assert ArgumentParser.args.example_arg is None
