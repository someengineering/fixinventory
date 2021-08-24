from keeper_cli.args import get_arg_parser, ArgumentParser
from keeper_cli.__main__ import add_args


def test_args():
    arg_parser = get_arg_parser()
    add_args(arg_parser)
    arg_parser.parse_args()
    assert ArgumentParser.args.keepercore_uri == "http://localhost:8080"
