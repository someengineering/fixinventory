from resotolib.args import ArgumentParser
from resotoshell.__main__ import add_args


def test_args():
    arg_parser = ArgumentParser(
        description="resoto Shell", env_args_prefix="RESOTOSHELL_"
    )
    add_args(arg_parser)
    arg_parser.parse_args()
    assert ArgumentParser.args.resotocore_uri == "https://localhost:8900"
