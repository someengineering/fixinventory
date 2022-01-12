from resotolib.args import ArgumentParser
from resotosh.__main__ import add_args


def test_args():
    arg_parser = ArgumentParser(
        description="Cloudkeeper Shell", env_args_prefix="RESOTOSH_"
    )
    add_args(arg_parser)
    arg_parser.parse_args()
    assert ArgumentParser.args.resotocore_uri == "http://localhost:8900"
