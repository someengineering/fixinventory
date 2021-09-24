from cklib.args import ArgumentParser
from ckworker.__main__ import add_args


def test_args():
    arg_parser = ArgumentParser(
        description="Cloudkeeper Worker",
        env_args_prefix="CKWORKER_",
    )
    add_args(arg_parser)
    arg_parser.parse_args()
    assert ArgumentParser.args.ckcore_uri == "http://localhost:8900"
