from resotolib.args import ArgumentParser
from resotoworker.__main__ import add_args
from resotoworker.collect import add_args as collect_add_args
from resotoworker.cleanup import add_args as cleanup_add_args
from resotoworker.resotocore import add_args as resotocore_add_args
from resotolib.core import add_args as core_add_args


def test_args():
    arg_parser = ArgumentParser(
        description="Cloudkeeper Worker",
        env_args_prefix="RESOTOWORKER_",
    )
    add_args(arg_parser)
    collect_add_args(arg_parser)
    cleanup_add_args(arg_parser)
    resotocore_add_args(arg_parser)
    core_add_args(arg_parser)
    arg_parser.parse_args()
    assert ArgumentParser.args.resotocore_uri == "http://localhost:8900"
