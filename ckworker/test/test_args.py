from cklib.args import ArgumentParser
from ckworker.__main__ import add_args
from ckworker.collect import add_args as collect_add_args
from ckworker.cleanup import add_args as cleanup_add_args
from ckworker.ckcore import add_args as ckcore_add_args
from cklib.core import add_args as core_add_args


def test_args():
    arg_parser = ArgumentParser(
        description="Cloudkeeper Worker",
        env_args_prefix="CKWORKER_",
    )
    add_args(arg_parser)
    collect_add_args(arg_parser)
    cleanup_add_args(arg_parser)
    ckcore_add_args(arg_parser)
    core_add_args(arg_parser)
    arg_parser.parse_args()
    assert ArgumentParser.args.ckcore_uri == "http://localhost:8900"
