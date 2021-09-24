from cklib.args import ArgumentParser
from ckmetrics.__main__ import add_args


def test_args():
    arg_parser = ArgumentParser(
        description="Cloudkeeper Metrics Exporter", env_args_prefix="CKMETRICS_"
    )
    add_args(arg_parser)
    arg_parser.parse_args()
    assert ArgumentParser.args.web_port == 9955
