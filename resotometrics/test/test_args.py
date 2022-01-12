from resotolib.args import ArgumentParser
from resotometrics.__main__ import add_args


def test_args():
    arg_parser = ArgumentParser(
        description="Cloudkeeper Metrics Exporter", env_args_prefix="RESOTOMETRICS_"
    )
    add_args(arg_parser)
    arg_parser.parse_args()
    assert ArgumentParser.args.resotocore_uri == "http://localhost:8900"
    assert ArgumentParser.args.resotocore_ws_uri == "ws://localhost:8900"
    assert ArgumentParser.args.resotocore_graph == "resoto"
    assert ArgumentParser.args.timeout == 300
