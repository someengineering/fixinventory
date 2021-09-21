from cklib.args import get_arg_parser, ArgumentParser
from cloudkeeper_plugin_onelogin import OneLoginPlugin


def test_args():
    arg_parser = get_arg_parser()
    OneLoginPlugin.add_args(arg_parser)
    arg_parser.parse_args()
    assert ArgumentParser.args.onelogin_region == "us"
    assert ArgumentParser.args.onelogin_client_id is None
    assert ArgumentParser.args.onelogin_client_secret is None
