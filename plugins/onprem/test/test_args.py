from resotolib.args import get_arg_parser, ArgumentParser
from cloudkeeper_plugin_onprem import OnpremCollectorPlugin


def test_args():
    arg_parser = get_arg_parser()
    OnpremCollectorPlugin.add_args(arg_parser)
    arg_parser.parse_args()
    assert ArgumentParser.args.onprem_location == "Default location"
    assert ArgumentParser.args.onprem_region == "Default region"
    assert ArgumentParser.args.onprem_ssh_user == "root"
    assert ArgumentParser.args.onprem_ssh_key is None
    assert len(ArgumentParser.args.onprem_server) == 0
