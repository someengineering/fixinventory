from cloudkeeper.args import get_arg_parser, ArgumentParser
from cloudkeeper_plugin_onprem import OnpremCollectorPlugin


def test_args():
    arg_parser = get_arg_parser()
    OnpremCollectorPlugin.add_args(arg_parser)
    arg_parser.parse_args()
    assert ArgumentParser.args.onprem_location is None
    assert ArgumentParser.args.onprem_subnet is None
    assert ArgumentParser.args.onprem_user == "root"
    assert ArgumentParser.args.onprem_ssh_key == "~/.ssh/id_rsa"
    assert len(ArgumentParser.args.onprem_server) == 0
