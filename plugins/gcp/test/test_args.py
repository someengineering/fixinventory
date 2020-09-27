from cloudkeeper.args import get_arg_parser, ArgumentParser
from cloudkeeper_plugin_gcp import GCPCollectorPlugin


def test_args():
    arg_parser = get_arg_parser()
    GCPCollectorPlugin.add_args(arg_parser)
    arg_parser.parse_args()
    assert len(ArgumentParser.args.gcp_service_account) == 0
    assert len(ArgumentParser.args.gcp_project) == 0
    assert len(ArgumentParser.args.gcp_collect) == 0
    assert len(ArgumentParser.args.gcp_no_collect) == 0
    assert ArgumentParser.args.gcp_project_pool_size == 5
    assert ArgumentParser.args.gcp_fork is False
