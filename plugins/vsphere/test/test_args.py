from cklib.args import get_arg_parser, ArgumentParser
from cloudkeeper_plugin_vsphere import VSphereCollectorPlugin


def test_args():
    arg_parser = get_arg_parser()
    VSphereCollectorPlugin.add_args(arg_parser)
    arg_parser.parse_args()
    assert ArgumentParser.args.vsphere_port == 443
