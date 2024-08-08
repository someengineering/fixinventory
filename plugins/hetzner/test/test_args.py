from fixlib.args import get_arg_parser
from fix_plugin_hetzner import HetznerCollectorPlugin

# from fixlib.args import ArgumentParser


def test_args():
    arg_parser = get_arg_parser()
    HetznerCollectorPlugin.add_args(arg_parser)
    arg_parser.parse_args()


#    assert ArgumentParser.args.example_arg is None
