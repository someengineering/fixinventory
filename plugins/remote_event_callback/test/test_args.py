from cloudkeeper.args import get_arg_parser, ArgumentParser
from cloudkeeper_plugin_remote_event_callback import RemoteEventCallbackPlugin


def test_args():
    arg_parser = get_arg_parser()
    RemoteEventCallbackPlugin.add_args(arg_parser)
    arg_parser.parse_args()
    assert len(ArgumentParser.args.remote_event_endpoint) == 0
    assert ArgumentParser.args.remote_event_callback_psk is None
