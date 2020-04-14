from cloudkeeper.args import get_arg_parser, ArgumentParser
from cloudkeeper_plugin_slack import SlackBotPlugin, SlackCollectorPlugin


def test_args():
    arg_parser = get_arg_parser()
    SlackBotPlugin.add_args(arg_parser)
    SlackCollectorPlugin.add_args(arg_parser)
    arg_parser.parse_args()
    assert ArgumentParser.args.slack_bot_token is None
