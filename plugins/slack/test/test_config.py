from resotolib.config import Config
from resoto_plugin_slack import SlackBotPlugin, SlackCollectorPlugin


def test_config():
    config = Config("dummy", "dummy")
    SlackCollectorPlugin.add_config(config)
    SlackBotPlugin.add_config(config)
    Config.init_default_config()
    assert Config.slack.bot_token is None
    assert Config.slack.include_archived is False
    assert Config.slack.do_not_verify_ssl is False
