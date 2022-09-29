from resotolib.config import Config
from resoto_plugin_posthog import PosthogCollectorPlugin


def test_config():
    config = Config("dummy", "dummy")
    PosthogCollectorPlugin.add_config(config)
    config.init_default_config()
    assert Config.posthog.projects == []
