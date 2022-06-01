from resotolib.config import Config
from resoto_plugin_cleanup_untagged import CleanupUntaggedPlugin


def test_config():
    config = Config("dummy", "dummy")
    CleanupUntaggedPlugin.add_config(config)
    Config.init_default_config()
    assert Config.plugin_cleanup_untagged.enabled is False
    assert Config.plugin_cleanup_untagged.validate(Config.plugin_cleanup_untagged) is True
