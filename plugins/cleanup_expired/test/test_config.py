from resotolib.config import Config
from resoto_plugin_cleanup_expired import CleanupExpiredPlugin


def test_config():
    config = Config("dummy", "dummy")
    CleanupExpiredPlugin.add_config(config)
    Config.init_default_config()
    assert Config.plugin_cleanup_expired.enabled is False
