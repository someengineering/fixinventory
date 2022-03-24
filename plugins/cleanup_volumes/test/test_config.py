from resotolib.config import Config
from resoto_plugin_cleanup_volumes import CleanupVolumesPlugin


def test_config():
    config = Config("dummy", "dummy")
    CleanupVolumesPlugin.add_config(config)
    Config.init_default_config()
    assert Config.plugin_cleanup_volumes.enabled is False
    assert Config.plugin_cleanup_volumes.min_age == "14 days"
