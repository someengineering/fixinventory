from resotolib.config import Config
from resoto_plugin_protector import ProtectorPlugin


def test_config():
    config = Config("dummy", "dummy")
    ProtectorPlugin.add_config(config)
    Config.init_default_config()
    assert Config.plugin_protector.enabled is False
    assert Config.plugin_protector.validate(Config.plugin_protector) is True
