from resotolib.config import Config
from resoto_plugin_protect_snowflakes import ProtectSnowflakesPlugin


def test_config():
    config = Config("dummy", "dummy")
    ProtectSnowflakesPlugin.add_config(config)
    Config.init_default_config()
    assert Config.plugin_protect_snowflakes.enabled is False
    assert (
        Config.plugin_protect_snowflakes.validate(Config.plugin_protect_snowflakes)
        is True
    )
