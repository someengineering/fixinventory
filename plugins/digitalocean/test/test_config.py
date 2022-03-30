from resotolib.config import Config
from resoto_plugin_digitalocean import DigitalOceanCollectorPlugin


def test_config() -> None:
    config = Config("dummy", "dummy")
    DigitalOceanCollectorPlugin.add_config(config)
    Config.init_default_config()
    assert len(Config.digitalocean.api_tokens) == 0
    assert len(Config.digitalocean.spaces_access_keys) == 0
