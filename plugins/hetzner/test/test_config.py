from fixlib.config import Config
from fix_plugin_hetzner import HetznerCollectorPlugin


def test_config():
    config = Config("dummy", "dummy")
    HetznerCollectorPlugin.add_config(config)
    Config.init_default_config()
    assert Config.hetzner.hcloud_tokens == []
