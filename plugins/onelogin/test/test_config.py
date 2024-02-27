from fixlib.config import Config
from fix_plugin_onelogin import OneLoginPlugin


def test_config():
    config = Config("dummy", "dummy")
    OneLoginPlugin.add_config(config)
    config.init_default_config()
    assert Config.onelogin.region == "us"
    assert Config.onelogin.client_id is None
    assert Config.onelogin.client_secret is None
