from resotolib.config import Config
from resoto_plugin_scarf import ScarfCollectorPlugin


def test_config():
    config = Config("dummy", "dummy")
    ScarfCollectorPlugin.add_config(config)
    config.init_default_config()
    assert Config.scarf.email == ""
    assert Config.scarf.password == ""
    assert Config.scarf.organizations == []
