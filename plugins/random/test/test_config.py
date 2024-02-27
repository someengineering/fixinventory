from fixlib.config import Config
from fix_plugin_random import RandomCollectorPlugin


def test_config():
    config = Config("dummy", "dummy")
    RandomCollectorPlugin.add_config(config)
    Config.init_default_config()

    assert Config.random.seed == 0
    assert Config.random.size == 1.0
