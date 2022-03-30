from resotolib.config import Config
from resoto_plugin_example_collector import ExampleCollectorPlugin


def test_config():
    config = Config("dummy", "dummy")
    ExampleCollectorPlugin.add_config(config)
    Config.init_default_config()


#    assert Config.example.region is None
