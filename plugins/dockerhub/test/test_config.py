from fixlib.config import Config
from fix_plugin_dockerhub import DockerHubCollectorPlugin


def test_config():
    config = Config("dummy", "dummy")
    DockerHubCollectorPlugin.add_config(config)
    config.init_default_config()
    assert Config.dockerhub.namespaces == []
