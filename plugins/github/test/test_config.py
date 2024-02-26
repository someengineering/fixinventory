from fixlib.config import Config
from fix_plugin_github import GithubCollectorPlugin


def test_config():
    config = Config("dummy", "dummy")
    GithubCollectorPlugin.add_config(config)
    config.init_default_config()
    assert Config.github.access_token is None
