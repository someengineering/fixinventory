from resotolib.config import Config
from resoto_plugin_cleanup_aws_loadbalancers import CleanupAWSLoadbalancersPlugin


def test_config():
    config = Config("dummy", "dummy")
    CleanupAWSLoadbalancersPlugin.add_config(config)
    Config.init_default_config()
    assert Config.plugin_cleanup_aws_loadbalancers.enabled is False
    assert Config.plugin_cleanup_aws_loadbalancers.min_age == "7 days"
