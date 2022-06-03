from resotolib.config import Config
from resoto_plugin_cleanup_aws_vpcs import CleanupAWSVPCsPlugin


def test_config():
    config = Config("dummy", "dummy")
    CleanupAWSVPCsPlugin.add_config(config)
    Config.init_default_config()
    assert Config.plugin_cleanup_aws_vpcs.enabled is False
    assert Config.plugin_cleanup_aws_vpcs.validate(Config.plugin_cleanup_aws_vpcs) is True
