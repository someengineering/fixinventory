from resotolib.config import Config
from resoto_plugin_cleanup_aws_alarms import CleanupAWSAlarmsPlugin


def test_config():
    config = Config("dummy", "dummy")
    CleanupAWSAlarmsPlugin.add_config(config)
    Config.init_default_config()
    assert Config.plugin_cleanup_aws_alarms.enabled is False
    assert Config.plugin_cleanup_aws_alarms.validate(Config.plugin_cleanup_aws_alarms.config) is True
