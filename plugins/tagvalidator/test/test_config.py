from resotolib.config import Config
from resoto_plugin_tagvalidator import TagValidatorPlugin


def test_config():
    config = Config("dummy", "dummy")
    TagValidatorPlugin.add_config(config)
    Config.init_default_config()
    assert Config.plugin_tagvalidator.enabled is False
    assert Config.plugin_tagvalidator.dry_run is False
    assert Config.plugin_tagvalidator.validate(Config.plugin_tagvalidator) is True
