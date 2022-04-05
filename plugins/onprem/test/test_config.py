from resotolib.config import Config
from resoto_plugin_onprem import OnpremCollectorPlugin


def test_config():
    config = Config("dummy", "dummy")
    OnpremCollectorPlugin.add_config(config)
    config.init_default_config()
    assert Config.onprem.location == "Default location"
    assert Config.onprem.region == "Default region"
    assert Config.onprem.ssh_user == "root"
    assert Config.onprem.ssh_key is None
    assert len(Config.onprem.server) == 0
    assert Config.onprem.pool_size == 5
    assert Config.onprem.fork_process is True
