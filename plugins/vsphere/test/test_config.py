from resotolib.config import Config
from resoto_plugin_vsphere import VSphereCollectorPlugin


def test_config():
    config = Config("dummy", "dummy")
    VSphereCollectorPlugin.add_config(config)
    Config.init_default_config()
    assert Config.vsphere.user is None
    assert Config.vsphere.password is None
    assert Config.vsphere.host is None
    assert Config.vsphere.port == 443
    assert Config.vsphere.insecure is True
