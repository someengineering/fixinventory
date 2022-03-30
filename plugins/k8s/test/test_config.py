from resotolib.config import Config
from resoto_plugin_k8s import KubernetesCollectorPlugin


def test_config():
    config = Config("dummy", "dummy")
    KubernetesCollectorPlugin.add_config(config)
    config.init_default_config()
    assert len(Config.k8s.context) == 0
    assert Config.k8s.config is None
    assert len(Config.k8s.cluster) == 0
    assert len(Config.k8s.apiserver) == 0
    assert len(Config.k8s.token) == 0
    assert len(Config.k8s.cacert) == 0
    assert len(Config.k8s.collect) == 0
    assert len(Config.k8s.no_collect) == 0
    assert Config.k8s.pool_size == 5
    assert Config.k8s.fork is True
    assert Config.k8s.all_contexts is False
