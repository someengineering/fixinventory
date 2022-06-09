from tempfile import TemporaryDirectory

import yaml

from resotolib.utils import num_default_threads
from resotolib.config import Config
from resoto_plugin_k8s import KubernetesCollectorPlugin
from resoto_plugin_k8s.config import K8sConfig, K8sAccess, K8sConfigFile


def test_k8s_access() -> None:
    config = K8sAccess(name="test", certificate_authority_data="test", server="test", token="test")
    yaml_string = config.to_yaml()
    yaml.safe_load(yaml_string)


def test_setup_config() -> None:
    as_files = [K8sAccess(name=n, certificate_authority_data=n, server=n, token=n) for n in ["a", "b", "c"]]
    configs = [K8sAccess(name=n, certificate_authority_data=n, server=n, token=n) for n in ["d", "e", "f"]]
    with TemporaryDirectory() as tmpdir:
        files = []
        for af in as_files:
            fn = tmpdir + "/" + af.name + ".yaml"
            with open(fn, "w") as f:
                f.write(af.to_yaml())
            files.append(K8sConfigFile(fn))
        cfg = K8sConfig(configs, files)
        result = cfg.cluster_access_configs(tmpdir)
        assert result.keys() == {"a", "b", "c", "d", "e", "f"}


def test_empty_config() -> None:
    config = Config("dummy", "dummy")
    KubernetesCollectorPlugin.add_config(config)
    config.init_default_config()
    k8s: K8sConfig = config.k8s
    assert k8s.configs == []
    assert k8s.config_files == []
    assert k8s.collect == []
    assert k8s.no_collect == []
    assert k8s.pool_size == num_default_threads()
    assert k8s.fork_process is False
