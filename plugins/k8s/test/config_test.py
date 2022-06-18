import pickle
from dataclasses import replace
from tempfile import TemporaryDirectory

import jsons
import yaml

from resotolib.utils import num_default_threads
from resotolib.config import Config
from resoto_plugin_k8s import KubernetesCollectorPlugin
from resoto_plugin_k8s.base import K8sConfig, K8sAccess, K8sConfigFile


def test_k8s_access() -> None:
    config = K8sAccess(name="test", certificate_authority_data="test", server="test", token="test")
    yaml_string = config.to_yaml()
    yaml.safe_load(yaml_string)


def test_k8s_config_pickle() -> None:
    access = K8sAccess(name="test", certificate_authority_data="test", server="test", token="test")
    file = K8sConfigFile("test", ["bla"], True)
    base = K8sConfig([access], [file])

    for config in [base, replace(base, _clients={}, _temp_dir=TemporaryDirectory())]:
        pickled = pickle.dumps(config)
        again = pickle.loads(pickled)
        assert config.configs == again.configs
        assert config.config_files == again.config_files


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


def test_config_roundtrip() -> None:
    cfg = K8sConfig(
        [K8sAccess(name=n, certificate_authority_data=n, server=n, token=n) for n in ["d", "e", "f"]],
        [K8sConfigFile(n, ["foo"]) for n in ["d", "e", "f"]],
    )
    js = jsons.dump(cfg, strip_attr="kind", strip_properties=True, strip_privates=True)
    # noinspection PyTypeChecker
    again = K8sConfig.from_json(js)
    assert cfg.configs == again.configs and cfg.config_files == again.config_files


def test_config_migrate_from_v1() -> None:
    js = dict(
        context=["ctx_a", "ctx_b", "ctx_c"],
        config=["cfg_a", "cfg_b", "cfg_c"],
        cluster=["cls_a", "cls_b", "cls_c"],
        apiserver=["api_a", "api_b", "api_c"],
        token=["tkn_a", "tkn_b", "tkn_c"],
        cacert=["ca_a", "ca_b", "ca_c"],
        collect=["c_a", "c_b", "c_c"],
        no_collect=["n_a", "n_b", "n_c"],
        pool_size=23,
        fork_process=True,
        all_contexts=True,
    )
    config = K8sConfig.from_json(js)
    assert len(config.configs) == 3
    assert len(config.config_files) == 3
    config.configs[0] = K8sAccess("cls_a", "api_a", "tkn_a", "ca_a")
    config.config_files[0] = K8sConfigFile("cfg_a", ["c_a", "n_a"], True)

    # can parse partial data
    js["apiserver"] = []
    K8sConfig.from_json(js)
    assert len(config.configs) == 3
    assert len(config.config_files) == 3

    # accepts missing data
    del js["apiserver"]
    del js["cacert"]
    K8sConfig.from_json(js)
    assert len(config.configs) == 3
    assert len(config.config_files) == 3

    fresh_20_config = {
        "context": [],
        "config": None,
        "cluster": [],
        "apiserver": [],
        "token": [],
        "cacert": [],
        "collect": [],
        "no_collect": [],
        "pool_size": 8,
        "fork_process": False,
        "all_contexts": False,
    }
    K8sConfig.from_json(fresh_20_config)


def test_empty_config() -> None:
    # make sure the running config is empty
    Config.running_config.data.clear()
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
