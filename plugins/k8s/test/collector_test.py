from fixtures import StaticFileClient
from resoto_plugin_k8s.config import K8sConfig, K8sAccess
from resoto_plugin_k8s import KubernetesCollectorPlugin
from resotolib.config import Config


def test_collect() -> None:
    # create a config with a single cluster: the values do not matter
    cfg = K8sConfig(configs=[K8sAccess(name="test", certificate_authority_data="test", server="test", token="test")])
    Config.add_config(K8sConfig)
    Config.running_config.data["k8s"] = cfg

    plugin = KubernetesCollectorPlugin()
    # start a collect: use the static file client to get the static json files
    plugin.collect(client_factory=StaticFileClient.static)
    assert len(plugin.graph.nodes) == 561
    assert len(plugin.graph.edges) == 813
    assert len(plugin.graph.deferred_edges) == 4
