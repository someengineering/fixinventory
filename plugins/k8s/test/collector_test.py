from typing import Tuple, List

import jsons

from fixtures import StaticFileClient
from resoto_plugin_k8s.base import K8sConfig, K8sAccess, K8sApiResource, K8sClient
from resoto_plugin_k8s import KubernetesCollectorPlugin
from resoto_plugin_k8s.resources import KubernetesCluster, KubernetesClusterInfo, KubernetesConfigMap
from resotolib.config import Config
from resotolib.graph import Graph
from pytest import fixture


@fixture
def config_map_in_graph() -> Tuple[KubernetesConfigMap, Graph, StaticFileClient]:
    # register a config
    cfg = K8sConfig(configs=[K8sAccess(name="test", certificate_authority_data="test", server="test", token="test")])
    Config.add_config(K8sConfig)
    Config.running_config.data["k8s"] = cfg

    # define the static client for the "test" account
    client = StaticFileClient("test", None)
    # noinspection PyProtectedMember
    cfg._clients = {"test": client}

    # create a cluster with id test
    cluster = KubernetesCluster(id="test", name="test", cluster_info=KubernetesClusterInfo("test", "test", "test"))
    graph = Graph(root=cluster)

    # create a config map
    cm = KubernetesConfigMap(id="cm1", name="cm1", namespace="ns1")
    graph.add_node(cm)
    graph.add_edge(cluster, cm)

    return cm, graph, client


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


def test_tag_update(config_map_in_graph: Tuple[KubernetesConfigMap, Graph, StaticFileClient]) -> None:
    cm, graph, client = config_map_in_graph
    cm.update_tag("test", "test")
    assert len(client.patches) == 1
    assert client.patches[0] == (KubernetesConfigMap, "ns1", "cm1", {"metadata": {"annotations": {"test": "test"}}})


def test_tag_delete(config_map_in_graph: Tuple[KubernetesConfigMap, Graph, StaticFileClient]) -> None:
    cm, graph, client = config_map_in_graph
    cm.delete_tag("test")
    assert len(client.patches) == 1
    assert client.patches[0] == (KubernetesConfigMap, "ns1", "cm1", {"metadata": {"annotations": {"test": None}}})


def test_resource_delete(config_map_in_graph: Tuple[KubernetesConfigMap, Graph, StaticFileClient]) -> None:
    cm, graph, client = config_map_in_graph
    cm.delete(graph)
    assert len(client.deletes) == 1
    assert client.deletes[0] == (KubernetesConfigMap, "ns1", "cm1")


def test_filter_beta_apis(config_map_in_graph: Tuple[KubernetesConfigMap, Graph, StaticFileClient]) -> None:
    _, _, client = config_map_in_graph
    apis = jsons.load(client.get("apis"), List[K8sApiResource])
    filtered = K8sClient.filter_apis(apis)
    assert len(filtered) == len(apis) - 2  # Event and Ingress is filtered out
