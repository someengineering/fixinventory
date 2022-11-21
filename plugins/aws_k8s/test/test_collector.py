from resoto_plugin_aws_k8s import AWSK8sCollectorPlugin
from resotolib.baseresources import BaseResource
from resotolib.graph import Graph
from typing import ClassVar
from types import SimpleNamespace


class KubernetesNode(BaseResource):
    kind: ClassVar[str] = "kubernetes_node"
    node_spec = SimpleNamespace(provider_id="aws:///eu-central-1a/123")

    def delete(self, graph: Graph) -> bool:
        return False


def test_post_collect() -> None:

    plugin = AWSK8sCollectorPlugin()

    node = KubernetesNode(id="123")

    graph = Graph(root=node)
    plugin.post_collect(graph)

    assert len(graph.deferred_edges) == 1
