from resoto_plugin_aws_k8s import AWSK8sCollectorPlugin
from resotolib.baseresources import BaseResource
from resotolib.graph import Graph
from typing import ClassVar
from types import SimpleNamespace


# class KubernetesService(BaseResource):
#     kind: ClassVar[str] = "kubernetes_service"
#     id = "123"
#     service_spec = SimpleNamespace(type = "LoadBalancer")
#     service_status = SimpleNamespace(load_balancer = SimpleNamespace(ingress = [{"hostname": "miau"}]))
#     # labels = {"eks.amazonaws.com/nodegroup": "main"}

#     def delete(self, graph: Graph) -> bool:
#         return False


# def test_post_collect() -> None:

#     plugin = AWSK8sCollectorPlugin()

#     node = KubernetesService(id="123")

#     graph = Graph(root=node)
#     plugin.post_collect(graph)

#     assert len(graph.deferred_edges) == 1

class KubernetesNode(BaseResource):
    kind: ClassVar[str] = "kubernetes_node"
    node_spec = SimpleNamespace(provider_id="aws:///eu-central-1a/123")

    def delete(self, graph: Graph) -> bool:
        return False


def test_post_collect() -> None:

    plugin =  AWSK8sCollectorPlugin()

    node = KubernetesNode(id="123")

    graph = Graph(root=node)
    plugin.post_collect(graph)

    assert len(graph.deferred_edges) == 1
