from resotolib.baseplugin import BasePostCollectPlugin
from resotolib.baseresources import BaseResource
from resotolib.graph import BySearchCriteria, ByNodeId, Graph

from resotolib.logger import log
import functools
from typing import Any


def rgetattr(obj: Any, attr: str, *args: Any) -> Any:
    def _getattr(obj: Any, attr: str) -> Any:
        return getattr(obj, attr, *args)

    return functools.reduce(_getattr, [obj] + attr.split("."))


def link_k8s_node_to_aws_nodegroup(graph: Graph, resource: BaseResource) -> None:
    if resource.kind == "kubernetes_node":
        if (labels := rgetattr(resource, "labels", {})) and (nodegroup := labels.get("eks.amazonaws.com/nodegroup")):
            graph.add_deferred_edge(
                BySearchCriteria(f"is(aws_eks_nodegroup) and reported.id={nodegroup}"),
                ByNodeId(resource.chksum),
            )


def link_k8s_cluster_to_eks_cluster(graph: Graph, resource: BaseResource) -> None:
    if resource.kind == "kubernetes_cluster" and resource.id.startswith("arn:aws"):
        graph.add_deferred_edge(
            BySearchCriteria(f"is(aws_eks_cluster) and reported.arn={resource.id}"),
            ByNodeId(resource.chksum),
        )


class AWSK8sCollectorPlugin(BasePostCollectPlugin):
    name = "aws_k8s"

    def post_collect(self, graph: Graph) -> None:
        log.info("plugin: collecting AWS to k8s edges")
        for node in graph.nodes:
            if isinstance(node, BaseResource):
                link_k8s_node_to_aws_nodegroup(graph, node)
                link_k8s_cluster_to_eks_cluster(graph, node)
            else:
                log.warn(f"Node {node} is not a BaseResource")
