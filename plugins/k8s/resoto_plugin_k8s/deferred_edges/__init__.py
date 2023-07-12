from resotolib.baseresources import BaseResource
from resotolib.graph import Graph
from resotolib.logger import log
from resoto_plugin_k8s.deferred_edges.aws import link_all as link_all_aws
from resoto_plugin_k8s.deferred_edges.digitalocean import link_all as link_all_do


def create_deferred_edges(graph: Graph) -> None:
    if not isinstance(graph, Graph):
        log.error(f"Expected type Graph, got {type(graph)}")
        return
    for node in graph.nodes:
        if not isinstance(node, BaseResource):
            log.warning(f"Node {node} is not a BaseResource")
            continue
        link_all_aws(graph, node)
        link_all_do(graph, node)
