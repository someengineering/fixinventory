from resoto_plugin_k8s.deferred_edges.utils import rgetattr
from resotolib.baseresources import BaseResource
from resotolib.graph import Graph
from resotolib.logger import log
from resoto_plugin_k8s.deferred_edges.aws import link_all as link_all_aws
from resoto_plugin_k8s.deferred_edges.digitalocean import link_all as link_all_do
from resoto_plugin_k8s.deferred_edges.azure import link_all as link_all_azure


def create_deferred_edges(graph: Graph) -> None:
    if not isinstance(graph, Graph):
        log.error(f"Expected type Graph, got {type(graph)}")
        return
    cloud_urls = {
        "amazonaws.com": link_all_aws,
        "azmk8s.io": link_all_azure,
        "digitaloceanspaces.com": link_all_do
    }
    for node in graph.nodes:
        if not isinstance(node, BaseResource):
            log.warning(f"Node {node} is not a BaseResource")
            continue
        if (server_url := rgetattr(node, "cluster_info.server_url", None)):
            cloud_url = '.'.join(server_url.split('.')[-2:])
            if cloud_urls.get(cloud_url) is not None:
                cloud_urls[cloud_url](graph, node)
