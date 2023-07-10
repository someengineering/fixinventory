from resotolib.baseresources import BaseResource
from resotolib.graph import Graph
from resotolib.logger import log
from resoto_plugin_k8s.deferred_edges.aws import (
    link_k8s_node_to_aws_nodegroup_or_ec2_instance,
    link_k8s_cluster_to_eks_cluster,
    link_pv_to_ebs_volume,
    link_service_to_elb,
)
from resoto_plugin_k8s.deferred_edges.digitalocean import (
    link_node_to_do_droplet,
    link_service_to_do_lb,
    link_pv_to_do_volume,
)


def link_graph_to_all(graph: Graph) -> None:
    if not isinstance(graph, Graph):
        log.error(f"Expected type Graph, got {type(graph)}")
        return
    for node in graph.nodes:
        if not isinstance(node, BaseResource):
            log.warning(f"Node {node} is not a BaseResource")
            continue
        # AWS
        link_k8s_node_to_aws_nodegroup_or_ec2_instance(graph, node)
        link_k8s_cluster_to_eks_cluster(graph, node)
        link_pv_to_ebs_volume(graph, node)
        link_service_to_elb(graph, node)
        # DigitalOcean
        link_node_to_do_droplet(graph, node)
        link_service_to_do_lb(graph, node)
        link_pv_to_do_volume(graph, node)
