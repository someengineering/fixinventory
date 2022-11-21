from resotolib.baseplugin import BasePostCollectPlugin
from resotolib.baseresources import BaseResource
from resotolib.graph import BySearchCriteria, ByNodeId, Graph

from resotolib.logger import log
import functools
from typing import Any, Set


def rgetattr(obj: Any, attr: str, *args: Any) -> Any:
    def _getattr(obj: Any, attr: str) -> Any:
        return getattr(obj, attr, *args)

    return functools.reduce(_getattr, [obj] + attr.split("."))


def link_k8s_node_to_aws_nodegroup_or_ec2_instance(graph: Graph, resource: BaseResource) -> None:
    if resource.kind == "kubernetes_node":
        if (labels := rgetattr(resource, "labels", {})) and (nodegroup := labels.get("eks.amazonaws.com/nodegroup")):
            graph.add_deferred_edge(
                BySearchCriteria(f"is(aws_eks_nodegroup) and reported.id={nodegroup}"),
                ByNodeId(resource.chksum),
            )
        if (pid := rgetattr(resource, "node_spec.provider_id", None)) and (pid.startswith("aws://")):
            _, ec2_zone_and_instance_id = pid.split("aws://")
            ec2_instance_id = ec2_zone_and_instance_id.split("/")[2]
            graph.add_deferred_edge(
                BySearchCriteria(f"is(aws_ec2_instance) and reported.id={ec2_instance_id}"),
                ByNodeId(resource.chksum),
            )


def link_k8s_cluster_to_eks_cluster(graph: Graph, resource: BaseResource) -> None:
    if resource.kind == "kubernetes_cluster" and resource.id.startswith("arn:aws"):
        graph.add_deferred_edge(
            BySearchCriteria(f"is(aws_eks_cluster) and reported.arn={resource.id}"),
            ByNodeId(resource.chksum),
        )


def link_service_to_elb(graph: Graph, resource: BaseResource) -> None:
    if resource.kind == "kubernetes_service":
        if (rgetattr(resource, "service_spec.type", None) == "LoadBalancer") and (
            ingresses := rgetattr(resource, "service_status.load_balancer.ingress", None)
        ):
            for ingress in ingresses:
                if elb_hostname := rgetattr(ingress, "hostname", None):
                    graph.add_deferred_edge(
                        BySearchCriteria(f"is(aws_elb) and reported.id={elb_hostname}"), ByNodeId(resource.chksum)
                    )


def link_pv_to_ebs_volume(graph: Graph, resource: BaseResource) -> None:
    if resource.kind == "kubernetes_persistent_volume":
        if vol_id := rgetattr(resource, "persistent_volume_spec.aws_elastic_block_store.volume_id", None):
            graph.add_deferred_edge(
                BySearchCriteria(f"is(aws_ec2_volume) and reported.id={vol_id}"), ByNodeId(resource.chksum)
            )


class AWSK8sCollectorPlugin(BasePostCollectPlugin):
    name = "aws_k8s"
    activate_with: Set[str] = {"aws", "k8s"}

    def post_collect(self, graph: Graph) -> None:
        log.info("plugin: collecting AWS to k8s edges")
        for node in graph.nodes:
            if isinstance(node, BaseResource):
                link_k8s_node_to_aws_nodegroup_or_ec2_instance(graph, node)
                link_k8s_cluster_to_eks_cluster(graph, node)
                link_pv_to_ebs_volume(graph, node)
                link_service_to_elb(graph, node)
            else:
                log.warn(f"Node {node} is not a BaseResource")
