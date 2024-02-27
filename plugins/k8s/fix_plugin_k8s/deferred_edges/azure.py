from fixlib.baseresources import BaseResource
from fixlib.graph import BySearchCriteria, ByNodeId, Graph
from fix_plugin_k8s.deferred_edges.utils import rgetattr


def link_k8s_cluster_to_aks_cluster(graph: Graph, resource: BaseResource) -> None:
    if resource.kind == "kubernetes_cluster":
        graph.add_deferred_edge(
            BySearchCriteria(f"is(azure_managed_cluster) and reported.name={resource.id}"),
            ByNodeId(resource.chksum),
        )


def link_service_to_azure_lb(graph: Graph, resource: BaseResource) -> None:
    if resource.kind == "kubernetes_service":
        if (rgetattr(resource, "service_spec.type", None) == "LoadBalancer") and (
            ingresses := rgetattr(resource, "service_status.load_balancer.ingress", None)
        ):
            for ingress in ingresses:
                if lb_ip := rgetattr(ingress, "ip", None):
                    graph.add_deferred_edge(
                        BySearchCriteria(f"is(azure_load_balancer) and reported.aks_public_ip_address={lb_ip}"),
                        ByNodeId(resource.chksum),
                    )


def link_pv_to_azure_disk(graph: Graph, resource: BaseResource) -> None:
    if resource.kind == "kubernetes_persistent_volume":
        if (
            (csi := rgetattr(resource, "persistent_volume_spec.csi", None))
            and (csi.get("driver") == "disk.csi.azure.com")
            and (vol_id := csi.get("volumeHandle"))
        ):
            graph.add_deferred_edge(
                BySearchCriteria(f"is(azure_disk) and reported.id={vol_id}"), ByNodeId(resource.chksum)
            )


def link_all(graph: Graph, resource: BaseResource) -> None:
    link_k8s_cluster_to_aks_cluster(graph, resource)
    link_service_to_azure_lb(graph, resource)
    link_pv_to_azure_disk(graph, resource)
