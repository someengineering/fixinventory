from fixlib.baseresources import BaseResource
from fixlib.graph import BySearchCriteria, ByNodeId, Graph
from fix_plugin_k8s.deferred_edges.utils import rgetattr


def link_node_to_do_droplet(graph: Graph, resource: BaseResource) -> None:
    if resource.kind == "kubernetes_node":
        if (pid := rgetattr(resource, "node_spec.provider_id", None)) and (pid.startswith("digitalocean://")):
            _, droplet_id = pid.split("digitalocean://")
            graph.add_deferred_edge(
                BySearchCriteria(f"is(digitalocean_droplet) and reported.id={droplet_id}"),
                ByNodeId(resource.chksum),
            )


def link_service_to_do_lb(graph: Graph, resource: BaseResource) -> None:
    if resource.kind == "kubernetes_service":
        if lb_id := resource.tags.get("kubernetes.digitalocean.com/load-balancer-id"):
            graph.add_deferred_edge(
                BySearchCriteria(f"is(digitalocean_load_balancer) and reported.id={lb_id}"),
                ByNodeId(resource.chksum),
            )


def link_pv_to_do_volume(graph: Graph, resource: BaseResource) -> None:
    if resource.kind == "kubernetes_persistent_volume":
        if (
            (csi := rgetattr(resource, "persistent_volume_spec.csi", None))
            and (csi.get("driver") == "dobs.csi.digitalocean.com")
            and (vol_id := csi.get("volumeHandle"))
        ):
            graph.add_deferred_edge(
                BySearchCriteria(f"is(digitalocean_volume) and reported.id={vol_id}"), ByNodeId(resource.chksum)
            )


def link_all(graph: Graph, resource: BaseResource) -> None:
    link_node_to_do_droplet(graph, resource)
    link_service_to_do_lb(graph, resource)
    link_pv_to_do_volume(graph, resource)
