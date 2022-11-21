from resotolib.baseplugin import BasePostCollectPlugin
from resotolib.baseresources import BaseResource
from resotolib.graph import BySearchCriteria, ByNodeId, Graph

from resotolib.logger import log
import functools
from typing import cast, Any, Set


def rgetattr(obj: Any, attr: str, *args: Any) -> Any:
    def _getattr(obj: Any, attr: str) -> Any:
        return getattr(obj, attr, *args)

    return functools.reduce(_getattr, [obj] + attr.split("."))


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


class DigitalOceanK8sCollectorPlugin(BasePostCollectPlugin):
    name = "digitalocean_k8s"
    activate_with: Set[str] = {"digitalocean", "k8s"}

    def post_collect(self, graph: Graph) -> None:
        log.info("plugin: collecting DigitalOcean to k8s edges")
        for node in graph.nodes:
            node = cast(BaseResource, node)
            link_node_to_do_droplet(graph, node)
            link_service_to_do_lb(graph, node)
            link_pv_to_do_volume(graph, node)
