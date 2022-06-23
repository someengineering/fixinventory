from resotolib.baseplugin import BasePostCollectPlugin
from resotolib.baseresources import BaseResource
from resotolib.graph import BySearchCriteria, ByNodeId, Graph

from resotolib.logger import log
import functools
from typing import cast, Any
from copy import deepcopy


def rgetattr(obj: Any, attr: str, *args: Any) -> Any:
    def _getattr(obj: Any, attr: str) -> Any:
        return getattr(obj, attr, *args)

    return functools.reduce(_getattr, [obj] + attr.split("."))


def link_do_droplet_to_node(graph: Graph, resource: BaseResource) -> None:
    if resource.kind == "kubernetes_node":
        if (pid := rgetattr(resource, "node_spec.provider_id", None)) and (pid.startswith("digitalocean://")):
            _, droplet_id = pid.split("digitalocean://")
            graph.add_deferred_edge(
                BySearchCriteria(f"is(digitalocean_droplet) and reported.id={droplet_id}"),
                ByNodeId(resource.chksum),
            )


def link_do_lb_to_service(graph: Graph, resource: BaseResource) -> None:
    if resource.kind == "kubernetes_service":
        if lb_id := resource.tags.get("kubernetes.digitalocean.com/load-balancer-id"):
            graph.add_deferred_edge(
                BySearchCriteria(f"is(digitalocean_load_balancer) and reported.id={lb_id}"),
                ByNodeId(resource.chksum),
            )


def link_do_volume_to_pv(graph: Graph, resource: BaseResource) -> None:
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

    def post_collect(self, graph: Graph) -> Graph:
        log.info("plugin: collecting DigitalOcean to k8s edges")
        _graph = deepcopy(graph)
        for node in graph.nodes:
            node = cast(BaseResource, node)
            link_do_droplet_to_node(_graph, node)
            link_do_lb_to_service(_graph, node)
            link_do_volume_to_pv(_graph, node)
        return _graph
