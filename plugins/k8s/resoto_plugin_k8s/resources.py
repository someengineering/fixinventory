import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import ClassVar, Optional, Dict, Type, List, Any

import jsons
from jsonbender import S, Bender, bend, OptionalS, K, F
from jsonbender.list_ops import ForallBend
from jsons import set_deserializer
from resoto_plugin_k8s.bender_opts import StringToUnitNumber, CPUCoresToNumber, Bend
from resotolib.baseresources import (
    BaseAccount,
    BaseResource,
    BaseInstance,
    BaseRegion,
    InstanceStatus,
    BaseVolume,
    BaseQuota,
    BaseLoadBalancer,
    EdgeType,
)
from resotolib.graph import Graph
from resotolib.types import Json

log = logging.getLogger("resoto.plugins.k8s")


@dataclass(eq=False)
class KubernetesResource(BaseResource):
    kind: ClassVar[str] = "kubernetes_resource"

    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("metadata", "uid"),
        "tags": OptionalS("metadata", "annotations", default={}),
        "name": S("metadata", "name"),
        "ctime": S("metadata", "creationTimestamp"),
        "resource_version": S("metadata", "resourceVersion"),
        "namespace": OptionalS("metadata", "namespace"),
        "labels": OptionalS("metadata", "labels", default={}),
        "_owner_references": OptionalS("metadata", "ownerReferences", default=[]),
    }

    resource_version: Optional[str] = None
    namespace: Optional[str] = None
    labels: Dict[str, str] = field(default_factory=dict)

    # private: holds all the owner references
    _owner_references: List[Json] = field(default_factory=list)

    def to_json(self) -> Json:
        return jsons.dump(  # type: ignore
            self,
            strip_privates=True,
            strip_nulls=True,
            strip_attr=(
                "k8s_name",
                "mapping",
                "phantom",
                "successor_kinds",
                "parent_resource",
                "usage_percentage",
                "dname",
                "kdname",
                "rtdname",
                "changes",
                "event_log",
                "str_event_log",
                "chksum",
                "age",
                "last_access",
                "last_update",
                "clean",
                "cleaned",
                "protected",
                "_graph",
                "graph",
                "max_graph_depth",
                "resource_type",
                "age",
                "last_access",
                "last_update",
                "clean",
                "cleaned",
                "protected",
                "uuid",
                "kind",
            ),
        )

    @classmethod
    def from_json(cls: Type["KubernetesResource"], json: Json) -> "KubernetesResource":
        mapped = bend(cls.mapping, json)
        return jsons.load(mapped, cls)

    @classmethod
    def k8s_name(cls: Type["KubernetesResource"]) -> str:
        return cls.__name__.removeprefix("Kubernetes")

    def update_tag(self, key, value) -> bool:
        raise NotImplementedError

    def delete_tag(self, key) -> bool:
        raise NotImplementedError

    def delete(self, graph) -> bool:
        raise NotImplementedError

    def owner_references(self) -> List[Json]:
        return self._owner_references


class GraphBuilder:
    def __init__(self, graph: Graph):
        self.graph = graph

    def node(self, clazz: Optional[type] = None, **node: Any) -> Optional[KubernetesResource]:
        for n in self.graph:
            is_clazz = isinstance(n, clazz) if clazz else True
            if is_clazz and all(getattr(n, k, None) == v for k, v in node.items()):
                return n
        return None

    def add_edge(
        self, from_node: KubernetesResource, edge_type: EdgeType, reverse: bool = False, **to_node: any
    ) -> None:
        to_n = self.node(**to_node)
        if to_n:
            start, end = (to_n, from_node) if reverse else (from_node, to_n)
            log.debug(f"Add edge: {start.name}:{start.k8s_name()} -> {end.name}:{end.k8s_name()}")
            self.graph.add_edge(start, end, edge_type=edge_type)

    def add_edges_from_selector(
        self,
        from_node: KubernetesResource,
        edge_type: EdgeType,
        selector: Dict[str, str],
        clazz: Optional[type] = None,
    ) -> None:
        for to_n in self.graph:
            is_clazz = isinstance(to_n, clazz) if clazz else True
            if is_clazz and to_n != from_node and selector.items() <= to_n.labels.items():
                log.debug(f"Add edge: {from_node.name}:{from_node.k8s_name()} -> {to_n.name}:{to_n.k8s_name()}")
                self.graph.add_edge(from_node, to_n, edge_type=edge_type)

    def connect_volumes(self, from_node: KubernetesResource, volumes: List[Json]) -> None:
        for volume in volumes:
            if "persistentVolumeClaim" in volume:
                name = volume["persistentVolumeClaim"]["claimName"]
                self.add_edge(
                    from_node,
                    EdgeType.default,
                    name=name,
                    namespace=from_node.namespace,
                    clazz=KubernetesPersistentVolumeClaim,
                )
            elif "configMap" in volume:
                name = volume["configMap"]["name"]
                self.add_edge(
                    from_node, EdgeType.default, name=name, namespace=from_node.namespace, clazz=KubernetesConfigMap
                )
            elif "secret" in volume:
                name = volume["secret"]["secretName"]
                self.add_edge(
                    from_node, EdgeType.default, name=name, namespace=from_node.namespace, clazz=KubernetesSecret
                )
            elif "projected" in volume:
                # iterate all projected volumes
                self.connect_volumes(from_node, volume["projected"]["sources"])


# region node


@dataclass(eq=False)
class KubernetesNodeStatusAddresses:
    kind: ClassVar[str] = "kubernetes_node_status_addresses"
    mapping: ClassVar[Dict[str, Bender]] = {
        "address": OptionalS("address"),
        "type": OptionalS("type"),
    }
    address: Optional[str] = field(default=None)
    type: Optional[str] = field(default=None)


@dataclass(eq=False)
class KubernetesNodeCondition:
    kind: ClassVar[str] = "kubernetes_node_status_conditions"
    mapping: ClassVar[Dict[str, Bender]] = {
        "last_heartbeat_time": OptionalS("lastHeartbeatTime"),
        "last_transition_time": OptionalS("lastTransitionTime"),
        "message": OptionalS("message"),
        "reason": OptionalS("reason"),
        "status": OptionalS("status"),
        "type": OptionalS("type"),
    }
    last_heartbeat_time: Optional[datetime] = field(default=None)
    last_transition_time: Optional[datetime] = field(default=None)
    message: Optional[str] = field(default=None)
    reason: Optional[str] = field(default=None)
    status: Optional[str] = field(default=None)
    type: Optional[str] = field(default=None)


@dataclass(eq=False)
class KubernetesNodeStatusConfigSource:
    kind: ClassVar[str] = "kubernetes_node_status_config_active_configmap"
    mapping: ClassVar[Dict[str, Bender]] = {
        "kubelet_config_key": OptionalS("kubeletConfigKey"),
        "name": OptionalS("name"),
        "namespace": OptionalS("namespace"),
        "resource_version": OptionalS("resourceVersion"),
        "uid": OptionalS("uid"),
    }
    kubelet_config_key: Optional[str] = field(default=None)
    name: Optional[str] = field(default=None)
    namespace: Optional[str] = field(default=None)
    resource_version: Optional[str] = field(default=None)
    uid: Optional[str] = field(default=None)


@dataclass(eq=False)
class KubernetesNodeConfigSource:
    kind: ClassVar[str] = "kubernetes_node_status_config_active"
    mapping: ClassVar[Dict[str, Bender]] = {
        "config_map": OptionalS("configMap") >> Bend(KubernetesNodeStatusConfigSource.mapping),
    }
    config_map: Optional[KubernetesNodeStatusConfigSource] = field(default=None)


@dataclass(eq=False)
class KubernetesNodeStatusConfig:
    kind: ClassVar[str] = "kubernetes_node_status_config"
    mapping: ClassVar[Dict[str, Bender]] = {
        "active": OptionalS("active") >> Bend(KubernetesNodeConfigSource.mapping),
        "assigned": OptionalS("assigned") >> Bend(KubernetesNodeConfigSource.mapping),
        "error": OptionalS("error"),
    }
    active: Optional[KubernetesNodeConfigSource] = field(default=None)
    assigned: Optional[KubernetesNodeConfigSource] = field(default=None)
    error: Optional[str] = field(default=None)


@dataclass(eq=False)
class KubernetesDaemonEndpoint:
    kind: ClassVar[str] = "kubernetes_daemon_endpoint"
    mapping: ClassVar[Dict[str, Bender]] = {
        "port": OptionalS("Port"),
    }
    port: Optional[int] = field(default=None)


@dataclass(eq=False)
class KubernetesNodeDaemonEndpoint:
    kind: ClassVar[str] = "kubernetes_node_daemon_endpoint"
    mapping: ClassVar[Dict[str, Bender]] = {
        "kubelet_endpoint": OptionalS("kubeletEndpoint") >> Bend(KubernetesDaemonEndpoint.mapping),
    }
    kubelet_endpoint: Optional[KubernetesDaemonEndpoint] = field(default=None)


@dataclass(eq=False)
class KubernetesNodeStatusImages:
    kind: ClassVar[str] = "kubernetes_node_status_images"
    mapping: ClassVar[Dict[str, Bender]] = {
        "names": OptionalS("names", default=[]),
        "size_bytes": OptionalS("sizeBytes", default=0),
    }
    names: List[str] = field(default_factory=list)
    size_bytes: Optional[int] = field(default=None)


@dataclass(eq=False)
class KubernetesNodeSystemInfo:
    kind: ClassVar[str] = "kubernetes_node_system_info"
    mapping: ClassVar[Dict[str, Bender]] = {
        "architecture": OptionalS("architecture"),
        "boot_id": OptionalS("bootID"),
        "container_runtime_version": OptionalS("containerRuntimeVersion"),
        "kernel_version": OptionalS("kernelVersion"),
        "kube_proxy_version": OptionalS("kubeProxyVersion"),
        "kubelet_version": OptionalS("kubeletVersion"),
        "machine_id": OptionalS("machineID"),
        "operating_system": OptionalS("operatingSystem"),
        "os_image": OptionalS("osImage"),
        "system_uuid": OptionalS("systemUUID"),
    }
    architecture: Optional[str] = field(default=None)
    boot_id: Optional[str] = field(default=None)
    container_runtime_version: Optional[str] = field(default=None)
    kernel_version: Optional[str] = field(default=None)
    kube_proxy_version: Optional[str] = field(default=None)
    kubelet_version: Optional[str] = field(default=None)
    machine_id: Optional[str] = field(default=None)
    operating_system: Optional[str] = field(default=None)
    os_image: Optional[str] = field(default=None)
    system_uuid: Optional[str] = field(default=None)


@dataclass(eq=False)
class KubernetesAttachedVolume:
    kind: ClassVar[str] = "kubernetes_attached_volume"
    mapping: ClassVar[Dict[str, Bender]] = {
        "device_path": OptionalS("devicePath"),
        "name": OptionalS("name"),
    }
    device_path: Optional[str] = field(default=None)
    name: Optional[str] = field(default=None)


@dataclass(eq=False)
class KubernetesNodeStatus:
    kind: ClassVar[str] = "kubernetes_node_status"
    mapping: ClassVar[Dict[str, Bender]] = {
        "addresses": OptionalS("addresses", default=[]) >> ForallBend(KubernetesNodeStatusAddresses.mapping),
        "conditions": OptionalS("conditions", default=[]) >> ForallBend(KubernetesNodeCondition.mapping),
        "config": OptionalS("config") >> Bend(KubernetesNodeStatusConfig.mapping),
        "capacity": OptionalS("capacity"),
        "daemon_endpoints": OptionalS("daemonEndpoints") >> Bend(KubernetesNodeDaemonEndpoint.mapping),
        "images": OptionalS("images", default=[]) >> ForallBend(KubernetesNodeStatusImages.mapping),
        "node_info": OptionalS("nodeInfo") >> Bend(KubernetesNodeSystemInfo.mapping),
        "phase": OptionalS("phase"),
        "volumes_attached": OptionalS("volumesAttached", default=[]) >> ForallBend(KubernetesAttachedVolume.mapping),
        "volumes_in_use": OptionalS("volumesInUse", default=[]),
    }
    addresses: List[KubernetesNodeStatusAddresses] = field(default_factory=list)
    capacity: Optional[Any] = field(default=None)
    conditions: List[KubernetesNodeCondition] = field(default_factory=list)
    config: Optional[KubernetesNodeStatusConfig] = field(default=None)
    daemon_endpoints: Optional[KubernetesNodeDaemonEndpoint] = field(default=None)
    images: List[KubernetesNodeStatusImages] = field(default_factory=list)
    node_info: Optional[KubernetesNodeSystemInfo] = field(default=None)
    phase: Optional[str] = field(default=None)
    volumes_attached: List[KubernetesAttachedVolume] = field(default_factory=list)
    volumes_in_use: List[str] = field(default_factory=list)


instance_status_map: ClassVar[Dict[str, str]] = {
    "Pending": InstanceStatus.BUSY,
    "Running": InstanceStatus.RUNNING,
    "Failed": InstanceStatus.TERMINATED,
    "Succeeded": InstanceStatus.STOPPED,
    "Unknown": InstanceStatus.UNKNOWN,
}


@dataclass(eq=False)
class KubernetesNode(KubernetesResource, BaseInstance):
    kind: ClassVar[str] = "kubernetes_node"
    mapping: ClassVar[Dict[str, Bender]] = KubernetesResource.mapping | {
        "node_status": OptionalS("status") >> Bend(KubernetesNodeStatus.mapping),
        "provider_id": S("spec", "providerID"),
        "instance_cores": S("status", "capacity", "cpu") >> CPUCoresToNumber(),
        "instance_memory": S("status", "capacity", "memory") >> StringToUnitNumber("GB"),
        "instance_type": K("kubernetes_node"),
        "instance_status": K(InstanceStatus.RUNNING.value),
    }
    provider_id: Optional[str] = None
    node_status: Optional[KubernetesNodeStatus] = field(default=None)

    def _instance_status_getter(self) -> str:
        return self._instance_status

    def _instance_status_setter(self, value: str) -> None:
        self._instance_status = value


# noinspection PyProtectedMember
KubernetesNode.instance_status = property(
    KubernetesNode._instance_status_getter, KubernetesNode._instance_status_setter
)
# endregion

# region pod


@dataclass(eq=False)
class KubernetesPodStatusConditions:
    kind: ClassVar[str] = "kubernetes_pod_status_conditions"
    mapping: ClassVar[Dict[str, Bender]] = {
        "last_probe_time": OptionalS("lastProbeTime"),
        "last_transition_time": OptionalS("lastTransitionTime"),
        "message": OptionalS("message"),
        "reason": OptionalS("reason"),
        "status": OptionalS("status"),
        "type": OptionalS("type"),
    }
    last_probe_time: Optional[datetime] = field(default=None)
    last_transition_time: Optional[datetime] = field(default=None)
    message: Optional[str] = field(default=None)
    reason: Optional[str] = field(default=None)
    status: Optional[str] = field(default=None)
    type: Optional[str] = field(default=None)


@dataclass(eq=False)
class KubernetesContainerStateRunning:
    kind: ClassVar[str] = "kubernetes_container_state_running"
    mapping: ClassVar[Dict[str, Bender]] = {
        "started_at": OptionalS("startedAt"),
    }
    started_at: Optional[datetime] = field(default=None)


@dataclass(eq=False)
class KubernetesContainerStateTerminated:
    kind: ClassVar[str] = "kubernetes_container_state_terminated"
    mapping: ClassVar[Dict[str, Bender]] = {
        "container_id": OptionalS("containerID"),
        "exit_code": OptionalS("exitCode"),
        "finished_at": OptionalS("finishedAt"),
        "message": OptionalS("message"),
        "reason": OptionalS("reason"),
        "signal": OptionalS("signal"),
        "started_at": OptionalS("startedAt"),
    }
    container_id: Optional[str] = field(default=None)
    exit_code: Optional[int] = field(default=None)
    finished_at: Optional[datetime] = field(default=None)
    message: Optional[str] = field(default=None)
    reason: Optional[str] = field(default=None)
    signal: Optional[int] = field(default=None)
    started_at: Optional[datetime] = field(default=None)


@dataclass(eq=False)
class KubernetesContainerStateWaiting:
    kind: ClassVar[str] = "kubernetes_container_state_waiting"
    mapping: ClassVar[Dict[str, Bender]] = {
        "message": OptionalS("message"),
        "reason": OptionalS("reason"),
    }
    message: Optional[str] = field(default=None)
    reason: Optional[str] = field(default=None)


@dataclass(eq=False)
class KubernetesContainerState:
    kind: ClassVar[str] = "kubernetes_container_state"
    mapping: ClassVar[Dict[str, Bender]] = {
        "running": OptionalS("running") >> Bend(KubernetesContainerStateRunning.mapping),
        "terminated": OptionalS("terminated") >> Bend(KubernetesContainerStateTerminated.mapping),
        "waiting": OptionalS("waiting") >> Bend(KubernetesContainerStateWaiting.mapping),
    }
    running: Optional[KubernetesContainerStateRunning] = field(default=None)
    terminated: Optional[KubernetesContainerStateTerminated] = field(default=None)
    waiting: Optional[KubernetesContainerStateWaiting] = field(default=None)


@dataclass(eq=False)
class KubernetesContainerStatus:
    kind: ClassVar[str] = "kubernetes_container_status"
    mapping: ClassVar[Dict[str, Bender]] = {
        "container_id": OptionalS("containerID"),
        "image": OptionalS("image"),
        "image_id": OptionalS("imageID"),
        "last_state": OptionalS("lastState") >> Bend(KubernetesContainerState.mapping),
        "name": OptionalS("name"),
        "ready": OptionalS("ready"),
        "restart_count": OptionalS("restartCount"),
        "started": OptionalS("started"),
        "state": OptionalS("state") >> Bend(KubernetesContainerState.mapping),
    }
    container_id: Optional[str] = field(default=None)
    image: Optional[str] = field(default=None)
    image_id: Optional[str] = field(default=None)
    last_state: Optional[KubernetesContainerState] = field(default=None)
    name: Optional[str] = field(default=None)
    ready: Optional[bool] = field(default=None)
    restart_count: Optional[int] = field(default=None)
    started: Optional[bool] = field(default=None)
    state: Optional[KubernetesContainerState] = field(default=None)


@dataclass(eq=False)
class KubernetesPodIPs:
    kind: ClassVar[str] = "kubernetes_pod_ips"
    mapping: ClassVar[Dict[str, Bender]] = {"ip": OptionalS("ip")}
    ip: Optional[str] = field(default=None)


@dataclass(eq=False)
class KubernetesPodStatus:
    kind: ClassVar[str] = "kubernetes_pod_status"
    mapping: ClassVar[Dict[str, Bender]] = {
        "conditions": OptionalS("conditions", default=[]) >> ForallBend(KubernetesPodStatusConditions.mapping),
        "container_statuses": OptionalS("containerStatuses", default=[])
        >> ForallBend(KubernetesContainerStatus.mapping),
        "ephemeral_container_statuses": OptionalS("ephemeralContainerStatuses", default=[])
        >> ForallBend(KubernetesContainerState.mapping),
        "host_ip": OptionalS("hostIP"),
        "init_container_statuses": OptionalS("initContainerStatuses", default=[])
        >> ForallBend(KubernetesContainerStatus.mapping),
        "message": OptionalS("message"),
        "nominated_node_name": OptionalS("nominatedNodeName"),
        "phase": OptionalS("phase"),
        "pod_ip": OptionalS("podIP"),
        "pod_ips": OptionalS("podIPs", default=[]) >> ForallBend(KubernetesPodIPs.mapping),
        "qos_class": OptionalS("qosClass"),
        "reason": OptionalS("reason"),
        "start_time": OptionalS("startTime"),
    }
    conditions: List[KubernetesPodStatusConditions] = field(default_factory=list)
    container_statuses: List[KubernetesContainerStatus] = field(default_factory=list)
    ephemeral_container_statuses: List[KubernetesContainerState] = field(default_factory=list)
    host_ip: Optional[str] = field(default=None)
    init_container_statuses: List[KubernetesContainerStatus] = field(default_factory=list)
    message: Optional[str] = field(default=None)
    nominated_node_name: Optional[str] = field(default=None)
    phase: Optional[str] = field(default=None)
    pod_ip: Optional[str] = field(default=None)
    pod_ips: List[KubernetesPodIPs] = field(default_factory=list)
    qos_class: Optional[str] = field(default=None)
    reason: Optional[str] = field(default=None)
    start_time: Optional[datetime] = field(default=None)


@dataclass(eq=False)
class KubernetesPod(KubernetesResource):
    kind: ClassVar[str] = "kubernetes_pod"
    mapping: ClassVar[Dict[str, Bender]] = KubernetesResource.mapping | {
        "pod_status": OptionalS("status") >> Bend(KubernetesPodStatus.mapping),
        "_volumes": OptionalS("spec", "volumes", default=[]),
    }
    pod_status: Optional[KubernetesPodStatus] = field(default=None)
    # private fields for lookup
    _volumes: List[Json] = field(default_factory=list)

    def connect_in_graph(self, builder: GraphBuilder) -> None:
        builder.connect_volumes(self, self._volumes)


# endregion

# region persistent volume claim
@dataclass(eq=False)
class KubernetesPersistentVolumeClaimStatusConditions:
    kind: ClassVar[str] = "kubernetes_persistent_volume_claim_status_conditions"
    mapping: ClassVar[Dict[str, Bender]] = {
        "last_probe_time": OptionalS("lastProbeTime"),
        "last_transition_time": OptionalS("lastTransitionTime"),
        "message": OptionalS("message"),
        "reason": OptionalS("reason"),
        "status": OptionalS("status"),
        "type": OptionalS("type"),
    }
    last_probe_time: Optional[datetime] = field(default=None)
    last_transition_time: Optional[datetime] = field(default=None)
    message: Optional[str] = field(default=None)
    reason: Optional[str] = field(default=None)
    status: Optional[str] = field(default=None)
    type: Optional[str] = field(default=None)


@dataclass(eq=False)
class KubernetesPersistentVolumeClaimStatus:
    kind: ClassVar[str] = "kubernetes_persistent_volume_claim_status"
    mapping: ClassVar[Dict[str, Bender]] = {
        "access_modes": OptionalS("accessModes", default=[]),
        "allocated_resources": OptionalS("allocatedResources"),
        "conditions": OptionalS("conditions", default=[])
        >> ForallBend(KubernetesPersistentVolumeClaimStatusConditions.mapping),
        "phase": OptionalS("phase"),
        "resize_status": OptionalS("resizeStatus"),
    }
    access_modes: List[str] = field(default_factory=list)
    allocated_resources: Optional[str] = field(default=None)
    conditions: List[KubernetesPersistentVolumeClaimStatusConditions] = field(default_factory=list)
    phase: Optional[str] = field(default=None)
    resize_status: Optional[str] = field(default=None)


@dataclass(eq=False)
class KubernetesPersistentVolumeClaim(KubernetesResource):
    kind: ClassVar[str] = "kubernetes_persistent_volume_claim"
    mapping: ClassVar[Dict[str, Bender]] = KubernetesResource.mapping | {
        "persistent_volume_claim_status": OptionalS("status") >> Bend(KubernetesPersistentVolumeClaimStatus.mapping),
    }
    persistent_volume_claim_status: Optional[KubernetesPersistentVolumeClaimStatus] = field(default=None)


# endregion
# region service


@dataclass(eq=False)
class KubernetesLoadbalancerIngressPorts:
    kind: ClassVar[str] = "kubernetes_loadbalancer_ingress_ports"
    mapping: ClassVar[Dict[str, Bender]] = {
        "error": OptionalS("error"),
        "port": OptionalS("port"),
        "protocol": OptionalS("protocol"),
    }
    error: Optional[str] = field(default=None)
    port: Optional[int] = field(default=None)
    protocol: Optional[str] = field(default=None)


@dataclass(eq=False)
class KubernetesLoadbalancerIngress:
    kind: ClassVar[str] = "kubernetes_loadbalancer_ingress"
    mapping: ClassVar[Dict[str, Bender]] = {
        "hostname": OptionalS("hostname"),
        "ip": OptionalS("ip"),
        "ports": OptionalS("ports", default=[]) >> ForallBend(KubernetesLoadbalancerIngressPorts.mapping),
    }
    hostname: Optional[str] = field(default=None)
    ip: Optional[str] = field(default=None)
    ports: List[KubernetesLoadbalancerIngressPorts] = field(default_factory=list)


@dataclass(eq=False)
class KubernetesLoadbalancerStatus:
    kind: ClassVar[str] = "kubernetes_loadbalancer_status"
    mapping: ClassVar[Dict[str, Bender]] = {
        "ingress": OptionalS("ingress", default=[]) >> ForallBend(KubernetesLoadbalancerIngress.mapping),
    }
    ingress: List[KubernetesLoadbalancerIngress] = field(default_factory=list)


@dataclass(eq=False)
class KubernetesServiceStatusConditions:
    kind: ClassVar[str] = "kubernetes_service_status_conditions"
    mapping: ClassVar[Dict[str, Bender]] = {
        "last_transition_time": OptionalS("lastTransitionTime"),
        "message": OptionalS("message"),
        "observed_generation": OptionalS("observedGeneration"),
        "reason": OptionalS("reason"),
        "status": OptionalS("status"),
        "type": OptionalS("type"),
    }
    last_transition_time: Optional[datetime] = field(default=None)
    message: Optional[str] = field(default=None)
    observed_generation: Optional[int] = field(default=None)
    reason: Optional[str] = field(default=None)
    status: Optional[str] = field(default=None)
    type: Optional[str] = field(default=None)


@dataclass(eq=False)
class KubernetesServiceStatus:
    kind: ClassVar[str] = "kubernetes_service_status"
    mapping: ClassVar[Dict[str, Bender]] = {
        "conditions": OptionalS("conditions", default=[]) >> ForallBend(KubernetesServiceStatusConditions.mapping),
        "load_balancer": OptionalS("loadBalancer") >> Bend(KubernetesLoadbalancerStatus.mapping),
    }
    conditions: List[KubernetesServiceStatusConditions] = field(default_factory=list)
    load_balancer: Optional[KubernetesLoadbalancerStatus] = field(default=None)


@dataclass(eq=False)
class KubernetesService(KubernetesResource):
    kind: ClassVar[str] = "kubernetes_service"
    mapping: ClassVar[Dict[str, Bender]] = KubernetesResource.mapping | {
        "service_status": OptionalS("status") >> Bend(KubernetesServiceStatus.mapping),
        "_selector": OptionalS("spec", "selector"),
    }
    service_status: Optional[KubernetesServiceStatus] = field(default=None)
    _selector: Optional[Dict[str, str]] = field(default=None)

    def connect_in_graph(self, builder: GraphBuilder) -> None:
        if self._selector:
            builder.add_edges_from_selector(self, EdgeType.default, self._selector, KubernetesPod)


# endregion


@dataclass(eq=False)
class KubernetesPodTemplate(KubernetesResource):
    kind: ClassVar[str] = "kubernetes_pod_template"


@dataclass(eq=False)
class KubernetesClusterInfo:
    kind: ClassVar[str] = "kubernetes_cluster_info"
    major: str
    minor: str
    platform: str


@dataclass(eq=False)
class KubernetesCluster(KubernetesResource, BaseAccount):
    kind: ClassVar[str] = "kubernetes_cluster"
    cluster_info: Optional[KubernetesClusterInfo] = None


@dataclass(eq=False)
class KubernetesConfigMap(KubernetesResource):
    kind: ClassVar[str] = "kubernetes_config_map"


@dataclass(eq=False)
class KubernetesEndpointAddress:
    kind: ClassVar[str] = "kubernetes_endpoint_address"
    mapping: ClassVar[Dict[str, Bender]] = {
        "ip": OptionalS("ip"),
        "node_name": OptionalS("nodeName"),
        "_target_ref": OptionalS("targetRef", "uid"),
    }

    ip: Optional[str] = field(default=None)
    node_name: Optional[str] = field(default=None)
    _target_ref: Optional[str] = field(default=None)

    def target_ref(self) -> Optional[str]:
        return self._target_ref


@dataclass(eq=False)
class KubernetesEndpointPort:
    kind: ClassVar[str] = "kubernetes_endpoint_port"
    mapping: ClassVar[Dict[str, Bender]] = {
        "name": OptionalS("name"),
        "port": OptionalS("port"),
        "protocol": OptionalS("protocol"),
    }

    name: Optional[str] = field(default=None)
    port: Optional[int] = field(default=None)
    protocol: Optional[str] = field(default=None)


@dataclass(eq=False)
class KubernetesEndpointSubset:
    kind: ClassVar[str] = "kubernetes_endpoint_subset"
    mapping: ClassVar[Dict[str, Bender]] = {
        "addresses": OptionalS("addresses", default=[]) >> ForallBend(KubernetesEndpointAddress.mapping),
        "ports": OptionalS("ports", default=[]) >> ForallBend(KubernetesEndpointPort.mapping),
    }
    addresses: List[KubernetesEndpointAddress] = field(default_factory=list)
    ports: List[KubernetesEndpointPort] = field(default_factory=list)


@dataclass(eq=False)
class KubernetesEndpoints(KubernetesResource):
    kind: ClassVar[str] = "kubernetes_endpoint"
    mapping: ClassVar[Dict[str, Bender]] = KubernetesResource.mapping | {
        "subsets": OptionalS("subsets", default=[]) >> ForallBend(KubernetesEndpointSubset.mapping),
    }

    subsets: List[KubernetesEndpointSubset] = field(default_factory=list)

    def connect_in_graph(self, builder: GraphBuilder) -> None:
        for subset in self.subsets:
            for address in subset.addresses:
                if address.target_ref():
                    builder.add_edge(self, EdgeType.default, id=address.target_ref())


@dataclass(eq=False)
class KubernetesEndpointSlice(KubernetesResource):
    kind: ClassVar[str] = "kubernetes_endpoint_slice"


@dataclass(eq=False)
class KubernetesEvent(KubernetesResource):
    kind: ClassVar[str] = "kubernetes_event"


@dataclass(eq=False)
class KubernetesLimitRange(KubernetesResource):
    kind: ClassVar[str] = "kubernetes_limit_range"


@dataclass(eq=False)
class KubernetesNamespaceStatusConditions:
    kind: ClassVar[str] = "kubernetes_namespace_status_conditions"
    mapping: ClassVar[Dict[str, Bender]] = {
        "last_transition_time": OptionalS("lastTransitionTime"),
        "message": OptionalS("message"),
        "reason": OptionalS("reason"),
        "status": OptionalS("status"),
        "type": OptionalS("type"),
    }
    last_transition_time: Optional[datetime] = field(default=None)
    message: Optional[str] = field(default=None)
    reason: Optional[str] = field(default=None)
    status: Optional[str] = field(default=None)
    type: Optional[str] = field(default=None)


@dataclass(eq=False)
class KubernetesNamespaceStatus:
    kind: ClassVar[str] = "kubernetes_namespace_status"
    mapping: ClassVar[Dict[str, Bender]] = {
        "conditions": OptionalS("conditions", default=[]) >> ForallBend(KubernetesNamespaceStatusConditions.mapping),
        "phase": OptionalS("phase"),
    }
    conditions: List[KubernetesNamespaceStatusConditions] = field(default_factory=list)
    phase: Optional[str] = field(default=None)


@dataclass(eq=False)
class KubernetesNamespace(KubernetesResource, BaseRegion):
    kind: ClassVar[str] = "kubernetes_namespace"
    mapping: ClassVar[Dict[str, Bender]] = KubernetesResource.mapping | {
        "namespace_status": OptionalS("status") >> Bend(KubernetesNamespaceStatus.mapping),
    }
    namespace_status: Optional[KubernetesNamespaceStatus] = field(default=None)


@dataclass(eq=False)
class KubernetesPersistentVolumeStatus:
    kind: ClassVar[str] = "kubernetes_persistent_volume_status"
    mapping: ClassVar[Dict[str, Bender]] = {
        "message": OptionalS("message"),
        "phase": OptionalS("phase"),
        "reason": OptionalS("reason"),
    }
    message: Optional[str] = field(default=None)
    phase: Optional[str] = field(default=None)
    reason: Optional[str] = field(default=None)


@dataclass(eq=False)
class KubernetesPersistentVolume(KubernetesResource, BaseVolume):
    kind: ClassVar[str] = "kubernetes_persistent_volume"
    mapping: ClassVar[Dict[str, Bender]] = KubernetesResource.mapping | {
        "persistent_volume_status": OptionalS("status") >> Bend(KubernetesPersistentVolumeStatus.mapping),
        "volume_size": OptionalS("spec", "capacity", "storage", default="0") >> StringToUnitNumber("GB"),
        "volume_type": OptionalS("spec", "storageClassName"),
        "volume_status": OptionalS("status", "phase"),
        "_claim_reference": OptionalS("spec", "claimRef", "uid"),
    }
    persistent_volume_status: Optional[KubernetesPersistentVolumeStatus] = field(default=None)
    _claim_reference: Optional[str] = field(default=None)

    def _volume_status_getter(self) -> str:
        return self._volume_status

    def _volume_status_setter(self, value: Optional[str]) -> None:
        self._volume_status = value

    def connect_in_graph(self, builder: GraphBuilder) -> None:
        if self._claim_reference:
            builder.add_edge(self, EdgeType.default, id=self._claim_reference)


KubernetesPersistentVolume.volume_status = property(
    KubernetesPersistentVolume._volume_status_getter, KubernetesPersistentVolume._volume_status_setter
)


@dataclass(eq=False)
class KubernetesReplicationControllerStatusConditions:
    kind: ClassVar[str] = "kubernetes_replication_controller_status_conditions"
    mapping: ClassVar[Dict[str, Bender]] = {
        "last_transition_time": OptionalS("lastTransitionTime"),
        "message": OptionalS("message"),
        "reason": OptionalS("reason"),
        "status": OptionalS("status"),
        "type": OptionalS("type"),
    }
    last_transition_time: Optional[datetime] = field(default=None)
    message: Optional[str] = field(default=None)
    reason: Optional[str] = field(default=None)
    status: Optional[str] = field(default=None)
    type: Optional[str] = field(default=None)


@dataclass(eq=False)
class KubernetesReplicationControllerStatus:
    kind: ClassVar[str] = "kubernetes_replication_controller_status"
    mapping: ClassVar[Dict[str, Bender]] = {
        "available_replicas": OptionalS("availableReplicas"),
        "conditions": OptionalS("conditions", default=[])
        >> ForallBend(KubernetesReplicationControllerStatusConditions.mapping),
        "fully_labeled_replicas": OptionalS("fullyLabeledReplicas"),
        "observed_generation": OptionalS("observedGeneration"),
        "ready_replicas": OptionalS("readyReplicas"),
        "replicas": OptionalS("replicas"),
    }
    available_replicas: Optional[int] = field(default=None)
    conditions: List[KubernetesReplicationControllerStatusConditions] = field(default_factory=list)
    fully_labeled_replicas: Optional[int] = field(default=None)
    observed_generation: Optional[int] = field(default=None)
    ready_replicas: Optional[int] = field(default=None)
    replicas: Optional[int] = field(default=None)


@dataclass(eq=False)
class KubernetesReplicationController(KubernetesResource):
    kind: ClassVar[str] = "kubernetes_replication_controller"
    mapping: ClassVar[Dict[str, Bender]] = KubernetesResource.mapping | {
        "replication_controller_status": OptionalS("status") >> Bend(KubernetesReplicationControllerStatus.mapping),
    }
    replication_controller_status: Optional[KubernetesReplicationControllerStatus] = field(default=None)


@dataclass(eq=False)
class KubernetesResourceQuotaStatus:
    kind: ClassVar[str] = "kubernetes_resource_quota_status"
    mapping: ClassVar[Dict[str, Bender]] = {
        "hard": OptionalS("hard"),
        "used": OptionalS("used"),
    }
    hard: Optional[Any] = field(default=None)
    used: Optional[Any] = field(default=None)


@dataclass(eq=False)
class KubernetesResourceQuota(KubernetesResource, BaseQuota):
    kind: ClassVar[str] = "kubernetes_resource_quota"
    mapping: ClassVar[Dict[str, Bender]] = KubernetesResource.mapping | {
        "resource_quota_status": OptionalS("status") >> Bend(KubernetesResourceQuotaStatus.mapping),
    }
    resource_quota_status: Optional[KubernetesResourceQuotaStatus] = field(default=None)


@dataclass(eq=False)
class KubernetesSecret(KubernetesResource):
    kind: ClassVar[str] = "kubernetes_secret"


@dataclass(eq=False)
class KubernetesServiceAccount(KubernetesResource):
    kind: ClassVar[str] = "kubernetes_service_account"
    mapping: ClassVar[Dict[str, Bender]] = KubernetesResource.mapping | {
        "_secrets": OptionalS("secrets", default=[]),
    }

    _secrets: List[Json] = field(default_factory=list)

    def connect_in_graph(self, builder: GraphBuilder) -> None:
        for secret in self._secrets:
            if name := secret.get("name", None):
                builder.add_edge(self, EdgeType.default, clazz=KubernetesSecret, name=name)


@dataclass(eq=False)
class KubernetesMutatingWebhookConfiguration(KubernetesResource):
    kind: ClassVar[str] = "kubernetes_mutating_webhook_configuration"


@dataclass(eq=False)
class KubernetesValidatingWebhookConfiguration(KubernetesResource):
    kind: ClassVar[str] = "kubernetes_validating_webhook_configuration"


@dataclass(eq=False)
class KubernetesControllerRevision(KubernetesResource):
    kind: ClassVar[str] = "kubernetes_controller_revision"


@dataclass(eq=False)
class KubernetesDaemonSetStatusConditions:
    kind: ClassVar[str] = "kubernetes_daemon_set_status_conditions"
    mapping: ClassVar[Dict[str, Bender]] = {
        "last_transition_time": OptionalS("lastTransitionTime"),
        "message": OptionalS("message"),
        "reason": OptionalS("reason"),
        "status": OptionalS("status"),
        "type": OptionalS("type"),
    }
    last_transition_time: Optional[datetime] = field(default=None)
    message: Optional[str] = field(default=None)
    reason: Optional[str] = field(default=None)
    status: Optional[str] = field(default=None)
    type: Optional[str] = field(default=None)


@dataclass(eq=False)
class KubernetesDaemonSetStatus:
    kind: ClassVar[str] = "kubernetes_daemon_set_status"
    mapping: ClassVar[Dict[str, Bender]] = {
        "collision_count": OptionalS("collisionCount"),
        "conditions": OptionalS("conditions", default=[]) >> ForallBend(KubernetesDaemonSetStatusConditions.mapping),
        "current_number_scheduled": OptionalS("currentNumberScheduled"),
        "desired_number_scheduled": OptionalS("desiredNumberScheduled"),
        "number_available": OptionalS("numberAvailable"),
        "number_misscheduled": OptionalS("numberMisscheduled"),
        "number_ready": OptionalS("numberReady"),
        "number_unavailable": OptionalS("numberUnavailable"),
        "observed_generation": OptionalS("observedGeneration"),
        "updated_number_scheduled": OptionalS("updatedNumberScheduled"),
    }
    collision_count: Optional[int] = field(default=None)
    conditions: List[KubernetesDaemonSetStatusConditions] = field(default_factory=list)
    current_number_scheduled: Optional[int] = field(default=None)
    desired_number_scheduled: Optional[int] = field(default=None)
    number_available: Optional[int] = field(default=None)
    number_misscheduled: Optional[int] = field(default=None)
    number_ready: Optional[int] = field(default=None)
    number_unavailable: Optional[int] = field(default=None)
    observed_generation: Optional[int] = field(default=None)
    updated_number_scheduled: Optional[int] = field(default=None)


@dataclass(eq=False)
class KubernetesDaemonSet(KubernetesResource):
    kind: ClassVar[str] = "kubernetes_daemon_set"
    mapping: ClassVar[Dict[str, Bender]] = KubernetesResource.mapping | {
        "daemon_set_status": OptionalS("status") >> Bend(KubernetesDaemonSetStatus.mapping),
    }
    daemon_set_status: Optional[KubernetesDaemonSetStatus] = field(default=None)


@dataclass(eq=False)
class KubernetesDeploymentStatusCondition:
    kind: ClassVar[str] = "kubernetes_deployment_status_condition"
    mapping: ClassVar[Dict[str, Bender]] = {
        "last_transition_time": OptionalS("lastTransitionTime"),
        "last_update_time": OptionalS("lastUpdateTime"),
        "message": OptionalS("message"),
        "reason": OptionalS("reason"),
        "status": OptionalS("status"),
        "type": OptionalS("type"),
    }
    last_transition_time: Optional[datetime] = field(default=None)
    last_update_time: Optional[datetime] = field(default=None)
    message: Optional[str] = field(default=None)
    reason: Optional[str] = field(default=None)
    status: Optional[str] = field(default=None)
    type: Optional[str] = field(default=None)


@dataclass(eq=False)
class KubernetesDeploymentStatus:
    kind: ClassVar[str] = "kubernetes_deployment_status"
    mapping: ClassVar[Dict[str, Bender]] = {
        "available_replicas": OptionalS("availableReplicas"),
        "collision_count": OptionalS("collisionCount"),
        "conditions": OptionalS("conditions", default=[]) >> ForallBend(KubernetesDeploymentStatusCondition.mapping),
        "observed_generation": OptionalS("observedGeneration"),
        "ready_replicas": OptionalS("readyReplicas"),
        "replicas": OptionalS("replicas"),
        "unavailable_replicas": OptionalS("unavailableReplicas"),
        "updated_replicas": OptionalS("updatedReplicas"),
    }
    available_replicas: Optional[int] = field(default=None)
    collision_count: Optional[int] = field(default=None)
    conditions: List[KubernetesDeploymentStatusCondition] = field(default_factory=list)
    observed_generation: Optional[int] = field(default=None)
    ready_replicas: Optional[int] = field(default=None)
    replicas: Optional[int] = field(default=None)
    unavailable_replicas: Optional[int] = field(default=None)
    updated_replicas: Optional[int] = field(default=None)


@dataclass(eq=False)
class KubernetesDeployment(KubernetesResource):
    kind: ClassVar[str] = "kubernetes_deployment"
    mapping: ClassVar[Dict[str, Bender]] = KubernetesResource.mapping | {
        "deployment_status": OptionalS("status") >> Bend(KubernetesDeploymentStatus.mapping),
        "_selector": OptionalS("spec", "selector", "matchLabels"),
    }
    deployment_status: Optional[KubernetesDeploymentStatus] = field(default=None)
    _selector: Optional[Dict[str, str]] = field(default=None)

    def connect_in_graph(self, builder: GraphBuilder) -> None:
        if self._selector:
            builder.add_edges_from_selector(self, EdgeType.default, self._selector)


@dataclass(eq=False)
class KubernetesReplicaSetStatusCondition:
    kind: ClassVar[str] = "kubernetes_replica_set_status_conditions"
    mapping: ClassVar[Dict[str, Bender]] = {
        "last_transition_time": OptionalS("lastTransitionTime"),
        "message": OptionalS("message"),
        "reason": OptionalS("reason"),
        "status": OptionalS("status"),
        "type": OptionalS("type"),
    }
    last_transition_time: Optional[datetime] = field(default=None)
    message: Optional[str] = field(default=None)
    reason: Optional[str] = field(default=None)
    status: Optional[str] = field(default=None)
    type: Optional[str] = field(default=None)


@dataclass(eq=False)
class KubernetesReplicaSetStatus:
    kind: ClassVar[str] = "kubernetes_replica_set_status"
    mapping: ClassVar[Dict[str, Bender]] = {
        "available_replicas": OptionalS("availableReplicas"),
        "conditions": OptionalS("conditions", default=[]) >> ForallBend(KubernetesReplicaSetStatusCondition.mapping),
        "fully_labeled_replicas": OptionalS("fullyLabeledReplicas"),
        "observed_generation": OptionalS("observedGeneration"),
        "ready_replicas": OptionalS("readyReplicas"),
        "replicas": OptionalS("replicas"),
    }
    available_replicas: Optional[int] = field(default=None)
    conditions: List[KubernetesReplicaSetStatusCondition] = field(default_factory=list)
    fully_labeled_replicas: Optional[int] = field(default=None)
    observed_generation: Optional[int] = field(default=None)
    ready_replicas: Optional[int] = field(default=None)
    replicas: Optional[int] = field(default=None)


@dataclass(eq=False)
class KubernetesReplicaSet(KubernetesResource):
    kind: ClassVar[str] = "kubernetes_replica_set"
    mapping: ClassVar[Dict[str, Bender]] = KubernetesResource.mapping | {
        "replica_set_status": OptionalS("status") >> Bend(KubernetesReplicaSetStatus.mapping),
    }
    replica_set_status: Optional[KubernetesReplicaSetStatus] = field(default=None)


@dataclass(eq=False)
class KubernetesStatefulSetStatusCondition:
    kind: ClassVar[str] = "kubernetes_stateful_set_status_condition"
    mapping: ClassVar[Dict[str, Bender]] = {
        "last_transition_time": OptionalS("lastTransitionTime"),
        "message": OptionalS("message"),
        "reason": OptionalS("reason"),
        "status": OptionalS("status"),
        "type": OptionalS("type"),
    }
    last_transition_time: Optional[datetime] = field(default=None)
    message: Optional[str] = field(default=None)
    reason: Optional[str] = field(default=None)
    status: Optional[str] = field(default=None)
    type: Optional[str] = field(default=None)


@dataclass(eq=False)
class KubernetesStatefulSetStatus:
    kind: ClassVar[str] = "kubernetes_stateful_set_status"
    mapping: ClassVar[Dict[str, Bender]] = {
        "available_replicas": OptionalS("availableReplicas"),
        "collision_count": OptionalS("collisionCount"),
        "conditions": OptionalS("conditions", default=[]) >> ForallBend(KubernetesStatefulSetStatusCondition.mapping),
        "current_replicas": OptionalS("currentReplicas"),
        "current_revision": OptionalS("currentRevision"),
        "observed_generation": OptionalS("observedGeneration"),
        "ready_replicas": OptionalS("readyReplicas"),
        "replicas": OptionalS("replicas"),
        "update_revision": OptionalS("updateRevision"),
        "updated_replicas": OptionalS("updatedReplicas"),
    }
    available_replicas: Optional[int] = field(default=None)
    collision_count: Optional[int] = field(default=None)
    conditions: List[KubernetesStatefulSetStatusCondition] = field(default_factory=list)
    current_replicas: Optional[int] = field(default=None)
    current_revision: Optional[str] = field(default=None)
    observed_generation: Optional[int] = field(default=None)
    ready_replicas: Optional[int] = field(default=None)
    replicas: Optional[int] = field(default=None)
    update_revision: Optional[str] = field(default=None)
    updated_replicas: Optional[int] = field(default=None)


@dataclass(eq=False)
class KubernetesStatefulSet(KubernetesResource):
    kind: ClassVar[str] = "kubernetes_stateful_set"
    mapping: ClassVar[Dict[str, Bender]] = KubernetesResource.mapping | {
        "stateful_set_status": OptionalS("status") >> Bend(KubernetesStatefulSetStatus.mapping),
    }
    stateful_set_status: Optional[KubernetesStatefulSetStatus] = field(default=None)


@dataclass(eq=False)
class KubernetesHorizontalPodAutoscalerStatus:
    kind: ClassVar[str] = "kubernetes_horizontal_pod_autoscaler_status"
    mapping: ClassVar[Dict[str, Bender]] = {
        "current_cpu_utilization_percentage": OptionalS("currentCPUUtilizationPercentage"),
        "current_replicas": OptionalS("currentReplicas"),
        "desired_replicas": OptionalS("desiredReplicas"),
        "last_scale_time": OptionalS("lastScaleTime"),
        "observed_generation": OptionalS("observedGeneration"),
    }
    current_cpu_utilization_percentage: Optional[int] = field(default=None)
    current_replicas: Optional[int] = field(default=None)
    desired_replicas: Optional[int] = field(default=None)
    last_scale_time: Optional[datetime] = field(default=None)
    observed_generation: Optional[int] = field(default=None)


@dataclass(eq=False)
class KubernetesHorizontalPodAutoscaler(KubernetesResource):
    kind: ClassVar[str] = "kubernetes_horizontal_pod_autoscaler"
    mapping: ClassVar[Dict[str, Bender]] = KubernetesResource.mapping | {
        "horizontal_pod_autoscaler_status": OptionalS("status")
        >> Bend(KubernetesHorizontalPodAutoscalerStatus.mapping),
    }
    horizontal_pod_autoscaler_status: Optional[KubernetesHorizontalPodAutoscalerStatus] = field(default=None)


@dataclass(eq=False)
class KubernetesCronJobStatusActive:
    kind: ClassVar[str] = "kubernetes_cron_job_status_active"
    mapping: ClassVar[Dict[str, Bender]] = {
        "api_version": OptionalS("apiVersion"),
        "field_path": OptionalS("fieldPath"),
        "name": OptionalS("name"),
        "namespace": OptionalS("namespace"),
        "resource_version": OptionalS("resourceVersion"),
        "uid": OptionalS("uid"),
    }
    api_version: Optional[str] = field(default=None)
    field_path: Optional[str] = field(default=None)
    name: Optional[str] = field(default=None)
    namespace: Optional[str] = field(default=None)
    resource_version: Optional[str] = field(default=None)
    uid: Optional[str] = field(default=None)


@dataclass(eq=False)
class KubernetesCronJobStatus:
    kind: ClassVar[str] = "kubernetes_cron_job_status"
    mapping: ClassVar[Dict[str, Bender]] = {
        "active": OptionalS("active", default=[]) >> ForallBend(KubernetesCronJobStatusActive.mapping),
        "last_schedule_time": OptionalS("lastScheduleTime"),
        "last_successful_time": OptionalS("lastSuccessfulTime"),
    }
    active: List[KubernetesCronJobStatusActive] = field(default_factory=list)
    last_schedule_time: Optional[datetime] = field(default=None)
    last_successful_time: Optional[datetime] = field(default=None)


@dataclass(eq=False)
class KubernetesCronJob(KubernetesResource):
    kind: ClassVar[str] = "kubernetes_cron_job"
    mapping: ClassVar[Dict[str, Bender]] = KubernetesResource.mapping | {
        "cron_job_status": OptionalS("status") >> Bend(KubernetesCronJobStatus.mapping),
    }
    cron_job_status: Optional[KubernetesCronJobStatus] = field(default=None)


@dataclass(eq=False)
class KubernetesJobStatusConditions:
    kind: ClassVar[str] = "kubernetes_job_status_conditions"
    mapping: ClassVar[Dict[str, Bender]] = {
        "last_probe_time": OptionalS("lastProbeTime"),
        "last_transition_time": OptionalS("lastTransitionTime"),
        "message": OptionalS("message"),
        "reason": OptionalS("reason"),
        "status": OptionalS("status"),
        "type": OptionalS("type"),
    }
    last_probe_time: Optional[datetime] = field(default=None)
    last_transition_time: Optional[datetime] = field(default=None)
    message: Optional[str] = field(default=None)
    reason: Optional[str] = field(default=None)
    status: Optional[str] = field(default=None)
    type: Optional[str] = field(default=None)


@dataclass(eq=False)
class KubernetesJobStatus:
    kind: ClassVar[str] = "kubernetes_job_status"
    mapping: ClassVar[Dict[str, Bender]] = {
        "active": OptionalS("active"),
        "completed_indexes": OptionalS("completedIndexes"),
        "completion_time": OptionalS("completionTime"),
        "conditions": OptionalS("conditions", default=[]) >> ForallBend(KubernetesJobStatusConditions.mapping),
        "failed": OptionalS("failed"),
        "ready": OptionalS("ready"),
        "start_time": OptionalS("startTime"),
        "succeeded": OptionalS("succeeded"),
    }
    active: Optional[int] = field(default=None)
    completed_indexes: Optional[str] = field(default=None)
    completion_time: Optional[datetime] = field(default=None)
    conditions: List[KubernetesJobStatusConditions] = field(default_factory=list)
    failed: Optional[int] = field(default=None)
    ready: Optional[int] = field(default=None)
    start_time: Optional[datetime] = field(default=None)
    succeeded: Optional[int] = field(default=None)


@dataclass(eq=False)
class KubernetesJob(KubernetesResource):
    kind: ClassVar[str] = "kubernetes_job"
    mapping: ClassVar[Dict[str, Bender]] = KubernetesResource.mapping | {
        "job_status": OptionalS("status") >> Bend(KubernetesJobStatus.mapping),
    }
    job_status: Optional[KubernetesJobStatus] = field(default=None)


@dataclass(eq=False)
class KubernetesFlowSchemaStatusConditions:
    kind: ClassVar[str] = "kubernetes_flow_schema_status_conditions"
    mapping: ClassVar[Dict[str, Bender]] = {
        "last_transition_time": OptionalS("lastTransitionTime"),
        "message": OptionalS("message"),
        "reason": OptionalS("reason"),
        "status": OptionalS("status"),
        "type": OptionalS("type"),
    }
    last_transition_time: Optional[datetime] = field(default=None)
    message: Optional[str] = field(default=None)
    reason: Optional[str] = field(default=None)
    status: Optional[str] = field(default=None)
    type: Optional[str] = field(default=None)


@dataclass(eq=False)
class KubernetesFlowSchemaStatus:
    kind: ClassVar[str] = "kubernetes_flow_schema_status"
    mapping: ClassVar[Dict[str, Bender]] = {
        "conditions": OptionalS("conditions", default=[]) >> ForallBend(KubernetesFlowSchemaStatusConditions.mapping),
    }
    conditions: List[KubernetesFlowSchemaStatusConditions] = field(default_factory=list)


@dataclass(eq=False)
class KubernetesFlowSchema(KubernetesResource):
    kind: ClassVar[str] = "kubernetes_flow_schema"
    mapping: ClassVar[Dict[str, Bender]] = KubernetesResource.mapping | {
        "flow_schema_status": OptionalS("status") >> Bend(KubernetesFlowSchemaStatus.mapping),
    }
    flow_schema_status: Optional[KubernetesFlowSchemaStatus] = field(default=None)


@dataclass(eq=False)
class KubernetesPriorityLevelConfigurationStatusConditions:
    kind: ClassVar[str] = "kubernetes_priority_level_configuration_status_conditions"
    mapping: ClassVar[Dict[str, Bender]] = {
        "last_transition_time": OptionalS("lastTransitionTime"),
        "message": OptionalS("message"),
        "reason": OptionalS("reason"),
        "status": OptionalS("status"),
        "type": OptionalS("type"),
    }
    last_transition_time: Optional[datetime] = field(default=None)
    message: Optional[str] = field(default=None)
    reason: Optional[str] = field(default=None)
    status: Optional[str] = field(default=None)
    type: Optional[str] = field(default=None)


@dataclass(eq=False)
class KubernetesPriorityLevelConfigurationStatus:
    kind: ClassVar[str] = "kubernetes_priority_level_configuration_status"
    mapping: ClassVar[Dict[str, Bender]] = {
        "conditions": OptionalS("conditions", default=[])
        >> ForallBend(KubernetesPriorityLevelConfigurationStatusConditions.mapping),
    }
    conditions: List[KubernetesPriorityLevelConfigurationStatusConditions] = field(default_factory=list)


@dataclass(eq=False)
class KubernetesPriorityLevelConfiguration(KubernetesResource):
    kind: ClassVar[str] = "kubernetes_priority_level_configuration"
    mapping: ClassVar[Dict[str, Bender]] = KubernetesResource.mapping | {
        "priority_level_configuration_status": OptionalS("status")
        >> Bend(KubernetesPriorityLevelConfigurationStatus.mapping),
    }
    priority_level_configuration_status: Optional[KubernetesPriorityLevelConfigurationStatus] = field(default=None)


@dataclass(eq=False)
class KubernetesIngressStatusLoadbalancerIngressPorts:
    kind: ClassVar[str] = "kubernetes_ingress_status_loadbalancer_ingress_ports"
    mapping: ClassVar[Dict[str, Bender]] = {
        "error": OptionalS("error"),
        "port": OptionalS("port"),
        "protocol": OptionalS("protocol"),
    }
    error: Optional[str] = field(default=None)
    port: Optional[int] = field(default=None)
    protocol: Optional[str] = field(default=None)


@dataclass(eq=False)
class KubernetesIngressStatusLoadbalancerIngress:
    kind: ClassVar[str] = "kubernetes_ingress_status_loadbalancer_ingress"
    mapping: ClassVar[Dict[str, Bender]] = {
        "hostname": OptionalS("hostname"),
        "ip": OptionalS("ip"),
        "ports": OptionalS("ports", default=[]) >> ForallBend(KubernetesIngressStatusLoadbalancerIngressPorts.mapping),
    }
    hostname: Optional[str] = field(default=None)
    ip: Optional[str] = field(default=None)
    ports: List[KubernetesIngressStatusLoadbalancerIngressPorts] = field(default_factory=list)


@dataclass(eq=False)
class KubernetesIngressStatusLoadbalancer:
    kind: ClassVar[str] = "kubernetes_ingress_status_loadbalancer"
    mapping: ClassVar[Dict[str, Bender]] = {
        "ingress": OptionalS("ingress", default=[]) >> ForallBend(KubernetesIngressStatusLoadbalancerIngress.mapping),
    }
    ingress: List[KubernetesIngressStatusLoadbalancerIngress] = field(default_factory=list)


@dataclass(eq=False)
class KubernetesIngressStatus:
    kind: ClassVar[str] = "kubernetes_ingress_status"
    mapping: ClassVar[Dict[str, Bender]] = {
        "load_balancer": OptionalS("loadBalancer") >> Bend(KubernetesIngressStatusLoadbalancer.mapping),
    }
    load_balancer: Optional[KubernetesIngressStatusLoadbalancer] = field(default=None)


@dataclass(eq=False)
class KubernetesIngress(KubernetesResource, BaseLoadBalancer):
    kind: ClassVar[str] = "kubernetes_ingress"
    mapping: ClassVar[Dict[str, Bender]] = KubernetesResource.mapping | {
        "ingress_status": OptionalS("status") >> Bend(KubernetesIngressStatus.mapping),
        "public_ip_address": OptionalS("status", "loadBalancer", "ingress", default=[])
        >> F(lambda x: x[0].get("ip") if x else None),  # take the public ip of the first load balancer
    }
    ingress_status: Optional[KubernetesIngressStatus] = field(default=None)


@dataclass(eq=False)
class KubernetesIngressClass(KubernetesResource):
    kind: ClassVar[str] = "kubernetes_ingress_class"
    mapping: ClassVar[Dict[str, Bender]] = KubernetesResource.mapping | {}


@dataclass(eq=False)
class KubernetesNetworkPolicyStatusConditions:
    kind: ClassVar[str] = "kubernetes_network_policy_status_conditions"
    mapping: ClassVar[Dict[str, Bender]] = {
        "last_transition_time": OptionalS("lastTransitionTime"),
        "message": OptionalS("message"),
        "observed_generation": OptionalS("observedGeneration"),
        "reason": OptionalS("reason"),
        "status": OptionalS("status"),
        "type": OptionalS("type"),
    }
    last_transition_time: Optional[datetime] = field(default=None)
    message: Optional[str] = field(default=None)
    observed_generation: Optional[int] = field(default=None)
    reason: Optional[str] = field(default=None)
    status: Optional[str] = field(default=None)
    type: Optional[str] = field(default=None)


@dataclass(eq=False)
class KubernetesNetworkPolicyStatus:
    kind: ClassVar[str] = "kubernetes_network_policy_status"
    mapping: ClassVar[Dict[str, Bender]] = {
        "conditions": OptionalS("conditions", default=[])
        >> ForallBend(KubernetesNetworkPolicyStatusConditions.mapping),
    }
    conditions: List[KubernetesNetworkPolicyStatusConditions] = field(default_factory=list)


@dataclass(eq=False)
class KubernetesNetworkPolicy(KubernetesResource):
    kind: ClassVar[str] = "kubernetes_network_policy"
    mapping: ClassVar[Dict[str, Bender]] = KubernetesResource.mapping | {
        "network_policy_status": OptionalS("status") >> Bend(KubernetesNetworkPolicyStatus.mapping),
    }
    network_policy_status: Optional[KubernetesNetworkPolicyStatus] = field(default=None)


@dataclass(eq=False)
class KubernetesRuntimeClass(KubernetesResource):
    kind: ClassVar[str] = "kubernetes_runtime_class"
    mapping: ClassVar[Dict[str, Bender]] = KubernetesResource.mapping | {}


@dataclass(eq=False)
class KubernetesPodDisruptionBudgetStatusConditions:
    kind: ClassVar[str] = "kubernetes_pod_disruption_budget_status_conditions"
    mapping: ClassVar[Dict[str, Bender]] = {
        "last_transition_time": OptionalS("lastTransitionTime"),
        "message": OptionalS("message"),
        "observed_generation": OptionalS("observedGeneration"),
        "reason": OptionalS("reason"),
        "status": OptionalS("status"),
        "type": OptionalS("type"),
    }
    last_transition_time: Optional[datetime] = field(default=None)
    message: Optional[str] = field(default=None)
    observed_generation: Optional[int] = field(default=None)
    reason: Optional[str] = field(default=None)
    status: Optional[str] = field(default=None)
    type: Optional[str] = field(default=None)


@dataclass(eq=False)
class KubernetesPodDisruptionBudgetStatus:
    kind: ClassVar[str] = "kubernetes_pod_disruption_budget_status"
    mapping: ClassVar[Dict[str, Bender]] = {
        "conditions": OptionalS("conditions", default=[])
        >> ForallBend(KubernetesPodDisruptionBudgetStatusConditions.mapping),
        "current_healthy": OptionalS("currentHealthy"),
        "desired_healthy": OptionalS("desiredHealthy"),
        "disrupted_pods": OptionalS("disruptedPods"),
        "disruptions_allowed": OptionalS("disruptionsAllowed"),
        "expected_pods": OptionalS("expectedPods"),
        "observed_generation": OptionalS("observedGeneration"),
    }
    conditions: List[KubernetesPodDisruptionBudgetStatusConditions] = field(default_factory=list)
    current_healthy: Optional[int] = field(default=None)
    desired_healthy: Optional[int] = field(default=None)
    disrupted_pods: Optional[Any] = field(default=None)
    disruptions_allowed: Optional[int] = field(default=None)
    expected_pods: Optional[int] = field(default=None)
    observed_generation: Optional[int] = field(default=None)


@dataclass(eq=False)
class KubernetesPodDisruptionBudget(KubernetesResource):
    kind: ClassVar[str] = "kubernetes_pod_disruption_budget"
    mapping: ClassVar[Dict[str, Bender]] = KubernetesResource.mapping | {
        "pod_disruption_budget_status": OptionalS("status") >> Bend(KubernetesPodDisruptionBudgetStatus.mapping),
    }
    pod_disruption_budget_status: Optional[KubernetesPodDisruptionBudgetStatus] = field(default=None)


@dataclass(eq=False)
class KubernetesClusterRole(KubernetesResource):
    kind: ClassVar[str] = "kubernetes_cluster_role"


@dataclass(eq=False)
class KubernetesClusterRoleBinding(KubernetesResource):
    kind: ClassVar[str] = "kubernetes_cluster_role_binding"


@dataclass(eq=False)
class KubernetesRole(KubernetesResource):
    kind: ClassVar[str] = "kubernetes_role"


@dataclass(eq=False)
class KubernetesRoleBinding(KubernetesResource):
    kind: ClassVar[str] = "kubernetes_role_binding"


@dataclass(eq=False)
class KubernetesPriorityClass(KubernetesResource):
    kind: ClassVar[str] = "kubernetes_priority_class"


@dataclass(eq=False)
class KubernetesCSIDriver(KubernetesResource):
    kind: ClassVar[str] = "kubernetes_csi_driver"


@dataclass(eq=False)
class KubernetesCSINode(KubernetesResource):
    kind: ClassVar[str] = "kubernetes_csi_node"


@dataclass(eq=False)
class KubernetesCSIStorageCapacity(KubernetesResource):
    kind: ClassVar[str] = "kubernetes_csi_storage_capacity"


@dataclass(eq=False)
class KubernetesStorageClass(KubernetesResource):
    kind: ClassVar[str] = "kubernetes_storage_class"


@dataclass(eq=False)
class KubernetesVolumeAttachmentStatusAttacherror:
    kind: ClassVar[str] = "kubernetes_volume_attachment_status_attacherror"
    mapping: ClassVar[Dict[str, Bender]] = {
        "message": OptionalS("message"),
        "time": OptionalS("time"),
    }
    message: Optional[str] = field(default=None)
    time: Optional[datetime] = field(default=None)


@dataclass(eq=False)
class KubernetesVolumeAttachmentStatusDetacherror:
    kind: ClassVar[str] = "kubernetes_volume_attachment_status_detacherror"
    mapping: ClassVar[Dict[str, Bender]] = {
        "message": OptionalS("message"),
        "time": OptionalS("time"),
    }
    message: Optional[str] = field(default=None)
    time: Optional[datetime] = field(default=None)


@dataclass(eq=False)
class KubernetesVolumeAttachmentStatus:
    kind: ClassVar[str] = "kubernetes_volume_attachment_status"
    mapping: ClassVar[Dict[str, Bender]] = {
        "attach_error": OptionalS("attachError") >> Bend(KubernetesVolumeAttachmentStatusAttacherror.mapping),
        "attached": OptionalS("attached"),
        "attachment_metadata": OptionalS("attachmentMetadata"),
        "detach_error": OptionalS("detachError") >> Bend(KubernetesVolumeAttachmentStatusDetacherror.mapping),
    }
    attach_error: Optional[KubernetesVolumeAttachmentStatusAttacherror] = field(default=None)
    attached: Optional[bool] = field(default=None)
    attachment_metadata: Optional[Any] = field(default=None)
    detach_error: Optional[KubernetesVolumeAttachmentStatusDetacherror] = field(default=None)


@dataclass(eq=False)
class KubernetesVolumeAttachment(KubernetesResource):
    kind: ClassVar[str] = "kubernetes_volume_attachment"
    mapping: ClassVar[Dict[str, Bender]] = KubernetesResource.mapping | {
        "volume_attachment_status": OptionalS("status") >> Bend(KubernetesVolumeAttachmentStatus.mapping),
    }
    volume_attachment_status: Optional[KubernetesVolumeAttachmentStatus] = field(default=None)


workload_resources: List[Type[KubernetesResource]] = [
    KubernetesControllerRevision,
    KubernetesCronJob,
    KubernetesDaemonSet,
    KubernetesDeployment,
    KubernetesHorizontalPodAutoscaler,
    KubernetesJob,
    KubernetesPod,
    KubernetesPodTemplate,
    KubernetesPriorityClass,
    KubernetesReplicaSet,
    KubernetesReplicationController,
    KubernetesStatefulSet,
]
service_resources: List[Type[KubernetesResource]] = [
    KubernetesEndpointSlice,
    KubernetesEndpoints,
    KubernetesIngress,
    KubernetesIngressClass,
    KubernetesService,
]
config_storage_resources: List[Type[KubernetesResource]] = [
    KubernetesCSIDriver,
    KubernetesCSINode,
    KubernetesCSIStorageCapacity,
    KubernetesConfigMap,
    KubernetesPersistentVolume,
    KubernetesPersistentVolumeClaim,
    KubernetesSecret,
    KubernetesStorageClass,
    # KubernetesVolume,
    KubernetesVolumeAttachment,
]
authentication_resources: List[Type[KubernetesResource]] = [
    # KubernetesCertificateSigningRequest,
    # KubernetesTokenRequest,
    # KubernetesTokenReview,
    KubernetesServiceAccount,
]
authorization_resources: List[Type[KubernetesResource]] = [
    # KubernetesLocalSubjectAccessReview,
    # KubernetesSelfSubjectAccessReview,
    # KubernetesSelfSubjectRulesReview,
    # KubernetesSubjectAccessReview,
    KubernetesClusterRole,
    KubernetesClusterRoleBinding,
    KubernetesRole,
    KubernetesRoleBinding,
]
policy_resources: List[Type[KubernetesResource]] = [
    # KubernetesPodSecurityPolicy
    KubernetesLimitRange,
    KubernetesNetworkPolicy,
    KubernetesPodDisruptionBudget,
    KubernetesResourceQuota,
]
extend_resources: List[Type[KubernetesResource]] = [
    # KubernetesCustomResourceDefinition,
    KubernetesMutatingWebhookConfiguration,
    KubernetesValidatingWebhookConfiguration,
]
cluster_resources: List[Type[KubernetesResource]] = [
    # KubernetesApiService,
    # KubernetesBinding
    # KubernetesLease,
    # KubernetesComponentStatus,
    KubernetesEvent,
    KubernetesFlowSchema,
    KubernetesNamespace,
    KubernetesNode,
    KubernetesPriorityLevelConfiguration,
    KubernetesRuntimeClass,
]

all_k8s_resources: List[Type[KubernetesResource]] = (
    workload_resources
    + service_resources
    + config_storage_resources
    + authentication_resources
    + authorization_resources
    + policy_resources
    + extend_resources
    + cluster_resources
)

all_k8s_resources_by_k8s_name: Dict[str, Type[KubernetesResource]] = {a.k8s_name(): a for a in all_k8s_resources}
all_k8s_resources_by_resoto_name: Dict[str, Type[KubernetesResource]] = {a.kind: a for a in all_k8s_resources}


# Work around jsons: it tries to deserialize class vars - it should ignore them.
def no_json(js: Json, tp: type = object, **kwargs: object) -> None:
    return None


set_deserializer(no_json, ClassVar)  # type: ignore
