import logging
from threading import Lock

from attrs import define, field
from datetime import datetime
from typing import ClassVar, Optional, Dict, Type, List, Any, Union, Tuple, Set
from collections import defaultdict

from fix_plugin_k8s.base import KubernetesResource, SortTransitionTime
from fixlib.baseresources import (
    BaseAccount,
    BaseInstance,
    BaseRegion,
    InstanceStatus,
    BaseVolume,
    BaseQuota,
    BaseLoadBalancer,
    EdgeType,
    VolumeStatus,
    ModelReference,
)
from fixlib.graph import Graph
from fixlib.json_bender import (
    StringToUnitNumber,
    CPUCoresToNumber,
    Bend,
    F,
    S,
    K,
    bend,
    ForallBend,
    Bender,
    MapEnum,
    Sort,
)
from fixlib.types import Json

log = logging.getLogger("fix.plugins.k8s")


class GraphBuilder:
    def __init__(self, graph: Graph):
        self.graph = graph
        self.name = getattr(graph.root, "name", "unknown")
        self.graph_nodes_access = Lock()
        self.graph_edges_access = Lock()

    def node(self, clazz: Optional[Type[KubernetesResource]] = None, **node: Any) -> Optional[KubernetesResource]:
        if isinstance(nd := node.get("node"), KubernetesResource):
            return nd
        with self.graph_nodes_access:
            for n in self.graph:
                is_clazz = isinstance(n, clazz) if clazz else True
                if is_clazz and all(getattr(n, k, None) == v for k, v in node.items()):
                    return n  # type: ignore
        return None

    def add_node(self, node: KubernetesResource, **kwargs: Any) -> None:
        log.debug(f"{self.name}: add node {node}")
        with self.graph_nodes_access:
            self.graph.add_node(node, **kwargs)

    def add_edge(
        self, from_node: KubernetesResource, edge_type: EdgeType, reverse: bool = False, **to_node: Any
    ) -> None:
        to_n = self.node(**to_node)
        if to_n:
            start, end = (to_n, from_node) if reverse else (from_node, to_n)
            log.debug(f"{self.name}: add edge: {start} -> {end}")
            with self.graph_edges_access:
                self.graph.add_edge(start, end, edge_type=edge_type)

    def add_edges_from_selector(
        self,
        from_node: KubernetesResource,
        edge_type: EdgeType,
        selector: Dict[str, str],
        clazz: Optional[Union[type, Tuple[type, ...]]] = None,
    ) -> None:
        with self.graph_nodes_access:
            for to_n in self.graph:
                is_clazz = isinstance(to_n, clazz) if clazz else True
                if is_clazz and to_n != from_node and selector.items() <= to_n.labels.items():
                    log.debug(f"{self.name}: add edge from selector: {from_node} -> {to_n}")
                    with self.graph_edges_access:
                        self.graph.add_edge(from_node, to_n, edge_type=edge_type)

    def connect_volumes(self, from_node: KubernetesResource, volumes: List[Json]) -> None:
        for volume in volumes:
            if "persistentVolumeClaim" in volume:
                if name := bend(S("persistentVolumeClaim", "claimName"), volume):
                    self.add_edge(
                        from_node,
                        EdgeType.default,
                        name=name,
                        namespace=from_node.namespace,
                        clazz=KubernetesPersistentVolumeClaim,
                    )
            elif "configMap" in volume:
                if name := bend(S("configMap", "name"), volume):
                    self.add_edge(
                        from_node, EdgeType.default, name=name, namespace=from_node.namespace, clazz=KubernetesConfigMap
                    )
            elif "secret" in volume:
                if name := bend(S("secret", "secretName"), volume):
                    self.add_edge(
                        from_node, EdgeType.default, name=name, namespace=from_node.namespace, clazz=KubernetesSecret
                    )
            elif "projected" in volume:
                if sources := bend(S("projected", "sources"), volume):
                    # iterate all projected volumes
                    self.connect_volumes(from_node, sources)


@define(eq=False, slots=False)
class KubernetesNodeStatusAddresses:
    kind: ClassVar[str] = "kubernetes_node_status_addresses"
    kind_display: ClassVar[str] = "Kubernetes Node Status Addresses"
    kind_description: ClassVar[str] = (
        "Kubernetes Node Status Addresses refer to the network addresses (IP or"
        " hostname) assigned to a node in a Kubernetes cluster. These addresses can be"
        " used to communicate and access the services running on the particular node."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "address": S("address"),
        "type": S("type"),
    }
    address: Optional[str] = field(default=None)
    type: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class KubernetesNodeCondition:
    kind: ClassVar[str] = "kubernetes_node_status_conditions"
    kind_display: ClassVar[str] = "Kubernetes Node Status Conditions"
    kind_description: ClassVar[str] = (
        "Kubernetes Node Status Conditions are a set of conditions that provide"
        " information about the health and status of a node in a Kubernetes cluster."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "last_heartbeat_time": S("lastHeartbeatTime"),
        "last_transition_time": S("lastTransitionTime"),
        "message": S("message"),
        "reason": S("reason"),
        "status": S("status"),
        "type": S("type"),
    }
    last_heartbeat_time: Optional[datetime] = field(default=None)
    last_transition_time: Optional[datetime] = field(default=None)
    message: Optional[str] = field(default=None)
    reason: Optional[str] = field(default=None)
    status: Optional[str] = field(default=None)
    type: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class KubernetesNodeStatusConfigSource:
    kind: ClassVar[str] = "kubernetes_node_status_config_active_configmap"
    kind_display: ClassVar[str] = "Kubernetes Node Status Config Active ConfigMap"
    kind_description: ClassVar[str] = (
        "This represents the active configuration map for the node status in a Kubernetes cluster."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "kubelet_config_key": S("kubeletConfigKey"),
        "name": S("name"),
        "namespace": S("namespace"),
        "resource_version": S("resourceVersion"),
        "uid": S("uid"),
    }
    kubelet_config_key: Optional[str] = field(default=None)
    name: Optional[str] = field(default=None)
    namespace: Optional[str] = field(default=None)
    resource_version: Optional[str] = field(default=None)
    uid: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class KubernetesNodeConfigSource:
    kind: ClassVar[str] = "kubernetes_node_status_config_active"
    kind_display: ClassVar[str] = "Kubernetes Node Status Config Active"
    kind_description: ClassVar[str] = "The active configuration status of a node in a Kubernetes cluster."
    mapping: ClassVar[Dict[str, Bender]] = {
        "config_map": S("configMap") >> Bend(KubernetesNodeStatusConfigSource.mapping),
    }
    config_map: Optional[KubernetesNodeStatusConfigSource] = field(default=None)


@define(eq=False, slots=False)
class KubernetesNodeStatusConfig:
    kind: ClassVar[str] = "kubernetes_node_status_config"
    kind_display: ClassVar[str] = "Kubernetes Node Status Config"
    kind_description: ClassVar[str] = (
        "Kubernetes Node Status Config is a configuration that provides information"
        " about the current status of a node in a Kubernetes cluster."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "active": S("active") >> Bend(KubernetesNodeConfigSource.mapping),
        "assigned": S("assigned") >> Bend(KubernetesNodeConfigSource.mapping),
        "error": S("error"),
    }
    active: Optional[KubernetesNodeConfigSource] = field(default=None)
    assigned: Optional[KubernetesNodeConfigSource] = field(default=None)
    error: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class KubernetesDaemonEndpoint:
    kind: ClassVar[str] = "kubernetes_daemon_endpoint"
    kind_display: ClassVar[str] = "Kubernetes Daemon Endpoint"
    kind_description: ClassVar[str] = (
        "A Kubernetes Daemon Endpoint refers to the network endpoint (usually an IP and port) for a daemon service"
        " running on a Kubernetes node, often used for metrics and health checks of system daemons."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "port": S("Port"),
    }
    port: Optional[int] = field(default=None)


@define(eq=False, slots=False)
class KubernetesNodeDaemonEndpoint:
    kind: ClassVar[str] = "kubernetes_node_daemon_endpoint"
    kind_display: ClassVar[str] = "Kubernetes Node Daemon Endpoint"
    kind_description: ClassVar[str] = (
        "The Kubernetes Node Daemon Endpoint refers to the network endpoint for the kubelet on a node within"
        " the cluster's node status details."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "kubelet_endpoint": S("kubeletEndpoint") >> Bend(KubernetesDaemonEndpoint.mapping),
    }
    kubelet_endpoint: Optional[KubernetesDaemonEndpoint] = field(default=None)


@define(eq=False, slots=False)
class KubernetesNodeStatusImages:
    kind: ClassVar[str] = "kubernetes_node_status_images"
    kind_display: ClassVar[str] = "Kubernetes Node Status Images"
    kind_description: ClassVar[str] = (
        "Kubernetes Node Status Images provides details about the container images available on the node, including"
        " the names of the images and their respective sizes in bytes."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "names": S("names", default=[]),
        "size_bytes": S("sizeBytes", default=0),
    }
    names: List[str] = field(factory=list)
    size_bytes: Optional[int] = field(default=None)


@define(eq=False, slots=False)
class KubernetesNodeSystemInfo:
    kind: ClassVar[str] = "kubernetes_node_system_info"
    kind_display: ClassVar[str] = "Kubernetes Node System Info"
    kind_description: ClassVar[str] = (
        "Kubernetes Node System Info provides information about the system running on"
        " a Kubernetes node, such as the operating system version, CPU and memory"
        " usage, and network configurations."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "architecture": S("architecture"),
        "boot_id": S("bootID"),
        "container_runtime_version": S("containerRuntimeVersion"),
        "kernel_version": S("kernelVersion"),
        "kube_proxy_version": S("kubeProxyVersion"),
        "kubelet_version": S("kubeletVersion"),
        "machine_id": S("machineID"),
        "operating_system": S("operatingSystem"),
        "os_image": S("osImage"),
        "system_uuid": S("systemUUID"),
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


@define(eq=False, slots=False)
class KubernetesAttachedVolume:
    kind: ClassVar[str] = "kubernetes_attached_volume"
    kind_display: ClassVar[str] = "Kubernetes Attached Volume"
    kind_description: ClassVar[str] = (
        "Kubernetes Attached Volumes are storage volumes attached to pods in a Kubernetes cluster, allowing"
        " the pod to persist data across restarts and failures."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "device_path": S("devicePath"),
        "name": S("name"),
    }
    device_path: Optional[str] = field(default=None)
    name: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class KubernetesNodeStatus:
    kind: ClassVar[str] = "kubernetes_node_status"
    kind_display: ClassVar[str] = "Kubernetes Node Status"
    kind_description: ClassVar[str] = (
        "Kubernetes Node Status refers to the current status of a node in a"
        " Kubernetes cluster, which includes information such as its availability,"
        " capacity, and conditions."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "addresses": S("addresses", default=[]) >> ForallBend(KubernetesNodeStatusAddresses.mapping),
        "conditions": S("conditions", default=[]) >> SortTransitionTime >> ForallBend(KubernetesNodeCondition.mapping),
        "config": S("config") >> Bend(KubernetesNodeStatusConfig.mapping),
        "capacity": S("capacity"),
        "daemon_endpoints": S("daemonEndpoints") >> Bend(KubernetesNodeDaemonEndpoint.mapping),
        "images": S("images", default=[]) >> ForallBend(KubernetesNodeStatusImages.mapping),
        "node_info": S("nodeInfo") >> Bend(KubernetesNodeSystemInfo.mapping),
        "phase": S("phase"),
        "volumes_attached": S("volumesAttached", default=[]) >> ForallBend(KubernetesAttachedVolume.mapping),
        "volumes_in_use": S("volumesInUse", default=[]),
    }
    addresses: List[KubernetesNodeStatusAddresses] = field(factory=list)
    capacity: Optional[Any] = field(default=None)
    conditions: List[KubernetesNodeCondition] = field(factory=list)
    config: Optional[KubernetesNodeStatusConfig] = field(default=None)
    daemon_endpoints: Optional[KubernetesNodeDaemonEndpoint] = field(default=None)
    images: List[KubernetesNodeStatusImages] = field(factory=list)
    node_info: Optional[KubernetesNodeSystemInfo] = field(default=None)
    phase: Optional[str] = field(default=None)
    volumes_attached: List[KubernetesAttachedVolume] = field(factory=list)
    volumes_in_use: List[str] = field(factory=list)


@define
class KubernetesTaint:
    kind: ClassVar[str] = "kubernetes_taint"
    kind_display: ClassVar[str] = "Kubernetes Taint"
    kind_description: ClassVar[str] = (
        "Kubernetes Taint is a feature that allows nodes (servers) to repel or"
        " tolerate certain pods (applications) based on specific conditions, such as"
        " hardware requirements or user-defined preferences."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "effect": S("effect"),
        "key": S("key"),
        "time_added": S("timeAdded"),
        "value": S("value"),
    }
    effect: Optional[str] = field(default=None)
    key: Optional[str] = field(default=None)
    time_added: Optional[datetime] = field(default=None)
    value: Optional[str] = field(default=None)


@define
class KubernetesNodeSpec:
    kind: ClassVar[str] = "kubernetes_node_spec"
    kind_display: ClassVar[str] = "Kubernetes Node Spec"
    kind_description: ClassVar[str] = (
        "Kubernetes Node Spec is a specification that defines the desired state of a"
        " Kubernetes node, including its hardware resources, such as CPU and memory,"
        " and other configurations like labels and taints."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "external_id": S("externalID"),
        "pod_cidr": S("podCIDR"),
        "pod_cidrs": S("podCIDRs", default=[]),
        "provider_id": S("providerID"),
        "taints": S("taints", default=[]) >> ForallBend(KubernetesTaint.mapping),
        "unschedulable": S("unschedulable"),
    }
    external_id: Optional[str] = field(default=None)
    pod_cidr: Optional[str] = field(default=None)
    pod_cidrs: List[str] = field(factory=list)
    provider_id: Optional[str] = field(default=None)
    taints: List[KubernetesTaint] = field(factory=list)
    unschedulable: Optional[bool] = field(default=None)


instance_status_map: Dict[str, InstanceStatus] = {
    "Pending": InstanceStatus.BUSY,
    "Running": InstanceStatus.RUNNING,
    "Failed": InstanceStatus.TERMINATED,
    "Succeeded": InstanceStatus.STOPPED,
    "Unknown": InstanceStatus.UNKNOWN,
}


@define(eq=False, slots=False)
class KubernetesNode(KubernetesResource, BaseInstance):
    kind: ClassVar[str] = "kubernetes_node"
    kind_display: ClassVar[str] = "Kubernetes Node"
    kind_description: ClassVar[str] = (
        "A Kubernetes Node is a worker machine in a Kubernetes cluster that runs"
        " containers. It is responsible for running and managing the containers that"
        " make up the applications within the cluster."
    )
    mapping: ClassVar[Dict[str, Bender]] = KubernetesResource.mapping | {
        "node_status": S("status") >> Bend(KubernetesNodeStatus.mapping),
        "node_spec": S("spec") >> Bend(KubernetesNodeSpec.mapping),
        "provider_id": S("spec", "providerID"),
        "instance_cores": S("status", "capacity", "cpu") >> CPUCoresToNumber(),
        "instance_memory": S("status", "capacity", "memory") >> StringToUnitNumber("GiB"),
        "instance_type": K("kubernetes_node"),
        "instance_status": K(InstanceStatus.RUNNING.value),
    }
    reference_kinds: ClassVar[ModelReference] = {
        "successors": {
            "default": ["kubernetes_csi_node", "kubernetes_pod"],
            "delete": [],
        }
    }

    provider_id: Optional[str] = None
    node_status: Optional[KubernetesNodeStatus] = field(default=None, metadata=dict(ignore_history=True))
    node_spec: Optional[KubernetesNodeSpec] = field(default=None)


# region pod


@define(eq=False, slots=False)
class KubernetesPodStatusConditions:
    kind: ClassVar[str] = "kubernetes_pod_status_conditions"
    kind_display: ClassVar[str] = "Kubernetes Pod Status Conditions"
    kind_description: ClassVar[str] = (
        "Kubernetes Pod Status Conditions represent the current status and conditions"
        " of a pod, providing information about its health and state."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "last_probe_time": S("lastProbeTime"),
        "last_transition_time": S("lastTransitionTime"),
        "message": S("message"),
        "reason": S("reason"),
        "status": S("status"),
        "type": S("type"),
    }
    last_probe_time: Optional[datetime] = field(default=None)
    last_transition_time: Optional[datetime] = field(default=None)
    message: Optional[str] = field(default=None)
    reason: Optional[str] = field(default=None)
    status: Optional[str] = field(default=None)
    type: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class KubernetesContainerStateRunning:
    kind: ClassVar[str] = "kubernetes_container_state_running"
    kind_display: ClassVar[str] = "Kubernetes Container State Running"
    kind_description: ClassVar[str] = (
        "Running state indicates that the container is currently up and running within a Kubernetes cluster."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "started_at": S("startedAt"),
    }
    started_at: Optional[datetime] = field(default=None)


@define(eq=False, slots=False)
class KubernetesContainerStateTerminated:
    kind: ClassVar[str] = "kubernetes_container_state_terminated"
    kind_display: ClassVar[str] = "Kubernetes Container State Terminated"
    kind_description: ClassVar[str] = (
        "This resource represents the terminated state of a container within a"
        " Kubernetes cluster. Terminated state indicates that the container has been"
        " stopped or exited."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "container_id": S("containerID"),
        "exit_code": S("exitCode"),
        "finished_at": S("finishedAt"),
        "message": S("message"),
        "reason": S("reason"),
        "signal": S("signal"),
        "started_at": S("startedAt"),
    }
    container_id: Optional[str] = field(default=None)
    exit_code: Optional[int] = field(default=None)
    finished_at: Optional[datetime] = field(default=None)
    message: Optional[str] = field(default=None)
    reason: Optional[str] = field(default=None)
    signal: Optional[int] = field(default=None)
    started_at: Optional[datetime] = field(default=None)


@define(eq=False, slots=False)
class KubernetesContainerStateWaiting:
    kind: ClassVar[str] = "kubernetes_container_state_waiting"
    kind_display: ClassVar[str] = "Kubernetes Container State Waiting"
    kind_description: ClassVar[str] = (
        "The waiting state of a container in Kubernetes indicates that it is waiting"
        " for a specific condition to be met before it can start running."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "message": S("message"),
        "reason": S("reason"),
    }
    message: Optional[str] = field(default=None)
    reason: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class KubernetesContainerState:
    kind: ClassVar[str] = "kubernetes_container_state"
    kind_display: ClassVar[str] = "Kubernetes Container State"
    kind_description: ClassVar[str] = (
        "Kubernetes Container State represents the current state of a container running in a Kubernetes cluster."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "running": S("running") >> Bend(KubernetesContainerStateRunning.mapping),
        "terminated": S("terminated") >> Bend(KubernetesContainerStateTerminated.mapping),
        "waiting": S("waiting") >> Bend(KubernetesContainerStateWaiting.mapping),
    }
    running: Optional[KubernetesContainerStateRunning] = field(default=None)
    terminated: Optional[KubernetesContainerStateTerminated] = field(default=None)
    waiting: Optional[KubernetesContainerStateWaiting] = field(default=None)


@define(eq=False, slots=False)
class KubernetesContainerStatus:
    kind: ClassVar[str] = "kubernetes_container_status"
    kind_display: ClassVar[str] = "Kubernetes Container Status"
    kind_description: ClassVar[str] = (
        "This is a status report for a container running in a Kubernetes cluster,"
        " indicating the current state and health of the container."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "container_id": S("containerID"),
        "image": S("image"),
        "image_id": S("imageID"),
        "last_state": S("lastState") >> Bend(KubernetesContainerState.mapping),
        "name": S("name"),
        "ready": S("ready"),
        "restart_count": S("restartCount"),
        "started": S("started"),
        "state": S("state") >> Bend(KubernetesContainerState.mapping),
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


@define(eq=False, slots=False)
class KubernetesPodIPs:
    kind: ClassVar[str] = "kubernetes_pod_ips"
    kind_display: ClassVar[str] = "Kubernetes Pod IPs"
    kind_description: ClassVar[str] = (
        "Kubernetes Pod IPs are the IP addresses assigned to individual pods in a"
        " Kubernetes cluster, allowing them to communicate with each other and"
        " external services."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"ip": S("ip")}
    ip: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class KubernetesPodStatus:
    kind: ClassVar[str] = "kubernetes_pod_status"
    kind_display: ClassVar[str] = "Kubernetes Pod Status"
    kind_description: ClassVar[str] = (
        "Kubernetes Pod Status refers to the current state of a pod in a Kubernetes"
        " cluster, indicating whether it is running, pending, or terminated."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "conditions": S("conditions", default=[])
        >> SortTransitionTime
        >> ForallBend(KubernetesPodStatusConditions.mapping),
        "container_statuses": S("containerStatuses", default=[]) >> ForallBend(KubernetesContainerStatus.mapping),
        "ephemeral_container_statuses": S("ephemeralContainerStatuses", default=[])
        >> ForallBend(KubernetesContainerState.mapping),
        "host_ip": S("hostIP"),
        "init_container_statuses": S("initContainerStatuses", default=[])
        >> ForallBend(KubernetesContainerStatus.mapping),
        "message": S("message"),
        "nominated_node_name": S("nominatedNodeName"),
        "phase": S("phase"),
        "pod_ip": S("podIP"),
        "pod_ips": S("podIPs", default=[]) >> ForallBend(KubernetesPodIPs.mapping),
        "qos_class": S("qosClass"),
        "reason": S("reason"),
        "start_time": S("startTime"),
    }
    conditions: List[KubernetesPodStatusConditions] = field(factory=list)
    container_statuses: List[KubernetesContainerStatus] = field(factory=list)
    ephemeral_container_statuses: List[KubernetesContainerState] = field(factory=list)
    host_ip: Optional[str] = field(default=None)
    init_container_statuses: List[KubernetesContainerStatus] = field(factory=list)
    message: Optional[str] = field(default=None)
    nominated_node_name: Optional[str] = field(default=None)
    phase: Optional[str] = field(default=None)
    pod_ip: Optional[str] = field(default=None)
    pod_ips: List[KubernetesPodIPs] = field(factory=list)
    qos_class: Optional[str] = field(default=None)
    reason: Optional[str] = field(default=None)
    start_time: Optional[datetime] = field(default=None)


@define
class KubernetesContainerPort:
    kind: ClassVar[str] = "kubernetes_container_port"
    kind_display: ClassVar[str] = "Kubernetes Container Port"
    kind_description: ClassVar[str] = (
        "A Kubernetes Container Port is a specific port exposed by a container within"
        " a Kubernetes cluster, allowing network communication to and from the"
        " container."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "container_port": S("containerPort"),
        "host_ip": S("hostIP"),
        "host_port": S("hostPort"),
        "name": S("name"),
        "protocol": S("protocol"),
    }
    container_port: Optional[int] = field(default=None)
    host_ip: Optional[str] = field(default=None)
    host_port: Optional[int] = field(default=None)
    name: Optional[str] = field(default=None)
    protocol: Optional[str] = field(default=None)


@define
class KubernetesResourceRequirements:
    kind: ClassVar[str] = "kubernetes_resource_requirements"
    kind_display: ClassVar[str] = "Kubernetes Resource Requirements"
    kind_description: ClassVar[str] = (
        "Kubernetes Resource Requirements define the amount of CPU and memory"
        " resources needed for a container to run on a Kubernetes cluster."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "limits": S("limits"),
        "requests": S("requests"),
    }
    limits: Optional[Any] = field(default=None)
    requests: Optional[Any] = field(default=None)


@define
class KubernetesSecurityContext:
    kind: ClassVar[str] = "kubernetes_security_context"
    kind_display: ClassVar[str] = "Kubernetes Security Context"
    kind_description: ClassVar[str] = (
        "A security context in Kubernetes defines privilege and access settings for a"
        " pod or specific containers within a pod. It includes settings such as the"
        " user and group IDs, file permissions, and capabilities."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "allow_privilege_escalation": S("allowPrivilegeEscalation"),
        "privileged": S("privileged"),
        "proc_mount": S("procMount"),
        "read_only_root_filesystem": S("readOnlyRootFilesystem"),
        "run_as_group": S("runAsGroup"),
        "run_as_non_root": S("runAsNonRoot"),
        "run_as_user": S("runAsUser"),
        "se_linux_options": S("seLinuxOptions"),
        "seccomp_profile": S("seccompProfile"),
        "windows_options": S("windowsOptions"),
    }
    allow_privilege_escalation: Optional[bool] = field(default=None)
    privileged: Optional[bool] = field(default=None)
    proc_mount: Optional[str] = field(default=None)
    read_only_root_filesystem: Optional[bool] = field(default=None)
    run_as_group: Optional[int] = field(default=None)
    run_as_non_root: Optional[bool] = field(default=None)
    run_as_user: Optional[int] = field(default=None)
    se_linux_options: Optional[Any] = field(default=None)
    seccomp_profile: Optional[Any] = field(default=None)
    windows_options: Optional[Any] = field(default=None)


@define
class KubernetesVolumeDevice:
    kind: ClassVar[str] = "kubernetes_volume_device"
    kind_display: ClassVar[str] = "Kubernetes Volume Device"
    kind_description: ClassVar[str] = (
        "Kubernetes Volume Device refers to a storage device that can be attached to"
        " a container in a Kubernetes cluster, providing persistent storage for the"
        " containerized applications."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "device_path": S("devicePath"),
        "name": S("name"),
    }
    device_path: Optional[str] = field(default=None)
    name: Optional[str] = field(default=None)


@define
class KubernetesVolumeMount:
    kind: ClassVar[str] = "kubernetes_volume_mount"
    kind_display: ClassVar[str] = "Kubernetes Volume Mount"
    kind_description: ClassVar[str] = (
        "A volume mount is a file or a directory from the host node that is made"
        " available to a container in a Kubernetes cluster, allowing the container to"
        " access and share data with the host or other containers."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "mount_path": S("mountPath"),
        "mount_propagation": S("mountPropagation"),
        "name": S("name"),
        "read_only": S("readOnly"),
        "sub_path": S("subPath"),
        "sub_path_expr": S("subPathExpr"),
    }
    mount_path: Optional[str] = field(default=None)
    mount_propagation: Optional[str] = field(default=None)
    name: Optional[str] = field(default=None)
    read_only: Optional[bool] = field(default=None)
    sub_path: Optional[str] = field(default=None)
    sub_path_expr: Optional[str] = field(default=None)


@define
class KubernetesContainer:
    kind: ClassVar[str] = "kubernetes_container"
    kind_display: ClassVar[str] = "Kubernetes Container"
    kind_description: ClassVar[str] = (
        "Kubernetes Containers are lightweight, portable, and scalable units that"
        " encapsulate an application and its dependencies, allowing for easy"
        " deployment and management on Kubernetes clusters."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "args": S("args", default=[]),
        "command": S("command", default=[]),
        "image": S("image"),
        "image_pull_policy": S("imagePullPolicy"),
        "name": S("name"),
        "ports": S("ports", default=[]) >> ForallBend(KubernetesContainerPort.mapping),
        "resources": S("resources") >> Bend(KubernetesResourceRequirements.mapping),
        "security_context": S("securityContext") >> Bend(KubernetesSecurityContext.mapping),
        "stdin": S("stdin"),
        "stdin_once": S("stdinOnce"),
        "termination_message_path": S("terminationMessagePath"),
        "termination_message_policy": S("terminationMessagePolicy"),
        "tty": S("tty"),
        "volume_devices": S("volumeDevices", default=[]) >> ForallBend(KubernetesVolumeDevice.mapping),
        "volume_mounts": S("volumeMounts", default=[]) >> ForallBend(KubernetesVolumeMount.mapping),
        "working_dir": S("workingDir"),
    }
    args: List[str] = field(factory=list)
    command: List[str] = field(factory=list)
    image: Optional[str] = field(default=None)
    image_pull_policy: Optional[str] = field(default=None)
    name: Optional[str] = field(default=None)
    ports: List[KubernetesContainerPort] = field(factory=list)
    resources: Optional[KubernetesResourceRequirements] = field(default=None)
    security_context: Optional[KubernetesSecurityContext] = field(default=None)
    stdin: Optional[bool] = field(default=None)
    stdin_once: Optional[bool] = field(default=None)
    termination_message_path: Optional[str] = field(default=None)
    termination_message_policy: Optional[str] = field(default=None)
    tty: Optional[bool] = field(default=None)
    volume_devices: List[KubernetesVolumeDevice] = field(factory=list)
    volume_mounts: List[KubernetesVolumeMount] = field(factory=list)
    working_dir: Optional[str] = field(default=None)


@define
class KubernetesPodSecurityContext:
    kind: ClassVar[str] = "kubernetes_pod_security_context"
    kind_display: ClassVar[str] = "Kubernetes Pod Security Context"
    kind_description: ClassVar[str] = (
        "Pod Security Context in Kubernetes is a configuration setting that allows"
        " users to define and enforce security policies for individual pods in a"
        " cluster, ensuring proper isolation and access controls."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "fs_group": S("fsGroup"),
        "fs_group_change_policy": S("fsGroupChangePolicy"),
        "run_as_group": S("runAsGroup"),
        "run_as_non_root": S("runAsNonRoot"),
        "run_as_user": S("runAsUser"),
        "se_linux_options": S("seLinuxOptions"),
        "seccomp_profile": S("seccompProfile"),
        "supplemental_groups": S("supplementalGroups", default=[]),
        "windows_options": S("windowsOptions"),
    }
    fs_group: Optional[int] = field(default=None)
    fs_group_change_policy: Optional[str] = field(default=None)
    run_as_group: Optional[int] = field(default=None)
    run_as_non_root: Optional[bool] = field(default=None)
    run_as_user: Optional[int] = field(default=None)
    se_linux_options: Optional[Any] = field(default=None)
    seccomp_profile: Optional[Any] = field(default=None)
    supplemental_groups: List[int] = field(factory=list)
    windows_options: Optional[Any] = field(default=None)


@define
class KubernetesToleration:
    kind: ClassVar[str] = "kubernetes_toleration"
    kind_display: ClassVar[str] = "Kubernetes Toleration"
    kind_description: ClassVar[str] = (
        "Kubernetes toleration is a feature that allows a pod to accept scheduling on"
        " nodes with specific taints based on specified conditions."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "effect": S("effect"),
        "key": S("key"),
        "operator": S("operator"),
        "toleration_seconds": S("tolerationSeconds"),
        "value": S("value"),
    }
    effect: Optional[str] = field(default=None)
    key: Optional[str] = field(default=None)
    operator: Optional[str] = field(default=None)
    toleration_seconds: Optional[int] = field(default=None)
    value: Optional[str] = field(default=None)


@define
class KubernetesVolume:
    kind: ClassVar[str] = "kubernetes_volume"
    kind_display: ClassVar[str] = "Kubernetes Volume"
    kind_description: ClassVar[str] = (
        "A storage unit used in Kubernetes to provide persistent storage for"
        " containers running in a Kubernetes cluster."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "aws_elastic_block_store": S("awsElasticBlockStore"),
        "azure_disk": S("azureDisk"),
        "azure_file": S("azureFile"),
        "cephfs": S("cephfs"),
        "cinder": S("cinder"),
        "config_map": S("configMap"),
        "csi": S("csi"),
        "downward_api": S("downwardAPI"),
        "empty_dir": S("emptyDir"),
        "ephemeral": S("ephemeral"),
        "fc": S("fc"),
        "flex_volume": S("flexVolume"),
        "flocker": S("flocker"),
        "gce_persistent_disk": S("gcePersistentDisk"),
        "git_repo": S("gitRepo"),
        "glusterfs": S("glusterfs"),
        "host_path": S("hostPath"),
        "iscsi": S("iscsi"),
        "name": S("name"),
        "nfs": S("nfs"),
        "persistent_volume_claim": S("persistentVolumeClaim"),
        "photon_persistent_disk": S("photonPersistentDisk"),
        "portworx_volume": S("portworxVolume"),
        "projected": S("projected"),
        "quobyte": S("quobyte"),
        "rbd": S("rbd"),
        "scale_io": S("scaleIO"),
        "secret": S("secret"),
        "storageos": S("storageos"),
        "vsphere_volume": S("vsphereVolume"),
    }
    aws_elastic_block_store: Optional[Any] = field(default=None)
    azure_disk: Optional[Any] = field(default=None)
    azure_file: Optional[Any] = field(default=None)
    cephfs: Optional[Any] = field(default=None)
    cinder: Optional[Any] = field(default=None)
    config_map: Optional[Any] = field(default=None)
    csi: Optional[Any] = field(default=None)
    downward_api: Optional[Any] = field(default=None)
    empty_dir: Optional[Any] = field(default=None)
    ephemeral: Optional[Any] = field(default=None)
    fc: Optional[Any] = field(default=None)
    flex_volume: Optional[Any] = field(default=None)
    flocker: Optional[Any] = field(default=None)
    gce_persistent_disk: Optional[Any] = field(default=None)
    git_repo: Optional[Any] = field(default=None)
    glusterfs: Optional[Any] = field(default=None)
    host_path: Optional[Any] = field(default=None)
    iscsi: Optional[Any] = field(default=None)
    name: Optional[str] = field(default=None)
    nfs: Optional[Any] = field(default=None)
    persistent_volume_claim: Optional[Any] = field(default=None)
    photon_persistent_disk: Optional[Any] = field(default=None)
    portworx_volume: Optional[Any] = field(default=None)
    projected: Optional[Any] = field(default=None)
    quobyte: Optional[Any] = field(default=None)
    rbd: Optional[Any] = field(default=None)
    scale_io: Optional[Any] = field(default=None)
    secret: Optional[Any] = field(default=None)
    storageos: Optional[Any] = field(default=None)
    vsphere_volume: Optional[Any] = field(default=None)


@define
class KubernetesPodSpec:
    kind: ClassVar[str] = "kubernetes_pod_spec"
    kind_display: ClassVar[str] = "Kubernetes Pod Spec"
    kind_description: ClassVar[str] = (
        "Kubernetes Pod Spec is a configuration file that describes the desired state"
        " of a pod in a Kubernetes cluster."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "active_deadline_seconds": S("activeDeadlineSeconds"),
        "automount_service_account_token": S("automountServiceAccountToken"),
        "containers": S("containers", default=[]) >> ForallBend(KubernetesContainer.mapping),
        "dns_policy": S("dnsPolicy"),
        "enable_service_links": S("enableServiceLinks"),
        "ephemeral_containers": S("ephemeralContainers", default=[]) >> ForallBend(KubernetesContainer.mapping),
        "host_ipc": S("hostIPC"),
        "host_network": S("hostNetwork"),
        "host_pid": S("hostPID"),
        "hostname": S("hostname"),
        "init_containers": S("initContainers", default=[]) >> ForallBend(KubernetesContainer.mapping),
        "node_name": S("nodeName"),
        "overhead": S("overhead"),
        "preemption_policy": S("preemptionPolicy"),
        "priority": S("priority"),
        "priority_class_name": S("priorityClassName"),
        "restart_policy": S("restartPolicy"),
        "runtime_class_name": S("runtimeClassName"),
        "scheduler_name": S("schedulerName"),
        "security_context": S("securityContext") >> Bend(KubernetesSecurityContext.mapping),
        "service_account": S("serviceAccount"),
        "service_account_name": S("serviceAccountName"),
        "set_hostname_as_fqdn": S("setHostnameAsFQDN"),
        "share_process_namespace": S("shareProcessNamespace"),
        "subdomain": S("subdomain"),
        "termination_grace_period_seconds": S("terminationGracePeriodSeconds"),
        "tolerations": S("tolerations", default=[]) >> ForallBend(KubernetesToleration.mapping),
        "volumes": S("volumes", default=[]) >> ForallBend(KubernetesVolume.mapping),
    }
    active_deadline_seconds: Optional[int] = field(default=None)
    automount_service_account_token: Optional[bool] = field(default=None)
    containers: List[KubernetesContainer] = field(factory=list)
    dns_policy: Optional[str] = field(default=None)
    enable_service_links: Optional[bool] = field(default=None)
    ephemeral_containers: List[KubernetesContainer] = field(factory=list)
    host_ipc: Optional[bool] = field(default=None)
    host_network: Optional[bool] = field(default=None)
    host_pid: Optional[bool] = field(default=None)
    hostname: Optional[str] = field(default=None)
    init_containers: List[KubernetesContainer] = field(factory=list)
    node_name: Optional[str] = field(default=None)
    preemption_policy: Optional[str] = field(default=None)
    priority: Optional[int] = field(default=None)
    priority_class_name: Optional[str] = field(default=None)
    restart_policy: Optional[str] = field(default=None)
    runtime_class_name: Optional[str] = field(default=None)
    scheduler_name: Optional[str] = field(default=None)
    security_context: Optional[KubernetesPodSecurityContext] = field(default=None)
    service_account: Optional[str] = field(default=None)
    service_account_name: Optional[str] = field(default=None)
    set_hostname_as_fqdn: Optional[bool] = field(default=None)
    share_process_namespace: Optional[bool] = field(default=None)
    subdomain: Optional[str] = field(default=None)
    termination_grace_period_seconds: Optional[int] = field(default=None)
    tolerations: List[KubernetesToleration] = field(factory=list)
    volumes: List[KubernetesVolume] = field(factory=list)


@define(eq=False, slots=False)
class KubernetesPod(KubernetesResource):
    kind: ClassVar[str] = "kubernetes_pod"
    kind_display: ClassVar[str] = "Kubernetes Pod"
    kind_description: ClassVar[str] = (
        "A Kubernetes Pod is the basic building block of a Kubernetes cluster, it"
        " represents a running process, or a group of running processes, on a node."
    )
    mapping: ClassVar[Dict[str, Bender]] = KubernetesResource.mapping | {
        "pod_status": S("status") >> Bend(KubernetesPodStatus.mapping),
        "pod_spec": S("spec") >> Bend(KubernetesPodSpec.mapping),
    }
    reference_kinds: ClassVar[ModelReference] = {
        "successors": {
            "default": ["kubernetes_secret", "kubernetes_persistent_volume_claim", "kubernetes_config_map"],
            "delete": ["kubernetes_stateful_set", "kubernetes_replica_set", "kubernetes_job", "kubernetes_daemon_set"],
        }
    }

    pod_status: Optional[KubernetesPodStatus] = field(default=None, metadata=dict(ignore_history=True))
    pod_spec: Optional[KubernetesPodSpec] = field(default=None)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        super().connect_in_graph(builder, source)
        volumes = bend(S("spec", "volumes", default=[]), source)
        builder.connect_volumes(self, volumes)
        if node_name := bend(S("spec", "nodeName"), source):
            builder.add_edge(self, EdgeType.default, True, clazz=KubernetesNode, name=node_name)
        container_array = bend(
            S("spec", "containers") >> ForallBend(S("env", default=[]) >> ForallBend(S("valueFrom"))), source
        )
        for from_array in container_array:
            for value_from in from_array:
                if value_from is None:
                    continue
                elif ref := value_from.get("secretKeyRef", None):
                    builder.add_edge(self, EdgeType.default, clazz=KubernetesSecret, name=ref["name"])
                elif ref := value_from.get("configMapKeyRef", None):
                    builder.add_edge(self, EdgeType.default, clazz=KubernetesConfigMap, name=ref["name"])


# endregion


# region persistent volume claim
@define(eq=False, slots=False)
class KubernetesPersistentVolumeClaimStatusConditions:
    kind: ClassVar[str] = "kubernetes_persistent_volume_claim_status_conditions"
    kind_display: ClassVar[str] = "Kubernetes Persistent Volume Claim Status Conditions"
    kind_description: ClassVar[str] = (
        "The status conditions of a Persistent Volume Claim (PVC) in Kubernetes"
        " represent the current state of the claim, providing information about any"
        " errors or warnings that may be affecting its availability or usability."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "last_probe_time": S("lastProbeTime"),
        "last_transition_time": S("lastTransitionTime"),
        "message": S("message"),
        "reason": S("reason"),
        "status": S("status"),
        "type": S("type"),
    }
    last_probe_time: Optional[datetime] = field(default=None)
    last_transition_time: Optional[datetime] = field(default=None)
    message: Optional[str] = field(default=None)
    reason: Optional[str] = field(default=None)
    status: Optional[str] = field(default=None)
    type: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class KubernetesPersistentVolumeClaimStatus:
    kind: ClassVar[str] = "kubernetes_persistent_volume_claim_status"
    kind_display: ClassVar[str] = "Kubernetes Persistent Volume Claim Status"
    kind_description: ClassVar[str] = (
        "The status of a Persistent Volume Claim (PVC) in Kubernetes, which"
        " represents a request for a specific amount of storage resources by a pod."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "access_modes": S("accessModes", default=[]),
        "allocated_resources": S("allocatedResources"),
        "conditions": S("conditions", default=[])
        >> SortTransitionTime
        >> ForallBend(KubernetesPersistentVolumeClaimStatusConditions.mapping),
        "phase": S("phase"),
        "resize_status": S("resizeStatus"),
    }
    access_modes: List[str] = field(factory=list)
    allocated_resources: Optional[str] = field(default=None)
    conditions: List[KubernetesPersistentVolumeClaimStatusConditions] = field(factory=list)
    phase: Optional[str] = field(default=None)
    resize_status: Optional[str] = field(default=None)


@define
class KubernetesLabelSelectorRequirement:
    kind: ClassVar[str] = "kubernetes_label_selector_requirement"
    kind_display: ClassVar[str] = "Kubernetes Label Selector Requirement"
    kind_description: ClassVar[str] = (
        "Kubernetes Label Selector Requirements specify constraints that must be met"
        " by resources in order to be selected by a given label selector."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "key": S("key"),
        "operator": S("operator"),
        "values": S("values", default=[]),
    }
    key: Optional[str] = field(default=None)
    operator: Optional[str] = field(default=None)
    values: List[str] = field(factory=list)


@define
class KubernetesLabelSelector:
    kind: ClassVar[str] = "kubernetes_label_selector"
    kind_display: ClassVar[str] = "Kubernetes Label Selector"
    kind_description: ClassVar[str] = (
        "A Kubernetes Label Selector is used to select and filter resources based on"
        " their labels, allowing for targeted operations and management within a"
        " Kubernetes cluster."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "match_expressions": S("matchExpressions", default=[])
        >> ForallBend(KubernetesLabelSelectorRequirement.mapping),
        "match_labels": S("matchLabels"),
    }
    match_expressions: List[KubernetesLabelSelectorRequirement] = field(factory=list)
    match_labels: Optional[Dict[str, str]] = field(default=None)


@define
class KubernetesPersistentVolumeClaimSpec:
    kind: ClassVar[str] = "kubernetes_persistent_volume_claim_spec"
    kind_display: ClassVar[str] = "Kubernetes Persistent Volume Claim Spec"
    kind_description: ClassVar[str] = (
        "A Kubernetes Persistent Volume Claim Spec is a specification that defines"
        " the requirements and characteristics of a Persistent Volume Claim, which is"
        " used to request storage resources in a Kubernetes cluster to be dynamically"
        " provisioned."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "access_modes": S("accessModes", default=[]),
        "resources": S("resources") >> Bend(KubernetesResourceRequirements.mapping),
        "selector": S("selector") >> Bend(KubernetesLabelSelector.mapping),
        "storage_class_name": S("storageClassName"),
        "volume_mode": S("volumeMode"),
        "volume_name": S("volumeName"),
    }
    access_modes: List[str] = field(factory=list)
    resources: Optional[KubernetesResourceRequirements] = field(default=None)
    selector: Optional[KubernetesLabelSelector] = field(default=None)
    storage_class_name: Optional[str] = field(default=None)
    volume_mode: Optional[str] = field(default=None)
    volume_name: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class KubernetesPersistentVolumeClaim(KubernetesResource):
    kind: ClassVar[str] = "kubernetes_persistent_volume_claim"
    kind_display: ClassVar[str] = "Kubernetes Persistent Volume Claim"
    kind_description: ClassVar[str] = (
        "A Kubernetes Persistent Volume Claim is a request for storage resources in a"
        " Kubernetes cluster. It allows users to request specific storage capacity and"
        " access modes for their applications."
    )
    mapping: ClassVar[Dict[str, Bender]] = KubernetesResource.mapping | {
        "persistent_volume_claim_status": S("status") >> Bend(KubernetesPersistentVolumeClaimStatus.mapping),
        "persistent_volume_claim_spec": S("spec") >> Bend(KubernetesPersistentVolumeClaimSpec.mapping),
    }
    reference_kinds: ClassVar[ModelReference] = {
        "successors": {"default": ["kubernetes_persistent_volume"], "delete": []}
    }

    persistent_volume_claim_status: Optional[KubernetesPersistentVolumeClaimStatus] = field(
        default=None, metadata=dict(ignore_history=True)
    )
    persistent_volume_claim_spec: Optional[KubernetesPersistentVolumeClaimSpec] = field(default=None)


# endregion
# region service


@define(eq=False, slots=False)
class KubernetesLoadbalancerIngressPorts:
    kind: ClassVar[str] = "kubernetes_loadbalancer_ingress_ports"
    kind_display: ClassVar[str] = "Kubernetes LoadBalancer Ingress Ports"
    kind_description: ClassVar[str] = (
        "Kubernetes LoadBalancer Ingress Ports are the ports exposed by a load"
        " balancer in a Kubernetes cluster for routing incoming traffic to services."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "error": S("error"),
        "port": S("port"),
        "protocol": S("protocol"),
    }
    error: Optional[str] = field(default=None)
    port: Optional[int] = field(default=None)
    protocol: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class KubernetesLoadbalancerIngress:
    kind: ClassVar[str] = "kubernetes_loadbalancer_ingress"
    kind_display: ClassVar[str] = "Kubernetes LoadBalancer Ingress"
    kind_description: ClassVar[str] = (
        "Kubernetes LoadBalancer Ingress is a feature in Kubernetes that provides"
        " external access to services running in a Kubernetes cluster by assigning"
        " them a public IP address and distributing incoming traffic to the"
        " corresponding services."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "hostname": S("hostname"),
        "ip": S("ip"),
        "ports": S("ports", default=[]) >> ForallBend(KubernetesLoadbalancerIngressPorts.mapping),
    }
    hostname: Optional[str] = field(default=None)
    ip: Optional[str] = field(default=None)
    ports: List[KubernetesLoadbalancerIngressPorts] = field(factory=list)


@define(eq=False, slots=False)
class KubernetesLoadbalancerStatus:
    kind: ClassVar[str] = "kubernetes_loadbalancer_status"
    kind_display: ClassVar[str] = "Kubernetes LoadBalancer Status"
    kind_description: ClassVar[str] = (
        "Kubernetes LoadBalancer Status represents the status of a load balancer in a Kubernetes cluster."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "ingress": S("ingress", default=[]) >> ForallBend(KubernetesLoadbalancerIngress.mapping),
    }
    ingress: List[KubernetesLoadbalancerIngress] = field(factory=list)


@define(eq=False, slots=False)
class KubernetesServiceStatusConditions:
    kind: ClassVar[str] = "kubernetes_service_status_conditions"
    kind_display: ClassVar[str] = "Kubernetes Service Status Conditions"
    kind_description: ClassVar[str] = (
        "Kubernetes Service Status Conditions represents the conditions associated"
        " with the current state of a service in a Kubernetes cluster."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "last_transition_time": S("lastTransitionTime"),
        "message": S("message"),
        "observed_generation": S("observedGeneration"),
        "reason": S("reason"),
        "status": S("status"),
        "type": S("type"),
    }
    last_transition_time: Optional[datetime] = field(default=None)
    message: Optional[str] = field(default=None)
    observed_generation: Optional[int] = field(default=None)
    reason: Optional[str] = field(default=None)
    status: Optional[str] = field(default=None)
    type: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class KubernetesServiceStatus:
    kind: ClassVar[str] = "kubernetes_service_status"
    kind_display: ClassVar[str] = "Kubernetes Service Status"
    kind_description: ClassVar[str] = (
        "Kubernetes Service Status refers to the current state or health of a service"
        " deployed on a Kubernetes cluster."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "conditions": S("conditions", default=[])
        >> SortTransitionTime
        >> ForallBend(KubernetesServiceStatusConditions.mapping),
        "load_balancer": S("loadBalancer") >> Bend(KubernetesLoadbalancerStatus.mapping),
    }
    conditions: List[KubernetesServiceStatusConditions] = field(factory=list)
    load_balancer: Optional[KubernetesLoadbalancerStatus] = field(default=None)


@define
class KubernetesServicePort:
    kind: ClassVar[str] = "kubernetes_service_port"
    kind_display: ClassVar[str] = "Kubernetes Service Port"
    kind_description: ClassVar[str] = (
        "A Kubernetes Service Port is a configuration that defines a port to expose"
        " for a Kubernetes service, allowing external access to the service."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "app_protocol": S("appProtocol"),
        "name": S("name"),
        "node_port": S("nodePort"),
        "port": S("port"),
        "protocol": S("protocol"),
        "target_port": S("targetPort"),
    }
    app_protocol: Optional[str] = field(default=None)
    name: Optional[str] = field(default=None)
    node_port: Optional[int] = field(default=None)
    port: Optional[int] = field(default=None)
    protocol: Optional[str] = field(default=None)
    target_port: Optional[Union[str, int]] = field(default=None)


@define
class KubernetesServiceSpec:
    kind: ClassVar[str] = "kubernetes_service_spec"
    kind_display: ClassVar[str] = "Kubernetes Service Spec"
    kind_description: ClassVar[str] = (
        "A Kubernetes Service Spec is a configuration file that defines how to expose"
        " and access a set of pods in a Kubernetes cluster. It specifies the type of"
        " service, port mapping, and other networking settings."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "allocate_load_balancer_node_ports": S("allocateLoadBalancerNodePorts"),
        "cluster_ip": S("clusterIP"),
        "cluster_ips": S("clusterIPs", default=[]),
        "external_ips": S("externalIPs", default=[]),
        "external_name": S("externalName"),
        "external_traffic_policy": S("externalTrafficPolicy"),
        "health_check_node_port": S("healthCheckNodePort"),
        "internal_traffic_policy": S("internalTrafficPolicy"),
        "ip_families": S("ipFamilies", default=[]),
        "ip_family_policy": S("ipFamilyPolicy"),
        "load_balancer_class": S("loadBalancerClass"),
        "load_balancer_ip": S("loadBalancerIP"),
        "load_balancer_source_ranges": S("loadBalancerSourceRanges", default=[]),
        "ports": S("ports", default=[]) >> ForallBend(KubernetesServicePort.mapping),
        "publish_not_ready_addresses": S("publishNotReadyAddresses"),
        "session_affinity": S("sessionAffinity"),
        "type": S("type"),
        "selector": S("selector", default={}),
    }
    allocate_load_balancer_node_ports: Optional[bool] = field(default=None)
    cluster_ip: Optional[str] = field(default=None)
    cluster_ips: List[str] = field(factory=list)
    external_ips: List[str] = field(factory=list)
    external_name: Optional[str] = field(default=None)
    external_traffic_policy: Optional[str] = field(default=None)
    health_check_node_port: Optional[int] = field(default=None)
    internal_traffic_policy: Optional[str] = field(default=None)
    ip_families: List[str] = field(factory=list)
    ip_family_policy: Optional[str] = field(default=None)
    load_balancer_class: Optional[str] = field(default=None)
    load_balancer_ip: Optional[str] = field(default=None)
    load_balancer_source_ranges: List[str] = field(factory=list)
    ports: List[KubernetesServicePort] = field(factory=list)
    publish_not_ready_addresses: Optional[bool] = field(default=None)
    session_affinity: Optional[str] = field(default=None)
    type: Optional[str] = field(default=None)
    selector: Optional[Dict[str, str]] = field(default=None)


@define(eq=False, slots=False)
class KubernetesService(KubernetesResource, BaseLoadBalancer):
    kind: ClassVar[str] = "kubernetes_service"
    kind_display: ClassVar[str] = "Kubernetes Service"
    kind_description: ClassVar[str] = (
        "A Kubernetes Service is an abstraction layer that defines a logical set of"
        " Pods and a policy by which to access them, providing a stable endpoint for"
        " accessing applications deployed on a Kubernetes cluster."
    )
    mapping: ClassVar[Dict[str, Bender]] = KubernetesResource.mapping | {
        "service_status": S("status") >> Bend(KubernetesServiceStatus.mapping),
        "service_spec": S("spec") >> Bend(KubernetesServiceSpec.mapping),
        "public_ip_address": S("spec", "externalIPs", 0),
    }
    reference_kinds: ClassVar[ModelReference] = {
        "successors": {
            "default": ["kubernetes_pod", "kubernetes_endpoint_slice"],
            "delete": [],
        }
    }
    service_status: Optional[KubernetesServiceStatus] = field(default=None, metadata=dict(ignore_history=True))
    service_spec: Optional[KubernetesServiceSpec] = field(default=None)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        super().connect_in_graph(builder, source)
        resolved_backends = set()

        pods = [
            ((key, val), pod)
            for pod in builder.graph.nodes
            if isinstance(pod, KubernetesPod)
            for key, val in pod.labels.items()
        ]
        pods_by_labels = defaultdict(list)
        for (key, val), pod in pods:
            pods_by_labels[(key, val)].append(pod)

        selector = bend(S("spec", "selector"), source)
        if selector:
            builder.add_edges_from_selector(self, EdgeType.default, selector, KubernetesPod)

            for key, value in selector.items():
                for pod in pods_by_labels.get((key, value), []):
                    resolved_backends.add(pod.name or pod.id)

        self.backends = list(sorted(resolved_backends))


# endregion


@define(eq=False, slots=False)
class KubernetesPodTemplate(KubernetesResource):
    kind: ClassVar[str] = "kubernetes_pod_template"
    kind_display: ClassVar[str] = "Kubernetes Pod Template"
    kind_description: ClassVar[str] = (
        "A Kubernetes Pod Template is a blueprint for creating and organizing pods,"
        " which are the smallest and simplest building blocks in a Kubernetes cluster."
        " It defines the specifications for containers, volumes, and other resources"
        " that make up a pod."
    )


@define(eq=False, slots=False)
class KubernetesClusterInfo:
    kind: ClassVar[str] = "kubernetes_cluster_info"
    kind_display: ClassVar[str] = "Kubernetes Cluster Info"
    kind_description: ClassVar[str] = (
        "Kubernetes Cluster Info provides information about the cluster using the"
        " Kubernetes container orchestration platform. It includes details about the"
        " nodes, pods, services, and other resources in the cluster."
    )
    major: str
    minor: str
    platform: str
    server_url: str


@define(eq=False, slots=False)
class KubernetesCluster(KubernetesResource, BaseAccount):
    kind: ClassVar[str] = "kubernetes_cluster"
    kind_display: ClassVar[str] = "Kubernetes Cluster"
    kind_description: ClassVar[str] = (
        "A Kubernetes cluster is a group of nodes (physical or virtual machines) that"
        " run containerized applications managed by Kubernetes."
    )
    reference_kinds: ClassVar[ModelReference] = {
        "successors": {
            "default": [
                "kubernetes_volume_attachment",
                "kubernetes_validating_webhook_configuration",
                "kubernetes_storage_class",
                "kubernetes_priority_level_configuration",
                "kubernetes_priority_class",
                "kubernetes_persistent_volume",
                "kubernetes_node",
                "kubernetes_namespace",
                "kubernetes_mutating_webhook_configuration",
                "kubernetes_flow_schema",
                "kubernetes_csi_node",
                "kubernetes_csi_driver",
                "kubernetes_cluster_role_binding",
                "kubernetes_cluster_role",
                "kubernetes_ingress_class",
            ],
            "delete": [],
        }
    }

    cluster_info: Optional[KubernetesClusterInfo] = None


@define(eq=False, slots=False)
class KubernetesConfigMap(KubernetesResource):
    kind: ClassVar[str] = "kubernetes_config_map"
    kind_display: ClassVar[str] = "Kubernetes Config Map"
    kind_description: ClassVar[str] = (
        "A Kubernetes Config Map is a way to store key-value pairs of configuration"
        " data that can be accessed by containers within a cluster."
    )
    # only use changed data for making a history change (not any base prop(
    metadata: ClassVar[Dict[str, Any]] = {"ignore_history": True}
    mapping: ClassVar[Dict[str, Bender]] = KubernetesResource.mapping | {"data": S("data")}
    data: Optional[Dict[str, str]] = field(default=None)


@define(eq=False, slots=False)
class KubernetesEndpointAddress:
    kind: ClassVar[str] = "kubernetes_endpoint_address"
    kind_display: ClassVar[str] = "Kubernetes Endpoint Address"
    kind_description: ClassVar[str] = (
        "The address of the Kubernetes endpoint, which is used to access and interact with a Kubernetes cluster."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "ip": S("ip"),
        "node_name": S("nodeName"),
        "_target_ref": S("targetRef", "uid"),
    }

    ip: Optional[str] = field(default=None)
    node_name: Optional[str] = field(default=None)
    _target_ref: Optional[str] = field(default=None)

    def target_ref(self) -> Optional[str]:
        return self._target_ref


@define(eq=False, slots=False)
class KubernetesEndpointPort:
    kind: ClassVar[str] = "kubernetes_endpoint_port"
    kind_display: ClassVar[str] = "Kubernetes Endpoint Port"
    kind_description: ClassVar[str] = (
        "Kubernetes Endpoint Port is the port number on which a service is exposed"
        " and can be accessed within a Kubernetes cluster."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "name": S("name"),
        "port": S("port"),
        "protocol": S("protocol"),
    }

    name: Optional[str] = field(default=None)
    port: Optional[int] = field(default=None)
    protocol: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class KubernetesEndpointSubset:
    kind: ClassVar[str] = "kubernetes_endpoint_subset"
    kind_display: ClassVar[str] = "Kubernetes Endpoint Subset"
    kind_description: ClassVar[str] = (
        "A subset of endpoints in a Kubernetes cluster, representing a group of"
        " network addresses where the Kubernetes services are accessible."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "addresses": S("addresses", default=[]) >> ForallBend(KubernetesEndpointAddress.mapping) >> Sort(S("ip")),
        "ports": S("ports", default=[]) >> ForallBend(KubernetesEndpointPort.mapping),
    }
    addresses: List[KubernetesEndpointAddress] = field(factory=list)
    ports: List[KubernetesEndpointPort] = field(factory=list)


@define(eq=False, slots=False)
class KubernetesEndpoints(KubernetesResource):
    kind: ClassVar[str] = "kubernetes_endpoint"
    kind_display: ClassVar[str] = "Kubernetes Endpoint"
    kind_description: ClassVar[str] = "A Kubernetes Endpoint defines a network address where a service can be accessed."
    mapping: ClassVar[Dict[str, Bender]] = KubernetesResource.mapping | {
        "subsets": S("subsets", default=[]) >> ForallBend(KubernetesEndpointSubset.mapping),
    }
    reference_kinds: ClassVar[ModelReference] = {
        "successors": {
            "default": ["kubernetes_pod", "kubernetes_node", "kubernetes_endpoint_slice"],
            "delete": [],
        }
    }

    subsets: List[KubernetesEndpointSubset] = field(factory=list)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        super().connect_in_graph(builder, source)
        for subset in self.subsets:
            for address in subset.addresses:
                if address.target_ref():
                    builder.add_edge(self, EdgeType.default, id=address.target_ref())


@define(eq=False, slots=False)
class KubernetesEndpointSlice(KubernetesResource):
    kind: ClassVar[str] = "kubernetes_endpoint_slice"
    kind_display: ClassVar[str] = "Kubernetes Endpoint Slice"
    kind_description: ClassVar[str] = (
        "Kubernetes Endpoint Slices are a feature that allows for more efficient and"
        " scalable service discovery in a Kubernetes cluster by splitting endpoints"
        " into smaller slices."
    )
    reference_kinds: ClassVar[ModelReference] = {
        "successors": {
            "default": [],
            "delete": ["kubernetes_service", "kubernetes_endpoint"],
        }
    }


@define(eq=False, slots=False)
class KubernetesLimitRange(KubernetesResource):
    kind: ClassVar[str] = "kubernetes_limit_range"
    kind_display: ClassVar[str] = "Kubernetes Limit Range"
    kind_description: ClassVar[str] = (
        "Kubernetes Limit Range is a feature that allows you to define resource"
        " constraints (such as CPU and memory limits) for containers and pods running"
        " on a Kubernetes cluster."
    )


@define(eq=False, slots=False)
class KubernetesNamespaceStatusConditions:
    kind: ClassVar[str] = "kubernetes_namespace_status_conditions"
    kind_display: ClassVar[str] = "Kubernetes Namespace Status Conditions"
    kind_description: ClassVar[str] = (
        "Kubernetes Namespace Status Conditions represent the current status and"
        " conditions of a namespace in a Kubernetes cluster."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "last_transition_time": S("lastTransitionTime"),
        "message": S("message"),
        "reason": S("reason"),
        "status": S("status"),
        "type": S("type"),
    }
    last_transition_time: Optional[datetime] = field(default=None)
    message: Optional[str] = field(default=None)
    reason: Optional[str] = field(default=None)
    status: Optional[str] = field(default=None)
    type: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class KubernetesNamespaceStatus:
    kind: ClassVar[str] = "kubernetes_namespace_status"
    kind_display: ClassVar[str] = "Kubernetes Namespace Status"
    kind_description: ClassVar[str] = (
        "This resource represents the status of a namespace in a Kubernetes cluster."
        " Namespaces are a way to divide cluster resources between multiple users or"
        " applications."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "conditions": S("conditions", default=[])
        >> SortTransitionTime
        >> ForallBend(KubernetesNamespaceStatusConditions.mapping),
        "phase": S("phase"),
    }
    conditions: List[KubernetesNamespaceStatusConditions] = field(factory=list)
    phase: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class KubernetesNamespace(KubernetesResource, BaseRegion):
    kind: ClassVar[str] = "kubernetes_namespace"
    kind_display: ClassVar[str] = "Kubernetes Namespace"
    kind_description: ClassVar[str] = (
        "A Kubernetes Namespace is a virtual cluster that allows users to divide"
        " resources and control access within a Kubernetes cluster."
    )
    mapping: ClassVar[Dict[str, Bender]] = KubernetesResource.mapping | {
        "namespace_status": S("status") >> Bend(KubernetesNamespaceStatus.mapping),
    }
    reference_kinds: ClassVar[ModelReference] = {
        "successors": {
            "default": [
                "kubernetes_stateful_set",
                "kubernetes_service",
                "kubernetes_secret",
                "kubernetes_role_binding",
                "kubernetes_role",
                "kubernetes_replica_set",
                "kubernetes_pod_disruption_budget",
                "kubernetes_pod",
                "kubernetes_job",
                "kubernetes_endpoint_slice",
                "kubernetes_service_account",
                "kubernetes_endpoint",
                "kubernetes_deployment",
                "kubernetes_persistent_volume_claim",
                "kubernetes_daemon_set",
                "kubernetes_cron_job",
                "kubernetes_controller_revision",
                "kubernetes_config_map",
            ],
            "delete": [],
        }
    }

    namespace_status: Optional[KubernetesNamespaceStatus] = field(default=None, metadata=dict(ignore_history=True))


@define(eq=False, slots=False)
class KubernetesPersistentVolumeStatus:
    kind: ClassVar[str] = "kubernetes_persistent_volume_status"
    kind_display: ClassVar[str] = "Kubernetes Persistent Volume Status"
    kind_description: ClassVar[str] = (
        "Persistent Volume Status represents the current state of a persistent volume"
        " in a Kubernetes cluster. It provides information about the volume's"
        " availability and usage."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "message": S("message"),
        "phase": S("phase"),
        "reason": S("reason"),
    }
    message: Optional[str] = field(default=None)
    phase: Optional[str] = field(default=None)
    reason: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class KubernetesPersistentVolumeSpecAwsElasticBlockStore:
    kind: ClassVar[str] = "kubernetes_persistent_volume_spec_aws_elastic_block_store"
    kind_display: ClassVar[str] = "Kubernetes Persistent Volume Spec AWS Elastic Block Store"
    kind_description: ClassVar[str] = (
        "This resource specification in Kubernetes is used to define a persistent"
        " volume that is backed by an Amazon Elastic Block Store (EBS) volume."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "volume_id": S("volumeID"),
        "fs_type": S("fsType"),
    }
    volume_id: Optional[str] = field(default=None)
    fs_type: Optional[str] = field(default=None)


@define
class KubernetesPersistentVolumeSpec:
    kind: ClassVar[str] = "kubernetes_persistent_volume_spec"
    kind_display: ClassVar[str] = "Kubernetes Persistent Volume Spec"
    kind_description: ClassVar[str] = (
        "A Persistent Volume Spec defines the properties and access modes of a"
        " persistent storage volume in Kubernetes, which can be dynamically"
        " provisioned and allocated to pods."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "access_modes": S("accessModes", default=[]),
        "aws_elastic_block_store": S("awsElasticBlockStore")
        >> Bend(KubernetesPersistentVolumeSpecAwsElasticBlockStore.mapping),
        "azure_disk": S("azureDisk"),
        "azure_file": S("azureFile"),
        "capacity": S("capacity"),
        "cephfs": S("cephfs"),
        "cinder": S("cinder"),
        "claim_ref": S("claimRef"),
        "csi": S("csi"),
        "fc": S("fc"),
        "flex_volume": S("flexVolume"),
        "flocker": S("flocker"),
        "gce_persistent_disk": S("gcePersistentDisk"),
        "glusterfs": S("glusterfs"),
        "host_path": S("hostPath"),
        "iscsi": S("iscsi"),
        "local": S("local"),
        "mount_options": S("mountOptions", default=[]),
        "nfs": S("nfs"),
        "node_affinity": S("nodeAffinity"),
        "persistent_volume_reclaim_policy": S("persistentVolumeReclaimPolicy"),
        "photon_persistent_disk": S("photonPersistentDisk"),
        "portworx_volume": S("portworxVolume"),
        "quobyte": S("quobyte"),
        "rbd": S("rbd"),
        "scale_io": S("scaleIO"),
        "storage_class_name": S("storageClassName"),
        "storageos": S("storageos"),
        "volume_mode": S("volumeMode"),
        "vsphere_volume": S("vsphereVolume"),
    }
    access_modes: List[str] = field(factory=list)
    aws_elastic_block_store: Optional[KubernetesPersistentVolumeSpecAwsElasticBlockStore] = field(default=None)
    azure_disk: Optional[str] = field(default=None)
    azure_file: Optional[str] = field(default=None)
    capacity: Optional[Json] = field(default=None)
    cephfs: Optional[str] = field(default=None)
    cinder: Optional[str] = field(default=None)
    claim_ref: Optional[Json] = field(default=None)
    csi: Optional[Any] = field(default=None)
    fc: Optional[str] = field(default=None)
    flex_volume: Optional[str] = field(default=None)
    flocker: Optional[str] = field(default=None)
    gce_persistent_disk: Optional[str] = field(default=None)
    glusterfs: Optional[str] = field(default=None)
    host_path: Optional[str] = field(default=None)
    iscsi: Optional[str] = field(default=None)
    local: Optional[str] = field(default=None)
    mount_options: List[str] = field(factory=list)
    nfs: Optional[str] = field(default=None)
    node_affinity: Optional[str] = field(default=None)
    persistent_volume_reclaim_policy: Optional[str] = field(default=None)
    photon_persistent_disk: Optional[str] = field(default=None)
    portworx_volume: Optional[str] = field(default=None)
    quobyte: Optional[str] = field(default=None)
    rbd: Optional[str] = field(default=None)
    scale_io: Optional[str] = field(default=None)
    storage_class_name: Optional[str] = field(default=None)
    storageos: Optional[str] = field(default=None)
    volume_mode: Optional[str] = field(default=None)
    vsphere_volume: Optional[str] = field(default=None)


VolumeStatusMapping = {
    "Available": VolumeStatus.AVAILABLE,
    "Bound": VolumeStatus.IN_USE,
    "Released": VolumeStatus.BUSY,
    "Failed": VolumeStatus.ERROR,
}


@define(eq=False, slots=False)
class KubernetesPersistentVolume(KubernetesResource, BaseVolume):
    kind: ClassVar[str] = "kubernetes_persistent_volume"
    kind_display: ClassVar[str] = "Kubernetes Persistent Volume"
    kind_description: ClassVar[str] = (
        "A Kubernetes Persistent Volume is a storage abstraction that provides access"
        " to persisted data for a Kubernetes cluster."
    )
    mapping: ClassVar[Dict[str, Bender]] = KubernetesResource.mapping | {
        "persistent_volume_status": S("status") >> Bend(KubernetesPersistentVolumeStatus.mapping),
        "persistent_volume_spec": S("spec") >> Bend(KubernetesPersistentVolumeSpec.mapping),
        "volume_size": S("spec", "capacity", "storage", default="0") >> StringToUnitNumber("GB"),
        "volume_type": S("spec", "storageClassName"),
        "volume_status": S("status", "phase") >> MapEnum(VolumeStatusMapping, VolumeStatus.UNKNOWN),
    }
    persistent_volume_status: Optional[KubernetesPersistentVolumeStatus] = field(
        default=None, metadata=dict(ignore_history=True)
    )
    persistent_volume_spec: Optional[KubernetesPersistentVolumeSpec] = field(default=None)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        super().connect_in_graph(builder, source)
        claim_ref = bend(S("spec", "claimRef", "uid"), source)
        if claim_ref:
            builder.add_edge(self, EdgeType.default, id=claim_ref, reverse=True)


@define(eq=False, slots=False)
class KubernetesReplicationControllerStatusConditions:
    kind: ClassVar[str] = "kubernetes_replication_controller_status_conditions"
    kind_display: ClassVar[str] = "Kubernetes Replication Controller Status Conditions"
    kind_description: ClassVar[str] = (
        "Kubernetes Replication Controller Status Conditions track the current state of a Replication Controller,"
        " including any events and their reasons, status, and types."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "last_transition_time": S("lastTransitionTime"),
        "message": S("message"),
        "reason": S("reason"),
        "status": S("status"),
        "type": S("type"),
    }
    last_transition_time: Optional[datetime] = field(default=None)
    message: Optional[str] = field(default=None)
    reason: Optional[str] = field(default=None)
    status: Optional[str] = field(default=None)
    type: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class KubernetesReplicationControllerStatus:
    kind: ClassVar[str] = "kubernetes_replication_controller_status"
    kind_display: ClassVar[str] = "Kubernetes Replication Controller Status"
    kind_description: ClassVar[str] = (
        "The replication controller status in Kubernetes provides information about"
        " the number of desired replicas, current replicas, and available replicas for"
        " a certain controller."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "available_replicas": S("availableReplicas"),
        "conditions": S("conditions", default=[])
        >> SortTransitionTime
        >> ForallBend(KubernetesReplicationControllerStatusConditions.mapping),
        "fully_labeled_replicas": S("fullyLabeledReplicas"),
        "observed_generation": S("observedGeneration"),
        "ready_replicas": S("readyReplicas"),
        "replicas": S("replicas"),
    }
    available_replicas: Optional[int] = field(default=None)
    conditions: List[KubernetesReplicationControllerStatusConditions] = field(factory=list)
    fully_labeled_replicas: Optional[int] = field(default=None)
    observed_generation: Optional[int] = field(default=None)
    ready_replicas: Optional[int] = field(default=None)
    replicas: Optional[int] = field(default=None)


@define(eq=False, slots=False)
class KubernetesReplicationController(KubernetesResource):
    kind: ClassVar[str] = "kubernetes_replication_controller"
    kind_display: ClassVar[str] = "Kubernetes Replication Controller"
    kind_description: ClassVar[str] = (
        "A Replication Controller is responsible for maintaining a specified number"
        " of pod replicas in a Kubernetes cluster. It ensures that the desired number"
        " of pods are always running in the cluster, even in the event of failures."
    )
    mapping: ClassVar[Dict[str, Bender]] = KubernetesResource.mapping | {
        "replication_controller_status": S("status") >> Bend(KubernetesReplicationControllerStatus.mapping),
    }
    replication_controller_status: Optional[KubernetesReplicationControllerStatus] = field(
        default=None, metadata=dict(ignore_history=True)
    )


@define(eq=False, slots=False)
class KubernetesResourceQuotaStatus:
    kind: ClassVar[str] = "kubernetes_resource_quota_status"
    kind_display: ClassVar[str] = "Kubernetes Resource Quota Status"
    kind_description: ClassVar[str] = (
        "Kubernetes Resource Quota Status provides information about the current"
        " resource utilization and limits for a namespace in a Kubernetes cluster."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "hard": S("hard"),
        "used": S("used"),
    }
    hard: Optional[Any] = field(default=None)
    used: Optional[Any] = field(default=None)


@define
class KubernetesResourceQuotaSpec:
    kind: ClassVar[str] = "kubernetes_resource_quota_spec"
    kind_display: ClassVar[str] = "Kubernetes Resource Quota Spec"
    kind_description: ClassVar[str] = (
        "Resource Quota Spec is a specification in Kubernetes that allows users to"
        " set limits on the amount of resources (CPU, memory, storage) that a"
        " namespace or a group of objects can consume."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "hard": S("hard"),
        "scope_selector": S("scopeSelector"),
        "scopes": S("scopes", default=[]),
    }
    hard: Optional[Any] = field(default=None)
    scope_selector: Optional[Any] = field(default=None)
    scopes: List[str] = field(factory=list)


@define(eq=False, slots=False)
class KubernetesResourceQuota(KubernetesResource, BaseQuota):
    kind: ClassVar[str] = "kubernetes_resource_quota"
    kind_display: ClassVar[str] = "Kubernetes Resource Quota"
    kind_description: ClassVar[str] = (
        "Kubernetes Resource Quota is a mechanism in Kubernetes for limiting and"
        " allocating resources to namespaces, ensuring fairness and preventing one"
        " namespace from using excessive resources."
    )
    mapping: ClassVar[Dict[str, Bender]] = KubernetesResource.mapping | {
        "resource_quota_status": S("status") >> Bend(KubernetesResourceQuotaStatus.mapping),
        "resource_quota_spec": S("spec") >> Bend(KubernetesResourceQuotaSpec.mapping),
    }
    resource_quota_status: Optional[KubernetesResourceQuotaStatus] = field(
        default=None, metadata=dict(ignore_history=True)
    )
    resource_quota_spec: Optional[KubernetesResourceQuotaSpec] = field(default=None)


@define(eq=False, slots=False)
class KubernetesSecret(KubernetesResource):
    kind: ClassVar[str] = "kubernetes_secret"
    kind_display: ClassVar[str] = "Kubernetes Secret"
    kind_description: ClassVar[str] = (
        "Kubernetes Secret is an object that contains sensitive data such as"
        " passwords, API keys, and tokens, which can be securely stored and accessed"
        " by containers in a Kubernetes cluster."
    )


@define(eq=False, slots=False)
class KubernetesServiceAccount(KubernetesResource):
    kind: ClassVar[str] = "kubernetes_service_account"
    kind_display: ClassVar[str] = "Kubernetes Service Account"
    kind_description: ClassVar[str] = (
        "A Kubernetes service account provides an identity and set of permissions for"
        " processes running in a pod within a Kubernetes cluster."
    )
    reference_kinds: ClassVar[ModelReference] = {"successors": {"default": ["kubernetes_secret"], "delete": []}}

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        super().connect_in_graph(builder, source)
        for secret in bend(S("secrets", default=[]), source):
            if name := secret.get("name", None):
                builder.add_edge(self, EdgeType.default, clazz=KubernetesSecret, name=name)


@define(eq=False, slots=False)
class KubernetesMutatingWebhookConfiguration(KubernetesResource):
    kind: ClassVar[str] = "kubernetes_mutating_webhook_configuration"
    kind_display: ClassVar[str] = "Kubernetes Mutating Webhook Configuration"
    kind_description: ClassVar[str] = (
        "Kubernetes Mutating Webhook Configuration allows you to define and configure"
        " webhooks that modify or mutate incoming requests to the Kubernetes API"
        " server."
    )


@define(eq=False, slots=False)
class KubernetesValidatingWebhookConfiguration(KubernetesResource):
    kind: ClassVar[str] = "kubernetes_validating_webhook_configuration"
    kind_display: ClassVar[str] = "Kubernetes Validating Webhook Configuration"
    kind_description: ClassVar[str] = (
        "A Kubernetes Validating Webhook Configuration is used to intercept and"
        " validate requests made to the Kubernetes API server, ensuring compliance"
        " with user-defined policies and preventing unauthorized access."
    )


@define(eq=False, slots=False)
class KubernetesControllerRevision(KubernetesResource):
    kind: ClassVar[str] = "kubernetes_controller_revision"
    kind_display: ClassVar[str] = "Kubernetes Controller Revision"
    kind_description: ClassVar[str] = (
        "Controller Revision in Kubernetes represents a specific revision of a controller's configuration and state."
    )
    reference_kinds: ClassVar[ModelReference] = {
        "successors": {
            "default": [],
            "delete": ["kubernetes_stateful_set", "kubernetes_daemon_set"],
        }
    }


@define(eq=False, slots=False)
class KubernetesDaemonSetStatusConditions:
    kind: ClassVar[str] = "kubernetes_daemon_set_status_conditions"
    kind_display: ClassVar[str] = "Kubernetes Daemon Set Status Conditions"
    kind_description: ClassVar[str] = (
        "Daemon Set Status Conditions represent the current conditions of a"
        " Kubernetes Daemon Set, which is used to ensure that a copy of a specific pod"
        " is running on each node in a cluster."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "last_transition_time": S("lastTransitionTime"),
        "message": S("message"),
        "reason": S("reason"),
        "status": S("status"),
        "type": S("type"),
    }
    last_transition_time: Optional[datetime] = field(default=None)
    message: Optional[str] = field(default=None)
    reason: Optional[str] = field(default=None)
    status: Optional[str] = field(default=None)
    type: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class KubernetesDaemonSetStatus:
    kind: ClassVar[str] = "kubernetes_daemon_set_status"
    kind_display: ClassVar[str] = "Kubernetes Daemon Set Status"
    kind_description: ClassVar[str] = (
        "The status of a Kubernetes Daemon Set, which is a way to ensure that a copy"
        " of a specific pod is running on all or some of the nodes in a cluster."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "collision_count": S("collisionCount"),
        "conditions": S("conditions", default=[])
        >> SortTransitionTime
        >> ForallBend(KubernetesDaemonSetStatusConditions.mapping),
        "current_number_scheduled": S("currentNumberScheduled"),
        "desired_number_scheduled": S("desiredNumberScheduled"),
        "number_available": S("numberAvailable"),
        "number_misscheduled": S("numberMisscheduled"),
        "number_ready": S("numberReady"),
        "number_unavailable": S("numberUnavailable"),
        "observed_generation": S("observedGeneration"),
        "updated_number_scheduled": S("updatedNumberScheduled"),
    }
    collision_count: Optional[int] = field(default=None)
    conditions: List[KubernetesDaemonSetStatusConditions] = field(factory=list)
    current_number_scheduled: Optional[int] = field(default=None)
    desired_number_scheduled: Optional[int] = field(default=None)
    number_available: Optional[int] = field(default=None)
    number_misscheduled: Optional[int] = field(default=None)
    number_ready: Optional[int] = field(default=None)
    number_unavailable: Optional[int] = field(default=None)
    observed_generation: Optional[int] = field(default=None)
    updated_number_scheduled: Optional[int] = field(default=None)


@define
class KubernetesPodTemplateSpec:
    kind: ClassVar[str] = "kubernetes_pod_template_spec"
    kind_display: ClassVar[str] = "Kubernetes Pod Template Spec"
    kind_description: ClassVar[str] = (
        "A Kubernetes Pod Template Spec defines the desired state for a pod,"
        " including the container images, environment variables, and other"
        " specifications."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "spec": S("spec") >> Bend(KubernetesPodSpec.mapping),
    }
    spec: Optional[KubernetesPodSpec] = field(default=None)


@define
class KubernetesDaemonSetSpec:
    kind: ClassVar[str] = "kubernetes_daemon_set_spec"
    kind_display: ClassVar[str] = "Kubernetes DaemonSet Spec"
    kind_description: ClassVar[str] = (
        "The Kubernetes DaemonSet Spec is a configuration that defines how pods are"
        " scheduled on every node in a Kubernetes cluster, ensuring that a copy of the"
        " specified pod runs on each node."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "min_ready_seconds": S("minReadySeconds"),
        "revision_history_limit": S("revisionHistoryLimit"),
        "selector": S("selector") >> Bend(KubernetesLabelSelector.mapping),
        "template": S("template") >> Bend(KubernetesPodTemplateSpec.mapping),
    }
    min_ready_seconds: Optional[int] = field(default=None)
    revision_history_limit: Optional[int] = field(default=None)
    selector: Optional[KubernetesLabelSelector] = field(default=None)
    template: Optional[KubernetesPodTemplateSpec] = field(default=None)


@define(eq=False, slots=False)
class KubernetesDaemonSet(KubernetesResource):
    kind: ClassVar[str] = "kubernetes_daemon_set"
    kind_display: ClassVar[str] = "Kubernetes DaemonSet"
    kind_description: ClassVar[str] = (
        "A Kubernetes DaemonSet ensures that all (or some) nodes in a cluster run a copy of a specified pod."
    )
    mapping: ClassVar[Dict[str, Bender]] = KubernetesResource.mapping | {
        "daemon_set_status": S("status") >> Bend(KubernetesDaemonSetStatus.mapping),
        "daemon_set_spec": S("spec") >> Bend(KubernetesDaemonSetSpec.mapping),
    }
    reference_kinds: ClassVar[ModelReference] = {
        "successors": {
            "default": ["kubernetes_pod", "kubernetes_controller_revision"],
            "delete": [],
        }
    }

    daemon_set_status: Optional[KubernetesDaemonSetStatus] = field(default=None, metadata=dict(ignore_history=True))
    daemon_set_spec: Optional[KubernetesDaemonSetSpec] = field(default=None)


@define(eq=False, slots=False)
class KubernetesDeploymentStatusCondition:
    kind: ClassVar[str] = "kubernetes_deployment_status_condition"
    kind_display: ClassVar[str] = "Kubernetes Deployment Status Condition"
    kind_description: ClassVar[str] = (
        "A condition in the status of a Kubernetes deployment that indicates the"
        " current state or status of the deployment."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "last_transition_time": S("lastTransitionTime"),
        "last_update_time": S("lastUpdateTime"),
        "message": S("message"),
        "reason": S("reason"),
        "status": S("status"),
        "type": S("type"),
    }
    last_transition_time: Optional[datetime] = field(default=None)
    last_update_time: Optional[datetime] = field(default=None)
    message: Optional[str] = field(default=None)
    reason: Optional[str] = field(default=None)
    status: Optional[str] = field(default=None)
    type: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class KubernetesDeploymentStatus:
    kind: ClassVar[str] = "kubernetes_deployment_status"
    kind_display: ClassVar[str] = "Kubernetes Deployment Status"
    kind_description: ClassVar[str] = (
        "Kubernetes Deployment Status represents the current state and health of a"
        " deployment in a Kubernetes cluster."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "available_replicas": S("availableReplicas"),
        "collision_count": S("collisionCount"),
        "conditions": S("conditions", default=[])
        >> SortTransitionTime
        >> ForallBend(KubernetesDeploymentStatusCondition.mapping),
        "observed_generation": S("observedGeneration"),
        "ready_replicas": S("readyReplicas"),
        "replicas": S("replicas"),
        "unavailable_replicas": S("unavailableReplicas"),
        "updated_replicas": S("updatedReplicas"),
    }
    available_replicas: Optional[int] = field(default=None)
    collision_count: Optional[int] = field(default=None)
    conditions: List[KubernetesDeploymentStatusCondition] = field(factory=list)
    observed_generation: Optional[int] = field(default=None)
    ready_replicas: Optional[int] = field(default=None)
    replicas: Optional[int] = field(default=None)
    unavailable_replicas: Optional[int] = field(default=None)
    updated_replicas: Optional[int] = field(default=None)


@define
class KubernetesRollingUpdateDeployment:
    kind: ClassVar[str] = "kubernetes_rolling_update_deployment"
    kind_display: ClassVar[str] = "Kubernetes Rolling Update Deployment"
    kind_description: ClassVar[str] = (
        "Rolling Update Deployment in Kubernetes allows for seamless updates of"
        " application deployments by gradually replacing existing instances with"
        " updated ones, ensuring zero downtime."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "max_surge": S("maxSurge"),
        "max_unavailable": S("maxUnavailable"),
    }
    max_surge: Optional[Union[str, int]] = field(default=None)
    max_unavailable: Optional[Union[str, int]] = field(default=None)


@define
class KubernetesDeploymentStrategy:
    kind: ClassVar[str] = "kubernetes_deployment_strategy"
    kind_display: ClassVar[str] = "Kubernetes Deployment Strategy"
    kind_description: ClassVar[str] = (
        "Kubernetes Deployment Strategy refers to the methodology used to manage and"
        " control the deployment of applications and services in a Kubernetes cluster,"
        " ensuring efficient and reliable deployment processes."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "rolling_update": S("rollingUpdate") >> Bend(KubernetesRollingUpdateDeployment.mapping),
        "type": S("type"),
    }
    rolling_update: Optional[KubernetesRollingUpdateDeployment] = field(default=None)
    type: Optional[str] = field(default=None)


@define
class KubernetesDeploymentSpec:
    kind: ClassVar[str] = "kubernetes_deployment_spec"
    kind_display: ClassVar[str] = "Kubernetes Deployment Spec"
    kind_description: ClassVar[str] = (
        "A Kubernetes Deployment Spec is a YAML specification file that defines how"
        " an application should be deployed and managed within a Kubernetes cluster."
        " It includes details such as the number of replicas, container images,"
        " networking, and resource requirements."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "min_ready_seconds": S("minReadySeconds"),
        "paused": S("paused"),
        "progress_deadline_seconds": S("progressDeadlineSeconds"),
        "replicas": S("replicas"),
        "revision_history_limit": S("revisionHistoryLimit"),
        "selector": S("selector") >> Bend(KubernetesLabelSelector.mapping),
        "strategy": S("strategy") >> Bend(KubernetesDeploymentStrategy.mapping),
        "template": S("template") >> Bend(KubernetesPodTemplateSpec.mapping),
    }
    min_ready_seconds: Optional[int] = field(default=None)
    paused: Optional[bool] = field(default=None)
    progress_deadline_seconds: Optional[int] = field(default=None)
    replicas: Optional[int] = field(default=None)
    revision_history_limit: Optional[int] = field(default=None)
    selector: Optional[KubernetesLabelSelector] = field(default=None)
    strategy: Optional[KubernetesDeploymentStrategy] = field(default=None)
    template: Optional[KubernetesPodTemplateSpec] = field(default=None)


@define(eq=False, slots=False)
class KubernetesDeployment(KubernetesResource):
    kind: ClassVar[str] = "kubernetes_deployment"
    kind_display: ClassVar[str] = "Kubernetes Deployment"
    kind_description: ClassVar[str] = (
        "A Kubernetes Deployment is a resource object in Kubernetes that defines how"
        " an application should be deployed and managed within a cluster."
    )
    mapping: ClassVar[Dict[str, Bender]] = KubernetesResource.mapping | {
        "deployment_status": S("status") >> Bend(KubernetesDeploymentStatus.mapping),
        "deployment_spec": S("spec") >> Bend(KubernetesDeploymentSpec.mapping),
    }
    reference_kinds: ClassVar[ModelReference] = {
        "successors": {
            "default": ["kubernetes_replica_set"],
            "delete": [],
        }
    }
    deployment_status: Optional[KubernetesDeploymentStatus] = field(default=None, metadata=dict(ignore_history=True))
    deployment_spec: Optional[KubernetesDeploymentSpec] = field(default=None)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        super().connect_in_graph(builder, source)
        selector = bend(S("spec", "selector", "matchLabels"), source)
        if selector:
            builder.add_edges_from_selector(self, EdgeType.default, selector, KubernetesReplicaSet)


@define(eq=False, slots=False)
class KubernetesReplicaSetStatusCondition:
    kind: ClassVar[str] = "kubernetes_replica_set_status_conditions"
    kind_display: ClassVar[str] = "Kubernetes Replica Set Status Conditions"
    kind_description: ClassVar[str] = (
        "Replica Set Status Conditions in Kubernetes are used to provide information"
        " about the current status of a Replica Set, such as whether it is progressing"
        " or has encountered any errors."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "last_transition_time": S("lastTransitionTime"),
        "message": S("message"),
        "reason": S("reason"),
        "status": S("status"),
        "type": S("type"),
    }
    last_transition_time: Optional[datetime] = field(default=None)
    message: Optional[str] = field(default=None)
    reason: Optional[str] = field(default=None)
    status: Optional[str] = field(default=None)
    type: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class KubernetesReplicaSetStatus:
    kind: ClassVar[str] = "kubernetes_replica_set_status"
    kind_display: ClassVar[str] = "Kubernetes Replica Set Status"
    kind_description: ClassVar[str] = (
        "The status of a Kubernetes Replica Set, which represents a set of pods that"
        " are all running the same application."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "available_replicas": S("availableReplicas"),
        "conditions": S("conditions", default=[])
        >> SortTransitionTime
        >> ForallBend(KubernetesReplicaSetStatusCondition.mapping),
        "fully_labeled_replicas": S("fullyLabeledReplicas"),
        "observed_generation": S("observedGeneration"),
        "ready_replicas": S("readyReplicas"),
        "replicas": S("replicas"),
    }
    available_replicas: Optional[int] = field(default=None)
    conditions: List[KubernetesReplicaSetStatusCondition] = field(factory=list)
    fully_labeled_replicas: Optional[int] = field(default=None)
    observed_generation: Optional[int] = field(default=None)
    ready_replicas: Optional[int] = field(default=None)
    replicas: Optional[int] = field(default=None)


@define
class KubernetesReplicaSetSpec:
    kind: ClassVar[str] = "kubernetes_replica_set_spec"
    kind_display: ClassVar[str] = "Kubernetes Replica Set Spec"
    kind_description: ClassVar[str] = (
        "A Kubernetes Replica Set Spec defines the desired state for creating and managing a group of replica pods."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "min_ready_seconds": S("minReadySeconds"),
        "replicas": S("replicas"),
        "selector": S("selector") >> Bend(KubernetesLabelSelector.mapping),
        "template": S("template") >> Bend(KubernetesPodTemplateSpec.mapping),
    }
    min_ready_seconds: Optional[int] = field(default=None)
    replicas: Optional[int] = field(default=None)
    selector: Optional[KubernetesLabelSelector] = field(default=None)
    template: Optional[KubernetesPodTemplateSpec] = field(default=None)


@define(eq=False, slots=False)
class KubernetesReplicaSet(KubernetesResource):
    kind: ClassVar[str] = "kubernetes_replica_set"
    kind_display: ClassVar[str] = "Kubernetes Replica Set"
    kind_description: ClassVar[str] = (
        "A ReplicaSet is a Kubernetes object that ensures a specified number of pod"
        " replicas are running at any given time, and handles scaling and self-healing"
        " of pods."
    )
    mapping: ClassVar[Dict[str, Bender]] = KubernetesResource.mapping | {
        "replica_set_status": S("status") >> Bend(KubernetesReplicaSetStatus.mapping),
        "replica_set_spec": S("spec") >> Bend(KubernetesReplicaSetSpec.mapping),
    }
    reference_kinds: ClassVar[ModelReference] = {
        "successors": {
            "default": ["kubernetes_pod"],
            "delete": ["kubernetes_deployment"],
        }
    }

    replica_set_status: Optional[KubernetesReplicaSetStatus] = field(default=None, metadata=dict(ignore_history=True))
    replica_set_spec: Optional[KubernetesReplicaSetSpec] = field(default=None)


@define(eq=False, slots=False)
class KubernetesStatefulSetStatusCondition:
    kind: ClassVar[str] = "kubernetes_stateful_set_status_condition"
    kind_display: ClassVar[str] = "Kubernetes StatefulSet Status Condition"
    kind_description: ClassVar[str] = (
        "A StatefulSet is a Kubernetes workload API object used to manage stateful"
        " applications. The status conditions provide information about the current"
        " state of the StatefulSet object."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "last_transition_time": S("lastTransitionTime"),
        "message": S("message"),
        "reason": S("reason"),
        "status": S("status"),
        "type": S("type"),
    }
    last_transition_time: Optional[datetime] = field(default=None)
    message: Optional[str] = field(default=None)
    reason: Optional[str] = field(default=None)
    status: Optional[str] = field(default=None)
    type: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class KubernetesStatefulSetStatus:
    kind: ClassVar[str] = "kubernetes_stateful_set_status"
    kind_display: ClassVar[str] = "Kubernetes Stateful Set Status"
    kind_description: ClassVar[str] = (
        "Stateful Set Status in Kubernetes represents the current status and"
        " condition of a Stateful Set, which is a workload API object used in"
        " Kubernetes for managing stateful applications and providing stable network"
        " identities to the pods."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "available_replicas": S("availableReplicas"),
        "collision_count": S("collisionCount"),
        "conditions": S("conditions", default=[])
        >> SortTransitionTime
        >> ForallBend(KubernetesStatefulSetStatusCondition.mapping),
        "current_replicas": S("currentReplicas"),
        "current_revision": S("currentRevision"),
        "observed_generation": S("observedGeneration"),
        "ready_replicas": S("readyReplicas"),
        "replicas": S("replicas"),
        "update_revision": S("updateRevision"),
        "updated_replicas": S("updatedReplicas"),
    }
    available_replicas: Optional[int] = field(default=None)
    collision_count: Optional[int] = field(default=None)
    conditions: List[KubernetesStatefulSetStatusCondition] = field(factory=list)
    current_replicas: Optional[int] = field(default=None)
    current_revision: Optional[str] = field(default=None)
    observed_generation: Optional[int] = field(default=None)
    ready_replicas: Optional[int] = field(default=None)
    replicas: Optional[int] = field(default=None)
    update_revision: Optional[str] = field(default=None)
    updated_replicas: Optional[int] = field(default=None)


@define
class KubernetesStatefulSetSpec:
    kind: ClassVar[str] = "kubernetes_stateful_set_spec"
    kind_display: ClassVar[str] = "Kubernetes StatefulSet Spec"
    kind_description: ClassVar[str] = (
        "A StatefulSet in Kubernetes is a workload API object that manages the"
        " deployment and scaling of a set of pods. The StatefulSet ensures that each"
        " pod in the set has a unique identity and that they are created and scaled in"
        " a predictable and ordered manner."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "min_ready_seconds": S("minReadySeconds"),
        "pod_management_policy": S("podManagementPolicy"),
        "replicas": S("replicas"),
        "revision_history_limit": S("revisionHistoryLimit"),
        "selector": S("selector") >> Bend(KubernetesLabelSelector.mapping),
        "service_name": S("serviceName"),
        "template": S("template") >> Bend(KubernetesPodTemplateSpec.mapping),
    }
    min_ready_seconds: Optional[int] = field(default=None)
    pod_management_policy: Optional[str] = field(default=None)
    replicas: Optional[int] = field(default=None)
    revision_history_limit: Optional[int] = field(default=None)
    selector: Optional[KubernetesLabelSelector] = field(default=None)
    service_name: Optional[str] = field(default=None)
    template: Optional[KubernetesPodTemplateSpec] = field(default=None)


@define(eq=False, slots=False)
class KubernetesStatefulSet(KubernetesResource):
    kind: ClassVar[str] = "kubernetes_stateful_set"
    kind_display: ClassVar[str] = "Kubernetes Stateful Set"
    kind_description: ClassVar[str] = (
        "A Kubernetes Stateful Set is a higher-level resource that allows for the"
        " management of stateful applications in a Kubernetes cluster. It ensures"
        " ordered deployment, scaling, and termination of replicas while maintaining"
        " stable network identities."
    )
    mapping: ClassVar[Dict[str, Bender]] = KubernetesResource.mapping | {
        "stateful_set_status": S("status") >> Bend(KubernetesStatefulSetStatus.mapping),
        "stateful_set_spec": S("spec") >> Bend(KubernetesStatefulSetSpec.mapping),
    }
    reference_kinds: ClassVar[ModelReference] = {
        "successors": {
            "default": ["kubernetes_pod", "kubernetes_controller_revision"],
            "delete": [],
        }
    }

    stateful_set_status: Optional[KubernetesStatefulSetStatus] = field(default=None, metadata=dict(ignore_history=True))
    stateful_set_spec: Optional[KubernetesStatefulSetSpec] = field(default=None)


@define(eq=False, slots=False)
class KubernetesHorizontalPodAutoscalerStatus:
    kind: ClassVar[str] = "kubernetes_horizontal_pod_autoscaler_status"
    kind_display: ClassVar[str] = "Kubernetes Horizontal Pod Autoscaler Status"
    kind_description: ClassVar[str] = (
        "The Horizontal Pod Autoscaler in Kubernetes automatically scales the number"
        " of pods running in a deployment based on the observed CPU utilization."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "current_cpu_utilization_percentage": S("currentCPUUtilizationPercentage"),
        "current_replicas": S("currentReplicas"),
        "desired_replicas": S("desiredReplicas"),
        "last_scale_time": S("lastScaleTime"),
        "observed_generation": S("observedGeneration"),
    }
    current_cpu_utilization_percentage: Optional[int] = field(default=None)
    current_replicas: Optional[int] = field(default=None)
    desired_replicas: Optional[int] = field(default=None)
    last_scale_time: Optional[datetime] = field(default=None)
    observed_generation: Optional[int] = field(default=None)


@define
class KubernetesCrossVersionObjectReference:
    kind: ClassVar[str] = "kubernetes_cross_version_object_reference"
    kind_display: ClassVar[str] = "Kubernetes Cross Version Object Reference"
    kind_description: ClassVar[str] = (
        "The `scale_target_ref` in a Kubernetes Horizontal Pod Autoscaler Spec is a reference to another resource,"
        " whose replicas the autoscaler should manage."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "api_version": S("apiVersion"),
        "resource_kind": S("kind"),
        "name": S("name"),
    }
    api_version: Optional[str] = field(default=None)
    resource_kind: Optional[str] = field(default=None)
    name: Optional[str] = field(default=None)


@define
class KubernetesHorizontalPodAutoscalerSpec:
    kind: ClassVar[str] = "kubernetes_horizontal_pod_autoscaler_spec"
    kind_display: ClassVar[str] = "Kubernetes Horizontal Pod Autoscaler Spec"
    kind_description: ClassVar[str] = (
        "The Kubernetes Horizontal Pod Autoscaler Spec is used to configure the"
        " autoscaling behavior of pods in a Kubernetes cluster, allowing for automatic"
        " scaling based on resource utilization metrics."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "max_replicas": S("maxReplicas"),
        "min_replicas": S("minReplicas"),
        "scale_target_ref": S("scaleTargetRef") >> Bend(KubernetesCrossVersionObjectReference.mapping),
        "target_cpu_utilization_percentage": S("targetCPUUtilizationPercentage"),
    }
    max_replicas: Optional[int] = field(default=None)
    min_replicas: Optional[int] = field(default=None)
    scale_target_ref: Optional[KubernetesCrossVersionObjectReference] = field(default=None)
    target_cpu_utilization_percentage: Optional[int] = field(default=None)


@define(eq=False, slots=False)
class KubernetesHorizontalPodAutoscaler(KubernetesResource):
    kind: ClassVar[str] = "kubernetes_horizontal_pod_autoscaler"
    kind_display: ClassVar[str] = "Kubernetes Horizontal Pod Autoscaler"
    kind_description: ClassVar[str] = (
        "The Kubernetes Horizontal Pod Autoscaler automatically scales the number of"
        " pods in a deployment up or down based on CPU usage or other specified"
        " metrics."
    )
    mapping: ClassVar[Dict[str, Bender]] = KubernetesResource.mapping | {
        "horizontal_pod_autoscaler_status": S("status") >> Bend(KubernetesHorizontalPodAutoscalerStatus.mapping),
        "horizontal_pod_autoscaler_spec": S("spec") >> Bend(KubernetesHorizontalPodAutoscalerSpec.mapping),
    }
    horizontal_pod_autoscaler_status: Optional[KubernetesHorizontalPodAutoscalerStatus] = field(
        default=None, metadata=dict(ignore_history=True)
    )
    horizontal_pod_autoscaler_spec: Optional[KubernetesHorizontalPodAutoscalerSpec] = field(default=None)


@define(eq=False, slots=False)
class KubernetesCronJobStatusActive:
    kind: ClassVar[str] = "kubernetes_cron_job_status_active"
    kind_display: ClassVar[str] = "Kubernetes Cron Job Status Active"
    kind_description: ClassVar[str] = (
        "Cron jobs are scheduled tasks in Kubernetes that run at specified intervals."
        " The 'active' status indicates that the cron job is currently running or has"
        " recently completed."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "api_version": S("apiVersion"),
        "field_path": S("fieldPath"),
        "name": S("name"),
        "namespace": S("namespace"),
        "resource_version": S("resourceVersion"),
        "uid": S("uid"),
    }
    api_version: Optional[str] = field(default=None)
    field_path: Optional[str] = field(default=None)
    name: Optional[str] = field(default=None)
    namespace: Optional[str] = field(default=None)
    resource_version: Optional[str] = field(default=None)
    uid: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class KubernetesCronJobStatus:
    kind: ClassVar[str] = "kubernetes_cron_job_status"
    kind_display: ClassVar[str] = "Kubernetes Cron Job Status"
    kind_description: ClassVar[str] = (
        "Kubernetes Cron Job Status represents the status of a scheduled job in a Kubernetes cluster."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "active": S("active", default=[]) >> ForallBend(KubernetesCronJobStatusActive.mapping),
        "last_schedule_time": S("lastScheduleTime"),
        "last_successful_time": S("lastSuccessfulTime"),
    }
    active: List[KubernetesCronJobStatusActive] = field(factory=list)
    last_schedule_time: Optional[datetime] = field(default=None)
    last_successful_time: Optional[datetime] = field(default=None)


@define
class KubernetesJobSpec:
    kind: ClassVar[str] = "kubernetes_job_spec"
    kind_display: ClassVar[str] = "Kubernetes Job Spec"
    kind_description: ClassVar[str] = (
        "A Kubernetes Job Spec is a declarative configuration file that defines a"
        " task or set of tasks to be run as part of a Kubernetes cluster, ensuring the"
        " task is successfully completed."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "active_deadline_seconds": S("activeDeadlineSeconds"),
        "backoff_limit": S("backoffLimit"),
        "completion_mode": S("completionMode"),
        "completions": S("completions"),
        "manual_selector": S("manualSelector"),
        "parallelism": S("parallelism"),
        "selector": S("selector") >> Bend(KubernetesLabelSelector.mapping),
        "suspend": S("suspend"),
        "template": S("template") >> Bend(KubernetesPodTemplateSpec.mapping),
        "ttl_seconds_after_finished": S("ttlSecondsAfterFinished"),
    }
    active_deadline_seconds: Optional[int] = field(default=None)
    backoff_limit: Optional[int] = field(default=None)
    completion_mode: Optional[str] = field(default=None)
    completions: Optional[int] = field(default=None)
    manual_selector: Optional[bool] = field(default=None)
    parallelism: Optional[int] = field(default=None)
    selector: Optional[KubernetesLabelSelector] = field(default=None)
    suspend: Optional[bool] = field(default=None)
    template: Optional[KubernetesPodTemplateSpec] = field(default=None)
    ttl_seconds_after_finished: Optional[int] = field(default=None)


@define
class KubernetesJobTemplateSpec:
    kind: ClassVar[str] = "kubernetes_job_template_spec"
    kind_display: ClassVar[str] = "Kubernetes Job Template Spec"
    kind_description: ClassVar[str] = (
        "A Kubernetes Job Template Spec is a specification for creating and managing"
        " batch jobs in a Kubernetes cluster."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "spec": S("spec") >> Bend(KubernetesJobSpec.mapping),
    }
    spec: Optional[KubernetesJobSpec] = field(default=None)


@define
class KubernetesCronJobSpec:
    kind: ClassVar[str] = "kubernetes_cron_job_spec"
    kind_display: ClassVar[str] = "Kubernetes Cron Job Spec"
    kind_description: ClassVar[str] = (
        "A Kubernetes Cron Job Spec is a resource specification used to define a"
        " scheduled job that runs at specified intervals in a Kubernetes cluster."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "concurrency_policy": S("concurrencyPolicy"),
        "failed_jobs_history_limit": S("failedJobsHistoryLimit"),
        "job_template": S("jobTemplate") >> Bend(KubernetesJobTemplateSpec.mapping),
        "schedule": S("schedule"),
        "starting_deadline_seconds": S("startingDeadlineSeconds"),
        "successful_jobs_history_limit": S("successfulJobsHistoryLimit"),
        "suspend": S("suspend"),
        "time_zone": S("timeZone"),
    }
    concurrency_policy: Optional[str] = field(default=None)
    failed_jobs_history_limit: Optional[int] = field(default=None)
    job_template: Optional[KubernetesJobTemplateSpec] = field(default=None)
    schedule: Optional[str] = field(default=None)
    starting_deadline_seconds: Optional[int] = field(default=None)
    successful_jobs_history_limit: Optional[int] = field(default=None)
    suspend: Optional[bool] = field(default=None)
    time_zone: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class KubernetesCronJob(KubernetesResource):
    kind: ClassVar[str] = "kubernetes_cron_job"
    kind_display: ClassVar[str] = "Kubernetes Cron Job"
    kind_description: ClassVar[str] = (
        "Kubernetes Cron Jobs are used to schedule and run jobs, which are tasks or"
        " scripts, at specified intervals within a Kubernetes cluster."
    )
    mapping: ClassVar[Dict[str, Bender]] = KubernetesResource.mapping | {
        "cron_job_status": S("status") >> Bend(KubernetesCronJobStatus.mapping),
        "cron_job_spec": S("spec") >> Bend(KubernetesCronJobSpec.mapping),
    }
    reference_kinds: ClassVar[ModelReference] = {"successors": {"default": ["kubernetes_job"], "delete": []}}

    cron_job_status: Optional[KubernetesCronJobStatus] = field(default=None, metadata=dict(ignore_history=True))
    cron_job_spec: Optional[KubernetesCronJobSpec] = field(default=None)


@define(eq=False, slots=False)
class KubernetesJobStatusConditions:
    kind: ClassVar[str] = "kubernetes_job_status_conditions"
    kind_display: ClassVar[str] = "Kubernetes Job Status Conditions"
    kind_description: ClassVar[str] = (
        "Conditions represent the current status of a Kubernetes job, such as whether"
        " it is complete, succeeded, failed, or has an error."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "last_probe_time": S("lastProbeTime"),
        "last_transition_time": S("lastTransitionTime"),
        "message": S("message"),
        "reason": S("reason"),
        "status": S("status"),
        "type": S("type"),
    }
    last_probe_time: Optional[datetime] = field(default=None)
    last_transition_time: Optional[datetime] = field(default=None)
    message: Optional[str] = field(default=None)
    reason: Optional[str] = field(default=None)
    status: Optional[str] = field(default=None)
    type: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class KubernetesJobStatus:
    kind: ClassVar[str] = "kubernetes_job_status"
    kind_display: ClassVar[str] = "Kubernetes Job Status"
    kind_description: ClassVar[str] = (
        "Kubernetes Job Status refers to the current state and progress of a job in a Kubernetes cluster."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "active": S("active"),
        "completed_indexes": S("completedIndexes"),
        "completion_time": S("completionTime"),
        "conditions": S("conditions", default=[])
        >> SortTransitionTime
        >> ForallBend(KubernetesJobStatusConditions.mapping),
        "failed": S("failed"),
        "ready": S("ready"),
        "start_time": S("startTime"),
        "succeeded": S("succeeded"),
    }
    active: Optional[int] = field(default=None)
    completed_indexes: Optional[str] = field(default=None)
    completion_time: Optional[datetime] = field(default=None)
    conditions: List[KubernetesJobStatusConditions] = field(factory=list)
    failed: Optional[int] = field(default=None)
    ready: Optional[int] = field(default=None)
    start_time: Optional[datetime] = field(default=None)
    succeeded: Optional[int] = field(default=None)


@define(eq=False, slots=False)
class KubernetesJob(KubernetesResource):
    kind: ClassVar[str] = "kubernetes_job"
    kind_display: ClassVar[str] = "Kubernetes Job"
    kind_description: ClassVar[str] = (
        "A Kubernetes Job is a resource that creates one or more pods and ensures"
        " that a specified number of them successfully terminate."
    )
    mapping: ClassVar[Dict[str, Bender]] = KubernetesResource.mapping | {
        "job_status": S("status") >> Bend(KubernetesJobStatus.mapping),
        "job_spec": S("spec") >> Bend(KubernetesJobSpec.mapping),
    }
    reference_kinds: ClassVar[ModelReference] = {
        "successors": {"default": ["kubernetes_pod"], "delete": ["kubernetes_cron_job"]}
    }

    job_status: Optional[KubernetesJobStatus] = field(default=None, metadata=dict(ignore_history=True))
    job_spec: Optional[KubernetesJobSpec] = field(default=None)


@define(eq=False, slots=False)
class KubernetesFlowSchemaStatusConditions:
    kind: ClassVar[str] = "kubernetes_flow_schema_status_conditions"
    kind_display: ClassVar[str] = "Kubernetes Flow Schema Status Conditions"
    kind_description: ClassVar[str] = (
        "Flow Schema Status Conditions represent the current status of a flow schema in a Kubernetes cluster."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "last_transition_time": S("lastTransitionTime"),
        "message": S("message"),
        "reason": S("reason"),
        "status": S("status"),
        "type": S("type"),
    }
    last_transition_time: Optional[datetime] = field(default=None)
    message: Optional[str] = field(default=None)
    reason: Optional[str] = field(default=None)
    status: Optional[str] = field(default=None)
    type: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class KubernetesFlowSchemaStatus:
    kind: ClassVar[str] = "kubernetes_flow_schema_status"
    kind_display: ClassVar[str] = "Kubernetes Flow Schema Status"
    kind_description: ClassVar[str] = (
        "The Kubernetes Flow Schema Status represents the current state of a FlowSchema resource, indicating whether"
        " it is actively being used in the API server to manage traffic flow and priorities."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "conditions": S("conditions", default=[])
        >> SortTransitionTime
        >> ForallBend(KubernetesFlowSchemaStatusConditions.mapping),
    }
    conditions: List[KubernetesFlowSchemaStatusConditions] = field(factory=list)


@define(eq=False, slots=False)
class KubernetesFlowSchema(KubernetesResource):
    kind: ClassVar[str] = "kubernetes_flow_schema"
    kind_display: ClassVar[str] = "Kubernetes Flow Schema"
    kind_description: ClassVar[str] = (
        "A Kubernetes Flow Schema configures the prioritization and fairness for requests in the API server, managing"
        " the sequence and concurrency of request processing."
    )
    mapping: ClassVar[Dict[str, Bender]] = KubernetesResource.mapping | {
        "flow_schema_status": S("status") >> Bend(KubernetesFlowSchemaStatus.mapping),
    }
    flow_schema_status: Optional[KubernetesFlowSchemaStatus] = field(default=None, metadata=dict(ignore_history=True))


@define(eq=False, slots=False)
class KubernetesPriorityLevelConfigurationStatusConditions:
    kind: ClassVar[str] = "kubernetes_priority_level_configuration_status_conditions"
    kind_display: ClassVar[str] = "Kubernetes Priority Level Configuration Status Conditions"
    kind_description: ClassVar[str] = (
        "Priority Level Configuration Status Conditions represent different"
        " conditions or states of priority level configuration in Kubernetes."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "last_transition_time": S("lastTransitionTime"),
        "message": S("message"),
        "reason": S("reason"),
        "status": S("status"),
        "type": S("type"),
    }
    last_transition_time: Optional[datetime] = field(default=None)
    message: Optional[str] = field(default=None)
    reason: Optional[str] = field(default=None)
    status: Optional[str] = field(default=None)
    type: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class KubernetesPriorityLevelConfigurationStatus:
    kind: ClassVar[str] = "kubernetes_priority_level_configuration_status"
    kind_display: ClassVar[str] = "Kubernetes Priority Level Configuration Status"
    kind_description: ClassVar[str] = (
        "Kubernetes Priority Level Configuration Status provides the current state of a priority level configuration,"
        " including information on operational parameters and health."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "conditions": S("conditions", default=[])
        >> SortTransitionTime
        >> ForallBend(KubernetesPriorityLevelConfigurationStatusConditions.mapping),
    }
    conditions: List[KubernetesPriorityLevelConfigurationStatusConditions] = field(factory=list)


@define(eq=False, slots=False)
class KubernetesPriorityLevelConfiguration(KubernetesResource):
    kind: ClassVar[str] = "kubernetes_priority_level_configuration"
    kind_display: ClassVar[str] = "Kubernetes Priority Level Configuration"
    kind_description: ClassVar[str] = (
        "The Kubernetes Priority Level Configuration represents resource configuration for establishing priority"
        " levels of network traffic in a cluster."
    )
    mapping: ClassVar[Dict[str, Bender]] = KubernetesResource.mapping | {
        "priority_level_configuration_status": S("status") >> Bend(KubernetesPriorityLevelConfigurationStatus.mapping),
    }
    priority_level_configuration_status: Optional[KubernetesPriorityLevelConfigurationStatus] = field(
        default=None, metadata=dict(ignore_history=True)
    )


@define(eq=False, slots=False)
class KubernetesIngressStatusLoadbalancerIngressPorts:
    kind: ClassVar[str] = "kubernetes_ingress_status_loadbalancer_ingress_ports"
    kind_display: ClassVar[str] = "Kubernetes Ingress Status LoadBalancer Ingress Ports"
    kind_description: ClassVar[str] = (
        "Kubernetes Ingress Status LoadBalancer Ingress Ports indicate the ports on the load balancer through which"
        " traffic is routed to the Ingress, including any errors encountered, the specific ports used, and the"
        " protocols (such as HTTP or HTTPS) associated with those ports."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "error": S("error"),
        "port": S("port"),
        "protocol": S("protocol"),
    }
    error: Optional[str] = field(default=None)
    port: Optional[int] = field(default=None)
    protocol: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class KubernetesIngressStatusLoadbalancerIngress:
    kind: ClassVar[str] = "kubernetes_ingress_status_loadbalancer_ingress"
    kind_display: ClassVar[str] = "Kubernetes Ingress Status LoadBalancer Ingress"
    kind_description: ClassVar[str] = (
        "The LoadBalancer Ingress status in Kubernetes Ingress represents the"
        " externally-reachable IP addresses associated with the load balancer."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "hostname": S("hostname"),
        "ip": S("ip"),
        "ports": S("ports", default=[]) >> ForallBend(KubernetesIngressStatusLoadbalancerIngressPorts.mapping),
    }
    hostname: Optional[str] = field(default=None)
    ip: Optional[str] = field(default=None)
    ports: List[KubernetesIngressStatusLoadbalancerIngressPorts] = field(factory=list)


@define(eq=False, slots=False)
class KubernetesIngressStatusLoadbalancer:
    kind: ClassVar[str] = "kubernetes_ingress_status_loadbalancer"
    kind_display: ClassVar[str] = "Kubernetes Ingress Status LoadBalancer"
    kind_description: ClassVar[str] = (
        "Kubernetes Ingress Status LoadBalancer represents the status of a load"
        " balancer associated with a Kubernetes Ingress."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "ingress": S("ingress", default=[]) >> ForallBend(KubernetesIngressStatusLoadbalancerIngress.mapping),
    }
    ingress: List[KubernetesIngressStatusLoadbalancerIngress] = field(factory=list)


@define(eq=False, slots=False)
class KubernetesIngressStatus:
    kind: ClassVar[str] = "kubernetes_ingress_status"
    kind_display: ClassVar[str] = "Kubernetes Ingress Status"
    kind_description: ClassVar[str] = (
        "Kubernetes Ingress Status is a functionality in Kubernetes that provides"
        " information about the status of the Ingress resource, which is used to"
        " configure external access to services within a cluster."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "load_balancer": S("loadBalancer") >> Bend(KubernetesIngressStatusLoadbalancer.mapping),
    }
    load_balancer: Optional[KubernetesIngressStatusLoadbalancer] = field(default=None)


@define
class KubernetesIngressRule:
    kind: ClassVar[str] = "kubernetes_ingress_rule"
    kind_display: ClassVar[str] = "Kubernetes Ingress Rule"
    kind_description: ClassVar[str] = (
        "A Kubernetes Ingress Rule defines how incoming traffic should be directed to"
        " services within a Kubernetes cluster."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "host": S("host"),
        "http": S("http"),
    }
    host: Optional[str] = field(default=None)
    http: Optional[Any] = field(default=None)


@define
class KubernetesIngressTLS:
    kind: ClassVar[str] = "kubernetes_ingress_tls"
    kind_display: ClassVar[str] = "Kubernetes Ingress TLS"
    kind_description: ClassVar[str] = (
        "Kubernetes Ingress TLS is a configuration that enables secure communication"
        " over HTTPS between clients and services within the Kubernetes cluster, using"
        " Transport Layer Security (TLS) encryption."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "hosts": S("hosts", default=[]),
        "secret_name": S("secretName"),
    }
    hosts: List[str] = field(factory=list)
    secret_name: Optional[str] = field(default=None)


@define
class KubernetesIngressSpec:
    kind: ClassVar[str] = "kubernetes_ingress_spec"
    kind_display: ClassVar[str] = "Kubernetes Ingress Spec"
    kind_description: ClassVar[str] = (
        "The Kubernetes Ingress Spec is a configuration that defines how external"
        " traffic is routed to services within a Kubernetes cluster."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "ingress_class_name": S("ingressClassName"),
        "rules": S("rules", default=[]) >> ForallBend(KubernetesIngressRule.mapping),
        "tls": S("tls", default=[]) >> ForallBend(KubernetesIngressTLS.mapping),
    }
    ingress_class_name: Optional[str] = field(default=None)
    rules: List[KubernetesIngressRule] = field(factory=list)
    tls: List[KubernetesIngressTLS] = field(factory=list)


def get_backend_service_names(json: Json) -> List[str]:
    default_services: Optional[str] = bend(
        S(
            "spec",
            "defaultBackend",
            "service",
            "name",
        ),
        json,
    )
    services_from_rules: List[str] = bend(
        S("spec", "rules", default=[])
        >> ForallBend(S("http", "paths", default=[]) >> ForallBend(S("backend", "service", "name")))
        >> F(lambda outer: [elem for inner in outer for elem in inner if elem]),
        json,
    )

    if default_services:
        services_from_rules.append(default_services)

    return services_from_rules


@define(eq=False, slots=False)
class KubernetesIngress(KubernetesResource, BaseLoadBalancer):
    kind: ClassVar[str] = "kubernetes_ingress"
    kind_display: ClassVar[str] = "Kubernetes Ingress"
    kind_description: ClassVar[str] = (
        "Kubernetes Ingress is an API object that manages external access to services within a Kubernetes cluster."
    )
    mapping: ClassVar[Dict[str, Bender]] = KubernetesResource.mapping | {
        "ingress_status": S("status") >> Bend(KubernetesIngressStatus.mapping),
        "public_ip_address": S("status", "loadBalancer", "ingress", default=[])[0]["ip"],
        # take the public ip of the first load balancer
        "ingress_spec": S("spec") >> Bend(KubernetesIngressSpec.mapping),
        # temporary values, they will be replaced in connect_in_graph call with pod ids
        "backends": F(get_backend_service_names),
    }
    ingress_status: Optional[KubernetesIngressStatus] = field(default=None, metadata=dict(ignore_history=True))
    ingress_spec: Optional[KubernetesIngressSpec] = field(default=None)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        super().connect_in_graph(builder, source)

        pods = [
            ((key, val), pod)
            for pod in builder.graph.nodes
            if isinstance(pod, KubernetesPod)
            for key, val in pod.labels.items()
        ]
        pods_by_labels: Dict[Tuple[str, str], List[KubernetesPod]] = defaultdict(list)
        for (key, val), pod in pods:
            pods_by_labels[(key, val)].append(pod)

        resolved_backends: Set[str] = set()

        for backend in self.backends:
            for service in builder.graph.searchall({"kind": KubernetesService.kind, "name": backend}):
                if not isinstance(service, KubernetesService):
                    continue

                builder.add_edge(self, edge_type=EdgeType.default, node=service)

                selector = service.service_spec.selector if service.service_spec else {}
                if not selector:
                    continue

                for key, value in selector.items():
                    for pod in pods_by_labels.get((key, value), []):
                        resolved_backends.add(pod.name or pod.id)

        self.backends = list(sorted(resolved_backends))


@define(eq=False, slots=False)
class KubernetesIngressClass(KubernetesResource):
    kind: ClassVar[str] = "kubernetes_ingress_class"
    kind_display: ClassVar[str] = "Kubernetes Ingress Class"
    kind_description: ClassVar[str] = (
        "Kubernetes Ingress Class is a resource that defines a class of Ingress"
        " controllers in a cluster, providing a way to configure external access to"
        " services within the cluster."
    )
    mapping: ClassVar[Dict[str, Bender]] = KubernetesResource.mapping | {}


@define(eq=False, slots=False)
class KubernetesNetworkPolicyStatusConditions:
    kind: ClassVar[str] = "kubernetes_network_policy_status_conditions"
    kind_display: ClassVar[str] = "Kubernetes Network Policy Status Conditions"
    kind_description: ClassVar[str] = (
        "Kubernetes Network Policy Status Conditions track the health and status changes of a network policy,"
        " including reasons and timestamps."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "last_transition_time": S("lastTransitionTime"),
        "message": S("message"),
        "observed_generation": S("observedGeneration"),
        "reason": S("reason"),
        "status": S("status"),
        "type": S("type"),
    }
    last_transition_time: Optional[datetime] = field(default=None)
    message: Optional[str] = field(default=None)
    observed_generation: Optional[int] = field(default=None)
    reason: Optional[str] = field(default=None)
    status: Optional[str] = field(default=None)
    type: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class KubernetesNetworkPolicyStatus:
    kind: ClassVar[str] = "kubernetes_network_policy_status"
    kind_display: ClassVar[str] = "Kubernetes Network Policy Status"
    kind_description: ClassVar[str] = (
        "The status of a Kubernetes Network Policy indicates the current operational condition of the network"
        " policy, such as whether it's active or encountering issues."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "conditions": S("conditions", default=[])
        >> SortTransitionTime
        >> ForallBend(KubernetesNetworkPolicyStatusConditions.mapping),
    }
    conditions: List[KubernetesNetworkPolicyStatusConditions] = field(factory=list)


@define(eq=False, slots=False)
class KubernetesNetworkPolicy(KubernetesResource):
    kind: ClassVar[str] = "kubernetes_network_policy"
    kind_display: ClassVar[str] = "Kubernetes Network Policy"
    kind_description: ClassVar[str] = (
        "Kubernetes Network Policy is used to define and enforce network rules and"
        " policies for communication between pods in a Kubernetes cluster."
    )
    mapping: ClassVar[Dict[str, Bender]] = KubernetesResource.mapping | {
        "network_policy_status": S("status") >> Bend(KubernetesNetworkPolicyStatus.mapping),
    }
    network_policy_status: Optional[KubernetesNetworkPolicyStatus] = field(
        default=None, metadata=dict(ignore_history=True)
    )


@define(eq=False, slots=False)
class KubernetesRuntimeClass(KubernetesResource):
    kind: ClassVar[str] = "kubernetes_runtime_class"
    kind_display: ClassVar[str] = "Kubernetes Runtime Class"
    kind_description: ClassVar[str] = (
        "Kubernetes Runtime Class is a resource in Kubernetes that allows you to"
        " specify different runtime configurations for pods, such as the container"
        " runtime or resource limits."
    )
    mapping: ClassVar[Dict[str, Bender]] = KubernetesResource.mapping | {}


@define(eq=False, slots=False)
class KubernetesPodDisruptionBudgetStatusConditions:
    kind: ClassVar[str] = "kubernetes_pod_disruption_budget_status_conditions"
    kind_display: ClassVar[str] = "Kubernetes Pod Disruption Budget Status Conditions"
    kind_description: ClassVar[str] = (
        "The Kubernetes Pod Disruption Budget Status Conditions reflect the detailed status"
        " and transitions of a Pod Disruption Budget."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "last_transition_time": S("lastTransitionTime"),
        "message": S("message"),
        "observed_generation": S("observedGeneration"),
        "reason": S("reason"),
        "status": S("status"),
        "type": S("type"),
    }
    last_transition_time: Optional[datetime] = field(default=None)
    message: Optional[str] = field(default=None)
    observed_generation: Optional[int] = field(default=None)
    reason: Optional[str] = field(default=None)
    status: Optional[str] = field(default=None)
    type: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class KubernetesPodDisruptionBudgetStatus:
    kind: ClassVar[str] = "kubernetes_pod_disruption_budget_status"
    kind_display: ClassVar[str] = "Kubernetes Pod Disruption Budget Status"
    kind_description: ClassVar[str] = (
        "The Kubernetes Pod Disruption Budget Status provides a snapshot of the current state of the"
        " pod disruption budget including health and disruption information."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "conditions": S("conditions", default=[])
        >> SortTransitionTime
        >> ForallBend(KubernetesPodDisruptionBudgetStatusConditions.mapping),
        "current_healthy": S("currentHealthy"),
        "desired_healthy": S("desiredHealthy"),
        "disrupted_pods": S("disruptedPods"),
        "disruptions_allowed": S("disruptionsAllowed"),
        "expected_pods": S("expectedPods"),
        "observed_generation": S("observedGeneration"),
    }
    conditions: List[KubernetesPodDisruptionBudgetStatusConditions] = field(factory=list)
    current_healthy: Optional[int] = field(default=None)
    desired_healthy: Optional[int] = field(default=None)
    disrupted_pods: Optional[Any] = field(default=None)
    disruptions_allowed: Optional[int] = field(default=None)
    expected_pods: Optional[int] = field(default=None)
    observed_generation: Optional[int] = field(default=None)


@define
class KubernetesPodDisruptionBudgetSpec:
    kind: ClassVar[str] = "kubernetes_pod_disruption_budget_spec"
    kind_display: ClassVar[str] = "Kubernetes Pod Disruption Budget Spec"
    kind_description: ClassVar[str] = (
        "A Kubernetes Pod Disruption Budget Spec defines the criteria for evicting pods"
        " from a node in a controlled way."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "max_unavailable": S("maxUnavailable"),
        "min_available": S("minAvailable"),
        "selector": S("selector") >> Bend(KubernetesLabelSelector.mapping),
    }
    max_unavailable: Optional[Union[str, int]] = field(default=None)
    min_available: Optional[Union[str, int]] = field(default=None)
    selector: Optional[KubernetesLabelSelector] = field(default=None)


@define(eq=False, slots=False)
class KubernetesPodDisruptionBudget(KubernetesResource):
    kind: ClassVar[str] = "kubernetes_pod_disruption_budget"
    kind_display: ClassVar[str] = "Kubernetes Pod Disruption Budget"
    kind_description: ClassVar[str] = (
        "A Kubernetes Pod Disruption Budget (PDB) is used to ensure that a specified number or percentage of"
        " pods within a replicated application remain available during voluntary disruptions."
    )
    mapping: ClassVar[Dict[str, Bender]] = KubernetesResource.mapping | {
        "pod_disruption_budget_status": S("status") >> Bend(KubernetesPodDisruptionBudgetStatus.mapping),
        "pod_disruption_budget_spec": S("spec") >> Bend(KubernetesPodDisruptionBudgetSpec.mapping),
    }
    pod_disruption_budget_status: Optional[KubernetesPodDisruptionBudgetStatus] = field(
        default=None, metadata=dict(ignore_history=True)
    )
    pod_disruption_budget_spec: Optional[KubernetesPodDisruptionBudgetSpec] = field(default=None)


@define(eq=False, slots=False)
class KubernetesClusterRole(KubernetesResource):
    kind: ClassVar[str] = "kubernetes_cluster_role"
    kind_display: ClassVar[str] = "Kubernetes Cluster Role"
    kind_description: ClassVar[str] = (
        "A Kubernetes Cluster Role is a set of permissions that defines what actions"
        " a user or group can perform within a Kubernetes cluster."
    )


@define(eq=False, slots=False)
class KubernetesClusterRoleBinding(KubernetesResource):
    kind: ClassVar[str] = "kubernetes_cluster_role_binding"
    kind_display: ClassVar[str] = "Kubernetes Cluster Role Binding"
    kind_description: ClassVar[str] = (
        "Cluster Role Binding is a Kubernetes resource that grants permissions to a"
        " Role or ClusterRole within a specific cluster."
    )


@define(eq=False, slots=False)
class KubernetesRole(KubernetesResource):
    kind: ClassVar[str] = "kubernetes_role"
    kind_display: ClassVar[str] = "Kubernetes Role"
    kind_description: ClassVar[str] = (
        "A Kubernetes role is a set of permissions that define what actions a user or"
        " group can perform on resources within a Kubernetes cluster."
    )


@define(eq=False, slots=False)
class KubernetesRoleBinding(KubernetesResource):
    kind: ClassVar[str] = "kubernetes_role_binding"
    kind_display: ClassVar[str] = "Kubernetes Role Binding"
    kind_description: ClassVar[str] = (
        "Kubernetes Role Binding is used to bind roles with groups or users, granting"
        " them permission to access and manage resources within a Kubernetes cluster."
    )


@define(eq=False, slots=False)
class KubernetesPriorityClass(KubernetesResource):
    kind: ClassVar[str] = "kubernetes_priority_class"
    kind_display: ClassVar[str] = "Kubernetes Priority Class"
    kind_description: ClassVar[str] = (
        "Kubernetes Priority Classes are used to assign priority to Pods in a"
        " Kubernetes cluster, allowing system administrators to control scheduling"
        " preferences and resource allocation for different workloads."
    )


@define(eq=False, slots=False)
class KubernetesCSIDriver(KubernetesResource):
    kind: ClassVar[str] = "kubernetes_csi_driver"
    kind_display: ClassVar[str] = "Kubernetes CSI Driver"
    kind_description: ClassVar[str] = (
        "A Kubernetes Container Storage Interface (CSI) driver is a plugin that"
        " allows external storage systems to be dynamically provisioned and managed by"
        " Kubernetes."
    )


@define(eq=False, slots=False)
class KubernetesCSINode(KubernetesResource):
    kind: ClassVar[str] = "kubernetes_csi_node"
    kind_display: ClassVar[str] = "Kubernetes CSI Node"
    kind_description: ClassVar[str] = (
        "A Kubernetes CSI (Container Storage Interface) Node is a cluster node where a CSI driver is installed,"
        " enabling it to interact with the storage backends to attach, mount, or unmount volumes as required"
        " by Pods on that node."
    )


@define(eq=False, slots=False)
class KubernetesCSIStorageCapacity(KubernetesResource):
    kind: ClassVar[str] = "kubernetes_csi_storage_capacity"
    kind_display: ClassVar[str] = "Kubernetes CSI Storage Capacity"
    kind_description: ClassVar[str] = (
        "Kubernetes CSI (Container Storage Interface) Storage Capacity refers to the"
        " amount of storage available for use by containers in a Kubernetes cluster"
        " using the CSI storage driver."
    )


@define(eq=False, slots=False)
class KubernetesStorageClass(KubernetesResource):
    kind: ClassVar[str] = "kubernetes_storage_class"
    kind_display: ClassVar[str] = "Kubernetes Storage Class"
    kind_description: ClassVar[str] = (
        "A Storage Class in Kubernetes provides a way to define different types of"
        " storage with different performance characteristics for application pods."
    )


@define(eq=False, slots=False)
class KubernetesVolumeError:
    kind: ClassVar[str] = "kubernetes_volume_error"
    kind_display: ClassVar[str] = "Kubernetes Volume Error"
    kind_description: ClassVar[str] = (
        "Kubernetes Volume Error refers to an issue or problem related to the use of"
        " volumes in a Kubernetes cluster, which can affect the successful storage and"
        " retrieval of data within the cluster."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "message": S("message"),
        "time": S("time"),
    }
    message: Optional[str] = field(default=None)
    time: Optional[datetime] = field(default=None)


@define(eq=False, slots=False)
class KubernetesVolumeAttachmentStatus:
    kind: ClassVar[str] = "kubernetes_volume_attachment_status"
    kind_display: ClassVar[str] = "Kubernetes Volume Attachment Status"
    kind_description: ClassVar[str] = (
        "Kubernetes Volume Attachment Status reflects the current attachment state of a volume to a node."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "attach_error": S("attachError") >> Bend(KubernetesVolumeError.mapping),
        "attached": S("attached"),
        "attachment_metadata": S("attachmentMetadata"),
        "detach_error": S("detachError") >> Bend(KubernetesVolumeError.mapping),
    }
    attach_error: Optional[KubernetesVolumeError] = field(default=None)
    attached: Optional[bool] = field(default=None)
    attachment_metadata: Optional[Any] = field(default=None)
    detach_error: Optional[KubernetesVolumeError] = field(default=None)


@define
class KubernetesVolumeAttachmentSpec:
    kind: ClassVar[str] = "kubernetes_volume_attachment_spec"
    kind_display: ClassVar[str] = "Kubernetes Volume Attachment Spec"
    kind_description: ClassVar[str] = (
        "Kubernetes Volume Attachment Spec is a specification used to attach a volume"
        " to a Kubernetes cluster, allowing for persistent storage for containers in"
        " the cluster."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "attacher": S("attacher"),
        "node_name": S("nodeName"),
        "source": S("source"),
    }
    attacher: Optional[str] = field(default=None)
    node_name: Optional[str] = field(default=None)
    source: Optional[Any] = field(default=None)


@define(eq=False, slots=False)
class KubernetesVolumeAttachment(KubernetesResource):
    kind: ClassVar[str] = "kubernetes_volume_attachment"
    kind_display: ClassVar[str] = "Kubernetes Volume Attachment"
    kind_description: ClassVar[str] = (
        "Kubernetes Volume Attachment is a resource that allows persistent volumes to"
        " be attached to a pod in a Kubernetes cluster."
    )
    mapping: ClassVar[Dict[str, Bender]] = KubernetesResource.mapping | {
        "volume_attachment_status": S("status") >> Bend(KubernetesVolumeAttachmentStatus.mapping),
        "volume_attachment_spec": S("spec") >> Bend(KubernetesVolumeAttachmentSpec.mapping),
    }
    volume_attachment_status: Optional[KubernetesVolumeAttachmentStatus] = field(
        default=None, metadata=dict(ignore_history=True)
    )
    volume_attachment_spec: Optional[KubernetesVolumeAttachmentSpec] = field(default=None)


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
    # KubernetesEvent, # ignore events
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
all_k8s_resources_by_fix_name: Dict[str, Type[KubernetesResource]] = {a.kind: a for a in all_k8s_resources}
