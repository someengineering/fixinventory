import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import ClassVar, Optional, Dict, Type, List

import jsons
from jsonbender import S, Bender, bend, F, OptionalS, K
from jsonbender.list_ops import Forall, ForallBend
from jsons import set_deserializer
from resoto_plugin_k8s.bender_opts import MapValue, StringToUnitNumber, CPUCoresToNumber, Bend
from resotolib.baseresources import BaseAccount, BaseResource, BaseInstance, BaseRegion, InstanceStatus
from resotolib.types import Json

# region Covered Resources


@dataclass
class KubernetesResource(BaseResource):
    kind: ClassVar[str] = "kubernetes_resource"
    k8s_name: ClassVar[str] = "unknown"

    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("metadata", "uid"),
        "tags": OptionalS("metadata", "annotations"),
        "name": S("metadata", "name"),
        "ctime": S("metadata", "creationTimestamp"),
        "resource_version": S("metadata", "resourceVersion"),
        "namespace": OptionalS("metadata", "namespace"),
    }

    resource_version: Optional[str] = None
    namespace: Optional[str] = None

    def to_js(self) -> Json:
        return jsons.dump(  # type: ignore
            self,
            strip_privates=True,
            strip_attr=(
                "k8s_name",
                "mapping",
                "phantom",
                "successor_kinds",
                "parent_resource",
                "usage_percentage",
                "dname",
                "kdname",
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
            ),
        )

    def to_json(self) -> str:
        return json.dumps(self.to_js())

    @classmethod
    def from_json(cls: Type["KubernetesResource"], json: Json) -> "KubernetesResource":
        mapped = bend(cls.mapping, json)
        return jsons.load(mapped, cls)

    def update_tag(self, key, value) -> bool:
        raise NotImplementedError

    def delete_tag(self, key) -> bool:
        raise NotImplementedError

    def delete(self, graph) -> bool:
        raise NotImplementedError


@dataclass
class KubernetesCondition:
    kind: ClassVar[str] = "kubernetes_base_condition"
    mapping: ClassVar[Dict[str, Bender]] = {
        "last_transition_time": OptionalS("lastTransitionTime"),
        "message": OptionalS("message"),
        "reason": OptionalS("reason"),
        "status": OptionalS("status"),
        "type": S("type"),
    }
    last_transition_time: datetime
    message: Optional[str]
    reason: Optional[str]
    status: Optional[str]
    type: str


@dataclass
class KubernetesNamespace(KubernetesResource, BaseRegion):
    kind: ClassVar[str] = "kubernetes_namespace"
    k8s_name: ClassVar[str] = "Namespace"


instance_status_map: ClassVar[Dict[str, str]] = {
    "Pending": InstanceStatus.BUSY,
    "Running": InstanceStatus.RUNNING,
    "Failed": InstanceStatus.TERMINATED,
    "Succeeded": InstanceStatus.STOPPED,
    "Unknown": InstanceStatus.UNKNOWN,
}


@dataclass
class KubernetesContainerStatus:
    kind: ClassVar[str] = "kubernetes_container_status"
    mapping: ClassVar[Dict[str, Bender]] = {
        "container_id": OptionalS("containerID"),
        "image": S("image"),
        "image_id": S("imageID"),
        "name": S("name"),
        "ready": S("ready"),
        "restart_count": S("restartCount"),
    }
    container_id: Optional[str]
    image: Optional[str]
    image_id: str
    ready: bool
    restart_count: int


@dataclass
class KubernetesPodCondition(KubernetesCondition):
    kind: ClassVar[str] = "kubernetes_pod_condition"
    mapping: ClassVar[Dict[str, Bender]] = KubernetesCondition.mapping | {
        "last_probe_time": OptionalS("lastProbeTime"),
    }
    last_probe_time: Optional[datetime]


@dataclass
class KubernetesPod(KubernetesResource, BaseInstance):
    kind: ClassVar[str] = "kubernetes_pod"
    k8s_name: ClassVar[str] = "Pod"
    mapping: ClassVar[Dict[str, Bender]] = KubernetesResource.mapping | {
        "instance_status": S("status", "phase") >> MapValue(instance_status_map) >> F(lambda x: x.value),
        "pod_conditions": S("status", "conditions") >> ForallBend(KubernetesPodCondition.mapping),
        "pod_container_statuses": S("status", "containerStatuses") >> ForallBend(KubernetesContainerStatus.mapping),
        "pod_init_container_statuses": S("status", "initContainerStatuses")
        >> ForallBend(KubernetesContainerStatus.mapping),
        "phase": S("status", "phase"),
        "host_ip": S("status", "hostIP"),
        "pod_ip": S("status", "podIP"),
        "pod_ips": S("status", "podIPs") >> Forall(lambda x: x["ip"]),
        "qos_class": S("status", "qosClass"),
    }

    pod_conditions: List[KubernetesPodCondition] = field(default_factory=list)
    pod_container_statuses: List[KubernetesContainerStatus] = field(default_factory=list)
    pod_init_container_statuses: List[KubernetesContainerStatus] = field(default_factory=list)
    phase: Optional[str] = None
    host_ip: Optional[str] = None
    pod_ip: Optional[str] = None
    pod_ips: List[str] = field(default_factory=list)
    qos_class: Optional[str] = None

    def _instance_status_getter(self) -> str:
        return self._instance_status

    def _instance_status_setter(self, value: str) -> None:
        self._instance_status = value


# noinspection PyProtectedMember
KubernetesPod.instance_status = property(KubernetesPod._instance_status_getter, KubernetesPod._instance_status_setter)


@dataclass
class KubernetesContainerImage:
    kind: ClassVar[str] = "kubernetes_node_condition"
    mapping: ClassVar[Dict[str, Bender]] = {
        "names": S("names"),
        "size_bytes": S("sizeBytes"),
    }
    names: List[str]
    size_bytes: int


@dataclass
class KubernetesNodeCondition(KubernetesCondition):
    kind: ClassVar[str] = "kubernetes_node_condition"
    mapping: ClassVar[Dict[str, Bender]] = KubernetesCondition.mapping | {
        "last_heartbeat_time": OptionalS("lastHeartbeatTime"),
    }
    last_heartbeat_time: Optional[datetime]


@dataclass
class KubernetesNodeInfo:
    kind: ClassVar[str] = "kubernetes_node_info"
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
    architecture: str
    boot_id: str
    container_runtime_version: str
    kernel_version: str
    kube_proxy_version: str
    kubelet_version: str
    machine_id: str
    operating_system: str
    os_image: str
    system_uuid: str


@dataclass
class KubernetesAttachedVolume:
    kind: ClassVar[str] = "kubernetes_attached_volume"
    mapping: ClassVar[Dict[str, Bender]] = {"name": S("name"), "device_path": S("devicePath")}

    name: str
    device_path: str


@dataclass
class KubernetesNode(KubernetesResource, BaseInstance):
    kind: ClassVar[str] = "kubernetes_node"
    k8s_name: ClassVar[str] = "Node"
    mapping: ClassVar[Dict[str, Bender]] = KubernetesResource.mapping | {
        "provider_id": S("spec", "providerID"),
        "instance_cores": S("status", "capacity", "cpu") >> CPUCoresToNumber(),
        "instance_memory": S("status", "capacity", "memory") >> StringToUnitNumber("GB"),
        "instance_type": K("kubernetes_node"),
        "instance_status": K(InstanceStatus.RUNNING.value),
        "node_conditions": S("status", "conditions") >> ForallBend(KubernetesNodeCondition.mapping),
        "node_daemon_endpoints": S("status", "daemonEndpoints") >> F(lambda de: {k: v["Port"] for k, v in de.items()}),
        "node_images": S("status", "images") >> ForallBend(KubernetesContainerImage.mapping),
        "node_info": S("status", "nodeInfo") >> Bend(KubernetesNodeInfo.mapping),
        "node_volumes_attached": S("status", "volumesAttached") >> ForallBend(KubernetesAttachedVolume.mapping),
        "node_volumes_in_use": S("status", "volumesInUse"),
    }

    provider_id: Optional[str] = None
    node_conditions: List[KubernetesNodeCondition] = field(default_factory=list)
    node_daemon_endpoints: Dict[str, int] = field(default_factory=dict)
    node_info: Optional[KubernetesNodeInfo] = None
    node_images: List[KubernetesContainerImage] = field(default_factory=list)
    node_volumes_attached: List[KubernetesAttachedVolume] = field(default_factory=list)
    node_volumes_in_use: List[str] = field(default_factory=list)

    def _instance_status_getter(self) -> str:
        return self._instance_status

    def _instance_status_setter(self, value: str) -> None:
        self._instance_status = value


# noinspection PyProtectedMember
KubernetesNode.instance_status = property(
    KubernetesNode._instance_status_getter, KubernetesNode._instance_status_setter
)


@dataclass
class KubernetesDaemonSetCondition(KubernetesCondition):
    kind: ClassVar[str] = "kubernetes_daemon_set_condition"


@dataclass
class KubernetesDaemonSetStatus:
    kind: ClassVar[str] = "kubernetes_daemon_set_status"
    mapping: ClassVar[Dict[str, Bender]] = {
        "collision_count": OptionalS("collisionCount"),
        "current_number_scheduled": OptionalS("currentNumberScheduled"),
        "desired_number_scheduled": OptionalS("desiredNumberScheduled"),
        "number_available": OptionalS("numberAvailable"),
        "number_misscheduled": OptionalS("numberMisscheduled"),
        "number_ready": OptionalS("numberReady"),
        "number_unavailable": OptionalS("numberUnavailable"),
        "observed_generation": OptionalS("observedGeneration"),
        "updated_number_scheduled": OptionalS("updatedNumberScheduled"),
        "conditions": OptionalS("conditions", default=[]) >> ForallBend(KubernetesDaemonSetCondition.mapping),
    }
    collisionCount: Optional[int]
    currentNumberScheduled: Optional[int]
    desiredNumberScheduled: Optional[int]
    numberAvailable: Optional[int]
    numberMisscheduled: Optional[int]
    numberReady: Optional[int]
    numberUnavailable: Optional[int]
    observedGeneration: Optional[int]
    updatedNumberScheduled: Optional[int]
    conditions: List[KubernetesDaemonSetCondition] = field(default_factory=list)


@dataclass
class KubernetesDaemonSet(KubernetesResource):
    kind: ClassVar[str] = "kubernetes_daemon_set"
    k8s_name: ClassVar[str] = "DaemonSet"
    mapping: ClassVar[Dict[str, Bender]] = KubernetesResource.mapping | {
        "daemon_set_status": S("status") >> Bend(KubernetesDaemonSetStatus.mapping),
    }

    daemon_set_status: Optional[KubernetesDaemonSetStatus] = None


@dataclass
class KubernetesCluster(BaseAccount, KubernetesResource):
    kind: ClassVar[str] = "kubernetes_cluster"
    k8s_name: ClassVar[str] = "Cluster"


@dataclass
class KubernetesDeploymentCondition(KubernetesCondition):
    kind: ClassVar[str] = "kubernetes_deployment_condition"
    mapping: ClassVar[Dict[str, Bender]] = KubernetesCondition.mapping | {
        "last_update_time": OptionalS("lastUpdateTime"),
    }
    last_update_time: Optional[datetime]


@dataclass
class KubernetesDeploymentStatus:
    kind: ClassVar[str] = "kubernetes_deployment_status"
    mapping: ClassVar[Dict[str, Bender]] = {
        "available_replicas": OptionalS("availableReplicas"),
        "collision_count": OptionalS("collisionCount"),
        "observed_generation": OptionalS("observedGeneration"),
        "ready_replicas": OptionalS("readyReplicas"),
        "replicas": OptionalS("replicas"),
        "unavailable_replicas": OptionalS("unavailableReplicas"),
        "updated_replicas": OptionalS("updatedReplicas"),
        "conditions": OptionalS("conditions") >> ForallBend(KubernetesDeploymentCondition.mapping),
    }

    available_replicas: Optional[int]
    collision_count: Optional[int]
    observed_generation: Optional[int]
    ready_replicas: Optional[int]
    replicas: Optional[int]
    unavailable_replicas: Optional[int]
    updated_replicas: Optional[int]
    conditions: List[KubernetesDeploymentCondition] = field(default_factory=list)


@dataclass
class KubernetesDeployment(KubernetesResource):
    kind: ClassVar[str] = "kubernetes_deployment"
    k8s_name: ClassVar[str] = "Deployment"
    mapping: ClassVar[Dict[str, Bender]] = KubernetesResource.mapping | {
        "deployment_status": S("status") >> Bend(KubernetesDeploymentStatus.mapping),
    }
    deployment_status: Optional[KubernetesDeploymentStatus] = None


# endregion


@dataclass
class KubernetesControllerRevision(KubernetesResource):
    kind: ClassVar[str] = "kubernetes_controller_revision"
    k8s_name: ClassVar[str] = "ControllerRevision"


@dataclass
class KubernetesHorizontalPodAutoscaler(KubernetesResource):
    kind: ClassVar[str] = "kubernetes_horizontal_pod_autoscaler"
    k8s_name: ClassVar[str] = "HorizontalPodAutoscaler"

    max_replicas: int = 0
    min_replicas: int = 0


@dataclass
class KubernetesReplicaSet(KubernetesResource, BaseResource):
    kind: ClassVar[str] = "kubernetes_replica_set"
    k8s_name: ClassVar[str] = "ReplicaSet"

    replicas: int = 0


@dataclass
class KubernetesStatefulSet(KubernetesResource, BaseResource):
    kind: ClassVar[str] = "kubernetes_stateful_set"
    k8s_name: ClassVar[str] = "StatefulSet"


all_k8s_resources: List[Type[KubernetesResource]] = [
    KubernetesCluster,
    KubernetesControllerRevision,
    KubernetesDaemonSet,
    KubernetesDeployment,
    KubernetesHorizontalPodAutoscaler,
    KubernetesNamespace,
    KubernetesNode,
    KubernetesPod,
    KubernetesReplicaSet,
    KubernetesStatefulSet,
]

all_k8s_resources_by_k8s_name = {a.k8s_name: a for a in all_k8s_resources}
all_k8s_resources_by_resoto_name = {a.kind: a for a in all_k8s_resources}

# Work around jsons: it tries to deserialize class vars - it should ignore them.
def no_json(js: Json, tp: type = object, **kwargs: object) -> None:
    return None


set_deserializer(no_json, ClassVar)
