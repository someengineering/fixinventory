import json
import os
from typing import Type, Optional, List, Tuple

import pytest
from _pytest.fixtures import SubRequest
from kubernetes.client import Configuration

from resoto_plugin_k8s.client import K8sResource, K8sClient
from resoto_plugin_k8s.resources import KubernetesResourceType
from resotolib.types import Json


def from_file(name: str) -> Optional[Json]:
    path = os.path.abspath(os.path.dirname(__file__) + "/files/" + name)
    if os.path.exists(path):
        with open(path) as f:
            content = f.read()
            ks = json.loads(content)
            return ks  # type: ignore
    return None


@pytest.fixture
def json_file(request: SubRequest) -> Json:
    for mark in request.node.iter_markers("json_file"):
        result = from_file(mark.args[0])
        if result is None:
            Exception("No file with this path: " + mark.args[0])
        else:
            return result
    raise Exception("No json_file mark found")


class StaticFileClient(K8sClient):
    def get(self, path: str) -> Json:
        return from_file(path.lstrip("/").replace("/", "_") + ".json") or {}

    def version(self) -> Json:
        return {"buildDate": "2022-03-16T14:02:06Z", "major": "1", "minor": "21", "platform": "linux/amd64"}

    def apis(self) -> List[K8sResource]:
        return [
            K8sResource(path="/api/v1/endpoints", kind="Endpoints", namespaced=True, verbs=["list"]),
            K8sResource(path="/api/v1/events", kind="Event", namespaced=True, verbs=["list"]),
            K8sResource(path="/api/v1/limitranges", kind="LimitRange", namespaced=True, verbs=["list"]),
            K8sResource(path="/api/v1/namespaces", kind="Namespace", namespaced=False, verbs=["list"]),
            K8sResource(path="/api/v1/nodes", kind="Node", namespaced=False, verbs=["list"]),
            K8sResource(
                path="/api/v1/persistentvolumeclaims", kind="PersistentVolumeClaim", namespaced=True, verbs=["list"]
            ),
            K8sResource(path="/api/v1/persistentvolumes", kind="PersistentVolume", namespaced=False, verbs=["list"]),
            K8sResource(path="/api/v1/pods", kind="Pod", namespaced=True, verbs=["list"]),
            K8sResource(path="/api/v1/podtemplates", kind="PodTemplate", namespaced=True, verbs=["list"]),
            K8sResource(
                path="/api/v1/replicationcontrollers", kind="ReplicationController", namespaced=True, verbs=["list"]
            ),
            K8sResource(path="/api/v1/resourcequotas", kind="ResourceQuota", namespaced=True, verbs=["list"]),
            K8sResource(path="/api/v1/secrets", kind="Secret", namespaced=True, verbs=["list"]),
            K8sResource(path="/api/v1/serviceaccounts", kind="ServiceAccount", namespaced=True, verbs=["list"]),
            K8sResource(path="/api/v1/services", kind="Service", namespaced=True, verbs=["list"]),
            K8sResource(
                path="/apis/apiregistration.k8s.io/v1/apiservices", kind="APIService", namespaced=False, verbs=["list"]
            ),
            K8sResource(
                path="/apis/apps/v1/controllerrevisions", kind="ControllerRevision", namespaced=True, verbs=["list"]
            ),
            K8sResource(path="/apis/apps/v1/daemonsets", kind="DaemonSet", namespaced=True, verbs=["list"]),
            K8sResource(path="/apis/apps/v1/deployments", kind="Deployment", namespaced=True, verbs=["list"]),
            K8sResource(path="/apis/apps/v1/replicasets", kind="ReplicaSet", namespaced=True, verbs=["list"]),
            K8sResource(path="/apis/apps/v1/statefulsets", kind="StatefulSet", namespaced=True, verbs=["list"]),
            K8sResource(path="/apis/events.k8s.io/v1/events", kind="Event", namespaced=True, verbs=["list"]),
            K8sResource(
                path="/apis/autoscaling/v1/horizontalpodautoscalers",
                kind="HorizontalPodAutoscaler",
                namespaced=True,
                verbs=["list"],
            ),
            K8sResource(path="/apis/batch/v1/cronjobs", kind="CronJob", namespaced=True, verbs=["list"]),
            K8sResource(path="/apis/batch/v1/jobs", kind="Job", namespaced=True, verbs=["list"]),
            K8sResource(
                path="/apis/certificates.k8s.io/v1/certificatesigningrequests",
                kind="CertificateSigningRequest",
                namespaced=False,
                verbs=["list"],
            ),
            K8sResource(
                path="/apis/networking.k8s.io/v1/ingressclasses",
                kind="IngressClass",
                namespaced=False,
                verbs=["list"],
            ),
            K8sResource(path="/apis/networking.k8s.io/v1/ingresses", kind="Ingress", namespaced=True, verbs=["list"]),
            K8sResource(
                path="/apis/networking.k8s.io/v1/networkpolicies", kind="NetworkPolicy", namespaced=True, verbs=["list"]
            ),
            K8sResource(path="/apis/extensions/v1beta1/ingresses", kind="Ingress", namespaced=True, verbs=["list"]),
            K8sResource(
                path="/apis/policy/v1/poddisruptionbudgets", kind="PodDisruptionBudget", namespaced=True, verbs=["list"]
            ),
            K8sResource(
                path="/apis/rbac.authorization.k8s.io/v1/clusterrolebindings",
                kind="ClusterRoleBinding",
                namespaced=False,
                verbs=["list"],
            ),
            K8sResource(
                path="/apis/rbac.authorization.k8s.io/v1/clusterroles",
                kind="ClusterRole",
                namespaced=False,
                verbs=["list"],
            ),
            K8sResource(
                path="/apis/rbac.authorization.k8s.io/v1/rolebindings",
                kind="RoleBinding",
                namespaced=True,
                verbs=["list"],
            ),
            K8sResource(path="/apis/rbac.authorization.k8s.io/v1/roles", kind="Role", namespaced=True, verbs=["list"]),
            K8sResource(path="/apis/storage.k8s.io/v1/csidrivers", kind="CSIDriver", namespaced=False, verbs=["list"]),
            K8sResource(path="/apis/storage.k8s.io/v1/csinodes", kind="CSINode", namespaced=False, verbs=["list"]),
            K8sResource(
                path="/apis/storage.k8s.io/v1/storageclasses", kind="StorageClass", namespaced=False, verbs=["list"]
            ),
            K8sResource(
                path="/apis/storage.k8s.io/v1/volumeattachments",
                kind="VolumeAttachment",
                namespaced=False,
                verbs=["list"],
            ),
            K8sResource(
                path="/apis/admissionregistration.k8s.io/v1/mutatingwebhookconfigurations",
                kind="MutatingWebhookConfiguration",
                namespaced=False,
                verbs=["list"],
            ),
            K8sResource(
                path="/apis/admissionregistration.k8s.io/v1/validatingwebhookconfigurations",
                kind="ValidatingWebhookConfiguration",
                namespaced=False,
                verbs=["list"],
            ),
            K8sResource(
                path="/apis/apiextensions.k8s.io/v1/customresourcedefinitions",
                kind="CustomResourceDefinition",
                namespaced=False,
                verbs=["list"],
            ),
            K8sResource(
                path="/apis/scheduling.k8s.io/v1/priorityclasses",
                kind="PriorityClass",
                namespaced=False,
                verbs=["list"],
            ),
            K8sResource(path="/apis/coordination.k8s.io/v1/leases", kind="Lease", namespaced=True, verbs=["list"]),
            K8sResource(
                path="/apis/node.k8s.io/v1/runtimeclasses", kind="RuntimeClass", namespaced=False, verbs=["list"]
            ),
            K8sResource(
                path="/apis/discovery.k8s.io/v1/endpointslices", kind="EndpointSlice", namespaced=True, verbs=["list"]
            ),
            K8sResource(
                path="/apis/flowcontrol.apiserver.k8s.io/v1beta1/flowschemas",
                kind="FlowSchema",
                namespaced=False,
                verbs=["list"],
            ),
            K8sResource(
                path="/apis/flowcontrol.apiserver.k8s.io/v1beta1/prioritylevelconfigurations",
                kind="PriorityLevelConfiguration",
                namespaced=False,
                verbs=["list"],
            ),
            K8sResource(
                path="/apis/snapshot.storage.k8s.io/v1beta1/volumesnapshotclasses",
                kind="VolumeSnapshotClass",
                namespaced=False,
                verbs=["list"],
            ),
            K8sResource(
                path="/apis/snapshot.storage.k8s.io/v1beta1/volumesnapshots",
                kind="VolumeSnapshot",
                namespaced=True,
                verbs=["list"],
            ),
            K8sResource(
                path="/apis/snapshot.storage.k8s.io/v1beta1/volumesnapshotcontents",
                kind="VolumeSnapshotContent",
                namespaced=False,
                verbs=["list"],
            ),
            K8sResource(path="/apis/cilium.io/v2/ciliumnodes", kind="CiliumNode", namespaced=False, verbs=["list"]),
            K8sResource(
                path="/apis/cilium.io/v2/ciliumnetworkpolicies",
                kind="CiliumNetworkPolicy",
                namespaced=True,
                verbs=["list"],
            ),
            K8sResource(
                path="/apis/cilium.io/v2/ciliumendpoints", kind="CiliumEndpoint", namespaced=True, verbs=["list"]
            ),
            K8sResource(
                path="/apis/cilium.io/v2/ciliumclusterwidenetworkpolicies",
                kind="CiliumClusterwideNetworkPolicy",
                namespaced=False,
                verbs=["list"],
            ),
            K8sResource(
                path="/apis/cilium.io/v2/ciliumidentities", kind="CiliumIdentity", namespaced=False, verbs=["list"]
            ),
            K8sResource(
                path="/apis/cilium.io/v2/ciliumexternalworkloads",
                kind="CiliumExternalWorkload",
                namespaced=False,
                verbs=["list"],
            ),
            K8sResource(
                path="/apis/cilium.io/v2/ciliumlocalredirectpolicies",
                kind="CiliumLocalRedirectPolicy",
                namespaced=True,
                verbs=["list"],
            ),
        ]

    def list_resources(
        self, resource: K8sResource, clazz: Type[KubernetesResourceType], path: Optional[str] = None
    ) -> List[Tuple[KubernetesResourceType, Json]]:
        result = self.get(path or resource.path)
        if result:
            return [(clazz.from_json(r), r) for r in result.get("items", [])]  # type: ignore
        else:
            return []

    @staticmethod
    def static(_: Configuration) -> K8sClient:
        return StaticFileClient()
