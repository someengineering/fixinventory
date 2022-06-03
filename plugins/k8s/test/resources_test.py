import pytest

# noinspection PyUnresolvedReferences
from fixtures import json_file
from resoto_plugin_k8s.resources import *
from resotolib.types import Json


@pytest.mark.json_file("apis_apps_v1_controllerrevisions.json")
def test_ControllerRevision(json_file: Json) -> None:
    round_trip(KubernetesControllerRevision, json_file)


# @pytest.mark.json_file("apis_batch_v1_cronjobs.json")
# def test_CronJob(json_file: Json) -> None:
#     round_trip(KubernetesCronJob, json_file)


@pytest.mark.json_file("apis_apps_v1_daemonsets.json")
def test_DaemonSet(json_file: Json) -> None:
    round_trip(KubernetesDaemonSet, json_file)


@pytest.mark.json_file("apis_apps_v1_deplpoyments.json")
def test_Deployment(json_file: Json) -> None:
    round_trip(KubernetesDeployment, json_file)


# @pytest.mark.json_file("apis_autoscaling_v2_horizontalpodautoscalers.json")
# def test_HorizontalPodAutoscaler(json_file: Json) -> None:
#     round_trip(KubernetesHorizontalPodAutoscaler, json_file)


# @pytest.mark.json_file("apis_batch_v1_jobs.json")
# def test_Job(json_file: Json) -> None:
#     round_trip(KubernetesJob, json_file)


@pytest.mark.json_file("api_v1_pods.json")
def test_Pod(json_file: Json) -> None:
    round_trip(KubernetesPod, json_file)


# @pytest.mark.json_file("api_v1_podtemplates.json")
# def test_PodTemplate(json_file: Json) -> None:
#     round_trip(KubernetesPodTemplate, json_file)


@pytest.mark.json_file("apis_scheduling.k8s.io_v1_priorityclasses.json")
def test_PriorityClass(json_file: Json) -> None:
    round_trip(KubernetesPriorityClass, json_file)


@pytest.mark.json_file("apis_apps_v1_replicasets.json")
def test_ReplicaSet(json_file: Json) -> None:
    round_trip(KubernetesReplicaSet, json_file)


# @pytest.mark.json_file("api_v1_replicationcontrollers.json")
# def test_ReplicationController(json_file: Json) -> None:
#     round_trip(KubernetesReplicationController, json_file)


@pytest.mark.json_file("apis_apps_v1_statefulsets.json")
def test_StatefulSet(json_file: Json) -> None:
    round_trip(KubernetesStatefulSet, json_file)


@pytest.mark.json_file("apis_discovery.k8s.io_v1_endpointslices.json")
def test_EndpointSlice(json_file: Json) -> None:
    round_trip(KubernetesEndpointSlice, json_file)


@pytest.mark.json_file("api_v1_endpoints.json")
def test_Endpoints(json_file: Json) -> None:
    round_trip(KubernetesEndpoints, json_file)


# @pytest.mark.json_file("apis_networking.k8s.io_v1_ingresses.json")
# def test_Ingress(json_file: Json) -> None:
#     round_trip(KubernetesIngress, json_file)


# @pytest.mark.json_file("apis_networking.k8s.io_v1_ingressclasses.json")
# def test_IngressClass(json_file: Json) -> None:
#     round_trip(KubernetesIngressClass, json_file)


@pytest.mark.json_file("api_v1_services.json")
def test_Service(json_file: Json) -> None:
    round_trip(KubernetesService, json_file)


@pytest.mark.json_file("apis_storage.k8s.io_v1_csidrivers.json")
def test_CSIDriver(json_file: Json) -> None:
    round_trip(KubernetesCSIDriver, json_file)


@pytest.mark.json_file("apis_storage.k8s.io_v1_csinodes.json")
def test_CSINode(json_file: Json) -> None:
    round_trip(KubernetesCSINode, json_file)


# @pytest.mark.json_file("apis_storage.k8s.io_v1beta1_csistoragecapacities.json")
# def test_CSIStorageCapacity(json_file: Json) -> None:
#     round_trip(KubernetesCSIStorageCapacity, json_file)


@pytest.mark.json_file("api_v1_configmaps.json")
def test_ConfigMap(json_file: Json) -> None:
    round_trip(KubernetesConfigMap, json_file)


@pytest.mark.json_file("api_v1_persistentvolumes.json")
def test_PersistentVolume(json_file: Json) -> None:
    round_trip(KubernetesPersistentVolume, json_file)


@pytest.mark.json_file("api_v1_persistentvolumeclaims.json")
def test_PersistentVolumeClaim(json_file: Json) -> None:
    round_trip(KubernetesPersistentVolumeClaim, json_file)


@pytest.mark.json_file("api_v1_secrets.json")
def test_Secret(json_file: Json) -> None:
    round_trip(KubernetesSecret, json_file)


@pytest.mark.json_file("apis_storage.k8s.io_v1_storageclasses.json")
def test_StorageClass(json_file: Json) -> None:
    round_trip(KubernetesStorageClass, json_file)


@pytest.mark.json_file("apis_storage.k8s.io_v1_volumeattachments.json")
def test_VolumeAttachment(json_file: Json) -> None:
    round_trip(KubernetesVolumeAttachment, json_file)


@pytest.mark.json_file("api_v1_serviceaccounts.json")
def test_ServiceAccount(json_file: Json) -> None:
    round_trip(KubernetesServiceAccount, json_file)


@pytest.mark.json_file("apis_rbac.authorization.k8s.io_v1_clusterroles.json")
def test_ClusterRole(json_file: Json) -> None:
    round_trip(KubernetesClusterRole, json_file)


@pytest.mark.json_file("apis_rbac.authorization.k8s.io_v1_clusterrolebindings.json")
def test_ClusterRoleBinding(json_file: Json) -> None:
    round_trip(KubernetesClusterRoleBinding, json_file)


@pytest.mark.json_file("apis_rbac.authorization.k8s.io_v1_roles.json")
def test_Role(json_file: Json) -> None:
    round_trip(KubernetesRole, json_file)


@pytest.mark.json_file("apis_rbac.authorization.k8s.io_v1_rolebindings.json")
def test_RoleBinding(json_file: Json) -> None:
    round_trip(KubernetesRoleBinding, json_file)


# @pytest.mark.json_file("api_v1_limitranges.json")
# def test_LimitRange(json_file: Json) -> None:
#     round_trip(KubernetesLimitRange, json_file)


# @pytest.mark.json_file("apis_networking.k8s.io_v1_networkpolicies.json")
# def test_NetworkPolicy(json_file: Json) -> None:
#     round_trip(KubernetesNetworkPolicy, json_file)


@pytest.mark.json_file("apis_policy_v1_poddisruptionbudgets.json")
def test_PodDisruptionBudget(json_file: Json) -> None:
    round_trip(KubernetesPodDisruptionBudget, json_file)


# @pytest.mark.json_file("api_v1_resourcequotas.json")
# def test_ResourceQuota(json_file: Json) -> None:
#     round_trip(KubernetesResourceQuota, json_file)


@pytest.mark.json_file("apis_admissionregistration.k8s.io_v1_mutatingwebhookconfigurations.json")
def test_MutatingWebhookConfiguration(json_file: Json) -> None:
    round_trip(KubernetesMutatingWebhookConfiguration, json_file)


@pytest.mark.json_file("apis_admissionregistration.k8s.io_v1_validatingwebhookconfigurations.json")
def test_ValidatingWebhookConfiguration(json_file: Json) -> None:
    round_trip(KubernetesValidatingWebhookConfiguration, json_file)


# @pytest.mark.json_file("api_v1_events.json")
# def test_Event(json_file: Json) -> None:
#     round_trip(KubernetesEvent, json_file)


@pytest.mark.json_file("apis_flowcontrol.apiserver.k8s.io_v1beta1_flowschemas.json")
def test_FlowSchema(json_file: Json) -> None:
    round_trip(KubernetesFlowSchema, json_file)


@pytest.mark.json_file("api_v1_namespaces.json")
def test_Namespace(json_file: Json) -> None:
    round_trip(KubernetesNamespace, json_file)


@pytest.mark.json_file("api_v1_nodes.json")
def test_Node(json_file: Json) -> None:
    round_trip(KubernetesNode, json_file)


@pytest.mark.json_file("apis_flowcontrol.apiserver.k8s.io_v1beta1_prioritylevelconfigurations.json")
def test_PriorityLevelConfiguration(json_file: Json) -> None:
    round_trip(KubernetesPriorityLevelConfiguration, json_file)


# @pytest.mark.json_file("apis_node.k8s.io_v1_runtimeclasses.json")
# def test_RuntimeClass(json_file: Json) -> None:
#     round_trip(KubernetesRuntimeClass, json_file)


def round_trip(resource_class: Type[KubernetesResource], json: Json) -> None:
    for js in json["items"]:
        resource = resource_class.from_json(js)
        js = resource.to_json()
        again = jsons.load(js, type(resource))
        js_again = again.to_json()
        assert js == js_again
