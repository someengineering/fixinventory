# noinspection PyUnresolvedReferences
import pytest

# noinspection PyUnresolvedReferences
from resotolib.types import Json

# noinspection PyUnresolvedReferences
from typing import Type, Tuple, TypeVar, List
import pytest

# noinspection PyUnresolvedReferences
import jsons

# noinspection PyUnresolvedReferences
from fixtures import json_file
from resoto_plugin_k8s.resources import *
from resotolib.types import Json
from resotolib.graph import Graph


@pytest.mark.json_file("apis_apps_v1_controllerrevisions.json")
def test_controller_revision(json_file: Json) -> None:
    round_trip(KubernetesControllerRevision, json_file)


# @pytest.mark.json_file("apis_batch_v1_cronjobs.json")
# def test_CronJob(json_file: Json) -> None:
#     round_trip(KubernetesCronJob, json_file)


@pytest.mark.json_file("apis_apps_v1_daemonsets.json")
def test_daemon_set(json_file: Json) -> None:
    round_trip(KubernetesDaemonSet, json_file)


@pytest.mark.json_file("apis_apps_v1_deplpoyments.json")
def test_deployment(json_file: Json) -> None:
    round_trip(KubernetesDeployment, json_file)


# @pytest.mark.json_file("apis_autoscaling_v2_horizontalpodautoscalers.json")
# def test_HorizontalPodAutoscaler(json_file: Json) -> None:
#     round_trip(KubernetesHorizontalPodAutoscaler, json_file)


# @pytest.mark.json_file("apis_batch_v1_jobs.json")
# def test_Job(json_file: Json) -> None:
#     round_trip(KubernetesJob, json_file)


@pytest.mark.json_file("api_v1_pods.json")
def test_pod(json_file: Json) -> None:
    round_trip(KubernetesPod, json_file)


# @pytest.mark.json_file("api_v1_podtemplates.json")
# def test_PodTemplate(json_file: Json) -> None:
#     round_trip(KubernetesPodTemplate, json_file)


@pytest.mark.json_file("apis_scheduling.k8s.io_v1_priorityclasses.json")
def test_priority_class(json_file: Json) -> None:
    round_trip(KubernetesPriorityClass, json_file)


@pytest.mark.json_file("apis_apps_v1_replicasets.json")
def test_replica_set(json_file: Json) -> None:
    round_trip(KubernetesReplicaSet, json_file)


# @pytest.mark.json_file("api_v1_replicationcontrollers.json")
# def test_ReplicationController(json_file: Json) -> None:
#     round_trip(KubernetesReplicationController, json_file)


@pytest.mark.json_file("apis_apps_v1_statefulsets.json")
def test_stateful_set(json_file: Json) -> None:
    round_trip(KubernetesStatefulSet, json_file)


@pytest.mark.json_file("apis_discovery.k8s.io_v1_endpointslices.json")
def test_endpoint_slice(json_file: Json) -> None:
    round_trip(KubernetesEndpointSlice, json_file)


@pytest.mark.json_file("api_v1_endpoints.json")
def test_endpoints(json_file: Json) -> None:
    round_trip(KubernetesEndpoints, json_file)


# @pytest.mark.json_file("apis_networking.k8s.io_v1_ingresses.json")
# def test_Ingress(json_file: Json) -> None:
#     round_trip(KubernetesIngress, json_file)


# @pytest.mark.json_file("apis_networking.k8s.io_v1_ingressclasses.json")
# def test_IngressClass(json_file: Json) -> None:
#     round_trip(KubernetesIngressClass, json_file)


@pytest.mark.json_file("api_v1_services.json")
def test_service(json_file: Json) -> None:
    round_trip(KubernetesService, json_file)


@pytest.mark.json_file("apis_storage.k8s.io_v1_csidrivers.json")
def test_csi_driver(json_file: Json) -> None:
    round_trip(KubernetesCSIDriver, json_file)


@pytest.mark.json_file("apis_storage.k8s.io_v1_csinodes.json")
def test_csi_node(json_file: Json) -> None:
    round_trip(KubernetesCSINode, json_file)


# @pytest.mark.json_file("apis_storage.k8s.io_v1beta1_csistoragecapacities.json")
# def test_CSIStorageCapacity(json_file: Json) -> None:
#     round_trip(KubernetesCSIStorageCapacity, json_file)


@pytest.mark.json_file("api_v1_configmaps.json")
def test_config_map(json_file: Json) -> None:
    round_trip(KubernetesConfigMap, json_file)


@pytest.mark.json_file("api_v1_persistentvolumes.json")
def test_persistent_volume(json_file: Json) -> None:
    round_trip(KubernetesPersistentVolume, json_file)


@pytest.mark.json_file("api_v1_persistentvolumeclaims.json")
def test_persistent_volume_claim(json_file: Json) -> None:
    round_trip(KubernetesPersistentVolumeClaim, json_file)


@pytest.mark.json_file("api_v1_secrets.json")
def test_secret(json_file: Json) -> None:
    round_trip(KubernetesSecret, json_file)


@pytest.mark.json_file("apis_storage.k8s.io_v1_storageclasses.json")
def test_storage_class(json_file: Json) -> None:
    round_trip(KubernetesStorageClass, json_file)


@pytest.mark.json_file("apis_storage.k8s.io_v1_volumeattachments.json")
def test_volume_attachment(json_file: Json) -> None:
    round_trip(KubernetesVolumeAttachment, json_file)


@pytest.mark.json_file("api_v1_serviceaccounts.json")
def test_service_account(json_file: Json) -> None:
    round_trip(KubernetesServiceAccount, json_file)


@pytest.mark.json_file("apis_rbac.authorization.k8s.io_v1_clusterroles.json")
def test_cluster_role(json_file: Json) -> None:
    round_trip(KubernetesClusterRole, json_file)


@pytest.mark.json_file("apis_rbac.authorization.k8s.io_v1_clusterrolebindings.json")
def test_cluster_role_binding(json_file: Json) -> None:
    round_trip(KubernetesClusterRoleBinding, json_file)


@pytest.mark.json_file("apis_rbac.authorization.k8s.io_v1_roles.json")
def test_role(json_file: Json) -> None:
    round_trip(KubernetesRole, json_file)


@pytest.mark.json_file("apis_rbac.authorization.k8s.io_v1_rolebindings.json")
def test_role_binding(json_file: Json) -> None:
    round_trip(KubernetesRoleBinding, json_file)


# @pytest.mark.json_file("api_v1_limitranges.json")
# def test_LimitRange(json_file: Json) -> None:
#     round_trip(KubernetesLimitRange, json_file)


# @pytest.mark.json_file("apis_networking.k8s.io_v1_networkpolicies.json")
# def test_NetworkPolicy(json_file: Json) -> None:
#     round_trip(KubernetesNetworkPolicy, json_file)


@pytest.mark.json_file("apis_policy_v1_poddisruptionbudgets.json")
def test_pod_disruption_budget(json_file: Json) -> None:
    round_trip(KubernetesPodDisruptionBudget, json_file)


# @pytest.mark.json_file("api_v1_resourcequotas.json")
# def test_ResourceQuota(json_file: Json) -> None:
#     round_trip(KubernetesResourceQuota, json_file)


@pytest.mark.json_file("apis_admissionregistration.k8s.io_v1_mutatingwebhookconfigurations.json")
def test_mutating_webhook_configuration(json_file: Json) -> None:
    round_trip(KubernetesMutatingWebhookConfiguration, json_file)


@pytest.mark.json_file("apis_admissionregistration.k8s.io_v1_validatingwebhookconfigurations.json")
def test_validating_webhook_configuration(json_file: Json) -> None:
    round_trip(KubernetesValidatingWebhookConfiguration, json_file)


# @pytest.mark.json_file("api_v1_events.json")
# def test_Event(json_file: Json) -> None:
#     round_trip(KubernetesEvent, json_file)


@pytest.mark.json_file("apis_flowcontrol.apiserver.k8s.io_v1beta1_flowschemas.json")
def test_flow_schema(json_file: Json) -> None:
    round_trip(KubernetesFlowSchema, json_file)


@pytest.mark.json_file("api_v1_namespaces.json")
def test_namespace(json_file: Json) -> None:
    round_trip(KubernetesNamespace, json_file)


@pytest.mark.json_file("api_v1_nodes.json")
def test_node(json_file: Json) -> None:
    round_trip(KubernetesNode, json_file)


@pytest.mark.json_file("apis_flowcontrol.apiserver.k8s.io_v1beta1_prioritylevelconfigurations.json")
def test_priority_level_configuration(json_file: Json) -> None:
    round_trip(KubernetesPriorityLevelConfiguration, json_file)


# @pytest.mark.json_file("apis_node.k8s.io_v1_runtimeclasses.json")
# def test_RuntimeClass(json_file: Json) -> None:
#     round_trip(KubernetesRuntimeClass, json_file)


def connect_in_graph(resources: List[Tuple[KubernetesResourceType, Json]]) -> Graph:
    builder = GraphBuilder(Graph())
    for resource, js in resources:
        resource.connect_in_graph(builder, js)
    return builder.graph


def round_trip(
    resource_class: Type[KubernetesResourceType], source: Json
) -> Tuple[List[Tuple[KubernetesResourceType, Json]], Graph]:
    result = []
    for js in source["items"]:
        resource: KubernetesResourceType = resource_class.from_json(js)  # type: ignore
        result.append((resource, js))
        js = resource.to_json()
        again = jsons.load(js, type(resource))
        js_again = again.to_json()
        assert js == js_again
    graph = connect_in_graph(result)
    return result, graph
