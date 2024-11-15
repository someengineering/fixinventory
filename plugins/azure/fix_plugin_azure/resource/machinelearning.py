from __future__ import annotations

from collections import defaultdict
import logging
from datetime import datetime
from typing import Any, ClassVar, Dict, Optional, List, Tuple, Type

from attr import define, field

from fix_plugin_azure.azure_client import AzureResourceSpec
from fix_plugin_azure.resource.base import (
    AzureProxyResource,
    AzureTrackedResource,
    MicrosoftResource,
    AzureSystemData,
    AzureSku,
    AzureManagedServiceIdentity,
    GraphBuilder,
    AzureBaseUsage,
    AzurePrivateLinkServiceConnectionState,
)
from fix_plugin_azure.resource.compute import AzureComputeVirtualMachineBase
from fix_plugin_azure.resource.containerservice import AzureContainerServiceManagedCluster
from fix_plugin_azure.resource.keyvault import AzureKeyVault
from fix_plugin_azure.resource.microsoft_graph import MicrosoftGraphServicePrincipal, MicrosoftGraphUser
from fix_plugin_azure.resource.network import AzureNetworkSubnet, AzureNetworkVirtualNetwork
from fix_plugin_azure.resource.storage import AzureStorageAccount
from fix_plugin_azure.resource.web import AzureWebApp
from fixlib.baseresources import (
    BaseInstanceType,
    ModelReference,
    BaseAIJob,
    AIJobStatus,
    BaseAIModel,
    PhantomBaseResource,
)
from fixlib.graph import BySearchCriteria
from fixlib.json_bender import MapEnum, Bender, S, ForallBend, Bend, K
from fixlib.types import Json

log = logging.getLogger("fix.plugins.azure")
service_name = "machine-learning"


class CheckVersionIsArchived:
    @classmethod
    def collect(
        cls,
        raw: List[Json],
        builder: GraphBuilder,
    ) -> List[MicrosoftResource]:
        result: List[MicrosoftResource] = []
        if issubclass(cls, MicrosoftResource):
            for js in raw:
                # map from api
                if instance := cls.from_api(js, builder):
                    # If the resource is archived, we will not take it
                    if instance.is_archived is True:
                        continue
                    # add to graph
                    if (added := builder.add_node(instance, js)) is not None:
                        result.append(added)
        return result


AZURE_ML_JOB_STATUS_MAPPING = {
    "CancelRequested": AIJobStatus.STOPPING,
    "Canceled": AIJobStatus.CANCELLED,
    "Completed": AIJobStatus.COMPLETED,
    "Failed": AIJobStatus.FAILED,
    "Finalizing": AIJobStatus.STOPPING,
    "NotResponding": AIJobStatus.UNKNOWN,
    "NotStarted": AIJobStatus.PENDING,
    "Paused": AIJobStatus.PAUSED,
    "Preparing": AIJobStatus.PREPARING,
    "Provisioning": AIJobStatus.PREPARING,
    "Queued": AIJobStatus.PENDING,
    "Running": AIJobStatus.RUNNING,
    "Starting": AIJobStatus.PREPARING,
    "Unknown": AIJobStatus.UNKNOWN,
}


@define(eq=False, slots=False)
class AzureEndpointAuthKeys:
    kind: ClassVar[str] = "azure_endpoint_auth_keys"
    mapping: ClassVar[Dict[str, Bender]] = {"primary_key": S("primaryKey"), "secondary_key": S("secondaryKey")}
    primary_key: Optional[str] = field(default=None, metadata={"description": "The primary key."})
    secondary_key: Optional[str] = field(default=None, metadata={"description": "The secondary key."})


@define(eq=False, slots=False)
class AzureMachineLearningBatchEndpoint(MicrosoftResource, AzureTrackedResource):
    kind: ClassVar[str] = "azure_machine_learning_batch_endpoint"
    _kind_display: ClassVar[str] = "Azure Machine Learning Batch Endpoint"
    _kind_service: ClassVar[Optional[str]] = service_name
    _kind_description: ClassVar[str] = "Azure Machine Learning Batch Endpoint is a feature for processing large volumes of data asynchronously. It provides a consistent interface for running machine learning models on batches of data, managing compute resources, and retrieving results. Users can schedule jobs, monitor progress, and access outputs through API calls or the Azure portal."  # fmt: skip
    _docs_url: ClassVar[str] = "https://learn.microsoft.com/en-us/azure/machine-learning/how-to-use-batch-endpoint"
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "endpoint", "group": "ai"}
    # Collected via AzureMachineLearningWorkspace()
    _reference_kinds: ClassVar[ModelReference] = {
        "successors": {"default": [MicrosoftGraphServicePrincipal.kind, MicrosoftGraphUser.kind]},
    }
    mapping: ClassVar[Dict[str, Bender]] = AzureTrackedResource.mapping | {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "ctime": S("systemData", "createdAt"),
        "mtime": S("systemData", "lastModifiedAt"),
        "auth_mode": S("properties", "authMode"),
        "description": S("properties", "description"),
        "keys": S("properties", "keys") >> Bend(AzureEndpointAuthKeys.mapping),
        "properties": S("properties", "properties"),
        "scoring_uri": S("properties", "scoringUri"),
        "swagger_uri": S("properties", "swaggerUri"),
        "defaults": S("properties", "defaults", "deploymentName"),
        "identity": S("identity") >> Bend(AzureManagedServiceIdentity.mapping),
        "azure_kind": S("kind"),
        "provisioning_state": S("properties", "provisioningState"),
        "azure_sku": S("sku") >> Bend(AzureSku.mapping),
    }
    auth_mode: Optional[str] = field(default=None, metadata={'description': 'Enum to determine endpoint authentication mode.'})  # fmt: skip
    description: Optional[str] = field(default=None, metadata={'description': 'Description of the inference endpoint.'})  # fmt: skip
    keys: Optional[AzureEndpointAuthKeys] = field(default=None, metadata={'description': 'Keys for endpoint authentication.'})  # fmt: skip
    properties: Optional[Dict[str, Any]] = field(default=None, metadata={'description': 'Property dictionary. Properties can be added, but not removed or altered.'})  # fmt: skip
    scoring_uri: Optional[str] = field(default=None, metadata={"description": "Endpoint URI."})
    swagger_uri: Optional[str] = field(default=None, metadata={"description": "Endpoint Swagger URI."})
    defaults: Optional[str] = field(default=None, metadata={"description": "Batch endpoint default values"})
    identity: Optional[AzureManagedServiceIdentity] = field(default=None, metadata={'description': 'Managed service identity (system assigned and/or user assigned identities)'})  # fmt: skip
    azure_kind: Optional[str] = field(default=None, metadata={'description': 'Metadata used by portal/tooling/etc to render different UX experiences for resources of the same type.'})  # fmt: skip
    azure_sku: Optional[AzureSku] = field(default=None, metadata={'description': 'The resource model definition representing SKU'})  # fmt: skip

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        # principal: collected via ms graph -> create a deferred edge
        if ai := self.identity:
            if pid := ai.principal_id:
                builder.add_deferred_edge(
                    from_node=self,
                    to_node=BySearchCriteria(f'is({MicrosoftGraphServicePrincipal.kind}) and reported.id=="{pid}"'),
                )
            if uai := ai.user_assigned_identities:
                for _, identity_info in uai.items():
                    if identity_info and identity_info.principal_id:
                        builder.add_deferred_edge(
                            from_node=self,
                            to_node=BySearchCriteria(
                                f'is({MicrosoftGraphUser.kind}) and reported.id=="{identity_info.principal_id}"'
                            ),
                        )


@define(eq=False, slots=False)
class AzureMachineLearningCodeContainerBase(AzureProxyResource):
    kind: ClassVar[str] = "azure_machine_learning_code_container_base"
    _kind_display: ClassVar[str] = "Azure Machine Learning Code Container Base"
    _kind_service: ClassVar[Optional[str]] = service_name
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "container", "group": "ai"}
    # Collected via AzureMachineLearningWorkspace()
    mapping: ClassVar[Dict[str, Bender]] = AzureProxyResource.mapping | {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "properties": S("properties", "properties"),
        "description": S("properties", "description"),
        "is_archived": S("properties", "isArchived", default=False),
        "latest_version": S("properties", "latestVersion"),
        "next_version": S("properties", "nextVersion"),
        "provisioning_state": S("properties", "provisioningState"),
    }
    description: Optional[str] = field(default=None, metadata={"description": "The asset description text."})
    is_archived: Optional[bool] = field(default=False, metadata={"description": "Is the asset archived?"})
    latest_version: Optional[str] = field(
        default=None, metadata={"description": "The latest version inside this container."}
    )
    next_version: Optional[str] = field(default=None, metadata={"description": "The next auto incremental version."})
    properties: Optional[Dict[str, Any]] = field(default=None, metadata={"description": ""})


@define(eq=False, slots=False)
class AzureMachineLearningWorkspaceCodeContainer(AzureMachineLearningCodeContainerBase, MicrosoftResource):
    # Defined to split registry and workspace resource
    kind: ClassVar[str] = "azure_machine_learning_workspace_code_container"
    _kind_display: ClassVar[str] = "Azure Machine Learning Workspace Code Container"
    _kind_description: ClassVar[str] = "Azure Machine Learning Workspace Code Container is a development environment for machine learning projects in Azure. It provides tools and libraries for data preparation, model training, and deployment. Users can write, test, and run code within the container, which integrates with Azure services and resources. The container supports collaboration and version control for ML workflows."  # fmt: skip
    _docs_url: ClassVar[str] = (
        "https://learn.microsoft.com/en-us/azure/machine-learning/how-to-access-workspace?view=azureml-api-2"
    )
    _reference_kinds: ClassVar[ModelReference] = {
        "successors": {
            "default": [
                "azure_machine_learning_workspace_code_version",
            ]
        },
    }

    def post_process(self, graph_builder: GraphBuilder, source: Json) -> None:
        if container_id := self.id:

            def collect_versions() -> None:
                api_spec = AzureResourceSpec(
                    service="machinelearningservices",
                    version="2024-04-01",
                    path=f"{container_id}/versions",
                    path_parameters=[],
                    query_parameters=["api-version"],
                    access_path="value",
                    expect_array=True,
                )
                items = graph_builder.client.list(api_spec)
                if not items:
                    return
                collected = AzureMachineLearningWorkspaceCodeVersion.collect(items, graph_builder)
                for resource in collected:
                    graph_builder.add_edge(self, node=resource)

            graph_builder.submit_work(service_name, collect_versions)


@define(eq=False, slots=False)
class AzureMachineLearningRegistryCodeContainer(AzureMachineLearningCodeContainerBase, MicrosoftResource):
    # Defined to split registry and workspace resource
    kind: ClassVar[str] = "azure_machine_learning_registry_code_container"
    _kind_display: ClassVar[str] = "Azure Machine Learning Registry Code Container"
    _kind_description: ClassVar[str] = "Azure Machine Learning Registry Code Container is a component of Azure Machine Learning that stores and manages versioned machine learning code assets. It provides a central repository for data scientists and developers to share, track, and collaborate on code artifacts, including scripts, notebooks, and models, within their machine learning projects and workflows."  # fmt: skip
    _docs_url: ClassVar[str] = (
        "https://learn.microsoft.com/en-us/azure/machine-learning/how-to-use-registry-container-resource"
    )
    _reference_kinds: ClassVar[ModelReference] = {
        "successors": {
            "default": [
                "azure_machine_learning_registry_code_version",
            ]
        },
    }

    def post_process(self, graph_builder: GraphBuilder, source: Json) -> None:
        if container_id := self.id:

            def collect_versions() -> None:
                api_spec = AzureResourceSpec(
                    service="machinelearningservices",
                    version="2024-04-01",
                    path=f"{container_id}/versions",
                    path_parameters=[],
                    query_parameters=["api-version"],
                    access_path="value",
                    expect_array=True,
                )
                items = graph_builder.client.list(api_spec)
                if not items:
                    return
                collected = AzureMachineLearningRegistryCodeVersion.collect(items, graph_builder)
                for resource in collected:
                    graph_builder.add_edge(self, node=resource)

            graph_builder.submit_work(service_name, collect_versions)


@define(eq=False, slots=False)
class AzureMachineLearningCodeVersionBase(CheckVersionIsArchived, AzureProxyResource):
    kind: ClassVar[str] = "azure_machine_learning_code_version_base"
    _kind_display: ClassVar[str] = "Azure Machine Learning Code Version Base"
    _kind_service: ClassVar[Optional[str]] = service_name
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "resource", "group": "ai"}
    # Collected via AzureMachineLearningCodeContainerBase()
    mapping: ClassVar[Dict[str, Bender]] = AzureProxyResource.mapping | {
        "id": S("id"),
        "name": S("name"),
        "ctime": S("systemData", "createdAt"),
        "mtime": S("systemData", "lastModifiedAt"),
        "tags": S("properties", "tags", default={}),
        "code_uri": S("properties", "codeUri"),
        "provisioning_state": S("properties", "provisioningState"),
        "description": S("properties", "description"),
        "properties": S("properties", "properties"),
        "is_anonymous": S("properties", "isAnonymous"),
        "is_archived": S("properties", "isArchived"),
    }
    description: Optional[str] = field(default=None, metadata={"description": "The asset description text."})
    properties: Optional[Dict[str, Any]] = field(default=None, metadata={'description': 'The asset property dictionary.'})  # fmt: skip
    is_anonymous: Optional[bool] = field(default=None, metadata={'description': 'If the name version are system generated (anonymous registration).'})  # fmt: skip
    is_archived: Optional[bool] = field(default=None, metadata={"description": "Is the asset archived?"})
    code_uri: Optional[str] = field(default=None, metadata={"description": "Uri where code is located"})


@define(eq=False, slots=False)
class AzureMachineLearningWorkspaceCodeVersion(AzureMachineLearningCodeVersionBase, MicrosoftResource):
    # Defined to split registry and workspace resource
    kind: ClassVar[str] = "azure_machine_learning_workspace_code_version"
    _kind_display: ClassVar[str] = "Azure Machine Learning Workspace Code Version"
    _kind_description: ClassVar[str] = "Azure Machine Learning Workspace Code Version is a feature that tracks and manages different iterations of machine learning code within an Azure workspace. It stores and organizes code snapshots, facilitating version control and collaboration among data scientists. Users can compare versions, revert changes, and reproduce experiments based on specific code states."  # fmt: skip
    _docs_url: ClassVar[str] = "https://learn.microsoft.com/en-us/azure/machine-learning/concept-code-version"


@define(eq=False, slots=False)
class AzureMachineLearningRegistryCodeVersion(AzureMachineLearningCodeVersionBase, MicrosoftResource):
    # Defined to split registry and workspace resource
    kind: ClassVar[str] = "azure_machine_learning_registry_code_version"
    _kind_description: ClassVar[str] = "Azure Machine Learning Registry Code Version is a component of Azure Machine Learning that manages and tracks different versions of machine learning code. It stores and organizes code iterations, facilitating collaboration among team members. Users can access, compare, and revert to previous versions, ensuring reproducibility and maintaining a history of code changes throughout the development process."  # fmt: skip
    _docs_url: ClassVar[str] = (
        "https://learn.microsoft.com/en-us/azure/machine-learning/how-to-manage-models-in-registry"
    )
    _kind_display: ClassVar[str] = "Azure Machine Learning Registry Code Version"
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "version", "group": "ai"}


@define(eq=False, slots=False)
class AzureMachineLearningComponentContainerBase(AzureProxyResource):
    kind: ClassVar[str] = "azure_machine_learning_component_container_base"
    _kind_display: ClassVar[str] = "Azure Machine Learning Component Container Base"
    _kind_service: ClassVar[Optional[str]] = service_name
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "container", "group": "ai"}
    # Collected via AzureMachineLearningWorkspace()
    mapping: ClassVar[Dict[str, Bender]] = AzureProxyResource.mapping | {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "properties": S("properties", "properties"),
        "description": S("properties", "description"),
        "is_archived": S("properties", "isArchived", default=False),
        "latest_version": S("properties", "latestVersion"),
        "next_version": S("properties", "nextVersion"),
        "provisioning_state": S("properties", "provisioningState"),
    }
    description: Optional[str] = field(default=None, metadata={"description": "The asset description text."})
    is_archived: Optional[bool] = field(default=False, metadata={"description": "Is the asset archived?"})
    latest_version: Optional[str] = field(
        default=None, metadata={"description": "The latest version inside this container."}
    )
    next_version: Optional[str] = field(default=None, metadata={"description": "The next auto incremental version."})
    properties: Optional[Dict[str, Any]] = field(default=None, metadata={"description": ""})


@define(eq=False, slots=False)
class AzureMachineLearningWorkspaceComponentContainer(AzureMachineLearningComponentContainerBase, MicrosoftResource):
    # Defined to split registry and workspace resource

    kind: ClassVar[str] = "azure_machine_learning_workspace_component_container"
    _kind_display: ClassVar[str] = "Azure Machine Learning Workspace Component Container"
    _kind_description: ClassVar[str] = "The Azure Machine Learning Workspace Component Container is a containerized environment within Azure Machine Learning that hosts and manages workspace components. It provides a unified space for storing, organizing, and accessing machine learning assets such as datasets, models, and experiments. Users can collaborate, version control, and deploy machine learning projects from this centralized container."  # fmt: skip
    _docs_url: ClassVar[str] = (
        "https://learn.microsoft.com/en-us/azure/machine-learning/concept-component-specification"
    )
    _reference_kinds: ClassVar[ModelReference] = {
        "successors": {
            "default": [
                "azure_machine_learning_workspace_component_version",
            ]
        },
    }

    def post_process(self, graph_builder: GraphBuilder, source: Json) -> None:
        if resource_id := self.id:

            def collect_versions() -> None:
                api_spec = AzureResourceSpec(
                    service="machinelearningservices",
                    version="2024-04-01",
                    path=f"{resource_id}/versions",
                    path_parameters=[],
                    query_parameters=["api-version"],
                    access_path="value",
                    expect_array=True,
                )
                items = graph_builder.client.list(api_spec)
                if not items:
                    return
                collected = AzureMachineLearningWorkspaceComponentVersion.collect(items, graph_builder)
                for resource in collected:
                    graph_builder.add_edge(self, node=resource)

            graph_builder.submit_work(service_name, collect_versions)


@define(eq=False, slots=False)
class AzureMachineLearningRegistryComponentContainer(AzureMachineLearningComponentContainerBase, MicrosoftResource):
    # Defined to split registry and workspace resource

    kind: ClassVar[str] = "azure_machine_learning_registry_component_container"
    _kind_display: ClassVar[str] = "Azure Machine Learning Registry Component Container"
    _kind_description: ClassVar[str] = "Azure Machine Learning Registry Component Container is a service for storing and managing machine learning components in Azure. It provides a centralized repository for versioning, sharing, and reusing ML artifacts such as models, datasets, and environments. Users can access and deploy components across different projects and teams, promoting collaboration and standardization in ML workflows."  # fmt: skip
    _docs_url: ClassVar[str] = (
        "https://learn.microsoft.com/en-us/azure/machine-learning/concept-component-specification"
    )
    _reference_kinds: ClassVar[ModelReference] = {
        "successors": {
            "default": [
                "azure_machine_learning_registry_component_version",
            ]
        },
    }

    def post_process(self, graph_builder: GraphBuilder, source: Json) -> None:
        if resource_id := self.id:

            def collect_versions() -> None:
                api_spec = AzureResourceSpec(
                    service="machinelearningservices",
                    version="2024-04-01",
                    path=f"{resource_id}/versions",
                    path_parameters=[],
                    query_parameters=["api-version"],
                    access_path="value",
                    expect_array=True,
                )
                items = graph_builder.client.list(api_spec)
                if not items:
                    return
                collected = AzureMachineLearningRegistryComponentVersion.collect(items, graph_builder)
                for resource in collected:
                    graph_builder.add_edge(self, node=resource)

            graph_builder.submit_work(service_name, collect_versions)


@define(eq=False, slots=False)
class AzureMachineLearningComponentVersionBase(CheckVersionIsArchived, AzureProxyResource):
    kind: ClassVar[str] = "azure_machine_learning_component_version_base"
    _kind_display: ClassVar[str] = "Azure Machine Learning Component Version Base"
    _kind_service: ClassVar[Optional[str]] = service_name
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "resource", "group": "ai"}
    # Collected via AzureMachineLearningComponentContainerBase()
    mapping: ClassVar[Dict[str, Bender]] = AzureProxyResource.mapping | {
        "id": S("id"),
        "name": S("name"),
        "ctime": S("systemData", "createdAt"),
        "mtime": S("systemData", "lastModifiedAt"),
        "component_spec": S("properties", "componentSpec"),
        "tags": S("properties", "tags", default={}),
        "code_uri": S("properties", "codeUri"),
        "provisioning_state": S("properties", "provisioningState"),
        "description": S("properties", "description"),
        "properties": S("properties", "properties"),
        "is_anonymous": S("properties", "isAnonymous"),
        "is_archived": S("properties", "isArchived"),
    }
    description: Optional[str] = field(default=None, metadata={"description": "The asset description text."})
    properties: Optional[Dict[str, Any]] = field(default=None, metadata={'description': 'The asset property dictionary.'})  # fmt: skip
    is_anonymous: Optional[bool] = field(default=None, metadata={'description': 'If the name version are system generated (anonymous registration).'})  # fmt: skip
    is_archived: Optional[bool] = field(default=None, metadata={"description": "Is the asset archived?"})
    component_spec: Optional[Any] = field(default=None, metadata={'description': 'Defines Component definition details. <see href= https://docs.microsoft.com/en-us/azure/machine-learning/reference-yaml-component-command />'})  # fmt: skip


@define(eq=False, slots=False)
class AzureMachineLearningWorkspaceComponentVersion(AzureMachineLearningComponentVersionBase, MicrosoftResource):
    # Defined to split registry and workspace resource

    kind: ClassVar[str] = "azure_machine_learning_workspace_component_version"
    _kind_display: ClassVar[str] = "Azure Machine Learning Workspace Component Version"
    _kind_description: ClassVar[str] = "Azure Machine Learning Workspace Component Version is a specific iteration of a reusable asset within an Azure Machine Learning workspace. It represents a snapshot of a component's configuration, code, and dependencies at a particular point in time. This versioning system helps track changes, maintain consistency, and facilitate collaboration among data scientists and machine learning engineers."  # fmt: skip
    _docs_url: ClassVar[str] = (
        "https://learn.microsoft.com/en-us/azure/machine-learning/how-to-manage-component-version"
    )


@define(eq=False, slots=False)
class AzureMachineLearningRegistryComponentVersion(AzureMachineLearningComponentVersionBase, MicrosoftResource):
    # Defined to split registry and workspace resource

    kind: ClassVar[str] = "azure_machine_learning_registry_component_version"
    _kind_display: ClassVar[str] = "Azure Machine Learning Registry Component Version"
    _kind_description: ClassVar[str] = "Azure Machine Learning Registry Component Version represents a specific iteration of a component within the Azure Machine Learning Registry. It contains the component's code, dependencies, and metadata for a particular version. This versioning system helps track changes, manage different implementations, and ensure reproducibility of machine learning workflows across projects and teams."  # fmt: skip
    _docs_url: ClassVar[str] = (
        "https://learn.microsoft.com/en-us/azure/machine-learning/reference-yaml-component-version"
    )
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "version", "group": "ai"}


@define(eq=False, slots=False)
class AzureMachineLearningComputeNode(MicrosoftResource, AzureProxyResource):
    kind: ClassVar[str] = "azure_machine_learning_compute_node"
    _kind_display: ClassVar[str] = "Azure Machine Learning Compute Node"
    _kind_service: ClassVar[Optional[str]] = service_name
    _kind_description: ClassVar[str] = "Azure Machine Learning Compute Node is a managed compute resource for running machine learning workloads. It provides a dedicated virtual machine environment for training models, conducting experiments, and deploying solutions. Users can configure the node's specifications, including CPU, GPU, and memory, to match their computational needs. It integrates with other Azure ML services for data processing and model management."  # fmt: skip
    _docs_url: ClassVar[str] = "https://learn.microsoft.com/en-us/azure/machine-learning/concept-compute-target"
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "instance", "group": "compute"}
    # Collected via AzureMachineLearningCompute()
    mapping: ClassVar[Dict[str, Bender]] = AzureProxyResource.mapping | {
        "id": S("nodeId"),
        "name": S("nodeId"),
        "compute_node_id": S("nodeId"),
        "compute_node_state": S("nodeState"),
        "port": S("port"),
        "private_ip_address": S("privateIpAddress"),
        "public_ip_address": S("publicIpAddress"),
        "compute_run_id": S("runId"),
    }
    compute_node_id: Optional[str] = field(default=None, metadata={"description": "Node ID. ID of the compute node."})
    compute_node_state: Optional[str] = field(
        default=None,
        metadata={
            "description": "State of the compute node. Values are idle, running, preparing, unusable, leaving, and preempted."
        },
    )
    port: Optional[int] = field(default=None, metadata={"description": "SSH port number of the node."})
    private_ip_address: Optional[str] = field(
        default=None, metadata={"description": "Private IP address of the compute node."}
    )
    public_ip_address: Optional[str] = field(
        default=None, metadata={"description": "Public IP address of the compute node."}
    )
    compute_run_id: Optional[str] = field(
        default=None, metadata={"description": "ID of the Experiment running on the node, if any; else null."}
    )


@define(eq=False, slots=False)
class AzureErrorDetail:
    kind: ClassVar[str] = "azure_error_detail"
    mapping: ClassVar[Dict[str, Bender]] = {"code": S("code"), "message": S("message"), "target": S("target")}
    code: Optional[str] = field(default=None, metadata={"description": "The error code."})
    message: Optional[str] = field(default=None, metadata={"description": "The error message."})
    target: Optional[str] = field(default=None, metadata={"description": "The error target."})


@define(eq=False, slots=False)
class AzureErrorResponse:
    kind: ClassVar[str] = "azure_error_response"
    mapping: ClassVar[Dict[str, Bender]] = {"error": S("error") >> Bend(AzureErrorDetail.mapping)}
    error: Optional[AzureErrorDetail] = field(default=None, metadata={"description": "The error detail."})


@define(eq=False, slots=False)
class AzureMachineLearningCompute(MicrosoftResource):
    kind: ClassVar[str] = "azure_machine_learning_compute"
    _kind_display: ClassVar[str] = "Azure Machine Learning Compute"
    _kind_service: ClassVar[Optional[str]] = service_name
    _kind_description: ClassVar[str] = "Azure Machine Learning Compute is a cloud-based service for running machine learning workloads. It provides managed compute resources for training and deploying models. Users can create and manage compute clusters, select virtual machine sizes, and autoscale resources as needed. The service supports various machine learning frameworks and integrates with other Azure services for data processing and model deployment."  # fmt: skip
    _docs_url: ClassVar[str] = "https://docs.microsoft.com/en-us/azure/machine-learning/concept-compute-target"
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "instance", "group": "compute"}
    # Collected via AzureMachineLearningWorkspace()
    _reference_kinds: ClassVar[ModelReference] = {
        "successors": {
            "default": [
                "azure_machine_learning_virtual_machine_size",
                "azure_machine_learning_compute_node",
                MicrosoftGraphServicePrincipal.kind,
                MicrosoftGraphUser.kind,
                AzureComputeVirtualMachineBase.kind,
                AzureContainerServiceManagedCluster.kind,
                AzureWebApp.kind,
            ]
        },
    }
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "ctime": S("systemData", "createdOn"),
        "mtime": S("systemData", "lastModifiedAt"),
        "location": S("location"),
        "compute_location": S("properties", "computeLocation"),
        "compute_type": S("properties", "computeType"),
        "created_on": S("properties", "createdOn"),
        "description": S("properties", "description"),
        "disable_local_auth": S("properties", "disableLocalAuth"),
        "is_attached_compute": S("properties", "isAttachedCompute"),
        "modified_on": S("properties", "modifiedOn"),
        "provisioning_errors": S("properties", "provisioningErrors") >> ForallBend(AzureErrorResponse.mapping),
        "provisioning_state": S("properties", "provisioningState"),
        "resource_id": S("properties", "resourceId"),
        "identity": S("identity") >> Bend(AzureManagedServiceIdentity.mapping),
        "azure_sku": S("sku") >> Bend(AzureSku.mapping),
        "properties": S("properties", "properties"),
        "system_data": S("systemData") >> Bend(AzureSystemData.mapping),
    }
    properties: Optional[Dict[str, Any]] = field(default=None, metadata={'description': 'Property dictionary. Properties can be added, but not removed or altered.'})  # fmt: skip
    compute_location: Optional[str] = field(default=None, metadata={'description': 'Location for the underlying compute'})  # fmt: skip
    compute_type: Optional[str] = field(default=None, metadata={"description": "The type of compute"})
    created_on: Optional[datetime] = field(default=None, metadata={'description': 'The time at which the compute was created.'})  # fmt: skip
    description: Optional[str] = field(default=None, metadata={'description': 'The description of the Machine Learning compute.'})  # fmt: skip
    disable_local_auth: Optional[bool] = field(default=None, metadata={'description': 'Opt-out of local authentication and ensure customers can use only MSI and AAD exclusively for authentication.'})  # fmt: skip
    is_attached_compute: Optional[bool] = field(default=None, metadata={'description': 'Indicating whether the compute was provisioned by user and brought from outside if true, or machine learning service provisioned it if false.'})  # fmt: skip
    modified_on: Optional[datetime] = field(default=None, metadata={'description': 'The time at which the compute was last modified.'})  # fmt: skip
    provisioning_errors: Optional[List[AzureErrorResponse]] = field(default=None, metadata={'description': 'Errors during provisioning'})  # fmt: skip
    resource_id: Optional[str] = field(default=None, metadata={'description': 'ARM resource id of the underlying compute'})  # fmt: skip
    identity: Optional[AzureManagedServiceIdentity] = field(default=None, metadata={'description': 'Managed service identity (system assigned and/or user assigned identities)'})  # fmt: skip
    azure_sku: Optional[AzureSku] = field(default=None, metadata={'description': 'The resource model definition representing SKU'})  # fmt: skip
    system_data: Optional[AzureSystemData] = field(default=None, metadata={'description': 'Metadata pertaining to creation and last modification of the resource.'})  # fmt: skip
    location: Optional[str] = field(default=None, metadata={'description': 'The geo-location where the resource lives'})  # fmt: skip

    @classmethod
    def collect_resources(cls, builder: GraphBuilder, **kwargs: Any) -> List["AzureMachineLearningCompute"]:
        log.debug(f"[Azure:{builder.account.id}] Collecting {cls.__name__} with ({kwargs})")

        if not issubclass(cls, MicrosoftResource):
            return []

        if spec := cls.api_spec:
            items = builder.client.list(spec, **kwargs)
            collected = cls.collect(items, builder)

            resources_by_location = defaultdict(list)

            for compute_resource in collected:
                location = getattr(compute_resource, "location", None)
                if location:
                    resources_by_location[location].append(compute_resource)

            # Process each unique location
            for location, compute_resources in resources_by_location.items():
                log.debug(f"Processing compute resources in location: {location}")

                # Collect VM sizes for the compute resources in this location
                cls._collect_vm_sizes(builder, location, compute_resources)

            if builder.config.collect_usage_metrics:
                try:
                    cls.collect_usage_metrics(builder, collected)
                except Exception as e:
                    log.warning(f"Failed to collect usage metrics for {cls.__name__}: {e}")

            return collected

        return []

    @staticmethod
    def _collect_vm_sizes(
        graph_builder: GraphBuilder, location: str, compute_resources: List["AzureMachineLearningCompute"]
    ) -> None:
        def collect_vm_sizes() -> None:
            api_spec = AzureResourceSpec(
                service="machinelearningservices",
                version="2024-04-01",
                path=f"/subscriptions/{{subscriptionId}}/providers/Microsoft.MachineLearningServices/locations/{location}/vmSizes",
                path_parameters=["subscriptionId"],
                query_parameters=["api-version"],
                access_path="value",
                expect_array=True,
            )
            items = graph_builder.client.list(api_spec)

            if not items:
                return

            # Set location for further connect_in_graph method
            for item in items:
                item["location"] = location

            # Collect the virtual machine sizes
            collected_vm_sizes = AzureMachineLearningVirtualMachineSize.collect(items, graph_builder)

            for compute_resource in compute_resources:
                vm_size = (compute_resource.properties or {}).get("vmSize")
                if vm_size:
                    for size in collected_vm_sizes:
                        if size.name == vm_size:
                            graph_builder.add_edge(compute_resource, node=size)
                        break

        graph_builder.submit_work(service_name, collect_vm_sizes)

    def post_process(self, graph_builder: GraphBuilder, source: Json) -> None:
        if resource_id := self.id:

            def collect_nodes() -> None:
                api_spec = AzureResourceSpec(
                    service="machinelearningservices",
                    version="2024-04-01",
                    path=f"{resource_id}/listNodes",
                    path_parameters=[],
                    query_parameters=["api-version"],
                    access_path="nodes",
                    expect_array=True,
                )
                items = graph_builder.client.list(api_spec)
                if not items:
                    return
                collected = AzureMachineLearningComputeNode.collect(items, graph_builder)
                for resource in collected:
                    graph_builder.add_edge(self, node=resource)

            graph_builder.submit_work(service_name, collect_nodes)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        # principal: collected via ms graph -> create a deferred edge
        if ai := self.identity:
            if pid := ai.principal_id:
                builder.add_deferred_edge(
                    from_node=self,
                    to_node=BySearchCriteria(f'is({MicrosoftGraphServicePrincipal.kind}) and reported.id=="{pid}"'),
                )
            if uai := ai.user_assigned_identities:
                for _, identity_info in uai.items():
                    if identity_info and identity_info.principal_id:
                        builder.add_deferred_edge(
                            from_node=self,
                            to_node=BySearchCriteria(
                                f'is({MicrosoftGraphUser.kind}) and reported.id=="{identity_info.principal_id}"'
                            ),
                        )
        if compute_resource_id := self.resource_id:
            builder.add_edge(
                self,
                clazz=(AzureComputeVirtualMachineBase, AzureContainerServiceManagedCluster, AzureWebApp),
                id=compute_resource_id,
            )


@define(eq=False, slots=False)
class AzureMachineLearningDataContainerBase(AzureProxyResource):
    kind: ClassVar[str] = "azure_machine_learning_data_container_base"
    _kind_display: ClassVar[str] = "Azure Machine Learning Data Container Base"
    _kind_service: ClassVar[Optional[str]] = service_name
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "container", "group": "ai"}
    # Collected via AzureMachineLearningWorkspace()
    mapping: ClassVar[Dict[str, Bender]] = AzureProxyResource.mapping | {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "properties": S("properties", "properties"),
        "description": S("properties", "description"),
        "is_archived": S("properties", "isArchived", default=False),
        "latest_version": S("properties", "latestVersion"),
        "next_version": S("properties", "nextVersion"),
        "provisioning_state": S("properties", "provisioningState"),
    }
    description: Optional[str] = field(default=None, metadata={"description": "The asset description text."})
    is_archived: Optional[bool] = field(default=False, metadata={"description": "Is the asset archived?"})
    latest_version: Optional[str] = field(default=None, metadata={"ignore_history": True, "description": "The latest version inside this container."})  # fmt: skip
    next_version: Optional[str] = field(default=None, metadata={"ignore_history": True, "description": "The next auto incremental version."})  # fmt: skip
    properties: Optional[Dict[str, Any]] = field(default=None, metadata={"description": ""})


@define(eq=False, slots=False)
class AzureMachineLearningWorkspaceDataContainer(AzureMachineLearningDataContainerBase, MicrosoftResource):
    # Defined to split registry and workspace resource

    kind: ClassVar[str] = "azure_machine_learning_workspace_data_container"
    _kind_display: ClassVar[str] = "Azure Machine Learning Workspace Data Container"
    _kind_description: ClassVar[str] = "The Azure Machine Learning Workspace Data Container is a storage resource within Azure Machine Learning. It serves as a central repository for datasets, models, and other artifacts used in machine learning projects. This container stores and manages data, facilitating collaboration among team members and providing version control for machine learning assets."  # fmt: skip
    _docs_url: ClassVar[str] = "https://learn.microsoft.com/en-us/azure/machine-learning/concept-data"
    _reference_kinds: ClassVar[ModelReference] = {
        "successors": {
            "default": [
                "azure_machine_learning_workspace_data_version",
            ]
        },
    }

    def post_process(self, graph_builder: GraphBuilder, source: Json) -> None:
        if resource_id := self.id:

            def collect_versions() -> None:
                api_spec = AzureResourceSpec(
                    service="machinelearningservices",
                    version="2024-04-01",
                    path=f"{resource_id}/versions",
                    path_parameters=[],
                    query_parameters=["api-version"],
                    access_path="value",
                    expect_array=True,
                )
                items = graph_builder.client.list(api_spec)
                if not items:
                    return
                collected = AzureMachineLearningWorkspaceDataVersion.collect(items, graph_builder)
                for resource in collected:
                    graph_builder.add_edge(self, node=resource)

            graph_builder.submit_work(service_name, collect_versions)


@define(eq=False, slots=False)
class AzureMachineLearningRegistryDataContainer(AzureMachineLearningDataContainerBase, MicrosoftResource):
    # Defined to split registry and workspace resource

    kind: ClassVar[str] = "azure_machine_learning_registry_data_container"
    _kind_display: ClassVar[str] = "Azure Machine Learning Registry Data Container"
    _kind_description: ClassVar[str] = "Azure Machine Learning Registry Data Container is a storage solution for machine learning artifacts in Azure. It stores and manages models, datasets, and environments, providing version control and collaboration features. Users can access, share, and deploy these artifacts across projects and teams, supporting the entire machine learning lifecycle within the Azure ecosystem."  # fmt: skip
    _docs_url: ClassVar[str] = (
        "https://learn.microsoft.com/en-us/azure/machine-learning/how-to-share-models-pipelines-across-workspaces-with-registries"
    )
    _reference_kinds: ClassVar[ModelReference] = {
        "successors": {
            "default": [
                "azure_machine_learning_registry_data_version",
            ]
        },
    }

    def post_process(self, graph_builder: GraphBuilder, source: Json) -> None:
        if resource_id := self.id:

            def collect_versions() -> None:
                api_spec = AzureResourceSpec(
                    service="machinelearningservices",
                    version="2024-04-01",
                    path=f"{resource_id}/versions",
                    path_parameters=[],
                    query_parameters=["api-version"],
                    access_path="value",
                    expect_array=True,
                )
                items = graph_builder.client.list(api_spec)
                if not items:
                    return
                collected = AzureMachineLearningRegistryDataVersion.collect(items, graph_builder)
                for resource in collected:
                    graph_builder.add_edge(self, node=resource)

            graph_builder.submit_work(service_name, collect_versions)


@define(eq=False, slots=False)
class AzureMachineLearningDataVersionBase(CheckVersionIsArchived, AzureProxyResource):
    kind: ClassVar[str] = "azure_machine_learning_data_version_base"
    _kind_display: ClassVar[str] = "Azure Machine Learning Data Version Base"
    _kind_service: ClassVar[Optional[str]] = service_name
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "resource", "group": "ai"}
    # Collected via AzureMachineLearningDataContainerBase()
    mapping: ClassVar[Dict[str, Bender]] = AzureProxyResource.mapping | {
        "id": S("id"),
        "name": S("name"),
        "ctime": S("systemData", "createdAt"),
        "mtime": S("systemData", "lastModifiedAt"),
        "data_type": S("properties", "dataType"),
        "data_uri": S("properties", "dataUri"),
        "tags": S("properties", "tags", default={}),
        "code_uri": S("properties", "codeUri"),
        "provisioning_state": S("properties", "provisioningState"),
        "description": S("properties", "description"),
        "properties": S("properties", "properties"),
        "is_anonymous": S("properties", "isAnonymous"),
        "is_archived": S("properties", "isArchived"),
    }
    description: Optional[str] = field(default=None, metadata={"description": "The asset description text."})
    properties: Optional[Dict[str, Any]] = field(default=None, metadata={'description': 'The asset property dictionary.'})  # fmt: skip
    is_anonymous: Optional[bool] = field(default=None, metadata={'description': 'If the name version are system generated (anonymous registration).'})  # fmt: skip
    is_archived: Optional[bool] = field(default=None, metadata={"description": "Is the asset archived?"})
    data_type: Optional[str] = field(default=None, metadata={"description": "Enum to determine the type of data."})
    data_uri: Optional[str] = field(default=None, metadata={'description': '[Required] Uri of the data. Example: https://go.microsoft.com/fwlink/?linkid=2202330'})  # fmt: skip


@define(eq=False, slots=False)
class AzureMachineLearningWorkspaceDataVersion(AzureMachineLearningDataVersionBase, MicrosoftResource):
    # Defined to split registry and workspace resource

    kind: ClassVar[str] = "azure_machine_learning_workspace_data_version"
    _kind_display: ClassVar[str] = "Azure Machine Learning Workspace Data Version"
    _kind_description: ClassVar[str] = "Azure Machine Learning Workspace Data Version is a feature that tracks and manages different iterations of datasets within a workspace. It stores metadata about data changes, creation dates, and lineage information. This versioning system helps data scientists and machine learning engineers maintain data consistency, reproduce experiments, and collaborate on projects using shared datasets."  # fmt: skip
    _docs_url: ClassVar[str] = "https://learn.microsoft.com/en-us/azure/machine-learning/how-to-version-track-datasets"


@define(eq=False, slots=False)
class AzureMachineLearningRegistryDataVersion(AzureMachineLearningDataVersionBase, MicrosoftResource):
    # Defined to split registry and workspace resource

    kind: ClassVar[str] = "azure_machine_learning_registry_data_version"
    _kind_display: ClassVar[str] = "Azure Machine Learning Registry Data Version"
    _kind_description: ClassVar[str] = "Azure Machine Learning Registry Data Version is a component that tracks and manages versions of datasets within the Azure Machine Learning service. It stores metadata about data assets, including their source, format, and schema. This versioning system helps data scientists and machine learning engineers maintain data lineage, reproduce experiments, and collaborate on projects effectively."  # fmt: skip
    _docs_url: ClassVar[str] = (
        "https://learn.microsoft.com/en-us/azure/machine-learning/how-to-manage-registries?tabs=cli"
    )
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "version", "group": "ai"}


@define(eq=False, slots=False)
class AzureMachineLearningDatastore(MicrosoftResource, AzureProxyResource):
    kind: ClassVar[str] = "azure_machine_learning_datastore"
    _kind_display: ClassVar[str] = "Azure Machine Learning Datastore"
    _kind_service: ClassVar[Optional[str]] = service_name
    _kind_description: ClassVar[str] = "Azure Machine Learning Datastore is a storage abstraction that connects to various Azure storage services. It provides a unified interface for accessing data across different storage types, including Azure Blob Storage, Azure Data Lake Storage, and Azure SQL Database. Users can read from and write to datastores without specifying connection information or authentication details in their code."  # fmt: skip
    _docs_url: ClassVar[str] = (
        "https://learn.microsoft.com/en-us/azure/machine-learning/concept-data?view=azureml-api-2"
    )
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "bucket", "group": "storage"}
    # Collected via AzureMachineLearningWorkspace()
    mapping: ClassVar[Dict[str, Bender]] = AzureProxyResource.mapping | {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "ctime": S("systemData", "createdAt"),
        "mtime": S("systemData", "lastModifiedAt"),
        "credentials": S("properties", "credentials", "credentialsType"),
        "datastore_type": S("properties", "datastoreType"),
        "is_default": S("properties", "isDefault"),
        "description": S("properties", "description"),
        "properties": S("properties", "properties"),
    }
    description: Optional[str] = field(default=None, metadata={"description": "The asset description text."})
    properties: Optional[Dict[str, Any]] = field(default=None, metadata={'description': 'The asset property dictionary.'})  # fmt: skip
    credentials: Optional[str] = field(default=None, metadata={'description': 'Base definition for datastore credentials.'})  # fmt: skip
    datastore_type: Optional[str] = field(default=None, metadata={'description': 'Enum to determine the datastore contents type.'})  # fmt: skip
    is_default: Optional[bool] = field(default=None, metadata={'description': 'Readonly property to indicate if datastore is the workspace default datastore'})  # fmt: skip


@define(eq=False, slots=False)
class AzureEndpointDeploymentResourcePropertiesBasicResource:
    kind: ClassVar[str] = "azure_endpoint_deployment_resource_properties_basic_resource"
    mapping: ClassVar[Dict[str, Bender]] = {
        "failure_reason": S("properties", "failureReason"),
        "id": S("id"),
        "name": S("name"),
        "provisioning_state": S("properties", "provisioningState"),
        "system_data": S("systemData") >> Bend(AzureSystemData.mapping),
        "type": S("properties", "type"),
    }
    failure_reason: Optional[str] = field(default=None, metadata={'description': 'The failure reason if the creation failed.'})  # fmt: skip
    id: Optional[str] = field(default=None, metadata={'description': 'Fully qualified resource ID for the resource. Ex - /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}'})  # fmt: skip
    name: Optional[str] = field(default=None, metadata={"description": "The name of the resource"})
    provisioning_state: Optional[str] = field(default=None, metadata={"description": ""})
    system_data: Optional[AzureSystemData] = field(default=None, metadata={'description': 'Metadata pertaining to creation and last modification of the resource.'})  # fmt: skip
    type: Optional[str] = field(default=None, metadata={"description": "Kind of the deployment."})


@define(eq=False, slots=False)
class AzureMachineLearningEndpoint(MicrosoftResource):
    kind: ClassVar[str] = "azure_machine_learning_endpoint"
    _kind_display: ClassVar[str] = "Azure Machine Learning Endpoint"
    _kind_service: ClassVar[Optional[str]] = service_name
    _kind_description: ClassVar[str] = "Azure Machine Learning Endpoint is a cloud-based service that provides a deployment target for machine learning models. It creates a secure HTTPS endpoint for real-time inference, handling incoming requests and returning predictions. Users can deploy models, manage versions, and monitor performance through this interface, facilitating integration of machine learning into applications and services."  # fmt: skip
    _docs_url: ClassVar[str] = "https://learn.microsoft.com/en-us/azure/machine-learning/concept-endpoints"
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "endpoint", "group": "ai"}
    # Collected via AzureMachineLearningWorkspace()
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "ctime": S("systemData", "createdAt"),
        "mtime": S("systemData", "lastModifiedAt"),
        "associated_resource_id": S("properties", "associatedResourceId"),
        "deployments": S("properties", "deployments")
        >> ForallBend(AzureEndpointDeploymentResourcePropertiesBasicResource.mapping),
        "endpoint_type": S("properties", "endpointType"),
        "endpoint_uri": S("properties", "endpointUri"),
        "failure_reason": S("properties", "failureReason"),
        "provisioning_state": S("properties", "provisioningState"),
        "should_create_ai_services_endpoint": S("properties", "shouldCreateAiServicesEndpoint"),
        "system_data": S("systemData") >> Bend(AzureSystemData.mapping),
    }
    associated_resource_id: Optional[str] = field(default=None, metadata={'description': 'Byo resource id for creating the built-in model service endpoints.'})  # fmt: skip
    deployments: Optional[List[AzureEndpointDeploymentResourcePropertiesBasicResource]] = field(default=None, metadata={'description': 'Deployments info.'})  # fmt: skip
    endpoint_type: Optional[str] = field(default=None, metadata={"description": "Type of the endpoint."})
    endpoint_uri: Optional[str] = field(default=None, metadata={"description": "Uri of the endpoint."})
    failure_reason: Optional[str] = field(default=None, metadata={'description': 'The failure reason if the creation failed.'})  # fmt: skip
    should_create_ai_services_endpoint: Optional[bool] = field(default=None, metadata={'description': 'Whether the proxy (non-byo) endpoint is a regular endpoint or a OneKeyV2 AI services account endpoint.'})  # fmt: skip
    system_data: Optional[AzureSystemData] = field(default=None, metadata={'description': 'Metadata pertaining to creation and last modification of the resource.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureBuildContext:
    kind: ClassVar[str] = "azure_build_context"
    mapping: ClassVar[Dict[str, Bender]] = {"context_uri": S("contextUri"), "dockerfile_path": S("dockerfilePath")}
    context_uri: Optional[str] = field(default=None, metadata={'description': '[Required] URI of the Docker build context used to build the image. Supports blob URIs on environment creation and may return blob or Git URIs. <seealso href= https://docs.docker.com/engine/reference/commandline/build/#extended-description />'})  # fmt: skip
    dockerfile_path: Optional[str] = field(default=None, metadata={'description': 'Path to the Dockerfile in the build context. <seealso href= https://docs.docker.com/engine/reference/builder/ />'})  # fmt: skip


@define(eq=False, slots=False)
class AzureInferenceContainerRoute:
    kind: ClassVar[str] = "azure_inference_container_route"
    mapping: ClassVar[Dict[str, Bender]] = {"path": S("path"), "port": S("port")}
    path: Optional[str] = field(default=None, metadata={"description": "[Required] The path for the route."})
    port: Optional[int] = field(default=None, metadata={"description": "[Required] The port for the route."})


@define(eq=False, slots=False)
class AzureInferenceContainerProperties:
    kind: ClassVar[str] = "azure_inference_container_properties"
    mapping: ClassVar[Dict[str, Bender]] = {
        "liveness_route": S("livenessRoute") >> Bend(AzureInferenceContainerRoute.mapping),
        "readiness_route": S("readinessRoute") >> Bend(AzureInferenceContainerRoute.mapping),
        "scoring_route": S("scoringRoute") >> Bend(AzureInferenceContainerRoute.mapping),
    }
    liveness_route: Optional[AzureInferenceContainerRoute] = field(default=None, metadata={"description": ""})
    readiness_route: Optional[AzureInferenceContainerRoute] = field(default=None, metadata={"description": ""})
    scoring_route: Optional[AzureInferenceContainerRoute] = field(default=None, metadata={"description": ""})


@define(eq=False, slots=False)
class AzureMachineLearningEnvironmentContainerBase(AzureProxyResource):
    kind: ClassVar[str] = "azure_machine_learning_environment_container_base"
    _kind_display: ClassVar[str] = "Azure Machine Learning Environment Container Base"
    _kind_service: ClassVar[Optional[str]] = service_name
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "container", "group": "ai"}
    # Collected via AzureMachineLearningWorkspace()
    mapping: ClassVar[Dict[str, Bender]] = AzureProxyResource.mapping | {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "properties": S("properties", "properties"),
        "description": S("properties", "description"),
        "is_archived": S("properties", "isArchived", default=False),
        "latest_version": S("properties", "latestVersion"),
        "next_version": S("properties", "nextVersion"),
        "provisioning_state": S("properties", "provisioningState"),
    }
    description: Optional[str] = field(default=None, metadata={"description": "The asset description text."})
    is_archived: Optional[bool] = field(default=False, metadata={"description": "Is the asset archived?"})
    latest_version: Optional[str] = field(
        default=None, metadata={"description": "The latest version inside this container."}
    )
    next_version: Optional[str] = field(default=None, metadata={"description": "The next auto incremental version."})
    properties: Optional[Dict[str, Any]] = field(default=None, metadata={"description": ""})


@define(eq=False, slots=False)
class AzureMachineLearningWorkspaceEnvironmentContainer(
    AzureMachineLearningEnvironmentContainerBase, MicrosoftResource
):
    # Defined to split registry and workspace resource

    kind: ClassVar[str] = "azure_machine_learning_workspace_environment_container"
    _kind_display: ClassVar[str] = "Azure Machine Learning Workspace Environment Container"
    _kind_description: ClassVar[str] = "The Azure Machine Learning Workspace Environment Container is a component of Azure's cloud-based machine learning platform. It provides a preconfigured workspace with necessary tools and dependencies for developing, training, and deploying machine learning models. This container includes libraries, frameworks, and computational resources, offering a consistent environment for data scientists and developers to collaborate on machine learning projects."  # fmt: skip
    _docs_url: ClassVar[str] = "https://learn.microsoft.com/en-us/azure/machine-learning/how-to-use-environments"
    _reference_kinds: ClassVar[ModelReference] = {
        "successors": {
            "default": [
                "azure_machine_learning_workspace_environment_version",
            ]
        },
    }

    def post_process(self, graph_builder: GraphBuilder, source: Json) -> None:
        if resource_id := self.id:

            def collect_versions() -> None:
                api_spec = AzureResourceSpec(
                    service="machinelearningservices",
                    version="2024-04-01",
                    path=f"{resource_id}/versions",
                    path_parameters=[],
                    query_parameters=["api-version"],
                    access_path="value",
                    expect_array=True,
                )
                items = graph_builder.client.list(api_spec)
                if not items:
                    return
                collected = AzureMachineLearningWorkspaceEnvironmentVersion.collect(items, graph_builder)
                for resource in collected:
                    graph_builder.add_edge(self, node=resource)

            graph_builder.submit_work(service_name, collect_versions)


@define(eq=False, slots=False)
class AzureMachineLearningRegistryEnvironmentContainer(AzureMachineLearningEnvironmentContainerBase, MicrosoftResource):
    # Defined to split registry and workspace resource

    kind: ClassVar[str] = "azure_machine_learning_registry_environment_container"
    _kind_display: ClassVar[str] = "Azure Machine Learning Registry Environment Container"
    _kind_description: ClassVar[str] = "Azure Machine Learning Registry Environment Container is a component of Azure Machine Learning that stores and manages environment definitions. It provides a central repository for containerized environments used in machine learning workflows. Users can create, version, and share environments across projects and teams, ensuring reproducibility and consistency in model development and deployment processes."  # fmt: skip
    _docs_url: ClassVar[str] = "https://learn.microsoft.com/en-us/azure/machine-learning/how-to-use-environments"
    _reference_kinds: ClassVar[ModelReference] = {
        "successors": {
            "default": [
                "azure_machine_learning_registry_environment_version",
            ]
        },
    }

    def post_process(self, graph_builder: GraphBuilder, source: Json) -> None:
        if resource_id := self.id:

            def collect_versions() -> None:
                api_spec = AzureResourceSpec(
                    service="machinelearningservices",
                    version="2024-04-01",
                    path=f"{resource_id}/versions",
                    path_parameters=[],
                    query_parameters=["api-version"],
                    access_path="value",
                    expect_array=True,
                )
                items = graph_builder.client.list(api_spec)
                if not items:
                    return
                collected = AzureMachineLearningRegistryEnvironmentVersion.collect(items, graph_builder)
                for resource in collected:
                    graph_builder.add_edge(self, node=resource)

            graph_builder.submit_work(service_name, collect_versions)


@define(eq=False, slots=False)
class AzureMachineLearningEnvironmentVersionBase(CheckVersionIsArchived, AzureProxyResource, PhantomBaseResource):
    kind: ClassVar[str] = "azure_machine_learning_environment_version_base"
    _kind_display: ClassVar[str] = "Azure Machine Learning Environment Version Base"
    _kind_service: ClassVar[Optional[str]] = service_name
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "resource", "group": "ai"}
    # Collected via AzureMachineLearningEnvironmentContainerBase()
    mapping: ClassVar[Dict[str, Bender]] = AzureProxyResource.mapping | {
        "id": S("id"),
        "name": S("name"),
        "ctime": S("systemData", "createdAt"),
        "mtime": S("systemData", "lastModifiedAt"),
        "auto_rebuild": S("properties", "autoRebuild"),
        "build": S("properties", "build") >> Bend(AzureBuildContext.mapping),
        "conda_file": S("properties", "condaFile"),
        "environment_type": S("properties", "environmentType"),
        "image": S("properties", "image"),
        "inference_config": S("properties", "inferenceConfig") >> Bend(AzureInferenceContainerProperties.mapping),
        "os_type": S("properties", "osType"),
        "stage": S("properties", "stage"),
        "tags": S("properties", "tags", default={}),
        "code_uri": S("properties", "codeUri"),
        "provisioning_state": S("properties", "provisioningState"),
        "description": S("properties", "description"),
        "properties": S("properties", "properties"),
        "is_anonymous": S("properties", "isAnonymous"),
        "is_archived": S("properties", "isArchived"),
    }
    description: Optional[str] = field(default=None, metadata={"description": "The asset description text."})
    properties: Optional[Dict[str, Any]] = field(default=None, metadata={'description': 'The asset property dictionary.'})  # fmt: skip
    is_anonymous: Optional[bool] = field(default=None, metadata={'description': 'If the name version are system generated (anonymous registration).'})  # fmt: skip
    is_archived: Optional[bool] = field(default=None, metadata={"description": "Is the asset archived?"})
    auto_rebuild: Optional[str] = field(default=None, metadata={'description': 'AutoRebuild setting for the derived image'})  # fmt: skip
    build: Optional[AzureBuildContext] = field(default=None, metadata={'description': 'Configuration settings for Docker build context'})  # fmt: skip
    conda_file: Optional[str] = field(default=None, metadata={'description': 'Standard configuration file used by Conda that lets you install any kind of package, including Python, R, and C/C++ packages. <see href= https://repo2docker.readthedocs.io/en/latest/config_files.html#environment-yml-install-a-conda-environment />'})  # fmt: skip
    environment_type: Optional[str] = field(default=None, metadata={'description': 'Environment type is either user created or curated by Azure ML service'})  # fmt: skip
    image: Optional[str] = field(default=None, metadata={'description': 'Name of the image that will be used for the environment. <seealso href= https://docs.microsoft.com/en-us/azure/machine-learning/how-to-deploy-custom-docker-image#use-a-custom-base-image />'})  # fmt: skip
    inference_config: Optional[AzureInferenceContainerProperties] = field(default=None, metadata={"description": ""})
    os_type: Optional[str] = field(default=None, metadata={"description": "The type of operating system."})
    stage: Optional[str] = field(default=None, metadata={'description': 'Stage in the environment lifecycle assigned to this environment'})  # fmt: skip


@define(eq=False, slots=False)
class AzureMachineLearningWorkspaceEnvironmentVersion(AzureMachineLearningEnvironmentVersionBase, MicrosoftResource):
    # Defined to split registry and workspace resource

    kind: ClassVar[str] = "azure_machine_learning_workspace_environment_version"
    _kind_display: ClassVar[str] = "Azure Machine Learning Workspace Environment Version"
    _kind_description: ClassVar[str] = "Azure Machine Learning Workspace Environment Version represents a specific configuration snapshot of a workspace environment. It includes libraries, dependencies, and settings required for machine learning projects. Users can create, manage, and deploy different versions to maintain consistency across development stages and ensure reproducibility of experiments and models within the Azure Machine Learning platform."  # fmt: skip
    _docs_url: ClassVar[str] = "https://learn.microsoft.com/en-us/azure/machine-learning/concept-environments"


@define(eq=False, slots=False)
class AzureMachineLearningRegistryEnvironmentVersion(AzureMachineLearningEnvironmentVersionBase, MicrosoftResource):
    # Defined to split registry and workspace resource

    kind: ClassVar[str] = "azure_machine_learning_registry_environment_version"
    _kind_display: ClassVar[str] = "Azure Machine Learning Registry Environment Version"
    _kind_description: ClassVar[str] = "Azure Machine Learning Registry Environment Version represents a specific iteration of a containerized environment in Azure Machine Learning. It includes dependencies, libraries, and runtime configurations required for machine learning workflows. Users can create, manage, and deploy these versions to maintain consistency across different stages of model development and deployment within Azure Machine Learning projects."  # fmt: skip
    _docs_url: ClassVar[str] = (
        "https://learn.microsoft.com/en-us/azure/machine-learning/concept-environments?view=azureml-api-2#environment-versions"
    )
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "version", "group": "ai"}


@define(eq=False, slots=False)
class AzureMachineLearningFeature(MicrosoftResource, AzureProxyResource):
    kind: ClassVar[str] = "azure_machine_learning_feature"
    _kind_display: ClassVar[str] = "Azure Machine Learning Feature"
    _kind_service: ClassVar[Optional[str]] = service_name
    _kind_description: ClassVar[str] = "Azure Machine Learning Feature is a cloud-based service for creating, managing, and deploying machine learning models. It offers tools for data preparation, model training, and evaluation. Users can build, test, and deploy models using various programming languages and frameworks. The service integrates with other Azure products and supports both supervised and unsupervised learning techniques."  # fmt: skip
    _docs_url: ClassVar[str] = "https://learn.microsoft.com/en-us/azure/machine-learning/"
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "resource", "group": "ai"}
    # Collected via AzureMachineLearningFeaturesetVersion()
    mapping: ClassVar[Dict[str, Bender]] = AzureProxyResource.mapping | {
        "id": S("id"),
        "name": S("name"),
        "properties": S("properties", "properties"),
        "description": S("properties", "description"),
        "data_type": S("properties", "dataType"),
        "feature_name": S("properties", "featureName"),
        "tags": S("properties", "tags", default={}),
    }
    data_type: Optional[str] = field(default=None, metadata={"description": "Specifies type."})
    feature_name: Optional[str] = field(default=None, metadata={"description": "Specifies name."})
    description: Optional[str] = field(default=None, metadata={"description": "The asset description text."})
    properties: Optional[Dict[str, Any]] = field(default=None, metadata={'description': ''})  # fmt: skip


@define(eq=False, slots=False)
class AzureTriggerBase:
    kind: ClassVar[str] = "azure_trigger_base"
    mapping: ClassVar[Dict[str, Bender]] = {
        "end_time": S("endTime"),
        "start_time": S("startTime"),
        "time_zone": S("timeZone"),
        "trigger_type": S("triggerType"),
    }
    end_time: Optional[str] = field(default=None, metadata={'description': 'Specifies end time of schedule in ISO 8601, but without a UTC offset. Refer https://en.wikipedia.org/wiki/ISO_8601. Recommented format would be 2022-06-01T00:00:01 If not present, the schedule will run indefinitely'})  # fmt: skip
    start_time: Optional[str] = field(default=None, metadata={'description': 'Specifies start time of schedule in ISO 8601 format, but without a UTC offset.'})  # fmt: skip
    time_zone: Optional[str] = field(default=None, metadata={'description': 'Specifies time zone in which the schedule runs. TimeZone should follow Windows time zone format. Refer: https://docs.microsoft.com/en-us/windows-hardware/manufacture/desktop/default-time-zones?view=windows-11'})  # fmt: skip
    trigger_type: Optional[str] = field(default=None, metadata={"description": ""})


@define(eq=False, slots=False)
class AzureRecurrenceSchedule:
    kind: ClassVar[str] = "azure_recurrence_schedule"
    mapping: ClassVar[Dict[str, Bender]] = {
        "hours": S("hours"),
        "minutes": S("minutes"),
        "month_days": S("monthDays"),
        "week_days": S("weekDays"),
    }
    hours: Optional[List[int]] = field(
        default=None, metadata={"description": "[Required] List of hours for the schedule."}
    )
    minutes: Optional[List[int]] = field(default=None, metadata={'description': '[Required] List of minutes for the schedule.'})  # fmt: skip
    month_days: Optional[List[int]] = field(
        default=None, metadata={"description": "List of month days for the schedule"}
    )
    week_days: Optional[List[str]] = field(default=None, metadata={"description": "List of days for the schedule."})


@define(eq=False, slots=False)
class AzureRecurrenceTrigger(AzureTriggerBase):
    kind: ClassVar[str] = "azure_recurrence_trigger"
    mapping: ClassVar[Dict[str, Bender]] = AzureTriggerBase.mapping | {
        "frequency": S("frequency"),
        "interval": S("interval"),
        "schedule": S("schedule") >> Bend(AzureRecurrenceSchedule.mapping),
    }
    frequency: Optional[str] = field(default=None, metadata={'description': 'Enum to describe the frequency of a recurrence schedule'})  # fmt: skip
    interval: Optional[int] = field(default=None, metadata={'description': '[Required] Specifies schedule interval in conjunction with frequency'})  # fmt: skip
    schedule: Optional[AzureRecurrenceSchedule] = field(default=None, metadata={"description": ""})


@define(eq=False, slots=False)
class AzureWebhook:
    kind: ClassVar[str] = "azure_webhook"
    mapping: ClassVar[Dict[str, Bender]] = {"event_type": S("eventType"), "webhook_type": S("webhookType")}
    event_type: Optional[str] = field(default=None, metadata={'description': 'Send callback on a specified notification event'})  # fmt: skip
    webhook_type: Optional[str] = field(default=None, metadata={'description': 'Enum to determine the webhook callback service type.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureNotificationSetting:
    kind: ClassVar[str] = "azure_notification_setting"
    mapping: ClassVar[Dict[str, Bender]] = {"email_on": S("emailOn"), "emails": S("emails"), "webhooks": S("webhooks")}
    email_on: Optional[List[str]] = field(default=None, metadata={'description': 'Send email notification to user on specified notification type'})  # fmt: skip
    emails: Optional[List[str]] = field(default=None, metadata={'description': 'This is the email recipient list which has a limitation of 499 characters in total concat with comma separator'})  # fmt: skip
    webhooks: Optional[Dict[str, AzureWebhook]] = field(default=None, metadata={'description': 'Send webhook callback to a service. Key is a user-provided name for the webhook.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureMaterializationSettings:
    kind: ClassVar[str] = "azure_materialization_settings"
    mapping: ClassVar[Dict[str, Bender]] = {
        "notification": S("notification") >> Bend(AzureNotificationSetting.mapping),
        "resource": S("resource", "instanceType"),
        "schedule": S("schedule") >> Bend(AzureRecurrenceTrigger.mapping),
        "spark_configuration": S("sparkConfiguration"),
        "store_type": S("storeType"),
    }
    notification: Optional[AzureNotificationSetting] = field(default=None, metadata={'description': 'Configuration for notification.'})  # fmt: skip
    resource: Optional[str] = field(default=None, metadata={"description": "DTO object representing compute resource"})
    schedule: Optional[AzureRecurrenceTrigger] = field(default=None, metadata={"description": ""})
    spark_configuration: Optional[Dict[str, str]] = field(default=None, metadata={'description': 'Specifies the spark compute settings'})  # fmt: skip
    store_type: Optional[str] = field(default=None, metadata={"description": ""})


@define(eq=False, slots=False)
class AzureMachineLearningFeaturesetContainer(MicrosoftResource, AzureProxyResource):
    kind: ClassVar[str] = "azure_machine_learning_featureset_container"
    _kind_display: ClassVar[str] = "Azure Machine Learning Featureset Container"
    _kind_service: ClassVar[Optional[str]] = service_name
    _kind_description: ClassVar[str] = "Azure Machine Learning Featureset Container is a component of Azure Machine Learning that stores and manages feature data for machine learning models. It provides a centralized repository for feature definitions, values, and metadata. Users can create, update, and retrieve features, ensuring consistency across training and inference pipelines while supporting feature reuse and version control."  # fmt: skip
    _docs_url: ClassVar[str] = "https://learn.microsoft.com/en-us/azure/machine-learning/concept-datasets-featuresets"
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "container", "group": "ai"}
    # Collected via AzureMachineLearningWorkspace()
    _reference_kinds: ClassVar[ModelReference] = {
        "successors": {
            "default": [
                "azure_machine_learning_featureset_version",
            ]
        },
    }
    mapping: ClassVar[Dict[str, Bender]] = AzureProxyResource.mapping | {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "properties": S("properties", "properties"),
        "description": S("properties", "description"),
        "is_archived": S("properties", "isArchived", default=False),
        "latest_version": S("properties", "latestVersion"),
        "next_version": S("properties", "nextVersion"),
        "provisioning_state": S("properties", "provisioningState"),
    }
    description: Optional[str] = field(default=None, metadata={"description": "The asset description text."})
    is_archived: Optional[bool] = field(default=False, metadata={"description": "Is the asset archived?"})
    latest_version: Optional[str] = field(
        default=None, metadata={"description": "The latest version inside this container."}
    )
    next_version: Optional[str] = field(default=None, metadata={"description": "The next auto incremental version."})
    properties: Optional[Dict[str, Any]] = field(default=None, metadata={"description": ""})

    def post_process(self, graph_builder: GraphBuilder, source: Json) -> None:
        if resource_id := self.id:

            def collect_versions() -> None:
                api_spec = AzureResourceSpec(
                    service="machinelearningservices",
                    version="2024-04-01",
                    path=f"{resource_id}/versions",
                    path_parameters=[],
                    query_parameters=["api-version"],
                    access_path="value",
                    expect_array=True,
                )
                items = graph_builder.client.list(api_spec)
                if not items:
                    return
                collected = AzureMachineLearningFeaturesetVersion.collect(items, graph_builder)
                for resource in collected:
                    graph_builder.add_edge(self, node=resource)

            graph_builder.submit_work(service_name, collect_versions)


@define(eq=False, slots=False)
class AzureMachineLearningFeaturesetVersion(MicrosoftResource, AzureProxyResource):
    kind: ClassVar[str] = "azure_machine_learning_featureset_version"
    _kind_display: ClassVar[str] = "Azure Machine Learning Featureset Version"
    _kind_service: ClassVar[Optional[str]] = service_name
    _kind_description: ClassVar[str] = "Azure Machine Learning Featureset Version is a component of Azure Machine Learning that manages and tracks versions of feature sets. It stores feature definitions, data, and metadata, enabling data scientists to reproduce experiments, compare model performance across versions, and maintain consistency in machine learning pipelines. This versioning system supports collaboration and helps ensure data lineage in ML projects."  # fmt: skip
    _docs_url: ClassVar[str] = "https://learn.microsoft.com/en-us/azure/machine-learning/concept-feature-store"
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "version", "group": "ai"}
    # Collected via AzureMachineLearningFeaturesetContainer()
    _reference_kinds: ClassVar[ModelReference] = {
        "successors": {
            "default": [
                "azure_machine_learning_feature",
            ]
        },
    }
    mapping: ClassVar[Dict[str, Bender]] = AzureProxyResource.mapping | {
        "id": S("id"),
        "name": S("name"),
        "ctime": S("systemData", "createdAt"),
        "mtime": S("systemData", "lastModifiedAt"),
        "entities": S("properties", "entities"),
        "materialization_settings": S("properties", "materializationSettings")
        >> Bend(AzureMaterializationSettings.mapping),
        "specification": S("properties", "specification", "path"),
        "stage": S("properties", "stage"),
        "tags": S("properties", "tags", default={}),
        "code_uri": S("properties", "codeUri"),
        "provisioning_state": S("properties", "provisioningState"),
        "description": S("properties", "description"),
        "properties": S("properties", "properties"),
        "is_anonymous": S("properties", "isAnonymous"),
        "is_archived": S("properties", "isArchived"),
    }
    description: Optional[str] = field(default=None, metadata={"description": "The asset description text."})
    properties: Optional[Dict[str, Any]] = field(default=None, metadata={'description': 'The asset property dictionary.'})  # fmt: skip
    is_anonymous: Optional[bool] = field(default=None, metadata={'description': 'If the name version are system generated (anonymous registration).'})  # fmt: skip
    is_archived: Optional[bool] = field(default=None, metadata={"description": "Is the asset archived?"})
    entities: Optional[List[str]] = field(default=None, metadata={"description": "Specifies list of entities"})
    materialization_settings: Optional[AzureMaterializationSettings] = field(default=None, metadata={'description': ''})  # fmt: skip
    specification: Optional[str] = field(default=None, metadata={'description': 'DTO object representing specification'})  # fmt: skip
    stage: Optional[str] = field(default=None, metadata={"description": "Specifies the asset stage"})

    def post_process(self, graph_builder: GraphBuilder, source: Json) -> None:
        if resource_id := self.id:

            def collect_features() -> None:
                api_spec = AzureResourceSpec(
                    service="machinelearningservices",
                    version="2024-04-01",
                    path=f"{resource_id}/features",
                    path_parameters=[],
                    query_parameters=["api-version"],
                    access_path="value",
                    expect_array=True,
                )
                items = graph_builder.client.list(api_spec)
                if not items:
                    return
                collected = AzureMachineLearningFeature.collect(items, graph_builder)
                for resource in collected:
                    graph_builder.add_edge(self, node=resource)

            graph_builder.submit_work(service_name, collect_features)


@define(eq=False, slots=False)
class AzureMachineLearningFeaturestoreEntityContainer(MicrosoftResource, AzureProxyResource):
    kind: ClassVar[str] = "azure_machine_learning_featurestore_entity_container"
    _kind_display: ClassVar[str] = "Azure Machine Learning Featurestore Entity Container"
    _kind_service: ClassVar[Optional[str]] = service_name
    _kind_description: ClassVar[str] = "Azure Machine Learning Featurestore Entity Container is a storage component within Azure Machine Learning. It stores and manages feature data for machine learning models. This container organizes features into logical groups, tracks feature lineage, and provides version control. It supports data access across different projects and teams, promoting feature reuse and consistency in model development."  # fmt: skip
    _docs_url: ClassVar[str] = "https://learn.microsoft.com/en-us/azure/machine-learning/concept-feature-store"
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "container", "group": "ai"}
    # Collected via AzureMachineLearningWorkspace()
    _reference_kinds: ClassVar[ModelReference] = {
        "successors": {
            "default": [
                "azure_machine_learning_featurestore_entity_version",
            ]
        },
    }
    mapping: ClassVar[Dict[str, Bender]] = AzureProxyResource.mapping | {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "properties": S("properties", "properties"),
        "description": S("properties", "description"),
        "is_archived": S("properties", "isArchived", default=False),
        "latest_version": S("properties", "latestVersion"),
        "next_version": S("properties", "nextVersion"),
        "provisioning_state": S("properties", "provisioningState"),
    }
    description: Optional[str] = field(default=None, metadata={"description": "The asset description text."})
    is_archived: Optional[bool] = field(default=False, metadata={"description": "Is the asset archived?"})
    latest_version: Optional[str] = field(
        default=None, metadata={"description": "The latest version inside this container."}
    )
    next_version: Optional[str] = field(default=None, metadata={"description": "The next auto incremental version."})
    properties: Optional[Dict[str, Any]] = field(default=None, metadata={"description": ""})

    def post_process(self, graph_builder: GraphBuilder, source: Json) -> None:
        if resource_id := self.id:

            def collect_versions() -> None:
                api_spec = AzureResourceSpec(
                    service="machinelearningservices",
                    version="2024-04-01",
                    path=f"{resource_id}/versions",
                    path_parameters=[],
                    query_parameters=["api-version"],
                    access_path="value",
                    expect_array=True,
                )
                items = graph_builder.client.list(api_spec)
                if not items:
                    return
                collected = AzureMachineLearningFeaturestoreEntityVersion.collect(items, graph_builder)
                for resource in collected:
                    graph_builder.add_edge(self, node=resource)

            graph_builder.submit_work(service_name, collect_versions)


@define(eq=False, slots=False)
class AzureIndexColumn:
    kind: ClassVar[str] = "azure_index_column"
    mapping: ClassVar[Dict[str, Bender]] = {"column_name": S("columnName"), "data_type": S("dataType")}
    column_name: Optional[str] = field(default=None, metadata={"description": "Specifies the column name"})
    data_type: Optional[str] = field(default=None, metadata={"description": ""})


@define(eq=False, slots=False)
class AzureMachineLearningFeaturestoreEntityVersion(MicrosoftResource, AzureProxyResource):
    kind: ClassVar[str] = "azure_machine_learning_featurestore_entity_version"
    _kind_display: ClassVar[str] = "Azure Machine Learning Featurestore Entity Version"
    _kind_service: ClassVar[Optional[str]] = service_name
    _kind_description: ClassVar[str] = "Azure Machine Learning Featurestore Entity Version represents a specific iteration of a feature entity in the Azure Machine Learning Featurestore. It contains metadata about the feature entity, including its schema, data sources, and transformations. This versioning system tracks changes to feature definitions over time, supporting reproducibility and consistency in machine learning workflows."  # fmt: skip
    _docs_url: ClassVar[str] = "https://learn.microsoft.com/en-us/azure/machine-learning/concept-feature-store"
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "version", "group": "ai"}
    # Collected via AzureMachineLearningFeaturestoreEntityContainer()
    mapping: ClassVar[Dict[str, Bender]] = AzureProxyResource.mapping | {
        "id": S("id"),
        "name": S("name"),
        "ctime": S("systemData", "createdAt"),
        "mtime": S("systemData", "lastModifiedAt"),
        "index_columns": S("properties", "indexColumns") >> ForallBend(AzureIndexColumn.mapping),
        "stage": S("properties", "stage"),
        "tags": S("properties", "tags", default={}),
        "code_uri": S("properties", "codeUri"),
        "provisioning_state": S("properties", "provisioningState"),
        "description": S("properties", "description"),
        "properties": S("properties", "properties"),
        "is_anonymous": S("properties", "isAnonymous"),
        "is_archived": S("properties", "isArchived"),
    }
    description: Optional[str] = field(default=None, metadata={"description": "The asset description text."})
    properties: Optional[Dict[str, Any]] = field(default=None, metadata={'description': 'The asset property dictionary.'})  # fmt: skip
    is_anonymous: Optional[bool] = field(default=None, metadata={'description': 'If the name version are system generated (anonymous registration).'})  # fmt: skip
    is_archived: Optional[bool] = field(default=None, metadata={"description": "Is the asset archived?"})
    index_columns: Optional[List[AzureIndexColumn]] = field(default=None, metadata={'description': 'Specifies index columns'})  # fmt: skip
    stage: Optional[str] = field(default=None, metadata={"description": "Specifies the asset stage"})


@define(eq=False, slots=False)
class AzureJobService:
    kind: ClassVar[str] = "azure_job_service"
    mapping: ClassVar[Dict[str, Bender]] = {
        "endpoint": S("endpoint"),
        "error_message": S("errorMessage"),
        "job_service_type": S("jobServiceType"),
        "nodes": S("nodes", "nodesValueType"),
        "port": S("port"),
        "properties": S("properties"),
        "status": S("status"),
    }
    endpoint: Optional[str] = field(default=None, metadata={"description": "Url for endpoint."})
    error_message: Optional[str] = field(default=None, metadata={"description": "Any error in the service."})
    job_service_type: Optional[str] = field(default=None, metadata={"description": "Endpoint type."})
    nodes: Optional[str] = field(default=None, metadata={"description": "Abstract Nodes definition"})
    port: Optional[int] = field(default=None, metadata={"description": "Port for endpoint."})
    properties: Optional[Dict[str, Any]] = field(default=None, metadata={'description': 'Additional properties to set on the endpoint.'})  # fmt: skip
    status: Optional[str] = field(default=None, metadata={"description": "Status of endpoint."})


@define(eq=False, slots=False)
class AzureMachineLearningJob(BaseAIJob, MicrosoftResource, AzureProxyResource):
    kind: ClassVar[str] = "azure_machine_learning_job"
    _kind_display: ClassVar[str] = "Azure Machine Learning Job"
    _kind_service: ClassVar[Optional[str]] = service_name
    _kind_description: ClassVar[str] = "Azure Machine Learning Job is a task execution unit within Azure Machine Learning service. It encapsulates the code, data, and compute resources required to run a machine learning workflow. Jobs can perform various operations like data preparation, model training, and evaluation. They support different compute targets and can be monitored, managed, and tracked through the Azure ML platform."  # fmt: skip
    _docs_url: ClassVar[str] = "https://learn.microsoft.com/en-us/azure/machine-learning/concept-ml-job"
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "job", "group": "ai"}
    # Collected via AzureMachineLearningWorkspace()
    _reference_kinds: ClassVar[ModelReference] = {
        "predecessors": {
            "default": [
                "azure_machine_learning_compute",
                "azure_machine_learning_workspace_component_version",
                "azure_machine_learning_registry_component_version",
            ]
        },
    }
    mapping: ClassVar[Dict[str, Bender]] = AzureProxyResource.mapping | {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "ctime": S("systemData", "createdAt"),
        "mtime": S("systemData", "lastModifiedAt"),
        "component_id": S("properties", "componentId"),
        "compute_id": S("properties", "computeId"),
        "display_name": S("properties", "displayName"),
        "experiment_name": S("properties", "experimentName"),
        "identity_type": S("properties", "identity", "identityType"),
        "is_archived": S("properties", "isArchived"),
        "job_type": S("properties", "jobType"),
        "notification_setting": S("properties", "notificationSetting") >> Bend(AzureNotificationSetting.mapping),
        "services": S("properties", "services"),
        "status": S("properties", "status") >> MapEnum(AZURE_ML_JOB_STATUS_MAPPING, AIJobStatus.UNKNOWN),
        "description": S("properties", "description"),
        "properties": S("properties", "properties"),
    }
    description: Optional[str] = field(default=None, metadata={"description": "The asset description text."})
    properties: Optional[Dict[str, Any]] = field(default=None, metadata={'description': 'The asset property dictionary.'})  # fmt: skip
    component_id: Optional[str] = field(default=None, metadata={'description': 'ARM resource ID of the component resource.'})  # fmt: skip
    compute_id: Optional[str] = field(default=None, metadata={'description': 'ARM resource ID of the compute resource.'})  # fmt: skip
    display_name: Optional[str] = field(default=None, metadata={"description": "Display name of job."})
    experiment_name: Optional[str] = field(default=None, metadata={'description': 'The name of the experiment the job belongs to. If not set, the job is placed in the Default experiment.'})  # fmt: skip
    identity_type: Optional[str] = field(default=None, metadata={'description': 'Base definition for identity configuration.'})  # fmt: skip
    is_archived: Optional[bool] = field(default=None, metadata={"description": "Is the asset archived?"})
    job_type: Optional[str] = field(default=None, metadata={"description": "Enum to determine the type of job."})
    notification_setting: Optional[AzureNotificationSetting] = field(default=None, metadata={'description': 'Configuration for notification.'})  # fmt: skip
    services: Optional[Dict[str, AzureJobService]] = field(default=None, metadata={'description': 'List of JobEndpoints. For local jobs, a job endpoint will have an endpoint value of FileStreamObject.'})  # fmt: skip

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if compute_id := self.compute_id:
            builder.add_edge(self, clazz=AzureMachineLearningCompute, reverse=True, id=compute_id)
        if component_id := self.component_id:
            builder.add_edge(
                self,
                clazz=(AzureMachineLearningWorkspaceComponentVersion, AzureMachineLearningRegistryComponentVersion),
                reverse=True,
                id=component_id,
            )


@define(eq=False, slots=False)
class AzureLabelClass:
    kind: ClassVar[str] = "azure_label_class"
    mapping: ClassVar[Dict[str, Bender]] = {"display_name": S("displayName"), "subclasses": S("subclasses")}
    display_name: Optional[str] = field(default=None, metadata={"description": "Display name of the label class."})
    subclasses: Optional[Dict[str, Any]] = field(default=None, metadata={'description': 'Dictionary of subclasses of the label class.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureLabelCategory:
    kind: ClassVar[str] = "azure_label_category"
    mapping: ClassVar[Dict[str, Bender]] = {
        "allow_multi_select": S("allowMultiSelect"),
        "classes": S("classes"),
        "display_name": S("displayName"),
    }
    allow_multi_select: Optional[bool] = field(default=None, metadata={'description': 'Indicates whether it is allowed to select multiple classes in this category.'})  # fmt: skip
    classes: Optional[Dict[str, AzureLabelClass]] = field(default=None, metadata={'description': 'Dictionary of label classes in this category.'})  # fmt: skip
    display_name: Optional[str] = field(default=None, metadata={"description": "Display name of the label category."})


@define(eq=False, slots=False)
class AzureLabelingDatasetConfiguration:
    kind: ClassVar[str] = "azure_labeling_dataset_configuration"
    mapping: ClassVar[Dict[str, Bender]] = {
        "asset_name": S("assetName"),
        "dataset_version": S("datasetVersion"),
        "enable_incremental_dataset_refresh": S("enableIncrementalDatasetRefresh"),
    }
    asset_name: Optional[str] = field(default=None, metadata={'description': 'Name of the data asset to perform labeling.'})  # fmt: skip
    dataset_version: Optional[str] = field(default=None, metadata={"description": "AML dataset version."})
    enable_incremental_dataset_refresh: Optional[bool] = field(default=None, metadata={'description': 'Indicates whether to enable incremental dataset refresh.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureComputeBinding:
    kind: ClassVar[str] = "azure_compute_binding"
    mapping: ClassVar[Dict[str, Bender]] = {"compute_id": S("computeId"), "node_count": S("nodeCount")}
    compute_id: Optional[str] = field(default=None, metadata={"description": "ID of the compute resource."})
    node_count: Optional[int] = field(default=None, metadata={"description": "Number of nodes."})


@define(eq=False, slots=False)
class AzureMLAssistConfiguration:
    kind: ClassVar[str] = "azure_ml_assist_configuration"
    mapping: ClassVar[Dict[str, Bender]] = {
        "inferencing_compute_binding": S("inferencingComputeBinding") >> Bend(AzureComputeBinding.mapping),
        "ml_assist_enabled": S("mlAssistEnabled"),
        "model_name_prefix": S("modelNamePrefix"),
        "prelabel_accuracy_threshold": S("prelabelAccuracyThreshold"),
        "training_compute_binding": S("trainingComputeBinding") >> Bend(AzureComputeBinding.mapping),
    }
    inferencing_compute_binding: Optional[AzureComputeBinding] = field(default=None, metadata={'description': 'Compute binding definition.'})  # fmt: skip
    ml_assist_enabled: Optional[bool] = field(default=None, metadata={'description': 'Indicates whether MLAssist feature is enabled.'})  # fmt: skip
    model_name_prefix: Optional[str] = field(default=None, metadata={'description': 'Name prefix to use for machine learning model. For each iteration modelName will be appended with iteration e.g.{modelName}_{i}.'})  # fmt: skip
    prelabel_accuracy_threshold: Optional[float] = field(default=None, metadata={'description': 'Prelabel accuracy threshold used in MLAssist feature.'})  # fmt: skip
    training_compute_binding: Optional[AzureComputeBinding] = field(default=None, metadata={'description': 'Compute binding definition.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureLabelingJobMediaProperties:
    kind: ClassVar[str] = "azure_labeling_job_media_properties"
    mapping: ClassVar[Dict[str, Bender]] = {"media_type": S("mediaType")}
    media_type: Optional[str] = field(default=None, metadata={"description": "Media type of data asset."})


@define(eq=False, slots=False)
class AzureAnnotationType:
    kind: ClassVar[str] = "azure_annotation_type"
    mapping: ClassVar[Dict[str, Bender]] = {"annotation_type": S("annotationType")}
    annotation_type: Optional[str] = field(default=None, metadata={'description': 'Annotation type of image labeling tasks.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureLabelingJobImageProperties(AzureLabelingJobMediaProperties, AzureAnnotationType):
    kind: ClassVar[str] = "azure_labeling_job_image_properties"
    mapping: ClassVar[Dict[str, Bender]] = AzureLabelingJobMediaProperties.mapping | AzureAnnotationType.mapping | {}


@define(eq=False, slots=False)
class AzureProgressMetrics:
    kind: ClassVar[str] = "azure_progress_metrics"
    mapping: ClassVar[Dict[str, Bender]] = {
        "completed_datapoint_count": S("completedDatapointCount"),
        "incremental_dataset_last_refresh_time": S("incrementalDatasetLastRefreshTime"),
        "skipped_datapoint_count": S("skippedDatapointCount"),
        "total_datapoint_count": S("totalDatapointCount"),
    }
    completed_datapoint_count: Optional[int] = field(default=None, metadata={'description': 'The completed datapoint count.'})  # fmt: skip
    incremental_dataset_last_refresh_time: Optional[datetime] = field(default=None, metadata={'description': 'The time of last successful incremental dataset refresh in UTC.'})  # fmt: skip
    skipped_datapoint_count: Optional[int] = field(default=None, metadata={'description': 'The skipped datapoint count.'})  # fmt: skip
    total_datapoint_count: Optional[int] = field(default=None, metadata={"description": "The total datapoint count."})


@define(eq=False, slots=False)
class AzureStatusMessage:
    kind: ClassVar[str] = "azure_status_message"
    mapping: ClassVar[Dict[str, Bender]] = {
        "code": S("code"),
        "created_time_utc": S("createdTimeUtc"),
        "level": S("level"),
        "message": S("message"),
    }
    code: Optional[str] = field(default=None, metadata={"description": "Service-defined message code."})
    created_time_utc: Optional[datetime] = field(default=None, metadata={'description': 'Time in UTC at which the message was created.'})  # fmt: skip
    level: Optional[str] = field(default=None, metadata={"description": "Severity level of the status message."})
    message: Optional[str] = field(default=None, metadata={'description': 'A human-readable representation of the message code.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureMachineLearningLabelingJob(BaseAIJob, MicrosoftResource):
    kind: ClassVar[str] = "azure_machine_learning_labeling_job"
    _kind_display: ClassVar[str] = "Azure Machine Learning Labeling Job"
    _kind_service: ClassVar[Optional[str]] = service_name
    _kind_description: ClassVar[str] = "Azure Machine Learning Labeling Job is a feature that helps users annotate data for machine learning projects. It provides tools for tagging images, text, or other data types, and supports collaboration among team members. The job organizes tasks, tracks progress, and manages the labeling workflow to prepare datasets for model training and evaluation."  # fmt: skip
    _docs_url: ClassVar[str] = (
        "https://learn.microsoft.com/en-us/azure/machine-learning/how-to-create-labeling-projects"
    )
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "job", "group": "ai"}
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "ctime": S("systemData", "createdTimeUtc"),
        "mtime": S("systemData", "lastModifiedAt"),
        "created_time_utc": S("properties", "createdTimeUtc"),
        "dataset_configuration": S("properties", "datasetConfiguration")
        >> Bend(AzureLabelingDatasetConfiguration.mapping),
        "job_instructions": S("properties", "jobInstructions", "uri"),
        "label_categories": S("properties", "labelCategories"),
        "labeling_job_media_properties": S("properties", "labelingJobMediaProperties")
        >> Bend(AzureLabelingJobImageProperties.mapping),
        "ml_assist_configuration": S("properties", "mlAssistConfiguration") >> Bend(AzureMLAssistConfiguration.mapping),
        "progress_metrics": S("properties", "progressMetrics") >> Bend(AzureProgressMetrics.mapping),
        "job_project_id": S("properties", "projectId"),
        "properties": S("properties", "properties"),
        "status": S("properties", "status") >> MapEnum(AZURE_ML_JOB_STATUS_MAPPING, AIJobStatus.UNKNOWN),
        "status_messages": S("properties", "statusMessages") >> ForallBend(AzureStatusMessage.mapping),
        "system_data": S("systemData") >> Bend(AzureSystemData.mapping),
    }
    created_time_utc: Optional[datetime] = field(default=None, metadata={'description': 'Created time of the job in UTC timezone.'})  # fmt: skip
    dataset_configuration: Optional[AzureLabelingDatasetConfiguration] = field(default=None, metadata={'description': 'Represents configuration of dataset used in a labeling job.'})  # fmt: skip
    job_instructions: Optional[str] = field(default=None, metadata={"description": "Instructions for a labeling job."})
    label_categories: Optional[Dict[str, AzureLabelCategory]] = field(default=None, metadata={'description': 'Label categories of the job.'})  # fmt: skip
    labeling_job_media_properties: Optional[AzureLabelingJobImageProperties] = field(default=None, metadata={'description': ''})  # fmt: skip
    ml_assist_configuration: Optional[AzureMLAssistConfiguration] = field(default=None, metadata={'description': 'Represents configuration for machine learning assisted features in a labeling job.'})  # fmt: skip
    progress_metrics: Optional[AzureProgressMetrics] = field(default=None, metadata={'description': 'Progress metrics for a labeling job.'})  # fmt: skip
    job_project_id: Optional[str] = field(default=None, metadata={'description': 'Internal id of the job(Previously called project).'})  # fmt: skip
    properties: Optional[Dict[str, Any]] = field(default=None, metadata={'description': 'The job property dictionary. Properties can be added, but not removed or altered.'})  # fmt: skip
    status_messages: Optional[List[AzureStatusMessage]] = field(default=None, metadata={'description': 'Status messages of the job.'})  # fmt: skip
    system_data: Optional[AzureSystemData] = field(default=None, metadata={'description': 'Metadata pertaining to creation and last modification of the resource.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureMachineLearningModelContainerBase(AzureProxyResource):
    kind: ClassVar[str] = "azure_machine_learning_model_container_base"
    _kind_display: ClassVar[str] = "Azure Machine Learning Model Container Base"
    _kind_service: ClassVar[Optional[str]] = service_name
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "container", "group": "ai"}
    # Collected via AzureMachineLearningWorkspace()
    mapping: ClassVar[Dict[str, Bender]] = AzureProxyResource.mapping | {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "properties": S("properties", "properties"),
        "description": S("properties", "description"),
        "is_archived": S("properties", "isArchived", default=False),
        "latest_version": S("properties", "latestVersion"),
        "next_version": S("properties", "nextVersion"),
        "provisioning_state": S("properties", "provisioningState"),
    }
    description: Optional[str] = field(default=None, metadata={"description": "The asset description text."})
    is_archived: Optional[bool] = field(default=False, metadata={"description": "Is the asset archived?"})
    latest_version: Optional[str] = field(
        default=None, metadata={"description": "The latest version inside this container."}
    )
    next_version: Optional[str] = field(default=None, metadata={"description": "The next auto incremental version."})
    properties: Optional[Dict[str, Any]] = field(default=None, metadata={"description": ""})


@define(eq=False, slots=False)
class AzureMachineLearningWorkspaceModelContainer(
    BaseAIModel, AzureMachineLearningModelContainerBase, MicrosoftResource
):
    # Defined to split registry and workspace resource

    kind: ClassVar[str] = "azure_machine_learning_workspace_model_container"
    _kind_display: ClassVar[str] = "Azure Machine Learning Workspace Model Container"
    _kind_description: ClassVar[str] = "Azure Machine Learning Workspace Model Container is a component within Azure Machine Learning that stores and manages machine learning models. It provides a centralized location for data scientists and developers to register, version, and deploy models. The container supports various model formats and integrates with Azure Machine Learning pipelines for model training, evaluation, and deployment processes."  # fmt: skip
    _docs_url: ClassVar[str] = (
        "https://learn.microsoft.com/en-us/azure/machine-learning/concept-model-management-and-deployment"
    )
    _reference_kinds: ClassVar[ModelReference] = {
        "successors": {
            "default": [
                "azure_machine_learning_workspace_model_version",
            ]
        },
    }

    def post_process(self, graph_builder: GraphBuilder, source: Json) -> None:
        if resource_id := self.id:

            def collect_versions() -> None:
                api_spec = AzureResourceSpec(
                    service="machinelearningservices",
                    version="2024-04-01",
                    path=f"{resource_id}/versions",
                    path_parameters=[],
                    query_parameters=["api-version"],
                    access_path="value",
                    expect_array=True,
                )
                items = graph_builder.client.list(api_spec)
                if not items:
                    return
                collected = AzureMachineLearningWorkspaceModelVersion.collect(items, graph_builder)
                for resource in collected:
                    graph_builder.add_edge(self, node=resource)

            graph_builder.submit_work(service_name, collect_versions)


@define(eq=False, slots=False)
class AzureMachineLearningRegistryModelContainer(
    BaseAIModel, AzureMachineLearningModelContainerBase, MicrosoftResource
):
    # Defined to split registry and workspace resource

    kind: ClassVar[str] = "azure_machine_learning_registry_model_container"
    _kind_display: ClassVar[str] = "Azure Machine Learning Registry Model Container"
    _kind_description: ClassVar[str] = "Azure Machine Learning Registry Model Container is a component of Azure Machine Learning that stores and manages machine learning models. It provides version control, metadata tracking, and deployment capabilities for models. Users can register, retrieve, and share models within their organization, facilitating collaboration and reproducibility in machine learning projects."  # fmt: skip
    _docs_url: ClassVar[str] = (
        "https://learn.microsoft.com/en-us/azure/machine-learning/concept-model-management-and-deployment"
    )
    _reference_kinds: ClassVar[ModelReference] = {
        "successors": {
            "default": [
                "azure_machine_learning_registry_model_version",
            ]
        },
    }

    def post_process(self, graph_builder: GraphBuilder, source: Json) -> None:
        if resource_id := self.id:

            def collect_versions() -> None:
                api_spec = AzureResourceSpec(
                    service="machinelearningservices",
                    version="2024-04-01",
                    path=f"{resource_id}/versions",
                    path_parameters=[],
                    query_parameters=["api-version"],
                    access_path="value",
                    expect_array=True,
                )
                items = graph_builder.client.list(api_spec)
                if not items:
                    return
                collected = AzureMachineLearningRegistryModelVersion.collect(items, graph_builder)
                for resource in collected:
                    graph_builder.add_edge(self, node=resource)

            graph_builder.submit_work(service_name, collect_versions)


@define(eq=False, slots=False)
class AzureFlavorData:
    kind: ClassVar[str] = "azure_flavor_data"
    mapping: ClassVar[Dict[str, Bender]] = {"data": S("data")}
    data: Optional[Dict[str, str]] = field(default=None, metadata={"description": "Model flavor-specific data."})


@define(eq=False, slots=False)
class AzureMachineLearningModelVersionBase(CheckVersionIsArchived, AzureProxyResource):
    kind: ClassVar[str] = "azure_machine_learning_base_model_version"
    _kind_display: ClassVar[str] = "Azure Machine Learning Base Model Version"
    _kind_service: ClassVar[Optional[str]] = service_name
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "version", "group": "ai"}
    # Collected via AzureMachineLearningModelContainerBase()
    mapping: ClassVar[Dict[str, Bender]] = AzureProxyResource.mapping | {
        "id": S("id"),
        "name": S("name"),
        "ctime": S("systemData", "createdAt"),
        "mtime": S("systemData", "lastModifiedAt"),
        "flavors": S("properties", "flavors"),
        "job_name": S("properties", "jobName"),
        "model_type": S("properties", "modelType"),
        "model_uri": S("properties", "modelUri"),
        "stage": S("properties", "stage"),
        "tags": S("properties", "tags", default={}),
        "code_uri": S("properties", "codeUri"),
        "provisioning_state": S("properties", "provisioningState"),
        "description": S("properties", "description"),
        "properties": S("properties", "properties"),
        "is_anonymous": S("properties", "isAnonymous"),
        "is_archived": S("properties", "isArchived"),
    }
    description: Optional[str] = field(default=None, metadata={"description": "The asset description text."})
    properties: Optional[Dict[str, Any]] = field(default=None, metadata={'description': 'The asset property dictionary.'})  # fmt: skip
    is_anonymous: Optional[bool] = field(default=None, metadata={'description': 'If the name version are system generated (anonymous registration).'})  # fmt: skip
    is_archived: Optional[bool] = field(default=None, metadata={"description": "Is the asset archived?"})
    flavors: Optional[Dict[str, AzureFlavorData]] = field(default=None, metadata={'description': 'Mapping of model flavors to their properties.'})  # fmt: skip
    job_name: Optional[str] = field(default=None, metadata={'description': 'Name of the training job which produced this model'})  # fmt: skip
    model_type: Optional[str] = field(default=None, metadata={'description': 'The storage format for this entity. Used for NCD.'})  # fmt: skip
    model_uri: Optional[str] = field(default=None, metadata={"description": "The URI path to the model contents."})
    stage: Optional[str] = field(default=None, metadata={'description': 'Stage in the model lifecycle assigned to this model'})  # fmt: skip


@define(eq=False, slots=False)
class AzureMachineLearningWorkspaceModelVersion(AzureMachineLearningModelVersionBase, MicrosoftResource):
    # Defined to split registry and workspace resource

    kind: ClassVar[str] = "azure_machine_learning_workspace_model_version"
    _kind_display: ClassVar[str] = "Azure Machine Learning Workspace Model Version"
    _kind_description: ClassVar[str] = "Azure Machine Learning Workspace Model Version represents a specific iteration of a machine learning model within an Azure ML workspace. It captures the model's artifacts, code, and metadata at a particular point in time. This versioning system facilitates tracking, comparing, and managing different iterations of models throughout their lifecycle, supporting reproducibility and collaboration in machine learning projects."  # fmt: skip
    _docs_url: ClassVar[str] = (
        "https://learn.microsoft.com/en-us/azure/machine-learning/concept-model-management-and-deployment"
    )


@define(eq=False, slots=False)
class AzureMachineLearningRegistryModelVersion(AzureMachineLearningModelVersionBase, MicrosoftResource):
    # Defined to split registry and workspace resource

    kind: ClassVar[str] = "azure_machine_learning_registry_model_version"
    _kind_display: ClassVar[str] = "Azure Machine Learning Registry Model Version"
    _kind_description: ClassVar[str] = "Azure Machine Learning Registry Model Version is a component that stores and manages versions of machine learning models in Azure. It tracks model metadata, artifacts, and performance metrics across iterations. Users can register, retrieve, and deploy specific model versions, facilitating version control, reproducibility, and collaboration in machine learning workflows."  # fmt: skip
    _docs_url: ClassVar[str] = (
        "https://learn.microsoft.com/en-us/azure/machine-learning/concept-model-management-and-deployment#registering-and-versioning-models"
    )


@define(eq=False, slots=False)
class AzureMachineLearningOnlineEndpoint(MicrosoftResource, AzureTrackedResource):
    kind: ClassVar[str] = "azure_machine_learning_online_endpoint"
    _kind_display: ClassVar[str] = "Azure Machine Learning Online Endpoint"
    _kind_service: ClassVar[Optional[str]] = service_name
    _kind_description: ClassVar[str] = "Azure Machine Learning Online Endpoint is a cloud-based service for deploying and hosting machine learning models. It provides a secure, managed environment for serving real-time predictions. Users can deploy models, manage versions, and scale compute resources as needed. The endpoint handles incoming requests, processes data, and returns predictions using the deployed model."  # fmt: skip
    _docs_url: ClassVar[str] = "https://learn.microsoft.com/en-us/azure/machine-learning/concept-endpoints"
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "endpoint", "group": "ai"}
    # Collected via AzureMachineLearningWorkspace()
    _reference_kinds: ClassVar[ModelReference] = {
        "predecessors": {
            "default": [
                "azure_machine_learning_compute",
            ]
        },
        "successors": {"default": [MicrosoftGraphServicePrincipal.kind, MicrosoftGraphUser.kind]},
    }
    mapping: ClassVar[Dict[str, Bender]] = AzureTrackedResource.mapping | {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "ctime": S("systemData", "createdAt"),
        "mtime": S("systemData", "lastModifiedAt"),
        "compute": S("properties", "compute"),
        "identity": S("identity") >> Bend(AzureManagedServiceIdentity.mapping),
        "azure_kind": S("kind"),
        "mirror_traffic": S("properties", "mirrorTraffic"),
        "provisioning_state": S("properties", "provisioningState"),
        "public_network_access": S("properties", "publicNetworkAccess"),
        "azure_sku": S("sku") >> Bend(AzureSku.mapping),
        "traffic": S("properties", "traffic"),
        "auth_mode": S("properties", "authMode"),
        "description": S("properties", "description"),
        "keys": S("keys") >> Bend(AzureEndpointAuthKeys.mapping),
        "properties": S("properties", "properties"),
        "scoring_uri": S("properties", "scoringUri"),
        "swagger_uri": S("properties", "swaggerUri"),
    }
    compute: Optional[str] = field(default=None, metadata={'description': 'ARM resource ID of the compute if it exists. optional'})  # fmt: skip
    identity: Optional[AzureManagedServiceIdentity] = field(default=None, metadata={'description': 'Managed service identity (system assigned and/or user assigned identities)'})  # fmt: skip
    azure_kind: Optional[str] = field(default=None, metadata={'description': 'Metadata used by portal/tooling/etc to render different UX experiences for resources of the same type.'})  # fmt: skip
    mirror_traffic: Optional[Dict[str, int]] = field(default=None, metadata={'description': 'Percentage of traffic to be mirrored to each deployment without using returned scoring. Traffic values need to sum to utmost 50.'})  # fmt: skip
    public_network_access: Optional[str] = field(default=None, metadata={'description': 'Enum to determine whether PublicNetworkAccess is Enabled or Disabled.'})  # fmt: skip
    azure_sku: Optional[AzureSku] = field(default=None, metadata={'description': 'The resource model definition representing SKU'})  # fmt: skip
    traffic: Optional[Dict[str, int]] = field(default=None, metadata={'description': 'Percentage of traffic from endpoint to divert to each deployment. Traffic values need to sum to 100.'})  # fmt: skip

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if compute_id := self.compute:
            builder.add_edge(self, reverse=True, clazz=AzureMachineLearningCompute, id=compute_id)

        # principal: collected via ms graph -> create a deferred edge
        if ai := self.identity:
            if pid := ai.principal_id:
                builder.add_deferred_edge(
                    from_node=self,
                    to_node=BySearchCriteria(f'is({MicrosoftGraphServicePrincipal.kind}) and reported.id=="{pid}"'),
                )
            if uai := ai.user_assigned_identities:
                for _, identity_info in uai.items():
                    if identity_info and identity_info.principal_id:
                        builder.add_deferred_edge(
                            from_node=self,
                            to_node=BySearchCriteria(
                                f'is({MicrosoftGraphUser.kind}) and reported.id=="{identity_info.principal_id}"'
                            ),
                        )


@define(eq=False, slots=False)
class AzureMachineLearningPrivateEndpointConnection(MicrosoftResource):
    kind: ClassVar[str] = "azure_machine_learning_private_endpoint_connection"
    _kind_display: ClassVar[str] = "Azure Machine Learning Private Endpoint Connection"
    _kind_service: ClassVar[Optional[str]] = service_name
    _kind_description: ClassVar[str] = "Azure Machine Learning Private Endpoint Connection is a network interface that securely connects Azure Machine Learning workspaces to virtual networks. It uses Azure Private Link to establish a private connection, restricting data access to authorized resources within the virtual network and preventing exposure to the public internet, enhancing security and compliance for machine learning workflows."  # fmt: skip
    _docs_url: ClassVar[str] = "https://learn.microsoft.com/en-us/azure/machine-learning/how-to-configure-private-link"
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "connection", "group": "ai"}
    # Collected via AzureMachineLearningWorkspace()
    _reference_kinds: ClassVar[ModelReference] = {
        "successors": {"default": [MicrosoftGraphServicePrincipal.kind, MicrosoftGraphUser.kind]},
    }
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "identity": S("identity") >> Bend(AzureManagedServiceIdentity.mapping),
        "location": S("location"),
        "name": S("name"),
        "private_endpoint_id": S("properties", "privateEndpoint", "id"),
        "private_link_service_connection_state": S("properties", "privateLinkServiceConnectionState")
        >> Bend(AzurePrivateLinkServiceConnectionState.mapping),
        "provisioning_state": S("properties", "provisioningState"),
        "azure_sku": S("sku") >> Bend(AzureSku.mapping),
        "system_data": S("systemData") >> Bend(AzureSystemData.mapping),
        "tags": S("tags"),
        "type": S("type"),
    }
    identity: Optional[AzureManagedServiceIdentity] = field(default=None, metadata={'description': 'Managed service identity (system assigned and/or user assigned identities)'})  # fmt: skip
    location: Optional[str] = field(default=None, metadata={"description": "Specifies the location of the resource."})
    private_endpoint_id: Optional[str] = field(default=None, metadata={"description": "The Private Endpoint resource."})
    private_link_service_connection_state: Optional[AzurePrivateLinkServiceConnectionState] = field(default=None, metadata={'description': 'A collection of information about the state of the connection between service consumer and provider.'})  # fmt: skip
    azure_sku: Optional[AzureSku] = field(default=None, metadata={'description': 'The resource model definition representing SKU'})  # fmt: skip
    system_data: Optional[AzureSystemData] = field(default=None, metadata={'description': 'Metadata pertaining to creation and last modification of the resource.'})  # fmt: skip
    type: Optional[str] = field(default=None, metadata={'description': 'The type of the resource. E.g. Microsoft.Compute/virtualMachines or Microsoft.Storage/storageAccounts '})  # fmt: skip

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        # principal: collected via ms graph -> create a deferred edge
        if ai := self.identity:
            if pid := ai.principal_id:
                builder.add_deferred_edge(
                    from_node=self,
                    to_node=BySearchCriteria(f'is({MicrosoftGraphServicePrincipal.kind}) and reported.id=="{pid}"'),
                )
            if uai := ai.user_assigned_identities:
                for _, identity_info in uai.items():
                    if identity_info and identity_info.principal_id:
                        builder.add_deferred_edge(
                            from_node=self,
                            to_node=BySearchCriteria(
                                f'is({MicrosoftGraphUser.kind}) and reported.id=="{identity_info.principal_id}"'
                            ),
                        )


@define(eq=False, slots=False)
class AzureMachineLearningPrivateLink(MicrosoftResource):
    kind: ClassVar[str] = "azure_machine_learning_private_link"
    _kind_display: ClassVar[str] = "Azure Machine Learning Private Link"
    _kind_service: ClassVar[Optional[str]] = service_name
    _kind_description: ClassVar[str] = "Azure Machine Learning Private Link is a network security feature that provides private connectivity between Azure Machine Learning workspaces and other Azure resources. It creates a secure, private endpoint within a virtual network, restricting access to authorized networks and eliminating exposure to the public internet while maintaining full functionality of Azure Machine Learning services."  # fmt: skip
    _docs_url: ClassVar[str] = "https://learn.microsoft.com/en-us/azure/machine-learning/how-to-configure-private-link"
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "link", "group": "ai"}
    # Collected via AzureMachineLearningWorkspace()
    _reference_kinds: ClassVar[ModelReference] = {
        "successors": {"default": [MicrosoftGraphServicePrincipal.kind, MicrosoftGraphUser.kind]},
    }
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "ctime": S("systemData", "createdAt"),
        "mtime": S("systemData", "lastModifiedAt"),
        "link_group_id": S("properties", "groupId"),
        "identity": S("identity") >> Bend(AzureManagedServiceIdentity.mapping),
        "required_members": S("properties", "requiredMembers"),
        "required_zone_names": S("properties", "requiredZoneNames"),
        "azure_sku": S("sku") >> Bend(AzureSku.mapping),
        "system_data": S("systemData") >> Bend(AzureSystemData.mapping),
    }
    link_group_id: Optional[str] = field(default=None, metadata={"description": "The private link resource group id."})
    identity: Optional[AzureManagedServiceIdentity] = field(default=None, metadata={'description': 'Managed service identity (system assigned and/or user assigned identities)'})  # fmt: skip
    required_members: Optional[List[str]] = field(default=None, metadata={'description': 'The private link resource required member names.'})  # fmt: skip
    required_zone_names: Optional[List[str]] = field(default=None, metadata={'description': 'The private link resource Private link DNS zone name.'})  # fmt: skip
    azure_sku: Optional[AzureSku] = field(default=None, metadata={'description': 'The resource model definition representing SKU'})  # fmt: skip
    system_data: Optional[AzureSystemData] = field(default=None, metadata={'description': 'Metadata pertaining to creation and last modification of the resource.'})  # fmt: skip

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        # principal: collected via ms graph -> create a deferred edge
        if ai := self.identity:
            if pid := ai.principal_id:
                builder.add_deferred_edge(
                    from_node=self,
                    to_node=BySearchCriteria(f'is({MicrosoftGraphServicePrincipal.kind}) and reported.id=="{pid}"'),
                )
            if uai := ai.user_assigned_identities:
                for _, identity_info in uai.items():
                    if identity_info and identity_info.principal_id:
                        builder.add_deferred_edge(
                            from_node=self,
                            to_node=BySearchCriteria(
                                f'is({MicrosoftGraphUser.kind}) and reported.id=="{identity_info.principal_id}"'
                            ),
                        )


@define(eq=False, slots=False)
class AzureRegistryPrivateLinkServiceConnectionState:
    kind: ClassVar[str] = "azure_registry_private_link_service_connection_state"
    mapping: ClassVar[Dict[str, Bender]] = {
        "actions_required": S("actionsRequired"),
        "description": S("description"),
        "status": S("status"),
    }
    actions_required: Optional[str] = field(default=None, metadata={'description': 'Some RP chose None . Other RPs use this for region expansion.'})  # fmt: skip
    description: Optional[str] = field(default=None, metadata={'description': 'User-defined message that, per NRP doc, may be used for approval-related message.'})  # fmt: skip
    status: Optional[str] = field(default=None, metadata={'description': 'Connection status of the service consumer with the service provider'})  # fmt: skip


@define(eq=False, slots=False)
class AzureRegistryPrivateEndpointConnection:
    kind: ClassVar[str] = "azure_registry_private_endpoint_connection"
    mapping: ClassVar[Dict[str, Bender]] = {
        "group_ids": S("properties", "groupIds"),
        "id": S("id"),
        "location": S("location"),
        "private_endpoint": S("properties", "privateEndpoint", "subnetArmId"),
        "provisioning_state": S("properties", "provisioningState"),
        "registry_private_link_service_connection_state": S("properties", "registryPrivateLinkServiceConnectionState")
        >> Bend(AzureRegistryPrivateLinkServiceConnectionState.mapping),
    }
    group_ids: Optional[List[str]] = field(default=None, metadata={"description": "The group ids"})
    id: Optional[str] = field(default=None, metadata={'description': 'This is the private endpoint connection name created on SRP Full resource id: /subscriptions/{subId}/resourceGroups/{rgName}/providers/Microsoft.MachineLearningServices/{resourceType}/{resourceName}/registryPrivateEndpointConnections/{peConnectionName}'})  # fmt: skip
    location: Optional[str] = field(default=None, metadata={"description": "Same as workspace location."})
    private_endpoint: Optional[str] = field(default=None, metadata={'description': 'The PE network resource that is linked to this PE connection.'})  # fmt: skip
    provisioning_state: Optional[str] = field(default=None, metadata={'description': 'One of null, Succeeded , Provisioning , Failed . While not approved, it s null.'})  # fmt: skip
    registry_private_link_service_connection_state: Optional[AzureRegistryPrivateLinkServiceConnectionState] = field(default=None, metadata={'description': 'The connection state.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureSystemCreatedAcrAccount:
    kind: ClassVar[str] = "azure_system_created_acr_account"
    mapping: ClassVar[Dict[str, Bender]] = {
        "acr_account_name": S("acrAccountName"),
        "acr_account_sku": S("acrAccountSku"),
        "arm_resource_id": S("armResourceId", "resourceId"),
    }
    acr_account_name: Optional[str] = field(default=None, metadata={"description": "Name of the ACR account"})
    acr_account_sku: Optional[str] = field(default=None, metadata={"description": "SKU of the ACR account"})
    arm_resource_id: Optional[str] = field(default=None, metadata={"description": "ARM ResourceId of a resource"})


@define(eq=False, slots=False)
class AzureUserCreatedAcrAccount:
    kind: ClassVar[str] = "azure_user_created_acr_account"
    mapping: ClassVar[Dict[str, Bender]] = {"arm_resource_id": S("armResourceId", "resourceId")}
    arm_resource_id: Optional[str] = field(default=None, metadata={"description": "ARM ResourceId of a resource"})


@define(eq=False, slots=False)
class AzureAcrDetails:
    kind: ClassVar[str] = "azure_acr_details"
    mapping: ClassVar[Dict[str, Bender]] = {
        "system_created_acr_account": S("systemCreatedAcrAccount") >> Bend(AzureSystemCreatedAcrAccount.mapping),
        "user_created_acr_account": S("userCreatedAcrAccount") >> Bend(AzureUserCreatedAcrAccount.mapping),
    }
    system_created_acr_account: Optional[AzureSystemCreatedAcrAccount] = field(default=None, metadata={'description': ''})  # fmt: skip
    user_created_acr_account: Optional[AzureUserCreatedAcrAccount] = field(default=None, metadata={"description": ""})


@define(eq=False, slots=False)
class AzureSystemCreatedStorageAccount:
    kind: ClassVar[str] = "azure_system_created_storage_account"
    mapping: ClassVar[Dict[str, Bender]] = {
        "allow_blob_public_access": S("allowBlobPublicAccess"),
        "arm_resource_id": S("armResourceId", "resourceId"),
        "storage_account_hns_enabled": S("storageAccountHnsEnabled"),
        "storage_account_name": S("storageAccountName"),
        "storage_account_type": S("storageAccountType"),
    }
    allow_blob_public_access: Optional[bool] = field(default=None, metadata={'description': 'Public blob access allowed'})  # fmt: skip
    arm_resource_id: Optional[str] = field(default=None, metadata={"description": "ARM ResourceId of a resource"})
    storage_account_hns_enabled: Optional[bool] = field(default=None, metadata={'description': 'HNS enabled for storage account'})  # fmt: skip
    storage_account_name: Optional[str] = field(default=None, metadata={"description": "Name of the storage account"})
    storage_account_type: Optional[str] = field(default=None, metadata={'description': 'Allowed values: Standard_LRS , Standard_GRS , Standard_RAGRS , Standard_ZRS , Standard_GZRS , Standard_RAGZRS , Premium_LRS , Premium_ZRS '})  # fmt: skip


@define(eq=False, slots=False)
class AzureUserCreatedStorageAccount:
    kind: ClassVar[str] = "azure_user_created_storage_account"
    mapping: ClassVar[Dict[str, Bender]] = {"arm_resource_id": S("armResourceId", "resourceId")}
    arm_resource_id: Optional[str] = field(default=None, metadata={"description": "ARM ResourceId of a resource"})


@define(eq=False, slots=False)
class AzureStorageAccountDetails:
    kind: ClassVar[str] = "azure_storage_account_details"
    mapping: ClassVar[Dict[str, Bender]] = {
        "system_created_storage_account": S("systemCreatedStorageAccount")
        >> Bend(AzureSystemCreatedStorageAccount.mapping),
        "user_created_storage_account": S("userCreatedStorageAccount") >> Bend(AzureUserCreatedStorageAccount.mapping),
    }
    system_created_storage_account: Optional[AzureSystemCreatedStorageAccount] = field(default=None, metadata={'description': ''})  # fmt: skip
    user_created_storage_account: Optional[AzureUserCreatedStorageAccount] = field(default=None, metadata={'description': ''})  # fmt: skip


@define(eq=False, slots=False)
class AzureRegistryRegionArmDetails:
    kind: ClassVar[str] = "azure_registry_region_arm_details"
    mapping: ClassVar[Dict[str, Bender]] = {
        "acr_details": S("acrDetails") >> ForallBend(AzureAcrDetails.mapping),
        "location": S("location"),
        "storage_account_details": S("storageAccountDetails") >> ForallBend(AzureStorageAccountDetails.mapping),
    }
    acr_details: Optional[List[AzureAcrDetails]] = field(default=None, metadata={"description": "List of ACR accounts"})
    location: Optional[str] = field(default=None, metadata={"description": "The location where the registry exists"})
    storage_account_details: Optional[List[AzureStorageAccountDetails]] = field(default=None, metadata={'description': 'List of storage accounts'})  # fmt: skip


@define(eq=False, slots=False)
class AzureMachineLearningRegistry(MicrosoftResource, AzureTrackedResource):
    kind: ClassVar[str] = "azure_machine_learning_registry"
    _kind_display: ClassVar[str] = "Azure Machine Learning Registry"
    _kind_service: ClassVar[Optional[str]] = service_name
    _kind_description: ClassVar[str] = "Azure Machine Learning Registry is a centralized repository for storing and managing machine learning models, datasets, and components. It provides version control, collaboration features, and integration with Azure Machine Learning workflows. Users can publish, share, and deploy models across their organization, ensuring reproducibility and governance in machine learning projects."  # fmt: skip
    _docs_url: ClassVar[str] = "https://learn.microsoft.com/en-us/azure/machine-learning/how-to-use-model-registry"
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "resource", "group": "ai"}
    api_spec: ClassVar[AzureResourceSpec] = AzureResourceSpec(
        service="machinelearningservices",
        version="2024-04-01",
        path="/subscriptions/{subscriptionId}/providers/Microsoft.MachineLearningServices/registries",
        path_parameters=["subscriptionId"],
        query_parameters=["api-version"],
        access_path="value",
        expect_array=True,
    )
    _reference_kinds: ClassVar[ModelReference] = {
        "successors": {
            "default": [
                MicrosoftGraphServicePrincipal.kind,
                MicrosoftGraphUser.kind,
                "azure_machine_learning_registry_code_container",
                "azure_machine_learning_registry_component_container",
                "azure_machine_learning_registry_data_container",
                "azure_machine_learning_registry_environment_container",
                "azure_machine_learning_registry_model_container",
            ]
        },
    }
    mapping: ClassVar[Dict[str, Bender]] = AzureTrackedResource.mapping | {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "ctime": S("systemData", "createdAt"),
        "mtime": S("systemData", "lastModifiedAt"),
        "discovery_url": S("properties", "discoveryUrl"),
        "identity": S("identity") >> Bend(AzureManagedServiceIdentity.mapping),
        "intellectual_property_publisher": S("properties", "intellectualPropertyPublisher"),
        "azure_kind": S("kind"),
        "managed_resource_group": S("properties", "managedResourceGroup", "resourceId"),
        "ml_flow_registry_uri": S("properties", "mlFlowRegistryUri"),
        "public_network_access": S("properties", "publicNetworkAccess"),
        "region_details": S("properties", "regionDetails") >> ForallBend(AzureRegistryRegionArmDetails.mapping),
        "registry_private_endpoint_connections": S("properties", "registryPrivateEndpointConnections")
        >> ForallBend(AzureRegistryPrivateEndpointConnection.mapping),
        "azure_sku": S("sku") >> Bend(AzureSku.mapping),
    }
    discovery_url: Optional[str] = field(default=None, metadata={"description": "Discovery URL for the Registry"})
    identity: Optional[AzureManagedServiceIdentity] = field(default=None, metadata={'description': 'Managed service identity (system assigned and/or user assigned identities)'})  # fmt: skip
    intellectual_property_publisher: Optional[str] = field(default=None, metadata={'description': 'IntellectualPropertyPublisher for the registry'})  # fmt: skip
    azure_kind: Optional[str] = field(default=None, metadata={'description': 'Metadata used by portal/tooling/etc to render different UX experiences for resources of the same type.'})  # fmt: skip
    managed_resource_group: Optional[str] = field(default=None, metadata={'description': 'ARM ResourceId of a resource'})  # fmt: skip
    ml_flow_registry_uri: Optional[str] = field(default=None, metadata={'description': 'MLFlow Registry URI for the Registry'})  # fmt: skip
    public_network_access: Optional[str] = field(default=None, metadata={'description': 'Is the Registry accessible from the internet? Possible values: Enabled or Disabled '})  # fmt: skip
    region_details: Optional[List[AzureRegistryRegionArmDetails]] = field(default=None, metadata={'description': 'Details of each region the registry is in'})  # fmt: skip
    registry_private_endpoint_connections: Optional[List[AzureRegistryPrivateEndpointConnection]] = field(default=None, metadata={'description': 'Private endpoint connections info used for pending connections in private link portal'})  # fmt: skip
    azure_sku: Optional[AzureSku] = field(default=None, metadata={'description': 'The resource model definition representing SKU'})  # fmt: skip

    def _collect_items(
        self,
        graph_builder: GraphBuilder,
        registry_id: str,
        resource_type: str,
        class_instance: MicrosoftResource,
        expected_errors: Optional[Dict[str, Optional[str]]] = None,
    ) -> None:
        path = f"{registry_id}/{resource_type}"
        api_spec = AzureResourceSpec(
            service="machinelearningservices",
            version="2024-04-01",
            path=path,
            path_parameters=[],
            query_parameters=["api-version"],
            access_path="value",
            expect_array=True,
            expected_error_codes=expected_errors or {},
        )
        items = graph_builder.client.list(api_spec)
        if not items:
            return
        collected = class_instance.collect(items, graph_builder)
        for clazz in collected:
            graph_builder.add_edge(self, node=clazz)

    def post_process(self, graph_builder: GraphBuilder, source: Json) -> None:
        if registry_id := self.id:
            resources_to_collect = [
                ("codes", AzureMachineLearningRegistryCodeContainer, {"UserError": None}),
                ("components", AzureMachineLearningRegistryComponentContainer, None),
                ("data", AzureMachineLearningRegistryDataContainer, None),
                ("environments", AzureMachineLearningRegistryEnvironmentContainer, None),
                ("models", AzureMachineLearningRegistryModelContainer, None),
            ]

            for resource_type, resource_class, expected_errors in resources_to_collect:
                graph_builder.submit_work(
                    service_name,
                    self._collect_items,
                    graph_builder,
                    registry_id,
                    resource_type,
                    resource_class,
                    expected_errors,
                )

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        # principal: collected via ms graph -> create a deferred edge
        if ai := self.identity:
            if pid := ai.principal_id:
                builder.add_deferred_edge(
                    from_node=self,
                    to_node=BySearchCriteria(f'is({MicrosoftGraphServicePrincipal.kind}) and reported.id=="{pid}"'),
                )
            if uai := ai.user_assigned_identities:
                for _, identity_info in uai.items():
                    if identity_info and identity_info.principal_id:
                        builder.add_deferred_edge(
                            from_node=self,
                            to_node=BySearchCriteria(
                                f'is({MicrosoftGraphUser.kind}) and reported.id=="{identity_info.principal_id}"'
                            ),
                        )


@define(eq=False, slots=False)
class AzureMachineLearningQuota(MicrosoftResource, PhantomBaseResource):
    kind: ClassVar[str] = "azure_machine_learning_quota"
    _kind_display: ClassVar[str] = "Azure Machine Learning Quota"
    _kind_service: ClassVar[Optional[str]] = service_name
    _kind_description: ClassVar[str] = "Azure Machine Learning Quota sets limits on resources available for machine learning workloads in Azure. It controls the number of compute instances, cores, and other resources a user or organization can utilize. This quota system helps manage costs and resource allocation, ensuring fair distribution across users and preventing overuse of Azure's machine learning services."  # fmt: skip
    _docs_url: ClassVar[str] = "https://learn.microsoft.com/en-us/azure/machine-learning/how-to-manage-quotas"
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "queue", "group": "ai"}
    api_spec: ClassVar[AzureResourceSpec] = AzureResourceSpec(
        service="machinelearningservices",
        version="2024-04-01",
        path="/subscriptions/{subscriptionId}/providers/Microsoft.MachineLearningServices/locations/{location}/quotas",
        path_parameters=["subscriptionId", "location"],
        query_parameters=["api-version"],
        access_path="value",
        expect_array=True,
        expected_error_codes={"InternalServerError": None, "ServiceError": None},
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "name": S("name", "value"),
        "aml_workspace_location": S("amlWorkspaceLocation"),
        "limit": S("limit"),
        "unit": S("unit"),
    }
    aml_workspace_location: Optional[str] = field(default=None, metadata={'description': 'Region of the AML workspace in the id.'})  # fmt: skip
    limit: Optional[int] = field(default=None, metadata={'description': 'The maximum permitted quota of the resource.'})  # fmt: skip
    unit: Optional[str] = field(default=None, metadata={'description': 'An enum describing the unit of quota measurement.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureMachineLearningSchedule(MicrosoftResource, AzureProxyResource):
    kind: ClassVar[str] = "azure_machine_learning_schedule"
    _kind_display: ClassVar[str] = "Azure Machine Learning Schedule"
    _kind_service: ClassVar[Optional[str]] = service_name
    _kind_description: ClassVar[str] = "Azure Machine Learning Schedule is a feature within Azure Machine Learning that automates and manages the execution of machine learning workflows. It enables users to set up recurring or one-time runs of their ML pipelines, experiments, or scripts. This tool helps coordinate tasks, handle dependencies, and optimize resource allocation for machine learning processes in Azure."  # fmt: skip
    _docs_url: ClassVar[str] = (
        "https://learn.microsoft.com/en-us/azure/machine-learning/concept-endpoints-online#schedule"
    )
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "config", "group": "ai"}
    # Collected via AzureMachineLearningWorkspace()
    mapping: ClassVar[Dict[str, Bender]] = AzureProxyResource.mapping | {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "ctime": S("systemData", "createdAt"),
        "mtime": S("systemData", "lastModifiedAt"),
        "action": S("properties", "action", "actionType"),
        "display_name": S("properties", "displayName"),
        "is_enabled": S("properties", "isEnabled"),
        "provisioning_state": S("properties", "provisioningState"),
        "trigger": S("properties", "trigger") >> Bend(AzureTriggerBase.mapping),
        "description": S("properties", "description"),
        "properties": S("properties", "properties"),
    }
    description: Optional[str] = field(default=None, metadata={"description": "The asset description text."})
    properties: Optional[Dict[str, Any]] = field(default=None, metadata={'description': 'The asset property dictionary.'})  # fmt: skip
    action: Optional[str] = field(default=None, metadata={"description": ""})
    display_name: Optional[str] = field(default=None, metadata={"description": "Display name of schedule."})
    is_enabled: Optional[bool] = field(default=None, metadata={"description": "Is the schedule enabled?"})
    trigger: Optional[AzureTriggerBase] = field(default=None, metadata={"description": ""})


@define(eq=False, slots=False)
class AzureServerlessInferenceEndpoint:
    kind: ClassVar[str] = "azure_serverless_inference_endpoint"
    mapping: ClassVar[Dict[str, Bender]] = {"headers": S("headers"), "uri": S("uri")}
    headers: Optional[Dict[str, str]] = field(default=None, metadata={'description': 'Specifies any required headers to target this serverless endpoint.'})  # fmt: skip
    uri: Optional[str] = field(default=None, metadata={'description': '[Required] The inference uri to target when making requests against the Serverless Endpoint.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureMachineLearningServerlessEndpoint(MicrosoftResource, AzureTrackedResource):
    kind: ClassVar[str] = "azure_machine_learning_serverless_endpoint"
    _kind_display: ClassVar[str] = "Azure Machine Learning Serverless Endpoint"
    _kind_service: ClassVar[Optional[str]] = service_name
    _kind_description: ClassVar[str] = "Azure Machine Learning Serverless Endpoint is a deployment option for machine learning models in Azure. It provides on-demand compute resources for model inference without the need to manage infrastructure. Users can deploy models, send requests, and receive predictions while paying only for the compute time used during inference operations."  # fmt: skip
    _docs_url: ClassVar[str] = (
        "https://learn.microsoft.com/en-us/azure/machine-learning/how-to-use-managed-online-endpoint-serverless"
    )
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "endpoint", "group": "ai"}
    # Collected via AzureMachineLearningWorkspace()
    _reference_kinds: ClassVar[ModelReference] = {
        "successors": {
            "default": [
                "azure_machine_learning_workspace_model_version",
                "azure_machine_learning_registry_model_version",
                MicrosoftGraphServicePrincipal.kind,
                MicrosoftGraphUser.kind,
            ]
        },
    }
    mapping: ClassVar[Dict[str, Bender]] = AzureTrackedResource.mapping | {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "ctime": S("systemData", "createdAt"),
        "mtime": S("systemData", "lastModifiedAt"),
        "auth_mode": S("properties", "authMode"),
        "content_safety": S("properties", "contentSafety", "contentSafetyStatus"),
        "endpoint_state": S("properties", "endpointState"),
        "identity": S("identity") >> Bend(AzureManagedServiceIdentity.mapping),
        "inference_endpoint": S("properties", "inferenceEndpoint") >> Bend(AzureServerlessInferenceEndpoint.mapping),
        "azure_kind": S("kind"),
        "marketplace_subscription_id": S("properties", "marketplaceSubscriptionId"),
        "model_settings": S("properties", "modelSettings", "modelId"),
        "provisioning_state": S("properties", "provisioningState"),
        "azure_sku": S("sku") >> Bend(AzureSku.mapping),
    }
    auth_mode: Optional[str] = field(default=None, metadata={"description": ""})
    content_safety: Optional[str] = field(default=None, metadata={"description": ""})
    endpoint_state: Optional[str] = field(default=None, metadata={"description": "State of the Serverless Endpoint."})
    identity: Optional[AzureManagedServiceIdentity] = field(default=None, metadata={'description': 'Managed service identity (system assigned and/or user assigned identities)'})  # fmt: skip
    inference_endpoint: Optional[AzureServerlessInferenceEndpoint] = field(default=None, metadata={"description": ""})
    azure_kind: Optional[str] = field(default=None, metadata={'description': 'Metadata used by portal/tooling/etc to render different UX experiences for resources of the same type.'})  # fmt: skip
    marketplace_subscription_id: Optional[str] = field(default=None, metadata={'description': 'The MarketplaceSubscription Azure ID associated to this ServerlessEndpoint.'})  # fmt: skip
    model_settings: Optional[str] = field(default=None, metadata={"description": ""})
    azure_sku: Optional[AzureSku] = field(default=None, metadata={'description': 'The resource model definition representing SKU'})  # fmt: skip

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if model_id := self.model_settings:
            builder.add_edge(
                self,
                clazz=(AzureMachineLearningWorkspaceModelVersion, AzureMachineLearningRegistryModelVersion),
                id=model_id,
            )

        # principal: collected via ms graph -> create a deferred edge
        if ai := self.identity:
            if pid := ai.principal_id:
                builder.add_deferred_edge(
                    from_node=self,
                    to_node=BySearchCriteria(f'is({MicrosoftGraphServicePrincipal.kind}) and reported.id=="{pid}"'),
                )
            if uai := ai.user_assigned_identities:
                for _, identity_info in uai.items():
                    if identity_info and identity_info.principal_id:
                        builder.add_deferred_edge(
                            from_node=self,
                            to_node=BySearchCriteria(
                                f'is({MicrosoftGraphUser.kind}) and reported.id=="{identity_info.principal_id}"'
                            ),
                        )


@define(eq=False, slots=False)
class AzureMachineLearningUsage(MicrosoftResource, AzureBaseUsage):
    kind: ClassVar[str] = "azure_machine_learning_usage"
    _kind_display: ClassVar[str] = "Azure Machine Learning Usage"
    _kind_service: ClassVar[Optional[str]] = service_name
    _kind_description: ClassVar[str] = "Azure Machine Learning Usage refers to the utilization of Microsoft's cloud-based platform for developing, training, and deploying machine learning models. It provides tools and services for data preparation, model creation, and deployment across various environments. Users can build, test, and manage machine learning workflows while monitoring resource consumption and performance metrics."  # fmt: skip
    _docs_url: ClassVar[str] = "https://learn.microsoft.com/en-us/azure/machine-learning/concept-plan-manage-cost"
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "log", "group": "ai"}
    api_spec: ClassVar[AzureResourceSpec] = AzureResourceSpec(
        service="machinelearningservices",
        version="2024-04-01",
        path="/subscriptions/{subscriptionId}/providers/Microsoft.MachineLearningServices/locations/{location}/usages",
        path_parameters=["subscriptionId", "location"],
        query_parameters=["api-version"],
        access_path="value",
        expect_array=True,
        expected_error_codes={
            **AzureBaseUsage._expected_error_codes,
            "InternalServerError": None,
            "ServiceError": None,
        },
    )
    mapping: ClassVar[Dict[str, Bender]] = AzureBaseUsage.mapping | {
        "id": S("id"),
        "name": S("name", "value"),
        "aml_workspace_location": S("amlWorkspaceLocation"),
    }
    aml_workspace_location: Optional[str] = field(default=None, metadata={'description': 'Region of the AML workspace in the id.'})  # fmt: skip

    def _keys(self) -> Tuple[Any, ...]:
        return tuple(list(super()._keys()) + [self.name])


@define(eq=False, slots=False)
class AzureEstimatedVMPrice:
    kind: ClassVar[str] = "azure_estimated_vm_price"
    mapping: ClassVar[Dict[str, Bender]] = {
        "os_type": S("osType"),
        "retail_price": S("retailPrice"),
        "vm_tier": S("vmTier"),
    }
    os_type: Optional[str] = field(default=None, metadata={"description": "Operating system type used by the VM."})
    retail_price: Optional[float] = field(default=None, metadata={'description': 'The price charged for using the VM.'})  # fmt: skip
    vm_tier: Optional[str] = field(default=None, metadata={"description": "The type of the VM."})


@define(eq=False, slots=False)
class AzureEstimatedVMPrices:
    kind: ClassVar[str] = "azure_estimated_vm_prices"
    mapping: ClassVar[Dict[str, Bender]] = {
        "billing_currency": S("billingCurrency"),
        "unit_of_measure": S("unitOfMeasure"),
        "values": S("values") >> ForallBend(AzureEstimatedVMPrice.mapping),
    }
    billing_currency: Optional[str] = field(default=None, metadata={'description': 'Three lettered code specifying the currency of the VM price. Example: USD'})  # fmt: skip
    unit_of_measure: Optional[str] = field(default=None, metadata={'description': 'The unit of time measurement for the specified VM price. Example: OneHour'})  # fmt: skip
    values: Optional[List[AzureEstimatedVMPrice]] = field(default=None, metadata={'description': 'The list of estimated prices for using a VM of a particular OS type, tier, etc.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureMachineLearningVirtualMachineSize(MicrosoftResource, BaseInstanceType):
    kind: ClassVar[str] = "azure_machine_learning_virtual_machine_size"
    _kind_display: ClassVar[str] = "Azure Machine Learning Virtual Machine Size"
    _kind_service: ClassVar[Optional[str]] = service_name
    _kind_description: ClassVar[str] = "Azure Machine Learning Virtual Machine Size refers to the computational resources allocated to a virtual machine used for machine learning tasks in Azure. It determines the processing power, memory, and storage capacity available for training models, running experiments, and deploying solutions. Users can select from various sizes to match their specific machine learning workload requirements and budget constraints."  # fmt: skip
    _docs_url: ClassVar[str] = (
        "https://learn.microsoft.com/en-us/azure/machine-learning/concept-compute-target#supported-vm-series-and-sizes"
    )
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "type", "group": "management"}
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("name"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "ctime": S("systemData", "createdAt"),
        "mtime": S("systemData", "lastModifiedAt"),
        "estimated_vm_prices": S("estimatedVMPrices") >> Bend(AzureEstimatedVMPrices.mapping),
        "family": S("family"),
        "gpus": S("gpus"),
        "low_priority_capable": S("lowPriorityCapable"),
        "max_resource_volume_mb": S("maxResourceVolumeMB"),
        "memory_gb": S("memoryGB"),
        "os_vhd_size_mb": S("osVhdSizeMB"),
        "premium_io": S("premiumIO"),
        "supported_compute_types": S("supportedComputeTypes"),
        "v_cp_us": S("vCPUs"),
        "location": S("location"),
        "instance_type": S("name"),
        "instance_cores": S("vCPUs"),
        "instance_memory": S("memoryGB"),
    }
    _create_provider_link: ClassVar[bool] = False
    estimated_vm_prices: Optional[AzureEstimatedVMPrices] = field(default=None, metadata={'description': 'The estimated price info for using a VM.'})  # fmt: skip
    family: Optional[str] = field(default=None, metadata={'description': 'The family name of the virtual machine size.'})  # fmt: skip
    gpus: Optional[int] = field(default=None, metadata={'description': 'The number of gPUs supported by the virtual machine size.'})  # fmt: skip
    low_priority_capable: Optional[bool] = field(default=None, metadata={'description': 'Specifies if the virtual machine size supports low priority VMs.'})  # fmt: skip
    max_resource_volume_mb: Optional[int] = field(default=None, metadata={'description': 'The resource volume size, in MB, allowed by the virtual machine size.'})  # fmt: skip
    memory_gb: Optional[float] = field(default=None, metadata={'description': 'The amount of memory, in GB, supported by the virtual machine size.'})  # fmt: skip
    os_vhd_size_mb: Optional[int] = field(default=None, metadata={'description': 'The OS VHD disk size, in MB, allowed by the virtual machine size.'})  # fmt: skip
    premium_io: Optional[bool] = field(default=None, metadata={'description': 'Specifies if the virtual machine size supports premium IO.'})  # fmt: skip
    supported_compute_types: Optional[List[str]] = field(default=None, metadata={'description': 'Specifies the compute types supported by the virtual machine size.'})  # fmt: skip
    v_cp_us: Optional[int] = field(default=None, metadata={'description': 'The number of vCPUs supported by the virtual machine size.'})  # fmt: skip
    location: Optional[str] = field(default=None, metadata={'description': 'The geo-location where the resource lives'})  # fmt: skip


@define(eq=False, slots=False)
class AzureEncryptionKeyVaultProperties:
    kind: ClassVar[str] = "azure_encryption_key_vault_properties"
    mapping: ClassVar[Dict[str, Bender]] = {
        "identity_client_id": S("identityClientId"),
        "key_identifier": S("keyIdentifier"),
        "key_vault_arm_id": S("keyVaultArmId"),
    }
    identity_client_id: Optional[str] = field(default=None, metadata={'description': 'For future use - The client id of the identity which will be used to access key vault.'})  # fmt: skip
    key_identifier: Optional[str] = field(default=None, metadata={'description': 'Key vault uri to access the encryption key.'})  # fmt: skip
    key_vault_arm_id: Optional[str] = field(default=None, metadata={'description': 'The ArmId of the keyVault where the customer owned encryption key is present.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureEncryptionProperty:
    kind: ClassVar[str] = "azure_encryption_property"
    mapping: ClassVar[Dict[str, Bender]] = {
        "identity": S("identity", "userAssignedIdentity"),
        "key_vault_properties": S("keyVaultProperties") >> Bend(AzureEncryptionKeyVaultProperties.mapping),
        "status": S("status"),
    }
    identity: Optional[str] = field(default=None, metadata={'description': 'Identity that will be used to access key vault for encryption at rest'})  # fmt: skip
    key_vault_properties: Optional[AzureEncryptionKeyVaultProperties] = field(default=None, metadata={'description': ''})  # fmt: skip
    status: Optional[str] = field(default=None, metadata={'description': 'Indicates whether or not the encryption is enabled for the workspace.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureServerlessComputeSettings:
    kind: ClassVar[str] = "azure_serverless_compute_settings"
    mapping: ClassVar[Dict[str, Bender]] = {
        "serverless_compute_custom_subnet": S("serverlessComputeCustomSubnet"),
        "serverless_compute_no_public_ip": S("serverlessComputeNoPublicIP"),
    }
    serverless_compute_custom_subnet: Optional[str] = field(default=None, metadata={'description': 'The resource ID of an existing virtual network subnet in which serverless compute nodes should be deployed'})  # fmt: skip
    serverless_compute_no_public_ip: Optional[bool] = field(default=None, metadata={'description': 'The flag to signal if serverless compute nodes deployed in custom vNet would have no public IP addresses for a workspace with private endpoint'})  # fmt: skip


@define(eq=False, slots=False)
class AzureSharedPrivateLinkResource:
    kind: ClassVar[str] = "azure_shared_private_link_resource"
    mapping: ClassVar[Dict[str, Bender]] = {
        "group_id": S("properties", "groupId"),
        "name": S("name"),
        "private_link_resource_id": S("properties", "privateLinkResourceId"),
        "request_message": S("properties", "requestMessage"),
        "status": S("properties", "status"),
    }
    group_id: Optional[str] = field(default=None, metadata={"description": "The private link resource group id."})
    name: Optional[str] = field(default=None, metadata={"description": "Unique name of the private link."})
    private_link_resource_id: Optional[str] = field(default=None, metadata={'description': 'The resource id that private link links to.'})  # fmt: skip
    request_message: Optional[str] = field(default=None, metadata={"description": "Request message."})
    status: Optional[str] = field(default=None, metadata={"description": "The private endpoint connection status."})


@define(eq=False, slots=False)
class AzureNotebookPreparationError:
    kind: ClassVar[str] = "azure_notebook_preparation_error"
    mapping: ClassVar[Dict[str, Bender]] = {"error_message": S("errorMessage"), "status_code": S("statusCode")}
    error_message: Optional[str] = field(default=None, metadata={"description": ""})
    status_code: Optional[int] = field(default=None, metadata={"description": ""})


@define(eq=False, slots=False)
class AzureNotebookResourceInfo:
    kind: ClassVar[str] = "azure_notebook_resource_info"
    mapping: ClassVar[Dict[str, Bender]] = {
        "fqdn": S("fqdn"),
        "notebook_preparation_error": S("notebookPreparationError") >> Bend(AzureNotebookPreparationError.mapping),
        "resource_id": S("resourceId"),
    }
    fqdn: Optional[str] = field(default=None, metadata={"description": ""})
    notebook_preparation_error: Optional[AzureNotebookPreparationError] = field(default=None, metadata={'description': ''})  # fmt: skip
    resource_id: Optional[str] = field(default=None, metadata={'description': 'the data plane resourceId that used to initialize notebook component'})  # fmt: skip


@define(eq=False, slots=False)
class AzureServiceManagedResourcesSettings:
    kind: ClassVar[str] = "azure_service_managed_resources_settings"
    mapping: ClassVar[Dict[str, Bender]] = {"cosmos_db": S("cosmosDb", "collectionsThroughput")}
    cosmos_db: Optional[int] = field(default=None, metadata={"description": ""})


@define(eq=False, slots=False)
class AzureManagedNetworkProvisionStatus:
    kind: ClassVar[str] = "azure_managed_network_provision_status"
    mapping: ClassVar[Dict[str, Bender]] = {"spark_ready": S("sparkReady"), "status": S("status")}
    spark_ready: Optional[bool] = field(default=None, metadata={"description": ""})
    status: Optional[str] = field(default=None, metadata={'description': 'Status for the managed network of a machine learning workspace.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureManagedNetworkOutboundRule:
    kind: ClassVar[str] = "azure_managed_network_outbound_rule"
    mapping: ClassVar[Dict[str, Bender]] = {"category": S("category"), "status": S("status"), "type": S("type")}
    category: Optional[str] = field(default=None, metadata={'description': 'Category of a managed network Outbound Rule of a machine learning workspace.'})  # fmt: skip
    status: Optional[str] = field(default=None, metadata={'description': 'Type of a managed network Outbound Rule of a machine learning workspace.'})  # fmt: skip
    type: Optional[str] = field(default=None, metadata={'description': 'Type of a managed network Outbound Rule of a machine learning workspace.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureManagedNetworkSettings:
    kind: ClassVar[str] = "azure_managed_network_settings"
    mapping: ClassVar[Dict[str, Bender]] = {
        "isolation_mode": S("isolationMode"),
        "network_id": S("networkId"),
        "outbound_rules": S("outboundRules"),
        "status": S("status") >> Bend(AzureManagedNetworkProvisionStatus.mapping),
    }
    isolation_mode: Optional[str] = field(default=None, metadata={'description': 'Isolation mode for the managed network of a machine learning workspace.'})  # fmt: skip
    network_id: Optional[str] = field(default=None, metadata={"description": ""})
    outbound_rules: Optional[Dict[str, AzureManagedNetworkOutboundRule]] = field(
        default=None, metadata={"description": ""}
    )
    status: Optional[AzureManagedNetworkProvisionStatus] = field(default=None, metadata={'description': 'Status of the Provisioning for the managed network of a machine learning workspace.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureFeatureStoreSettings:
    kind: ClassVar[str] = "azure_feature_store_settings"
    mapping: ClassVar[Dict[str, Bender]] = {
        "compute_runtime": S("computeRuntime", "sparkRuntimeVersion"),
        "offline_store_connection_name": S("offlineStoreConnectionName"),
        "online_store_connection_name": S("onlineStoreConnectionName"),
    }
    compute_runtime: Optional[str] = field(default=None, metadata={'description': 'Compute runtime config for feature store type workspace.'})  # fmt: skip
    offline_store_connection_name: Optional[str] = field(default=None, metadata={"description": ""})
    online_store_connection_name: Optional[str] = field(default=None, metadata={"description": ""})


@define(eq=False, slots=False)
class AzureWorkspaceHubConfig:
    kind: ClassVar[str] = "azure_workspace_hub_config"
    mapping: ClassVar[Dict[str, Bender]] = {
        "additional_workspace_storage_accounts": S("additionalWorkspaceStorageAccounts"),
        "default_workspace_resource_group": S("defaultWorkspaceResourceGroup"),
    }
    additional_workspace_storage_accounts: Optional[List[str]] = field(default=None, metadata={"description": ""})
    default_workspace_resource_group: Optional[str] = field(default=None, metadata={"description": ""})


@define(eq=False, slots=False)
class AzureMachineLearningWorkspace(MicrosoftResource):
    kind: ClassVar[str] = "azure_machine_learning_workspace"
    _kind_display: ClassVar[str] = "Azure Machine Learning Workspace"
    _kind_service: ClassVar[Optional[str]] = service_name
    _kind_description: ClassVar[str] = "Azure Machine Learning Workspace is a cloud-based environment for developing, training, and deploying machine learning models. It provides tools and services for data preparation, model creation, and experiment tracking. Users can collaborate on projects, manage datasets, and deploy models to production. The workspace integrates with other Azure services for enhanced functionality and resource management."  # fmt: skip
    _docs_url: ClassVar[str] = "https://learn.microsoft.com/en-us/azure/machine-learning/concept-workspace"
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "resource", "group": "ai"}
    api_spec: ClassVar[AzureResourceSpec] = AzureResourceSpec(
        service="machinelearningservices",
        version="2024-04-01",
        path="/subscriptions/{subscriptionId}/providers/Microsoft.MachineLearningServices/workspaces",
        path_parameters=["subscriptionId"],
        query_parameters=["api-version"],
        access_path="value",
        expect_array=True,
    )
    _reference_kinds: ClassVar[ModelReference] = {
        "successors": {
            "default": [
                "azure_machine_learning_batch_endpoint",
                "azure_machine_learning_compute",
                "azure_machine_learning_datastore",
                "azure_machine_learning_endpoint",
                "azure_machine_learning_job",
                "azure_machine_learning_labeling_job",
                "azure_machine_learning_online_endpoint",
                "azure_machine_learning_private_endpoint_connection",
                "azure_machine_learning_private_link",
                "azure_machine_learning_schedule",
                "azure_machine_learning_serverless_endpoint",
                "azure_machine_learning_workspace_connection",
                "azure_machine_learning_workspace_code_container",
                "azure_machine_learning_workspace_component_container",
                "azure_machine_learning_workspace_data_container",
                "azure_machine_learning_workspace_environment_container",
                "azure_machine_learning_featureset_container",
                "azure_machine_learning_featurestore_entity_container",
                "azure_machine_learning_workspace_model_container",
                MicrosoftGraphServicePrincipal.kind,
                MicrosoftGraphUser.kind,
            ]
        },
        "predecessors": {
            "default": [
                AzureKeyVault.kind,
                AzureNetworkVirtualNetwork.kind,
                AzureStorageAccount.kind,
                AzureNetworkSubnet.kind,
            ]
        },
    }
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "ctime": S("systemData", "createdAt"),
        "mtime": S("systemData", "lastModifiedAt"),
        "allow_public_access_when_behind_vnet": S("properties", "allowPublicAccessWhenBehindVnet"),
        "application_insights": S("properties", "applicationInsights"),
        "associated_workspaces": S("properties", "associatedWorkspaces"),
        "container_registry": S("properties", "containerRegistry"),
        "description": S("properties", "description"),
        "discovery_url": S("properties", "discoveryUrl"),
        "enable_data_isolation": S("properties", "enableDataIsolation"),
        "workspace_encryption": S("properties", "encryption") >> Bend(AzureEncryptionProperty.mapping),
        "feature_store_settings": S("properties", "featureStoreSettings") >> Bend(AzureFeatureStoreSettings.mapping),
        "friendly_name": S("properties", "friendlyName"),
        "hbi_workspace": S("properties", "hbiWorkspace"),
        "hub_resource_id": S("properties", "hubResourceId"),
        "identity": S("identity") >> Bend(AzureManagedServiceIdentity.mapping),
        "image_build_compute": S("properties", "imageBuildCompute"),
        "key_vault": S("properties", "keyVault"),
        "azure_kind": S("kind"),
        "managed_network": S("properties", "managedNetwork") >> Bend(AzureManagedNetworkSettings.mapping),
        "ml_flow_tracking_uri": S("properties", "mlFlowTrackingUri"),
        "notebook_info": S("properties", "notebookInfo") >> Bend(AzureNotebookResourceInfo.mapping),
        "primary_user_assigned_identity": S("properties", "primaryUserAssignedIdentity"),
        "private_endpoint_connection_ids": S("properties", "privateEndpointConnections") >> ForallBend(S("id")),
        "private_link_count": S("properties", "privateLinkCount"),
        "provisioning_state": S("properties", "provisioningState"),
        "public_network_access": S("properties", "publicNetworkAccess"),
        "serverless_compute_settings": S("properties", "serverlessComputeSettings")
        >> Bend(AzureServerlessComputeSettings.mapping),
        "service_managed_resources_settings": S("properties", "serviceManagedResourcesSettings")
        >> Bend(AzureServiceManagedResourcesSettings.mapping),
        "service_provisioned_resource_group": S("properties", "serviceProvisionedResourceGroup"),
        "shared_private_link_resources": S("properties", "sharedPrivateLinkResources")
        >> ForallBend(AzureSharedPrivateLinkResource.mapping),
        "azure_sku": S("sku") >> Bend(AzureSku.mapping),
        "storage_account": S("properties", "storageAccount"),
        "storage_hns_enabled": S("properties", "storageHnsEnabled"),
        "system_data": S("systemData") >> Bend(AzureSystemData.mapping),
        "tenant_id": S("properties", "tenantId"),
        "v1_legacy_mode": S("properties", "v1LegacyMode"),
        "workspace_hub_config": S("properties", "workspaceHubConfig") >> Bend(AzureWorkspaceHubConfig.mapping),
        "workspace_id": S("properties", "workspaceId"),
    }
    allow_public_access_when_behind_vnet: Optional[bool] = field(default=None, metadata={'description': 'The flag to indicate whether to allow public access when behind VNet.'})  # fmt: skip
    application_insights: Optional[str] = field(default=None, metadata={'description': 'ARM id of the application insights associated with this workspace.'})  # fmt: skip
    associated_workspaces: Optional[List[str]] = field(default=None, metadata={"description": ""})
    container_registry: Optional[str] = field(default=None, metadata={'description': 'ARM id of the container registry associated with this workspace.'})  # fmt: skip
    description: Optional[str] = field(default=None, metadata={"description": "The description of this workspace."})
    discovery_url: Optional[str] = field(default=None, metadata={'description': 'Url for the discovery service to identify regional endpoints for machine learning experimentation services'})  # fmt: skip
    enable_data_isolation: Optional[bool] = field(default=None, metadata={"description": ""})
    workspace_encryption: Optional[AzureEncryptionProperty] = field(default=None, metadata={"description": ""})
    feature_store_settings: Optional[AzureFeatureStoreSettings] = field(default=None, metadata={'description': 'Settings for feature store type workspace.'})  # fmt: skip
    friendly_name: Optional[str] = field(default=None, metadata={'description': 'The friendly name for this workspace. This name in mutable'})  # fmt: skip
    hbi_workspace: Optional[bool] = field(default=None, metadata={'description': 'The flag to signal HBI data in the workspace and reduce diagnostic data collected by the service'})  # fmt: skip
    hub_resource_id: Optional[str] = field(default=None, metadata={"description": ""})
    identity: Optional[AzureManagedServiceIdentity] = field(default=None, metadata={'description': 'Managed service identity (system assigned and/or user assigned identities)'})  # fmt: skip
    image_build_compute: Optional[str] = field(default=None, metadata={'description': 'The compute name for image build'})  # fmt: skip
    key_vault: Optional[str] = field(default=None, metadata={'description': 'ARM id of the key vault associated with this workspace. This cannot be changed once the workspace has been created'})  # fmt: skip
    azure_kind: Optional[str] = field(default=None, metadata={"description": ""})
    managed_network: Optional[AzureManagedNetworkSettings] = field(default=None, metadata={'description': 'Managed Network settings for a machine learning workspace.'})  # fmt: skip
    ml_flow_tracking_uri: Optional[str] = field(default=None, metadata={'description': 'The URI associated with this workspace that machine learning flow must point at to set up tracking.'})  # fmt: skip
    notebook_info: Optional[AzureNotebookResourceInfo] = field(default=None, metadata={"description": ""})
    primary_user_assigned_identity: Optional[str] = field(default=None, metadata={'description': 'The user assigned identity resource id that represents the workspace identity.'})  # fmt: skip
    private_endpoint_connection_ids: Optional[List[str]] = field(default=None, metadata={'description': 'The list of private endpoint connections in the workspace.'})  # fmt: skip
    private_link_count: Optional[int] = field(default=None, metadata={'description': 'Count of private connections in the workspace'})  # fmt: skip
    public_network_access: Optional[str] = field(default=None, metadata={'description': 'Whether requests from Public Network are allowed.'})  # fmt: skip
    serverless_compute_settings: Optional[AzureServerlessComputeSettings] = field(default=None, metadata={'description': ''})  # fmt: skip
    service_managed_resources_settings: Optional[AzureServiceManagedResourcesSettings] = field(default=None, metadata={'description': ''})  # fmt: skip
    service_provisioned_resource_group: Optional[str] = field(default=None, metadata={'description': 'The name of the managed resource group created by workspace RP in customer subscription if the workspace is CMK workspace'})  # fmt: skip
    shared_private_link_resources: Optional[List[AzureSharedPrivateLinkResource]] = field(default=None, metadata={'description': 'The list of shared private link resources in this workspace.'})  # fmt: skip
    azure_sku: Optional[AzureSku] = field(default=None, metadata={'description': 'The resource model definition representing SKU'})  # fmt: skip
    storage_account: Optional[str] = field(default=None, metadata={'description': 'ARM id of the storage account associated with this workspace. This cannot be changed once the workspace has been created'})  # fmt: skip
    storage_hns_enabled: Optional[bool] = field(default=None, metadata={'description': 'If the storage associated with the workspace has hierarchical namespace(HNS) enabled.'})  # fmt: skip
    system_data: Optional[AzureSystemData] = field(default=None, metadata={'description': 'Metadata pertaining to creation and last modification of the resource.'})  # fmt: skip
    tenant_id: Optional[str] = field(default=None, metadata={'description': 'The tenant id associated with this workspace.'})  # fmt: skip
    v1_legacy_mode: Optional[bool] = field(default=None, metadata={'description': 'Enabling v1_legacy_mode may prevent you from using features provided by the v2 API.'})  # fmt: skip
    workspace_hub_config: Optional[AzureWorkspaceHubConfig] = field(default=None, metadata={'description': 'WorkspaceHub s configuration object.'})  # fmt: skip
    workspace_id: Optional[str] = field(default=None, metadata={'description': 'The immutable id associated with this workspace.'})  # fmt: skip

    def _collect_items(
        self,
        graph_builder: GraphBuilder,
        workspace_id: str,
        resource_type: str,
        class_instance: MicrosoftResource,
        expected_errors: Optional[Dict[str, Optional[str]]] = None,
    ) -> None:
        path = f"{workspace_id}/{resource_type}"
        api_spec = AzureResourceSpec(
            service="machinelearningservices",
            version="2024-04-01",
            path=path,
            path_parameters=[],
            query_parameters=["api-version"],
            access_path="value",
            expect_array=True,
            expected_error_codes=expected_errors or {},
        )
        items = graph_builder.client.list(api_spec)
        if not items:
            return
        collected = class_instance.collect(items, graph_builder)
        for clazz in collected:
            graph_builder.add_edge(self, node=clazz)

    def post_process(self, graph_builder: GraphBuilder, source: Json) -> None:
        if workspace_id := self.id:
            resources_to_collect = [
                ("batchEndpoints", AzureMachineLearningBatchEndpoint, None),
                ("computes", AzureMachineLearningCompute, None),
                ("datastores", AzureMachineLearningDatastore, None),
                ("endpoints", AzureMachineLearningEndpoint, None),
                ("jobs", AzureMachineLearningJob, None),
                ("labelingJobs", AzureMachineLearningLabelingJob, None),
                ("onlineEndpoints", AzureMachineLearningOnlineEndpoint, None),
                ("privateEndpointConnections", AzureMachineLearningPrivateEndpointConnection, None),
                ("privateLinkResources", AzureMachineLearningPrivateLink, None),
                ("schedules", AzureMachineLearningSchedule, None),
                ("serverlessEndpoints", AzureMachineLearningServerlessEndpoint, None),
                ("connections", AzureMachineLearningWorkspaceConnection, None),
                ("codes", AzureMachineLearningWorkspaceCodeContainer, {"UserError": None}),
                ("components", AzureMachineLearningWorkspaceComponentContainer, None),
                ("data", AzureMachineLearningWorkspaceDataContainer, None),
                ("environments", AzureMachineLearningWorkspaceEnvironmentContainer, None),
                ("featuresets", AzureMachineLearningFeaturesetContainer, {"UserError": None}),
                ("featurestoreEntities", AzureMachineLearningFeaturestoreEntityContainer, {"UserError": None}),
                ("models", AzureMachineLearningWorkspaceModelContainer, None),
            ]

            for resource_type, resource_class, expected_errors in resources_to_collect:
                graph_builder.submit_work(
                    service_name,
                    self._collect_items,
                    graph_builder,
                    workspace_id,
                    resource_type,
                    resource_class,
                    expected_errors,
                )

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if key_vault_id := self.key_vault:
            builder.add_edge(self, clazz=AzureKeyVault, reverse=True, id=key_vault_id)
        if (network := self.managed_network) and (network_id := network.network_id):
            builder.add_edge(self, clazz=AzureNetworkVirtualNetwork, reverse=True, id=network_id)
        if storage_id := self.storage_account:
            builder.add_edge(self, clazz=AzureStorageAccount, reverse=True, id=storage_id)
        if (compute_settings := self.serverless_compute_settings) and (
            subnet_id := compute_settings.serverless_compute_custom_subnet
        ):
            builder.add_edge(self, clazz=AzureNetworkSubnet, reverse=True, id=subnet_id)

        # principal: collected via ms graph -> create a deferred edge
        if ai := self.identity:
            if pid := ai.principal_id:
                builder.add_deferred_edge(
                    from_node=self,
                    to_node=BySearchCriteria(f'is({MicrosoftGraphServicePrincipal.kind}) and reported.id=="{pid}"'),
                )
            if uai := ai.user_assigned_identities:
                for _, identity_info in uai.items():
                    if identity_info and identity_info.principal_id:
                        builder.add_deferred_edge(
                            from_node=self,
                            to_node=BySearchCriteria(
                                f'is({MicrosoftGraphUser.kind}) and reported.id=="{identity_info.principal_id}"'
                            ),
                        )


@define(eq=False, slots=False)
class AzureMachineLearningWorkspaceConnection(MicrosoftResource):
    kind: ClassVar[str] = "azure_machine_learning_workspace_connection"
    _kind_display: ClassVar[str] = "Azure Machine Learning Workspace Connection"
    _kind_service: ClassVar[Optional[str]] = service_name
    _kind_description: ClassVar[str] = "Azure Machine Learning Workspace Connection is a resource that links an Azure Machine Learning workspace to other Azure services. It facilitates data access, compute resource management, and model deployment within the Azure ecosystem. This connection integrates machine learning projects with Azure storage, compute, and networking capabilities, supporting the end-to-end machine learning lifecycle."  # fmt: skip
    _docs_url: ClassVar[str] = "https://learn.microsoft.com/en-us/azure/machine-learning/how-to-manage-workspace-cli"
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "resource", "group": "ai"}
    # Collected via AzureMachineLearningWorkspace()
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "name": S("name"),
        "tags": K({}),
        "ctime": S("systemData", "createdAt"),
        "mtime": S("systemData", "lastModifiedAt"),
        "compute_auth_type": S("properties", "authType"),
        "compute_connection_category": S("properties", "category"),
        "created_by_workspace_arm_id": S("properties", "createdByWorkspaceArmId"),
        "compute_expiry_time": S("properties", "expiryTime"),
        "compute_connection_group": S("properties", "group"),
        "compute_is_shared_to_all": S("properties", "isSharedToAll"),
        "workspace_connection_metadata": S("properties", "metadata"),
        "compute_shared_user_list": S("properties", "sharedUserList"),
        "system_data": S("systemData") >> Bend(AzureSystemData.mapping),
        "compute_target": S("properties", "target"),
        "connection_value": S("properties", "value"),
        "value_format": S("properties", "valueFormat"),
    }
    compute_auth_type: Optional[str] = field(default=None, metadata={'description': 'Authentication type of the connection target'})  # fmt: skip
    compute_connection_category: Optional[str] = field(
        default=None, metadata={"description": "Category of the connection"}
    )
    created_by_workspace_arm_id: Optional[str] = field(default=None, metadata={"description": ""})
    compute_expiry_time: Optional[datetime] = field(default=None, metadata={"description": ""})
    compute_connection_group: Optional[str] = field(
        default=None, metadata={"description": "Group based on connection category"}
    )
    compute_is_shared_to_all: Optional[bool] = field(default=None, metadata={"description": ""})
    workspace_connection_metadata: Optional[Dict[str, str]] = field(default=None, metadata={'description': 'Store user metadata for this connection'})  # fmt: skip
    compute_shared_user_list: Optional[List[str]] = field(default=None, metadata={"description": ""})
    system_data: Optional[AzureSystemData] = field(default=None, metadata={'description': 'Metadata pertaining to creation and last modification of the resource.'})  # fmt: skip
    compute_target: Optional[str] = field(default=None, metadata={"description": ""})
    connection_value: Optional[str] = field(
        default=None, metadata={"description": "Value details of the workspace connection."}
    )
    value_format: Optional[str] = field(default=None, metadata={'description': 'format for the workspace connection value'})  # fmt: skip


resources: List[Type[MicrosoftResource]] = [
    AzureMachineLearningBatchEndpoint,
    AzureMachineLearningWorkspaceCodeContainer,
    AzureMachineLearningWorkspaceCodeVersion,
    AzureMachineLearningWorkspaceComponentContainer,
    AzureMachineLearningWorkspaceComponentVersion,
    AzureMachineLearningWorkspaceDataContainer,
    AzureMachineLearningWorkspaceDataVersion,
    AzureMachineLearningWorkspaceModelContainer,
    AzureMachineLearningWorkspaceModelVersion,
    AzureMachineLearningWorkspaceEnvironmentContainer,
    AzureMachineLearningWorkspaceEnvironmentVersion,
    AzureMachineLearningComputeNode,
    AzureMachineLearningCompute,
    AzureMachineLearningDatastore,
    AzureMachineLearningEndpoint,
    AzureMachineLearningFeature,
    AzureMachineLearningFeaturesetContainer,
    AzureMachineLearningFeaturesetVersion,
    AzureMachineLearningFeaturestoreEntityContainer,
    AzureMachineLearningFeaturestoreEntityVersion,
    AzureMachineLearningJob,
    AzureMachineLearningLabelingJob,
    AzureMachineLearningOnlineEndpoint,
    AzureMachineLearningPrivateEndpointConnection,
    AzureMachineLearningPrivateLink,
    AzureMachineLearningRegistry,
    AzureMachineLearningRegistryCodeContainer,
    AzureMachineLearningRegistryCodeVersion,
    AzureMachineLearningRegistryComponentContainer,
    AzureMachineLearningRegistryComponentVersion,
    AzureMachineLearningRegistryDataContainer,
    AzureMachineLearningRegistryDataVersion,
    AzureMachineLearningRegistryModelContainer,
    AzureMachineLearningRegistryModelVersion,
    AzureMachineLearningRegistryEnvironmentContainer,
    AzureMachineLearningRegistryEnvironmentVersion,
    # AzureMachineLearningQuota,  # TODO: filter only needed quota
    AzureMachineLearningSchedule,
    AzureMachineLearningServerlessEndpoint,
    AzureMachineLearningUsage,
    AzureMachineLearningVirtualMachineSize,
    AzureMachineLearningWorkspace,
    AzureMachineLearningWorkspaceConnection,
]
