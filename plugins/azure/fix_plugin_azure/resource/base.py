from __future__ import annotations

import logging
from concurrent.futures import Future
from datetime import datetime, timedelta
from typing import Any, ClassVar, Dict, Optional, TypeVar, List, Type, Callable, cast, Union, Set

from attr import define, field
from azure.identity import DefaultAzureCredential

from fix_plugin_azure.azure_client import AzureResourceSpec, MicrosoftClient, MicrosoftRestSpec
from fix_plugin_azure.config import AzureConfig
from fix_plugin_azure.utils import case_insensitive_eq
from fixlib.baseresources import (
    BaseGroup,
    BaseResource,
    Cloud,
    EdgeType,
    BaseAccount,
    BaseRegion,
    ModelReference,
    PhantomBaseResource,
)
from fixlib.config import current_config
from fixlib.core.actions import CoreFeedback
from fixlib.graph import Graph, EdgeKey, NodeSelector, ByNodeId
from fixlib.json import from_json
from fixlib.json_bender import AsFloat, Bender, bend, S, ForallBend, Bend
from fixlib.lock import RWLock
from fixlib.threading import ExecutorQueue
from fixlib.types import Json
from fixlib.utils import utc

log = logging.getLogger("fix.plugins.azure")
service_name = "azure_base"


def get_client(subscription_id: str) -> MicrosoftClient:
    config = current_config()
    azure_config = cast(AzureConfig, config.azure)
    #  Taking credentials from the config if access through the environment cannot be provided
    if azure_config.accounts and (account := azure_config.accounts.get(subscription_id)):
        credential = account.credentials()
    else:
        # Increase the process timeout to ensure proper handling of credentials
        # in environments with a high number of parallel futures. This helps to avoid timeouts
        # during the credential acquisition process.
        credential = DefaultAzureCredential(process_timeout=300)
    return MicrosoftClient.create(config=azure_config, credential=credential, subscription_id=subscription_id)


T = TypeVar("T")


def parse_json(
    json: Json, clazz: Type[T], builder: Optional[GraphBuilder] = None, mapping: Optional[Dict[str, Bender]] = None
) -> Optional[T]:
    """
    Use this method to parse json into a class. If the json can not be parsed, the error is reported to the core.
    Based on configuration, either the exception is raised or None is returned.
    :param json: the json to parse.
    :param clazz: the class to parse into.
    :param builder: the graph builder.
    :param mapping: the optional mapping to apply before parsing.
    :return: The parsed object or None.
    """
    try:
        mapped = bend(mapping, json) if mapping is not None else json
        return from_json(mapped, clazz)
    except Exception as e:
        message = f"Failed to parse json into {clazz.__name__}: {e}. Source: {json}"
        if builder:
            # report and log the error
            builder.core_feedback.error(message, log)
            # based on the strict flag, either raise the exception or return None
            if builder.config.discard_account_on_resource_error:
                raise
        else:
            log.warning(message)
        return None


@define(eq=False, slots=False)
class MicrosoftResource(BaseResource):
    kind: ClassVar[str] = "microsoft_resource"
    _kind_display: ClassVar[str] = "Microsoft Resource"
    # The mapping to transform the incoming API json into the internal representation.
    mapping: ClassVar[Dict[str, Bender]] = {}
    # Which API to call and what to expect in the result.
    api_spec: ClassVar[Optional[MicrosoftRestSpec]] = None
    # Check if we want to create provider link. Default is True
    _create_provider_link: ClassVar[bool] = True
    # Azure common properties
    etag: Optional[str] = field(default=None, metadata={'description': 'A unique read-only string that changes whenever the resource is updated.'})  # fmt: skip
    provisioning_state: Optional[str] = field(default=None, metadata={'description': 'The current provisioning state.'})  # fmt: skip

    @property
    def resource_subscription_id(self) -> Optional[str]:
        return self.extract_part("subscriptions")

    @property
    def resource_group_name(self) -> Optional[str]:
        return self.extract_part("resourceGroups")

    def extract_part(self, part: str) -> Optional[str]:
        """
        Extracts a specific part from a resource ID.

        The function takes a resource ID and a specified part to extract, such as 'subscriptions'.
        The resource ID is expected to follow the Azure Resource Manager path format.

        Example:
        For the resource ID "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/...",
        calling extract_part("subscriptions") would return the value representing the subscription ID.

        Parameters:
        - part (str): The part to extract from the resource ID.

        Returns:
        Optional[str]: The extracted part of the resource ID, or None if not found.
        """
        id_parts = self.id.split("/")
        try:
            return id_parts[id_parts.index(part) + 1]
        except ValueError:
            return None

    def delete(self, graph: Graph) -> bool:
        """
        Deletes a resource by ID.

        Returns:
        bool: True if the resource was successfully deleted; False otherwise.
        """
        subscription_id = self.resource_subscription_id
        if subscription_id is None:
            log.warning("Failed to delete resource. Subscription ID is not available.")
            return False
        return get_client(subscription_id).delete(self.id)

    def delete_tag(self, key: str) -> bool:
        """Deletes a tag value.

        This method removes a specific value from a tag associated with a subscription, while keeping the tag itself intact.
        The tag remains on the account, but the specified value will be deleted.
        """
        subscription_id = self.resource_subscription_id
        if subscription_id is None:
            log.warning("Failed to delete tag. Subscription ID is not available.")
            return False
        return get_client(subscription_id).delete_resource_tag(tag_name=key, resource_id=self.id)

    def update_tag(self, key: str, value: str) -> bool:
        """Creates a tag value. The name of the tag must already exist.

        This method allows for the creation or update of a tag value associated with the specified tag name.
        The tag name must already exist for the operation to be successful.
        """
        subscription_id = self.resource_subscription_id
        if subscription_id is None:
            log.warning("Failed to update tag. Subscription ID is not available.")
            return False
        return get_client(subscription_id).update_resource_tag(tag_name=key, tag_value=value, resource_id=self.id)

    def pre_process(self, graph_builder: GraphBuilder, source: Json) -> None:
        """
        Hook method to pre process the resource before it is added to the graph.
        Default: do nothing.
        """
        pass

    def post_process(self, graph_builder: GraphBuilder, source: Json) -> None:
        """
        Hook method to post process the resource after it is added to the graph.
        Default: do nothing.
        """
        pass

    def after_collect(self, builder: GraphBuilder, source: Json) -> None:
        """
        Hook method to post process the resource after all connections are done.
        Default: do nothing.
        """
        pass

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        # Default behavior: add resource to the namespace
        pass

    @classmethod
    def collect_usage_metrics(
        cls: Type[MicrosoftResourceType], builder: GraphBuilder, collected_resources: List[MicrosoftResourceType]
    ) -> None:
        # Default behavior: do nothing
        pass

    @classmethod
    def collect_resources(
        cls: Type[MicrosoftResourceType], builder: GraphBuilder, **kwargs: Any
    ) -> List[MicrosoftResourceType]:
        # Default behavior: in case the class has an ApiSpec, call the api and call collect.
        log.debug(f"[Azure:{builder.account.id}] Collecting {cls.__name__} with ({kwargs})")
        if spec := cls.api_spec:
            try:
                items = builder.client.list(spec, **kwargs)
                collected = cls.collect(items, builder)
                if builder.config.collect_usage_metrics:
                    try:
                        cls.collect_usage_metrics(builder, collected)
                    except Exception as e:
                        log.warning(f"Failed to collect usage metrics for {cls.__name__}: {e}")
                return collected
            except Exception as e:
                msg = f"Error while collecting {cls.__name__} with service {spec.service} and location: {builder.location}: {e}"
                builder.core_feedback.info(msg, log)
                raise

        return []

    @classmethod
    def collect(
        cls: Type[MicrosoftResourceType],
        raw: List[Json],
        builder: GraphBuilder,
    ) -> List[MicrosoftResourceType]:
        # Default behavior: iterate over json snippets and for each:
        # - bend the json
        # - transform the result into a resource
        # - add the resource to the graph
        # In case additional work needs to be done, override this method.
        result: List[MicrosoftResourceType] = []
        for js in raw:
            # map from api
            if instance := cls.from_api(js, builder):
                instance.pre_process(builder, js)
                # add to graph
                if (added := builder.add_node(instance, js)) is not None:
                    # post process
                    added.post_process(builder, js)
                    result.append(added)
        return result

    @classmethod
    def from_api(
        cls: Type[MicrosoftResourceType], json: Json, builder: Optional[GraphBuilder] = None
    ) -> Optional[MicrosoftResourceType]:
        return parse_json(json, cls, builder, cls.mapping)

    @classmethod
    def called_collect_apis(cls) -> List[MicrosoftRestSpec]:
        # The default implementation will return the defined api_spec if defined, otherwise an empty list.
        # In case your resource needs more than this api call, please override this method and return the proper list.
        if spec := cls.api_spec:
            return [spec]
        else:
            return []

    @classmethod
    def called_mutator_apis(cls) -> List[MicrosoftRestSpec]:
        return []


MicrosoftResourceType = TypeVar("MicrosoftResourceType", bound=MicrosoftResource)


@define(eq=False, slots=False)
class AzurePairedRegion:
    kind: ClassVar[str] = "azure_paired_region"
    mapping: ClassVar[Dict[str, Bender]] = {"id": S("id"), "name": S("name"), "subscription_id": S("subscriptionId")}
    id: Optional[str] = field(default=None, metadata={'description': 'The fully qualified id of the location. For example, /subscriptions/8d65815f-a5b6-402f-9298-045155da7d74/locations/westus.'})  # fmt: skip
    name: Optional[str] = field(default=None, metadata={"description": "The name of the paired region."})
    subscription_id: Optional[str] = field(default=None, metadata={"description": "The subscription id."})


@define(eq=False, slots=False)
class AzureLocationMetadata:
    kind: ClassVar[str] = "azure_location_metadata"
    mapping: ClassVar[Dict[str, Bender]] = {
        "geography": S("geography"),
        "geography_group": S("geographyGroup"),
        "home_location": S("homeLocation"),
        "latitude": S("latitude"),
        "longitude": S("longitude"),
        "paired_region": S("pairedRegion") >> ForallBend(AzurePairedRegion.mapping),
        "physical_location": S("physicalLocation"),
        "region_category": S("regionCategory"),
        "region_type": S("regionType"),
    }
    geography: Optional[str] = field(default=None, metadata={"description": "The geography of the location."})
    geography_group: Optional[str] = field(default=None, metadata={'description': 'The geography group of the location.'})  # fmt: skip
    home_location: Optional[str] = field(default=None, metadata={"description": "The home location of an edge zone."})
    latitude: Optional[str] = field(default=None, metadata={"description": "The latitude of the location."})
    longitude: Optional[str] = field(default=None, metadata={"description": "The longitude of the location."})
    paired_region: Optional[List[AzurePairedRegion]] = field(default=None, metadata={'description': 'The regions paired to this region.'})  # fmt: skip
    physical_location: Optional[str] = field(default=None, metadata={'description': 'The physical location of the azure location.'})  # fmt: skip
    region_category: Optional[str] = field(default=None, metadata={"description": "The category of the region."})
    region_type: Optional[str] = field(default=None, metadata={"description": "The type of the region."})


@define(eq=False, slots=False)
class AzureAvailabilityZoneMappings:
    kind: ClassVar[str] = "azure_availability_zone_mappings"
    mapping: ClassVar[Dict[str, Bender]] = {"logical_zone": S("logicalZone"), "physical_zone": S("physicalZone")}
    logical_zone: Optional[str] = field(default=None, metadata={'description': 'The logical zone id for the availability zone.'})  # fmt: skip
    physical_zone: Optional[str] = field(default=None, metadata={'description': 'The fully qualified physical zone id of availability zone to which logical zone id is mapped to.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureLocation(MicrosoftResource, BaseRegion):
    kind: ClassVar[str] = "azure_location"
    _kind_display: ClassVar[str] = "Azure Location"
    _kind_service: ClassVar[str] = "resources"
    _kind_description: ClassVar[str] = "Azure Location is a geographic area containing one or more Azure data centers. It represents a specific region where customers can deploy and run their cloud resources. Azure Locations provide options for data residency, compliance, and reduced latency by allowing users to choose where their applications and data are stored and processed within Microsoft's global infrastructure."  # fmt: skip
    _docs_url: ClassVar[str] = "https://learn.microsoft.com/en-us/azure/virtual-machines/regions"
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "region", "group": "management"}
    api_spec: ClassVar[AzureResourceSpec] = AzureResourceSpec(
        service="resources",
        version="2022-12-01",
        path="/subscriptions/{subscriptionId}/locations",
        path_parameters=["subscriptionId"],
        query_parameters=["api-version"],
        access_path="value",
        expect_array=True,
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "availability_zone_mappings": S("availabilityZoneMappings")
        >> ForallBend(AzureAvailabilityZoneMappings.mapping),
        "display_name": S("displayName"),
        "location_metadata": S("metadata") >> Bend(AzureLocationMetadata.mapping),
        "regional_display_name": S("regionalDisplayName"),
        "subscription_id": S("subscriptionId"),
        "long_name": S("displayName"),
        "latitude": S("metadata", "latitude") >> AsFloat(),
        "longitude": S("metadata", "longitude") >> AsFloat(),
    }
    availability_zone_mappings: Optional[List[AzureAvailabilityZoneMappings]] = field(default=None, metadata={'description': 'The availability zone mappings for this region.'})  # fmt: skip
    display_name: Optional[str] = field(default=None, metadata={"description": "The display name of the location."})
    location_metadata: Optional[AzureLocationMetadata] = field(default=None, metadata={'description': 'Location metadata information.'})  # fmt: skip
    regional_display_name: Optional[str] = field(default=None, metadata={'description': 'The display name of the location and its region.'})  # fmt: skip
    subscription_id: Optional[str] = field(default=None, metadata={"description": "The subscription id."})

    def compute_region_in_use(self, graph_builder: GraphBuilder) -> bool:
        ignore_kinds: Set[str] = {"azure_network_virtual_network", "azure_network_watcher"}

        def ignore_for_count(resource: BaseResource) -> bool:
            if isinstance(resource, PhantomBaseResource):
                return True
            if resource.kind in ignore_kinds:
                return True
            return False

        # A region with less than 3 real resources is considered not in use.
        # Azure is creating a couple of resources in every region automatically.
        count = 0
        empty_region = 3
        for succ in graph_builder.graph.descendants(self):
            if not ignore_for_count(succ):
                count += 1
                if count > empty_region:
                    break

        in_use = count > empty_region
        self.region_in_use = in_use
        return in_use


@define(eq=False, slots=False)
class AzureResourceGroup(MicrosoftResource, BaseGroup):
    kind: ClassVar[str] = "azure_resource_group"
    _kind_display: ClassVar[str] = "Azure Resource Group"
    _kind_service: ClassVar[str] = "resources"
    _kind_description: ClassVar[str] = "An Azure Resource Group is a container for organizing and managing related Azure resources. It serves as a logical unit for grouping services, applications, and infrastructure components within a single Azure subscription. Resource Groups help users control access, track costs, and apply policies across multiple resources, simplifying administration and deployment of cloud-based solutions."  # fmt: skip
    _docs_url: ClassVar[str] = (
        "https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/manage-resource-groups-portal"
    )
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "group", "group": "management"}
    api_spec: ClassVar[AzureResourceSpec] = AzureResourceSpec(
        service="resources",
        version="2022-09-01",
        path="/subscriptions/{subscriptionId}/resourcegroups",
        path_parameters=["subscriptionId"],
        query_parameters=["api-version"],
        access_path="value",
        expect_array=True,
    )
    _reference_kinds: ClassVar[ModelReference] = {
        "successors": {"default": ["microsoft_resource"]},
    }
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "managed_by": S("managedBy"),
        "location": S("location"),
        "provisioning_state": S("properties", "provisioningState"),
    }
    managed_by: Optional[str] = field(default=None, metadata={'description': 'The id of the resource that manages this resource group.'})  # fmt: skip
    location: Optional[str] = field(default=None, metadata={'description': 'The resource location.'})  # fmt: skip
    _resource_ids_in_group: Optional[List[str]] = None

    def post_process(self, graph_builder: GraphBuilder, source: Json) -> None:
        def collect_resources_in_group() -> None:
            resources_api_spec = AzureResourceSpec(
                service="resources",
                version="2021-04-01",
                path=f"{self.id}/resources",
                path_parameters=["subscriptionId"],
                query_parameters=["api-version"],
                access_path="value",
                expect_array=True,
            )

            self._resource_ids_in_group = [r["id"] for r in graph_builder.client.list(resources_api_spec)]

        def collect_network_gateways() -> None:
            from fix_plugin_azure.resource.network import AzureNetworkVirtualNetworkGateway

            api_spec = AzureResourceSpec(
                service="network",
                version="2023-09-01",
                path=f"{self.id}/providers/Microsoft.Network/virtualNetworkGateways",
                path_parameters=[],
                query_parameters=["api-version"],
                access_path="value",
                expect_array=True,
            )
            items = graph_builder.client.list(api_spec)
            AzureNetworkVirtualNetworkGateway.collect(items, graph_builder)

        def collect_local_network_gateway() -> None:
            from fix_plugin_azure.resource.network import AzureNetworkLocalNetworkGateway

            api_spec = AzureResourceSpec(
                service="network",
                version="2023-09-01",
                path=f"{self.id}/providers/Microsoft.Network/localNetworkGateways",
                path_parameters=[],
                query_parameters=["api-version"],
                access_path="value",
                expect_array=True,
            )
            items = graph_builder.client.list(api_spec)
            AzureNetworkLocalNetworkGateway.collect(items, graph_builder)

        def collect_network_gateway_connections() -> None:
            from fix_plugin_azure.resource.network import AzureNetworkVirtualNetworkGatewayConnection

            api_spec = AzureResourceSpec(
                service="network",
                version="2023-09-01",
                path=f"{self.id}/providers/Microsoft.Network/connections",
                path_parameters=[],
                query_parameters=["api-version"],
                access_path="value",
                expect_array=True,
            )
            items = graph_builder.client.list(api_spec)
            AzureNetworkVirtualNetworkGatewayConnection.collect(items, graph_builder)

        graph_builder.submit_work(service_name, collect_resources_in_group)
        graph_builder.submit_work(service_name, collect_network_gateways)
        graph_builder.submit_work(service_name, collect_local_network_gateway)
        graph_builder.submit_work(service_name, collect_network_gateway_connections)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if resource_ids := self._resource_ids_in_group:
            for resource_id in resource_ids:
                builder.add_edge(self, edge_type=EdgeType.default, clazz=MicrosoftResource, id=resource_id)


@define(eq=False, slots=False)
class AzureUsageName:
    kind: ClassVar[str] = "azure_usage_name"
    mapping: ClassVar[Dict[str, Bender]] = {"localized_value": S("localizedValue"), "value": S("value")}
    localized_value: Optional[str] = field(default=None, metadata={'description': 'Gets a localized string describing the resource name.'})  # fmt: skip
    value: Optional[str] = field(default=None, metadata={"description": "Gets a string describing the resource name."})


@define(eq=False, slots=False)
class AzureBaseUsage(PhantomBaseResource):
    kind: ClassVar[str] = "azure_usage"
    _kind_display: ClassVar[str] = "Azure Usage"
    _kind_service: ClassVar[Optional[str]] = "resources"
    _kind_description: ClassVar[str] = "Azure Usage represents the usage of a resource in an Azure subscription. It provides information about the current value of the usage, the limit of usage, and the unit of measurement. Azure Usage is used to track resource consumption and enforce usage limits, helping users manage costs and optimize resource utilization."  # fmt: skip
    mapping: ClassVar[Dict[str, Bender]] = {
        "name": S("name", "value"),  # inherited by BaseResource - name already defined there
        "usage_name": S("name") >> Bend(AzureUsageName.mapping),
        "current_value": S("currentValue"),
        "limit": S("limit"),
        "unit": S("unit"),
    }
    usage_name: Optional[AzureUsageName] = field(default=None, metadata={"description": "The name of the type of usage."})  # fmt: skip
    current_value: Optional[int] = field(default=None, metadata={"description": "The current value of the usage."})
    limit: Optional[int] = field(default=None, metadata={"description": "The limit of usage."})
    unit: Optional[str] = field(default=None, metadata={"description": "An enum describing the unit of measurement."})
    _expected_error_codes: ClassVar[Dict[str, Optional[str]]] = {"SubscriptionHasNoUsages": None}


@define(eq=False, slots=False)
class AzureExtendedLocation:
    kind: ClassVar[str] = "azure_extended_location"
    mapping: ClassVar[Dict[str, Bender]] = {"name": S("name"), "type": S("type")}
    name: Optional[str] = field(default=None, metadata={"description": "The name of the extended location."})
    type: Optional[str] = field(default=None, metadata={"description": "The type of extendedlocation."})


@define(eq=False, slots=False)
class AzureUserAssignedIdentity:
    kind: ClassVar[str] = "azure_user_assigned_identity"
    mapping: ClassVar[Dict[str, Bender]] = {
        "client_id": S("clientId"),
        "principal_id": S("principalId"),
        "object_id": S("objectId"),
        "resource_id": S("resourceId"),
    }
    client_id: Optional[str] = field(default=None, metadata={"description": "The client ID of the identity."})
    principal_id: Optional[str] = field(default=None, metadata={"description": "The principal ID of the identity."})
    object_id: Optional[str] = field(default=None, metadata={'description': 'The object ID of the user assigned identity.'})  # fmt: skip
    resource_id: Optional[str] = field(default=None, metadata={'description': 'The resource ID of the user assigned identity.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureUserIdentity:
    kind: ClassVar[str] = "azure_user_identity"
    mapping: ClassVar[Dict[str, Bender]] = {"client_id": S("clientId"), "principal_id": S("principalId")}
    client_id: Optional[str] = field(default=None, metadata={'description': 'the client identifier of the Service Principal which this identity represents.'})  # fmt: skip
    principal_id: Optional[str] = field(default=None, metadata={'description': 'the object identifier of the Service Principal which this identity represents.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureResourceIdentity:
    kind: ClassVar[str] = "azure_resource_identity"
    mapping: ClassVar[Dict[str, Bender]] = {
        "principal_id": S("principalId"),
        "tenant_id": S("tenantId"),
        "type": S("type"),
        "user_assigned_identities": S("userAssignedIdentities"),
    }
    principal_id: Optional[str] = field(default=None, metadata={'description': 'The Azure Active Directory principal id.'})  # fmt: skip
    tenant_id: Optional[str] = field(default=None, metadata={"description": "The Azure Active Directory tenant id."})
    type: Optional[str] = field(default=None, metadata={'description': 'The identity type. Set this to SystemAssigned in order to automatically create and assign an Azure Active Directory principal for the resource.'})  # fmt: skip
    user_assigned_identities: Optional[Dict[str, AzureUserIdentity]] = field(default=None, metadata={'description': 'The resource ids of the user assigned identities to use'})  # fmt: skip


@define(eq=False, slots=False)
class AzurePrincipalClient:
    kind: ClassVar[str] = "azure_principal_client"
    mapping: ClassVar[Dict[str, Bender]] = {"client_id": S("clientId"), "principal_id": S("principalId")}
    client_id: Optional[str] = field(default=None, metadata={'description': 'The client id of user assigned identity.'})  # fmt: skip
    principal_id: Optional[str] = field(default=None, metadata={'description': 'The principal id of user assigned identity.'})  # fmt: skip


@define(eq=False, slots=False)
class AzurePrivateLinkServiceConnectionState:
    kind: ClassVar[str] = "azure_private_link_service_connection_state"
    mapping: ClassVar[Dict[str, Bender]] = {
        "actions_required": S("actionsRequired"),
        "description": S("description"),
        "status": S("status"),
    }
    actions_required: Optional[str] = field(default=None, metadata={'description': 'A message indicating if changes on the service provider require any updates on the consumer.'})  # fmt: skip
    description: Optional[str] = field(default=None, metadata={'description': 'The reason for approval/rejection of the connection.'})  # fmt: skip
    status: Optional[str] = field(default=None, metadata={"description": "The private endpoint connection status."})


@define(eq=False, slots=False)
class AzureSubscriptionPolicies:
    kind: ClassVar[str] = "azure_subscription_policies"
    mapping: ClassVar[Dict[str, Bender]] = {
        "location_placement_id": S("locationPlacementId"),
        "quota_id": S("quotaId"),
        "spending_limit": S("spendingLimit"),
    }
    location_placement_id: Optional[str] = field(default=None, metadata={'description': 'The subscription location placement id. The id indicates which regions are visible for a subscription. For example, a subscription with a location placement id of public_2014-09-01 has access to azure public regions.'})  # fmt: skip
    quota_id: Optional[str] = field(default=None, metadata={"description": "The subscription quota id."})
    spending_limit: Optional[str] = field(default=None, metadata={"description": "The subscription spending limit."})


@define(eq=False, slots=False)
class AzureSubscription(MicrosoftResource, BaseAccount):
    kind: ClassVar[str] = "azure_subscription"
    _kind_display: ClassVar[str] = "Azure Subscription"
    _kind_service: ClassVar[str] = "resources"
    _kind_description: ClassVar[str] = "An Azure Subscription is a logical container for organizing and managing Microsoft Azure resources. It provides access to cloud services and defines usage limits and billing arrangements. Users can create, deploy, and control Azure resources within their subscription, while Microsoft tracks resource consumption and generates invoices based on the subscription's payment model."  # fmt: skip
    _docs_url: ClassVar[str] = (
        "https://learn.microsoft.com/en-us/azure/cost-management-billing/manage/create-subscription"
    )
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "account", "group": "management"}
    api_spec: ClassVar[AzureResourceSpec] = AzureResourceSpec(
        service="resources",
        version="2022-12-01",
        path="/subscriptions",
        path_parameters=[],
        query_parameters=["api-version"],
        access_path="value",
        expect_array=True,
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("subscriptionId"),
        "tags": S("tags", default={}),
        "authorization_source": S("authorizationSource"),
        "name": S("displayName"),
        "display_name": S("displayName"),
        "managed_by_tenants": S("managedByTenants", default=[]) >> ForallBend(S("tenantId")),
        "state": S("state"),
        "subscription_id": S("subscriptionId"),
        "subscription_policies": S("subscriptionPolicies") >> Bend(AzureSubscriptionPolicies.mapping),
        "tenant_id": S("tenantId"),
    }
    authorization_source: Optional[str] = field(default=None, metadata={'description': 'The authorization source of the request. Valid values are one or more combinations of legacy, rolebased, bypassed, direct and management. For example, legacy, rolebased.'})  # fmt: skip
    display_name: Optional[str] = field(default=None, metadata={"description": "The subscription display name."})
    managed_by_tenants: Optional[List[str]] = field(default=None, metadata={'description': 'An array containing the tenants managing the subscription.'})  # fmt: skip
    state: Optional[str] = field(default=None, metadata={'description': 'The subscription state. Possible values are enabled, warned, pastdue, disabled, and deleted.'})  # fmt: skip
    subscription_id: str = field(default="", metadata={"description": "The subscription id."})
    subscription_policies: Optional[AzureSubscriptionPolicies] = field(default=None, metadata={'description': 'Subscription policies.'})  # fmt: skip
    tenant_id: Optional[str] = field(default=None, metadata={"description": "The subscription tenant id."})
    account_name: Optional[str] = field(default=None, metadata={"description": "The account used to collect this subscription."})  # fmt: skip


@define(eq=False, slots=False)
class AzureSubResource:
    kind: ClassVar[str] = "azure_sub_resource"
    mapping: ClassVar[Dict[str, Bender]] = {"id": S("id")}
    id: Optional[str] = field(default=None, metadata={"description": "Resource id."})


@define(eq=False, slots=False)
class AzureChildResource:
    kind: ClassVar[str] = "azure_child_resource"
    mapping: ClassVar[Dict[str, Bender]] = {"etag": S("etag"), "id": S("id"), "name": S("name"), "type": S("type")}
    etag: Optional[str] = field(default=None, metadata={'description': 'A unique read-only string that changes whenever the resource is updated.'})  # fmt: skip
    type: Optional[str] = field(default=None, metadata={"description": "Resource type."})


@define(eq=False, slots=False)
class AzureSystemData:
    kind: ClassVar[str] = "azure_system_data"
    mapping: ClassVar[Dict[str, Bender]] = {
        "created_at": S("createdAt"),
        "created_by": S("createdBy"),
        "created_by_type": S("createdByType"),
        "last_modified_at": S("lastModifiedAt"),
        "last_modified_by": S("lastModifiedBy"),
        "last_modified_by_type": S("lastModifiedByType"),
    }
    created_at: Optional[datetime] = field(default=None, metadata={'description': 'The timestamp of resource creation (utc).'})  # fmt: skip
    created_by: Optional[str] = field(default=None, metadata={'description': 'The identity that created the resource.'})  # fmt: skip
    created_by_type: Optional[str] = field(default=None, metadata={'description': 'The type of identity that created the resource.'})  # fmt: skip
    last_modified_at: Optional[datetime] = field(default=None, metadata={'description': 'The type of identity that last modified the resource.'})  # fmt: skip
    last_modified_by: Optional[str] = field(default=None, metadata={'description': 'The identity that last modified the resource.'})  # fmt: skip
    last_modified_by_type: Optional[str] = field(default=None, metadata={'description': 'The type of identity that last modified the resource.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureTrackedResource:
    kind: ClassVar[str] = "azure_tracked_resource"
    mapping: ClassVar[Dict[str, Bender]] = {
        "location": S("location"),
        "system_data": S("systemData") >> Bend(AzureSystemData.mapping),
        "type": S("type"),
        "ctime": S("systemData", "createdAt"),
        "mtime": S("systemData", "lastModifiedAt"),
    }
    location: Optional[str] = field(default=None, metadata={'description': 'The geo-location where the resource lives'})  # fmt: skip
    system_data: Optional[AzureSystemData] = field(default=None, metadata={'description': 'Metadata pertaining to creation and last modification of the resource.'})  # fmt: skip
    type: Optional[str] = field(default=None, metadata={'description': 'The type of the resource. E.g. Microsoft.Compute/virtualMachines or Microsoft.Storage/storageAccounts '})  # fmt: skip


@define(eq=False, slots=False)
class AzureProxyResource:
    kind: ClassVar[str] = "azure_proxy_resource"
    mapping: ClassVar[Dict[str, Bender]] = {
        "system_data": S("systemData") >> Bend(AzureSystemData.mapping),
        "type": S("type"),
        "ctime": S("systemData", "createdAt"),
        "mtime": S("systemData", "lastModifiedAt"),
    }
    system_data: Optional[AzureSystemData] = field(default=None, metadata={'description': 'Metadata pertaining to creation and last modification of the resource.'})  # fmt: skip
    type: Optional[str] = field(default=None, metadata={'description': 'The type of the resource. E.g. Microsoft.Compute/virtualMachines or Microsoft.Storage/storageAccounts '})  # fmt: skip


@define(eq=False, slots=False)
class AzureManagedServiceIdentity:
    kind: ClassVar[str] = "azure_identity"
    mapping: ClassVar[Dict[str, Bender]] = {
        "client_id": S("clientId"),
        "principal_id": S("principalId"),
        "tenant_id": S("tenantId"),
        "type": S("type"),
        "user_assigned_identities": S("userAssignedIdentities"),
    }
    client_id: Optional[str] = field(default=None, metadata={'description': 'The client id of user assigned identity.'})  # fmt: skip
    principal_id: Optional[str] = field(default=None, metadata={'description': 'The principal ID of resource identity.'})  # fmt: skip
    tenant_id: Optional[str] = field(default=None, metadata={"description": "The tenant ID of resource."})
    type: Optional[str] = field(default=None, metadata={"description": "Type of managed service identity."})
    user_assigned_identities: Optional[Dict[str, AzureUserAssignedIdentity]] = field(default=None, metadata={'description': 'The list of user identities associated with the resource. The user identity dictionary key references will be ARM resource ids in the form: /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ManagedIdentity/userAssignedIdentities/{identityName} .'})  # fmt: skip


@define(eq=False, slots=False)
class AzureSkuCapacity:
    kind: ClassVar[str] = "azure_sku_capacity"
    mapping: ClassVar[Dict[str, Bender]] = {
        "default": S("default"),
        "elastic_maximum": S("elasticMaximum"),
        "maximum": S("maximum"),
        "minimum": S("minimum"),
        "scale_type": S("scaleType"),
    }
    default: Optional[int] = field(default=None, metadata={'description': 'Default number of workers for this App Service plan SKU.'})  # fmt: skip
    elastic_maximum: Optional[int] = field(default=None, metadata={'description': 'Maximum number of Elastic workers for this App Service plan SKU.'})  # fmt: skip
    maximum: Optional[int] = field(default=None, metadata={'description': 'Maximum number of workers for this App Service plan SKU.'})  # fmt: skip
    minimum: Optional[int] = field(default=None, metadata={'description': 'Minimum number of workers for this App Service plan SKU.'})  # fmt: skip
    scale_type: Optional[str] = field(default=None, metadata={'description': 'Available scale configurations for an App Service plan.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureCapability:
    kind: ClassVar[str] = "azure_capability"
    mapping: ClassVar[Dict[str, Bender]] = {"name": S("name"), "reason": S("reason"), "value": S("value")}
    name: Optional[str] = field(default=None, metadata={"description": "Name of the SKU capability."})
    reason: Optional[str] = field(default=None, metadata={"description": "Reason of the SKU capability."})
    value: Optional[str] = field(default=None, metadata={"description": "Value of the SKU capability."})


@define(eq=False, slots=False)
class AzureSku:
    kind: ClassVar[str] = "azure_sku"
    mapping: ClassVar[Dict[str, Bender]] = {
        "capabilities": S("capabilities") >> ForallBend(AzureCapability.mapping),
        "capacity": S("capacity"),
        "name": S("name"),
        "tier": S("tier"),
        "family": S("family"),
        "size": S("size"),
        "locations": S("locations"),
        "sku_capacity": S("skuCapacity") >> Bend(AzureSkuCapacity.mapping),
    }
    capacity: Optional[int] = field(default=None, metadata={'description': 'Specifies the number of virtual machines in the scale set.'})  # fmt: skip
    family: Optional[str] = field(default=None, metadata={"description": "The family of the sku."})
    name: Optional[str] = field(default=None, metadata={"description": "The sku name."})
    tier: Optional[str] = field(default=None, metadata={'description': 'Specifies the tier of virtual machines in a scale set. Possible values: **standard** **basic**.'})  # fmt: skip
    size: Optional[str] = field(default=None, metadata={"description": "Size of the particular SKU"})


@define(eq=False, slots=False)
class AzurePrivateEndpointConnection:
    kind: ClassVar[str] = "azure_private_endpoint_connection"
    mapping: ClassVar[Dict[str, Bender]] = {
        "group_ids": S("properties", "groupIds"),
        "id": S("id"),
        "name": S("name"),
        "private_endpoint": S("properties", "privateEndpoint", "id"),
        "private_link_service_connection_state": S("properties", "privateLinkServiceConnectionState")
        >> Bend(AzurePrivateLinkServiceConnectionState.mapping),
        "provisioning_state": S("properties", "provisioningState"),
        "system_data": S("systemData") >> Bend(AzureSystemData.mapping),
        "type": S("type"),
    }
    group_ids: Optional[List[str]] = field(default=None, metadata={'description': 'The group ids for the private endpoint resource.'})  # fmt: skip
    id: Optional[str] = field(default=None, metadata={'description': 'Fully qualified resource ID for the resource. E.g. /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName} '})  # fmt: skip
    name: Optional[str] = field(default=None, metadata={"description": "The name of the resource"})
    private_endpoint: Optional[str] = field(default=None, metadata={"description": "The private endpoint resource."})
    private_link_service_connection_state: Optional[AzurePrivateLinkServiceConnectionState] = field(default=None, metadata={'description': 'A collection of information about the state of the connection between service consumer and provider.'})  # fmt: skip
    system_data: Optional[AzureSystemData] = field(default=None, metadata={'description': 'Metadata pertaining to creation and last modification of the resource.'})  # fmt: skip
    type: Optional[str] = field(default=None, metadata={'description': 'The type of the resource. E.g. Microsoft.Compute/virtualMachines or Microsoft.Storage/storageAccounts '})  # fmt: skip


class GraphBuilder:
    def __init__(
        self,
        graph: Graph,
        cloud: Cloud,
        account: BaseAccount,
        client: MicrosoftClient,
        executor: ExecutorQueue,
        core_feedback: CoreFeedback,
        config: AzureConfig,
        location_lookup: Optional[Dict[str, BaseRegion]] = None,
        location: Optional[BaseRegion] = None,
        graph_access_lock: Optional[RWLock] = None,
        last_run_started_at: Optional[datetime] = None,
        after_collect_actions: Optional[List[Callable[[], Any]]] = None,
    ) -> None:
        self.graph = graph
        self.cloud = cloud
        self.account = account
        self.client = client
        self.executor = executor
        self.core_feedback = core_feedback
        self.location_lookup = location_lookup or {}
        self.location = location
        self.graph_access_lock = graph_access_lock or RWLock()
        self.name = f"Azure:{account.name}"
        self.config = config
        self.last_run_started_at = last_run_started_at
        self.created_at = utc()
        self.after_collect_actions = after_collect_actions if after_collect_actions is not None else []

        if last_run_started_at:
            now = utc()

            # limit the metrics to the last hour
            if now - last_run_started_at > timedelta(hours=2):
                start = now - timedelta(hours=2)
            else:
                start = last_run_started_at

            delta = now - start

            min_delta = max(delta, timedelta(seconds=60))
            # in case the last collection happened too quickly, raise the metrics timedelta to 60s,
            # otherwise we get an error from Azure
            if min_delta != delta:
                start = now - min_delta
                delta = min_delta
        else:
            now = utc()
            delta = timedelta(hours=1)
            start = now - delta

        self.metrics_start = start
        self.metrics_delta = delta

    def submit_work(self, service: str, fn: Callable[..., T], *args: Any, **kwargs: Any) -> Future[T]:
        """
        Use this method for work that can be done in parallel.
        Example: fetching tags of a resource.
        """
        return self.executor.submit_work(service, fn, *args, **kwargs)

    def node(
        self,
        clazz: Optional[Type[MicrosoftResourceType]] = None,
        filter_fn: Optional[Callable[[Any], bool]] = None,
        **node: Any,
    ) -> Optional[MicrosoftResourceType]:
        """
        Returns first node on the graph that is of given `clazz`
        and/or conforms to the `filter` and matches attributes given in `**node`.
        """
        if isinstance(nd := node.get("node"), MicrosoftResource):
            return nd  # type: ignore
        with self.graph_access_lock.read_access:
            for n in self.graph:
                if clazz and not isinstance(n, clazz):
                    continue
                if (filter_fn(n) if filter_fn else True) and all(
                    case_insensitive_eq(getattr(n, k, None), v) for k, v in node.items()
                ):
                    return n  # type: ignore
        return None

    def nodes(
        self,
        clazz: Optional[Type[MicrosoftResourceType]] = None,
        filter: Optional[Callable[[Any], bool]] = None,
        **node: Any,
    ) -> List[MicrosoftResourceType]:
        """
        Returns list of all nodes on the graph that are of given `clazz`
        and/or conform to the `filter` and match attributes given in `**node`.
        """
        result: List[MicrosoftResourceType] = []
        if isinstance(nd := node.get("node"), MicrosoftResource):
            result.append(nd)  # type: ignore
        with self.graph_access_lock.read_access:
            for n in self.graph:
                if clazz and not isinstance(n, clazz):
                    continue
                if (filter(n) if filter else True) and all(getattr(n, k, None) == v for k, v in node.items()):
                    result.append(n)
        return result

    def add_node(self, node: MicrosoftResourceType, source: Optional[Json] = None) -> Optional[MicrosoftResourceType]:
        log.debug(f"{self.name}: add node {node}")
        node._cloud = self.cloud
        node._account = self.account

        last_edge_key: Optional[EdgeKey] = None  # indicates if this node has been connected

        # add edge from location to resource
        if self.location:
            last_edge_key = self.add_edge(self.location, node=node)
        elif (source) and (source_location := source.get("location")):
            # reference the location node if available
            if location := self.location_lookup.get(source_location):
                node._region = location
                last_edge_key = self.add_edge(location, node=node)
        elif (node_location := getattr(node, "location", None)) is not None:
            # reference the location node if available in resource property
            if location := self.location_lookup.get(node_location):
                node._region = location
                last_edge_key = self.add_edge(location, node=node)
        if source and "locations" in source:
            for loc in source["locations"]:
                # reference the location node if available
                if location := self.location_lookup.get(loc):
                    last_edge_key = self.add_edge(location, node=node)
                    node._region = location  # TODO: how to handle multiple locations?
        elif last_edge_key is None:
            # add edge from subscription to resource
            last_edge_key = self.add_edge(self.account, node=node)

        # create provider link
        if node._provider_link is None and node._create_provider_link:
            node._provider_link = f"https://portal.azure.com/#@/resource{node.id}/overview"

        if last_edge_key is not None:
            with self.graph_access_lock.write_access:
                self.graph.add_node(node, source=source or {})
            return node
        else:
            log.debug(f"Node is not attached in the graph. Ignore. Source: {node}")
            return None

    def add_edge(
        self,
        from_node: BaseResource,
        edge_type: EdgeType = EdgeType.default,
        reverse: bool = False,
        filter_fn: Optional[Callable[[Any], bool]] = None,
        **to_node: Any,
    ) -> Optional[EdgeKey]:
        """
        Creates edge between `from_node` and another node using `GraphBuilder.node(filter, **to_node)`.
        """
        to_n = self.node(filter_fn=filter_fn, **to_node)
        if isinstance(from_node, MicrosoftResource) and isinstance(to_n, MicrosoftResource):
            start, end = (to_n, from_node) if reverse else (from_node, to_n)
            log.debug(f"{self.name}: add edge: {start} -> {end} [{edge_type}]")
            with self.graph_access_lock.write_access:
                return self.graph.add_edge(start, end, edge_type=edge_type)
        return None

    def add_edges(
        self,
        from_node: BaseResource,
        edge_type: EdgeType = EdgeType.default,
        reverse: bool = False,
        filter_fn: Optional[Callable[[Any], bool]] = None,
        **to_nodes: Any,
    ) -> None:
        """
        Creates edges between `from_node` and all nodes found with `GraphBuilder.nodes(filter, **to_node)`.
        """
        node: Type[MicrosoftResource]
        for node in self.nodes(filter=filter_fn, **to_nodes):
            self.add_edge(from_node, edge_type, reverse, node=node)

    def dependant_node(
        self, from_node: BaseResource, reverse: bool = False, delete_same_as_default: bool = False, **to_node: Any
    ) -> None:
        to_n = self.node(**to_node)
        if isinstance(from_node, MicrosoftResource) and isinstance(to_n, MicrosoftResource):
            start, end = (to_n, from_node) if reverse else (from_node, to_n)
            log.debug(f"{self.name}: add edge: {start} -> {end} [default]")
            with self.graph_access_lock.write_access:
                self.graph.add_edge(start, end, edge_type=EdgeType.default)
                if delete_same_as_default:
                    start, end = end, start
                log.debug(f"{self.name}: add edge: {end} -> {start} [delete]")
                self.graph.add_edge(end, start, edge_type=EdgeType.delete)

    def add_deferred_edge(
        self,
        from_node: Union[BaseResource, NodeSelector],
        to_node: Union[BaseResource, NodeSelector],
        edge_type: EdgeType = EdgeType.default,
    ) -> None:
        start: NodeSelector = ByNodeId(from_node.chksum) if isinstance(from_node, BaseResource) else from_node
        end: NodeSelector = ByNodeId(to_node.chksum) if isinstance(to_node, BaseResource) else to_node
        self.graph.add_deferred_edge(start, end, edge_type)

    def resources_of(self, resource_type: Type[MicrosoftResourceType]) -> List[MicrosoftResourceType]:
        with self.graph_access_lock.read_access:
            return [n for n in self.graph.nodes if isinstance(n, resource_type)]

    def edges_of(
        self,
        from_type: Type[MicrosoftResource],
        to_type: Type[MicrosoftResource],
        edge_type: EdgeType = EdgeType.default,
    ) -> List[EdgeKey]:
        with self.graph_access_lock.read_access:
            return [
                key
                for (from_node, to_node, key) in self.graph.edges
                if isinstance(from_node, from_type) and isinstance(to_node, to_type) and key.edge_type == edge_type
            ]

    def with_location(self, location: BaseRegion) -> GraphBuilder:
        return GraphBuilder(
            graph=self.graph,
            cloud=self.cloud,
            account=self.account,
            client=self.client.for_location(location.safe_name),
            executor=self.executor,
            core_feedback=self.core_feedback,
            location_lookup=self.location_lookup,
            location=location,
            graph_access_lock=self.graph_access_lock,
            config=self.config,
            last_run_started_at=self.last_run_started_at,
            after_collect_actions=self.after_collect_actions,
        )


resources: List[Type[MicrosoftResource]] = [
    AzureResourceGroup,
]
