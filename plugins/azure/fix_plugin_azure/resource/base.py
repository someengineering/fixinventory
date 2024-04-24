from __future__ import annotations

import logging
from concurrent.futures import Future
from datetime import datetime, timedelta
from threading import Lock
from typing import Any, ClassVar, Dict, Optional, TypeVar, List, Type, Callable, cast

from attr import define, field
from azure.core.utils import CaseInsensitiveDict
from azure.identity import DefaultAzureCredential

from fix_plugin_azure.azure_client import AzureApiSpec, AzureClient
from fix_plugin_azure.config import AzureConfig, AzureCredentials
from fixlib.utils import utc
from fixlib.baseresources import BaseResource, Cloud, EdgeType, BaseAccount, BaseRegion, ModelReference
from fixlib.core.actions import CoreFeedback
from fixlib.graph import Graph, EdgeKey
from fixlib.json_bender import Bender, bend, S, ForallBend, Bend
from fixlib.threading import ExecutorQueue
from fixlib.types import Json
from fixlib.config import current_config

log = logging.getLogger("fix.plugins.azure")


def get_client(subscription_id: str) -> AzureClient:
    config = current_config()
    azure_config = cast(AzureConfig, config.azure)
    #  Taking credentials from the config if access through the environment cannot be provided
    if azure_config.accounts and (account := azure_config.accounts.get(subscription_id)):
        credential = account.credentials()
    else:
        credential = DefaultAzureCredential()
    return AzureClient.create(config=azure_config, credential=credential, subscription_id=subscription_id)


T = TypeVar("T")


class AzureResource(BaseResource):
    kind: ClassVar[str] = "azure_resource"
    # The mapping to transform the incoming API json into the internal representation.
    mapping: ClassVar[Dict[str, Bender]] = {}
    # Which API to call and what to expect in the result.
    api_spec: ClassVar[Optional[AzureApiSpec]] = None
    # Check if we want to create provider link. Default is True
    _is_provider_link: bool = True

    def resource_subscription_id(self) -> Optional[str]:
        return self.extract_part("subscriptionId")

    def extract_part(self, part: str) -> Optional[str]:
        """
        Extracts a specific part from a resource ID.

        The function takes a resource ID and a specified part to extract, such as 'subscriptionId'.
        The resource ID is expected to follow the Azure Resource Manager path format.

        Example:
        For the resource ID "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/...",
        calling extract_part("subscriptionId") would return the value within the curly braces,
        representing the subscription ID.

        Parameters:
        - part (str): The part to extract from the resource ID.

        Returns:
        str: The extracted part of the resource ID.
        """
        id_parts = self.id.split("/")

        if part == "subscriptionId":
            if "subscriptions" not in id_parts:
                return None
            if index := id_parts.index("subscriptions"):
                return id_parts[index + 1]
            return None
        else:
            return None

    def delete(self, graph: Graph) -> bool:
        """
        Deletes a resource by ID.

        Returns:
        bool: True if the resource was successfully deleted; False otherwise.
        """
        subscription_id = self.resource_subscription_id()
        if subscription_id is None:
            log.warning("Failed to delete resource. Subscription ID is not available.")
            return False
        return get_client(subscription_id).delete(self.id)

    def delete_tag(self, key: str) -> bool:
        """Deletes a tag value.

        This method removes a specific value from a tag associated with a subscription, while keeping the tag itself intact.
        The tag remains on the account, but the specified value will be deleted.
        """
        subscription_id = self.resource_subscription_id()
        if subscription_id is None:
            log.warning("Failed to delete tag. Subscription ID is not available.")
            return False
        return get_client(subscription_id).delete_resource_tag(tag_name=key, resource_id=self.id)

    def update_tag(self, key: str, value: str) -> bool:
        """Creates a tag value. The name of the tag must already exist.

        This method allows for the creation or update of a tag value associated with the specified tag name.
        The tag name must already exist for the operation to be successful.
        """
        subscription_id = self.resource_subscription_id()
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
        cls: Type[AzureResource], builder: GraphBuilder, collected_resources: List[AzureResourceType]
    ) -> None:
        # Default behavior: do nothing
        pass

    @classmethod
    def collect_resources(
        cls: Type[AzureResourceType], builder: GraphBuilder, **kwargs: Any
    ) -> List[AzureResourceType]:
        # Default behavior: in case the class has an ApiSpec, call the api and call collect.
        log.debug(f"[Azure:{builder.subscription.id}] Collecting {cls.__name__} with ({kwargs})")
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
        cls: Type[AzureResourceType],
        raw: List[Json],
        builder: GraphBuilder,
    ) -> List[AzureResourceType]:
        # Default behavior: iterate over json snippets and for each:
        # - bend the json
        # - transform the result into a resource
        # - add the resource to the graph
        # In case additional work needs to be done, override this method.
        result: List[AzureResourceType] = []
        for js in raw:
            # map from api
            instance = cls.from_api(js)
            instance.pre_process(builder, js)
            # add to graph
            if (added := builder.add_node(instance, js)) is not None:
                # post process
                added.post_process(builder, js)
                result.append(added)
        return result

    @classmethod
    def from_api(cls: Type[AzureResourceType], json: Json) -> AzureResourceType:
        mapped = bend(cls.mapping, json)
        return cls.from_json(mapped)

    @classmethod
    def called_collect_apis(cls) -> List[AzureApiSpec]:
        # The default implementation will return the defined api_spec if defined, otherwise an empty list.
        # In case your resource needs more than this api call, please override this method and return the proper list.
        if spec := cls.api_spec:
            return [spec]
        else:
            return []

    @classmethod
    def called_mutator_apis(cls) -> List[AzureApiSpec]:
        return []


AzureResourceType = TypeVar("AzureResourceType", bound=AzureResource)


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
class AzureLocation(AzureResource, BaseRegion):
    kind: ClassVar[str] = "azure_location"
    api_spec: ClassVar[AzureApiSpec] = AzureApiSpec(
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
    }
    availability_zone_mappings: Optional[List[AzureAvailabilityZoneMappings]] = field(default=None, metadata={'description': 'The availability zone mappings for this region.'})  # fmt: skip
    display_name: Optional[str] = field(default=None, metadata={"description": "The display name of the location."})
    location_metadata: Optional[AzureLocationMetadata] = field(default=None, metadata={'description': 'Location metadata information.'})  # fmt: skip
    regional_display_name: Optional[str] = field(default=None, metadata={'description': 'The display name of the location and its region.'})  # fmt: skip
    subscription_id: Optional[str] = field(default=None, metadata={"description": "The subscription id."})


@define(eq=False, slots=False)
class AzureResourceGroup(AzureResource):
    kind: ClassVar[str] = "azure_resource_group"
    api_spec: ClassVar[AzureApiSpec] = AzureApiSpec(
        service="resources",
        version="2022-09-01",
        path="/subscriptions/{subscriptionId}/resourcegroups",
        path_parameters=["subscriptionId"],
        query_parameters=["api-version"],
        access_path="value",
        expect_array=True,
    )
    reference_kinds: ClassVar[ModelReference] = {
        "successors": {"default": ["azure_resource"]},
    }
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "managed_by": S("managedBy"),
        "provisioning_state": S("properties", "provisioningState"),
    }
    managed_by: Optional[str] = field(default=None, metadata={'description': 'The id of the resource that manages this resource group.'})  # fmt: skip
    provisioning_state: Optional[str] = field(default=None, metadata={"description": "The resource group properties."})
    _resource_ids_in_group: Optional[List[str]] = None

    def post_process(self, graph_builder: GraphBuilder, source: Json) -> None:
        def collect_resources_in_group() -> None:
            resources_api_spec = AzureApiSpec(
                service="resources",
                version="2021-04-01",
                path="/subscriptions/{subscriptionId}/resourceGroups/" + f"{self.safe_name}/resources",
                path_parameters=["subscriptionId"],
                query_parameters=["api-version"],
                access_path="value",
                expect_array=True,
            )

            self._resource_ids_in_group = [r["id"] for r in graph_builder.client.list(resources_api_spec)]

        graph_builder.submit_work("azure_resource_group", collect_resources_in_group)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if resource_ids := self._resource_ids_in_group:
            for resource_id in resource_ids:
                builder.add_edge(self, edge_type=EdgeType.default, clazz=AzureResource, id=resource_id)


@define(eq=False, slots=False)
class AzureExtendedLocation:
    kind: ClassVar[str] = "azure_extended_location"
    mapping: ClassVar[Dict[str, Bender]] = {"name": S("name"), "type": S("type")}
    name: Optional[str] = field(default=None, metadata={"description": "The name of the extended location."})
    type: Optional[str] = field(default=None, metadata={"description": "The type of extendedlocation."})


@define(eq=False, slots=False)
class AzurePrincipalidClientid:
    kind: ClassVar[str] = "azure_principalid_clientid"
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
class AzureSubscription(AzureResource, BaseAccount):
    kind: ClassVar[str] = "azure_subscription"
    api_spec: ClassVar[AzureApiSpec] = AzureApiSpec(
        service="resources",
        version="2022-12-01",
        path="/subscriptions",
        path_parameters=[],
        query_parameters=["api-version"],
        access_path="value",
        expect_array=True,
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "tags": S("tags", default={}),
        "authorization_source": S("authorizationSource"),
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

    @classmethod
    def list_subscriptions(cls, config: AzureConfig, credentials: AzureCredentials) -> List[AzureSubscription]:
        client = AzureClient.create(config, credentials, "global")
        return [cls.from_api(js) for js in client.list(cls.api_spec)]


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
class AzureSku:
    kind: ClassVar[str] = "azure_sku"
    mapping: ClassVar[Dict[str, Bender]] = {
        "capacity": S("capacity"),
        "name": S("name"),
        "tier": S("tier"),
        "family": S("family"),
    }
    capacity: Optional[int] = field(default=None, metadata={'description': 'Specifies the number of virtual machines in the scale set.'})  # fmt: skip
    family: Optional[str] = field(default=None, metadata={"description": "The family of the sku."})
    name: Optional[str] = field(default=None, metadata={"description": "The sku name."})
    tier: Optional[str] = field(default=None, metadata={'description': 'Specifies the tier of virtual machines in a scale set. Possible values: **standard** **basic**.'})  # fmt: skip


class GraphBuilder:
    def __init__(
        self,
        graph: Graph,
        cloud: Cloud,
        subscription: AzureSubscription,
        client: AzureClient,
        executor: ExecutorQueue,
        core_feedback: CoreFeedback,
        config: AzureConfig,
        location_lookup: Optional[Dict[str, AzureLocation]] = None,
        location: Optional[AzureLocation] = None,
        graph_nodes_access: Optional[Lock] = None,
        graph_edges_access: Optional[Lock] = None,
        last_run_started_at: Optional[datetime] = None,
    ) -> None:
        self.graph = graph
        self.cloud = cloud
        self.subscription = subscription
        self.client = client
        self.executor = executor
        self.core_feedback = core_feedback
        self.location_lookup = location_lookup or {}
        self.location = location
        self.graph_nodes_access = graph_nodes_access or Lock()
        self.graph_edges_access = graph_edges_access or Lock()
        self.name = f"Azure:{subscription.name}"
        self.config = config
        self.last_run_started_at = last_run_started_at
        self.created_at = utc()

        if last_run_started_at:
            now = utc()
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
        # Converting the total seconds in 'delta' to minutes for further compute interval
        self.metrics_delta = delta.total_seconds() / 60

    def submit_work(self, service: str, fn: Callable[..., T], *args: Any, **kwargs: Any) -> Future[T]:
        """
        Use this method for work that can be done in parallel.
        Example: fetching tags of a resource.
        """
        return self.executor.submit_work(service, fn, *args, **kwargs)

    def node(
        self,
        clazz: Optional[Type[AzureResourceType]] = None,
        filter_fn: Optional[Callable[[Any], bool]] = None,
        **node: Any,
    ) -> Optional[AzureResourceType]:
        """
        Returns first node on the graph that is of given `clazz`
        and/or conforms to the `filter` and matches attributes given in `**node`.
        """
        if isinstance(nd := node.get("node"), AzureResource):
            return nd  # type: ignore
        with self.graph_nodes_access:
            for n in self.graph:
                if clazz and not isinstance(n, clazz):
                    continue
                if (filter_fn(n) if filter_fn else True) and all(getattr(n, k, None) == v for k, v in node.items()):
                    return n  # type: ignore
        return None

    def nodes(
        self,
        clazz: Optional[Type[AzureResourceType]] = None,
        filter: Optional[Callable[[Any], bool]] = None,
        **node: Any,
    ) -> List[AzureResourceType]:
        """
        Returns list of all nodes on the graph that are of given `clazz`
        and/or conform to the `filter` and match attributes given in `**node`.
        """
        result: List[AzureResourceType] = []
        if isinstance(nd := node.get("node"), AzureResource):
            result.append(nd)  # type: ignore
        with self.graph_nodes_access:
            for n in self.graph:
                if clazz and not isinstance(n, clazz):
                    continue
                if (filter(n) if filter else True) and all(getattr(n, k, None) == v for k, v in node.items()):
                    result.append(n)
        return result

    def add_node(self, node: AzureResourceType, source: Optional[Json] = None) -> Optional[AzureResourceType]:
        log.debug(f"{self.name}: add node {node}")
        node._cloud = self.cloud
        node._account = self.subscription

        last_edge_key: Optional[EdgeKey] = None  # indicates if this node has been connected

        # add edge from location to resource
        if self.location:
            last_edge_key = self.add_edge(self.location, node=node)
        elif source and "location" in source:
            # reference the location node if available
            if location := self.location_lookup.get(source["location"]):
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
            last_edge_key = self.add_edge(self.subscription, node=node)

        # create provider link
        if node._metadata.get("provider_link") is None and node._is_provider_link:
            node._metadata["provider_link"] = f"https://portal.azure.com/#@/resource{node.id}/overview"

        if last_edge_key is not None:
            with self.graph_nodes_access:
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
        if isinstance(from_node, AzureResource) and isinstance(to_n, AzureResource):
            start, end = (to_n, from_node) if reverse else (from_node, to_n)
            log.debug(f"{self.name}: add edge: {start} -> {end} [{edge_type}]")
            with self.graph_edges_access:
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
        node: Type[AzureResource]
        for node in self.nodes(filter=filter_fn, **to_nodes):
            self.add_edge(from_node, edge_type, reverse, node=node)

    def dependant_node(
        self, from_node: BaseResource, reverse: bool = False, delete_same_as_default: bool = False, **to_node: Any
    ) -> None:
        to_n = self.node(**to_node)
        if isinstance(from_node, AzureResource) and isinstance(to_n, AzureResource):
            start, end = (to_n, from_node) if reverse else (from_node, to_n)
            log.debug(f"{self.name}: add edge: {start} -> {end} [default]")
            with self.graph_edges_access:
                self.graph.add_edge(start, end, edge_type=EdgeType.default)
                if delete_same_as_default:
                    start, end = end, start
                log.debug(f"{self.name}: add edge: {end} -> {start} [delete]")
                self.graph.add_edge(end, start, edge_type=EdgeType.delete)

    def resources_of(self, resource_type: Type[AzureResourceType]) -> List[AzureResourceType]:
        with self.graph_nodes_access:
            return [n for n in self.graph.nodes if isinstance(n, resource_type)]

    def edges_of(
        self, from_type: Type[AzureResource], to_type: Type[AzureResource], edge_type: EdgeType = EdgeType.default
    ) -> List[EdgeKey]:
        with self.graph_edges_access:
            return [
                key
                for (from_node, to_node, key) in self.graph.edges
                if isinstance(from_node, from_type) and isinstance(to_node, to_type) and key.edge_type == edge_type
            ]

    def fetch_locations(self) -> List[AzureLocation]:
        locations = AzureLocation.collect_resources(self)
        self.location_lookup = CaseInsensitiveDict({loc.safe_name: loc for loc in locations})  # type: ignore
        return locations

    def with_location(self, location: AzureLocation) -> GraphBuilder:
        return GraphBuilder(
            graph=self.graph,
            cloud=self.cloud,
            subscription=self.subscription,
            client=self.client.for_location(location.safe_name),
            executor=self.executor,
            core_feedback=self.core_feedback,
            location_lookup=self.location_lookup,
            location=location,
            graph_nodes_access=self.graph_nodes_access,
            graph_edges_access=self.graph_edges_access,
            config=self.config,
        )


resources: List[Type[AzureResource]] = [AzureResourceGroup]
