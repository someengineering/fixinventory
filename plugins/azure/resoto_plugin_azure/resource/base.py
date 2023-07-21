from __future__ import annotations

import logging
from concurrent.futures import Future
from threading import Lock
from typing import Any, ClassVar, Dict, Optional, TypeVar, List, Type, Callable

from attr import define, field
from azure.core.utils import CaseInsensitiveDict

from resoto_plugin_azure.azure_client import AzureApiSpec, AzureClient
from resoto_plugin_azure.config import AzureCredentials
from resotolib.baseresources import BaseResource, Cloud, EdgeType, BaseAccount, BaseRegion
from resotolib.core.actions import CoreFeedback
from resotolib.graph import Graph, EdgeKey
from resotolib.json_bender import Bender, bend, S, ForallBend, Bend
from resotolib.threading import ExecutorQueue
from resotolib.types import Json

log = logging.getLogger("resoto.plugins.azure")
T = TypeVar("T")


class AzureResource(BaseResource):
    kind: ClassVar[str] = "azure_resource"
    # The mapping to transform the incoming API json into the internal representation.
    mapping: ClassVar[Dict[str, Bender]] = {}
    # Which API to call and what to expect in the result.
    api_spec: ClassVar[Optional[AzureApiSpec]] = None

    def delete(self, graph: Any) -> bool:
        # TODO: implement me.
        # get_client().delete(self.id)
        return False

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

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        # Default behavior: add resource to the namespace
        pass

    @classmethod
    def collect_resources(
        cls: Type[AzureResourceType], builder: GraphBuilder, **kwargs: Any
    ) -> List[AzureResourceType]:
        # Default behavior: in case the class has an ApiSpec, call the api and call collect.
        log.debug(f"[Azure:{builder.subscription.id}] Collecting {cls.__name__} with ({kwargs})")
        if spec := cls.api_spec:
            # TODO: add error handling
            items = builder.client.list(spec, **kwargs)
            return cls.collect(items, builder)
        return []

    @classmethod
    def collect(cls: Type[AzureResourceType], raw: List[Json], builder: GraphBuilder) -> List[AzureResourceType]:
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
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "managed_by": S("managedBy"),
        "provisioning_state": S("properties", "provisioningState"),
    }
    managed_by: Optional[str] = field(default=None, metadata={'description': 'The id of the resource that manages this resource group.'})  # fmt: skip
    provisioning_state: Optional[str] = field(default=None, metadata={"description": "The resource group properties."})


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
    def list_subscriptions(cls, credentials: AzureCredentials) -> List[AzureSubscription]:
        client = AzureClient.create(credentials, "global")
        return [cls.from_api(js) for js in client.list(cls.api_spec)]


class GraphBuilder:
    def __init__(
        self,
        graph: Graph,
        cloud: Cloud,
        subscription: AzureSubscription,
        client: AzureClient,
        executor: ExecutorQueue,
        core_feedback: CoreFeedback,
        location_lookup: Optional[Dict[str, AzureLocation]] = None,
        location: Optional[AzureLocation] = None,
        graph_nodes_access: Optional[Lock] = None,
        graph_edges_access: Optional[Lock] = None,
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

    def submit_work(self, fn: Callable[..., T], *args: Any, **kwargs: Any) -> Future[T]:
        """
        Use this method for work that can be done in parallel.
        Example: fetching tags of a resource.
        """
        return self.executor.submit_work("azure_all", fn, *args, **kwargs)

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
        )
