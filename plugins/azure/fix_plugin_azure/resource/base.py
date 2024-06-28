from __future__ import annotations

import logging
from concurrent.futures import Future
from datetime import datetime, timedelta
from typing import Any, ClassVar, Dict, Optional, TypeVar, List, Type, Callable, cast

from attr import define, field
from azure.identity import DefaultAzureCredential

from fix_plugin_azure.azure_client import AzureResourceSpec, MicrosoftClient, MicrosoftRestSpec
from fix_plugin_azure.config import AzureConfig
from fixlib.baseresources import(
    BaseGroup,
    BaseDNSRecordSet,
    BaseDNSZone,
    BaseInstanceProfile,
    BaseOrganizationalRoot,
    BaseOrganizationalUnit,
    BaseResource, BaseRole, BaseUser,
    Cloud,
    EdgeType,
    BaseAccount,
    BaseRegion,
    ModelReference,
)
from fixlib.config import current_config
from fixlib.core.actions import CoreFeedback
from fixlib.graph import Graph, EdgeKey
from fixlib.json_bender import Bender, bend, S, ForallBend, Bend
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


class MicrosoftResource(BaseResource):
    kind: ClassVar[str] = "microsoft_resource"
    # The mapping to transform the incoming API json into the internal representation.
    mapping: ClassVar[Dict[str, Bender]] = {}
    # Which API to call and what to expect in the result.
    api_spec: ClassVar[Optional[MicrosoftRestSpec]] = None
    # Check if we want to create provider link. Default is True
    _is_provider_link: ClassVar[bool] = True
    # Azure common properties
    etag: Optional[str] = field(default=None, metadata={'description': 'A unique read-only string that changes whenever the resource is updated.'})  # fmt: skip
    provisioning_state: Optional[str] = field(default=None, metadata={'description': 'The current provisioning state.'})  # fmt: skip

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
            instance = cls.from_api(js)
            instance.pre_process(builder, js)
            # add to graph
            if (added := builder.add_node(instance, js)) is not None:
                # post process
                added.post_process(builder, js)
                result.append(added)
        return result

    @classmethod
    def from_api(cls: Type[MicrosoftResourceType], json: Json) -> MicrosoftResourceType:
        mapped = bend(cls.mapping, json)
        return cls.from_json(mapped)

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
class AzureMxRecord:
    kind: ClassVar[str] = "azure_mx_record"
    mapping: ClassVar[Dict[str, Bender]] = {"exchange": S("exchange"), "preference": S("preference")}
    exchange: Optional[str] = field(default=None, metadata={'description': 'The domain name of the mail host for this MX record.'})  # fmt: skip
    preference: Optional[int] = field(default=None, metadata={'description': 'The preference value for this MX record.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureSrvRecord:
    kind: ClassVar[str] = "azure_srv_record"
    mapping: ClassVar[Dict[str, Bender]] = {
        "port": S("port"),
        "priority": S("priority"),
        "target": S("target"),
        "weight": S("weight"),
    }
    port: Optional[int] = field(default=None, metadata={"description": "The port value for this SRV record."})
    priority: Optional[int] = field(default=None, metadata={"description": "The priority value for this SRV record."})
    target: Optional[str] = field(default=None, metadata={'description': 'The target domain name for this SRV record.'})  # fmt: skip
    weight: Optional[int] = field(default=None, metadata={"description": "The weight value for this SRV record."})


@define(eq=False, slots=False)
class AzureTxtRecord:
    kind: ClassVar[str] = "azure_txt_record"
    mapping: ClassVar[Dict[str, Bender]] = {"value": S("value")}
    value: Optional[List[str]] = field(default=None, metadata={"description": "The text value of this TXT record."})


@define(eq=False, slots=False)
class AzureSoaRecord:
    kind: ClassVar[str] = "azure_soa_record"
    mapping: ClassVar[Dict[str, Bender]] = {
        "email": S("email"),
        "expire_time": S("expireTime"),
        "host": S("host"),
        "minimum_ttl": S("minimumTTL"),
        "refresh_time": S("refreshTime"),
        "retry_time": S("retryTime"),
        "serial_number": S("serialNumber"),
    }
    email: Optional[str] = field(default=None, metadata={"description": "The email contact for this SOA record."})
    expire_time: Optional[int] = field(default=None, metadata={"description": "The expire time for this SOA record."})
    host: Optional[str] = field(default=None, metadata={'description': 'The domain name of the authoritative name server for this SOA record.'})  # fmt: skip
    minimum_ttl: Optional[int] = field(default=None, metadata={'description': 'The minimum value for this SOA record. By convention this is used to determine the negative caching duration.'})  # fmt: skip
    refresh_time: Optional[int] = field(default=None, metadata={'description': 'The refresh value for this SOA record.'})  # fmt: skip
    retry_time: Optional[int] = field(default=None, metadata={"description": "The retry time for this SOA record."})
    serial_number: Optional[int] = field(default=None, metadata={'description': 'The serial number for this SOA record.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureCaaRecord:
    kind: ClassVar[str] = "azure_caa_record"
    mapping: ClassVar[Dict[str, Bender]] = {"flags": S("flags"), "tag": S("tag"), "value": S("value")}
    flags: Optional[int] = field(default=None, metadata={'description': 'The flags for this CAA record as an integer between 0 and 255.'})  # fmt: skip
    tag: Optional[str] = field(default=None, metadata={"description": "The tag for this CAA record."})
    value: Optional[str] = field(default=None, metadata={"description": "The value for this CAA record."})


@define(eq=False, slots=False)
class AzureDNSRecordSet(AzureResource, BaseDNSRecordSet):
    kind: ClassVar[str] = "azure_dns_record_set"
    reference_kinds: ClassVar[ModelReference] = {
        "predecessors": {"default": ["azure_dns_zone"]},
    }
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "a_records": S("properties") >> S("ARecords", default=[]) >> ForallBend(S("ipv4Address")),
        "aaaa_records": S("properties") >> S("AAAARecords", default=[]) >> ForallBend(S("ipv6Address")),
        "caa_records": S("properties", "caaRecords") >> ForallBend(AzureCaaRecord.mapping),
        "cname_record": S("properties", "CNAMERecord", "cname"),
        "etag": S("etag"),
        "fqdn": S("properties", "fqdn"),
        "record_set_metadata": S("properties", "metadata"),
        "mx_records": S("properties", "MXRecords") >> ForallBend(AzureMxRecord.mapping),
        "ns_records": S("properties") >> S("NSRecords", default=[]) >> ForallBend(S("nsdname")),
        "provisioning_state": S("properties", "provisioningState"),
        "ptr_records": S("properties") >> S("PTRRecords", default=[]) >> ForallBend(S("ptrdname")),
        "soa_record": S("properties", "SOARecord") >> Bend(AzureSoaRecord.mapping),
        "srv_records": S("properties", "SRVRecords") >> ForallBend(AzureSrvRecord.mapping),
        "target_resource": S("properties", "targetResource", "id"),
        "ttl": S("properties", "TTL"),
        "txt_records": S("properties", "TXTRecords") >> ForallBend(AzureTxtRecord.mapping),
    }
    a_records: Optional[List[str]] = field(default=None, metadata={'description': 'The list of A records in the record set.'})  # fmt: skip
    aaaa_records: Optional[List[str]] = field(default=None, metadata={'description': 'The list of AAAA records in the record set.'})  # fmt: skip
    caa_records: Optional[List[AzureCaaRecord]] = field(default=None, metadata={'description': 'The list of CAA records in the record set.'})  # fmt: skip
    cname_record: Optional[str] = field(default=None, metadata={"description": "A CNAME record."})
    fqdn: Optional[str] = field(default=None, metadata={'description': 'Fully qualified domain name of the record set.'})  # fmt: skip
    record_set_metadata: Optional[Dict[str, str]] = field(default=None, metadata={'description': 'The metadata attached to the record set.'})  # fmt: skip
    mx_records: Optional[List[AzureMxRecord]] = field(default=None, metadata={'description': 'The list of MX records in the record set.'})  # fmt: skip
    ns_records: Optional[List[str]] = field(default=None, metadata={'description': 'The list of NS records in the record set.'})  # fmt: skip
    ptr_records: Optional[List[str]] = field(default=None, metadata={'description': 'The list of PTR records in the record set.'})  # fmt: skip
    soa_record: Optional[AzureSoaRecord] = field(default=None, metadata={"description": "An SOA record."})
    srv_records: Optional[List[AzureSrvRecord]] = field(default=None, metadata={'description': 'The list of SRV records in the record set.'})  # fmt: skip
    target_resource: Optional[str] = field(default=None, metadata={"description": "A reference to a another resource"})
    ttl: Optional[int] = field(default=None, metadata={'description': 'The TTL (time-to-live) of the records in the record set.'})  # fmt: skip
    txt_records: Optional[List[AzureTxtRecord]] = field(default=None, metadata={'description': 'The list of TXT records in the record set.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureDNSZone(AzureResource, BaseDNSZone):
    kind: ClassVar[str] = "azure_dns_zone"
    api_spec: ClassVar[AzureApiSpec] = AzureApiSpec(
        service="resources",
        version="2018-05-01",
        path="/subscriptions/{subscriptionId}/providers/Microsoft.Network/dnszones",
        path_parameters=["subscriptionId"],
        query_parameters=["api-version"],
        access_path="value",
        expect_array=True,
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "etag": S("etag"),
        "max_number_of_record_sets": S("properties", "maxNumberOfRecordSets"),
        "max_number_of_records_per_record_set": S("properties", "maxNumberOfRecordsPerRecordSet"),
        "name_servers": S("properties", "nameServers"),
        "number_of_record_sets": S("properties", "numberOfRecordSets"),
        "registration_virtual_networks": S("properties")
        >> S("registrationVirtualNetworks", default=[])
        >> ForallBend(S("id")),
        "resolution_virtual_networks": S("properties")
        >> S("resolutionVirtualNetworks", default=[])
        >> ForallBend(S("id")),
        "zone_type": S("properties", "zoneType"),
    }
    max_number_of_record_sets: Optional[int] = field(default=None, metadata={'description': 'The maximum number of record sets that can be created in this DNS zone. This is a read-only property and any attempt to set this value will be ignored.'})  # fmt: skip
    max_number_of_records_per_record_set: Optional[int] = field(default=None, metadata={'description': 'The maximum number of records per record set that can be created in this DNS zone. This is a read-only property and any attempt to set this value will be ignored.'})  # fmt: skip
    name_servers: Optional[List[str]] = field(default=None, metadata={'description': 'The name servers for this DNS zone. This is a read-only property and any attempt to set this value will be ignored.'})  # fmt: skip
    number_of_record_sets: Optional[int] = field(default=None, metadata={'description': 'The current number of record sets in this DNS zone. This is a read-only property and any attempt to set this value will be ignored.'})  # fmt: skip
    registration_virtual_networks: Optional[List[str]] = field(default=None, metadata={'description': 'A list of references to virtual networks that register hostnames in this DNS zone. This is a only when ZoneType is Private.'})  # fmt: skip
    resolution_virtual_networks: Optional[List[str]] = field(default=None, metadata={'description': 'A list of references to virtual networks that resolve records in this DNS zone. This is a only when ZoneType is Private.'})  # fmt: skip
    zone_type: Optional[str] = field(default=None, metadata={'description': 'The type of this DNS zone (Public or Private).'})  # fmt: skip

    def post_process(self, graph_builder: GraphBuilder, source: Json) -> None:
        def collect_record_sets() -> None:
            api_spec = AzureApiSpec(
                service="resources",
                version="2018-05-01",
                path=f"{self.id}/recordsets",
                path_parameters=[],
                query_parameters=["api-version"],
                access_path="value",
                expect_array=True,
            )
            items = graph_builder.client.list(api_spec)

            record_sets = AzureDNSRecordSet.collect(items, graph_builder)
            for record_set in record_sets:
                dns_zone_id = "/".join(record_set.id.split("/")[:-2])
                graph_builder.add_edge(
                    record_set, edge_type=EdgeType.default, reverse=True, clazz=AzureDNSZone, id=dns_zone_id
                )

        graph_builder.submit_work(service_name, collect_record_sets)


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
    }
    availability_zone_mappings: Optional[List[AzureAvailabilityZoneMappings]] = field(default=None, metadata={'description': 'The availability zone mappings for this region.'})  # fmt: skip
    display_name: Optional[str] = field(default=None, metadata={"description": "The display name of the location."})
    location_metadata: Optional[AzureLocationMetadata] = field(default=None, metadata={'description': 'Location metadata information.'})  # fmt: skip
    regional_display_name: Optional[str] = field(default=None, metadata={'description': 'The display name of the location and its region.'})  # fmt: skip
    subscription_id: Optional[str] = field(default=None, metadata={"description": "The subscription id."})


@define(eq=False, slots=False)
class AzureResourceGroup(MicrosoftResource, BaseGroup):
    kind: ClassVar[str] = "azure_resource_group"
    api_spec: ClassVar[AzureResourceSpec] = AzureResourceSpec(
        service="resources",
        version="2022-09-01",
        path="/subscriptions/{subscriptionId}/resourcegroups",
        path_parameters=["subscriptionId"],
        query_parameters=["api-version"],
        access_path="value",
        expect_array=True,
    )
    reference_kinds: ClassVar[ModelReference] = {
        "successors": {"default": ["microsoft_resource"]},
    }
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "managed_by": S("managedBy"),
        "provisioning_state": S("properties", "provisioningState"),
    }
    managed_by: Optional[str] = field(default=None, metadata={'description': 'The id of the resource that manages this resource group.'})  # fmt: skip
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
            from fix_plugin_azure.resource.network import AzureVirtualNetworkGateway

            api_spec = AzureApiSpec(
                service="network",
                version="2023-09-01",
                path=f"{self.id}/providers/Microsoft.Network/virtualNetworkGateways",
                path_parameters=[],
                query_parameters=["api-version"],
                access_path="value",
                expect_array=True,
            )
            items = graph_builder.client.list(api_spec)
            AzureVirtualNetworkGateway.collect(items, graph_builder)

        def collect_local_network_gateway() -> None:
            from fix_plugin_azure.resource.network import AzureLocalNetworkGateway

            api_spec = AzureApiSpec(
                service="network",
                version="2023-09-01",
                path=f"{self.id}/providers/Microsoft.Network/localNetworkGateways",
                path_parameters=[],
                query_parameters=["api-version"],
                access_path="value",
                expect_array=True,
            )
            items = graph_builder.client.list(api_spec)
            AzureLocalNetworkGateway.collect(items, graph_builder)

        def collect_network_gateway_connections() -> None:
            from fix_plugin_azure.resource.network import AzureVirtualNetworkGatewayConnection

            api_spec = AzureApiSpec(
                service="network",
                version="2023-09-01",
                path=f"{self.id}/providers/Microsoft.Network/connections",
                path_parameters=[],
                query_parameters=["api-version"],
                access_path="value",
                expect_array=True,
            )
            items = graph_builder.client.list(api_spec)
            AzureVirtualNetworkGatewayConnection.collect(items, graph_builder)

        graph_builder.submit_work(service_name, collect_resources_in_group)
        graph_builder.submit_work(service_name, collect_network_gateways)
        graph_builder.submit_work(service_name, collect_local_network_gateway)
        graph_builder.submit_work(service_name, collect_network_gateway_connections)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if resource_ids := self._resource_ids_in_group:
            for resource_id in resource_ids:
                builder.add_edge(self, edge_type=EdgeType.default, clazz=MicrosoftResource, id=resource_id)

@define(eq=False, slots=False)
class ProvisioningError:
    mapping: ClassVar[Dict[str, Bender]] = {
        "error_code": S("errorCode"),
        "error_message": S("errorMessage"),
        "additional_details": S("additionalDetails")
    }
    error_code: Optional[str] = field(default=None)
    error_message: Optional[str] = field(default=None)
    additional_details: Optional[str] = field(default=None)

@define(eq=False, slots=False)
class AzureADGroup(AzureResource, BaseGroup):
    kind: ClassVar[str] = "azure_ad_group"
    api_spec: ClassVar[AzureApiSpec] = AzureApiSpec(
        service="resources",
        version="",
        path="https://graph.microsoft.com/v1.0/groups",
        path_parameters=[],
        query_parameters=[],
        access_path="value",
        expect_array=True,
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "classification": S("classification"),
        "created_date_time": S("createdDateTime"),
        "ctime": S("createdDateTime"),
        "creation_options": S("creationOptions"),
        "deleted_date_time": S("deletedDateTime"),
        "description": S("description"),
        "display_name": S("displayName"),
        "expiration_date_time": S("expirationDateTime"),
        "group_types": S("groupTypes"),
        "id": S("id"),
        "is_assignable_to_role": S("isAssignableToRole"),
        "mail": S("mail"),
        "mail_enabled": S("mailEnabled"),
        "mail_nickname": S("mailNickname"),
        "membership_rule": S("membershipRule"),
        "membership_rule_processing_state": S("membershipRuleProcessingState"),
        "on_premises_domain_name": S("onPremisesDomainName"),
        "on_premises_last_sync_date_time": S("onPremisesLastSyncDateTime"),
        "on_premises_net_bios_name": S("onPremisesNetBiosName"),
        "on_premises_provisioning_errors": S("onPremisesProvisioningErrors") >> Bend(ProvisioningError.mapping),
        "on_premises_sam_account_name": S("onPremisesSamAccountName"),
        "on_premises_security_identifier": S("onPremisesSecurityIdentifier"),
        "on_premises_sync_enabled": S("onPremisesSyncEnabled"),
        "preferred_data_location": S("preferredDataLocation"),
        "preferred_language": S("preferredLanguage"),
        "proxy_addresses": S("proxyAddresses"),
        "renewed_date_time": S("renewedDateTime"),
        "resource_behavior_options": S("resourceBehaviorOptions"),
        "resource_provisioning_options": S("resourceProvisioningOptions"),
        "security_enabled": S("securityEnabled"),
        "security_identifier": S("securityIdentifier"),
        "service_provisioning_errors": S("serviceProvisioningErrors") >> Bend(ProvisioningError.mapping),
        "theme": S("theme"),
        "unique_name": S("uniqueName"),
        "visibility": S("visibility"),
    }
    
    classification: Optional[str] = field(default=None, metadata={"description": "The classification for the group."})
    created_date_time: Optional[datetime] = field(default=None, metadata={"description": "Timestamp of when the group was created."})
    creation_options: List[str] = field(factory=list, metadata={"description": "Options used to create this group."})
    deleted_date_time: Optional[datetime] = field(default=None, metadata={"description": "Timestamp of when the group was deleted."})
    description: Optional[str] = field(default=None, metadata={"description": "An optional description for the group."})
    display_name: Optional[str] = field(default=None, metadata={"description": "The display name for the group."})
    expiration_date_time: Optional[datetime] = field(default=None, metadata={"description": "Timestamp of when group expires if applicable."})
    group_types: List[str] = field(factory=list, metadata={"description": "Specifies the group type and its membership."})
    is_assignable_to_role: Optional[bool] = field(default=None, metadata={"description": "Indicates whether this group can be assigned to an Azure Active Directory role."})
    mail: Optional[str] = field(default=None, metadata={"description": "The SMTP address for the group."})
    mail_enabled: bool = field(default=False, metadata={"description": "Specifies whether the group is mail-enabled."})
    mail_nickname: Optional[str] = field(default=None, metadata={"description": "The mail alias for the group."})
    membership_rule: Optional[str] = field(default=None, metadata={"description": "The rule that determines members for this group if the group is a dynamic group."})
    membership_rule_processing_state: Optional[str] = field(default=None, metadata={"description": "Indicates whether the dynamic membership processing is on or paused."})
    on_premises_domain_name: Optional[str] = field(default=None, metadata={"description": "Contains the on-premises domain FQDN, also called dnsDomainName synchronized from the on-premises directory."})
    on_premises_last_sync_date_time: Optional[datetime] = field(default=None, metadata={"description": "Indicates the last time at which the group was synced with the on-premises directory."})
    on_premises_net_bios_name: Optional[str] = field(default=None, metadata={"description": "Contains the on-premises NetBIOS name synchronized from the on-premises directory."})
    on_premises_provisioning_errors: List[ProvisioningError] = field(factory=list, metadata={"description": "Errors when using Microsoft synchronization product during provisioning."})
    on_premises_sam_account_name: Optional[str] = field(default=None, metadata={"description": "Contains the on-premises SAM account name synchronized from the on-premises directory."})
    on_premises_security_identifier: Optional[str] = field(default=None, metadata={"description": "Contains the on-premises security identifier (SID) for the group that was synchronized from on-premises to the cloud."})
    on_premises_sync_enabled: Optional[bool] = field(default=None, metadata={"description": "Indicates whether this group is synchronized from an on-premises directory."})
    preferred_data_location: Optional[str] = field(default=None, metadata={"description": "The preferred data location for the group."})
    preferred_language: Optional[str] = field(default=None, metadata={"description": "The preferred language for the group."})
    proxy_addresses: List[str] = field(factory=list, metadata={"description": "Email addresses for the group that direct to the same group mailbox."})
    renewed_date_time: Optional[datetime] = field(default=None, metadata={"description": "Timestamp of when the group was last renewed."})
    resource_behavior_options: List[str] = field(factory=list, metadata={"description": "Specifies the group behaviors that can be set for a Microsoft 365 group."})
    resource_provisioning_options: List[str] = field(factory=list, metadata={"description": "Specifies the group resources that are provisioned as part of Microsoft 365 group creation."})
    security_enabled: bool = field(default=False, metadata={"description": "Specifies whether the group is a security group."})
    security_identifier: Optional[str] = field(default=None, metadata={"description": "Security identifier of the group, used in Windows scenarios."})
    service_provisioning_errors: List[ProvisioningError] = field(factory=list, metadata={"description": "Errors published by a federated service describing a non-transient, service-specific error regarding the properties or link from a group object."})
    theme: Optional[str] = field(default=None, metadata={"description": "Specifies a Microsoft 365 group's color theme."})
    unique_name: Optional[str] = field(default=None, metadata={"description": "The unique name of the group."})
    visibility: Optional[str] = field(default=None, metadata={"description": "Specifies the group join policy and group content visibility."})

@define(eq=False, slots=False)
class AzureADUser(AzureResource, BaseUser):
    kind: ClassVar[str] = "azure_ad_user"
    api_spec: ClassVar[AzureApiSpec] = AzureApiSpec(
        service="resources",
        version="",
        path="https://graph.microsoft.com/v1.0/users",
        path_parameters=[],
        query_parameters=[],
        access_path="value",
        expect_array=True,
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "business_phones": S("businessPhones"),
        "display_name": S("displayName"),
        "given_name": S("givenName"),
        "id": S("id"),
        "job_title": S("jobTitle"),
        "mail": S("mail"),
        "mobile_phone": S("mobilePhone"),
        "office_location": S("officeLocation"),
        "preferred_language": S("preferredLanguage"),
        "surname": S("surname"),
        "user_principal_name": S("userPrincipalName"),
    }

    business_phones: List[str] = field(factory=list, metadata={"description": "The user's business phone numbers."})
    display_name: Optional[str] = field(default=None, metadata={"description": "The name displayed in the address book for the user."})
    given_name: Optional[str] = field(default=None, metadata={"description": "The user's given name (first name)."})
    job_title: Optional[str] = field(default=None, metadata={"description": "The user's job title."})
    mail: Optional[str] = field(default=None, metadata={"description": "The user's email address."})
    mobile_phone: Optional[str] = field(default=None, metadata={"description": "The user's mobile phone number."})
    office_location: Optional[str] = field(default=None, metadata={"description": "The user's office location."})
    preferred_language: Optional[str] = field(default=None, metadata={"description": "The user's preferred language."})
    surname: Optional[str] = field(default=None, metadata={"description": "The user's surname (last name)."})
    user_principal_name: Optional[str] = field(default=None, metadata={"description": "The user principal name (UPN) of the user."})

@define(eq=False, slots=False)
class AzureADDirectoryRole(AzureResource, BaseRole):
    kind: ClassVar[str] = "azure_ad_directory_role"
    api_spec: ClassVar[AzureApiSpec] = AzureApiSpec(
        service="resources",
        version="",
        path="https://graph.microsoft.com/v1.0/directoryRoles",
        path_parameters=[],
        query_parameters=[],
        access_path="value",
        expect_array=True,
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "deleted_datetime": S("deletedDateTime"),
        "description": S("description"),
        "display_name": S("displayName"),
        "id": S("id"),
        "role_template_id": S("roleTemplateId"),
    }
    deleted_datetime: Optional[datetime] = field(default=None, metadata={"description": "Deletion time of the directory role, if applicable."})
    description: Optional[str] = field(default=None, metadata={"description": "Description of the directory role."})
    display_name: Optional[str] = field(default=None, metadata={"description": "Display name of the directory role."})
    role_template_id: Optional[str] = field(default=None, metadata={"description": "Id of the directory role template."})

@define(eq=False, slots=False)
class AzureUsageName:
    kind: ClassVar[str] = "azure_usage_name"
    mapping: ClassVar[Dict[str, Bender]] = {"localized_value": S("localizedValue"), "value": S("value")}
    localized_value: Optional[str] = field(default=None, metadata={'description': 'Gets a localized string describing the resource name.'})  # fmt: skip
    value: Optional[str] = field(default=None, metadata={"description": "Gets a string describing the resource name."})


@define(eq=False, slots=False)
class AzureBaseUsage:
    kind: ClassVar[str] = "azure_usage"
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
    _expected_error_codes: ClassVar[List[str]] = ["SubscriptionHasNoUsages"]


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
class AzurePrincipalClient:
    kind: ClassVar[str] = "azure_principal_client"
    mapping: ClassVar[Dict[str, Bender]] = {"client_id": S("clientId"), "principal_id": S("principalId")}
    client_id: Optional[str] = field(default=None, metadata={'description': 'The client id of user assigned identity.'})  # fmt: skip
    principal_id: Optional[str] = field(default=None, metadata={'description': 'The principal id of user assigned identity.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureManagedServiceIdentity:
    kind: ClassVar[str] = "azure_managed_service_identity"
    mapping: ClassVar[Dict[str, Bender]] = {
        "principal_id": S("principalId"),
        "tenant_id": S("tenantId"),
        "type": S("type"),
        "user_assigned_identities": S("userAssignedIdentities"),
    }
    principal_id: Optional[str] = field(default=None, metadata={'description': 'The principal id of the system assigned identity. This property will only be provided for a system assigned identity.'})  # fmt: skip
    tenant_id: Optional[str] = field(default=None, metadata={'description': 'The tenant id of the system assigned identity. This property will only be provided for a system assigned identity.'})  # fmt: skip
    type: Optional[str] = field(default=None, metadata={'description': 'The type of identity used for the resource. The type SystemAssigned, UserAssigned includes both an implicitly created identity and a set of user assigned identities. The type None will remove any identities from the virtual machine.'})  # fmt: skip
    user_assigned_identities: Optional[Dict[str, AzurePrincipalClient]] = field(default=None, metadata={'description': 'The list of user identities associated with resource. The user identity dictionary key references will be ARM resource ids in the form: /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ManagedIdentity/userAssignedIdentities/{identityName} .'})  # fmt: skip


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
class AzureManagementGroup(AzureResource, BaseOrganizationalRoot, BaseOrganizationalUnit):
    kind: ClassVar[str] = "azure_management_group"
    api_spec: ClassVar[AzureApiSpec] = AzureApiSpec(
        service="resources",
        version="2023-04-01",
        path="/providers/Microsoft.Management/managementGroups",
        path_parameters=[],
        query_parameters=["api-version"],
        access_path="value",
        expect_array=True,
        expected_error_codes=["AuthorizationFailed"],
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "display_name": S("properties", "displayName"),
        "tenant_id": S("properties", "tenantId"),
        "type": S("type"),
    }
    type: Optional[str] = field(default=None, metadata={"description": "Resource type."})
    display_name: Optional[str] = field(default=None, metadata={'description': 'The friendly name of the management group.'})  # fmt: skip
    tenant_id: Optional[str] = field(default=None, metadata={'description': 'The AAD Tenant ID associated with the management group. For example, 00000000-0000-0000-0000-000000000000'})  # fmt: skip


@define(eq=False, slots=False)
class AzureManagedIdentity(AzureResource, BaseInstanceProfile):
    kind: ClassVar[str] = "azure_managed_identity"
    api_spec: ClassVar[AzureApiSpec] = AzureApiSpec(
        service="resources",
        version="2023-01-31",
        path="/subscriptions/{subscriptionId}/providers/Microsoft.ManagedIdentity/userAssignedIdentities",
        path_parameters=["subscriptionId"],
        query_parameters=["api-version"],
        access_path="value",
        expect_array=True,
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "location": S("location"),
        "name": S("name"),
        "system_data": S("systemData") >> Bend(AzureSystemData.mapping),
        "type": S("type"),
        "tags": S("tags", default={}),
        "client_id": S("properties", "clientId"),
        "principal_id": S("properties", "principalId"),
        "tenant_id": S("properties", "tenantId"),
    }
    system_data: Optional[AzureSystemData] = field(default=None, metadata={'description': 'Metadata pertaining to creation and last modification of the resource.'})  # fmt: skip
    type: Optional[str] = field(default=None, metadata={'description': 'The type of the resource. E.g. Microsoft.Compute/virtualMachines or Microsoft.Storage/storageAccounts '})  # fmt: skip
    location: Optional[str] = field(default=None, metadata={'description': 'The geo-location where the resource lives'})  # fmt: skip
    client_id: Optional[str] = field(default=None, metadata={'description': 'The id of the app associated with the identity. This is a random generated UUID by MSI.'})  # fmt: skip
    principal_id: Optional[str] = field(default=None, metadata={'description': 'The id of the service principal object associated with the created identity.'})  # fmt: skip
    tenant_id: Optional[str] = field(default=None, metadata={'description': 'The id of the tenant which the identity belongs to.'})  # fmt: skip


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
        account: BaseAccount,
        client: MicrosoftClient,
        executor: ExecutorQueue,
        core_feedback: CoreFeedback,
        config: AzureConfig,
        location_lookup: Optional[Dict[str, BaseRegion]] = None,
        location: Optional[BaseRegion] = None,
        graph_access_lock: Optional[RWLock] = None,
        last_run_started_at: Optional[datetime] = None,
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
                if (filter_fn(n) if filter_fn else True) and all(getattr(n, k, None) == v for k, v in node.items()):
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
            last_edge_key = self.add_edge(self.account, node=node)

        # create provider link
        if node._metadata.get("provider_link") is None and node._is_provider_link:
            node._metadata["provider_link"] = f"https://portal.azure.com/#@/resource{node.id}/overview"

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
        )


resources: List[Type[MicrosoftResource]] = [
    AzureResourceGroup,
    AzureManagementGroup,
    AzureDNSZone,
    AzureDNSRecordSet,
    AzureManagedIdentity,
    AzureADGroup,
    AzureADUser,
    AzureADDirectoryRole,
]
