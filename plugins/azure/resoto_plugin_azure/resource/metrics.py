from datetime import datetime
from typing import ClassVar, Dict, Optional, List, Tuple, TypeVar

from attr import define, field

from resoto_plugin_azure.azure_client import AzureApiSpec, AzureClient
from resoto_plugin_azure.resource.base import AzurePrivateLinkServiceConnectionState, AzureResource
from resoto_plugin_azure.utils import MetricNormalization
from resotolib.baseresources import BaseResource
from resotolib.json import from_json
from resotolib.json_bender import Bender, S, K, ForallBend, Bend, bend
from resotolib.utils import utc_str


@define(eq=False, slots=False)
class AzureMetricValueName:
    kind: ClassVar[str] = "azure_metric_value_name"
    mapping: ClassVar[Dict[str, Bender]] = {
        "localized_value": S("localizedValue"),
        "value": S("value"),
    }
    localized_value: Optional[str] = field(default=None)
    value: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AzureMetricMetadataValues:
    kind: ClassVar[str] = "azure_metric_metadata_values"
    mapping: ClassVar[Dict[str, Bender]] = {
        "name": S("name") >> Bend(AzureMetricValueName.mapping),
        "value": S("value"),
    }
    name: Optional[str] = field(default=None)
    value: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AzureMetricTimeSeriesValues:
    kind: ClassVar[str] = "azure_metric_time_series_values"
    mapping: ClassVar[Dict[str, Bender]] = {
        "timestamp": S("timeStamp"),
        "count": S("count"),
        "total": S("total"),
        "minimum": S("minimum"),
        "maximum": S("maximum"),
        "average": S("average"),
    }
    timestamp: datetime = field()
    count: Optional[int] = field(default=None)
    minimum: Optional[float] = field(default=None)
    maximum: Optional[float] = field(default=None)
    average: Optional[float] = field(default=None)
    total: Optional[float] = field(default=None)


@define(eq=False, slots=False)
class AzureMetricTimeSeries:
    kind: ClassVar[str] = "azure_metric_time_series"
    mapping: ClassVar[Dict[str, Bender]] = {
        "metadata_values": S("metadatavalues") >> ForallBend(AzureMetricMetadataValues.mapping),
        "data": S("data") >> ForallBend(AzureMetricTimeSeriesValues.mapping),
    }
    metadata_values: Optional[List[AzureMetricMetadataValues]] = field(default=None)
    data: Optional[List[AzureMetricTimeSeriesValues]] = field(default=None)


@define(eq=False, slots=False)
class AzureMetricValue:
    kind: ClassVar[str] = "azure_metric_value"
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "type": S("type"),
        "name": S("name") >> Bend(AzureMetricValueName.mapping),
        "displayDescription": S("displayDescription"),
        "unit": S("unit"),
        "timeseries": S("timeseries", default=[]) >> ForallBend(AzureMetricTimeSeries.mapping),
    }
    id: Optional[str] = field(default=None)
    type: Optional[str] = field(default=None)
    name: Optional[str] = field(default=None)
    display_description: Optional[str] = field(default=None)
    unit: Optional[str] = field(default=None)
    timeseries: Optional[List[AzureMetricTimeSeries]] = field(default=None)


@define(hash=True, frozen=True)
class AzureMetricQuery:
    metric_name: str
    metric_namespace: str
    ref_id: str
    instance_id: str
    metric_id: str
    aggregation: str = "total"
    unit: str = "Count"

    @staticmethod
    def create(
        metric_name: str,
        metric_namespace: str,
        instance_id: str,
        ref_id: str,
        metric_id: Optional[str] = None,
        aggregation: str = "total",
        unit: str = "Count",
    ) -> "AzureMetricQuery":
        metric_id = f"{instance_id}/providers/Microsoft.Insights/metrics/{metric_name}"
        # noinspection PyTypeChecker
        return AzureMetricQuery(
            metric_name=metric_name,
            metric_namespace=metric_namespace,
            instance_id=instance_id,
            metric_id=metric_id,
            aggregation=aggregation,
            ref_id=ref_id,
            unit=unit,
        )


@define(eq=False, slots=False)
class AzureMetricData:
    kind: ClassVar[str] = "azure_metric"
    mapping: ClassVar[Dict[str, Bender]] = {
        "timespan": S("timespan"),
        "interval": S("interval"),
        "namespace": S("namespace"),
        "resource_region": S("resourceregion"),
        "full_metric_values_data": S("value") >> ForallBend(AzureMetricValue.mapping),
    }
    full_metric_values_data: List[AzureMetricValue] = field(factory=list)
    metric_id: Optional[str] = field(default=None)
    metric_values: Optional[List[float]] = field(default=None)
    metric_timestamps: Optional[List[datetime]] = field(default=None)
    timespan: Optional[str] = field(default=None)
    interval: Optional[str] = field(default=None)
    namespace: Optional[str] = field(default=None)
    resource_region: Optional[str] = field(default=None)

    def set_values(self, query_aggregation: str) -> None:
        if self.full_metric_values_data:
            metric_values_result = [
                data
                for metric_value in self.full_metric_values_data
                for timeseries in metric_value.timeseries or []
                for data in timeseries.data or []
            ]
            self.metric_values = [getattr(metric, query_aggregation) for metric in metric_values_result][::-1]
            self.metric_timestamps = [
                data.timestamp
                for metric_value in self.full_metric_values_data
                for timeseries in metric_value.timeseries or []
                for data in timeseries.data or []
            ][::-1]
            self.metric_id = self.full_metric_values_data[0].id

    def first_non_zero(self) -> Optional[Tuple[datetime, float]]:
        if self.metric_timestamps and self.metric_values:
            for timestamp, value in zip(self.metric_timestamps, self.metric_values):
                if value != 0 and value is not None:
                    return timestamp, value
        return None

    @staticmethod
    def query_for(
        client: AzureClient,
        queries: List[AzureMetricQuery],
        start_time: datetime,
        end_time: datetime,
    ) -> "Dict[AzureMetricQuery, AzureMetricData]":
        lookup = {q.metric_id: q for q in queries}
        result: Dict[AzureMetricQuery, AzureMetricData] = {}

        api_spec = AzureApiSpec(
            service="metric",
            version="2021-05-01",
            path="",
            path_parameters=[],
            query_parameters=[
                "api-version",
                "metricnames",
                "metricNamespace",
                "timespan",
                "aggregation",
            ],
            access_path="value",
            expect_array=False,
        )
        timespan = f"{utc_str(start_time)}/{utc_str(end_time)}"

        for query in queries:
            api_spec.path = f"{query.instance_id}/providers/Microsoft.Insights/metrics"
            part = client.list(
                api_spec,
                metricnames=query.metric_name,
                metricNamespace=query.metric_namespace,
                timespan=timespan,
                aggregation=query.aggregation,
            )
            for single in part:
                metric = from_json(bend(AzureMetricData.mapping, single), AzureMetricData)
                metric.set_values(query.aggregation)
                metric_id = metric.metric_id
                if metric_id is not None:
                    result[lookup[metric_id]] = metric

        return result


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
    created_at: Optional[datetime] = field(default=None, metadata={'description': 'The timestamp of resource creation (UTC).'})  # fmt: skip
    created_by: Optional[str] = field(default=None, metadata={'description': 'The identity that created the resource.'})  # fmt: skip
    created_by_type: Optional[str] = field(default=None, metadata={'description': 'The type of identity that created the resource.'})  # fmt: skip
    last_modified_at: Optional[datetime] = field(default=None, metadata={'description': 'The timestamp of resource last modification (UTC)'})  # fmt: skip
    last_modified_by: Optional[str] = field(default=None, metadata={'description': 'The identity that last modified the resource.'})  # fmt: skip
    last_modified_by_type: Optional[str] = field(default=None, metadata={'description': 'The type of identity that last modified the resource.'})  # fmt: skip


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
    provisioning_state: Optional[str] = field(default=None, metadata={'description': 'The current provisioning state.'})  # fmt: skip
    system_data: Optional[AzureSystemData] = field(default=None, metadata={'description': 'Metadata pertaining to creation and last modification of the resource.'})  # fmt: skip
    type: Optional[str] = field(default=None, metadata={'description': 'The type of the resource. E.g. Microsoft.Compute/virtualMachines or Microsoft.Storage/storageAccounts '})  # fmt: skip


@define(eq=False, slots=False)
class AzureTrackedResource:
    kind: ClassVar[str] = "azure_tracked_resource"
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "location": S("location"),
        "name": S("name"),
        "system_data": S("systemData") >> Bend(AzureSystemData.mapping),
        "tags": S("tags"),
        "type": S("type"),
    }
    id: Optional[str] = field(default=None, metadata={'description': 'Fully qualified resource ID for the resource. Ex - /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}'})  # fmt: skip
    location: Optional[str] = field(default=None, metadata={'description': 'The geo-location where the resource lives'})  # fmt: skip
    name: Optional[str] = field(default=None, metadata={"description": "The name of the resource"})
    system_data: Optional[AzureSystemData] = field(default=None, metadata={'description': 'Metadata pertaining to creation and last modification of the resource.'})  # fmt: skip
    tags: Optional[Dict[str, str]] = field(default=None, metadata={"description": "Resource tags."})
    type: Optional[str] = field(default=None, metadata={'description': 'The type of the resource. E.g. Microsoft.Compute/virtualMachines or Microsoft.Storage/storageAccounts '})  # fmt: skip


@define(eq=False, slots=False)
class AzureMetrics:
    kind: ClassVar[str] = "azure_metrics"
    mapping: ClassVar[Dict[str, Bender]] = {
        "internal_id": S("internalId"),
        "prometheus_query_endpoint": S("prometheusQueryEndpoint"),
    }
    internal_id: Optional[str] = field(default=None, metadata={'description': 'An internal identifier for the metrics container. Only to be used by the system'})  # fmt: skip
    prometheus_query_endpoint: Optional[str] = field(default=None, metadata={'description': 'The Prometheus query endpoint for the Azure Monitor Workspace'})  # fmt: skip


@define(eq=False, slots=False)
class AzureIngestionSettings:
    kind: ClassVar[str] = "azure_ingestion_settings"
    mapping: ClassVar[Dict[str, Bender]] = {
        "data_collection_endpoint_resource_id": S("dataCollectionEndpointResourceId"),
        "data_collection_rule_resource_id": S("dataCollectionRuleResourceId"),
    }
    data_collection_endpoint_resource_id: Optional[str] = field(default=None, metadata={'description': 'The Azure resource Id of the default data collection endpoint for this Azure Monitor Workspace.'})  # fmt: skip
    data_collection_rule_resource_id: Optional[str] = field(default=None, metadata={'description': 'The Azure resource Id of the default data collection rule for this Azure Monitor Workspace.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureAzureMonitorWorkspace:
    kind: ClassVar[str] = "azure_azure_monitor_workspace"
    mapping: ClassVar[Dict[str, Bender]] = {
        "account_id": S("accountId"),
        "default_ingestion_settings": S("defaultIngestionSettings") >> Bend(AzureIngestionSettings.mapping),
        "metrics": S("metrics") >> Bend(AzureMetrics.mapping),
        "private_endpoint_connections": S("privateEndpointConnections")
        >> ForallBend(AzurePrivateEndpointConnection.mapping),
        "provisioning_state": S("provisioningState"),
        "public_network_access": S("publicNetworkAccess"),
    }
    account_id: Optional[str] = field(default=None, metadata={'description': 'The immutable Id of the Azure Monitor Workspace. This property is read-only.'})  # fmt: skip
    default_ingestion_settings: Optional[AzureIngestionSettings] = field(default=None, metadata={'description': 'The Data Collection Rule and Endpoint used for ingestion by default.'})  # fmt: skip
    metrics: Optional[AzureMetrics] = field(default=None, metadata={'description': 'Properties related to the metrics container in the Azure Monitor Workspace'})  # fmt: skip
    private_endpoint_connections: Optional[List[AzurePrivateEndpointConnection]] = field(default=None, metadata={'description': 'List of private endpoint connections'})  # fmt: skip
    provisioning_state: Optional[str] = field(default=None, metadata={'description': 'The provisioning state of the Azure Monitor Workspace. Set to Succeeded if everything is healthy.'})  # fmt: skip
    public_network_access: Optional[str] = field(default=None, metadata={'description': 'Gets or sets allow or disallow public network access to Azure Monitor Workspace'})  # fmt: skip


@define(eq=False, slots=False)
class AzureProviderResourceOperationDescription:
    kind: ClassVar[str] = "azure_provider_resource_operation_description"
    mapping: ClassVar[Dict[str, Bender]] = {
        "description": S("description"),
        "operation": S("operation"),
        "provider": S("provider"),
        "resource": S("resource"),
    }
    description: Optional[str] = field(default=None, metadata={'description': 'The short, localized friendly description of the operation; suitable for tool tips and detailed views.'})  # fmt: skip
    operation: Optional[str] = field(default=None, metadata={'description': 'The concise, localized friendly name for the operation; suitable for dropdowns. E.g. Create or Update Virtual Machine , Restart Virtual Machine .'})  # fmt: skip
    provider: Optional[str] = field(default=None, metadata={'description': 'The localized friendly form of the resource provider name, e.g. Microsoft Monitoring Insights or Microsoft Compute .'})  # fmt: skip
    resource: Optional[str] = field(default=None, metadata={'description': 'The localized friendly name of the resource type related to this operation. E.g. Virtual Machines or Job Schedule Collections .'})  # fmt: skip


@define(eq=False, slots=False)
class AzureOperation(AzureResource):
    kind: ClassVar[str] = "azure_operation"
    api_spec: ClassVar[AzureApiSpec] = AzureApiSpec(
        service="monitor",
        version="2023-04-03",
        path="/providers/Microsoft.Monitor/operations",
        path_parameters=[],
        query_parameters=["api-version"],
        access_path="value",
        expect_array=True,
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": K(None),
        "tags": S("tags", default={}),
        "name": S("name"),
        "action_type": S("actionType"),
        "operation_display": S("display") >> Bend(AzureProviderResourceOperationDescription.mapping),
        "is_data_action": S("isDataAction"),
        "origin": S("origin"),
    }
    action_type: Optional[str] = field(default=None, metadata={'description': 'Enum. Indicates the action type. Internal refers to actions that are for internal only APIs.'})  # fmt: skip
    operation_display: Optional[AzureProviderResourceOperationDescription] = field(default=None, metadata={'description': 'Localized display information for this particular operation.'})  # fmt: skip
    is_data_action: Optional[bool] = field(default=None, metadata={'description': 'Whether the operation applies to data-plane. This is true for data-plane operations and false for ARM/control-plane operations.'})  # fmt: skip
    origin: Optional[str] = field(default=None, metadata={'description': 'The intended executor of the operation; as in Resource Based Access Control (RBAC) and audit logs UX. Default value is user,system '})  # fmt: skip


V = TypeVar("V", bound=BaseResource)


def update_resource_metrics(
    resources_map: Dict[str, V],
    metric_result: Dict[AzureMetricQuery, AzureMetricData],
    metric_normalizers: Dict[str, MetricNormalization],
) -> None:
    for query, metric in metric_result.items():
        resource = resources_map.get(query.ref_id)
        if resource is None:
            continue
        metric_data = metric.metric_values
        if metric_data:
            metric_value = next(iter(metric_data), None)
        else:
            metric_value = None
        if metric_value is None:
            continue
        normalizer = metric_normalizers.get(query.metric_name)
        if not normalizer:
            continue

        name = normalizer.name
        value = metric_normalizers[query.metric_name].normalize_value(metric_value)

        resource._resource_usage[name][normalizer.stat_map[query.aggregation]] = value
