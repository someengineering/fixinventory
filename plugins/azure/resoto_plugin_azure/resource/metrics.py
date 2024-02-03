from datetime import datetime
from typing import ClassVar, Dict, Optional, List, Tuple, TypeVar

from attr import define, field

from resoto_plugin_azure.azure_client import AzureApiSpec
from resoto_plugin_azure.resource.base import GraphBuilder
from resoto_plugin_azure.utils import MetricNormalization
from resotolib.baseresources import BaseResource
from resotolib.json import from_json
from resotolib.json_bender import Bender, S, ForallBend, Bend, bend
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
        builder: GraphBuilder,
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
            part = builder.client.list(
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
