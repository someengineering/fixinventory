from copy import deepcopy
from datetime import datetime, timedelta
from functools import cached_property
import logging
from typing import ClassVar, Dict, Optional, List, Tuple, TypeVar

from azure.core.exceptions import (
    HttpResponseError,
)

from attr import define, field

from fix_plugin_azure.azure_client import AzureResourceSpec
from fix_plugin_azure.resource.base import (
    GraphBuilder,
    AzureMetricQuery,
    MetricNormalization,
    STAT_MAP,
    MicrosoftResource,
)
from fixlib.baseresources import BaseResource, MetricUnit
from fixlib.json import from_json
from fixlib.json_bender import Bender, S, ForallBend, Bend, bend
from fixlib.utils import utc_str

log = logging.getLogger("fix.plugins.azure")
service_name = "metric"


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


class __FiiP:
    pass


fip = __FiiP()


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
    metric_values: Optional[Dict[str, float]] = field(default=None)
    timespan: Optional[str] = field(default=None)
    interval: Optional[str] = field(default=None)
    namespace: Optional[str] = field(default=None)
    resource_region: Optional[str] = field(default=None)

    def set_values(self, query_aggregations: Tuple[str, ...]) -> None:
        # Check if there are full metric values data available
        if self.full_metric_values_data:
            # Extract metric values from the full metric values data
            metric_values_result = [
                data
                for metric_value in self.full_metric_values_data or []
                for timeseries in metric_value.timeseries or []
                for data in timeseries.data or []
            ]

            # Calculate aggregated metric values based on the provided aggregations
            metric_values: Dict[str, float] = {}

            for attr in query_aggregations:
                # Extract attribute values for each metric
                metric_attrs = [
                    getattr(metric, attr) for metric in metric_values_result if getattr(metric, attr) is not None
                ]
                # Calculate the average value for the attribute across metrics and add it to metric_values list
                if metric_attrs:
                    metric_values[attr] = sum(metric_attrs) / len(metric_attrs)

            # Set the calculated metric values
            self.metric_values = metric_values

            # Set the metric ID
            self.metric_id = self.full_metric_values_data[0].id

    @staticmethod
    def compute_interval(delta: timedelta) -> str:
        period = delta.total_seconds() / 60
        intervals = {
            5: "1M",
            15: "5M",
            30: "15M",
            60: "30M",
            360: "1H",
            720: "6H",
            1440: "12H",
        }
        for interval, time in intervals.items():
            if period < interval:
                return "PT" + time
        return "P1D"

    @staticmethod
    def query_for(
        builder: GraphBuilder,
        resource: MicrosoftResource,
        queries: List[AzureMetricQuery],
        start_time: datetime,
        end_time: datetime,
    ) -> None:

        # Define API specifications for querying Azure metrics
        api_spec = AzureResourceSpec(
            service="metric",
            version="2019-07-01",
            path="",
            path_parameters=[],
            query_parameters=[
                "api-version",
                "metricnames",
                "metricNamespace",
                "timespan",
                "aggregation",
                "interval",
                "AutoAdjustTimegrain",
                "ValidateDimensions",
            ],
            access_path=None,
            expect_array=False,
        )

        # Submit queries for each AzureMetricQuery
        for query in queries:
            builder.submit_work(
                service_name,
                AzureMetricData._query_for_single,
                builder,
                query,
                api_spec,
                start_time,
                end_time,
                resource,
            )

    @staticmethod
    def _query_for_single(
        builder: GraphBuilder,
        query: AzureMetricQuery,
        api_spec: AzureResourceSpec,
        start_time: datetime,
        end_time: datetime,
        resource: MicrosoftResource,
    ) -> None:
        try:
            local_api_spec = deepcopy(api_spec)
            # Set the path for the API call based on the instance ID of the query
            local_api_spec.path = f"{query.instance_id}/providers/Microsoft.Insights/metrics"
            # Retrieve metric data from the API
            aggregation = ",".join(query.aggregation)
            # Define the timespan and interval for the query
            timespan = f"{utc_str(query.custom_start_time or start_time)}/{utc_str(end_time)}"
            interval = AzureMetricData.compute_interval(query.period)
            part = builder.client.list(
                local_api_spec,
                metricnames=query.metric_name,
                metricNamespace=query.metric_namespace,
                timespan=timespan,
                aggregation=aggregation,
                interval=interval,
                AutoAdjustTimegrain=True,
                ValidateDimensions=False,
            )
            # Iterate over the retrieved data and map it to AzureMetricData objects
            for single in part:
                metric: AzureMetricData = from_json(bend(AzureMetricData.mapping, single), AzureMetricData)
                metric.set_values(query.aggregation)
                update_resource_metrics(resource, query, metric)
        except HttpResponseError as e:
            # Handle unsupported metric namespace error
            log.warning(f"Request error occurredwhile processing metrics: {e}.")
        except Exception as e:
            log.warning(f"An error occurred while processing metrics: {e}.")


V = TypeVar("V", bound=BaseResource)


def update_resource_metrics(
    resource: MicrosoftResource,
    query: AzureMetricQuery,
    metric: AzureMetricData,
) -> None:

    metric_data = metric.metric_values
    normalizer = query.normalization
    if metric_data:
        for aggregation, metric_value in metric_data.items():
            name = query.metric_normalization_name + "_" + normalizer.unit
            value = normalizer.normalize_value(metric_value)
            stat_name = STAT_MAP.get(aggregation)
            try:
                if stat_name:
                    resource._resource_usage[name][str(stat_name)] = value
            except KeyError as e:
                log.warning(f"An error occurred while setting metric values: {e}")
                raise


class __NormalizerFactory:
    __instance = None

    def __new__(cls) -> "__NormalizerFactory":
        if cls.__instance is None:
            cls.__instance = super().__new__(cls)
        return cls.__instance

    @cached_property
    def count(self) -> MetricNormalization:
        return MetricNormalization(
            unit=MetricUnit.Count,
            normalize_value=lambda x: round(x, ndigits=4),
        )

    @cached_property
    def bytes(self) -> MetricNormalization:
        return MetricNormalization(
            unit=MetricUnit.Bytes,
            normalize_value=lambda x: round(x, ndigits=4),
        )

    @cached_property
    def bytes_per_second(self) -> MetricNormalization:
        return MetricNormalization(
            unit=MetricUnit.BytesPerSecond,
            normalize_value=lambda x: round(x, ndigits=4),
        )

    @cached_property
    def iops(self) -> MetricNormalization:
        return MetricNormalization(
            unit=MetricUnit.IOPS,
            normalize_value=lambda x: round(x, ndigits=4),
        )

    @cached_property
    def seconds(self) -> MetricNormalization:
        return MetricNormalization(
            unit=MetricUnit.Seconds,
            normalize_value=lambda x: round(x, ndigits=4),
        )

    @cached_property
    def milliseconds(self) -> MetricNormalization:
        return MetricNormalization(
            unit=MetricUnit.Milliseconds,
            normalize_value=lambda x: round(x, ndigits=4),
        )

    @cached_property
    def percent(self) -> MetricNormalization:
        return MetricNormalization(
            unit=MetricUnit.Percent,
            normalize_value=lambda x: round(x, ndigits=4),
        )


NormalizerFactory = __NormalizerFactory()
