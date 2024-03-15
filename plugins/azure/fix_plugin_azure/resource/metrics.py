from datetime import datetime
from concurrent.futures import as_completed
import logging
from typing import ClassVar, Dict, Optional, List, Tuple, TypeVar

from azure.core.exceptions import (
    HttpResponseError,
)

from attr import define, field

from fix_plugin_azure.azure_client import AzureApiSpec
from fix_plugin_azure.resource.base import GraphBuilder
from fix_plugin_azure.utils import MetricNormalization
from fixlib.baseresources import BaseResource
from fixlib.json import from_json
from fixlib.json_bender import Bender, S, ForallBend, Bend, bend
from fixlib.utils import utc_str

log = logging.getLogger("fix.plugins.azure")


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
    aggregation: Tuple[str, ...]
    unit: str = "Count"

    @staticmethod
    def create(
        metric_name: str,
        metric_namespace: str,
        instance_id: str,
        ref_id: str,
        aggregation: Tuple[str, ...],
        metric_id: Optional[str] = None,
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
    def compute_interval(period: float) -> str:
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
        queries: List[AzureMetricQuery],
        start_time: datetime,
        end_time: datetime,
        period: float,
    ) -> "Dict[AzureMetricQuery, AzureMetricData]":
        """
        A static method to query Azure metrics for multiple queries simultaneously.

        Args:
            builder (GraphBuilder): An instance of GraphBuilder used for submitting work.
            queries (List[AzureMetricQuery]): A list of AzureMetricQuery objects representing the metrics to query.
            start_time (datetime): The start time for the metrics query.
            end_time (datetime): The end time for the metrics query.
            period (float): The period over which to aggregate the metrics.

        Returns:
            Dict[AzureMetricQuery, AzureMetricData]: A dictionary mapping each query to its corresponding metric data.
        """
        # Create a lookup dictionary for efficient mapping of metric IDs to queries
        lookup = {q.metric_id: q for q in queries}
        result: Dict[AzureMetricQuery, AzureMetricData] = {}

        # Define API specifications for querying Azure metrics
        api_spec = AzureApiSpec(
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
        # Define the timespan and interval for the query
        timespan = f"{utc_str(start_time)}/{utc_str(end_time)}"
        interval = AzureMetricData.compute_interval(period)

        # Submit queries for each AzureMetricQuery
        futures = []
        for query in queries:
            future = builder.submit_work(
                "azure_metric",
                AzureMetricData._query_for_single,
                builder,
                query,
                api_spec,
                timespan,
                interval,
            )
            futures.append(future)

        # Retrieve results from submitted queries and populate the result dictionary
        for future in as_completed(futures):
            try:
                metric, metric_id = future.result()
                if metric is not None and metric_id is not None:
                    result[lookup[metric_id]] = metric
            except Exception as e:
                log.error(f"An error occurred while processing a metric query: {e}")
                raise e

        return result

    @staticmethod
    def _query_for_single(
        builder: GraphBuilder,
        query: AzureMetricQuery,
        api_spec: AzureApiSpec,
        timespan: str,
        interval: str,
    ) -> "Tuple[Optional[AzureMetricData], Optional[str]]":
        try:
            # Set the path for the API call based on the instance ID of the query
            api_spec.path = f"{query.instance_id}/providers/Microsoft.Insights/metrics"
            # Retrieve metric data from the API
            aggregation = ",".join(query.aggregation)
            part = builder.client.list(
                api_spec,
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
                metric_id = metric.metric_id
                if metric_id is not None:
                    return metric, metric_id
            return None, None
        except HttpResponseError as e:
            # Handle unsupported metric namespace error
            log.warning(f"Request error occurred: {e}.")
            return None, None
        except Exception as e:
            raise e


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
            for aggregation, metric_value in metric_data.items():
                normalizer = metric_normalizers.get(query.metric_name)
                if not normalizer:
                    continue
                name = normalizer.metric_name + "_" + normalizer.unit
                value = metric_normalizers[query.metric_name].normalize_value(metric_value)

                resource._resource_usage[name][normalizer.stat_map[aggregation]] = value
