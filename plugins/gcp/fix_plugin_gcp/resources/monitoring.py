from copy import deepcopy
from functools import cached_property
import logging
from datetime import datetime, timedelta
from typing import Callable, ClassVar, Dict, List, Optional, Tuple, TypeVar, Union
from concurrent.futures import as_completed

from attr import define, field, frozen

from fix_plugin_gcp.resources.base import GraphBuilder, GcpRegion
from fix_plugin_gcp.gcp_client import GcpApiSpec
from fixlib.baseresources import MetricName, MetricUnit, BaseResource, StatName
from fixlib.durations import duration_str
from fixlib.json import from_json
from fixlib.json_bender import S, Bender, ForallBend, bend
from fixlib.utils import utc_str

service_name = "monitoring"
log = logging.getLogger("fix.plugins.gcp")
T = TypeVar("T")


STAT_LIST: List[str] = ["ALIGN_MIN", "ALIGN_MEAN", "ALIGN_MAX"]


def identity(x: T) -> T:
    return x


@frozen(kw_only=True)
class MetricNormalization:
    unit: MetricUnit
    # Use Tuple instead of Dict for stat_map because it should be immutable
    stat_map: Tuple[Tuple[str, StatName], Tuple[str, StatName], Tuple[str, StatName]] = (
        ("ALIGN_MIN", StatName.min),
        ("ALIGN_MEAN", StatName.avg),
        ("ALIGN_MAX", StatName.max),
    )
    normalize_value: Callable[[float], float] = identity

    def get_stat_value(self, key: str) -> Optional[StatName]:
        """
        Get the value from stat_map based on the given key.

        Args:
            key: The key to search for in the stat_map.

        Returns:
            The corresponding value from stat_map.
        """
        for stat_key, value in self.stat_map:
            if stat_key == key:
                return value
        return None


@define(hash=True, frozen=True)
class GcpMonitoringQuery:
    metric_name: Union[str, MetricName]  # final name of the metric
    query_name: str  # name of the metric (e.g., GCP metric type)
    period: timedelta  # period of the metric
    ref_id: str  # A unique identifier for the resource, formatted as `{resource_kind}/{resource_id}/{resource_region}`.
    # Example: "gcp_instance/12345/us-central1". This is used to uniquely reference resources across kinds and regions.
    metric_id: str  # unique metric identifier (metric_name + instance_id)
    stat: str  # aggregation type, supports ALIGN_MEAN, ALIGN_MAX, ALIGN_MIN
    project_id: str  # GCP project name
    normalization: Optional[MetricNormalization] = None  # normalization info
    metric_filters: Optional[Tuple[Tuple[str, str], ...]] = None  # Immutable structure

    @staticmethod
    def create(
        *,
        query_name: str,
        period: timedelta,
        ref_id: str,
        metric_name: Union[str, MetricName],
        stat: str,
        project_id: str,
        metric_filters: Dict[str, str],
        normalization: Optional[MetricNormalization] = None,
    ) -> "GcpMonitoringQuery":
        sorted_filters = sorted(metric_filters.items())
        filter_suffix = "/" + "/".join(f"{key}={value}" for key, value in sorted_filters)
        metric_id = f"{query_name}/{ref_id}/{stat}{filter_suffix}"
        immutable_filters = tuple(sorted_filters)
        return GcpMonitoringQuery(
            metric_name=metric_name,
            query_name=query_name,
            period=period,
            ref_id=ref_id,
            metric_id=metric_id,
            stat=stat,
            normalization=normalization,
            project_id=project_id,
            metric_filters=immutable_filters,
        )


@define(eq=False, slots=False)
class GcpMonitoringMetricData:
    kind: ClassVar[str] = "gcp_monitoring_metric_data"
    mapping: ClassVar[Dict[str, Bender]] = {
        "metric_values": S("points")
        >> ForallBend(S("value", "doubleValue").or_else(S("value", "int64Value", default=0.0))),
        "metric_kind": S("metricKind"),
        "value_type": S("valueType"),
        "metric_type": S("metric", "type"),
    }
    metric_values: Optional[List[float]] = field(factory=list)
    metric_kind: Optional[str] = field(default=None)
    value_type: Optional[str] = field(default=None)
    metric_type: Optional[str] = field(default=None)

    @classmethod
    def called_collect_apis(cls) -> List[GcpApiSpec]:
        api_spec = GcpApiSpec(
            service="monitoring",
            version="v3",
            accessors=["projects", "timeSeries"],
            action="list",
            request_parameter={
                "name": "projects/{project}",
            },
            request_parameter_in={"project"},
            response_path="timeSeries",
        )
        return [api_spec]

    @staticmethod
    def query_for(
        builder: GraphBuilder,
        queries: List[GcpMonitoringQuery],
        start_time: datetime,
        end_time: datetime,
    ) -> "Dict[GcpMonitoringQuery, GcpMonitoringMetricData]":
        if builder.region:
            log.info(
                f"[{builder.region.safe_name}|{start_time}|{duration_str(end_time - start_time)}] Query for {len(queries)} metrics."
            )
        else:
            log.info(f"[global|{start_time}|{duration_str(end_time - start_time)}] Query for {len(queries)} metrics.")
        lookup = {q.metric_id: q for q in queries}
        result: Dict[GcpMonitoringQuery, GcpMonitoringMetricData] = {}
        futures = []

        api_spec = GcpApiSpec(
            service="monitoring",
            version="v3",
            accessors=["projects", "timeSeries"],
            action="list",
            request_parameter={
                "name": "projects/{project}",
                "aggregation_crossSeriesReducer": "REDUCE_NONE",
                "aggregation_groupByFields": "[]",
                "interval_endTime": utc_str(end_time),
                "interval_startTime": utc_str(start_time),
                "view": "FULL",
                # Below parameters are intended to be set dynamically
                # "aggregation_alignmentPeriod": None,
                # "aggregation_perSeriesAligner": None,
                # "filter": None,
            },
            request_parameter_in={"project"},
            response_path="timeSeries",
        )

        for query in queries:
            future = builder.submit_work(
                GcpMonitoringMetricData._query_for_chunk,
                builder,
                api_spec,
                query,
            )
            futures.append(future)
        # Retrieve results from submitted queries and populate the result dictionary
        for future in as_completed(futures):
            try:
                metric_query_result: List[Tuple[str, GcpMonitoringMetricData]] = future.result()
                for metric_id, metric in metric_query_result:
                    if metric is not None and metric_id is not None:
                        result[lookup[metric_id]] = metric
            except Exception as e:
                log.warning(f"An error occurred while processing a metric query: {e}")
                raise e
        return result

    @staticmethod
    def _query_for_chunk(
        builder: GraphBuilder,
        api_spec: GcpApiSpec,
        query: GcpMonitoringQuery,
    ) -> "List[Tuple[str, GcpMonitoringMetricData]]":
        query_result = []
        local_api_spec = deepcopy(api_spec)

        # Base filter
        filters = [
            f'metric.type = "{query.query_name}"',
            f'resource.labels.project_id="{query.project_id}"',
        ]

        # Add additional filters
        if query.metric_filters:
            filters.extend(f'{key} = "{value}"' for key, value in query.metric_filters)

        # Join filters with " AND " to form the final filter string
        local_api_spec.request_parameter["filter"] = " AND ".join(filters)
        local_api_spec.request_parameter["aggregation_alignmentPeriod"] = f"{int(query.period.total_seconds())}s"
        local_api_spec.request_parameter["aggregation_perSeriesAligner"] = query.stat

        try:
            part = builder.client.list(local_api_spec)
            for single in part:
                metric = from_json(bend(GcpMonitoringMetricData.mapping, single), GcpMonitoringMetricData)
                query_result.append((query.metric_id, metric))
            return query_result
        except Exception as e:
            raise e


V = TypeVar("V", bound=BaseResource)


def update_resource_metrics(
    resources_map: Dict[str, V],
    monitoring_metric_result: Dict[GcpMonitoringQuery, GcpMonitoringMetricData],
) -> None:
    for query, metric in monitoring_metric_result.items():
        resource = resources_map.get(query.ref_id)
        if resource is None:
            continue
        if not metric.metric_values or len(metric.metric_values) == 0:
            continue
        normalizer = query.normalization
        if not normalizer:
            continue

        average_value = sum(metric.metric_values) / len(metric.metric_values)

        try:
            metric_name = query.metric_name
            if not metric_name:
                continue
            name = metric_name + "_" + normalizer.unit
            value = normalizer.normalize_value(average_value)
            stat_name = normalizer.get_stat_value(query.stat) if normalizer.get_stat_value(query.stat) else "avg"
            resource._resource_usage[name][str(stat_name)] = value
        except KeyError as e:
            log.warning(f"An error occured while setting metric values: {e}")
            raise


class NormalizerFactory:
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


normalizer_factory = NormalizerFactory()
