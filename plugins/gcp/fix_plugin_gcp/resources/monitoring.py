from functools import cached_property, lru_cache
import logging
import re
from datetime import datetime, timedelta
from typing import Callable, ClassVar, Dict, List, Optional, Type, Tuple, TypeVar, Any, Union
from concurrent.futures import as_completed
from json import loads as json_loads

from attr import define, field, frozen

from fix_plugin_gcp.gcp_client import GcpClient
from fix_plugin_gcp.resources.base import GcpApiSpec, GcpResource, GraphBuilder, GcpRegion
from fixlib.baseresources import MetricName, MetricUnit, ModelReference, BaseResource, StatName
from fixlib.durations import duration_str
from fixlib.graph import Graph
from fixlib.json import from_json, sort_json
from fixlib.json_bender import S, K, Bend, Bender, ForallBend, bend, F, SecondsFromEpochToDatetime
from fixlib.types import Json
from fixlib.utils import utc_str

service_name = "monitoring"
log = logging.getLogger("fix.plugins.gcp")
T = TypeVar("T")


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
    resource_name: str  # name of resource
    period: timedelta  # period of the metric
    ref_id: str  # reference ID for the resource (e.g., instance ID)
    metric_id: str  # unique metric identifier (metric_name + instance_id)
    stat: str  # aggregation type, supports ALIGN_MEAN, ALIGN_MAX, ALIGN_MIN
    label_type: str
    normalization: Optional[MetricNormalization] = None  # normalization info
    region: Optional[GcpRegion] = None

    @staticmethod
    def create(
        *,
        query_name: str,
        period: timedelta,
        ref_id: str,
        resource_name: str,
        metric_name: Union[str, MetricName],
        stat: str,
        label_type: str,
        normalization: Optional[MetricNormalization] = None,
        region: Optional[GcpRegion] = None,
    ) -> "GcpMonitoringQuery":
        # Metric ID generation: metric name + resource ID
        metric_id = f"{metric_name}/{ref_id}"

        return GcpMonitoringQuery(
            metric_name=metric_name,
            query_name=query_name,
            period=period,
            ref_id=ref_id,
            resource_name=resource_name,
            metric_id=metric_id,
            label_type=label_type,
            stat=stat,
            region=region,
            normalization=normalization,
        )


@define(eq=False, slots=False)
class GcpMonitoringMetricData:
    kind: ClassVar[str] = "gcp_monitoring_metric_data"
    mapping: ClassVar[Dict[str, Bender]] = {
        "metric_values": S("points", default=[]) >> ForallBend(S("value", "doubleValue")),
        "metric_kind": S("metricKind"),
        "value_type": S("valueType"),
        "metric_type": S("metric", "type"),
    }
    metric_values: List[float] = field(factory=list)
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
                # set parametes below dynamically
                # "aggregation_alignmentPeriod": None,
                # "aggregation_perSeriesAligner": None,
                # "filter": None,
            },
            request_parameter_in={"project"},
            response_path="timeSeries",
        )

        for query in queries:
            api_spec.request_parameter["filter"] = (
                f"metric.type = {query.query_name} AND metric.labels.{query.label_type} = {query.resource_name}"
            )
            api_spec.request_parameter["aggregation_alignmentPeriod"] = f"{int(query.period.total_seconds())}s"
            api_spec.request_parameter["aggregation_perSeriesAligner"] = query.stat
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
        try:
            part = builder.client.list(api_spec)
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
        if len(metric.metric_values) == 0:
            continue
        normalizer = query.normalization
        if not normalizer:
            continue

        most_recent_value = metric.metric_values[0]

        try:
            metric_name = query.metric_name
            if not metric_name:
                continue
            name = metric_name + "_" + normalizer.unit
            value = normalizer.normalize_value(most_recent_value)
            stat_name = normalizer.get_stat_value(query.stat)
            if stat_name:
                resource._resource_usage[name][str(stat_name)] = value
        except KeyError as e:
            log.warning(f"An error occured while setting metric values: {e}")
            raise
