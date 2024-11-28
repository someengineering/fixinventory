import logging
from copy import deepcopy
from datetime import datetime
from functools import cached_property, lru_cache
from typing import ClassVar, Dict, List, Optional, TypeVar, Callable

from attr import define, field

from fix_plugin_gcp.gcp_client import GcpApiSpec
from fix_plugin_gcp.resources.base import GraphBuilder, GcpMonitoringQuery, MetricNormalization, GcpResource
from fixlib.baseresources import MetricUnit, StatName, BaseResource
from fixlib.durations import duration_str
from fixlib.json import from_json
from fixlib.json_bender import S, Bender, ForallBend, bend, K, AsFloat
from fixlib.utils import utc_str

service_name = "monitoring"
log = logging.getLogger("fix.plugins.gcp")
T = TypeVar("T")
V = TypeVar("V", bound=BaseResource)

STANDART_STAT_MAP: Dict[str, StatName] = {
    "ALIGN_MIN": StatName.min,
    "ALIGN_MEAN": StatName.avg,
    "ALIGN_MAX": StatName.max,
}
PERCENTILE_STAT_MAP: Dict[str, StatName] = {
    "ALIGN_PERCENTILE_05": StatName.min,
    "ALIGN_PERCENTILE_50": StatName.avg,
    "ALIGN_PERCENTILE_99": StatName.max,
}


@define(eq=False, slots=False)
class GcpMonitoringMetricData:
    kind: ClassVar[str] = "gcp_monitoring_metric_data"
    mapping: ClassVar[Dict[str, Bender]] = {
        "metric_values": S("points")
        >> ForallBend((S("value", "doubleValue").or_else(S("value", "int64Value")) >> AsFloat())).or_else(K([])),
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
        resource: GcpResource,
        queries: List[GcpMonitoringQuery],
        start_time: datetime,
        end_time: datetime,
    ) -> None:
        if builder.region:
            log.info(
                f"[{builder.region.safe_name}|{start_time}|{duration_str(end_time - start_time)}] Query for {len(queries)} metrics."
            )
        else:
            log.info(f"[global|{start_time}|{duration_str(end_time - start_time)}] Query for {len(queries)} metrics.")

        api_spec = GcpApiSpec(
            service="monitoring",
            version="v3",
            accessors=["projects", "timeSeries"],
            action="list",
            request_parameter={
                "name": "projects/{project}",
                "interval_endTime": utc_str(end_time),
                "interval_startTime": utc_str(start_time),
                "aggregation_crossSeriesReducer": "REDUCE_NONE",
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
            builder.submit_work(
                GcpMonitoringMetricData._query_for_chunk,
                builder,
                resource,
                api_spec,
                query,
            )

    @staticmethod
    def _query_for_chunk(
        builder: GraphBuilder,
        resource: GcpResource,
        api_spec: GcpApiSpec,
        query: GcpMonitoringQuery,
    ) -> None:
        local_api_spec = deepcopy(api_spec)

        # Base filter
        filters = [
            f'metric.type = "{query.query_name}"',
            f'resource.labels.project_id="{query.project_id}"',
        ]

        # Add additional filters
        if query.metric_filters:
            filters.extend(f'{key} = "{value}"' for key, value in query.metric_filters.items())

        # Join filters with " AND " to form the final filter string
        local_api_spec.request_parameter["filter"] = " AND ".join(filters)
        local_api_spec.request_parameter["aggregation_alignmentPeriod"] = f"{int(query.period.total_seconds())}s"
        local_api_spec.request_parameter["aggregation_perSeriesAligner"] = query.stat

        try:
            part = builder.client.list(local_api_spec)
            for single in part:
                metric = from_json(bend(GcpMonitoringMetricData.mapping, single), GcpMonitoringMetricData)
                update_resource_metrics(resource, query, metric)
        except Exception as e:
            log.warning(f"An error occurred while processing a metric data: {e}")


def update_resource_metrics(
    resource: GcpResource,
    query: GcpMonitoringQuery,
    metric: GcpMonitoringMetricData,
) -> None:
    if len(metric.metric_values) == 0:
        return
    normalizer = query.normalization
    for metric_value, maybe_stat_name in normalizer.compute_stats(metric.metric_values):
        try:
            metric_name = query.metric_name
            if not metric_name:
                continue
            name = metric_name + "_" + normalizer.unit
            value = normalizer.normalize_value(metric_value)
            stat_name = maybe_stat_name or STANDART_STAT_MAP.get(query.stat) or PERCENTILE_STAT_MAP.get(query.stat)
            if stat_name:
                resource._resource_usage[name][str(stat_name)] = value
        except KeyError as e:
            log.warning(f"An error occurred while setting metric values: {e}")
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

    @lru_cache(maxsize=128)
    def milliseconds(self, normalize_value: Optional[Callable[[float], float]] = None) -> MetricNormalization:
        return MetricNormalization(
            unit=MetricUnit.Milliseconds,
            normalize_value=normalize_value or (lambda x: round(x, ndigits=4)),
        )

    @cached_property
    def percent(self) -> MetricNormalization:
        return MetricNormalization(
            unit=MetricUnit.Percent,
            normalize_value=lambda x: round(x, ndigits=4),
        )


normalizer_factory = NormalizerFactory()
