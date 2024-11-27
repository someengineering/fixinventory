from concurrent.futures import as_completed
from datetime import timedelta, datetime, timezone
from typing import List, Tuple, Dict

from fix_plugin_gcp.resources.base import GraphBuilder, GcpMonitoringQuery
from fix_plugin_gcp.resources.monitoring import GcpMonitoringMetricData, normalizer_factory
from fixlib.baseresources import MetricName


def test_metric(random_builder: GraphBuilder) -> None:
    now = datetime(2020, 3, 1, tzinfo=timezone.utc)
    earlier = now - timedelta(days=60)
    read = GcpMonitoringQuery.create(
        query_name="compute.googleapis.com/instance/disk/read_ops_count",
        period=timedelta(hours=1),
        ref_id="gcp_instance/random_instance/global",
        metric_name=MetricName.DiskRead,
        normalization=normalizer_factory.count,
        stat="ALIGN_MIN",
        project_id=random_builder.project.id,
        metric_filters={"metric.labels.instance_name": "random_instance", "resource.labels.zone": "global"},
    )
    write = GcpMonitoringQuery.create(
        query_name="compute.googleapis.com/instance/disk/write_ops_count",
        period=timedelta(hours=1),
        ref_id="gcp_instance/random_instance/global",
        metric_name=MetricName.DiskWrite,
        normalization=normalizer_factory.count,
        stat="ALIGN_MIN",
        project_id=random_builder.project.id,
        metric_filters={"metric.labels.instance_name": "random_instance", "resource.labels.zone": "global"},
    )
    queries = GcpMonitoringMetricData.query_for(random_builder, [read, write], earlier, now)
    mq_lookup = {q.metric_id: q for q in [read, write]}
    result: Dict[GcpMonitoringQuery, GcpMonitoringMetricData] = {}
    for metric_data in as_completed(queries):
        metric_query_result: List[Tuple[str, GcpMonitoringMetricData]] = metric_data.result()
        for metric_id, metric in metric_query_result:
            if metric is not None and metric_id is not None:
                result[mq_lookup[metric_id]] = metric
    assert all(value > 0 for value in result[read].metric_values or [])
    assert all(value > 0 for value in result[write].metric_values or [])
