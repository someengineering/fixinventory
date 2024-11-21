from datetime import timedelta, datetime, timezone

from fix_plugin_gcp.resources.base import GraphBuilder
from fix_plugin_gcp.resources.monitoring import GcpMonitoringQuery, GcpMonitoringMetricData, normalizer_factory
from fixlib.baseresources import MetricName


def test_metric(random_builder: GraphBuilder) -> None:
    now = datetime(2020, 3, 1, tzinfo=timezone.utc)
    earlier = now - timedelta(days=60)
    read = GcpMonitoringQuery.create(
        query_name="compute.googleapis.com/instance/disk/read_ops_count",
        period=timedelta(hours=1),
        ref_id="random_instance",
        resource_name="random_instance",
        metric_name=MetricName.DiskRead,
        normalization=normalizer_factory.count,
        stat="ALIGN_MIN",
        label_name="instance_name",
    )
    write = GcpMonitoringQuery.create(
        query_name="compute.googleapis.com/instance/disk/write_ops_count",
        period=timedelta(hours=1),
        ref_id="random_instance",
        resource_name="random_instance",
        metric_name=MetricName.DiskWrite,
        normalization=normalizer_factory.count,
        stat="ALIGN_MIN",
        label_name="instance_name",
    )
    result = GcpMonitoringMetricData.query_for(random_builder, [read, write], earlier, now)
    assert all(value > 0 for value in result[read].metric_values), "Not all values are greater than 0 for 'read'."
    assert all(value > 0 for value in result[write].metric_values), "Not all values are greater than 0 for 'write'."
