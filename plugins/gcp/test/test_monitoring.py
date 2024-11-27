from datetime import timedelta, datetime, timezone

from fix_plugin_gcp.resources.base import GraphBuilder, GcpMonitoringQuery
from fix_plugin_gcp.resources.monitoring import GcpMonitoringMetricData, normalizer_factory
from fix_plugin_gcp.resources.compute import GcpInstance
from fixlib.baseresources import MetricName


def test_metric(random_builder: GraphBuilder) -> None:
    now = datetime(2020, 3, 1, tzinfo=timezone.utc)
    earlier = now - timedelta(days=60)
    read = GcpMonitoringQuery.create(
        query_name="compute.googleapis.com/instance/disk/read_ops_count",
        period=timedelta(hours=1),
        ref_id="gcp_instance/random_instance/global",
        metric_name=MetricName.DiskRead,
        normalization=normalizer_factory.iops,
        stat="ALIGN_MIN",
        project_id=random_builder.project.id,
        metric_filters={"metric.labels.instance_name": "random_instance", "resource.labels.zone": "global"},
    )
    write = GcpMonitoringQuery.create(
        query_name="compute.googleapis.com/instance/disk/write_ops_count",
        period=timedelta(hours=1),
        ref_id="gcp_instance/random_instance/global",
        metric_name=MetricName.DiskWrite,
        normalization=normalizer_factory.iops,
        stat="ALIGN_MIN",
        project_id=random_builder.project.id,
        metric_filters={"metric.labels.instance_name": "random_instance", "resource.labels.zone": "global"},
    )
    gcp_instance = GcpInstance(id="random_instance")
    GcpMonitoringMetricData.query_for(random_builder, gcp_instance, [read, write], earlier, now)
    random_builder.executor.wait_for_submitted_work()
    usages = list(gcp_instance._resource_usage.keys())
    assert usages[0] == f"{read.metric_name}_{read.normalization.unit}"
    assert usages[1] == f"{write.metric_name}_{write.normalization.unit}"
