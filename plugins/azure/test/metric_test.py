from datetime import timedelta, datetime, timezone
from fix_plugin_azure.resource.base import GraphBuilder, AzureMetricQuery

from fix_plugin_azure.resource.compute import AzureComputeVirtualMachine
from fix_plugin_azure.resource.metrics import AzureMetricData, NormalizerFactory

from fixlib.baseresources import MetricName


def test_metric(builder: GraphBuilder) -> None:
    now = datetime(2020, 3, 1, tzinfo=timezone.utc)
    earlier = now - timedelta(days=60)
    delta = now - earlier
    resource_id = "/subscriptions/rwqrr2-31f1-rwqrrw-5325-wrq2r/resourceGroups/FOO/providers/Microsoft.Compute/virtualMachines/test1"
    vm = AzureComputeVirtualMachine(id=resource_id, name="test1")
    write = AzureMetricQuery.create(
        metric_name="Disk Write Operations/Sec",
        metric_namespace="Microsoft.Compute/virtualMachines",
        metric_normalization_name=MetricName.DiskWrite,
        normalization=NormalizerFactory.iops,
        period=delta,
        instance_id=resource_id,
        ref_id=resource_id,
        aggregation=("average", "minimum", "maximum"),
        unit="CountPerSecond",
    )
    AzureMetricData.query_for(builder=builder, resource=vm, queries=[write], start_time=earlier, end_time=now)
    builder.executor.wait_for_submitted_work()
    assert vm._resource_usage["disk_write_iops"] == {
        "avg": 247685.5622,
        "min": 291286.2900,
        "max": 193903.4467,
    }
