from datetime import timedelta, datetime, timezone
from fix_plugin_azure.resource.base import GraphBuilder

from fix_plugin_azure.resource.metrics import AzureMetricQuery, AzureMetricData


def test_metric(builder: GraphBuilder) -> None:
    now = datetime(2020, 3, 1, tzinfo=timezone.utc)
    earlier = now - timedelta(days=60)
    delta = now - earlier
    resource_id = "/subscriptions/rwqrr2-31f1-rwqrrw-5325-wrq2r/resourceGroups/FOO/providers/Microsoft.Compute/virtualMachines/test1"
    write = AzureMetricQuery.create(
        "Disk Write Operations/Sec",
        "Microsoft.Compute/virtualMachines",
        resource_id,
        resource_id,
        ("average", "minimum", "maximum"),
        unit="CountPerSecond",
    )
    result = AzureMetricData.query_for(builder=builder, queries=[write], start_time=earlier, end_time=now, delta=delta)
    assert result[write].metric_values == {
        "average": 247685.56222444447,
        "minimum": 291286.29000000004,
        "maximum": 193903.44666666666,
    }
