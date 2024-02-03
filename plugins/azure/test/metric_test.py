from datetime import timedelta, datetime, timezone
from resoto_plugin_azure.resource.base import GraphBuilder

from resoto_plugin_azure.resource.metrics import AzureMetricQuery, AzureMetricData


def test_metric(builder: GraphBuilder) -> None:
    now = datetime(2020, 3, 1, tzinfo=timezone.utc)
    earlier = now - timedelta(days=60)
    resource_id = "/subscriptions/rwqrr2-31f1-rwqrrw-5325-wrq2r/resourceGroups/FOO/providers/Microsoft.Compute/virtualMachines/test1"
    write = AzureMetricQuery.create(
        "Disk Write Operations/Sec",
        "Microsoft.Compute/virtualMachines",
        resource_id,
        resource_id,
        unit="CountPerSecond",
    )
    result = AzureMetricData.query_for(builder, [write], earlier, now)
    assert result[write].first_non_zero() == (datetime(2020, 1, 18, 16, 40, tzinfo=timezone.utc), 4836225.51)
