from conftest import roundtrip_check
from fix_plugin_azure.resource.base import GraphBuilder
from fix_plugin_azure.resource.sql import (
    AzureSqlServerManagedInstancePool,
    AzureSqlServerManagedInstance,
    AzureSqlServer,
    AzureSqlServerVirtualCluster,
)


def test_sql_instance_pool(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureSqlServerManagedInstancePool, builder)
    assert len(collected) == 2


def test_sql_managed_instance(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureSqlServerManagedInstance, builder)
    assert len(collected) == 2


def test_sql_server(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureSqlServer, builder)
    assert len(collected) == 1


def test_sql_virtual_cluster(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureSqlServerVirtualCluster, builder)
    assert len(collected) == 2
