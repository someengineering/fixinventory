from conftest import roundtrip_check
from fix_plugin_azure.resource.base import GraphBuilder
from fix_plugin_azure.resource.postgresql import (
    AzurePostgresqlServer,
    AzurePostgresqlCapability,
)


def test_sql_instance_pool(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzurePostgresqlServer, builder)
    assert len(collected) == 1


def test_sql_managed_instance(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzurePostgresqlCapability, builder)
    assert len(collected) == 1
