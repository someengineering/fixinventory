from conftest import roundtrip_check
from fix_plugin_azure.resource.base import GraphBuilder
from fix_plugin_azure.resource.postgresql import (
    AzurePostgresqlServer,
)


def test_postgres_server(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzurePostgresqlServer, builder)
    assert len(collected) == 1
