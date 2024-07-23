from conftest import roundtrip_check
from fix_plugin_azure.resource.base import GraphBuilder
from fix_plugin_azure.resource.mysql import AzureMysqlCapability, AzureMysqlCapabilitySet, AzureMysqlServer


def test_mysql_capability(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureMysqlCapability, builder)
    assert len(collected) == 1


def test_mysql_capability_set(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureMysqlCapabilitySet, builder)
    assert len(collected) == 1


def test_mysql_server(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureMysqlServer, builder)
    assert len(collected) == 1
