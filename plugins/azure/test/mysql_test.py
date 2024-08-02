from conftest import roundtrip_check
from fix_plugin_azure.resource.base import GraphBuilder
from fix_plugin_azure.resource.mysql import AzureMysqlServer


def test_mysql_server(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureMysqlServer, builder)
    assert len(collected) == 1
