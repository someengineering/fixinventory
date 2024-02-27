from conftest import roundtrip_check
from fix_plugin_azure.resource.base import GraphBuilder, AzureResourceGroup


def test_resource_group(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureResourceGroup, builder)
    assert len(collected) == 2
