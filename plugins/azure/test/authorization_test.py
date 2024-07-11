from conftest import roundtrip_check
from fix_plugin_azure.resource.authorization import AzureRoleAssignment, AzureRoleDefinition, AzureDenyAssignment
from fix_plugin_azure.resource.base import GraphBuilder


def test_role_assignment(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureRoleAssignment, builder)
    assert len(collected) == 3


def test_role_definition(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureRoleDefinition, builder)
    assert len(collected) == 2


def test_deny_assignment(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureDenyAssignment, builder)
    assert len(collected) == 1
