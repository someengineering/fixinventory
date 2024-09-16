from conftest import roundtrip_check
from fix_plugin_azure.resource.authorization import (
    AzureAuthorizationRoleAssignment,
    AzureAuthorizationRoleDefinition,
    AzureAuthorizationDenyAssignment,
)
from fix_plugin_azure.resource.base import GraphBuilder


def test_role_assignment(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureAuthorizationRoleAssignment, builder)
    assert len(collected) == 3
    for c in collected:
        c.connect_in_graph(builder, {})
    assert len(builder.graph.deferred_edges) == 3


def test_role_definition(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureAuthorizationRoleDefinition, builder)
    assert len(collected) == 2


def test_deny_assignment(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureAuthorizationDenyAssignment, builder)
    assert len(collected) == 1
