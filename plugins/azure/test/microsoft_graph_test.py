from conftest import roundtrip_check
from fix_plugin_azure.resource.base import GraphBuilder
from fix_plugin_azure.resource.microsoft_graph import (
    MicrosoftGraphDevice,
    MicrosoftGraphServicePrincipal,
    MicrosoftGraphGroup,
    MicrosoftGraphRole,
    MicrosoftGraphUser,
    MicrosoftGraphPolicy,
)


def test_microsoft_graph_device(builder: GraphBuilder) -> None:
    collected = roundtrip_check(MicrosoftGraphDevice, builder)
    assert len(collected) == 1


def test_microsoft_graph_service_principal(builder: GraphBuilder) -> None:
    collected = roundtrip_check(MicrosoftGraphServicePrincipal, builder)
    assert len(collected) == 1


def test_microsoft_graph_group(builder: GraphBuilder) -> None:
    collected = roundtrip_check(MicrosoftGraphGroup, builder)
    assert len(collected) == 1


def test_microsoft_graph_role(builder: GraphBuilder) -> None:
    collected = roundtrip_check(MicrosoftGraphRole, builder)
    assert len(collected) == 1


def test_microsoft_graph_user(builder: GraphBuilder) -> None:
    collected = roundtrip_check(MicrosoftGraphUser, builder)
    assert len(collected) == 1


def test_microsoft_graph_policy(builder: GraphBuilder) -> None:
    collected = roundtrip_check(MicrosoftGraphPolicy, builder)
    assert len(collected) == 7
