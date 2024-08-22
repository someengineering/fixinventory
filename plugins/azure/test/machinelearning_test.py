from conftest import roundtrip_check
from fix_plugin_azure.resource.base import GraphBuilder
from fix_plugin_azure.resource.machinelearning import AzureMachineLearningWorkspace, AzureMachineLearningRegistry


def test_workspace(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureMachineLearningWorkspace, builder)
    assert len(collected) == 1


def test_registry(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureMachineLearningRegistry, builder)
    assert len(collected) == 1
