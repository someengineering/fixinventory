from conftest import roundtrip_check
from fix_plugin_azure.azure_client import MicrosoftClient
from fix_plugin_azure.collector import AzureSubscriptionCollector
from fix_plugin_azure.config import AzureConfig, AzureCredentials
from fix_plugin_azure.resource.base import AzureSubscription, GraphBuilder
from fix_plugin_azure.resource.machinelearning import *

from fixlib.baseresources import Cloud
from fixlib.core.actions import CoreFeedback


def test_workspace(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureMachineLearningWorkspace, builder)
    assert len(collected) == 1


def test_registry(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureMachineLearningRegistry, builder)
    assert len(collected) == 1


def test_workspace_child_resources(
    config: AzureConfig,
    azure_subscription: AzureSubscription,
    credentials: AzureCredentials,
    core_feedback: CoreFeedback,
    azure_client: MicrosoftClient,
) -> None:
    subscription_collector = AzureSubscriptionCollector(
        config, Cloud(id="azure"), azure_subscription, credentials, core_feedback, filter_unused_resources=False
    )
    subscription_collector.collect()

    workspace_and_registry_resources = [
        AzureMachineLearningBatchEndpoint,
        AzureMachineLearningWorkspaceCodeContainer,
        AzureMachineLearningWorkspaceComponentContainer,
        AzureMachineLearningWorkspaceDataContainer,
        AzureMachineLearningWorkspaceModelContainer,
        AzureMachineLearningWorkspaceEnvironmentContainer,
        AzureMachineLearningCompute,
        AzureMachineLearningDatastore,
        AzureMachineLearningEndpoint,
        AzureMachineLearningFeature,
        AzureMachineLearningFeaturesetContainer,
        AzureMachineLearningFeaturestoreEntityContainer,
        AzureMachineLearningJob,
        AzureMachineLearningLabelingJob,
        AzureMachineLearningOnlineEndpoint,
        AzureMachineLearningPrivateEndpointConnection,
        AzureMachineLearningPrivateLink,
        AzureMachineLearningSchedule,
        AzureMachineLearningServerlessEndpoint,
        AzureMachineLearningUsage,
        AzureMachineLearningWorkspaceConnection,
        AzureMachineLearningWorkspaceCodeVersion,
        AzureMachineLearningWorkspaceComponentVersion,
        AzureMachineLearningWorkspaceDataVersion,
        AzureMachineLearningWorkspaceModelVersion,
        AzureMachineLearningWorkspaceEnvironmentVersion,
        AzureMachineLearningFeaturesetVersion,
        AzureMachineLearningFeaturestoreEntityVersion,
        AzureMachineLearningRegistry,
        AzureMachineLearningRegistryCodeContainer,
        AzureMachineLearningRegistryCodeVersion,
        AzureMachineLearningRegistryComponentContainer,
        AzureMachineLearningRegistryComponentVersion,
        AzureMachineLearningRegistryDataContainer,
        AzureMachineLearningRegistryDataVersion,
        AzureMachineLearningRegistryModelContainer,
        AzureMachineLearningRegistryModelVersion,
        AzureMachineLearningRegistryEnvironmentContainer,
        AzureMachineLearningRegistryEnvironmentVersion,
    ]
    for resource in workspace_and_registry_resources:
        instances = list(subscription_collector.graph.search("kind", resource.kind))  # type: ignore

        assert len(instances) > 0, f"No instances found for {resource.__name__}"
