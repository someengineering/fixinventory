from conftest import roundtrip_check

from fix_plugin_azure.azure_client import MicrosoftClient
from fix_plugin_azure.collector import AzureSubscriptionCollector
from fix_plugin_azure.config import AzureConfig, AzureCredentials
from fix_plugin_azure.resource.base import AzureSubscription, GraphBuilder
from fix_plugin_azure.resource.compute import AzureComputeVirtualMachineScaleSet
from fix_plugin_azure.resource.security import (
    AzureSecurityPricing,
    AzureSecurityServerVulnerabilityAssessmentsSetting,
    AzureSecuritySetting,
    AzureSecurityAutoProvisioningSetting,
)

from fixlib.baseresources import Cloud, Severity
from fixlib.core.actions import CoreFeedback


def test_security_assessment(
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
    instances = list(subscription_collector.graph.search("kind", AzureComputeVirtualMachineScaleSet.kind))
    assert instances[0]._assessments[0].provider == "azure_security_assessment"
    assert (
        instances[0]._assessments[0].findings[0].title
        == "Install endpoint protection solution on virtual machine scale sets"
    )
    assert instances[0]._assessments[0].findings[0].severity == Severity.medium


def test_security_pricing(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureSecurityPricing, builder)
    assert len(collected) == 13


def test_security_server_vulnerability_assessments_setting(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureSecurityServerVulnerabilityAssessmentsSetting, builder)
    assert len(collected) == 1


def test_security_setting(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureSecuritySetting, builder)
    assert len(collected) == 4


def test_auto_provisioning_setting(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureSecurityAutoProvisioningSetting, builder)
    assert len(collected) == 2
    assert collected[0].auto_provision
    assert not collected[1].auto_provision
