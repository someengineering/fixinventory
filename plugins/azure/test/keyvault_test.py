from conftest import roundtrip_check
from fix_plugin_azure.resource.base import GraphBuilder
from fix_plugin_azure.resource.keyvault import AzureKeyVault, AzureManagedHsm, AzureKey
from fix_plugin_azure.resource.monitor import (
    AzureMonitorActionGroup,
    AzureMonitorActivityLogAlert,
    AzureMonitorAlertRule,
    AzureMonitorLogProfile,
    AzureMetricAlert,
    AzureMonitorPrivateLinkScope,
    AzureMonitorWorkspace,
    AzureMonitorDataCollectionRule,
    AzureMonitorPipelineGroup,
    AzureMonitorScheduledQueryRule,
    AzureMonitorDiagnosticSettings,
)


def test_key_vault(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureKeyVault, builder)
    assert len(collected) == 1
    collected[0].post_process(builder, {})
    builder.executor.wait_for_submitted_work()
    assert len(builder.nodes(AzureKey)) == 4


def test_hsm(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureManagedHsm, builder)
    assert len(collected) == 2
