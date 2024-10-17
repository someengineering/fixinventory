from conftest import roundtrip_check
from fix_plugin_azure.resource.base import GraphBuilder
from fix_plugin_azure.resource.monitor import (
    AzureMonitorActionGroup,
    AzureMonitorActivityLogAlert,
    AzureMonitorAlertRule,
    AzureMonitorLogProfile,
    AzureMonitorMetricAlert,
    AzureMonitorPrivateLinkScope,
    AzureMonitorWorkspace,
    AzureMonitorDataCollectionRule,
    AzureMonitorPipelineGroup,
    AzureMonitorScheduledQueryRule,
    AzureMonitorDiagnosticSettings,
)


def test_action_groups(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureMonitorActionGroup, builder)
    assert len(collected) == 2


def test_activity_log_alert(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureMonitorActivityLogAlert, builder)
    assert len(collected) == 2


def test_alert_rule(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureMonitorAlertRule, builder)
    assert len(collected) == 2


def test_data_collection_rule(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureMonitorDataCollectionRule, builder)
    assert len(collected) == 2


def test_log_profile(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureMonitorLogProfile, builder)
    assert len(collected) == 1


def test_alert(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureMonitorMetricAlert, builder)
    assert len(collected) == 2


def test_private_link_scope(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureMonitorPrivateLinkScope, builder)
    assert len(collected) == 2


def test_monitor_workspace(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureMonitorWorkspace, builder)
    assert len(collected) == 2


def test_pipeline_group(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureMonitorPipelineGroup, builder)
    assert len(collected) == 2


def test_scheduled_query_rule(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureMonitorScheduledQueryRule, builder)
    assert len(collected) == 2


def test_subscription_diagnostic(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureMonitorDiagnosticSettings, builder)
    assert len(collected) == 1
