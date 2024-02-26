from .random_client import FixturedClient, roundtrip, json_roundtrip
from fix_plugin_gcp.resources.billing import *
from fix_plugin_gcp.resources.base import GraphBuilder


def test_gcp_billing_account(random_builder: GraphBuilder) -> None:
    roundtrip(GcpBillingAccount, random_builder)
    json_roundtrip(GcpProjectBillingInfo, random_builder)
    assert len(random_builder.edges_of(GcpBillingAccount, GcpProjectBillingInfo)) > 0


def test_gcp_service(random_builder: GraphBuilder) -> None:
    roundtrip(GcpService, random_builder)


def test_gcp_service_and_sku(random_builder: GraphBuilder) -> None:
    SERVICE_ID = "services/6F81-5844-456A"
    SERVICE_NAME = "Compute Engine"
    fixture_replies = {
        "Service": {"serviceId": lambda: SERVICE_ID, "displayName": lambda: SERVICE_NAME},
        "Sku": {"name": lambda: SERVICE_ID},
    }
    with FixturedClient(random_builder, fixture_replies) as random_builder:
        services = GcpService.collect_resources(random_builder)
        random_builder.executor.wait_for_submitted_work()
        for service in services:
            service.connect_in_graph(random_builder, {"Dummy": "Source"})
        assert len(random_builder.edges_of(GcpService, GcpSku)) > 0
