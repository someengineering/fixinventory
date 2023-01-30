from .random_client import roundtrip, json_roundtrip
from resoto_plugin_gcp.resources.billing import *


def test_gcp_billing_account(random_builder: GraphBuilder) -> None:
    roundtrip(GcpBillingAccount, random_builder)
    json_roundtrip(GcpProjectBillingInfo, random_builder)
    assert len(random_builder.edges_of(GcpBillingAccount, GcpProjectBillingInfo)) > 0


def test_gcp_service(random_builder: GraphBuilder) -> None:
    roundtrip(GcpService, random_builder)
    json_roundtrip(GcpSku, random_builder)
    assert len(random_builder.edges_of(GcpService, GcpSku)) > 0
