from .random_client import roundtrip
from resoto_plugin_gcp.resources.base import GraphBuilder
from resoto_plugin_gcp.resources.billing import *


def test_gcp_billing_account(random_builder: GraphBuilder) -> None:
    roundtrip(GcpBillingAccount, random_builder)


def test_gcp_service(random_builder: GraphBuilder) -> None:
    roundtrip(GcpService, random_builder)
