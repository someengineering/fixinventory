from .random_client import roundtrip
from resoto_plugin_gcp.resources.storage import *
from resoto_plugin_gcp.resources.base import GraphBuilder


def test_gcp_billing_account(random_builder: GraphBuilder) -> None:
    roundtrip(GcpBucket, random_builder)
