from .random_client import roundtrip
from resoto_plugin_gcp.resources.base import GraphBuilder
from resoto_plugin_gcp.resources.container import *


def test_gcp_container_cluster(random_builder: GraphBuilder) -> None:
    roundtrip(GcpContainerCluster, random_builder)


def test_gcp_container_operation(random_builder: GraphBuilder) -> None:
    roundtrip(GcpContainerOperation, random_builder)
