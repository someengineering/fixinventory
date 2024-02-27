from .random_client import connect_resource, roundtrip
from fix_plugin_gcp.resources.container import *
from fix_plugin_gcp.resources.base import GraphBuilder


def test_gcp_container_cluster(random_builder: GraphBuilder) -> None:
    roundtrip(GcpContainerCluster, random_builder)


def test_gcp_container_operation(random_builder: GraphBuilder) -> None:
    op = roundtrip(GcpContainerOperation, random_builder)
    connect_resource(random_builder, op, GcpContainerCluster, selfLink=op.target_link)
    assert len(random_builder.edges_of(GcpContainerCluster, GcpContainerOperation)) == 1
