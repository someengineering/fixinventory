import json
import os
from fix_plugin_gcp.resources.base import *
from fix_plugin_gcp.resources.compute import GcpMachineType


def test_node_by_filter(random_builder: GraphBuilder) -> None:
    with open(os.path.dirname(__file__) + "/files/machine_type.json") as f:
        GcpMachineType.collect(raw=json.load(f)["items"]["machineTypes"], builder=random_builder)

    assert random_builder.node(clazz=GcpMachineType, name="m2-ultramem-416")

    def filter_1(node: GcpMachineType) -> bool:
        return node.name is not None and node.name.startswith("m2-ultramem") and node.kind == "gcp_machine_type"

    def filter_2(node: GcpMachineType) -> bool:
        return node.name is not None and node.name.startswith("m2-ultramem")

    def filter_3(node: GcpMachineType) -> bool:
        return node.name is not None and node.name.startswith("m")

    assert random_builder.node(filter=filter_1)
    assert random_builder.node(clazz=GcpMachineType, filter=filter_2)
    node_1 = random_builder.node(clazz=GcpMachineType, filter=filter_3)
    node_2 = random_builder.node(clazz=GcpMachineType, filter=filter_3, instance_cores=416)
    assert node_1 != node_2


def test_nodes_by_filter(random_builder: GraphBuilder) -> None:
    with open(os.path.dirname(__file__) + "/files/machine_type.json") as f:
        GcpMachineType.collect(raw=json.load(f)["items"]["machineTypes"], builder=random_builder)

    def filter_1(node: GcpMachineType) -> bool:
        return node.instance_cores > 16

    nodes = random_builder.nodes(clazz=GcpMachineType, filter=filter_1)
    assert len(nodes) == 5
    nodes = random_builder.nodes(clazz=GcpMachineType, maximum_persistent_disks=128)
    assert len(nodes) == 7


def test_gcp_region_collects_quotas(random_builder: GraphBuilder) -> None:
    with open(os.path.dirname(__file__) + "/files/gcp_regions.json") as f:
        GcpRegion.collect(raw=json.load(f)["items"], builder=random_builder)

    region_quotas = random_builder.nodes(clazz=GcpRegionQuota)
    assert len(region_quotas) == 2  # 2 regions in the file

    for predecessor in random_builder.graph.predecessors(region_quotas[0]):
        assert isinstance(predecessor, GcpRegion)
