import json
import os
from resoto_plugin_gcp.resources.base import *
from resoto_plugin_gcp.resources.compute import GcpMachineType


def test_node_by_filter(random_builder: GraphBuilder) -> None:
    with open(os.path.dirname(__file__) + "/files/machine_type.json") as f:
        GcpMachineType.collect(raw=json.load(f)["items"]["machineTypes"], builder=random_builder)

    assert random_builder.node(clazz=GcpMachineType, id="804416")

    def filter_1(node: GcpMachineType) -> bool:
        return node.name is not None and node.name.startswith("m2-ultramem") and node.kind == "gcp_machine_type"

    def filter_2(node: GcpMachineType) -> bool:
        return node.name is not None and node.name.startswith("m2-ultramem")

    assert random_builder.node(filter=filter_1)
    assert random_builder.node(clazz=GcpMachineType, filter=filter_2)


def test_nodes_by_filter(random_builder: GraphBuilder) -> None:
    with open(os.path.dirname(__file__) + "/files/machine_type.json") as f:
        GcpMachineType.collect(raw=json.load(f)["items"]["machineTypes"], builder=random_builder)

    def filter_1(node: GcpMachineType) -> bool:
        return node.instance_cores > 16

    nodes = random_builder.nodes(clazz=GcpMachineType, filter=filter_1)
    assert len(nodes) == 5
    nodes = random_builder.nodes(clazz=GcpMachineType, maximum_persistent_disks=128)
    assert len(nodes) == 7
