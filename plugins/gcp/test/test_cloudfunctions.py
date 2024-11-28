import json
import os

from fix_plugin_gcp.resources.base import GraphBuilder
from fix_plugin_gcp.resources.cloudfunctions import GcpCloudFunction


def test_gcp_cloudfunctions(random_builder: GraphBuilder) -> None:
    with open(os.path.dirname(__file__) + "/files/cloudfunctions.json") as f:
        GcpCloudFunction.collect(raw=json.load(f)["functions"], builder=random_builder)

    functions = random_builder.nodes(clazz=GcpCloudFunction)
    assert len(functions) == 1
