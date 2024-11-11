import json
import os

from fix_plugin_gcp.resources.base import GraphBuilder
from fix_plugin_gcp.resources.aiplatform import resources


def test_gcp_aiplatform_resources(random_builder: GraphBuilder) -> None:
    file_path = os.path.join(os.path.dirname(__file__), "files", "aiplatform_resources.json")
    with open(file_path, "r") as f:
        data = json.load(f)

    for resource, res_class in zip(data["resources"], resources):
        res_class.collect(raw=[resource], builder=random_builder)
        collected = random_builder.nodes(clazz=res_class)
        assert len(collected) == 1
