import json
import os
from pathlib import Path
from queue import Queue
from typing import List

import yaml

from fix_plugin_gcp import GcpConfig
from fix_plugin_gcp.collector import GcpProjectCollector, all_resources, called_collect_apis, called_mutator_apis
from fix_plugin_gcp.gcp_client import GcpApiSpec
from fix_plugin_gcp.resources.base import GcpProject, GraphBuilder
from fix_plugin_gcp.resources.billing import GcpSku
from fix_plugin_gcp.resources.compute import GcpMachineType
from fixlib.baseresources import Cloud
from fixlib.config import current_config
from fixlib.core.actions import CoreFeedback
from fixlib.graph import Graph


def collector_with_graph(graph: Graph) -> GcpProjectCollector:
    collector = GcpProjectCollector(
        config=GcpConfig(),
        cloud=Cloud(id="gcp"),
        project=GcpProject(id="test"),
        core_feedback=CoreFeedback("test", "test", "test", Queue()),
    )
    collector.graph = graph
    return collector


def test_project_collection(random_builder: GraphBuilder) -> None:
    # create the collector from the builder values
    config: GcpConfig = current_config().gcp
    project = GcpProjectCollector(config, random_builder.cloud, random_builder.project, random_builder.core_feedback)
    # use the graph provided by the random builder - it already has regions and zones
    # the random builder will not create new regions or zones during the test
    project.graph = random_builder.graph
    project.collect()
    # the number of resources in the graph is not fixed, but it should be at least the number of resource kinds
    assert len(project.graph.nodes) >= len(all_resources)


def test_remove_unconnected_nodes(random_builder: GraphBuilder) -> None:
    with open(os.path.dirname(__file__) + "/files/machine_type.json") as f:
        GcpMachineType.collect(raw=json.load(f)["items"]["machineTypes"], builder=random_builder)
    with open(os.path.dirname(__file__) + "/files/skus.json") as f:
        GcpSku.collect(raw=json.load(f)["skus"], builder=random_builder)

    collector = collector_with_graph(random_builder.graph)

    num_all_machine_types = len(list(collector.graph.search("kind", "gcp_machine_type")))
    num_all_skus = len(list(collector.graph.search("kind", "gcp_sku")))

    collector.remove_unconnected_nodes()

    assert len(list(collector.graph.search("kind", "gcp_machine_type"))) < num_all_machine_types
    assert len(list(collector.graph.search("kind", "gcp_sku"))) < num_all_skus


def test_role_creation() -> None:
    def iam_role_for(name: str, description: str, calls: List[GcpApiSpec], file: bool = False) -> str:
        permissions = sorted({p for api in calls for p in api.iam_permissions})
        result = yaml.safe_dump(
            {"title": name, "description": description, "stage": "GA", "includedPermissions": permissions},
            sort_keys=False,
        )
        if file:
            with open(Path.home() / f"{name}.yaml", "w") as f:
                f.write(result)
        return result

    write_files = False
    c = iam_role_for("fix_access", "Permissions required to collect resources.", called_collect_apis(), write_files)
    m = iam_role_for("fix_mutate", "Permissions required to mutate resources.", called_mutator_apis(), write_files)
    assert c is not None
    assert m is not None
