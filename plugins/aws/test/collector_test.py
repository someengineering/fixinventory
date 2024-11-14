import json
import threading
from contextlib import suppress
from typing import Type, List, Tuple, Set, Any

from networkx import DiGraph, is_directed_acyclic_graph

from fix_plugin_aws.collector import (
    AwsAccountCollector,
    all_resources,
    called_collect_apis,
    called_mutator_apis,
)
from fix_plugin_aws.resource.base import AwsResource, AwsApiSpec, GraphBuilder, AwsRegion
from fix_plugin_aws.resource.ec2 import AwsEc2Instance
from fixlib.baseresources import BaseResource
from fixlib.core.model_export import dataclasses_to_fixcore_model
from test import account_collector, builder, aws_client, aws_config, no_feedback  # noqa: F401


def test_collect(account_collector: AwsAccountCollector) -> None:
    account_collector.collect()

    def count_kind(clazz: Type[AwsResource]) -> int:
        count = 0
        for node in account_collector.graph.nodes:
            if isinstance(node, clazz):
                count += 1
        return count

    for resource in all_resources:
        # there will be no instances of resources that are not exported
        if not resource._model_export:
            continue
        assert count_kind(resource) > 0, f"No instances of {resource.__name__} found"

    # make sure all threads have been joined
    assert len(threading.enumerate()) == 1
    # ensure the correct number of nodes and edges
    assert count_kind(AwsResource) == 257
    assert len(account_collector.graph.edges) == 571
    assert len(account_collector.graph.deferred_edges) == 2
    for node in account_collector.graph.nodes:
        if isinstance(node, AwsRegion):
            assert node.region_in_use


def test_dependencies() -> None:
    model = dataclasses_to_fixcore_model({AwsResource})

    def for_edge_type(edge_type: str) -> DiGraph:
        graph = DiGraph()
        for kind in model:
            if (successors := kind.get("successor_kinds")) and edge_type in successors:
                for successor in successors[edge_type]:
                    graph.add_edge(kind["fqn"], successor)
        return graph

    def show_graph(graph: DiGraph) -> str:
        result = "digraph {\n"
        for start, end in graph.edges:
            result += "  " + start + "->" + end + "\n"
        result += "}"
        return result

    assert is_directed_acyclic_graph(for_edge_type("default")), show_graph(for_edge_type("default"))
    assert is_directed_acyclic_graph(for_edge_type("delete")), show_graph(for_edge_type("delete"))


def test_all_called_apis() -> None:
    def iam_statement(name: str, apis: List[AwsApiSpec]) -> Tuple[Set[str], str]:
        permissions = {api.iam_permission() for api in apis}
        doc = dict(Sid=name, Effect="Allow", Action=sorted(permissions), Resource="*")
        return permissions, json.dumps(doc, indent=2)

    collect_allow, collect_statement = iam_statement("FixCollectPermission", called_collect_apis())
    print("\n\n", collect_statement, "\n\n")
    assert json.loads(collect_statement)
    assert len(collect_allow) >= 74
    assert "s3:ListAllMyBuckets" in collect_allow

    mutate_allow, mutate_statement = iam_statement("FixMutatePermission", called_mutator_apis())
    print("\n\n", mutate_statement, "\n\n")


def test_service_name_is_defined_in_all_resources() -> None:
    for rt in all_resources:
        assert rt.service_name() is not None, rt.__name__ + " has no service_name"


def test_raise_error_if_configured(builder: GraphBuilder) -> None:
    # make sure any mapping exception is raised
    builder.config.discard_account_on_resource_error = True
    with suppress(Exception):
        AwsEc2Instance.from_api({"is": "wrong"}, builder)

    # ignore any mapping exception
    builder.config.discard_account_on_resource_error = False
    assert AwsEc2Instance.from_api({"is": "wrong"}, builder) is None


def test_resource_classes() -> None:
    def all_base_classes(cls: Type[Any]) -> Set[Type[Any]]:
        bases = set(cls.__bases__)
        for base in cls.__bases__:
            bases.update(all_base_classes(base))
        return bases

    expected_declared_properties = ["kind", "_kind_display"]
    expected_props_in_hierarchy = ["_kind_service", "_metadata"]
    for rc in all_resources:
        if not rc._model_export:
            continue
        for prop in expected_declared_properties:
            assert prop in rc.__dict__, f"{rc.__name__} missing {prop}"
        with_bases = (all_base_classes(rc) | {rc}) - {AwsResource, BaseResource}
        for prop in expected_props_in_hierarchy:
            assert any(prop in base.__dict__ for base in with_bases), f"{rc.__name__} missing {prop}"
        for base in with_bases:
            if "connect_in_graph" in base.__dict__:
                assert (
                    "_reference_kinds" in base.__dict__
                ), f"{rc.__name__} should define _reference_kinds property, since it defines connect_in_graph"
