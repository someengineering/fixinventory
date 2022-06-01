import jsons
import pytest

# noinspection PyUnresolvedReferences
from fixtures import json_file
from resoto_plugin_k8s.resources import (
    KubernetesPod,
    KubernetesResource,
    KubernetesNamespace,
    KubernetesNode,
    KubernetesDaemonSet,
    KubernetesDeployment,
)
from resotolib.types import Json


@pytest.mark.json_file("pod.json")
def test_pod(json_file: Json) -> None:
    round_trip(KubernetesPod.from_json(json_file))


@pytest.mark.json_file("namespace.json")
def test_namespace(json_file: Json) -> None:
    round_trip(KubernetesNamespace.from_json(json_file))


@pytest.mark.json_file("node.json")
def test_node(json_file: Json) -> None:
    round_trip(KubernetesNode.from_json(json_file))


@pytest.mark.json_file("daemonset.json")
def test_node(json_file: Json) -> None:
    round_trip(KubernetesDaemonSet.from_json(json_file))


@pytest.mark.json_file("deployment.json")
def test_node(json_file: Json) -> None:
    round_trip(KubernetesDeployment.from_json(json_file))


def round_trip(resource: KubernetesResource) -> None:
    js = resource.to_js()
    again = jsons.load(js, type(resource))
    assert resource == again
