import json
from typing import List
from xml.etree import ElementTree

import pytest
import yaml
from aiostream import stream
from hypothesis import given, settings, HealthCheck
from hypothesis.strategies import lists

from core.types import JsonElement, Json
from core.web.content_renderer import (
    respond_json,
    respond_ndjson,
    respond_yaml,
    respond_dot,
    respond_text,
    respond_cytoscape,
    respond_graphml,
)
from tests.core.hypothesis_extension import (
    json_array_gen,
    json_simple_element_gen,
    node_gen,
    graph_stream,
)


@given(json_array_gen)
@settings(max_examples=20, suppress_health_check=HealthCheck.all())
@pytest.mark.asyncio
async def test_json(elements: List[JsonElement]) -> None:
    async with stream.iterate(elements).stream() as streamer:
        result = ""
        async for elem in respond_json(streamer):
            result += elem
        assert json.loads(result) == elements


@given(json_array_gen)
@settings(max_examples=20, suppress_health_check=HealthCheck.all())
@pytest.mark.asyncio
async def test_ndjson(elements: List[JsonElement]) -> None:
    async with stream.iterate(elements).stream() as streamer:
        result = []
        async for elem in respond_ndjson(streamer):
            result.append(json.loads(elem.strip()))
        assert result == elements


@given(json_array_gen)
@settings(max_examples=20, suppress_health_check=HealthCheck.all())
@pytest.mark.asyncio
async def test_yaml(elements: List[JsonElement]) -> None:
    async with stream.iterate(elements).stream() as streamer:
        result = ""
        async for elem in respond_yaml(streamer):
            result += elem
        assert [a for a in yaml.full_load_all(result)] == elements


@given(lists(json_simple_element_gen, min_size=1, max_size=10))
@settings(max_examples=20, suppress_health_check=HealthCheck.all())
@pytest.mark.asyncio
async def test_text_simple_elements(elements: List[JsonElement]) -> None:
    async with stream.iterate(elements).stream() as streamer:
        result = ""
        async for elem in respond_text(streamer):
            result += elem
        # every element is rendered as single line
        assert len(elements) == len(result.split("\n"))


@given(lists(node_gen(), min_size=1, max_size=10))
@settings(max_examples=20, suppress_health_check=HealthCheck.all())
@pytest.mark.asyncio
async def test_text_complex_elements(elements: List[JsonElement]) -> None:
    async with stream.iterate(elements).stream() as streamer:
        result = ""
        async for elem in respond_text(streamer):
            result += elem
        # every element is rendered as yaml with --- as object deliminator
        assert len(elements) == len(result.split("---"))


@given(lists(node_gen(), min_size=1, max_size=10))
@settings(max_examples=20, suppress_health_check=HealthCheck.all())
@pytest.mark.asyncio
async def test_cytoscape(elements: List[Json]) -> None:
    async with graph_stream(elements).stream() as streamer:
        result = ""
        async for elem in respond_cytoscape(streamer):
            result += elem
        # The resulting string can be parsed as json
        assert json.loads(result)


@given(lists(node_gen(), min_size=1, max_size=10))
@settings(max_examples=20, suppress_health_check=HealthCheck.all())
@pytest.mark.asyncio
async def test_graphml(elements: List[Json]) -> None:
    async with graph_stream(elements).stream() as streamer:
        result = ""
        async for elem in respond_graphml(streamer):
            result += elem
    # The resulting string can be parsed as xml
    assert ElementTree.fromstring(result)


@pytest.mark.asyncio
async def test_dot() -> None:
    def node(name: str, account_name: str) -> Json:
        ancestors = {"account": {"reported": {"name": account_name}}}
        return {"type": "node", "id": name, "reported": {"kind": name, "name": name}, "ancestors": ancestors}

    def edge(from_node: str, to_node: str) -> Json:
        return {"type": "edge", "from": from_node, "to": to_node}

    nodes = [node("a", "acc1"), node("b", "acc1"), node("c", "acc2")]
    edges = [edge("a", "b"), edge("a", "c"), edge("b", "c")]

    async with stream.iterate(nodes + edges).stream() as streamer:
        result = ""
        async for elem in respond_dot(streamer):
            result += elem
        expected = (
            "digraph {\n"
            "rankdir=LR\n"
            "overlap=false\n"
            "splines=true\n"
            "node [shape=Mrecord colorscheme=paired12]\n"
            "edge [arrowsize=0.5]\n"
            ' "a" [label="a|a", style=filled fillcolor=1];\n'
            ' "b" [label="b|b", style=filled fillcolor=2];\n'
            ' "c" [label="c|c", style=filled fillcolor=3];\n'
            ' "a" -> "b"\n'
            ' "a" -> "c"\n'
            ' "b" -> "c"\n'
            ' subgraph "acc1" {\n'
            '    "a"\n'
            '    "b"\n'
            " }\n"
            ' subgraph "acc2" {\n'
            '    "c"\n'
            " }\n"
            "}"
        )
        assert result == expected
