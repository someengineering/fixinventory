import json
import os
from dataclasses import fields
from typing import Type

from resoto_plugin_aws.resource.base import GraphBuilder, AWSResourceType
from resotolib.graph import Graph


def all_props_set(obj: Type[AWSResourceType]) -> None:
    for field in fields(obj):
        prop = field.name
        if not prop.startswith("_") and prop not in [
            "account",
            "arn",
            "atime",
            "mtime",
            "ctime",
            "changes",
            "chksum",
            "last_access",
            "last_update",
        ]:
            if getattr(obj, prop) is None:
                raise Exception(f"Prop >{prop}< is not set")


def round_trip(file: str, cls: Type[AWSResourceType], root: str) -> AWSResourceType:
    path = os.path.abspath(os.path.dirname(__file__) + "/files/" + file)
    builder = GraphBuilder(Graph(), None, None, None)  # type: ignore
    with open(path) as f:
        js = json.load(f)
        cls.collect(js[root], builder)
    assert len(builder.graph.nodes) > 0
    for node in builder.graph.nodes:
        assert isinstance(node, cls)
        as_js = node.to_json()
        again = cls.from_json(as_js)
        assert again.to_json() == as_js
    first = next(iter(builder.graph.nodes))
    all_props_set(first)
    return first  # type: ignore
