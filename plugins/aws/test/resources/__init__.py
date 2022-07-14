import json
import os
import re

from attrs import fields
from typing import Type, Any, Callable, Optional, Set, Tuple

from boto3 import Session

from resoto_plugin_aws.config import AwsConfig
from resoto_plugin_aws.aws_client import AwsClient
from resoto_plugin_aws.resource.base import (
    GraphBuilder,
    AwsResourceType,
    AwsAccount,
    AwsRegion,
    AwsResource,
    AwsApiSpec,
)
from resotolib.baseresources import Cloud
from resotolib.graph import Graph


class BotoDummyStsClient:
    def __getattr__(self, action_name: str) -> Callable[[], Any]:
        def call(*args: Any, **kwargs: Any) -> Any:
            return {"Credentials": {"AccessKeyId": "xxx", "SecretAccessKey": "xxx", "SessionToken": "xxx"}}

        return call


class BotoFileClient:
    def __init__(self, service: str) -> None:
        self.service = service

    @staticmethod
    def can_paginate(_: str) -> bool:
        return False

    @classmethod
    def path_from_action(cls, a: AwsApiSpec) -> str:
        return cls.path_from(a.service, a.api_action, **(a.parameter or {}))

    @staticmethod
    def path_from(service: str, action_name: str, **kwargs: Any) -> str:
        def arg_string(v: Any) -> str:
            if isinstance(v, list):
                return "_".join(arg_string(x) for x in v)
            elif isinstance(v, dict):
                return "_".join(arg_string(v) for k, v in v.items())
            else:
                return re.sub(r"[^a-zA-Z0-9]", "_", str(v))

        vals = "__" + ("_".join(arg_string(v) for _, v in sorted(kwargs.items()))) if kwargs else ""
        action = action_name.replace("_", "-")
        return os.path.abspath(os.path.dirname(__file__) + f"/files/{service}/{action}{vals}.json")

    def __getattr__(self, action_name: str) -> Callable[[], Any]:
        def call_action(*args: Any, **kwargs: Any) -> Any:
            assert not args, "No arguments allowed!"
            path = self.path_from(self.service, action_name, **kwargs)
            if os.path.exists(path):
                with open(path) as f:
                    return json.load(f)
            else:
                # print(f"Not found: {path}")
                return {}

        return call_action


# use this factory in tests, to rely on API responses from file system
class BotoFileBasedSession(Session):  # type: ignore
    def client(self, service_name: str, **kwargs: Any) -> Any:
        return BotoDummyStsClient() if service_name == "sts" else BotoFileClient(service_name)


def all_props_set(obj: AwsResourceType, ignore_props: Set[str]) -> None:
    for field in fields(type(obj)):
        prop = field.name
        if (
            not prop.startswith("_")
            and prop
            not in {
                "account",
                "arn",
                "atime",
                "mtime",
                "ctime",
                "changes",
                "chksum",
                "last_access",
                "last_update",
            }
            | ignore_props
        ):
            if getattr(obj, prop) is None:
                raise Exception(f"Prop >{prop}< is not set: {obj}")


def round_trip_for(cls: Type[AwsResourceType], *ignore_props: str) -> Tuple[AwsResourceType, GraphBuilder]:
    if api := cls.api_spec:
        return round_trip(BotoFileClient.path_from_action(api), cls, api.result_property, set(ignore_props))
    raise AttributeError("No api_spec for class: " + cls.__name__)


def build_from_file(path: str, cls: Type[AwsResourceType], root: Optional[str]) -> GraphBuilder:
    config = AwsConfig()
    config.sessions().session_class_factory = BotoFileBasedSession
    client = AwsClient(config, "123456789012", "role", "us-east-1")
    builder = GraphBuilder(Graph(), Cloud(id="test"), AwsAccount(id="test"), AwsRegion(id="test"), client)
    with open(path) as f:
        js = json.load(f)
        js = js[root] if root else [js]
        cls.collect(js, builder)
    return builder


def check_single_node(node: AwsResource) -> None:
    assert isinstance(node, AwsResource), f"Expect AWSResource but got: {type(node)}: {node}"
    as_js = node.to_json()
    again = type(node).from_json(as_js)
    assert again.to_json() == as_js, f"Left: {as_js}\nRight: {again.to_json()}"


def round_trip(
    file: str, cls: Type[AwsResourceType], root: Optional[str] = None, ignore_props: Optional[Set[str]] = None
) -> Tuple[AwsResourceType, GraphBuilder]:
    builder = build_from_file(file, cls, root)
    assert len(builder.graph.nodes) > 0
    for node, data in builder.graph.nodes(data=True):
        node.connect_in_graph(builder, data["source"])
        check_single_node(node)
    first = next(iter(builder.graph.nodes))
    all_props_set(first, ignore_props or set())
    return first, builder
