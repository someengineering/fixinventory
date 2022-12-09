import json
import os
import re
from concurrent.futures import Executor, Future
from queue import Queue
from typing import Type, Any, Callable, Set, Tuple, Optional

from attrs import fields
from boto3 import Session

from resoto_plugin_aws.aws_client import AwsClient
from resoto_plugin_aws.configuration import AwsConfig
from resoto_plugin_aws.resource.base import (
    GraphBuilder,
    AwsResourceType,
    AwsAccount,
    AwsRegion,
    AwsResource,
    AwsApiSpec,
    ExecutorQueue,
)
from resotolib.baseresources import Cloud
from resotolib.core.actions import CoreFeedback
from resotolib.graph import Graph


class DummyExecutor(Executor):
    def submit(self, fn: Callable[..., Any], *args: Any, **kwargs: Any) -> Future[Any]:  # type: ignore
        result = fn(*args, **kwargs)
        f: Future[Any] = Future()
        f.set_result(result)
        return f


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
    def path_from(service_name: str, action_name: str, **kwargs: Any) -> str:
        def arg_string(v: Any) -> str:
            if isinstance(v, list):
                return "_".join(arg_string(x) for x in v)
            elif isinstance(v, dict):
                return "_".join(arg_string(v) for k, v in v.items())
            else:
                return re.sub(r"[^a-zA-Z0-9]", "_", str(v))

        vals = "__" + ("_".join(arg_string(v) for _, v in sorted(kwargs.items()))) if kwargs else ""
        # cut the action string if it becomes too long
        vals = vals[0:220] if len(vals) > 220 else vals
        action = action_name.replace("_", "-")
        service = service_name.replace("-", "_")
        path = os.path.dirname(__file__) + f"/files/{service}/{action}{vals}.json"
        return os.path.abspath(path)

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


class BotoErrorClient:
    def __init__(self, exception: Exception):
        self.exception = exception

    def __getattr__(self, action_name: str) -> Callable[[], Any]:
        raise self.exception


# use this factory in tests, to check how the collector behaves n terms of errors
class BotoErrorSession(Session):  # type: ignore
    def __init__(self, exception: Exception = Exception("Test exception"), **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.exception = exception

    def client(self, service_name: str, **kwargs: Any) -> Any:
        return BotoErrorClient(self.exception)

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        return self


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


def build_graph(cls: Type[AwsResourceType], region_name: Optional[str] = None) -> GraphBuilder:
    config = AwsConfig()
    config.sessions().session_class_factory = BotoFileBasedSession
    client = AwsClient(config, "123456789012", role="role", region=(region_name or "us-east-1"))
    queue = ExecutorQueue(DummyExecutor(), "test")
    region = AwsRegion(id="eu-central-1", name=(region_name or "eu-central-1"))
    feedback = CoreFeedback("test", "test", "collect", Queue())
    builder = GraphBuilder(Graph(), Cloud(id="test"), AwsAccount(id="test"), region, client, queue, feedback)
    cls.collect_resources(builder)
    builder.executor.wait_for_submitted_work()
    return builder


def check_single_node(node: AwsResource) -> None:
    assert isinstance(node, AwsResource), f"Expect AWSResource but got: {type(node)}: {node}"
    as_js = node.to_json()
    again = type(node).from_json(as_js)
    assert again.to_json() == as_js, f"Left: {as_js}\nRight: {again.to_json()}"


def round_trip_for(
    cls: Type[AwsResourceType],
    *ignore_props: str,
    region_name: Optional[str] = None,
) -> Tuple[AwsResourceType, GraphBuilder]:
    builder = build_graph(cls, region_name=region_name)
    assert len(builder.graph.nodes) > 0
    for node, data in builder.graph.nodes(data=True):
        node.connect_in_graph(builder, data["source"])
        check_single_node(node)
    first = next(iter(builder.graph.nodes))
    all_props_set(first, set(ignore_props))
    return first, builder
