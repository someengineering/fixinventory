import json
import os
from attrs import fields
from typing import Type, Any, Callable

from boto3 import Session

from resoto_plugin_aws.aws_client import AwsClient
from resoto_plugin_aws.config import AwsConfig
from resoto_plugin_aws.resource.base import GraphBuilder, AWSResourceType, AWSAccount, AWSRegion
from resotolib.baseresources import Cloud
from resotolib.graph import Graph


class BotoFileClient:
    def __init__(self, service: str) -> None:
        self.service = service

    def __getattr__(self, action_name: str) -> Callable[[], Any]:
        def call_action() -> Any:
            action = action_name.replace("_", "-")
            path = os.path.abspath(os.path.dirname(__file__) + f"/files/{self.service}/{action}.json")
            if os.path.exists(path):
                with open(path) as f:
                    return json.load(f)
            else:
                return {}

        return call_action


# use this factory in tests, to rely on API responses from file system
class BotoFileBasedSession(Session):  # type: ignore
    def client(self, service_name: str, **kwargs: Any) -> Any:
        return BotoFileClient(service_name)


def all_props_set(obj: AWSResourceType) -> None:
    for field in fields(type(obj)):
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
    client = AwsClient(AwsConfig(), "123456789012", "role", "us-east-1")
    builder = GraphBuilder(Graph(), Cloud("test"), AWSAccount("test"), AWSRegion("test"), client)
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
