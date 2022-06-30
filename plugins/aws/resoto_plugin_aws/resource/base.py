import logging
from dataclasses import dataclass
from typing import ClassVar, Dict, Optional, List, Type, Any, TypeVar

import jsons

from resoto_plugin_aws.resources import AWSRegion, AWSEC2InstanceType, AWSAccount
from resotolib.baseresources import BaseResource, EdgeType, Cloud
from resotolib.graph import Graph
from resotolib.json_bender import Bender, bend
from resotolib.types import Json

log = logging.getLogger("resoto.plugins.aws")


@dataclass(eq=False)
class AWSResource(BaseResource):
    mapping: ClassVar[Dict[str, Bender]] = {}
    kind: ClassVar[str] = "aws_resource"
    arn: Optional[str] = None

    # TODO: implement me
    def update_tag(self, key, value) -> bool:
        pass

    # TODO: implement me
    def delete_tag(self, key) -> bool:
        pass

    # TODO: implement me
    def delete(self, graph) -> bool:
        return False

    def to_json(self) -> Json:
        return jsons.dump(  # type: ignore
            self,
            strip_privates=True,
            strip_nulls=True,
            strip_attr=(
                "mapping",
                "phantom",
                "successor_kinds",
                "parent_resource",
                "usage_percentage",
                "dname",
                "kdname",
                "rtdname",
                "changes",
                "event_log",
                "str_event_log",
                "chksum",
                "age",
                "last_access",
                "last_update",
                "clean",
                "cleaned",
                "protected",
                "_graph",
                "graph",
                "max_graph_depth",
                "resource_type",
                "age",
                "last_access",
                "last_update",
                "clean",
                "cleaned",
                "protected",
                "uuid",
                "kind",
            ),
        )

    @classmethod
    def from_json(cls: Type["AWSResource"], json: Json) -> "AWSResource":
        return jsons.load(json, cls)  # type: ignore

    @classmethod
    def from_api(cls: Type["AWSResource"], json: Json) -> "AWSResource":
        mapped = bend(cls.mapping, json)
        return cls.from_json(mapped)

    @classmethod
    def collect(cls: Type["AWSResource"], json: List[Json], builder: "GraphBuilder") -> None:
        # Default behavior: iterate over json snippets and for each:
        # - bend the json
        # - transform the result into a resource
        # - add the resource to the graph
        # In case additional work needs to be done, override this method.
        for js in json:
            instance = cls.from_api(js)
            builder.add_node(instance, js)

    def connect_in_graph(self, builder: "GraphBuilder", source: Json) -> None:
        # Default behavior: add resource to the namespace
        pass

    def __str__(self) -> str:
        return f"{self.kind}:{self.name}"


AWSResourceType = TypeVar("AWSResourceType", bound=AWSResource)


class GraphBuilder:
    def __init__(self, graph: Graph, cloud: Cloud, account: AWSAccount, region: AWSRegion) -> None:
        self.graph = graph
        self.cloud = cloud
        self.account = account
        self.region = region
        self.name = getattr(graph.root, "name", "unknown")

    def node(self, clazz: Optional[Type[AWSResource]] = None, **node: Any) -> Optional[AWSResource]:
        if isinstance(nd := node.get("node"), AWSResource):
            return nd
        for n in self.graph:
            f: AWSResource = n
            is_clazz = isinstance(n, clazz) if clazz else True
            if is_clazz and f.region() == self.region and all(getattr(n, k, None) == v for k, v in node.items()):
                return n  # type: ignore
        return None

    def add_node(self, node: AWSResource, source: Json) -> None:
        log.debug(f"{self.name}: add node {node}")
        node._cloud = self.cloud
        node._account = self.account
        node._region = self.region
        self.graph.add_node(node, source=source)

    def add_edge(self, from_node: AWSResource, edge_type: EdgeType, reverse: bool = False, **to_node: Any) -> None:
        to_n = self.node(**to_node)
        if to_n:
            start, end = (to_n, from_node) if reverse else (from_node, to_n)
            log.debug(f"{self.name}: add edge: {start} -> {end}")
            self.graph.add_edge(start, end, edge_type=edge_type)

    def instance_type(self, instance_type: str) -> Optional[AWSEC2InstanceType]:
        # TODO: implement me
        return None
