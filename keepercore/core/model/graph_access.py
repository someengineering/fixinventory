from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from functools import reduce
from typing import Optional, Tuple, Generator, Any, List, Set, Dict

import jsons
from networkx import DiGraph, MultiDiGraph, all_shortest_paths

from core import feature
from core.model.model import Model
from core.model.typed_model import to_js
from core.types import Json


class EdgeType:
    # This edge type defines logical dependencies between resources.
    # It is the main edge type and is assumed, if no edge type is given.
    dependency = "dependency"

    # This edge type defines the order of delete operations.
    # A resource can be deleted, if all outgoing resources are deleted.
    delete = "delete"

    # The default edge type, that is used as fallback if no edge type is given.
    # The related graph is also used as source of truth for graph updates.
    default = dependency

    # The list of all allowed edge types.
    # Note: the database schema has to be adapted to support additional edge types.
    allowed_edge_types = {dependency, delete}


class GraphBuilder:
    def __init__(self, model: Model, with_flatten: bool = feature.DB_SEARCH):
        self.model = model
        self.graph = MultiDiGraph()
        self.with_flatten = with_flatten

    def add_node(self, js: Json) -> None:
        if "id" in js and "data" in js:
            # validate kind of this data
            coerced = self.model.check_valid(js["data"])
            item = js["data"] if coerced is None else coerced
            did = js["id"]  # this is the identifier in the json document
            kind = self.model[item]
            merge = js.get("merge", None) == "true"
            # create content hash
            sha = GraphBuilder.content_hash(item)
            # flat all properties into a single string for search
            flat = GraphBuilder.flatten(item) if self.with_flatten else None
            self.graph.add_node(did, data=item, hash=sha, kind=kind, flat=flat, merge=merge)
        elif "from" in js and "to" in js:
            from_node = js["from"]
            to_node = js["to"]
            edge_type = js.get("edge_type", EdgeType.default)
            key = GraphAccess.edge_key(from_node, to_node, edge_type)
            self.graph.add_edge(from_node, to_node, key, edge_type=edge_type)
        else:
            raise AttributeError(f"Format not understood! Got {json.dumps(js)} which is neither vertex nor edge.")

    @staticmethod
    def content_hash(js: Json) -> str:
        sha256 = hashlib.sha256()
        sha256.update(json.dumps(js, sort_keys=True).encode("utf-8"))
        return sha256.hexdigest()

    @staticmethod
    def flatten(js: Json) -> str:
        result = ""

        def dispatch(value: object) -> None:
            nonlocal result
            if isinstance(value, dict):
                flatten_object(value)
            elif isinstance(value, list):
                flatten_array(value)
            elif isinstance(value, bool):
                pass
            else:
                result += f" {value}"

        def flatten_object(js_doc: Json) -> None:
            for value in js_doc.values():
                dispatch(value)

        def flatten_array(arr: List[Any]) -> None:
            for value in arr:
                dispatch(value)

        dispatch(js)
        return result[1::]

    def check_complete(self) -> None:
        # check that all vertices are given, that were defined in any edge definition
        # note: DiGraph will create an empty vertex node automatically
        for node_id, node in self.graph.nodes(data=True):
            assert node.get("data"), f"Vertex {node_id} was used in an edge definition but not provided as vertex!"

        edge_types = {edge[2] for edge in self.graph.edges(data="edge_type")}
        al = EdgeType.allowed_edge_types
        assert not edge_types.difference(al), f"Graph contains unknown edge types! Given: {edge_types}. Known: {al}"
        # make sure there is only one root node
        GraphAccess.root_id(self.graph)

    @staticmethod
    def graph_from_single_item(model: Model, node_id: str, data: Json) -> MultiDiGraph:
        builder = GraphBuilder(model)
        builder.add_node({"id": node_id, "data": data})
        return builder.graph


class GraphAccess:
    def __init__(self, sub: MultiDiGraph, maybe_root_id: Optional[str] = None):
        super().__init__()
        self.g = sub
        self.nodes = sub.nodes()
        self.visited_nodes: Set[object] = set()
        self.visited_edges: Set[Tuple[object, object, str]] = set()
        self.edge_types: Set[str] = {edge[2] for edge in sub.edges(data="edge_type")}
        self.at = datetime.now(timezone.utc)
        self.at_json = jsons.dump(self.at)
        self.maybe_root_id = maybe_root_id

    def root(self) -> str:
        return self.maybe_root_id if self.maybe_root_id else GraphAccess.root_id(self.g)

    def node(self, node_id: str) -> Optional[Tuple[str, Json, str, List[str], str]]:
        self.visited_nodes.add(node_id)
        if self.g.has_node(node_id):
            n = self.nodes[node_id]
            return self.dump(node_id, n)
        else:
            return None

    def has_edges(self) -> bool:
        return bool(self.edge_types)

    def has_edge(self, from_id: object, to_id: object, edge_type: str) -> bool:
        result: bool = self.g.has_edge(from_id, to_id, self.edge_key(from_id, to_id, edge_type))
        if result:
            self.visited_edges.add((from_id, to_id, edge_type))
        return result

    @staticmethod
    def dump(node_id: str, node: Dict[str, Any]) -> Tuple[str, Json, str, List[str], str]:
        js: Json = to_js(node["data"])
        sha256 = node["hash"] if "hash" in node else GraphBuilder.content_hash(js)
        flat = node["flat"] if "flat" in node else GraphBuilder.flatten(js)
        kinds = (
            list(node["kind"].kind_hierarchy())
            if "kind" in node
            else [js["kind"]]
            if "kind" in js
            else [node.kind()]  # type: ignore
            if hasattr(node, "kind")
            else []
        )
        return node_id, js, sha256, kinds, flat

    def not_visited_nodes(self) -> Generator[Tuple[str, Dict[str, Any], str, List[str], str], None, None]:
        return (self.dump(nid, self.nodes[nid]) for nid in self.g.nodes if nid not in self.visited_nodes)

    def not_visited_edges(self, edge_type: str) -> Generator[Tuple[str, str], None, None]:
        # edge collection with (from, to, type): filter and drop type -> (from, to)
        edges = self.g.edges(data="edge_type")
        return (edge[:2] for edge in edges if edge[2] == edge_type and edge not in self.visited_edges)

    @staticmethod
    def edge_key(from_node: object, to_node: object, edge_type: str) -> str:
        return f"{from_node}_{to_node}_{edge_type}"

    @staticmethod
    def root_id(graph: DiGraph) -> str:
        # noinspection PyTypeChecker
        roots: List[str] = [n for n, d in graph.in_degree if d == 0]
        assert len(roots) == 1, f"Given subgraph has more than one root: {roots}"
        return roots[0]

    @staticmethod
    def merge_sub_graph_roots(graph: DiGraph) -> list[str]:
        graph_root = GraphAccess.root_id(graph)
        merge_nodes = [node_id for node_id, data in graph.nodes(data=True) if data.get("merge", False)]
        result = []
        for node in merge_nodes:
            # compute the shortest path from root to here and sort out all successors that are also predecessors
            predecessors = reduce(lambda res, path: res | set(path), all_shortest_paths(graph, graph_root, node), set())
            result += [a for a in graph.successors(node) if a not in predecessors]
        return result

    @staticmethod
    def sub_graph(graph: DiGraph, from_node: str, parents: set[str]) -> set[str]:
        to_visit = [from_node]
        visited: set[str] = {from_node}

        def succ(node) -> list[str]:
            return [a for a in graph.successors(node) if a not in visited and a not in parents]

        while to_visit:
            to_visit = reduce(lambda li, node: li + succ(node), to_visit, [])
            visited = visited.union(to_visit)
        return visited

    @staticmethod
    def access_from_roots(
        graph: DiGraph, roots: list[str]
    ) -> Generator[Tuple[str, GraphAccess, GraphAccess], None, None]:
        all_successors: Set[str] = set()
        graph_root = GraphAccess.root_id(graph)
        for root in roots:
            predecessors = reduce(lambda res, path: res | set(path), all_shortest_paths(graph, graph_root, root), set())
            successors: set[str] = GraphAccess.sub_graph(graph, root, predecessors)
            # make sure nodes are not "mixed" between different merge nodes
            overlap = successors & all_successors
            if overlap:
                raise AttributeError(f"Nodes are referenced in more than one merge node: {overlap}")
            all_successors |= successors
            pre = GraphAccess(graph.subgraph(predecessors | {root}))
            sub = GraphAccess(graph.subgraph(successors), root)
            yield root, pre, sub
