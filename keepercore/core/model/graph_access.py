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
        self.nodes = 0
        self.edges = 0

    def add_from_json(self, js: Json) -> None:
        if "id" in js and "reported" in js:
            self.add_node(js["id"], js["reported"], js.get("metadata", None), js.get("merge", None) is True)
        elif "from" in js and "to" in js:
            self.add_edge(js["from"], js["to"], js.get("edge_type", EdgeType.default))
        else:
            raise AttributeError(f"Format not understood! Got {json.dumps(js)} which is neither vertex nor edge.")

    def add_node(self, node_id: str, reported: Json, metadata: Optional[Json] = None, merge: bool = False) -> None:
        self.nodes += 1
        # validate kind of this reported json
        coerced = self.model.check_valid(reported)
        item = reported if coerced is None else coerced
        kind = self.model[item]
        # create content hash
        sha = GraphBuilder.content_hash(item, metadata)
        # flat all properties into a single string for search
        flat = GraphBuilder.flatten(item) if self.with_flatten else None
        self.graph.add_node(node_id, reported=item, metadata=metadata, hash=sha, kind=kind, flat=flat, merge=merge)

    def add_edge(self, from_node: str, to_node: str, edge_type: str) -> None:
        self.edges += 1
        key = GraphAccess.edge_key(from_node, to_node, edge_type)
        self.graph.add_edge(from_node, to_node, key, edge_type=edge_type)

    @staticmethod
    def content_hash(js: Json, metadata: Optional[Json] = None) -> str:
        sha256 = hashlib.sha256()
        sha256.update(json.dumps(js, sort_keys=True).encode("utf-8"))
        if metadata:
            sha256.update(json.dumps(metadata, sort_keys=True).encode("utf-8"))
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
            assert node.get("reported"), f"Vertex {node_id} was used in an edge definition but not provided as vertex!"

        edge_types = {edge[2] for edge in self.graph.edges(data="edge_type")}
        al = EdgeType.allowed_edge_types
        assert not edge_types.difference(al), f"Graph contains unknown edge types! Given: {edge_types}. Known: {al}"
        # make sure there is only one root node
        GraphAccess.root_id(self.graph)


NodeData = Tuple[str, Json, Optional[Json], str, List[str], str]


class GraphAccess:
    def __init__(
        self,
        sub: MultiDiGraph,
        maybe_root_id: Optional[str] = None,
        visited_nodes: Optional[set[Any]] = None,
        visited_edges: Optional[Set[Tuple[Any, Any, str]]] = None,
    ):
        super().__init__()
        self.g = sub
        self.nodes = sub.nodes()
        self.visited_nodes: Set[object] = visited_nodes if visited_nodes else set()
        self.visited_edges: Set[Tuple[object, object, str]] = visited_edges if visited_edges else set()
        self.at = datetime.now(timezone.utc)
        self.at_json = jsons.dump(self.at)
        self.maybe_root_id = maybe_root_id

    def root(self) -> str:
        return self.maybe_root_id if self.maybe_root_id else GraphAccess.root_id(self.g)

    def node(self, node_id: str) -> Optional[NodeData]:
        self.visited_nodes.add(node_id)
        if self.g.has_node(node_id):
            n = self.nodes[node_id]
            return self.dump(node_id, n)
        else:
            return None

    def has_edge(self, from_id: object, to_id: object, edge_type: str) -> bool:
        result: bool = self.g.has_edge(from_id, to_id, self.edge_key(from_id, to_id, edge_type))
        if result:
            self.visited_edges.add((from_id, to_id, edge_type))
        return result

    @staticmethod
    def dump(node_id: str, node: Dict[str, Any]) -> NodeData:
        js: Json = to_js(node["reported"])
        metadata: Optional[Json] = node.get("metadata", None)
        sha256 = node["hash"] if "hash" in node else GraphBuilder.content_hash(js, metadata)
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
        return node_id, js, metadata, sha256, kinds, flat

    def not_visited_nodes(self) -> Generator[NodeData, None, None]:
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
    def merge_graphs(
        graph: DiGraph,
    ) -> Tuple[list[str], GraphAccess, Generator[Tuple[str, GraphAccess], None, None]]:
        """
        Find all merge graphs in the provided graph.
        A merge graph is a self contained graph under a node which is marked with merge=true.
        Such nodes are merged with the merge node in the database.
        Example:
        A -> B -> C(merge=true) -> E -> E1 -> E2
                                -> F -> F1
               -> D(merge=true) -> G -> G1 -> G2 -> G3 -> G4

        This will result in 3 merge roots:
            E: [A, B, C]
            F: [A, B, C]
            G: [A, B, D]

        Note that all successors of a merge node that is also a predecessor of the merge node is sorted out.
        Example: A -> B -> C(merge=true) -> A  ==> A is not considered merge root.

        :param graph: the incoming multi graph update.
        :return: the list of all merge roots, the expected parent graph and all merge root graphs.
        """

        # Find merge nodes: all nodes that are marked as merge node -> all children (merge roots) should be merged.
        # This method returns all merge roots as key, with the respective predecessor nodes as value.
        def merge_roots() -> dict[str, set[str]]:
            graph_root = GraphAccess.root_id(graph)
            merge_nodes = [node_id for node_id, data in graph.nodes(data=True) if data.get("merge", False)]
            assert len(merge_nodes) > 0, "No merge nodes provided in the graph. Mark at least one node with merge=true!"
            result: dict[str, set[str]] = {}
            for node in merge_nodes:
                # compute the shortest path from root to here and sort out all successors that are also predecessors
                pres: set[str] = reduce(lambda res, p: res | set(p), all_shortest_paths(graph, graph_root, node), set())
                for a in graph.successors(node):
                    if a not in pres:
                        result[a] = pres
            return result

        # Walk the graph from given starting node and return all successors.
        # A successor which is also a predecessor is not followed.
        def sub_graph_nodes(from_node: str, parent_ids: set[str]) -> set[str]:
            to_visit = [from_node]
            visited: set[str] = {from_node}

            def successors(node: str) -> list[str]:
                return [a for a in graph.successors(node) if a not in visited and a not in parent_ids]

            while to_visit:
                to_visit = reduce(lambda li, node: li + successors(node), to_visit, [])
                visited.update(to_visit)
            return visited

        # Create a generator for all given merge roots by:
        #   - creating the set of all successors
        #   - creating a subgraph which contains all predecessors and all succors
        #   - all predecessors are marked as visited
        #   - all predecessor edges are marked as visited
        # This way it is possible to have nodes in the graph that will not be touched by the update
        # while edges will be created from successors of the merge node to predecessors of the merge node.
        def merge_sub_graphs(
            root_nodes: dict[str, set[str]], parent_nodes: set[str], parent_edges: set[Tuple[str, str, str]]
        ) -> Generator[Tuple[str, GraphAccess], None, None]:
            all_successors: Set[str] = set()
            for root, predecessors in root_nodes.items():
                successors: set[str] = sub_graph_nodes(root, predecessors)
                # make sure nodes are not "mixed" between different merge nodes
                overlap = successors & all_successors
                if overlap:
                    raise AttributeError(f"Nodes are referenced in more than one merge node: {overlap}")
                all_successors |= successors
                # create subgraph with all successors and all parents, where all parents are already marked as visited
                sub = GraphAccess(graph.subgraph(successors | parent_nodes), root, parent_nodes, parent_edges)
                yield root, sub

        roots = merge_roots()
        parents: set[str] = reduce(lambda res, ps: res | ps, roots.values(), set())
        parent_graph = graph.subgraph(parents)
        graphs = merge_sub_graphs(roots, parents, set(parent_graph.edges(data="edge_type")))
        return list(roots.keys()), GraphAccess(parent_graph, GraphAccess.root_id(graph)), graphs
