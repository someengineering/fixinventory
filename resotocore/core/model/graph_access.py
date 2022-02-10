from __future__ import annotations

import hashlib
import json
import logging
import re
from collections import namedtuple, defaultdict
from functools import reduce
from typing import Optional, Generator, Any, Dict, List, Set, Tuple

from networkx import DiGraph, MultiDiGraph, all_shortest_paths, is_directed_acyclic_graph

from core.model.model import Model
from core.model.resolve_in_graph import GraphResolver, NodePath, ResolveProp
from core.types import Json
from core.util import utc, utc_str, value_in_path, set_value_in_path, value_in_path_get

log = logging.getLogger(__name__)

# This version is used when the content hash of a node is computed.
# All computed hashes will be invalidated, by incrementing the version.
# This can be used, if computed values should be recomputed for all imported data.
ContentHashVersion = 2


class Section:
    # The reported section contains the data gathered by the collector.
    # This data is usually not changed by the user directly, but implicitly via changes on the
    # infrastructure, so the next collect run will change this state.
    reported = "reported"

    # This section holds changes that should be reflected by the given node.
    # The desired section can be queried the same way as the reported section
    # and allows to query commands of the graph with a common desired state.
    # For example the clean flag is manifested in the desired section.
    # The separate clean step would query all nodes that should be cleaned
    # and can compute the correct order of action by walking the graph structure.
    desired = "desired"

    # This section holds information about this node that are gathered during the import process.
    # Example: This section resolves common graph attributes like cloud, account, region, zone to make
    # querying the graph easy.
    metadata = "metadata"

    # Following sections are used to lookup special kinds in the graph hierarchy to simplify access.
    # See GraphResolver for details.
    # All resolved ancestors are written to this section.
    ancestors = "ancestors"

    # Resolved descendants would be written to this section.
    # Only here for completeness - currently not used.
    descendants = "descendants"

    # The set of all content sections
    content_ordered = [reported, desired, metadata]
    content = set(content_ordered)

    # The list of all lookup sections
    lookup_sections_ordered = [ancestors, descendants]

    # The list of all sections
    all_ordered = [*content_ordered, *lookup_sections_ordered]
    all = set(all_ordered)

    # remove the section plus dot if it exists in the string: reported.foo => foo
    __no_section = re.compile("^(" + "|".join(f"({s})" for s in content_ordered) + ")[.]")

    @classmethod
    def without_section(cls, path: str) -> str:
        return cls.__no_section.sub("", path, 1)


class EdgeType:
    # This edge type defines the default relationship between resources.
    # It is the main edge type and is assumed, if no edge type is given.
    # The related graph is also used as source of truth for graph updates.
    default: str = "default"

    # This edge type defines the order of delete operations.
    # A resource can be deleted, if all outgoing resources are deleted.
    delete: str = "delete"

    # The set of all allowed edge types.
    # Note: the database schema has to be adapted to support additional edge types.
    all: Set[str] = {default, delete}


class Direction:
    # Opposite direction as the edge direction.
    inbound = "in"
    # Same direction as the edge direction
    outbound = "out"
    # Ignore the direction of the edge and traverse in any direction.
    any = "any"

    # The set of all allowed directions.
    all: Set[str] = {inbound, outbound, any}


EdgeKey = namedtuple("EdgeKey", ["from_node", "to_node", "edge_type"])


class GraphBuilder:
    def __init__(self, model: Model):
        self.model = model
        self.graph = MultiDiGraph()
        self.nodes = 0
        self.edges = 0

    def add_from_json(self, js: Json) -> None:
        if "id" in js and Section.reported in js:
            self.add_node(
                js["id"],
                js[Section.reported],
                js.get(Section.desired, None),
                js.get(Section.metadata, None),
                js.get("search", None),
                js.get("replace", False) is True,
            )
        elif "from" in js and "to" in js:
            self.add_edge(js["from"], js["to"], js.get("edge_type", EdgeType.default))
        else:
            raise AttributeError(f"Format not understood! Got {json.dumps(js)} which is neither vertex nor edge.")

    def add_node(
        self,
        node_id: str,
        reported: Json,
        desired: Optional[Json] = None,
        metadata: Optional[Json] = None,
        search: Optional[str] = None,
        replace: bool = False,
    ) -> None:
        self.nodes += 1
        # validate kind of this reported json
        coerced = self.model.check_valid(reported)
        reported = reported if coerced is None else coerced
        kind = self.model[reported]
        # create content hash
        sha = GraphBuilder.content_hash(reported, desired, metadata)
        # flat all properties into a single string for search
        flat = search if isinstance(search, str) else (GraphBuilder.flatten(reported))
        self.graph.add_node(
            node_id,
            id=node_id,
            reported=reported,
            desired=desired,
            metadata=metadata,
            hash=sha,
            kind=kind,
            kinds=list(kind.kind_hierarchy()),
            kinds_set=kind.kind_hierarchy(),
            flat=flat,
            replace=replace | metadata.get("replace", False) is True if metadata else False,
        )

    def add_edge(self, from_node: str, to_node: str, edge_type: str) -> None:
        self.edges += 1
        key = GraphAccess.edge_key(from_node, to_node, edge_type)
        self.graph.add_edge(from_node, to_node, key, edge_type=edge_type)

    @staticmethod
    def content_hash(js: Json, desired: Optional[Json] = None, metadata: Optional[Json] = None) -> str:
        sha256 = hashlib.sha256()
        # all content hashes will be different, when the version changes
        sha256.update(ContentHashVersion.to_bytes(2, "big"))
        sha256.update(json.dumps(js, sort_keys=True).encode("utf-8"))
        if desired:
            sha256.update(json.dumps(desired, sort_keys=True).encode("utf-8"))
        if metadata:
            sha256.update(json.dumps(metadata, sort_keys=True).encode("utf-8"))
        return sha256.hexdigest()

    @staticmethod
    def flatten(js: Json) -> str:
        result = ""

        def dispatch(value: object) -> None:
            nonlocal result
            if isinstance(value, dict):
                for elem in value.values():
                    dispatch(elem)
            elif isinstance(value, list):
                for elem in value:
                    dispatch(elem)
            elif value is None or isinstance(value, bool):
                pass
            else:
                if result:
                    result += " "
                result += str(value).strip()

        dispatch(js)
        return result

    def check_complete(self) -> None:
        # check that all vertices are given, that were defined in any edge definition
        # note: DiGraph will create an empty vertex node automatically
        for node_id, node in self.graph.nodes(data=True):
            assert node.get(Section.reported), f"{node_id} was used in an edge definition but not provided as vertex!"

        edge_types = {edge[2] for edge in self.graph.edges(data="edge_type")}
        al = EdgeType.all
        assert not edge_types.difference(al), f"Graph contains unknown edge types! Given: {edge_types}. Known: {al}"
        # make sure there is only one root node
        rid = GraphAccess.root_id(self.graph)
        root_node = self.graph.nodes[rid]

        # make sure the root
        if value_in_path(root_node, NodePath.reported_kind) == "graph_root" and rid != "root":
            # remove node with wrong id +
            root_node = self.graph.nodes[rid]
            root_node["id"] = "root"
            self.graph.add_node("root", **root_node)

            for succ in list(self.graph.successors(rid)):
                for edge_type in EdgeType.all:
                    key = GraphAccess.edge_key(rid, succ, edge_type)
                    if self.graph.has_edge(rid, succ, key):
                        self.graph.remove_edge(rid, succ, key)
                        self.add_edge("root", succ, edge_type)
            self.graph.remove_node(rid)


NodeData = Tuple[str, Json, Optional[Json], Optional[Json], Optional[Json], str, List[str], str]


class GraphAccess:
    def __init__(
        self,
        sub: MultiDiGraph,
        maybe_root_id: Optional[str] = None,
        visited_nodes: Optional[Set[Any]] = None,
        visited_edges: Optional[Set[EdgeKey]] = None,
    ):
        super().__init__()
        self.g = sub
        self.nodes = sub.nodes()
        self.visited_nodes: Set[object] = visited_nodes if visited_nodes else set()
        self.visited_edges: Set[EdgeKey] = visited_edges if visited_edges else set()
        self.at = utc()
        self.at_json = utc_str(self.at)
        self.maybe_root_id = maybe_root_id
        self.resolved = False

    def root(self) -> str:
        return self.maybe_root_id if self.maybe_root_id else GraphAccess.root_id(self.g)

    def node(self, node_id: str) -> Optional[Json]:
        self.visited_nodes.add(node_id)
        if self.g.has_node(node_id):
            n = self.nodes[node_id]
            return self.dump(node_id, n)
        else:
            return None

    def has_edge(self, from_id: object, to_id: object, edge_type: str) -> bool:
        key = self.edge_key(from_id, to_id, edge_type)
        result: bool = self.g.has_edge(from_id, to_id, key)
        if result:
            self.visited_edges.add(key)
        return result

    def resolve(self) -> None:
        if not self.resolved:
            self.resolved = True
            log.info("Resolve attributes in graph")
            for node_id in self.nodes:
                self.__resolve(node_id, self.nodes[node_id])
            self.__resolve_count_descendants()
            log.info("Resolve attributes finished.")

    def __resolve_count_descendants(self) -> None:
        visited: Set[str] = set()

        def count_successors_by(node_id: str, edge_type: str, path: List[str]) -> Dict[str, int]:
            result: Dict[str, int] = {}
            to_visit = list(self.successors(node_id, edge_type))
            while to_visit:
                visit_next: List[str] = []
                for elem_id in to_visit:
                    if elem_id not in visited:
                        visited.add(elem_id)
                        elem = self.nodes[elem_id]
                        if not value_in_path_get(elem, NodePath.is_phantom, False):
                            extracted = value_in_path(elem, path)
                            if isinstance(extracted, str):
                                result[extracted] = result.get(extracted, 0) + 1
                        # check if there is already a successor summary: stop the traversal and take the result.
                        existing = value_in_path(elem, NodePath.descendant_summary)
                        if existing and isinstance(existing, dict):
                            for summary_item, count in existing.items():
                                result[summary_item] = result.get(summary_item, 0) + count
                        else:
                            visit_next.extend(a for a in self.successors(elem_id, edge_type) if a not in visited)
                to_visit = visit_next
            return result

        for on_kind, prop in GraphResolver.count_successors.items():
            for node_id, node in self.g.nodes(data=True):
                kinds = node.get("kinds_set")
                if kinds and on_kind in kinds:
                    summary = count_successors_by(node_id, EdgeType.default, prop.extract_path)
                    set_value_in_path(summary, prop.to_path, node)
                    total = reduce(lambda l, r: l + r, summary.values(), 0)
                    set_value_in_path(total, NodePath.descendant_count, node)

    def __resolve(self, node_id: str, node: Json) -> Json:
        def with_ancestor(ancestor: Json, prop: ResolveProp) -> None:
            extracted = value_in_path(ancestor, prop.extract_path)
            if extracted:
                set_value_in_path(extracted, prop.to_path, node)

        for resolver in GraphResolver.to_resolve:
            # search for ancestor that matches filter criteria
            anc = self.ancestor_of(node_id, EdgeType.default, resolver.kind)
            if anc:
                for res in resolver.resolve:
                    with_ancestor(anc, res)
        return node

    def dump(self, node_id: str, node: Json) -> Json:
        return self.dump_direct(node_id, node)

    def predecessors(self, node_id: str, edge_type: str) -> Generator[str, Any, None]:
        for pred_id in self.g.predecessors(node_id):
            # direction from parent node to provided node
            if self.g.has_edge(pred_id, node_id, self.edge_key(pred_id, node_id, edge_type)):
                yield pred_id

    def successors(self, node_id: str, edge_type: str) -> Generator[str, Any, None]:
        for succ_id in self.g.successors(node_id):
            # direction from provided node to successor node
            if self.g.has_edge(node_id, succ_id, self.edge_key(node_id, succ_id, edge_type)):
                yield succ_id

    def ancestor_of(self, node_id: str, edge_type: str, kind: str) -> Optional[Json]:
        # note: we are using breadth first search here on purpose.
        # if there is an ancestor with less distance to this node, we should use this one
        next_level = [node_id]

        while next_level:
            parents: List[str] = []
            for p_id in next_level:
                p: Json = self.nodes[p_id]
                kinds: Optional[List[str]] = value_in_path(p, NodePath.kinds)
                if kinds and kind in kinds:
                    return p
                else:
                    parents.extend(self.predecessors(p_id, edge_type))
            next_level = parents
        return None

    def is_acyclic_per_edge_type(self) -> bool:
        """
        Checks if the graph is acyclic with respect to a specific edge type.
        This means it is valid if there are cycles in the graph but not for the same edge type.
        :return: True if the graph is acyclic for all edge types, otherwise False.
        """
        edges_per_type = defaultdict(list)
        # edge is a tuple: (from_node, to_node, edge_key)
        for edge in self.g.edges(keys=True):
            key: EdgeKey = edge[2]
            edges_per_type[key.edge_type].append(edge)
        for edges in edges_per_type.values():
            typed_graph = self.g.edge_subgraph(edges)
            acyclic = is_directed_acyclic_graph(typed_graph)
            if not acyclic:
                return False
        return True

    @staticmethod
    def dump_direct(node_id: str, node: Json, recompute: bool = False) -> Json:
        reported = node[Section.reported]
        desired: Optional[Json] = node.get(Section.desired, None)
        metadata: Optional[Json] = node.get(Section.metadata, None)
        if "id" not in node:
            node["id"] = node_id
        if recompute or "hash" not in node:
            node["hash"] = GraphBuilder.content_hash(reported, desired, metadata)
        if recompute or "flat" not in node:
            node["flat"] = GraphBuilder.flatten(reported)
        if "kinds" not in node:
            node["kinds"] = [reported["kind"]]
        return node

    def not_visited_nodes(self) -> Generator[Json, None, None]:
        return (self.dump(nid, self.nodes[nid]) for nid in self.g.nodes if nid not in self.visited_nodes)

    def not_visited_edges(self, edge_type: str) -> Generator[Tuple[str, str], None, None]:
        # edge collection with (from, to, type): filter and drop type -> (from, to)
        edges = self.g.edges(data="edge_type")
        return (edge[:2] for edge in edges if edge[2] == edge_type and edge not in self.visited_edges)

    @staticmethod
    def edge_key(from_node: object, to_node: object, edge_type: str) -> EdgeKey:
        return EdgeKey(from_node, to_node, edge_type)

    @staticmethod
    def root_id(graph: DiGraph) -> str:
        # noinspection PyTypeChecker
        roots: List[str] = [n for n, d in graph.in_degree if d == 0]
        assert len(roots) == 1, f"Given subgraph has more than one root: {roots}"
        return roots[0]

    @staticmethod
    def merge_graphs(
        graph: MultiDiGraph,
    ) -> Tuple[List[str], GraphAccess, Generator[Tuple[str, GraphAccess], None, None]]:
        """
        Find all merge graphs in the provided graph.
        A merge graph is a self contained graph under a node which is marked with replace=true.
        Such nodes are replaced with the replace node in the database.
        Example:
        A -> B -> C(replace=true) -> E -> E1 -> E2
                                  -> F -> F1
               -> D(replace=true) -> G -> G1 -> G2 -> G3 -> G4

        This will result in 2 merge roots:
            C: [A, B]
            D: [A, B]

        Note that all successors of a merge node that is also a predecessors of the merge node is sorted out.

        :param graph: the incoming multi graph update.
        :return: the list of all merge roots, the expected parent graph and all merge root graphs.
        """

        # Find replace nodes: all nodes that are marked as replace node.
        # This method returns all replace roots as key, with the respective predecessors nodes as value.
        def replace_roots() -> Dict[str, Set[str]]:
            graph_root = GraphAccess.root_id(graph)
            replace_nodes = {node_id: data for node_id, data in graph.nodes(data=True) if data.get("replace", False)}
            assert (
                len(replace_nodes) > 0
            ), "No replace nodes provided in the graph. Mark at least one node with replace=true!"
            result: Dict[str, Set[str]] = {}
            for node, data in replace_nodes.items():
                kind = GraphResolver.resolved_kind(data)
                assert (
                    kind is not None
                ), f"Node {node} is marked as replace node, but the kind is not resolved during import!"
                # compute the shortest path from root to here
                pres: Set[str] = reduce(lambda res, p: {*res, *p}, all_shortest_paths(graph, graph_root, node), set())
                result[node] = pres
            # make sure there is no replace node beyond another replace node
            rs = result.copy()
            for node in rs:
                for nid, parent_nodes in rs.items():
                    if nid != node and node in parent_nodes:
                        log.info(f"Node {nid} marked as replace, but is child of another replace node {node}. Ignore.")
                        result.pop(nid, None)
            return result

        # Walk the graph from given starting node and return all successors.
        # A successor which is also a predecessors is not followed.
        def sub_graph_nodes(from_node: str, parent_ids: Set[str]) -> Set[str]:
            to_visit = [from_node]
            visited: Set[str] = {from_node}

            def successors(node: str) -> List[str]:
                return [a for a in graph.successors(node) if a not in visited and a not in parent_ids]

            while to_visit:
                to_visit = reduce(lambda li, node: li + successors(node), to_visit, [])
                visited.update(to_visit)
            return visited

        # Create a generator for all given merge roots by:
        #   - creating the set of all successors
        #   - creating a subgraph which contains all predecessors and all succors
        #   - all predecessors are marked as visited
        #   - all predecessors edges are marked as visited
        # This way it is possible to have nodes in the graph that will not be touched by the update
        # while edges will be created from successors of the merge node to predecessors of the merge node.
        def merge_sub_graphs(
            root_nodes: Dict[str, Set[str]], parent_nodes: Set[str], parent_edges: Set[EdgeKey]
        ) -> Generator[Tuple[str, GraphAccess], None, None]:
            all_successors: Set[str] = set()
            for root, predecessors in root_nodes.items():
                successors: Set[str] = sub_graph_nodes(root, predecessors)
                # make sure nodes are not "mixed" between different merge nodes
                overlap = successors & all_successors
                if overlap:
                    raise AttributeError(f"Nodes are referenced in more than one merge node: {overlap}")
                all_successors.update(successors)
                # create subgraph with all successors and all parents, where all parents are already marked as visited
                sub = GraphAccess(graph.subgraph(successors), root, parent_nodes, parent_edges)
                yield root, sub

        GraphAccess(graph).resolve()  # resolve graph references
        roots = replace_roots()
        parents: Set[str] = reduce(lambda res, ps: {*res, *ps}, roots.values(), set())
        parent_graph = graph.subgraph(parents)
        graphs = merge_sub_graphs(roots, parents, set(parent_graph.edges(data="edge_type")))
        return list(roots.keys()), GraphAccess(parent_graph, GraphAccess.root_id(graph)), graphs
