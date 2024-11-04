from __future__ import annotations

import hashlib
import json
import logging
import re
from collections import namedtuple, defaultdict
from functools import reduce
from typing import Optional, Generator, Any, Dict, List, Set, Tuple, Union, Iterator, DefaultDict, Iterable

from attrs import define
from networkx import DiGraph, MultiDiGraph, is_directed_acyclic_graph

from fixcore.ids import NodeId
from fixcore.model.model import (
    Model,
    Kind,
    AnyKind,
    ComplexKind,
    ArrayKind,
    DateTimeKind,
    DictionaryKind,
    StringKind,
    Property,
    SimpleKind,
    DateKind,
    DurationKind,
    UsageDatapoint,
)
from fixcore.model.resolve_in_graph import GraphResolver, NodePath, ResolveProp
from fixcore.model.typed_model import from_js
from fixcore.types import Json, EdgeType, JsonElement
from fixcore.util import utc, utc_str, value_in_path, set_value_in_path, path_exists

log = logging.getLogger(__name__)

# This version is used when the content hash of a node is computed.
# All computed hashes will be invalidated, by incrementing the version.
# This can be used, if computed values should be recomputed for all imported data.
ContentHashVersion = 3


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

    # This section holds information about security issues detected for this node.
    security = "security"

    # Following sections are used to lookup special kinds in the graph hierarchy to simplify access.
    # See GraphResolver for details.
    # All resolved ancestors are written to this section.
    ancestors = "ancestors"

    # Resolved descendants would be written to this section.
    # Only here for completeness - currently not used.
    descendants = "descendants"

    # Usage of the resource
    usage = "usage"

    # The set of all content sections
    content_ordered = [reported, security, desired, metadata]
    content = set(content_ordered)

    # The list of all lookup sections
    lookup_sections_ordered = [ancestors, descendants, usage]
    lookup_sections = set(lookup_sections_ordered)

    # The list of all sections
    all_ordered = [*content_ordered, *lookup_sections_ordered]
    all = set(all_ordered)

    # remove the section plus dot if it exists in the string: reported.foo => foo
    __no_section = re.compile("^/?(" + "|".join(f"({s})" for s in content_ordered) + ")[.]")

    @classmethod
    def without_section(cls, path: str) -> str:
        return cls.__no_section.sub("", path, 1)


class EdgeTypes:
    # This edge type defines the default relationship between resources.
    # It is the main edge type and is assumed, if no edge type is given.
    # The related graph is also used as source of truth for graph updates.
    default: EdgeType = "default"

    # This edge type defines the order of delete operations.
    # A resource can be deleted, if all outgoing resources are deleted.
    delete: EdgeType = "delete"

    # This edge type defines the IAM relationship.
    # It models allowed permissions between principals and resources, as well as the inter-principal relationship.
    # Example: AWS IAM User (principal) has permission to write to an S3 bucket (resource).
    iam: EdgeType = "iam"

    # The set of all allowed edge types.
    # Note: the database schema has to be adapted to support additional edge types.
    all: Set[EdgeType] = {default, delete, iam}


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

# Global list of properties to ignore when computing the history hash of a node.
PropsToIgnoreForHistory = {"ctime", "atime", "mtime", "age", "last_access", "last_update", "resource_version"}


@define
class BySearchCriteria:
    query: str


@define
class ByNodeId:
    value: NodeId


NodeSelector = Union[ByNodeId, BySearchCriteria]


@define
class DeferredEdge:
    from_node: NodeSelector
    to_node: NodeSelector
    edge_type: EdgeType
    reported: Optional[Json] = None
    content_hash: Optional[str] = None

    def data(self) -> Optional[Json]:
        return dict(reported=self.reported, hash=self.content_hash) if self.reported and self.content_hash else None


class GraphBuilder:
    def __init__(self, model: Model, change_id: str):
        self.model = model
        self.graph = MultiDiGraph()
        self.nodes = 0
        self.edges = 0
        self.deferred_edges: List[DeferredEdge] = []
        self.usage: List[UsageDatapoint] = []
        self.at = int(utc().timestamp())
        self.change_id = change_id
        self.organizational_root: Optional[NodeId] = None

    def add_from_json(self, js: Json) -> None:
        if "id" in js and Section.reported in js:
            usage_json = js.get(Section.usage, {})
            if len(usage_json) == 0:
                usage_json = None
            self.add_node(
                node_id=js["id"],
                reported=js[Section.reported],
                desired=js.get(Section.desired),
                metadata=js.get(Section.metadata),
                ancestors=js.get(Section.ancestors),
                search=js.get("search"),
                replace=js.get("replace", False) is True,
            )
            if usage_json:
                usage = UsageDatapoint(
                    id=js["id"],
                    change_id=self.change_id,
                    at=self.at,
                    v=usage_json,
                )
                self.usage.append(usage)
        elif "from" in js and "to" in js:
            self.add_edge(
                js["from"], js["to"], js.get("edge_type", EdgeTypes.default), reported=js.get(Section.reported)
            )
        elif "from_selector" in js and "to_selector" in js:

            def parse_selector(js: Json) -> NodeSelector:
                if "node_id" in js:
                    return ByNodeId(NodeId(from_js(js["node_id"], str)))
                elif "search_criteria" in js:
                    return BySearchCriteria(from_js(js["search_criteria"], str))
                else:
                    raise AttributeError(f"can't parse edge selector! Got {json.dumps(js)}")

            reported = js.get("reported")
            self.add_deferred_edge(
                parse_selector(js["from_selector"]),
                parse_selector(js["to_selector"]),
                js.get("edge_type", EdgeTypes.default),
                reported,
                GraphBuilder.content_hash(reported) if reported else None,
            )
        else:
            raise AttributeError(f"Format not understood! Got {json.dumps(js)} which is neither vertex nor edge.")

    def __update_property_size(self, kind: Kind, element: JsonElement) -> None:
        def prop_size(prop: Property, pk: Kind, part: JsonElement) -> None:
            if part is None:
                pass
            elif isinstance(pk, (StringKind, DateTimeKind, DateKind, DurationKind)) and isinstance(part, str):
                str_len = len(part)
                if prop.metadata is None:
                    prop.metadata = {}
                size = prop.metadata.get("len", 0)
                prop.metadata["len"] = max(size, str_len)
            elif isinstance(pk, SimpleKind):
                pass
            elif isinstance(pk, ArrayKind) and isinstance(part, list) and isinstance(pk.inner, StringKind):
                for elem in part:
                    prop_size(prop, pk.inner, elem)
            elif isinstance(pk, ArrayKind) and isinstance(part, list):
                for elem in part:
                    self.__update_property_size(pk.inner, elem)
            elif isinstance(pk, DictionaryKind) and isinstance(part, dict) and isinstance(pk.value_kind, StringKind):
                for elem in part.values():
                    prop_size(prop, pk.value_kind, elem)
            elif isinstance(pk, DictionaryKind) and isinstance(part, dict):
                for k, v in part.items():
                    self.__update_property_size(pk.key_kind, k)
                    self.__update_property_size(pk.value_kind, v)
            elif isinstance(pk, ComplexKind) and isinstance(part, dict):
                for cp, cpk in pk.all_props_with_kind():
                    prop_size(cp, cpk, part.get(cp.name, None))

        if isinstance(kind, ComplexKind) and isinstance(element, dict):
            prop_size(Property("root", kind.fqn), kind, element)

    def add_node(
        self,
        node_id: NodeId,
        reported: Json,
        desired: Optional[Json] = None,
        metadata: Optional[Json] = None,
        ancestors: Optional[Json] = None,
        search: Optional[str] = None,
        replace: bool = False,
    ) -> None:
        self.nodes += 1
        # validate kind of this reported json
        coerced = self.model.check_valid(reported)
        reported = reported if coerced is None else coerced
        kind = self.model[reported]
        # if replace is defined, make it part of metadata
        if replace:
            metadata = metadata or {}
            metadata["replace"] = True
        # get kind hierarchy
        kinds = kind.kind_hierarchy()
        # create content hash
        sha = GraphBuilder.content_hash(reported, desired, metadata, kinds)
        hist_hash = GraphBuilder.history_hash(reported, kind)
        # flat all properties into a single string for search
        flat = search if isinstance(search, str) else (GraphBuilder.flatten(reported, kind))
        # set organizational root
        if "organizational_root" in kinds:
            assert self.organizational_root is None, "There can be only one organizational root!"
            self.organizational_root = node_id
        self.graph.add_node(
            node_id,
            id=node_id,
            reported=reported,
            desired=desired,
            metadata=metadata,
            ancestors=ancestors,
            hash=sha,
            hist_hash=hist_hash,
            kind=kind,
            kinds=list(kinds),
            kinds_set=kinds,
            flat=flat,
        )
        # update property sizes
        self.__update_property_size(kind, reported)

    def add_edge(self, from_node: str, to_node: str, edge_type: EdgeType, reported: Optional[Json] = None) -> None:
        self.edges += 1
        key = GraphAccess.edge_key(from_node, to_node, edge_type)
        sha = GraphBuilder.content_hash(reported) if reported else None
        self.graph.add_edge(from_node, to_node, key, reported=reported, hash=sha)

    def add_deferred_edge(
        self,
        from_selector: NodeSelector,
        to_selector: NodeSelector,
        edge_type: EdgeType,
        reported: Optional[Json],
        content_hash: Optional[str],
    ) -> None:
        self.deferred_edges.append(DeferredEdge(from_selector, to_selector, edge_type, reported, content_hash))

    @staticmethod
    def content_hash(
        js: Json,
        desired: Optional[Json] = None,
        metadata: Optional[Json] = None,
        kinds: Optional[Iterable[str]] = None,
    ) -> str:
        sha256 = hashlib.sha256()
        # all content hashes will be different, when the version changes
        sha256.update(ContentHashVersion.to_bytes(2, "big"))
        sha256.update(json.dumps(js, sort_keys=True).encode("utf-8"))
        if desired:
            sha256.update(json.dumps(desired, sort_keys=True).encode("utf-8"))
        if metadata:
            sha256.update(json.dumps(metadata, sort_keys=True).encode("utf-8"))
        if kinds:
            sha256.update(":".join(sorted(kinds)).encode("utf-8"))
        return sha256.hexdigest()[0:8]

    @staticmethod
    def history_hash(js: Json, kind: Kind) -> str:
        sha256 = hashlib.sha256()

        def walk_element(el: JsonElement, el_kind: Kind, maybe_prop: Optional[Property]) -> None:
            if el is None:
                pass
            elif isinstance(el_kind, ComplexKind):
                walk_complex(el, el_kind)
            elif isinstance(el_kind, ArrayKind):
                if isinstance(el, list):
                    for elem in el:
                        walk_element(elem, el_kind.inner, maybe_prop)
            elif isinstance(el_kind, DictionaryKind):
                if isinstance(el, dict):
                    for _, v in sorted(el.items()):
                        walk_element(v, el_kind.value_kind, maybe_prop)
            elif isinstance(el_kind, (DateKind, DateTimeKind)):  # default: ignore, opt-in to keep
                if maybe_prop and maybe_prop.meta_get("keep_history", bool, False):
                    sha256.update(str(el).encode("utf-8"))
            elif isinstance(el_kind, SimpleKind):
                sha256.update(str(el).encode("utf-8"))

        def walk_complex(el: JsonElement, el_kind: ComplexKind) -> None:
            if isinstance(el, dict):
                for prop, prop_kind in el_kind.direct_property_with_kinds():  # properties are already sorted
                    if (
                        (not prop.meta_get("ignore_history", bool, False))
                        and (prop.name not in PropsToIgnoreForHistory)
                        and (prop_val := el.get(prop.name))
                    ):
                        walk_element(prop_val, prop_kind, prop)
                if not el_kind.metadata.get("ignore_history"):  # if defined on type, do not walk the hierarchy
                    for base in el_kind.resolved_bases().values():
                        walk_complex(el, base)

        walk_element(js, kind, None)
        return sha256.hexdigest()[0:8]

    @staticmethod
    def flatten(js: Json, kind: Kind) -> str:
        result = ""

        def dispatch(value: Any, k: Kind) -> None:
            nonlocal result
            if isinstance(value, dict):
                for prop, elem in value.items():
                    sub = (
                        k.property_kind_of(prop, AnyKind())
                        if isinstance(k, ComplexKind)
                        else (k.value_kind if isinstance(k, DictionaryKind) else AnyKind())
                    )
                    dispatch(elem, sub)
            elif isinstance(value, list):
                sub = k.inner if isinstance(k, ArrayKind) else AnyKind()
                for elem in value:
                    dispatch(elem, sub)
            elif value is None or isinstance(value, bool):
                pass
            else:
                # in case of date time: "2017-05-30T22:04:34Z" -> "2017-05-30 22:04:34"
                if isinstance(k, DateTimeKind):
                    value = re.sub("[ZT]", " ", value)
                if result:
                    result += " "
                result += str(value).strip()

        dispatch(js, kind)
        return result

    def check_complete(self) -> None:
        # check that all vertices are given, that were defined in any edge definition
        # note: DiGraph will create an empty vertex node automatically
        for node_id, node in self.graph.nodes(data=True):
            assert node.get(Section.reported), f"{node_id} was used in an edge definition but not provided as vertex!"

        edge_types: Set[str] = {key.edge_type for _, _, key in self.graph.edges(keys=True)}
        al = EdgeTypes.all
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
                for edge_type in EdgeTypes.all:
                    key = GraphAccess.edge_key(rid, succ, edge_type)
                    if self.graph.has_edge(rid, succ, key):
                        data = self.graph.get_edge_data(rid, succ, key)
                        self.graph.remove_edge(rid, succ, key)
                        self.add_edge("root", succ, edge_type, data.get("reported"))
            self.graph.remove_node(rid)


NodeData = Tuple[str, Json, Optional[Json], Optional[Json], Optional[Json], str, List[str], str]


class GraphAccess:
    def __init__(
        self,
        sub: MultiDiGraph,
        maybe_root_id: Optional[str] = None,
        visited_nodes: Optional[Set[NodeId]] = None,
        visited_edges: Optional[Set[EdgeKey]] = None,
    ):
        super().__init__()
        self.g = sub
        self.nodes = sub.nodes()
        self.visited_nodes: Set[NodeId] = visited_nodes if visited_nodes else set()
        self.visited_edges: Set[EdgeKey] = visited_edges if visited_edges else set()
        self.at = utc()
        self.at_json = utc_str(self.at)
        self.maybe_root_id = maybe_root_id
        self.resolved = False

    def root(self) -> str:
        return self.maybe_root_id if self.maybe_root_id else GraphAccess.root_id(self.g)

    def node(self, node_id: NodeId) -> Optional[Json]:
        self.visited_nodes.add(node_id)
        if self.g.has_node(node_id):
            n = self.nodes[node_id]
            return self.dump(node_id, n)
        else:
            return None

    def cloud_node_id(self) -> Optional[NodeId]:
        cloud_ids = [
            data.get("id") for nid, data in self.nodes(data=True) if "cloud" in data.get("kinds", []) and data.get("id")
        ]
        assert len(cloud_ids) <= 1, f"More than one cloud node found: {cloud_ids}"
        return cloud_ids[0] if cloud_ids else None

    def has_edge(self, from_id: object, to_id: object, edge_type: EdgeType) -> Tuple[bool, Optional[Json]]:
        key = self.edge_key(from_id, to_id, edge_type)
        if self.g.has_edge(from_id, to_id, key):
            self.visited_edges.add(key)
            return True, self.g.get_edge_data(from_id, to_id, key)
        return False, None

    def resolve(self) -> None:
        if not self.resolved:
            self.resolved = True
            log.info("Resolve attributes in graph")
            for node_id in self.nodes:
                self.__resolve(node_id, self.nodes[node_id])
            self.__resolve_count_descendants()
            log.info("Resolve attributes finished.")

    def __resolve_count_descendants(self) -> None:
        empty_set: Set[str] = set()

        def count_descendants_of(rid: str, rname: str, ancestor_kind: str, path: List[str]) -> Dict[str, int]:
            result: DefaultDict[str, int] = defaultdict(int)
            rid_path = ["ancestors", ancestor_kind, "reported", "id"]
            rname_path = ["ancestors", ancestor_kind, "reported", "name"]
            for _, elem in self.g.nodes(data=True):
                if value_in_path(elem, rid_path) == rid and value_in_path(elem, rname_path) == rname:
                    kinds_set = elem.get("kinds_set", empty_set)
                    extracted = value_in_path(elem, path)
                    if "phantom_resource" not in kinds_set and isinstance(extracted, str):
                        result[extracted] += 1
            return result

        empty_set = set()
        for _, node in self.g.nodes(data=True):
            kinds = node.get("kinds_set", empty_set)
            for on_kind, prop in GraphResolver.count_successors.items():
                if on_kind in kinds:
                    if (rid := value_in_path(node, NodePath.reported_id)) and (
                        rname := value_in_path(node, NodePath.reported_name)
                    ):
                        # Descendant summary: we need to compare id and name.
                        # Example AWS global region: id=us-east-1, name=global
                        summary = count_descendants_of(rid, rname, on_kind, prop.extract_path)
                        set_value_in_path(summary, prop.to_path, node)
                        # descendant count
                        total = reduce(lambda left, right: left + right, summary.values(), 0)
                        set_value_in_path(total, NodePath.descendant_count, node)
                        # update hash
                        node["hash"] = GraphBuilder.content_hash(
                            node["reported"],
                            desired=node.get("desired"),
                            metadata=node.get("metadata"),
                            kinds=node.get("kinds"),
                        )

    def __resolve(self, node_id: NodeId, node: Json) -> Json:
        def with_ancestor(ancestor: Json, prop: ResolveProp) -> None:
            extracted = value_in_path(ancestor, prop.extract_path)
            if extracted:
                set_value_in_path(extracted, prop.to_path, node)

        for resolver in GraphResolver.to_resolve:
            # search for ancestor that matches filter criteria
            anc = self.ancestor_of(node_id, EdgeTypes.default, resolver.kind)
            if anc:
                on_self = anc.get("id") == node_id
                for res in resolver.resolve:
                    if not path_exists(node, res.to_path) and (not on_self or res.apply_on_self):
                        with_ancestor(anc, res)
        return node

    def dump(self, node_id: NodeId, node: Json) -> Json:
        kind = node.get("kind", AnyKind())
        return self.dump_direct(node_id, node, kind)

    def predecessors(self, node_id: NodeId, edge_type: EdgeType) -> Generator[NodeId, Any, None]:
        for pred_id in self.g.predecessors(node_id):
            # direction from parent node to provided node
            if self.g.has_edge(pred_id, node_id, self.edge_key(pred_id, node_id, edge_type)):
                yield pred_id

    def successors(self, node_id: NodeId, edge_type: EdgeType) -> Generator[NodeId, Any, None]:
        for succ_id in self.g.successors(node_id):
            # direction from provided node to successor node
            if self.g.has_edge(node_id, succ_id, self.edge_key(node_id, succ_id, edge_type)):
                yield succ_id

    def ancestor_of(self, node_id: NodeId, edge_type: EdgeType, kind: str) -> Optional[Json]:
        # note: we are using breadth first search here on purpose.
        # if there is an ancestor with less distance to this node, we should use this one
        next_level = [node_id]

        while next_level:
            parents: List[NodeId] = []
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
    def dump_direct(node_id: NodeId, node: Json, kind: Kind, recompute: bool = False) -> Json:
        reported = node[Section.reported]
        desired: Optional[Json] = node.get(Section.desired, None)
        metadata: Optional[Json] = node.get(Section.metadata, None)
        kinds: Optional[List[str]] = node.get("kinds", None)
        if "id" not in node:
            node["id"] = node_id
        if recompute or "hash" not in node:
            node["hash"] = GraphBuilder.content_hash(reported, desired, metadata, kinds)
        if recompute or "flat" not in node:
            node["flat"] = GraphBuilder.flatten(reported, kind)
        if "kinds" not in node:
            node["kinds"] = [reported["kind"]]
        return node

    def not_visited_nodes(self) -> Iterator[Json]:
        return (self.dump(nid, self.nodes[nid]) for nid in self.g.nodes if nid not in self.visited_nodes)

    def not_visited_edges(self, edge_type: EdgeType) -> Iterator[Tuple[str, str, Json]]:
        for fn, tn, key, data in self.g.edges(keys=True, data=True):
            if key.edge_type == edge_type:
                if key not in self.visited_edges:
                    yield fn, tn, data

    @staticmethod
    def edge_key(from_node: object, to_node: object, edge_type: EdgeType) -> EdgeKey:
        return EdgeKey(from_node, to_node, edge_type)

    @staticmethod
    def root_id(graph: DiGraph) -> NodeId:
        # noinspection PyTypeChecker
        roots: List[NodeId] = [n for n, d in graph.in_degree if d == 0]
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

        Note that all successors of a merge node that is also a predecessors of the merge node are sorted out.

        :param graph: the incoming multi graph update.
        :return: the list of all merge roots, the expected parent graph and all merge root graphs.
        """

        # run DFS from the source and collect all nodes until a replace node is found.
        def collect_until_replace_node(
            graph: MultiDiGraph, source: NodeId, seen: Set[NodeId]
        ) -> Tuple[Dict[NodeId, Json], set[NodeId]]:
            if source in seen:
                return {}, set()
            seen.add(source)
            # if we hit a replace node, stop here
            data = graph.nodes[source]
            replace = (data.get("metadata", {}) or {}).get("replace", False)
            if replace:
                return {source: data}, {source}

            replace_nodes: Dict[NodeId, Json] = {}
            replace_nodes_predecessors: Set[NodeId] = {source}

            for child in graph.successors(source):
                rn, pred = collect_until_replace_node(graph, child, seen)
                replace_nodes.update(rn)
                replace_nodes_predecessors.update(pred)

            return replace_nodes, replace_nodes_predecessors

        # Find replace nodes: all nodes that are marked as replace node.
        # This method returns all replace roots as key, with the respective predecessors nodes as value.
        def replace_roots() -> Dict[NodeId, Set[NodeId]]:
            graph_root = GraphAccess.root_id(graph)
            replace_nodes, preds = collect_until_replace_node(graph, graph_root, set())
            result: Dict[NodeId, Set[NodeId]] = {node: preds for node in replace_nodes}
            assert (
                len(replace_nodes) > 0
            ), "No replace nodes provided in the graph. Mark at least one node with replace=true!"
            for node, data in replace_nodes.items():
                kind = GraphResolver.resolved_kind(data)
                assert (
                    kind is not None
                ), f"Node {node} is marked as replace node, but the kind is not resolved during import!"
            return result

        # Walk the graph from given starting node and return all successors.
        # A successor which is also a predecessors is not followed.
        def sub_graph_nodes(from_node: NodeId, parent_ids: Set[NodeId]) -> Set[NodeId]:
            to_visit = [from_node]
            visited: Set[NodeId] = {from_node}

            def successors(node: NodeId) -> List[NodeId]:
                return [a for a in graph.successors(node) if a not in visited and a not in parent_ids]

            while to_visit:
                to_visit = reduce(lambda li, node: li + successors(node), to_visit, list[NodeId]())
                visited.update(to_visit)
            return visited

        # Create a generator for all given merge roots by:
        #   - creating the set of all successors
        #   - creating a subgraph which contains all predecessors and all successors
        #   - all predecessors are marked as visited
        #   - all predecessors edges are marked as visited
        # This way it is possible to have nodes in the graph that will not be touched by the update
        # while edges will be created from successors of the merge node to predecessors of the merge node.
        def merge_sub_graphs(
            root_nodes: Dict[NodeId, Set[NodeId]], parent_nodes: Set[NodeId], parent_edges: Set[EdgeKey]
        ) -> Generator[Tuple[NodeId, GraphAccess], None, None]:
            all_successors: Set[NodeId] = set()
            for root, predecessors in root_nodes.items():
                successors: Set[NodeId] = sub_graph_nodes(root, predecessors)
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
        parents: Set[NodeId] = reduce(lambda res, ps: {*res, *ps}, roots.values(), set[NodeId]())
        parent_graph = graph.subgraph(parents)
        graphs = merge_sub_graphs(roots, parents, set(parent_graph.edges(data="edge_type")))
        return list(roots.keys()), GraphAccess(parent_graph, GraphAccess.root_id(graph)), graphs
