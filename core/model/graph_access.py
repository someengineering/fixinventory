import json
import jsons
import hashlib

from datetime import datetime, timezone
from typing import Optional, Tuple, Generator, Any, List, Set, Dict

from core import feature
from core.model.model import Model
from core.types import Json
from networkx import DiGraph
from core.model.typed_model import to_js


class GraphBuilder:

    def __init__(self, model: Model, with_flatten: bool = feature.DB_SEARCH):
        self.model = model
        self.graph = DiGraph()
        self.with_flatten = with_flatten
        self.visited_ids: Set[str] = set()

    def add_node(self, js: Json) -> None:
        if "id" in js and "data" in js:
            # validate kind of this data
            coerced = self.model.check_valid(js["data"])
            item = js["data"] if coerced is None else coerced
            did = js["id"]  # this is the identifier in the json document
            kind = self.model[item]
            # create content hash
            sha = GraphBuilder.content_hash(item)
            # flat all properties into a single string for search
            flat = GraphBuilder.flatten(item) if self.with_flatten else None
            self.visited_ids.add(did)
            self.graph.add_node(did, data=item, hash=sha, kind=kind, flat=flat)
        elif "from" in js and "to" in js:
            if js["from"] in self.visited_ids and js["to"] in self.visited_ids:
                self.graph.add_edge(js["from"], js["to"])
            else:
                raise AttributeError(f'Received edge: {js["from"]}->{js["to"]} but not related vertexes.')
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

    @staticmethod
    def graph_from_single_item(model: Model, node_id: str, data: Json) -> DiGraph:
        builder = GraphBuilder(model)
        builder.add_node({"id": node_id, "data": data})
        return builder.graph


class GraphAccess:

    def __init__(self, sub: DiGraph):
        super().__init__()
        self.g = sub
        self.nodes = sub.nodes()
        self.edges = [e[:2] for e in sub.edges.data()]
        self.visited_nodes: Set[object] = set()
        self.visited_edges: Set[object] = set()
        self.at = datetime.now(timezone.utc)
        self.at_json = jsons.dump(self.at)

    def root(self) -> str:
        return GraphAccess.root_id(self.g)

    def node(self, node_id: str) -> Optional[Tuple[str, Json, str, List[str], str]]:
        self.visited_nodes.add(node_id)
        if self.g.has_node(node_id):
            n = self.nodes[node_id]
            return self.dump(node_id, n)
        else:
            return None

    def has_edge(self, from_id: object, to_id: object) -> bool:
        result: bool = self.g.has_edge(from_id, to_id)
        if result:
            self.visited_edges.add((from_id, to_id))
        return result

    @staticmethod
    def dump(node_id: str, node: Dict[str, Any]) -> Tuple[str, Json, str, List[str], str]:
        js: Json = to_js(node["data"])
        sha256 = node["hash"] if "hash" in node else GraphBuilder.content_hash(js)
        flat = node["flat"] if "flat" in node else GraphBuilder.flatten(js)
        kinds = node["kind"].kind_hierarchy() if "kind" in node else [js["kind"]] if "kind" in js else [
            node.kind()] if hasattr(node, "kind") else []  # type: ignore
        return node_id, js, sha256, kinds, flat

    def not_visited_nodes(self) -> Generator[Tuple[str, Dict[str, Any], str, List[str], str], None, None]:
        return (self.dump(nid, self.nodes[nid]) for nid in self.g.nodes if nid not in self.visited_nodes)

    def not_visited_edges(self) -> Generator[Tuple[str, str], None, None]:
        return (edge for edge in self.edges if edge not in self.visited_edges)

    @staticmethod
    def root_id(graph: DiGraph) -> str:
        # noinspection PyTypeChecker
        roots: List[str] = [n for n, d in graph.in_degree if d == 0]
        assert len(roots) == 1, f"Given subgraph has more than one root: {roots}"
        return roots[0]
