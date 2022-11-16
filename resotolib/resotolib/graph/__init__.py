from __future__ import annotations
import networkx
from enum import Enum
from networkx.algorithms.dag import is_directed_acyclic_graph
from datetime import datetime
import threading
import pickle
import json
import jsons
import re
import tempfile
from resotolib.logger import log
from resotolib.baseresources import (
    BaseCloud,
    BaseAccount,
    GraphRoot,
    Cloud,
    BaseResource,
    EdgeType,
)
from resotolib.types import Json
from resotolib.utils import json_default, get_resource_attributes
from resotolib.args import ArgumentParser
from resotolib.core.model_export import (
    dataclasses_to_resotocore_model,
    node_to_dict,
)
from resotolib.event import (
    Event,
    EventType,
    add_event_listener,
    remove_event_listener,
)
from prometheus_client import Summary
from typing import Dict, Iterator, List, Tuple, Optional, Union, Any
from io import BytesIO
from typeguard import check_type
from time import time
from collections import defaultdict, namedtuple, deque
from attrs import define, fields


@define
class BySearchCriteria:
    query: str


@define
class ByNodeId:
    value: str


NodeSelector = Union[ByNodeId, BySearchCriteria]


metrics_graph_search = Summary("resoto_graph_search_seconds", "Time it took the Graph search() method")
metrics_graph_searchall = Summary("resoto_graph_searchall_seconds", "Time it took the Graph searchall() method")
metrics_graph_searchre = Summary("resoto_graph_searchre_seconds", "Time it took the Graph searchre() method")
metrics_graph_search_first = Summary(
    "resoto_graph_search_first_seconds",
    "Time it took the Graph search_first() method",
)
metrics_graph_search_first_all = Summary(
    "resoto_graph_search_first_all_seconds",
    "Time it took the Graph search_first_all() method",
)
metrics_graph_search_first_parent_class = Summary(
    "resoto_graph_search_first_parent_seconds",
    "Time it took the Graph search_first_parent_class() method",
)
metrics_graph_resolve_deferred_connections = Summary(
    "resoto_graph_resolve_deferred_connections",
    "Time it took the Graph resolve_deferred_connections() method",
)
metrics_graphcache_update_cache = Summary(
    "resoto_graphcache_update_cache_seconds",
    "Time it took the GraphCache update_cache() method",
)
metrics_graph2json = Summary("resoto_graph2json_seconds", "Time it took the graph2json() method")
metrics_graph2text = Summary("resoto_graph2text_seconds", "Time it took the graph2text() method")
metrics_graph2graphml = Summary("resoto_graph2graphml_seconds", "Time it took the graph2graphml() method")
metrics_graph2pickle = Summary("resoto_graph2pickle_seconds", "Time it took the graph2pickle() method")
metrics_graph2gexf = Summary("resoto_graph2gexf_seconds", "Time it took the graph2gexf() method")
metrics_graph2pajek = Summary("resoto_graph2pajek_seconds", "Time it took the graph2pajek() method")

EdgeKey = namedtuple("EdgeKey", ["src", "dst", "edge_type"])


class Graph(networkx.MultiDiGraph):
    """A directed Graph"""

    def __init__(self, *args, root: BaseResource = None, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.root = None
        self._log_edge_creation = True
        if isinstance(root, BaseResource):
            self.root = root
            self.add_node(self.root, label=self.root.name, **get_resource_attributes(self.root))
        self.deferred_edges: List[Tuple[NodeSelector, NodeSelector, EdgeType]] = []

    def merge(self, graph: Graph):
        """Merge another graph into ourselves

        If the other graph has a graph.root an edge will be created between
        it and our own graph root.
        """
        if isinstance(self.root, BaseResource) and isinstance(getattr(graph, "root", None), BaseResource):
            log.debug(f"Merging graph of {graph.root.rtdname} into graph of {self.root.rtdname}")
            self.add_edge(self.root, graph.root)
        else:
            log.warning("Merging graphs with no valid roots")

        try:
            self._log_edge_creation = False
            self.update(edges=graph.edges, nodes=graph.nodes)
            self.deferred_edges.extend(graph.deferred_edges)
        finally:
            self._log_edge_creation = True
        self.resolve_deferred_connections()

    def add_resource(
        self,
        parent: BaseResource,
        node_for_adding: BaseResource,
        edge_type: EdgeType = None,
        **attr,
    ):
        """Add a resource node to the graph

        When adding resource nodes to the graph there's always a label and a
        kind as well as an edge connecting the new resource with its parent
        resource. This way we should never have disconnected nodes within the graph.

        The graph_attributes are a Dict of key=value pairs that contain all the
        attributes of a graph node. When working with the graph that information isn't
        too important as each node is a standard Python object containing all its
        properties. However when exporting in graphml, gexf or json those attributes are
        the only thing being exported with the node name. So we'll try to turn every
        public property of a graph node into key=value attribute pairs to be exported
        with the graph.

        Attributes can also be used in graph searches to find nodes matching certain
        attributes.
        """
        resource_attr = get_resource_attributes(node_for_adding)

        self.add_node(node_for_adding, label=node_for_adding.name, **resource_attr, **attr)
        self.add_edge(src=parent, dst=node_for_adding, edge_type=edge_type)

    def add_node(self, node_for_adding: BaseResource, **attr):
        super().add_node(node_for_adding, **attr)
        if isinstance(node_for_adding, BaseResource):
            # We hand a reference to ourselves to the added BaseResource
            # which stores it as a weakref.
            node_for_adding._graph = self

    def has_edge(
        self, src: BaseResource, dst: BaseResource, key: Optional[EdgeKey] = None, edge_type: Optional[str] = None
    ) -> bool:
        edge_type = edge_type or EdgeType.default
        key = key or EdgeKey(src=src, dst=dst, edge_type=edge_type)
        return super().has_edge(src, dst, key=key)

    def add_edge(
        self,
        src: BaseResource,
        dst: BaseResource,
        key: EdgeKey = None,
        edge_type: EdgeType = None,
        **attr,
    ):
        if src is None or dst is None:
            log.error(f"Not creating edge from or to NoneType: {src} to {dst}")
            return

        if edge_type is None:
            edge_type = EdgeType.default
        if key is None:
            key = EdgeKey(src=src, dst=dst, edge_type=edge_type)

        if self.has_edge(src, dst, key=key):
            log.debug(f"Edge from {src} to {dst} already exists in graph")
            return
        return_key = super().add_edge(src, dst, key=key, **attr)
        if self._log_edge_creation and isinstance(src, BaseResource) and isinstance(dst, BaseResource):
            log.debug(f"Added edge from {src.rtdname} to {dst.rtdname} (type: {edge_type.value})")
            try:
                src.successor_added(dst, self)
            except Exception:
                log.exception(
                    (f"Unhandled exception while telling {src.rtdname}" f" that {dst.rtdname} was added as a successor")
                )
            try:
                dst.predecessor_added(src, self)
            except Exception:
                log.exception(
                    (
                        f"Unhandled exception while telling {dst.rtdname}"
                        f" that {src.rtdname} was added as a predecessor"
                    )
                )
        return return_key

    def add_deferred_edge(self, src: NodeSelector, dst: NodeSelector, edge_type: EdgeType = EdgeType.default) -> None:
        self.deferred_edges.append((src, dst, edge_type))

    def remove_node(self, node: BaseResource):
        super().remove_node(node)

    def remove_edge(
        self,
        src: BaseResource,
        dst: BaseResource,
        key: EdgeKey = None,
        edge_type: EdgeType = None,
    ):
        if edge_type is None:
            edge_type = EdgeType.default
        if key is None:
            key = EdgeKey(src=src, dst=dst, edge_type=edge_type)
        super().remove_edge(src, dst, key=key)

    def predecessors(self, node: BaseResource, edge_type: EdgeType = None):
        if edge_type is None:
            edge_type = EdgeType.default
        for predecessor in super().predecessors(node):
            key = (predecessor, node, edge_type)
            if self.has_edge(predecessor, node, key=key):
                yield predecessor

    def successors(self, node: BaseResource, edge_type: EdgeType = None):
        if edge_type is None:
            edge_type = EdgeType.default
        for successor in super().successors(node):
            key = (node, successor, edge_type)
            if self.has_edge(node, successor, key=key):
                yield successor

    def ancestors(self, node: BaseResource, edge_type: EdgeType = None):
        return networkx.algorithms.dag.ancestors(self.edge_type_subgraph(edge_type), node)

    def descendants(self, node: BaseResource, edge_type: EdgeType = None):
        return networkx.algorithms.dag.descendants(self.edge_type_subgraph(edge_type), node)

    def edge_type_subgraph(self, edge_type: EdgeType = None):
        if edge_type is None:
            edge_type = EdgeType.default
        edges = []
        for edge in self.edges(keys=True):
            if len(edge) == 3:
                key: EdgeKey = edge[2]
                if key.edge_type == edge_type:
                    edges.append(edge)
        return self.edge_subgraph(edges)

    def is_dag_per_edge_type(self) -> bool:
        """
        Checks if the graph is acyclic with respect to each edge type.
        This means it is valid if there are cycles in the graph but not for the same edge type.
        :return: True if the graph is acyclic for all edge types, otherwise False.
        """
        log.debug("Ensuring graph is directed and acyclic per edge type")
        edges_per_type = defaultdict(list)
        for edge in self.edges(keys=True):
            if len(edge) == 3:
                key: EdgeKey = edge[2]
                edges_per_type[key.edge_type].append(edge)
        for edges in edges_per_type.values():
            typed_graph = self.edge_subgraph(edges)
            if not is_directed_acyclic_graph(typed_graph):
                return False
        return True

    @metrics_graph_search.time()
    def search(self, attr, value, regex_search=False):
        """Search for graph nodes by their attribute value"""
        if value is None:
            log.debug(f"Not searching graph for nodes with attribute values {attr}: {value}")
            return ()
        log.debug((f"Searching graph for nodes with attribute values {attr}: {value}" f" (regex: {regex_search})"))
        for node in self.nodes():
            node_attr = getattr(node, attr, None)
            if (
                node_attr is not None
                and not callable(node_attr)
                and (
                    (regex_search is False and node_attr == value)
                    or (regex_search is True and re.search(value, str(node_attr)))
                )
            ):
                yield node

    @metrics_graph_searchre.time()
    def searchre(self, attr, regex):
        """Regex search for graph nodes by their attribute value"""
        log.debug(f"Regex searching graph for nodes with attribute values {attr}: {regex}")
        return self.search(attr, regex, regex_search=True)

    @metrics_graph_searchall.time()
    def searchall(self, match: Dict):
        """Search for graph nodes by multiple attributes and values"""
        return (
            node for node in self.nodes() if all(getattr(node, attr, None) == value for attr, value in match.items())
        )

    @metrics_graph_search_first.time()
    def search_first(self, attr, value):
        """Return the first graph node that matches a certain attribute value"""
        node = next(iter(self.search(attr, value)), None)
        if node:
            log.debug(f"Found node {node} with {attr}: {value}")
        else:
            log.debug(f"Found no node with {attr}: {value}")
        return node

    @metrics_graph_search_first_all.time()
    def search_first_all(self, match: Dict):
        """Return the first graph node that matches multiple attributes and values"""
        node = next(iter(self.searchall(match)), None)
        if node:
            log.debug(f"Found node {node} with {match}")
        else:
            log.debug(f"Found no node with {match}")
        return node

    @metrics_graph_search_first_parent_class.time()
    def search_first_parent_class(self, node, cls):
        """Return the first parent node matching a certain class

        This is being used to search up the graph and e.g. find the account that the
        graph node is a member of.
        """
        queue = deque(self.predecessors(node))
        already_checked = set(self.predecessors(node))
        while queue:
            current = queue.popleft()
            if isinstance(current, cls):
                return current
            for n in self.predecessors(current):
                if n not in already_checked:
                    already_checked.add(n)
                    queue.append(n)
        return None

    @metrics_graph_resolve_deferred_connections.time()
    def resolve_deferred_connections(self):
        log.debug("Resolving deferred graph connections")
        for node in self.nodes:
            if isinstance(node, BaseResource):
                node.resolve_deferred_connections(self)

    def export_model(self, **kwargs: Any) -> List[Json]:
        """Return the graph node dataclass model in resotocore format"""
        classes = set()
        for node in self.nodes:
            classes.add(type(node))
        model = dataclasses_to_resotocore_model(classes, aggregate_root=BaseResource, **kwargs)

        # fixme: workaround to report kind
        for resource_model in model:
            if resource_model.get("fqn") == "resource":
                resource_model.get("properties", []).append(
                    {
                        "name": "kind",
                        "kind": "string",
                        "required": True,
                        "description": "",
                    }
                )
        return model

    def export_iterator(self) -> GraphExportIterator:
        return GraphExportIterator(self)


class GraphContainer:
    """A context containing a Graph()

    This can be passed to various code parts like e.g. a WebServer() allowing
    replacement and updating of the graph without losing its context.
    """

    GRAPH_ROOT = GraphRoot(id="root", tags={})

    def __init__(self, cache_graph=True) -> None:
        self._graph = None
        self._observers = []
        self.__lock = threading.Lock()
        self.graph = Graph(root=self.GRAPH_ROOT)
        if cache_graph:
            self.cache = GraphCache()
            self.cache.update_cache(Event(EventType.STARTUP, self.graph))
            add_event_listener(EventType.COLLECT_FINISH, self.cache.update_cache)
            add_event_listener(EventType.CLEANUP_FINISH, self.cache.update_cache)
        else:
            self.cache = None

    def __del__(self):
        if self.cache is not None:
            remove_event_listener(EventType.CLEANUP_FINISH, self.cache.update_cache)
            remove_event_listener(EventType.COLLECT_FINISH, self.cache.update_cache)

    @property
    def graph(self):
        return self._graph

    @graph.setter
    def graph(self, value):
        self._graph = value

    def add(self, graph) -> None:
        """Add another graph to the existing one"""
        with self.__lock:
            self.graph = networkx.compose(self.graph, graph)

    @staticmethod
    def add_args(arg_parser: ArgumentParser) -> None:
        """Add args to the arg parser

        This adds the GraphContainer()'s own args.
        """
        arg_parser.add_argument(
            "--tag-as-metrics-label",
            help="Tag to use as metrics label",
            dest="metrics_tag_as_label",
            type=str,
            default=None,
            nargs="+",
        )

    @property
    def pickle(self):
        if self.cache and self.cache.pickle:
            return self.cache.pickle
        else:
            return graph2pickle(self.graph)

    @property
    def json(self):
        if self.cache and self.cache.json:
            return self.cache.json
        else:
            return graph2json(self.graph)

    @property
    def text(self):
        if self.cache and self.cache.text:
            return self.cache.text
        else:
            return graph2text(self.graph)

    @property
    def graphml(self):
        if self.cache and self.cache.graphml:
            return self.cache.graphml
        else:
            return graph2graphml(self.graph)

    @property
    def gexf(self):
        if self.cache and self.cache.gexf:
            return self.cache.gexf
        else:
            return graph2gexf(self.graph)

    @property
    def pajek(self):
        if self.cache and self.cache.pajek:
            return self.cache.pajek
        else:
            return graph2pajek(self.graph)


# The mlabels() and mtags() functions are being used to dynamically add more labels
# to each metric. The idea here is that via a cli arg we can specify resource tags
# that should be exported as labels for each metric. This way we don't have to touch
# the code itself any time we want to add another metrics dimension. Instead we could
# just have a tag like 'project' and then use the '--tag-as-metrics-label project'
# argument to export another label based on the given tag.
def mlabels(labels: List) -> List:
    """Takes a list of labels and appends any cli arg specified tag names to it."""
    if ArgumentParser.args and getattr(ArgumentParser.args, "metrics_tag_as_label", None):
        for tag in ArgumentParser.args.metrics_tag_as_label:
            labels.append(make_valid_label(tag))
    return labels


def mtags(labels: Tuple, node: BaseResource) -> Tuple:
    """Takes a tuple containing labels and adds any tags specified as cli args to it.

    Returns the extended tuple.
    """
    if not type(labels) is tuple:
        if type(labels) is list:
            labels = tuple(labels)
        else:
            labels = tuple([labels])
    ret = list(labels)
    if ArgumentParser.args and getattr(ArgumentParser.args, "metrics_tag_as_label", None):
        for tag in ArgumentParser.args.metrics_tag_as_label:
            if tag in node.tags:
                tag_value = node.tags[tag]
                ret.append(tag_value)
            else:
                ret.append("")
    return tuple(ret)


def make_valid_label(label: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_]", "_", label)


class GraphCache:
    """A Cache of multiple Graph formats

    The Graph can be exported in multiple file formats.
    Calculating them is expensive. Since the Graph only gets updated
    every interval we only need to calculate its representations
    once per interval and then cache the result.

    TODO: instead of just in-memory strings move this to mmaped
    files or maybe use sqlite3 which has an easy to use interface
    and built-in mmap support.

    TODO: Version the Graph and the Cache
    """

    def __init__(self) -> None:
        self._json_cache = None
        self._graphml_cache = None
        self._text_cache = None
        self._gexf_cache = None
        self._pickle_cache = None
        self._pajek_cache = None

    @metrics_graphcache_update_cache.time()
    def update_cache(self, event: Event) -> None:
        log.debug("Updating the Graph Cache")
        graph = event.data
        log.debug("Generating pickle cache")
        self._pickle_cache = graph2pickle(graph)
        # log.debug('Generating JSON cache')
        # self._json_cache = graph2json(graph)
        # log.debug('Generating Text cache')
        # self._text_cache = graph2text(graph)
        # log.debug('Generating GraphML cache')
        # self._graphml_cache = graph2graphml(graph)
        # log.debug('Generating GEXF cache')
        # self._gexf_cache = graph2gexf(graph)

    @property
    def pickle(self):
        return self._pickle_cache

    @property
    def json(self):
        return self._json_cache

    @property
    def text(self):
        return self._text_cache

    @property
    def graphml(self):
        return self._graphml_cache

    @property
    def gexf(self):
        return self._gexf_cache

    @property
    def pajek(self):
        return self._pajek_cache

    @property
    def metrics(self):
        return self._metrics_cache


def dump_graph(graph) -> str:
    """Debug dump the graph and list each nodes predecessor and successor nodes"""
    for node in graph.nodes:
        yield f"Node: {node.name} (type: {node.kind})"
        for predecessor_node in graph.predecessors(node):
            yield (f"\tParent: {predecessor_node.name}" f" (type: {predecessor_node.kind})")
        for successor_node in graph.successors(node):
            yield (f"\tChild {successor_node.name} (type: {successor_node.kind})")


@metrics_graph2json.time()
def graph2json(graph):
    return json.dumps(networkx.node_link_data(graph), default=json_default, skipkeys=True) + "\n"


@metrics_graph2text.time()
def graph2text(graph):
    return "\n".join(dump_graph(graph)) + "\n"


@metrics_graph2graphml.time()
def graph2graphml(graph):
    return "\n".join(networkx.generate_graphml(graph)) + "\n"


@metrics_graph2pickle.time()
def graph2pickle(graph):
    return pickle.dumps(graph)


@metrics_graph2gexf.time()
def graph2gexf(graph):
    gexf = BytesIO()
    networkx.write_gexf(graph, gexf)
    return gexf.getvalue().decode("utf8")


@metrics_graph2pajek.time()
def graph2pajek(graph):
    new_graph = graph.copy()
    for _, node_data in new_graph.nodes(data=True):
        # Pajek exporter requires attribute with name 'id' to be int
        # or not existing and all other attributes to be strings.
        if "id" in node_data:
            node_data["identifier"] = node_data["id"]
            del node_data["id"]
        for attribute in node_data:
            node_data[attribute] = str(node_data[attribute])
    return "\n".join(networkx.generate_pajek(new_graph)) + "\n"


def validate_dataclass(node: BaseResource):
    for field in fields(type(node)):
        value = getattr(node, field.name)
        try:
            check_type(str(value), value, field.type)
        except TypeError:
            log.exception(
                f"In {node.rtdname} expected {field.name}"
                f" type {field.type} ({type(field.type)})"
                f" for value {value} ({type(value)})"
            )


def validate_graph_dataclasses_and_nodes(graph: Graph) -> None:
    log.debug("Validating attribute types of all graph dataclasses")
    node_chksums = {}
    for node in graph.nodes:
        if isinstance(node, BaseResource):
            validate_dataclass(node)
            if node.chksum not in node_chksums:
                node_chksums[node.chksum] = node
            else:
                log.error(f"Duplicate checksum {node.chksum} for node {node.rtdname} in graph")


def update_graph_ref(graph: Graph) -> None:
    for node in graph.nodes:
        if isinstance(node, BaseResource):
            node._graph = graph


def sanitize(graph: Graph, root: GraphRoot = None) -> None:
    log.debug("Sanitizing Graph")
    plugin_roots = {}
    graph_roots = []

    if root is None and isinstance(getattr(graph, "root", None), BaseResource):
        root = graph.root

    if root is None:
        log.debug("No graph root found - unable to sanitize")
        return

    for node in graph.successors(root):
        if isinstance(node, Cloud):
            log.debug(f"Found Plugin Root {node.id}")
            plugin_roots[node.id] = node
        elif isinstance(node, GraphRoot):
            log.debug(f"Found Graph Root {node.id}")
            graph_roots.append(node)
        else:
            log.debug(f"Found unknown node {node.id} of type {node.kind}")

    if len(graph_roots) > 0:
        for graph_root in graph_roots:
            log.debug(f"Moving children of graph root {graph_root.id}")
            for node in list(graph.successors(graph_root)):
                if isinstance(node, Cloud):
                    if node.id in plugin_roots:
                        log.debug(
                            f"Found existing plugin root {node.id}" " - attaching children and removing plugin root"
                        )
                        for plugin_root_child in list(graph.successors(node)):
                            log.debug(
                                f"Found node {plugin_root_child.id} of type "
                                f"{plugin_root_child.kind}"
                                " - attaching to existing plugin root"
                            )
                            graph.add_edge(plugin_roots[node.id], plugin_root_child)
                            graph.remove_edge(node, plugin_root_child)
                        graph.remove_node(node)
                    else:
                        log.debug(f"Found new plugin root {node.id}" " - attaching to top level root")
                        graph.add_edge(root, node)
                        graph.remove_edge(graph_root, node)
                else:
                    log.debug(f"Found unknown node {node.id} of type {node.kind}" " - attaching to top level root")
                    graph.add_edge(root, node)
                    graph.remove_edge(graph_root, node)
            log.debug(f"Removing graph root {graph_root.id}")
            graph.remove_node(graph_root)
    graph.resolve_deferred_connections()
    update_graph_ref(graph)
    validate_graph_dataclasses_and_nodes(graph)


class GraphMergeKind(Enum):
    cloud = "cloud"
    account = "account"


class GraphExportIterator:
    def __init__(
        self,
        graph: Graph,
        delete_tempfile: bool = True,
        tempdir: Optional[str] = None,
        graph_merge_kind: GraphMergeKind = GraphMergeKind.cloud,
    ):
        self.graph = graph
        ts = datetime.now().strftime("%Y-%m-%d-%H-%M")
        self.tempfile = tempfile.NamedTemporaryFile(
            prefix=f"resoto-graph-{ts}-",
            suffix=".ndjson",
            delete=delete_tempfile,
            dir=tempdir,
        )
        if not delete_tempfile:
            log.info(f"Writing graph json to file {self.tempfile.name}")

        if not isinstance(graph_merge_kind, GraphMergeKind):
            log.error(f"Graph merge kind is wrong type {type(graph_merge_kind)}")
            graph_merge_kind = GraphMergeKind.cloud

        if graph_merge_kind == GraphMergeKind.cloud:
            self.graph_merge_kind = BaseCloud
        elif graph_merge_kind == GraphMergeKind.account:
            self.graph_merge_kind = BaseAccount
        else:
            log.error(f"Graph merge kind has unknown value {graph_merge_kind} - defaulting to 'cloud'")
            self.graph_merge_kind = BaseCloud

        self.graph_exported = False
        self.found_replace_node = False
        self.export_lock = threading.Lock()
        self.total_lines = 0
        self.number_of_nodes = int(graph.number_of_nodes())
        self.number_of_edges = int(graph.number_of_edges())
        self.number_of_deferred_edges = len(graph.deferred_edges)

    def __del__(self):
        try:
            self.tempfile.close()
        except Exception:
            pass

    def __iter__(self) -> Iterator[bytes]:
        if not self.graph_exported:
            self.export_graph()
        start_time = time()
        last_sent = time()
        lines_sent = 0
        percent = 0
        report_every = round(self.total_lines / 10)

        self.tempfile.seek(0)
        while line := self.tempfile.readline():
            lines_sent += 1
            if report_every > 0 and lines_sent > 0 and lines_sent % report_every == 0:
                percent = round(lines_sent / self.total_lines * 100)
                elapsed = time() - last_sent
                log.debug(f"Sent {lines_sent}/{self.total_lines} nodes and edges ({percent}%) - {elapsed:.4f}s")
                last_sent = time()
            yield line
        elapsed = time() - start_time
        log.info(
            f"Sent {lines_sent}/{self.total_lines},"
            f" {self.number_of_nodes} nodes, {self.number_of_edges} edges"
            f" and {self.number_of_deferred_edges} deferred edges"
            f" in {elapsed:.4f}s"
        )

    def export_graph(self) -> None:
        with self.export_lock:
            start_time = time()
            for node in self.graph.nodes:
                node_dict = node_to_dict(node)
                if isinstance(node, self.graph_merge_kind):
                    log.debug(f"Replacing sub graph below {node.rtdname}")
                    if "metadata" not in node_dict or not isinstance(node_dict["metadata"], dict):
                        node_dict["metadata"] = {}
                    node_dict["metadata"]["replace"] = True
                    self.found_replace_node = True
                node_json = jsons.dumps(node_dict) + "\n"
                self.tempfile.write(node_json.encode())
                self.total_lines += 1
            elapsed_nodes = time() - start_time
            log.debug(f"Exported {self.number_of_nodes} nodes in {elapsed_nodes:.4f}s")
            if not self.found_replace_node:
                log.warning(f"No nodes of kind {self.graph_merge_kind.kind} found in graph")
            start_time = time()
            for edge in self.graph.edges:
                from_node = edge[0]
                to_node = edge[1]
                if not isinstance(from_node, BaseResource) or not isinstance(to_node, BaseResource):
                    log.error(f"One of {from_node} and {to_node} is no base resource")
                    continue
                edge_dict = {"from": from_node.chksum, "to": to_node.chksum}
                if len(edge) == 3:
                    key = edge[2]
                    if isinstance(key, EdgeKey) and key.edge_type != EdgeType.default:
                        edge_dict["edge_type"] = key.edge_type.value
                edge_json = json.dumps(edge_dict) + "\n"
                self.tempfile.write(edge_json.encode())
                self.total_lines += 1
            for from_selector, to_selector, edge_type in self.graph.deferred_edges:
                deferred_edge_dict = {}
                if isinstance(from_selector, ByNodeId):
                    deferred_edge_dict["from_selector"] = {"node_id": from_selector.value}
                else:
                    deferred_edge_dict["from_selector"] = {"search_criteria": from_selector.query}
                if isinstance(to_selector, ByNodeId):
                    deferred_edge_dict["to_selector"] = {"node_id": to_selector.value}
                else:
                    deferred_edge_dict["to_selector"] = {"search_criteria": to_selector.query}
                deferred_edge_dict["edge_type"] = edge_type.value
                deferred_edge_json = json.dumps(deferred_edge_dict) + "\n"
                self.tempfile.write(deferred_edge_json.encode())
                self.total_lines += 1
            elapsed_edges = time() - start_time
            log.debug(f"Exported {self.number_of_edges} edges in {elapsed_edges:.4f}s")
            elapsed = elapsed_nodes + elapsed_edges
            log.info(f"Exported {self.total_lines} nodes and edges in {elapsed:.4f}s")
            self.graph_exported = True
            del self.graph
            self.tempfile.seek(0)
