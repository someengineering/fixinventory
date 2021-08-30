from __future__ import annotations
import networkx
import threading
import pickle
import json
import re
import cloudkeeper.logging
from cloudkeeper.baseresources import GraphRoot, Cloud, BaseResource
from cloudkeeper.utils import RWLock, json_default, get_resource_attributes
from cloudkeeper.args import ArgumentParser
from cloudkeeper.metrics import graph2metrics
from cloudkeeper.graph.export import (
    get_node_attributes,
    dataclasses_to_keepercore_model,
)
from cloudkeeper.event import (
    Event,
    EventType,
    add_event_listener,
    remove_event_listener,
)
from prometheus_client import Summary
from typing import Dict, List, IO, Optional
from io import BytesIO
from dataclasses import fields
from typeguard import check_type
from time import time

log = cloudkeeper.logging.getLogger(__name__)

metrics_graph_search = Summary(
    "cloudkeeper_graph_search_seconds", "Time it took the Graph search() method"
)
metrics_graph_searchall = Summary(
    "cloudkeeper_graph_searchall_seconds", "Time it took the Graph searchall() method"
)
metrics_graph_searchre = Summary(
    "cloudkeeper_graph_searchre_seconds", "Time it took the Graph searchre() method"
)
metrics_graph_search_first = Summary(
    "cloudkeeper_graph_search_first_seconds",
    "Time it took the Graph search_first() method",
)
metrics_graph_search_first_all = Summary(
    "cloudkeeper_graph_search_first_all_seconds",
    "Time it took the Graph search_first_all() method",
)
metrics_graph_search_first_parent_class = Summary(
    "cloudkeeper_graph_search_first_parent_seconds",
    "Time it took the Graph search_first_parent_class() method",
)
metrics_graph_resolve_deferred_connections = Summary(
    "cloudkeeper_graph_resolve_deferred_connections",
    "Time it took the Graph resolve_deferred_connections() method",
)
metrics_graphcache_update_cache = Summary(
    "cloudkeeper_graphcache_update_cache_seconds",
    "Time it took the GraphCache update_cache() method",
)
metrics_graph2json = Summary(
    "cloudkeeper_graph2json_seconds", "Time it took the graph2json() method"
)
metrics_graph2text = Summary(
    "cloudkeeper_graph2text_seconds", "Time it took the graph2text() method"
)
metrics_graph2graphml = Summary(
    "cloudkeeper_graph2graphml_seconds", "Time it took the graph2graphml() method"
)
metrics_graph2pickle = Summary(
    "cloudkeeper_graph2pickle_seconds", "Time it took the graph2pickle() method"
)
metrics_graph2gexf = Summary(
    "cloudkeeper_graph2gexf_seconds", "Time it took the graph2gexf() method"
)
metrics_graph2pajek = Summary(
    "cloudkeeper_graph2pajek_seconds", "Time it took the graph2pajek() method"
)


class Graph(networkx.DiGraph):
    """A directed Graph"""

    def __init__(self, *args, root: BaseResource = None, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.lock = RWLock()
        self.root = None
        if isinstance(root, BaseResource):
            self.root = root
            self.add_node(
                self.root, label=self.root.name, **get_resource_attributes(self.root)
            )

    def merge(self, graph: networkx.DiGraph):
        """Merge another graph into ourselves

        If the other graph has a graph.root an edge will be created between
        it and our own graph root.
        """
        self.update(graph)
        if isinstance(self.root, BaseResource) and isinstance(
            getattr(graph, "root", None), BaseResource
        ):
            log.debug(
                (
                    f"Merging graph of {graph.root.rtdname}"
                    f" into graph of {self.root.rtdname}"
                )
            )
            self.add_edge(self.root, graph.root)
        else:
            log.warning("Merging graphs with no valid roots")

    def add_resource(self, parent, node_for_adding, **attr):
        """Add a resource node to the graph

        When adding resource nodes to the graph there's always a label and a
        resource_type as well as an edge connecting the new resource with its parent
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

        self.add_node(
            node_for_adding, label=node_for_adding.name, **resource_attr, **attr
        )
        self.add_edge(parent, node_for_adding)

    def add_node(self, node_for_adding, **attr):
        with self.lock.write_access:
            super().add_node(node_for_adding, **attr)
        if isinstance(node_for_adding, BaseResource):
            # We hand a reference to ourselve to the added BaseResource
            # which stores it as a weakref.
            node_for_adding._graph = self

    def add_edge(self, src, dst, **attr):
        if src is None or dst is None:
            log.error(f"Not creating edge from or to NoneType: {src} to {dst}")
            return
        if self.has_edge(src, dst):
            log.error(f"Edge from {src} to {dst} already exists in graph")
            return
        with self.lock.write_access:
            super().add_edge(src, dst, **attr)
        if isinstance(src, BaseResource) and isinstance(dst, BaseResource):
            log.debug(f"Added edge from {src.rtdname} to {dst.rtdname}")
            try:
                src.successor_added(dst, self)
            except Exception:
                log.exception(
                    (
                        f"Unhandeled exception while telling {src.rtdname}"
                        f" that {dst.rtdname} was added as a successor"
                    )
                )
            try:
                dst.predecessor_added(src, self)
            except Exception:
                log.exception(
                    (
                        f"Unhandeled exception while telling {dst.rtdname}"
                        f" that {src.rtdname} was added as a predecessor"
                    )
                )

    def remove_node(self, *args, **kwargs):
        with self.lock.write_access:
            super().remove_node(*args, **kwargs)

    def remove_edge(self, *args, **kwargs):
        with self.lock.write_access:
            super().remove_edge(*args, **kwargs)

    @metrics_graph_search.time()
    def search(self, attr, value, regex_search=False):
        """Search for graph nodes by their attribute value"""
        if value is None:
            log.debug(
                f"Not searching graph for nodes with attribute values {attr}: {value}"
            )
            return ()
        log.debug(
            (
                f"Searching graph for nodes with attribute values {attr}: {value}"
                f" (regex: {regex_search})"
            )
        )
        with self.lock.read_access:
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
        log.debug(
            f"Regex searching graph for nodes with attribute values {attr}: {regex}"
        )
        return self.search(attr, regex, regex_search=True)

    @metrics_graph_searchall.time()
    def searchall(self, match: Dict):
        """Search for graph nodes by multiple attributes and values"""
        with self.lock.read_access:
            return (
                node
                for node in self.nodes()
                if all(
                    getattr(node, attr, None) == value for attr, value in match.items()
                )
            )

    @metrics_graph_search_first.time()
    def search_first(self, attr, value):
        """Return the first graph node that matches a certain attribute value"""
        with self.lock.read_access:
            node = next(iter(self.search(attr, value)), None)
        if node:
            log.debug(f"Found node {node} with {attr}: {value}")
        else:
            log.debug(f"Found no node with {attr}: {value}")
        return node

    @metrics_graph_search_first_all.time()
    def search_first_all(self, match: Dict):
        """Return the first graph node that matches multiple attributes and values"""
        with self.lock.read_access:
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
        ret = None
        try:
            for predecessor_node in list(self.predecessors(node)):
                if isinstance(predecessor_node, cls):
                    ret = predecessor_node
                else:
                    ret = self.search_first_parent_class(predecessor_node, cls)
                if ret:
                    break
        except RecursionError:
            log.exception(
                f"Recursive search error triggered for node {node}'s parent class {cls}"
            )
        return ret

    @metrics_graph_resolve_deferred_connections.time()
    def resolve_deferred_connections(self):
        log.debug("Resolving deferred graph connections")
        for node in self.nodes:
            node.resolve_deferred_connections(self)

    def export_model(self) -> List:
        """Return the graph node dataclass model in keepercore format"""
        classes = set()
        with self.lock.read_access:
            for node in self.nodes:
                classes.add(type(node))
        model = dataclasses_to_keepercore_model(classes)

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

    # We can't pickle a Lock() so we're removing it before pickling
    # and recreating a fresh instance when unpickling
    def __getstate__(self):
        d = self.__dict__.copy()
        if "lock" in d:
            del d["lock"]
        return d

    def __setstate__(self, d):
        d["lock"] = RWLock()
        self.__dict__.update(d)


class GraphContainer:
    """A context containing a Graph()

    This can be passed to various code parts like e.g. a WebServer() allowing
    replacement and updating of the graph without losing its context.
    """

    GRAPH_ROOT = GraphRoot("root", {})

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

    @property
    def metrics(self):
        if self.cache and self.cache.metrics:
            return self.cache.metrics
        else:
            return graph2metrics(self.graph)


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
        self._metrics_cache = None

    @metrics_graphcache_update_cache.time()
    def update_cache(self, event: Event) -> None:
        log.debug("Updating the Graph Cache")
        graph = event.data
        log.debug("Generating metrics cache")
        self._metrics_cache = graph2metrics(graph)
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
        yield f"Node: {node.name} (type: {node.resource_type})"
        for predecessor_node in graph.predecessors(node):
            yield (
                f"\tParent: {predecessor_node.name}"
                f" (type: {predecessor_node.resource_type})"
            )
        for successor_node in graph.successors(node):
            yield (
                f"\tChild {successor_node.name} (type: {successor_node.resource_type})"
            )


@metrics_graph2json.time()
def graph2json(graph):
    return (
        json.dumps(networkx.node_link_data(graph), default=json_default, skipkeys=True)
        + "\n"
    )


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
    for field in fields(node):
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
    node_sha256s = {}
    for node in graph.nodes:
        if isinstance(node, BaseResource):
            validate_dataclass(node)
            if node.sha256 not in node_sha256s:
                node_sha256s[node.sha256] = node
            else:
                log.error(
                    f"Duplicate checksum {node.sha256} for node {node.rtdname} in graph"
                )


def update_graph_ref(graph: Graph) -> None:
    for node in graph.nodes:
        if isinstance(node, BaseResource):
            node._graph = graph


def set_max_depth(graph: Graph, node: BaseResource, current_depth: int = 0) -> None:
    if isinstance(node, BaseResource):
        if current_depth > node.max_graph_depth:
            node.max_graph_depth = current_depth

    for child_node in node.successors(graph):
        set_max_depth(graph, child_node, current_depth + 1)


def sanitize(graph: Graph, root: GraphRoot = None) -> None:
    log.debug("Sanitizing Graph")
    plugin_roots = {}
    graph_roots = []

    if root is None and isinstance(getattr(graph, "root", None), BaseResource):
        root = graph.root

    if root is None:
        log.error("No graph root found - unable to sanitize")
        return

    for node in graph.successors(root):
        if isinstance(node, Cloud):
            log.debug(f"Found Plugin Root {node.id}")
            plugin_roots[node.id] = node
        elif isinstance(node, GraphRoot):
            log.debug(f"Found Graph Root {node.id}")
            graph_roots.append(node)
        else:
            log.error(f"Found unknown node {node.id} of type {node.resource_type}")

    if len(graph_roots) > 0:
        for graph_root in graph_roots:
            log.debug(f"Moving children of graph root {graph_root.id}")
            for node in list(graph.successors(graph_root)):
                if isinstance(node, Cloud):
                    if node.id in plugin_roots:
                        log.debug(
                            f"Found existing plugin root {node.id}"
                            " - attaching children and removing plugin root"
                        )
                        for plugin_root_child in list(graph.successors(node)):
                            log.debug(
                                f"Found node {plugin_root_child.id} of type "
                                f"{plugin_root_child.resource_type}"
                                " - attaching to existing plugin root"
                            )
                            graph.add_edge(plugin_roots[node.id], plugin_root_child)
                            graph.remove_edge(node, plugin_root_child)
                        graph.remove_node(node)
                    else:
                        log.debug(
                            f"Found new plugin root {node.id}"
                            " - attaching to top level root"
                        )
                        graph.add_edge(root, node)
                        graph.remove_edge(graph_root, node)
                else:
                    log.debug(
                        f"Found unknown node {node.id} of type {node.resource_type}"
                        " - attaching to top level root"
                    )
                    graph.add_edge(root, node)
                    graph.remove_edge(graph_root, node)
            log.debug(f"Removing graph root {graph_root.id}")
            graph.remove_node(graph_root)
    graph.resolve_deferred_connections()
    update_graph_ref(graph)
    set_max_depth(graph, root)
    validate_graph_dataclasses_and_nodes(graph)


class GraphExportIterator:
    def __init__(self, graph: Graph, output: Optional[IO] = None):
        self.graph = graph
        self.nodes_sent = 0
        self.edges_sent = 0
        report_every_percent = 10
        self.nodes_total = self.graph.number_of_nodes()
        self.edges_total = self.graph.number_of_edges()
        self.report_every_n_nodes = round(self.nodes_total / report_every_percent)
        self.report_every_n_edges = round(self.edges_total / report_every_percent)
        self.last_sent = time()
        self.output = output
        if self.output is not None:
            log.debug(f"Writing graph json to file {self.output}")

    def __iter__(self):
        with self.graph.lock.read_access:
            for node in self.graph.nodes:
                node_attributes = get_node_attributes(node)
                node_json = {"id": node.sha256, "data": node_attributes}
                if getattr(node, "_merge", None):
                    log.debug(f"Merging graph above {node.rtdname}")
                    node_json.update({"merge": True})
                attributes_json = json.dumps(node_json) + "\n"
                self.nodes_sent += 1
                if self.nodes_sent % self.report_every_n_nodes == 0:
                    percent = round(self.nodes_sent / self.nodes_total * 100)
                    elapsed = time() - self.last_sent
                    log.debug(
                        f"Sent {self.nodes_sent} nodes ({percent}%) - {elapsed:.4f}s"
                    )
                    self.last_sent = time()
                if self.output is not None:
                    self.output.write(attributes_json)
                yield attributes_json.encode()
            for edge in self.graph.edges:
                from_node = edge[0]
                to_node = edge[1]
                if not isinstance(from_node, BaseResource) or not isinstance(
                    to_node, BaseResource
                ):
                    log.error(f"One of {from_node} and {to_node} is no base resource")
                    continue
                link = {"from": from_node.sha256, "to": to_node.sha256}
                link_json = json.dumps(link) + "\n"
                self.edges_sent += 1
                if self.edges_sent % self.report_every_n_edges == 0:
                    percent = round(self.edges_sent / self.edges_total * 100)
                    elapsed = time() - self.last_sent
                    log.debug(
                        f"Sent {self.edges_sent} edges ({percent}%) - {elapsed:.4f}s"
                    )
                    self.last_sent = time()
                if self.output is not None:
                    self.output.write(link_json)
                yield link_json.encode()
