import requests
import json
from urllib.parse import urlencode
from resotolib.config import Config
from resotolib.core import resotocore
from resotolib.graph import Graph, sanitize
from resotolib.core.model_export import node_from_dict, node_to_dict
from resotolib.core.ca import TLSData
from resotolib.baseresources import EdgeType
from resotolib.args import ArgumentParser
from resotolib.logger import log
from resotolib.jwt import encode_jwt_to_headers
from typing import Optional


class CoreGraph:
    def __init__(
        self,
        base_uri: str = None,
        graph: str = None,
        tls_data: Optional[TLSData] = None,
    ) -> None:
        if base_uri is None:
            self.base_uri = resotocore.http_uri
        else:
            self.base_uri = base_uri.strip("/")
        if graph is None:
            self.graph_name = Config.resotoworker.graph
        else:
            self.graph_name = graph
        self.verify = None
        if tls_data:
            self.verify = tls_data.ca_cert_path
        self.graph_uri = f"{self.base_uri}/graph/{self.graph_name}"
        self.search_uri = f"{self.graph_uri}/search/graph"

    def execute(self, command: str):
        log.debug(f"Executing command: {command}")
        headers = {"Accept": "application/x-ndjson", "Content-Type": "text/plain"}
        execute_endpoint = f"{self.base_uri}/cli/execute"
        if self.graph_name:
            query_string = urlencode({"graph": self.graph_name})
            execute_endpoint += f"?{query_string}"
        return self.post(execute_endpoint, command, headers, verify=self.verify)

    def search(self, search: str, edge_type: Optional[EdgeType] = None):
        log.debug(f"Sending search {search}")
        headers = {"Accept": "application/x-ndjson"}
        search_endpoint = self.search_uri
        if edge_type is not None:
            query_string = urlencode({"edge_type": edge_type.value})
            search_endpoint += f"?{query_string}"
        return self.post(search_endpoint, search, headers, verify=self.verify)

    @staticmethod
    def post(uri, data, headers, verify: Optional[str] = None):
        if getattr(ArgumentParser.args, "psk", None):
            encode_jwt_to_headers(headers, {}, ArgumentParser.args.psk)
        r = requests.post(uri, data=data, headers=headers, stream=True, verify=verify)
        if r.status_code != 200:
            log.error(r.content.decode())
            raise RuntimeError(f"Failed to search graph: {r.content.decode()}")
        for line in r.iter_lines():
            if not line:
                continue
            try:
                data = json.loads(line.decode("utf-8"))
                yield data
            except TypeError as e:
                log.error(e)
                continue

    def graph(self, search: str) -> Graph:
        def process_data_line(data: dict, graph: Graph):
            """Process a single line of resotocore graph data"""

            if data.get("type") == "node":
                node_id = data.get("id")
                node = node_from_dict(data)
                node_mapping[node_id] = node
                log.debug(f"Adding node {node} to the graph")
                graph.add_node(node)
                if node.kind == "graph_root":
                    log.debug(f"Setting graph root {node}")
                    graph.root = node
            elif data.get("type") == "edge":
                node_from = data.get("from")
                node_to = data.get("to")
                edge_type = EdgeType.from_value(data.get("edge_type"))
                if node_from not in node_mapping or node_to not in node_mapping:
                    raise ValueError(f"One of {node_from} -> {node_to} unknown")
                graph.add_edge(node_mapping[node_from], node_mapping[node_to], edge_type=edge_type)

        graph = Graph()
        node_mapping = {}
        for data in self.search(search):
            try:
                process_data_line(data, graph)
            except ValueError as e:
                log.error(e)
                continue
        sanitize(graph)
        return graph

    def patch_nodes(self, graph: Graph):
        headers = {"Content-Type": "application/x-ndjson"}
        if getattr(ArgumentParser.args, "psk", None):
            encode_jwt_to_headers(headers, {}, ArgumentParser.args.psk)

        r = requests.patch(
            f"{self.graph_uri}/nodes",
            data=GraphChangeIterator(graph),
            headers=headers,
            verify=self.verify,
        )
        if r.status_code != 200:
            err = r.content.decode("utf-8")
            log.error(err)
            raise RuntimeError(f"Failed to patch nodes: {err}")


class GraphChangeIterator:
    def __init__(self, graph: Graph):
        self.graph = graph

    def __iter__(self):
        for node in self.graph.nodes:
            if not node.changes.changed:
                continue
            node_dict = node_to_dict(node, changes_only=True)
            node_json = json.dumps(node_dict) + "\n"
            log.debug(f"Updating node {node_dict}")
            yield node_json.encode()
