import requests
import json
from urllib.parse import urlencode
from cklib.graph import Graph, sanitize
from cklib.graph.export import node_from_dict, node_to_dict
from cklib.args import ArgumentParser
from cklib.logging import log
from cklib.jwt import encode_jwt_to_headers


class CoreGraph:
    def __init__(self, base_uri: str = None, graph: str = None) -> None:
        if base_uri is None:
            self.base_uri = ArgumentParser.args.ckcore_uri.strip("/")
        else:
            self.base_uri = base_uri.strip("/")
        if graph is None:
            self.graph_name = ArgumentParser.args.ckcore_graph
        else:
            self.graph_name = graph
        self.graph_uri = f"{self.base_uri}/graph/{self.graph_name}"
        self.query_uri = f"{self.graph_uri}/query/graph"

    def execute(self, command: str):
        log.debug(f"Executing command {command}")
        headers = {"Accept": "application/x-ndjson", "Content-Type": "text/plain"}
        execute_endpoint = f"{self.base_uri}/cli/execute"
        if self.graph_name:
            query_string = urlencode({"graph": self.graph_name})
            execute_endpoint += f"?{query_string}"
        return self.post(execute_endpoint, command, headers)

    def query(self, query: str):
        log.debug(f"Sending query {query}")
        headers = {"Accept": "application/x-ndjson"}
        return self.post(self.query_uri, query, headers)

    @staticmethod
    def post(uri, data, headers):
        if getattr(ArgumentParser.args, "psk", None):
            encode_jwt_to_headers(headers, {}, ArgumentParser.args.psk)
        r = requests.post(uri, data=data, headers=headers, stream=True)
        if r.status_code != 200:
            log.error(r.content.decode())
            raise RuntimeError(f"Failed to query graph: {r.content.decode()}")
        for line in r.iter_lines():
            if not line:
                continue
            try:
                data = json.loads(line.decode("utf-8"))
                yield data
            except TypeError as e:
                log.error(e)
                continue

    def graph(self, query: str) -> Graph:
        def process_data_line(data: dict, graph: Graph):
            """Process a single line of ckcore graph data"""

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
                if node_from not in node_mapping or node_to not in node_mapping:
                    raise ValueError(f"One of {node_from} -> {node_to} unknown")
                graph.add_edge(node_mapping[node_from], node_mapping[node_to])

        graph = Graph()
        node_mapping = {}
        for data in self.query(query):
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
            f"{self.graph_uri}/nodes", data=GraphChangeIterator(graph), headers=headers
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
