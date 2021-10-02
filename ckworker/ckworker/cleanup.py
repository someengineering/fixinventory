import requests
import json
from cklib.logging import log
from cklib.args import ArgumentParser
from cklib.graph import Graph, sanitize
from cklib.graph.export import node_from_dict
from cklib.jwt import encode_jwt_to_headers
from cklib.cleaner import Cleaner


def cleanup():
    """Run resource cleanup"""

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

    log.info("Running cleanup")
    base_uri = ArgumentParser.args.ckcore_uri.strip("/")
    ckcore_graph = ArgumentParser.args.ckcore_graph
    graph_uri = f"{base_uri}/graph/{ckcore_graph}"
    query_uri = f"{graph_uri}/query/graph"
    query_filter = ""
    if ArgumentParser.args.collector and len(ArgumentParser.args.collector) > 0:
        clouds = '["' + '", "'.join(ArgumentParser.args.collector) + '"]'
        query_filter = f"and metadata.ancestors.cloud.id in {clouds} "
    query = f"desired.clean == true {query_filter}<-[0:]->"
    log.debug(f"Sending query {query}")

    headers = {"accept": "application/x-ndjson"}
    if getattr(ArgumentParser.args, "psk", None):
        encode_jwt_to_headers(headers, {}, ArgumentParser.args.psk)

    r = requests.post(query_uri, data=query, headers=headers, stream=True)
    if r.status_code != 200:
        log.error(r.content)
        raise RuntimeError(f"Failed to query graph: {r.content}")
    graph = Graph()
    node_mapping = {}

    for line in r.iter_lines():
        if not line:
            continue
        data = json.loads(line.decode("utf-8"))
        try:
            process_data_line(data, graph)
        except ValueError as e:
            log.error(e)
            continue
    sanitize(graph)
    cleaner = Cleaner(graph)
    cleaner.cleanup()


def add_args(arg_parser: ArgumentParser) -> None:
    Cleaner.add_args(arg_parser)
