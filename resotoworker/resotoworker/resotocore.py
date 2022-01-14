import json
import requests
from resotolib.args import ArgumentParser
from resotolib.logging import log
from resotolib.jwt import encode_jwt_to_headers
from resotolib.graph import Graph, GraphExportIterator


def send_to_resotocore(graph: Graph):
    if not ArgumentParser.args.resotocore_uri:
        return

    log.info("resotocore Event Handler called")

    base_uri = ArgumentParser.args.resotocore_uri.strip("/")
    resotocore_graph = ArgumentParser.args.resotocore_graph
    dump_json = ArgumentParser.args.debug_dump_json

    create_graph(base_uri, resotocore_graph)
    update_model(graph, base_uri, dump_json=dump_json)
    send_graph(graph, base_uri, resotocore_graph, dump_json=dump_json)


def create_graph(resotocore_base_uri: str, resotocore_graph: str):
    graph_uri = f"{resotocore_base_uri}/graph/{resotocore_graph}"

    log.debug(f"Creating graph {resotocore_graph} via {graph_uri}")

    headers = {"accept": "application/json"}
    if getattr(ArgumentParser.args, "psk", None):
        encode_jwt_to_headers(headers, {}, ArgumentParser.args.psk)

    r = requests.post(graph_uri, data="", headers=headers)
    if r.status_code != 200:
        log.error(r.content)
        raise RuntimeError(f"Failed to create graph: {r.content}")


def update_model(graph: Graph, resotocore_base_uri: str, dump_json: bool = False):
    model_uri = f"{resotocore_base_uri}/model"

    log.debug(f"Updating model via {model_uri}")

    model_json = json.dumps(graph.export_model(), indent=4)
    if dump_json:
        with open("model.dump.json", "w") as model_outfile:
            model_outfile.write(model_json)

    headers = {}
    if getattr(ArgumentParser.args, "psk", None):
        encode_jwt_to_headers(headers, {}, ArgumentParser.args.psk)

    r = requests.patch(model_uri, data=model_json, headers=headers)
    if r.status_code != 200:
        log.error(r.content)
        raise RuntimeError(f"Failed to create model: {r.content}")


def send_graph(
    graph: Graph,
    resotocore_base_uri: str,
    resotocore_graph: str,
    dump_json: bool = False,
):
    merge_uri = f"{resotocore_base_uri}/graph/{resotocore_graph}/merge"

    log.debug(f"Sending graph via {merge_uri}")

    graph_outfile = None
    if dump_json:
        graph_outfile = open("graph.dump.json", "w")

    try:
        graph_export_iterator = GraphExportIterator(graph, graph_outfile)

        headers = {
            "Content-Type": "application/x-ndjson",
            "Resoto-Worker-Nodes": str(graph.number_of_nodes()),
            "Resoto-Worker-Edges": str(graph.number_of_edges()),
        }
        if getattr(ArgumentParser.args, "psk", None):
            encode_jwt_to_headers(headers, {}, ArgumentParser.args.psk)

        r = requests.post(
            merge_uri,
            data=graph_export_iterator,
            headers=headers,
        )
        if r.status_code != 200:
            log.error(r.content)
            raise RuntimeError(f"Failed to send graph: {r.content}")
        log.debug(f"resotocore reply: {r.content.decode()}")
        log.debug(
            f"Sent {graph_export_iterator.nodes_sent} nodes and"
            f" {graph_export_iterator.edges_sent} edges to resotocore"
        )
    finally:
        if graph_outfile is not None:
            graph_outfile.close()


def add_args(arg_parser: ArgumentParser) -> None:
    arg_parser.add_argument(
        "--debug-dump-json",
        help="Dump the generated json data (default: False)",
        dest="debug_dump_json",
        action="store_true",
    )
