import json
import requests
import tempfile
from datetime import datetime
from resotolib.args import ArgumentParser
from resotolib.logger import log
from resotolib.jwt import encode_jwt_to_headers
from resotolib.graph import Graph, GraphExportIterator
from resotolib.config import Config
from resotolib.core import resotocore
from typing import Callable, Optional
from tenacity import Retrying
from tenacity.stop import stop_after_attempt
from tenacity.wait import wait_fixed


class Resotocore:
    def __init__(
        self,
        send_request: Callable[[requests.Request], requests.Response],
        config: Config,
    ) -> None:
        self._send_request = send_request
        self._config = config

    def send_to_resotocore(self, graph: Graph, task_id: str) -> None:
        if not ArgumentParser.args.resotocore_uri:
            return None

        log.info("resotocore Event Handler called")

        base_uri = resotocore.http_uri
        resotocore_graph = self._config.resotoworker.graph
        dump_json = self._config.resotoworker.debug_dump_json
        tempdir = self._config.resotoworker.tempdir
        graph_merge_kind = self._config.resotoworker.graph_merge_kind

        self.create_graph(base_uri, resotocore_graph)
        self.update_model(graph, base_uri, dump_json=dump_json, tempdir=tempdir)

        graph_export_iterator = GraphExportIterator(
            graph,
            delete_tempfile=not dump_json,
            tempdir=tempdir,
            graph_merge_kind=graph_merge_kind,
        )
        #  The graph is not required any longer and can be released.
        del graph
        graph_export_iterator.export_graph()
        if not graph_export_iterator.found_replace_node:
            log.error("No replace node found, not sending graph to resotocore")
            return
        self.send_graph(graph_export_iterator, base_uri, resotocore_graph, task_id)

    def create_graph(self, resotocore_base_uri: str, resotocore_graph: str) -> None:
        graph_uri = f"{resotocore_base_uri}/graph/{resotocore_graph}"

        log.debug(f"Creating graph {resotocore_graph} via {graph_uri}")

        headers = {
            "accept": "application/json",
            "Content-Type": "application/json",
        }
        if getattr(ArgumentParser.args, "psk", None):
            encode_jwt_to_headers(headers, {}, ArgumentParser.args.psk)

        for attempt in Retrying(reraise=True, stop=stop_after_attempt(3), wait=wait_fixed(10)):
            with attempt:
                request = requests.Request(method="POST", url=graph_uri, data="", headers=headers)
                r = self._send_request(request)
                if r.status_code != 200:
                    log.error(r.content)
                    raise RuntimeError(f"Failed to create graph: {r.content}")  # type: ignore

    def update_model(
        self,
        graph: Graph,
        resotocore_base_uri: str,
        dump_json: bool = False,
        tempdir: Optional[str] = None,
    ) -> None:
        model_uri = f"{resotocore_base_uri}/model"

        log.debug(f"Updating model via {model_uri}")

        model_json = json.dumps(graph.export_model(), indent=4)

        if dump_json:
            ts = datetime.now().strftime("%Y-%m-%d-%H-%M")
            with tempfile.NamedTemporaryFile(
                prefix=f"resoto-model-{ts}-",
                suffix=".json",
                delete=not dump_json,
                dir=tempdir,
            ) as model_outfile:
                log.info(f"Writing model json to file {model_outfile.name}")
                model_outfile.write(model_json.encode())

        headers = {"Content-Type": "application/json"}
        if getattr(ArgumentParser.args, "psk", None):
            encode_jwt_to_headers(headers, {}, ArgumentParser.args.psk)

        for attempt in Retrying(reraise=True, stop=stop_after_attempt(3), wait=wait_fixed(10)):
            with attempt:
                request = requests.Request(method="PATCH", url=model_uri, data=model_json, headers=headers)
                r = self._send_request(request)
                if r.status_code != 200:
                    log.error(r.content)
                    raise RuntimeError(f"Failed to create model: {r.content}")  # type: ignore

    def send_graph(
        self,
        graph_export_iterator: GraphExportIterator,
        resotocore_base_uri: str,
        resotocore_graph: str,
        task_id: str,
    ) -> None:
        merge_uri = f"{resotocore_base_uri}/graph/{resotocore_graph}/merge"

        log.debug(f"Sending graph via {merge_uri}")

        headers = {
            "Content-Type": "application/x-ndjson",
            "Resoto-Worker-Nodes": str(graph_export_iterator.number_of_nodes),
            "Resoto-Worker-Edges": str(graph_export_iterator.number_of_edges),
            "Resoto-Worker-Task-Id": task_id,
        }
        if getattr(ArgumentParser.args, "psk", None):
            encode_jwt_to_headers(headers, {}, ArgumentParser.args.psk)

        for attempt in Retrying(reraise=True, stop=stop_after_attempt(3), wait=wait_fixed(10)):
            with attempt:
                request = requests.Request(method="POST", url=merge_uri, data=graph_export_iterator, headers=headers)
                r = self._send_request(request)
                if r.status_code != 200:
                    log.error(r.content)
                    raise RuntimeError(f"Failed to send graph: {r.content}")  # type: ignore
                log.debug(f"resotocore reply: {r.content.decode()}")
        log.debug(f"Sent {graph_export_iterator.total_lines} items to resotocore")
