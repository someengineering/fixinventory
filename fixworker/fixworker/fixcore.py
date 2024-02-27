import json
import requests
import tempfile
from datetime import datetime
from fixlib.args import ArgumentParser
from fixlib.logger import log
from fixlib.jwt import encode_jwt_to_headers
from fixlib.graph import Graph, GraphExportIterator, export_model
from fixlib.config import Config
from fixlib.core import fixcore
from typing import Callable, Optional
from tenacity import Retrying
from tenacity.stop import stop_after_attempt
from tenacity.wait import wait_fixed


class FixCore:
    def __init__(
        self,
        send_request: Callable[[requests.Request], requests.Response],
        config: Config,
    ) -> None:
        self._send_request = send_request
        self._config = config

    def create_graph_and_update_model(self, tempdir: str) -> None:
        base_uri = fixcore.http_uri
        fixcore_graph = self._config.fixworker.graph
        dump_json = self._config.fixworker.debug_dump_json
        self.create_graph(base_uri, fixcore_graph)
        self.update_model(base_uri, fixcore_graph, dump_json=dump_json, tempdir=tempdir)

    def send_to_fixcore(self, graph: Graph, task_id: str, tempdir: str) -> None:
        if not ArgumentParser.args.fixcore_uri:
            return None

        base_uri = fixcore.http_uri
        fixcore_graph = self._config.fixworker.graph
        dump_json = self._config.fixworker.debug_dump_json
        graph_merge_kind = self._config.fixworker.graph_merge_kind

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
            log.error("No replace node found, not sending graph to fixcore")
            return
        self.send_graph(graph_export_iterator, base_uri, fixcore_graph, task_id)

    def create_graph(self, fixcore_base_uri: str, fixcore_graph: str) -> None:
        graph_uri = f"{fixcore_base_uri}/graph/{fixcore_graph}"

        log.debug(f"Creating graph {fixcore_graph} via {graph_uri}")

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
        fixcore_base_uri: str,
        fixcore_graph: str,
        dump_json: bool = False,
        tempdir: Optional[str] = None,
    ) -> None:
        model_uri = f"{fixcore_base_uri}/graph/{fixcore_graph}/model"

        log.debug(f"Updating model via {model_uri}")

        model_json = json.dumps(export_model(), indent=4)

        if dump_json:
            ts = datetime.now().strftime("%Y-%m-%d-%H-%M")
            with tempfile.NamedTemporaryFile(
                prefix=f"fix-model-{ts}-",
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
                request = requests.Request(method="PUT", url=model_uri, data=model_json, headers=headers)
                r = self._send_request(request)
                if r.status_code != 200:
                    log.error(r.content)
                    raise RuntimeError(f"Failed to create model: {r.content}")  # type: ignore

    def send_graph(
        self,
        graph_export_iterator: GraphExportIterator,
        fixcore_base_uri: str,
        fixcore_graph: str,
        task_id: str,
    ) -> None:
        merge_uri = f"{fixcore_base_uri}/graph/{fixcore_graph}/merge"

        log.debug(f"Sending graph via {merge_uri}")

        headers = {
            "Content-Type": "application/x-ndjson",
            "Fix-Worker-Nodes": str(graph_export_iterator.number_of_nodes),
            "Fix-Worker-Edges": str(graph_export_iterator.number_of_edges),
            "Fix-Worker-Task-Id": task_id,
        }
        params = dict(wait_for_result=False)
        if getattr(ArgumentParser.args, "psk", None):
            encode_jwt_to_headers(headers, {}, ArgumentParser.args.psk)

        for attempt in Retrying(reraise=True, stop=stop_after_attempt(3), wait=wait_fixed(10)):
            with attempt:
                request = requests.Request(
                    method="POST", url=merge_uri, data=graph_export_iterator, params=params, headers=headers
                )
                r = self._send_request(request)
                if r.status_code not in (200, 204):
                    log.error(r.content)
                    raise RuntimeError(f"Failed to send graph: {r.content}")  # type: ignore
        log.debug(f"Sent {graph_export_iterator.total_lines} items to fixcore")
