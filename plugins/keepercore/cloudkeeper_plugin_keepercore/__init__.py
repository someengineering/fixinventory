from typing import List, Dict, Union
from cloudkeeper.baseresources import BaseResource
import cloudkeeper.logging
import threading
from .datamodel_export import dataclasses_to_keepercore_model
from cloudkeeper.baseplugin import BasePlugin
from cloudkeeper.graph import Graph
from cloudkeeper.args import ArgumentParser
from cloudkeeper.event import (
    Event,
    EventType,
    add_event_listener,
    remove_event_listener,
)
from datetime import date, datetime, timezone, timedelta
import requests
import json

log = cloudkeeper.logging.getLogger("cloudkeeper." + __name__)


class KeepercorePlugin(BasePlugin):
    def __init__(self):
        super().__init__()
        self.name = "keepercore"
        self.exit = threading.Event()
        add_event_listener(EventType.SHUTDOWN, self.shutdown)

        if ArgumentParser.args.keepercore_uri:
            add_event_listener(
                EventType.COLLECT_FINISH, self.keepercore_event_handler, blocking=False
            )

    def __del__(self):
        if ArgumentParser.args.keepercore_uri:
            remove_event_listener(
                EventType.COLLECT_FINISH, self.keepercore_event_handler
            )
        remove_event_listener(EventType.SHUTDOWN, self.shutdown)

    def go(self):
        if ArgumentParser.args.keepercore_uri:
            self.exit.wait()

    @staticmethod
    def keepercore_event_handler(event: Event):
        if not ArgumentParser.args.keepercore_uri:
            return

        log.warn("LATEST CODE 123")
        graph: Graph = event.data
        log.info("Keepercore Event Handler called")
        model = get_model_from_graph(graph)
        base_uri = ArgumentParser.args.keepercore_uri.strip("/")
        keepercore_graph = ArgumentParser.args.keepercore_graph
        model_uri = f"{base_uri}/model"
        graph_uri = f"{base_uri}/graph/{keepercore_graph}"
        report_uri = f"{graph_uri}/reported/sub_graph/root"
        log.debug(f"Creating graph {keepercore_graph} via {graph_uri}")
        r = requests.post(graph_uri, data="", headers={"accept": "application/json"})
        if r.status_code != 200:
            log.error(r.content)
        log.debug(f"Updating model via {model_uri}")
        model_json = json.dumps(model, indent=4)
        print(model_json)
        r = requests.patch(model_uri, data=model_json)
        if r.status_code != 200:
            log.error(r.content)

        return
        graph_iterator = GraphIterator(graph)
        log.debug(f"Sending subgraph via {report_uri}")
        r = requests.put(
            report_uri,
            data=graph_iterator,
            headers={"Content-Type": "application/x-ndjson"},
        )
        log.debug(r.content.decode())
        log.debug(
            f"Sent {graph_iterator.nodes_sent} nodes and {graph_iterator.edges_sent} edges to keepercore"
        )

    @staticmethod
    def add_args(arg_parser: ArgumentParser) -> None:
        arg_parser.add_argument(
            "--keepercore-uri",
            help="Keepercore URI",
            default=None,
            dest="keepercore_uri",
        )
        arg_parser.add_argument(
            "--keepercore-graph",
            help="Keepercore graph name",
            default="ck",
            dest="keepercore_graph",
        )

    def shutdown(self, event: Event):
        log.debug(
            f"Received event {event.event_type} - shutting down keepercore plugin"
        )
        self.exit.set()


def get_model_from_graph(graph: Graph) -> List:
    classes = []
    with graph.lock.read_access:
        for node in graph.nodes:
            cls = type(node)
            if cls not in classes:
                classes.append(cls)
    model = dataclasses_to_keepercore_model(classes)
    return model


def get_node_attributes(node: BaseResource) -> Dict:
    return {}


class GraphIterator:
    def __init__(self, graph: Graph):
        self.graph = graph
        self.nodes_sent = 0
        self.edges_sent = 0

    def __iter__(self):
        with self.graph.lock.read_access:
            for node in self.graph.nodes:
                node_attributes = get_node_attributes(node)
                node_id = node.sha256
                node_json = {"id": node_id, "data": node_attributes}
                attributes_json = json.dumps(node_json) + "\n"
                self.nodes_sent += 1
                yield (attributes_json.encode())
            for node in self.graph.nodes:
                for successor in node.successors(self.graph):
                    successor_id = successor.sha256
                    link = {"from": node_id, "to": successor_id}
                    link_json = json.dumps(link) + "\n"
                    self.edges_sent += 1
                    yield (link_json.encode())
