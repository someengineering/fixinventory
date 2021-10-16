import cklib.logging
import threading
from cklib.baseplugin import BasePlugin
from cklib.graph import Graph
from cklib.args import ArgumentParser
from cklib.event import (
    Event,
    EventType,
    add_event_listener,
    remove_event_listener,
)
import requests
import json

log = cklib.logging.getLogger("cloudkeeper." + __name__)


class CkCorePlugin(BasePlugin):
    def __init__(self):
        super().__init__()
        self.name = "ckcore"
        self.exit = threading.Event()
        add_event_listener(EventType.SHUTDOWN, self.shutdown)

        if ArgumentParser.args.ckcore_uri:
            add_event_listener(
                EventType.COLLECT_FINISH, self.ckcore_event_handler, blocking=False
            )

    def __del__(self):
        if ArgumentParser.args.ckcore_uri:
            remove_event_listener(EventType.COLLECT_FINISH, self.ckcore_event_handler)
        remove_event_listener(EventType.SHUTDOWN, self.shutdown)

    def go(self):
        if ArgumentParser.args.ckcore_uri:
            self.exit.wait()

    @staticmethod
    def ckcore_event_handler(event: Event):
        if not ArgumentParser.args.ckcore_uri:
            return

        graph: Graph = event.data
        log.info("ckcore Event Handler called")
        base_uri = ArgumentParser.args.ckcore_uri.strip("/")
        ckcore_graph = ArgumentParser.args.ckcore_graph
        model_uri = f"{base_uri}/model"
        graph_uri = f"{base_uri}/graph/{ckcore_graph}"
        report_uri = f"{graph_uri}/reported/sub_graph/root"
        log.debug(f"Creating graph {ckcore_graph} via {graph_uri}")
        r = requests.post(graph_uri, data="", headers={"accept": "application/json"})
        if r.status_code != 200:
            log.error(r.content)
        log.debug(f"Updating model via {model_uri}")
        model_json = json.dumps(graph.export_model(), indent=4)
        r = requests.patch(model_uri, data=model_json)
        if r.status_code != 200:
            log.error(r.content)

        graph_export_iterator = graph.export_iterator()
        log.debug(f"Sending subgraph via {report_uri}")
        r = requests.put(
            report_uri,
            data=graph.export_iterator(),
            headers={"Content-Type": "application/x-ndjson"},
        )
        log.debug(r.content.decode())
        log.debug(
            f"Sent {graph_export_iterator.nodes_sent} nodes and {graph_export_iterator.edges_sent} edges to ckcore"
        )

    @staticmethod
    def add_args(arg_parser: ArgumentParser) -> None:
        arg_parser.add_argument(
            "--ckcore-uri",
            help="ckcore URI",
            default=None,
            dest="ckcore_uri",
        )
        arg_parser.add_argument(
            "--ckcore-graph",
            help="ckcore graph name",
            default="ck",
            dest="ckcore_graph",
        )

    def shutdown(self, event: Event):
        log.debug(f"Received event {event.event_type} - shutting down ckcore plugin")
        self.exit.set()
