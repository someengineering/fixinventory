import graph_exporter.logging
import sys
import requests
import json
import time
from prometheus_client import Summary, start_http_server, REGISTRY
from prometheus_client.core import GaugeMetricFamily
from threading import Event
from graph_exporter.args import get_arg_parser, ArgumentParser
from typing import Dict, Iterator
from signal import signal, SIGTERM, SIGINT


log = graph_exporter.logging.getLogger(__name__)
shutdown_event = Event()

metrics_update_metrics = Summary(
    "graph_exporter_update_metrics_seconds",
    "Time it took the update_metrics() function",
)


def handler(sig, frame) -> None:
    log.info("Shutting down")
    shutdown_event.set()


def main() -> None:
    signal(SIGINT, handler)
    signal(SIGTERM, handler)

    arg_parser = get_arg_parser()
    add_args(arg_parser)
    arg_parser.parse_args()

    metrics = {}
    graph_collector = GraphCollector(metrics)
    REGISTRY.register(graph_collector)

    base_uri = ArgumentParser.args.keepercore_uri.strip("/")
    keepercore_graph = ArgumentParser.args.keepercore_graph
    graph_uri = f"{base_uri}/graph/{keepercore_graph}"
    query_uri = f"{graph_uri}/query/aggregate"

    start_http_server(ArgumentParser.args.web_port)
    while not shutdown_event.is_set():
        try:
            update_metrics(metrics, query_uri)
        except Exception as e:
            log.error(e)
            time.sleep(10)
            continue
        shutdown_event.wait(900)
    shutdown_event.wait()
    sys.exit(0)


def query(query: str, query_uri: str) -> Iterator:
    r = requests.post(
        query_uri, data=query, headers={"accept": "application/x-ndjson"}, stream=True
    )
    if r.status_code != 200:
        log.error(r.content)
        raise RuntimeError(f"Failed to query graph: {r.content}")

    for line in r.iter_lines():
        if not line:
            continue

        data = json.loads(line.decode("utf-8"))
        yield data


@metrics_update_metrics.time()
def update_metrics(metrics: Dict, query_uri: str) -> None:
    
    metric = "test"
    labels = ("foo", "bar")
    help_text = "Some test metric"
    value = 10.0
    metrics[metric] = GaugeMetricFamily(
        f"cloudkeeper_{metric}",
        help_text,
        labels=labels,
    )
    metrics[metric].add_metric(labels, value)


def add_args(arg_parser: ArgumentParser) -> None:
    arg_parser.add_argument(
        "--web-port",
        help="TCP port to listen on",
        default=9855,
        type=int,
        dest="web_port",
    )
    arg_parser.add_argument(
        "--keepercore-uri",
        help="Keepercore URI",
        default="http://localhost:8080",
        dest="keepercore_uri",
    )
    arg_parser.add_argument(
        "--keepercore-ws-uri",
        help="Keepercore Websocket URI",
        default="ws://localhost:8080",
        dest="keepercore_ws_uri",
    )
    arg_parser.add_argument(
        "--keepercore-graph",
        help="Keepercore graph name",
        default="ck",
        dest="keepercore_graph",
    )


class GraphCollector:
    """A Prometheus compatible Collector implementation"""

    def __init__(self, metrics: Dict) -> None:
        self.metrics = metrics

    def collect(self):
        """collect() is being called whenever the /metrics endpoint is requested"""
        log.debug("GraphCollector generating metrics")

        for metric in self.metrics.values():
            yield metric


if __name__ == "__main__":
    main()
