import graph_exporter.logging
import sys
import requests
import json
import time
import inspect
import cloudkeeper.baseresources
from prometheus_client import Summary, start_http_server, REGISTRY
from prometheus_client.core import GaugeMetricFamily, CounterMetricFamily
from threading import Event
from graph_exporter.args import get_arg_parser, ArgumentParser
from typing import Dict, Iterator, Tuple
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


class Metrics:
    def __init__(self) -> None:
        self.live = {}
        self.staging = {}

    def swap(self) -> None:
        self.live = self.staging
        self.staging = {}


def main() -> None:
    signal(SIGINT, handler)
    signal(SIGTERM, handler)

    arg_parser = get_arg_parser()
    add_args(arg_parser)
    arg_parser.parse_args()

    metrics = Metrics()
    graph_collector = GraphCollector(metrics)
    REGISTRY.register(graph_collector)

    base_uri = ArgumentParser.args.keepercore_uri.strip("/")
    keepercore_graph = ArgumentParser.args.keepercore_graph
    graph_uri = f"{base_uri}/graph/{keepercore_graph}"
    query_uri = f"{graph_uri}/reported/query/aggregate"

    start_http_server(ArgumentParser.args.web_port)
    while not shutdown_event.is_set():
        try:
            start_time = time.time()
            update_metrics(metrics, query_uri)
            metrics.swap()
            run_time = time.time() - start_time
            log.debug(f"Updated metrics for {run_time:.2f} seconds")
        except Exception as e:
            log.error(e)
            time.sleep(10)
            continue
        shutdown_event.wait(900)
    sys.exit(0)


def query(query_str: str, query_uri: str) -> Iterator:
    r = requests.post(
        query_uri,
        data=query_str,
        headers={"accept": "application/x-ndjson"},
        stream=True,
    )
    if r.status_code != 200:
        log.error(r.content)
        raise RuntimeError(f"Failed to query graph: {r.content}")

    for line in r.iter_lines():
        if not line:
            continue

        data = json.loads(line.decode("utf-8"))
        yield data


def find_metrics(mod):
    log.debug("Finding metrics")
    metrics_descriptions = {}
    for _, obj in inspect.getmembers(mod):
        if inspect.isclass(obj) and hasattr(obj, "metrics_description"):
            metrics_description = obj.metrics_description
            if len(metrics_description) > 0:
                metrics_descriptions.update(metrics_description)
    return metrics_descriptions


@metrics_update_metrics.time()
def update_metrics(metrics: Metrics, query_uri: str) -> None:
    metrics_descriptions = find_metrics(cloudkeeper.baseresources)

    for _, data in metrics_descriptions.items():
        if shutdown_event.is_set():
            return

        metrics_query = data.get("query")
        metric_type = data.get("type")
        metric_help = data.get("help", "")

        if metrics_query is None:
            continue

        if metric_type not in ("gauge"):
            log.error(f"Do not know how to handle metrics of type {metric_type}")
            continue

        for result in query(metrics_query, query_uri):
            labels = get_labels_from_result(result)
            label_values = get_label_values_from_result(result, labels)

            for metric_name, metric_value in get_metrics_from_result(result).items():
                if metric_name not in metrics.staging:
                    log.debug(f"Adding metric {metric_name} of type {metric_type}")
                    if metric_type == "gauge":
                        metrics.staging[metric_name] = GaugeMetricFamily(
                            f"cloudkeeper_{metric_name}",
                            metric_help,
                            labels=labels,
                        )
                    elif metric_type == "counter":
                        metrics.staging[metric_name] = CounterMetricFamily(
                            f"cloudkeeper_{metric_name}",
                            metric_help,
                            labels=labels,
                        )
                if metric_type == "counter" and metric_name in metrics.live:
                    current_metric = metrics.live[metric_name]
                    for sample in current_metric.samples:
                        if sample.labels == result.get("group"):
                            metric_value += sample.value
                            break
                metrics.staging[metric_name].add_metric(label_values, metric_value)


def get_metrics_from_result(result: Dict):
    result_metrics = dict(result)
    del result_metrics["group"]
    return result_metrics


def get_labels_from_result(result: Dict):
    labels = tuple(result.get("group", {}).keys())
    return labels


def get_label_values_from_result(result: Dict, labels: Tuple):
    label_values = []
    for label in labels:
        label_value = result.get("group", {}).get(label)
        if label_value is None:
            label_value = ""
        label_values.append(str(label_value))
    return tuple(label_values)


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

    def __init__(self, metrics: Metrics) -> None:
        self.metrics = metrics

    def collect(self):
        """collect() is being called whenever the /metrics endpoint is requested"""
        log.debug("GraphCollector generating metrics")

        for metric in self.metrics.live.values():
            yield metric


if __name__ == "__main__":
    main()
