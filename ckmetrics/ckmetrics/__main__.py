import sys
import requests
import json
import time
import inspect
import cklib.baseresources
from cklib.logging import log, add_args as logging_add_args
from functools import partial
from cklib.event import CkEvents
from cklib.jwt import encode_jwt_to_headers
from prometheus_client import Summary, start_http_server, REGISTRY
from prometheus_client.core import GaugeMetricFamily, CounterMetricFamily
from threading import Event
from cklib.args import ArgumentParser
from typing import Dict, Iterator, Tuple
from signal import signal, SIGTERM, SIGINT


shutdown_event = Event()

metrics_update_metrics = Summary(
    "ckmetrics_update_metrics_seconds",
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

    arg_parser = ArgumentParser(
        description="Cloudkeeper Metrics Exporter", env_args_prefix="CKMETRICS_"
    )
    add_args(arg_parser)
    logging_add_args(arg_parser)
    arg_parser.parse_args()

    metrics = Metrics()
    graph_collector = GraphCollector(metrics)
    REGISTRY.register(graph_collector)

    base_uri = ArgumentParser.args.ckcore_uri.strip("/")
    ckcore_graph = ArgumentParser.args.ckcore_graph
    graph_uri = f"{base_uri}/graph/{ckcore_graph}"
    query_uri = f"{graph_uri}/reported/query/aggregate"

    start_http_server(ArgumentParser.args.web_port)
    message_processor = partial(ckcore_message_processor, metrics, query_uri)
    ke = CkEvents(
        identifier="ckmetrics",
        ckcore_uri=ArgumentParser.args.ckcore_uri,
        ckcore_ws_uri=ArgumentParser.args.ckcore_ws_uri,
        events={
            "generate_metrics": {
                "timeout": ArgumentParser.args.timeout,
                "wait_for_completion": True,
            },
        },
        message_processor=message_processor,
    )
    ke.start()
    shutdown_event.wait()
    ke.shutdown()
    sys.exit(0)


def ckcore_message_processor(metrics: Metrics, query_uri: str, message: Dict) -> None:
    if not isinstance(message, dict):
        log.error(f"Invalid message: {message}")
        return
    kind = message.get("kind")
    message_type = message.get("message_type")
    data = message.get("data")
    log.debug(f"Received message of kind {kind}, type {message_type}, data: {data}")
    if kind == "action":
        try:
            if message_type == "generate_metrics":
                start_time = time.time()
                update_metrics(metrics, query_uri)
                run_time = time.time() - start_time
                log.debug(f"Updated metrics for {run_time:.2f} seconds")
            else:
                raise ValueError(f"Unknown message type {message_type}")
        except Exception as e:
            log.exception(f"Failed to {message_type}: {e}")
            reply_kind = "action_error"
        else:
            reply_kind = "action_done"

        reply_message = {
            "kind": reply_kind,
            "message_type": message_type,
            "data": data,
        }
        return reply_message


def query(query_str: str, query_uri: str) -> Iterator:
    headers = {"Accept": "application/x-ndjson"}
    if ArgumentParser.args.psk:
        encode_jwt_to_headers(headers, {}, ArgumentParser.args.psk)

    r = requests.post(
        query_uri,
        data=query_str,
        headers=headers,
        stream=True,
    )
    if r.status_code != 200:
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
    metrics_descriptions = find_metrics(cklib.baseresources)
    for _, data in metrics_descriptions.items():
        if shutdown_event.is_set():
            return

        metrics_query = data.get("query")
        metric_type = data.get("type")
        metric_help = data.get("help", "")

        if metrics_query is None:
            continue

        if metric_type not in ("gauge", "counter"):
            log.error(f"Do not know how to handle metrics of type {metric_type}")
            continue

        try:
            for result in query(metrics_query, query_uri):
                labels = get_labels_from_result(result)
                label_values = get_label_values_from_result(result, labels)

                for metric_name, metric_value in get_metrics_from_result(
                    result
                ).items():
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
        except RuntimeError as e:
            log.error(e)
            continue
    metrics.swap()


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
        help="TCP port to listen on (default: 9955)",
        default=9955,
        type=int,
        dest="web_port",
    )
    arg_parser.add_argument(
        "--ckcore-uri",
        help="ckcore URI (default: http://localhost:8900)",
        default="http://localhost:8900",
        dest="ckcore_uri",
    )
    arg_parser.add_argument(
        "--ckcore-ws-uri",
        help="ckcore Websocket URI (default: ws://localhost:8900)",
        default="ws://localhost:8900",
        dest="ckcore_ws_uri",
    )
    arg_parser.add_argument(
        "--ckcore-graph",
        help="ckcore graph name (default: ck)",
        default="ck",
        dest="ckcore_graph",
    )
    arg_parser.add_argument(
        "--psk",
        help="Pre-shared key",
        default=None,
        dest="psk",
    )
    arg_parser.add_argument(
        "--timeout",
        help="Metrics generation timeout in seconds (default: 300)",
        default=300,
        dest="timeout",
        type=int,
    )


class GraphCollector:
    """A Prometheus compatible Collector implementation"""

    def __init__(self, metrics: Metrics) -> None:
        self.metrics = metrics

    def collect(self):
        """collect() is being called whenever the /metrics endpoint is requested"""
        log.debug("generating metrics")

        for metric in self.metrics.live.values():
            yield metric


if __name__ == "__main__":
    main()
