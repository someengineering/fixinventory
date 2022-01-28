import sys
import time
import inspect
import resotolib.baseresources
from resotolib.logging import log, setup_logger, add_args as logging_add_args
from resotolib.jwt import add_args as jwt_add_args
from functools import partial
from resotolib.core.actions import CoreActions
from resotometrics.metrics import Metrics, GraphCollector
from resotometrics.query import (
    query,
    get_labels_from_result,
    get_metrics_from_result,
    get_label_values_from_result,
)
from resotolib.web import WebServer
from resotolib.web.metrics import WebApp
from prometheus_client import Summary, REGISTRY
from prometheus_client.core import GaugeMetricFamily, CounterMetricFamily
from threading import Event
from resotolib.args import ArgumentParser
from signal import signal, SIGTERM, SIGINT

shutdown_event = Event()

metrics_update_metrics = Summary(
    "resotometrics_update_metrics_seconds",
    "Time it took the update_metrics() function",
)


def handler(sig, frame) -> None:
    log.info("Shutting down")
    shutdown_event.set()


def main() -> None:
    setup_logger("resotometrics")

    signal(SIGINT, handler)
    signal(SIGTERM, handler)

    arg_parser = ArgumentParser(
        description="resoto metrics exporter", env_args_prefix="RESOTOMETRICS_"
    )
    add_args(arg_parser)
    logging_add_args(arg_parser)
    jwt_add_args(arg_parser)
    WebServer.add_args(arg_parser)
    WebApp.add_args(arg_parser)
    arg_parser.parse_args()

    metrics = Metrics()
    graph_collector = GraphCollector(metrics)
    REGISTRY.register(graph_collector)

    base_uri = ArgumentParser.args.resotocore_uri.strip("/")
    resotocore_graph = ArgumentParser.args.resotocore_graph
    graph_uri = f"{base_uri}/graph/{resotocore_graph}"
    query_uri = f"{graph_uri}/query/aggregate?section=reported"

    message_processor = partial(core_actions_processor, metrics, query_uri)
    core_actions = CoreActions(
        identifier="resotometrics",
        resotocore_uri=ArgumentParser.args.resotocore_uri,
        resotocore_ws_uri=ArgumentParser.args.resotocore_ws_uri,
        actions={
            "generate_metrics": {
                "timeout": ArgumentParser.args.timeout,
                "wait_for_completion": True,
            },
        },
        message_processor=message_processor,
    )
    web_server = WebServer(WebApp())
    web_server.daemon = True
    web_server.start()
    core_actions.start()
    shutdown_event.wait()
    web_server.shutdown()
    core_actions.shutdown()
    sys.exit(0)


def core_actions_processor(metrics: Metrics, query_uri: str, message: dict) -> None:
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
    metrics_descriptions = find_metrics(resotolib.baseresources)
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
                                f"resoto_{metric_name}",
                                metric_help,
                                labels=labels,
                            )
                        elif metric_type == "counter":
                            metrics.staging[metric_name] = CounterMetricFamily(
                                f"resoto_{metric_name}",
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


def add_args(arg_parser: ArgumentParser) -> None:
    arg_parser.add_argument(
        "--resotocore-uri",
        help="resotocore URI (default: http://localhost:8900)",
        default="http://localhost:8900",
        dest="resotocore_uri",
    )
    arg_parser.add_argument(
        "--resotocore-ws-uri",
        help="resotocore Websocket URI (default: ws://localhost:8900)",
        default="ws://localhost:8900",
        dest="resotocore_ws_uri",
    )
    arg_parser.add_argument(
        "--resotocore-graph",
        help="resotocore graph name (default: resoto)",
        default="resoto",
        dest="resotocore_graph",
    )
    arg_parser.add_argument(
        "--timeout",
        help="Metrics generation timeout in seconds (default: 300)",
        default=300,
        dest="timeout",
        type=int,
    )


if __name__ == "__main__":
    main()
