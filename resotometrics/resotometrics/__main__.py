import os
import sys
import time
import resotolib.proc
from resotolib.logger import log, setup_logger, add_args as logging_add_args
from resotolib.jwt import add_args as jwt_add_args
from resotolib.config import Config
from resotolib.core import (
    add_args as resotocore_add_args,
    resotocore,
    wait_for_resotocore,
)
from resotolib.core.ca import TLSData
from .config import ResotoMetricsConfig
from functools import partial
from resotolib.core.actions import CoreActions
from resotometrics.metrics import Metrics, GraphCollector
from resotometrics.search import (
    search,
    get_labels_from_result,
    get_metrics_from_result,
    get_label_values_from_result,
)
from resotolib.web import WebServer
from resotolib.web.metrics import WebApp
from prometheus_client import Summary, REGISTRY
from prometheus_client.core import GaugeMetricFamily, CounterMetricFamily
from resotolib.event import add_event_listener, EventType, Event as ResotoEvent
from threading import Event
from typing import Optional
from resotolib.args import ArgumentParser


shutdown_event = Event()

metrics_update_metrics = Summary(
    "resotometrics_update_metrics_seconds",
    "Time it took the update_metrics() function",
)


def shutdown(event: ResotoEvent) -> None:
    log.info("Shutting down")
    shutdown_event.set()


def main() -> None:
    setup_logger("resotometrics")
    resotolib.proc.parent_pid = os.getpid()

    add_event_listener(EventType.SHUTDOWN, shutdown)
    arg_parser = ArgumentParser(description="resoto metrics exporter", env_args_prefix="RESOTOMETRICS_")
    add_args(arg_parser)
    Config.add_args(arg_parser)
    resotocore_add_args(arg_parser)
    logging_add_args(arg_parser)
    jwt_add_args(arg_parser)
    TLSData.add_args(arg_parser)
    arg_parser.parse_args()

    try:
        wait_for_resotocore(resotocore.http_uri)
    except TimeoutError as e:
        log.fatal(f"Failed to connect to resotocore: {e}")
        sys.exit(1)

    tls_data = None
    if resotocore.is_secure:
        tls_data = TLSData(
            common_name=ArgumentParser.args.subscriber_id,
            resotocore_uri=resotocore.http_uri,
        )
        tls_data.start()
    config = Config(
        ArgumentParser.args.subscriber_id,
        resotocore_uri=resotocore.http_uri,
        tls_data=tls_data,
    )
    config.add_config(ResotoMetricsConfig)
    config.load_config()

    resotolib.proc.initializer()

    metrics = Metrics()
    graph_collector = GraphCollector(metrics)
    REGISTRY.register(graph_collector)

    resotocore_graph = Config.resotometrics.graph
    graph_uri = f"{resotocore.http_uri}/graph/{resotocore_graph}"
    search_uri = f"{graph_uri}/search/aggregate?section=reported"

    message_processor = partial(core_actions_processor, metrics, search_uri, tls_data)
    core_actions = CoreActions(
        identifier=ArgumentParser.args.subscriber_id,
        resotocore_uri=resotocore.http_uri,
        resotocore_ws_uri=resotocore.ws_uri,
        actions={
            "generate_metrics": {
                "timeout": Config.resotometrics.timeout,
                "wait_for_completion": True,
            },
        },
        message_processor=message_processor,
        tls_data=tls_data,
    )
    web_server_args = {}
    if tls_data and not Config.resotometrics.no_tls:
        web_server_args = {
            "ssl_cert": tls_data.cert_path,
            "ssl_key": tls_data.key_path,
        }
    web_server = WebServer(
        WebApp(mountpoint=Config.resotometrics.web_path),
        web_host=Config.resotometrics.web_host,
        web_port=Config.resotometrics.web_port,
        **web_server_args,
    )
    web_server.daemon = True
    web_server.start()
    core_actions.start()
    shutdown_event.wait()
    web_server.shutdown()
    core_actions.shutdown()
    resotolib.proc.kill_children(resotolib.proc.SIGTERM, ensure_death=True)
    log.info("Shutdown complete")
    sys.exit(0)


def core_actions_processor(metrics: Metrics, search_uri: str, tls_data: TLSData, message: dict) -> None:
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
                update_metrics(metrics, search_uri, tls_data)
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


@metrics_update_metrics.time()
def update_metrics(metrics: Metrics, search_uri: str, tls_data: Optional[TLSData] = None) -> None:
    metrics_descriptions = Config.resotometrics.metrics
    for _, data in metrics_descriptions.items():
        if shutdown_event.is_set():
            return
        metrics_search = data.search
        metric_type = data.type.value
        metric_help = data.help

        if metrics_search is None:
            continue

        if metric_type not in ("gauge", "counter", "cleanup_counter"):
            log.error(f"Do not know how to handle metrics of type {metric_type}")
            continue

        try:
            for result in search(metrics_search, search_uri, tls_data=tls_data):
                labels = get_labels_from_result(result)
                label_values = get_label_values_from_result(result, labels)

                for metric_name, metric_value in get_metrics_from_result(result).items():
                    if metric_name not in metrics.staging:
                        log.debug(f"Adding metric {metric_name} of type {metric_type}")
                        if metric_type == "gauge":
                            metrics.staging[metric_name] = GaugeMetricFamily(
                                f"resoto_{metric_name}",
                                metric_help,
                                labels=labels,
                            )
                        elif metric_type in ("counter", "cleanup_counter"):
                            metrics.staging[metric_name] = CounterMetricFamily(
                                f"resoto_{metric_name}",
                                metric_help,
                                labels=labels,
                            )
                    if metric_type == "cleanup_counter" and metric_name in metrics.live:
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
        "--subscriber-id",
        help="Unique subscriber ID (default: resoto.metrics)",
        default="resoto.metrics",
        dest="subscriber_id",
        type=str,
    )


if __name__ == "__main__":
    main()
