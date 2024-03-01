import os
import sys
import time
import fixlib.proc
from fixlib.logger import log, setup_logger, add_args as logging_add_args
from fixlib.jwt import add_args as jwt_add_args
from fixlib.config import Config
from fixlib.core import (
    add_args as fixcore_add_args,
    fixcore,
    wait_for_fixcore,
)
from fixlib.core.ca import TLSData
from .config import FixMetricsConfig
from functools import partial
from fixlib.core.actions import CoreActions
from fixmetrics.metrics import Metrics, GraphCollector
from fixmetrics.search import (
    search,
    get_labels_from_result,
    get_metrics_from_result,
    get_label_values_from_result,
)
from fixlib.web import WebServer
from fixlib.web.metrics import WebApp
from prometheus_client import Summary, REGISTRY
from prometheus_client.core import GaugeMetricFamily, CounterMetricFamily
from fixlib.event import add_event_listener, EventType, Event as FixEvent
from threading import Event
from typing import Optional
from fixlib.args import ArgumentParser
from fixlib.utils import ensure_bw_compat


shutdown_event = Event()

metrics_update_metrics = Summary(
    "fixmetrics_update_metrics_seconds",
    "Time it took the update_metrics() function",
)


def shutdown(event: FixEvent) -> None:
    log.info("Shutting down")
    shutdown_event.set()


def main() -> None:
    ensure_bw_compat()
    setup_logger("fixmetrics")
    fixlib.proc.parent_pid = os.getpid()

    add_event_listener(EventType.SHUTDOWN, shutdown)
    arg_parser = ArgumentParser(
        description="Fix Inventory Metrics: a Prometheus exporter for cloud inventory data",
        env_args_prefix="FIXMETRICS_",
    )
    add_args(arg_parser)
    Config.add_args(arg_parser)
    fixcore_add_args(arg_parser)
    logging_add_args(arg_parser)
    jwt_add_args(arg_parser)
    TLSData.add_args(arg_parser)
    arg_parser.parse_args()

    try:
        wait_for_fixcore(fixcore.http_uri)
    except TimeoutError as e:
        log.fatal(f"Failed to connect to fixcore: {e}")
        sys.exit(1)

    tls_data = None
    if fixcore.is_secure:
        tls_data = TLSData(
            common_name=ArgumentParser.args.subscriber_id,
            fixcore_uri=fixcore.http_uri,
        )
        tls_data.start()
    config = Config(
        ArgumentParser.args.subscriber_id,
        fixcore_uri=fixcore.http_uri,
        tls_data=tls_data,
    )
    config.add_config(FixMetricsConfig)
    config.load_config()

    fixlib.proc.initializer()

    metrics = Metrics()
    graph_collector = GraphCollector(metrics)
    REGISTRY.register(graph_collector)

    fixcore_graph = Config.fixmetrics.graph
    graph_uri = f"{fixcore.http_uri}/graph/{fixcore_graph}"
    search_uri = f"{graph_uri}/search/aggregate?section=reported"

    message_processor = partial(core_actions_processor, metrics, search_uri, tls_data)
    core_actions = CoreActions(
        identifier=ArgumentParser.args.subscriber_id,
        fixcore_uri=fixcore.http_uri,
        fixcore_ws_uri=fixcore.ws_uri,
        actions={
            "generate_metrics": {
                "timeout": Config.fixmetrics.timeout,
                "wait_for_completion": True,
            },
        },
        message_processor=message_processor,
        tls_data=tls_data,
    )
    web_server_args = {}
    if tls_data and not Config.fixmetrics.no_tls:
        web_server_args = {
            "ssl_cert": tls_data.cert_path,
            "ssl_key": tls_data.key_path,
        }
    web_server = WebServer(
        WebApp(mountpoint=Config.fixmetrics.web_path),
        web_host=Config.fixmetrics.web_host,
        web_port=Config.fixmetrics.web_port,
        **web_server_args,
    )
    web_server.daemon = True
    web_server.start()
    core_actions.start()
    shutdown_event.wait()
    web_server.shutdown()
    core_actions.shutdown()
    fixlib.proc.kill_children(fixlib.proc.SIGTERM, ensure_death=True)
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
    metrics_descriptions = Config.fixmetrics.metrics
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
                                f"fix_{metric_name}",
                                metric_help,
                                labels=labels,
                            )
                        elif metric_type in ("counter", "cleanup_counter"):
                            metrics.staging[metric_name] = CounterMetricFamily(
                                f"fix_{metric_name}",
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
        help="Unique subscriber ID (default: fix.metrics)",
        default="fix.metrics",
        dest="subscriber_id",
        type=str,
    )


if __name__ == "__main__":
    main()
