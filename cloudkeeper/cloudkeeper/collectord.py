from functools import partial
import time
import os
import threading
import multiprocessing
import websocket
from concurrent import futures
from networkx.algorithms.dag import is_directed_acyclic_graph
import requests
import json
import cloudkeeper.logging as logging
import cloudkeeper.signal
from typing import List, Optional, Dict
from cloudkeeper.graph import GraphContainer, Graph, sanitize
from cloudkeeper.pluginloader import PluginLoader
from cloudkeeper.baseplugin import BaseCollectorPlugin, PluginType
from cloudkeeper.args import get_arg_parser
from cloudkeeper.utils import log_stats, increase_limits
from cloudkeeper.args import ArgumentParser
from cloudkeeper.event import (
    add_event_listener,
    Event,
    EventType,
    KeepercoreEvents,
    add_args as event_add_args,
)


log = logging.getLogger(__name__)

# This will be used in main() and shutdown()
shutdown_event = threading.Event()
collect_event = threading.Event()


def main() -> None:
    log.info("Cloudkeeper collectord initializing")
    # Try to run in a new process group and
    # ignore if not possible for whatever reason
    try:
        os.setpgid(0, 0)
    except Exception:
        pass

    cloudkeeper.signal.parent_pid = os.getpid()

    # Add cli args
    collector_arg_parser = get_arg_parser(add_help=False)
    PluginLoader.add_args(collector_arg_parser)
    (args, _) = collector_arg_parser.parse_known_args()
    ArgumentParser.args = args

    arg_parser = get_arg_parser()
    logging.add_args(arg_parser)
    PluginLoader.add_args(arg_parser)
    GraphContainer.add_args(arg_parser)
    event_add_args(arg_parser)
    add_args(arg_parser)

    # Find cloudkeeper Plugins in the cloudkeeper.plugins module
    plugin_loader = PluginLoader(PluginType.COLLECTOR)
    plugin_loader.add_plugin_args(arg_parser)

    # At this point the CLI, all Plugins as well as the WebServer have
    # added their args to the arg parser
    arg_parser.parse_args()

    # Handle Ctrl+c and other means of termination/shutdown
    cloudkeeper.signal.initializer()
    add_event_listener(EventType.SHUTDOWN, shutdown, blocking=False)

    # Try to increase nofile and nproc limits
    increase_limits()

    all_collector_plugins = plugin_loader.plugins(PluginType.COLLECTOR)
    message_processor = partial(keepercore_message_processor, all_collector_plugins)

    ke = KeepercoreEvents(
        identifier="collectord",
        keepercore_uri=ArgumentParser.args.keepercore_uri,
        keepercore_ws_uri=ArgumentParser.args.keepercore_ws_uri,
        events={
            "collect": {
                "timeout": ArgumentParser.args.timeout,
                "wait_for_completion": True,
            },
            "cleanup": {
                "timeout": ArgumentParser.args.timeout,
                "wait_for_completion": True,
            },
        },
        message_processor=message_processor,
    )
    ke.start()

    # We wait for the shutdown Event to be set() and then end the program
    # While doing so we print the list of active threads once per 15 minutes
    while not shutdown_event.is_set():
        log_stats()
        shutdown_event.wait(900)
    time.sleep(5)
    cloudkeeper.signal.kill_children(cloudkeeper.signal.SIGTERM, ensure_death=True)
    log.info("Shutdown complete")
    quit()


def keepercore_message_processor(
    collectors: List[BaseCollectorPlugin], ws: websocket.WebSocketApp, message: Dict
) -> None:
    if not isinstance(ws, websocket.WebSocketApp):
        log.error(f"Invalid websocket: {ws}")
        return
    if not isinstance(message, dict):
        log.error(f"Invalid message: {message}")
        return
    kind = message.get("kind")
    message_type = message.get("message_type")
    data = message.get("data")
    log.debug(f"Received message of kind {kind}, type {message_type}, data: {data}")
    if kind == "action":
        if message_type == "collect":
            try:
                collect(collectors)
            except Exception as e:
                log.exception(f"Failed to collect: {e}")
                reply_kind = "action_error"
            else:
                reply_kind = "action_done"
        elif message_type == "cleanup":
            try:
                cleanup()
            except Exception as e:
                log.exception(f"Failed to cleanup: {e}")
                reply_kind = "action_error"
            else:
                reply_kind = "action_done"

        reply_message = {
            "kind": reply_kind,
            "message_type": message_type,
            "data": data,
        }
        log.debug(f"Sending reply {reply_message}")
        ws.send(json.dumps(reply_message))


def cleanup():
    log.info("Running cleanup")


def collect_plugin_graph(
    collector_plugin: BaseCollectorPlugin, args=None
) -> Optional[Graph]:
    collector: BaseCollectorPlugin = collector_plugin()
    collector_name = f"collector_{collector.cloud}"
    cloudkeeper.signal.set_thread_name(collector_name)

    if args is not None:
        ArgumentParser.args = args

    log.debug(f"Starting new collect process for {collector.cloud}")
    collector.start()
    collector.join(ArgumentParser.args.timeout)
    if not collector.is_alive():  # The plugin has finished its work
        if not collector.finished:
            log.error(
                f"Plugin {collector.cloud} did not finish collection"
                " - ignoring plugin results"
            )
            return None
        if not is_directed_acyclic_graph(collector.graph):
            log.error(
                f"Graph of plugin {collector.cloud} is not acyclic"
                " - ignoring plugin results"
            )
            return None
        log.info(f"Collector of plugin {collector.cloud} finished")
        return collector.graph
    else:
        log.error(f"Plugin {collector.cloud} timed out - discarding Plugin graph")
        return None


def collect(collectors: List[BaseCollectorPlugin]):
    graph_container = GraphContainer(cache_graph=False)
    graph = graph_container.graph
    max_workers = (
        len(collectors)
        if len(collectors) < ArgumentParser.args.pool_size
        else ArgumentParser.args.pool_size
    )
    pool_args = {"max_workers": max_workers}
    if ArgumentParser.args.fork:
        pool_args["mp_context"] = multiprocessing.get_context("spawn")
        pool_args["initializer"] = cloudkeeper.signal.initializer
        pool_executor = futures.ProcessPoolExecutor
        collect_args = {"args": ArgumentParser.args}
    else:
        pool_executor = futures.ThreadPoolExecutor
        collect_args = {}

    with pool_executor(**pool_args) as executor:
        wait_for = [
            executor.submit(
                collect_plugin_graph,
                collector,
                **collect_args,
            )
            for collector in collectors
        ]
        for future in futures.as_completed(wait_for):
            cluster_graph = future.result()
            if not isinstance(cluster_graph, Graph):
                log.error(f"Skipping invalid cluster_graph {type(cluster_graph)}")
                continue
            graph.merge(cluster_graph)
    sanitize(graph)
    send_to_keepercore(graph)


def send_to_keepercore(graph: Graph):
    if not ArgumentParser.args.keepercore_uri:
        return

    log.info("Keepercore Event Handler called")
    base_uri = ArgumentParser.args.keepercore_uri.strip("/")
    keepercore_graph = ArgumentParser.args.keepercore_graph
    model_uri = f"{base_uri}/model"
    graph_uri = f"{base_uri}/graph/{keepercore_graph}"
    report_uri = f"{graph_uri}/reported/merge"
    log.debug(f"Creating graph {keepercore_graph} via {graph_uri}")
    r = requests.post(graph_uri, data="", headers={"accept": "application/json"})
    if r.status_code != 200:
        log.error(r.content)
        raise RuntimeError(f"Failed to create graph: {r.content}")
    log.debug(f"Updating model via {model_uri}")
    model_json = json.dumps(graph.export_model(), indent=4)
    r = requests.patch(model_uri, data=model_json)
    if r.status_code != 200:
        log.error(r.content)
        raise RuntimeError(f"Failed to create model: {r.content}")
    graph_export_iterator = graph.export_iterator()
    log.debug(f"Sending subgraph via {report_uri}")
    r = requests.post(
        report_uri,
        data=graph.export_iterator(),
        headers={"Content-Type": "application/x-ndjson"},
    )
    if r.status_code != 200:
        log.error(r.content)
        raise RuntimeError(f"Failed to send graph: {r.content}")
    log.debug(r.content.decode())
    log.debug(
        f"Sent {graph_export_iterator.nodes_sent} nodes and {graph_export_iterator.edges_sent} edges to keepercore"
    )


def add_args(arg_parser: ArgumentParser) -> None:
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
    arg_parser.add_argument(
        "--pool-size",
        help="Collector Thread/Process Pool Size (default: 5)",
        dest="pool_size",
        default=5,
        type=int,
    )
    arg_parser.add_argument(
        "--fork",
        help="Use forked process instead of threads (default: False)",
        dest="fork",
        action="store_true",
    )
    arg_parser.add_argument(
        "--timeout",
        help="Collection Timeout in seconds (default: 10800)",
        default=10800,
        dest="timeout",
        type=int,
    )


def shutdown(event: Event) -> None:
    reason = event.data.get("reason")
    emergency = event.data.get("emergency")

    if emergency:
        cloudkeeper.signal.emergency_shutdown(reason)

    current_pid = os.getpid()
    if current_pid != cloudkeeper.signal.parent_pid:
        return

    if reason is None:
        reason = "unknown reason"
    log.info(
        (
            f"Received shut down event {event.event_type}:"
            f" {reason} - killing all threads and child processes"
        )
    )
    # Send 'friendly' signal to children to have them shut down
    cloudkeeper.signal.kill_children(cloudkeeper.signal.SIGTERM)
    kt = threading.Thread(target=force_shutdown, name="shutdown")
    kt.start()
    shutdown_event.set()  # and then end the program


def force_shutdown(delay: int = 10) -> None:
    time.sleep(delay)
    log_stats()
    log.error(
        (
            "Some child process or thread timed out during shutdown"
            " - forcing shutdown completion"
        )
    )
    os._exit(0)


if __name__ == "__main__":
    main()
