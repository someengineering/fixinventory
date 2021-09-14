from functools import partial
import time
import os
import threading
import multiprocessing
from cloudkeeper.baseresources import BaseResource
import websocket
from concurrent import futures
from networkx.algorithms.dag import is_directed_acyclic_graph
import requests
import json
import cloudkeeper.logging as logging
import cloudkeeper.signal
from pydoc import locate
from datetime import datetime, date, timedelta, timezone
from typing import List, Optional, Dict
from dataclasses import fields
from cloudkeeper.graph import GraphContainer, Graph, sanitize, GraphExportIterator
from cloudkeeper.graph.export import optional_origin
from cloudkeeper.pluginloader import PluginLoader
from cloudkeeper.baseplugin import BaseCollectorPlugin, PluginType
from cloudkeeper.args import get_arg_parser
from cloudkeeper.utils import log_stats, increase_limits, str2timedelta, str2timezone
from cloudkeeper.args import ArgumentParser
from cloudkeeper.cleaner import Cleaner
from cloudkeeper.event import (
    add_event_listener,
    Event,
    EventType,
    KeepercoreEvents,
    KeepercoreTasks,
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
    Cleaner.add_args(arg_parser)
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
        identifier="workerd-events",
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
    kt = KeepercoreTasks(
        identifier="workerd-tasks",
        keepercore_ws_uri=ArgumentParser.args.keepercore_ws_uri,
        tasks=["tag"],
        task_queue_filter={},
        message_processor=tasks_processor,
    )
    ke.start()
    kt.start()

    # We wait for the shutdown Event to be set() and then end the program
    # While doing so we print the list of active threads once per 15 minutes
    shutdown_event.wait()
    time.sleep(1)  # everything gets 1000ms to shutdown gracefully before we force it
    cloudkeeper.signal.kill_children(cloudkeeper.signal.SIGTERM, ensure_death=True)
    log.info("Shutdown complete")
    os._exit(0)


def tasks_processor(ws: websocket.WebSocketApp, message: Dict) -> None:
    task_id = message.get("task_id")
    # task_name = message.get("task_name")
    # task_attrs = message.get("attrs", {})
    task_data = message.get("data", {})
    delete_tags = task_data.get("delete", [])
    update_tags = task_data.get("update", {})
    node_data = task_data.get("node")
    result = "done"
    extra_data = {}

    try:
        node = make_node(node_data)
        for delete_tag in delete_tags:
            del node.tags[delete_tag]

        for k, v in update_tags.items():
            node.tags[k] = v
    except Exception as e:
        log.exception("Error while updating tags")
        result = "error"
        extra_data["error"] = str(e)

    reply_message = {
        "task_id": task_id,
        "result": result,
    }
    reply_message.update(extra_data)
    log.debug(f"Sending reply {reply_message}")
    ws.send(json.dumps(reply_message))


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
        try:
            if message_type == "collect":
                collect(collectors)
            elif message_type == "cleanup":
                cleanup()
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
        log.debug(f"Sending reply {reply_message}")
        ws.send(json.dumps(reply_message))


def make_node(node_data: Dict):
    """Create an instance from keepercore graph node data"""
    node_data_reported = node_data.get("reported", {})
    node_data_desired = node_data.get("desired", {})
    node_data_metadata = node_data.get("metadata", {})

    node_data = dict(node_data_reported)
    del node_data["kind"]

    python_type = node_data_metadata.get("python_type", "NoneExisting")
    node_type = locate(python_type)
    if node_type is None:
        raise ValueError(f"Do not know how to handle {node_data_reported}")

    restore_node_field_types(node_type, node_data)

    ancestors = {}
    for ancestor in ("cloud", "account", "region", "zone"):
        if ancestor in node_data_reported and ancestor in node_data_metadata:
            ancestors[f"_{ancestor}"] = make_node(
                {
                    "reported": node_data_reported[ancestor],
                    "metadata": node_data_metadata[ancestor],
                }
            )
    node_data.update(ancestors)

    node = node_type(**node_data)

    protect_node = node_data_metadata.get("protected", False)
    if protect_node:
        node.protected = protect_node
    clean_node = node_data_desired.get("clean", False)
    if clean_node:
        node.clean = clean_node
    node._raise_tags_exceptions = True
    return node


def cleanup():
    """Run resource cleanup"""

    def process_data_line(data: Dict, graph: Graph):
        """Process a single line of keepercore graph data"""

        if data.get("type") == "node":
            node_id = data.get("id")
            node = make_node(data)
            node_mapping[node_id] = node
            log.debug(f"Adding node {node} to the graph")
            graph.add_node(node)
            if node.kind == "graph_root":
                log.debug(f"Setting graph root {node}")
                graph.root = node
            if node_id != node.sha256:
                log.warning(
                    f"ID {node_id} of node {node} does not match checksum {node.sha256}"
                )
        elif data.get("type") == "edge":
            node_from = data.get("from")
            node_to = data.get("to")
            if node_from not in node_mapping or node_to not in node_mapping:
                raise ValueError(f"One of {node_from} -> {node_to} unknown")
            graph.add_edge(node_mapping[node_from], node_mapping[node_to])

    log.info("Running cleanup")
    base_uri = ArgumentParser.args.keepercore_uri.strip("/")
    keepercore_graph = ArgumentParser.args.keepercore_graph
    graph_uri = f"{base_uri}/graph/{keepercore_graph}"
    query_uri = f"{graph_uri}/query/graph"
    query = "desired.clean==true -[0:]-"
    r = requests.post(
        query_uri, data=query, headers={"accept": "application/x-ndjson"}, stream=True
    )
    if r.status_code != 200:
        log.error(r.content)
        raise RuntimeError(f"Failed to query graph: {r.content}")
    graph = Graph()
    node_mapping = {}

    for line in r.iter_lines():
        if not line:
            continue
        data = json.loads(line.decode("utf-8"))
        try:
            process_data_line(data, graph)
        except ValueError as e:
            log.error(e)
            continue
    sanitize(graph)
    cleaner = Cleaner(graph)
    cleaner.cleanup()


def restore_node_field_types(node_type: BaseResource, node_data_reported: Dict):
    for field in fields(node_type):
        if field.name not in node_data_reported:
            continue
        field_type = optional_origin(field.type)

        if field_type == datetime:
            datetime_str = str(node_data_reported[field.name])
            if datetime_str.endswith("Z"):
                datetime_str = datetime_str[:-1] + "+00:00"
            node_data_reported[field.name] = datetime.fromisoformat(datetime_str)
        elif field_type == date:
            node_data_reported[field.name] = date.fromisoformat(
                node_data_reported[field.name]
            )
        elif field_type == timedelta:
            node_data_reported[field.name] = str2timedelta(
                node_data_reported[field.name]
            )
        elif field_type == timezone:
            node_data_reported[field.name] = str2timezone(
                node_data_reported[field.name]
            )


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
    if ArgumentParser.args.debug_dump_json:
        with open("model.dump.json", "w") as model_outfile:
            model_outfile.write(model_json)
    r = requests.patch(model_uri, data=model_json)
    if r.status_code != 200:
        log.error(r.content)
        raise RuntimeError(f"Failed to create model: {r.content}")
    graph_outfile = None
    if ArgumentParser.args.debug_dump_json:
        graph_outfile = open("graph.dump.json", "w")
    graph_export_iterator = GraphExportIterator(graph, graph_outfile)
    log.debug(f"Sending subgraph via {report_uri}")
    r = requests.post(
        report_uri,
        data=graph_export_iterator,
        headers={"Content-Type": "application/x-ndjson"},
    )
    if graph_outfile is not None:
        graph_outfile.close()
    if r.status_code != 200:
        log.error(r.content)
        raise RuntimeError(f"Failed to send graph: {r.content}")
    log.debug(f"Keepercore reply: {r.content.decode()}")
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
    arg_parser.add_argument(
        "--debug-dump-json",
        help="Dump the generated json data (default: False)",
        dest="debug_dump_json",
        action="store_true",
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
