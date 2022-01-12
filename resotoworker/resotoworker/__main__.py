from functools import partial
import time
import os
import threading
import resotolib.signal
from typing import List, Dict
from resotolib.logging import log, setup_logger, add_args as logging_add_args
from resotolib.graph import add_args as graph_add_args
from resotolib.jwt import add_args as jwt_add_args
from resotolib.pluginloader import PluginLoader
from resotolib.baseplugin import BaseCollectorPlugin, PluginType
from resotolib.web import WebServer
from resotolib.web.metrics import WebApp
from resotolib.utils import log_stats, increase_limits
from resotolib.args import ArgumentParser
from resotolib.core import add_args as core_add_args
from resotolib.core.actions import CoreActions
from resotolib.core.tasks import CoreTasks
from resotoworker.collect import collect, add_args as collect_add_args
from resotoworker.cleanup import cleanup, add_args as cleanup_add_args
from resotoworker.resotocore import add_args as resotocore_add_args
from resotoworker.tag import core_tag_tasks_processor
from resotolib.event import (
    add_event_listener,
    Event,
    EventType,
    add_args as event_add_args,
)


# This will be used in main() and shutdown()
shutdown_event = threading.Event()
collect_event = threading.Event()


def main() -> None:
    setup_logger("resotoworker")
    # Try to run in a new process group and
    # ignore if not possible for whatever reason
    try:
        os.setpgid(0, 0)
    except Exception:
        pass

    resotolib.signal.parent_pid = os.getpid()

    # Add cli args
    # The following double parsing of cli args is done so that when
    # a user specifies e.g. `--collector aws --help`  they would
    # no longer be shown cli args for other collectors like gcp.
    collector_arg_parser = ArgumentParser(
        description="Cloudkeeper Worker",
        env_args_prefix="RESOTOWORKER_",
        add_help=False,
        add_machine_help=False,
    )
    PluginLoader.add_args(collector_arg_parser)
    (args, _) = collector_arg_parser.parse_known_args()
    ArgumentParser.args = args

    arg_parser = ArgumentParser(
        description="Cloudkeeper Worker",
        env_args_prefix="RESOTOWORKER_",
    )
    jwt_add_args(arg_parser)
    logging_add_args(arg_parser)
    graph_add_args(arg_parser)
    collect_add_args(arg_parser)
    cleanup_add_args(arg_parser)
    core_add_args(arg_parser)
    resotocore_add_args(arg_parser)
    CoreActions.add_args(arg_parser)
    WebApp.add_args(arg_parser)
    PluginLoader.add_args(arg_parser)
    event_add_args(arg_parser)
    add_args(arg_parser)

    # Find resoto Plugins in the resoto.plugins module
    plugin_loader = PluginLoader()
    plugin_loader.add_plugin_args(arg_parser)

    # At this point the CLI, all Plugins as well as the WebServer have
    # added their args to the arg parser
    arg_parser.parse_args()

    # Handle Ctrl+c and other means of termination/shutdown
    resotolib.signal.initializer()
    add_event_listener(EventType.SHUTDOWN, shutdown, blocking=False)

    # Try to increase nofile and nproc limits
    increase_limits()

    web_server = WebServer(WebApp())
    web_server.daemon = True
    web_server.start()

    core_actions = CoreActions(
        identifier=f"{ArgumentParser.args.resotocore_subscriber_id}-collect_cleanup",
        resotocore_uri=ArgumentParser.args.resotocore_uri,
        resotocore_ws_uri=ArgumentParser.args.resotocore_ws_uri,
        actions={
            "collect": {
                "timeout": ArgumentParser.args.timeout,
                "wait_for_completion": True,
            },
            "cleanup": {
                "timeout": ArgumentParser.args.timeout,
                "wait_for_completion": True,
            },
        },
        message_processor=partial(
            core_actions_processor, plugin_loader.plugins(PluginType.COLLECTOR)
        ),
    )

    task_queue_filter = {}
    if ArgumentParser.args.collector and len(ArgumentParser.args.collector) > 0:
        task_queue_filter = {"cloud": list(ArgumentParser.args.collector)}
    core_tasks = CoreTasks(
        identifier="workerd-tasks",
        resotocore_ws_uri=ArgumentParser.args.resotocore_ws_uri,
        tasks=["tag"],
        task_queue_filter=task_queue_filter,
        message_processor=core_tag_tasks_processor,
    )
    core_actions.start()
    core_tasks.start()

    for Plugin in plugin_loader.plugins(PluginType.ACTION):
        try:
            log.debug(f"Starting action plugin {Plugin}")
            plugin = Plugin()
            plugin.start()
        except Exception as e:
            log.exception(f"Caught unhandled persistent Plugin exception {e}")

    # We wait for the shutdown Event to be set() and then end the program
    # While doing so we print the list of active threads once per 15 minutes
    shutdown_event.wait()
    web_server.shutdown()
    time.sleep(1)  # everything gets 1000ms to shutdown gracefully before we force it
    resotolib.signal.kill_children(resotolib.signal.SIGTERM, ensure_death=True)
    log.info("Shutdown complete")
    os._exit(0)


def core_actions_processor(
    collectors: List[BaseCollectorPlugin], message: Dict
) -> None:
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
                start_time = time.time()
                collect(collectors)
                run_time = int(time.time() - start_time)
                log.debug(f"Collect ran for {run_time} seconds")
            elif message_type == "cleanup":
                start_time = time.time()
                cleanup()
                run_time = int(time.time() - start_time)
                log.debug(f"Cleanup ran for {run_time} seconds")
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


def add_args(arg_parser: ArgumentParser) -> None:
    arg_parser.add_argument(
        "--timeout",
        help="Collection/cleanup Timeout in seconds (default: 10800)",
        default=10800,
        dest="timeout",
        type=int,
    )
    arg_parser.add_argument(
        "--web-port",
        help="Web Port (default 9955)",
        default=9956,
        dest="web_port",
        type=int,
    )
    arg_parser.add_argument(
        "--web-host",
        help="IP to bind to (default: ::)",
        default="::",
        dest="web_host",
        type=str,
    )


def shutdown(event: Event) -> None:
    reason = event.data.get("reason")
    emergency = event.data.get("emergency")

    if emergency:
        resotolib.signal.emergency_shutdown(reason)

    current_pid = os.getpid()
    if current_pid != resotolib.signal.parent_pid:
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
