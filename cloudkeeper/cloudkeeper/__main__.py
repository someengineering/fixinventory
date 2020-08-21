import time
import os
import sys
import resource
import threading
import cloudkeeper.logging as logging
import cloudkeeper.signal
from signal import SIGKILL, SIGUSR1, SIGTERM
from cloudkeeper.graph import GraphContainer
from cloudkeeper.pluginloader import PluginLoader
from cloudkeeper.baseplugin import PluginType
from cloudkeeper.web import WebServer
from cloudkeeper.scheduler import Scheduler
from cloudkeeper.args import get_arg_parser
from cloudkeeper.processor import Processor
from cloudkeeper.cleaner import Cleaner
from cloudkeeper.metrics import GraphCollector
from cloudkeeper.utils import log_stats, get_child_process_info
from cloudkeeper.cli import Cli
from cloudkeeper.event import add_event_listener, dispatch_event, Event, EventType, add_args as event_add_args
from prometheus_client import REGISTRY


# Try to run in a new process group
try:
    os.setpgid(0, 0)
except (PermissionError, AttributeError):
    pass

log = logging.getLogger(__name__)

# This will be used in main() and signal_handler()
shutdown_event = threading.Event()


def main() -> None:
    cloudkeeper.signal.parent_pid = os.getpid()
    args_str = ""
    if len(sys.argv) > 1:
        args_str = f" {' '.join(sys.argv[1:])}"
    cloudkeeper.signal.set_proc_title(f"cloudkeeper{args_str}")
    cloudkeeper.signal.set_proc_name("cloudkeeper")
    # Add cli args
    arg_parser = get_arg_parser()

    logging.add_args(arg_parser)
    Cli.add_args(arg_parser)
    WebServer.add_args(arg_parser)
    Scheduler.add_args(arg_parser)
    Processor.add_args(arg_parser)
    Cleaner.add_args(arg_parser)
    PluginLoader.add_args(arg_parser)
    GraphContainer.add_args(arg_parser)
    event_add_args(arg_parser)

    # Find cloudkeeper Plugins in the cloudkeeper.plugins module
    plugin_loader = PluginLoader()
    plugin_loader.add_plugin_args(arg_parser)

    # At this point the CLI, all Plugins as well as the WebServer have added their args to the arg parser
    arg_parser.parse_args()

    cloudkeeper.signal.initializer()

    # Handle Ctrl+c and other means of termination/shutdown
    cloudkeeper.signal.on_parent_exit(SIGKILL)
    add_event_listener(EventType.SHUTDOWN, shutdown, blocking=False)

    # Try to increase nofile and nproc limits
    for limit_name in ("RLIMIT_NOFILE", "RLIMIT_NPROC"):
        soft_limit, hard_limit = resource.getrlimit(getattr(resource, limit_name))
        log.debug(f"Current {limit_name} soft: {soft_limit} hard: {hard_limit}")
        try:
            if soft_limit < hard_limit:
                log.debug(f"Increasing {limit_name} {soft_limit} -> {hard_limit}")
                resource.setrlimit(getattr(resource, limit_name), (hard_limit, hard_limit))
        except (ValueError):
            log.error(f"Failed to increase {limit_name} {soft_limit} -> {hard_limit}")

    # We're using a GraphContainer() to contain the graph which gets replaced at runtime.
    # This way we're not losing the context in other places like the webserver when the
    # graph gets reassigned.
    graph_container = GraphContainer()

    # GraphCollector() is a custom Prometheus Collector that
    # takes a graph and yields its metrics
    graph_collector = GraphCollector(graph_container)
    REGISTRY.register(graph_collector)

    # Scheduler() starts an APScheduler instance
    scheduler = Scheduler(graph_container)
    scheduler.daemon = True
    scheduler.start()

    # Cli() is the CLI Thread
    cli = Cli(graph_container, scheduler)
    cli.daemon = True
    cli.start()

    # WebServer is handed the graph container context so it can e.g. produce graphml from it
    # The webserver serves Prometheus Metrics as well as different graph endpoints
    web_server = WebServer(graph_container)
    web_server.daemon = True
    web_server.start()

    for Plugin in plugin_loader.plugins(PluginType.PERSISTENT):
        try:
            log.debug(f"Starting persistent Plugin {Plugin}")
            plugin = Plugin()
            plugin.daemon = True
            plugin.start()
        except Exception as e:
            log.exception(f"Caught unhandled persistent Plugin exception {e}")

    processor = Processor(graph_container, plugin_loader.plugins(PluginType.COLLECTOR))
    processor.daemon = True
    processor.start()

    # Dispatch the STARTUP event
    dispatch_event(Event(EventType.STARTUP))

    # We wait for the shutdown Event to be set() and then end the program
    # While doing so we print the list of active threads once per 15 minutes
    while not shutdown_event.is_set():
        log_stats()
        shutdown_event.wait(900)
    time.sleep(3)
    num_children = len(get_child_process_info().keys())
    if num_children > 0:
        log.debug(f"There are still {num_children} children alive - sending SIGTERM followed by SIGKILL")
        cloudkeeper.signal.kill_children(SIGTERM)
        time.sleep(2)
        cloudkeeper.signal.kill_children(SIGKILL)
    log.info("Shutdown complete")
    quit()


def shutdown(event: Event) -> None:
    reason = event.data.get("reason")
    emergency = event.data.get("emergency")

    if emergency:
        log.fatal(f"EMERGENCY SHUTDOWN: {reason}")
        os.killpg(os.getpgid(0), SIGKILL)

    current_pid = os.getpid()
    if current_pid != cloudkeeper.signal.parent_pid:
        return

    if reason is None:
        reason = "unknown reason"
    log.info(f"Received shut down event {event.event_type}: {reason} - killing all threads and child processes")
    # Send 'friendly' SIGUSR1 to children to have them shut down
    cloudkeeper.signal.kill_children(SIGUSR1)
    kt = threading.Thread(target=force_shutdown, name="shutdown")
    kt.start()
    shutdown_event.set()  # and then end the program


def force_shutdown(delay: int = 10) -> None:
    time.sleep(delay)
    log_stats()
    log.error("Some child process or thread timed out during shutdown")
    cloudkeeper.signal.kill_children(SIGKILL)
    os._exit(0)


if __name__ == "__main__":
    main()
