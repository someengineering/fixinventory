import sys
import logging
import time
import os
import resource
import threading
from signal import signal, getsignal, SIGINT, SIGTERM, SIGKILL, SIGUSR1
from cloudkeeper.graph import GraphContainer
from cloudkeeper.pluginloader import PluginLoader
from cloudkeeper.baseplugin import PluginType
from cloudkeeper.web import WebServer
from cloudkeeper.scheduler import Scheduler
from cloudkeeper.args import get_arg_parser, ArgumentParser
from cloudkeeper.processor import Processor
from cloudkeeper.cleaner import Cleaner
from cloudkeeper.metrics import GraphCollector
from cloudkeeper.utils import log_stats, signal_on_parent_exit
from cloudkeeper.cli import Cli
from cloudkeeper.event import add_event_listener, dispatch_event, Event, EventType, add_args as event_add_args
from prometheus_client import REGISTRY


# Try to run in a new process group
try:
    os.setpgid(0, 0)
except (PermissionError, AttributeError):
    pass

log_format = '%(asctime)s - %(levelname)s - %(process)d/%(threadName)s - %(message)s'
logging.basicConfig(level=logging.WARN, format=log_format)
logging.getLogger('cloudkeeper').setLevel(logging.INFO)
log = logging.getLogger(__name__)

# Plugins might produce debug logging during arg parsing so we manually
# look for verbosity and set the log level before using the arg parser.
argv = sys.argv[1:]
if '-v' in argv or '--verbose' in argv:
    logging.getLogger('cloudkeeper').setLevel(logging.DEBUG)

# This will be used in main() and signal_handler()
shutdown_event = threading.Event()
parent_pid = os.getpid()
original_sigint_handler = getsignal(SIGINT)
original_sigterm_handler = getsignal(SIGTERM)


def main() -> None:
    # Add cli args
    arg_parser = get_arg_parser()

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

    # Write log to a file in addition to stdout
    if ArgumentParser.args.logfile:
        log_formatter = logging.Formatter(log_format)
        fh = logging.FileHandler(ArgumentParser.args.logfile)
        fh.setFormatter(log_formatter)
        logging.getLogger().addHandler(fh)

    # Handle Ctrl+c and other means of termination/shutdown
    signal_on_parent_exit()
    add_event_listener(EventType.SHUTDOWN, shutdown, blocking=False)
    signal(SIGINT, signal_handler)
    signal(SIGTERM, signal_handler)
    signal(SIGUSR1, signal_handler)

    # Try to increase nofile limit
    nofile_soft, nofile_hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    try:
        if nofile_soft < nofile_hard:
            log.debug(f'Increasing RLIMIT_NOFILE {nofile_soft} -> {nofile_hard}')
            resource.setrlimit(resource.RLIMIT_NOFILE, (nofile_hard, nofile_hard))
    except (ValueError):
        log.error(f'Failed to increase RLIMIT_NOFILE {nofile_soft} -> {nofile_hard}')

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
            log.debug(f'Starting persistent Plugin {Plugin}')
            plugin = Plugin()
            plugin.daemon = True
            plugin.start()
        except Exception as e:
            log.exception(f'Caught unhandled persistent Plugin exception {e}')

    collector = Processor(graph_container, plugin_loader.plugins(PluginType.COLLECTOR))
    collector.daemon = True
    collector.start()

    # Dispatch the STARTUP event
    dispatch_event(Event(EventType.STARTUP))

    # We wait for the shutdown Event to be set() and then end the program
    # While doing so we print the list of active threads once per 15 minutes
    while not shutdown_event.is_set():
        log_stats()
        shutdown_event.wait(900)
    time.sleep(5)
    log.info('Shutdown complete')
    quit()


def shutdown(event: Event) -> None:
    reason = event.data.get('reason')
    emergency = event.data.get('emergency')

    if emergency:
        log.fatal(f'EMERGENCY SHUTDOWN: {reason}')
        os.killpg(os.getpgid(0), SIGKILL)

    current_pid = os.getpid()
    if current_pid != parent_pid:
        return

    if reason is None:
        reason = 'unknown reason'
    log.info(f'Received shut down event {event.event_type}: {reason} - killing all threads and child processes')
    os.killpg(os.getpgid(0), SIGUSR1)
    kt = threading.Thread(target=force_shutdown, name='shutdown')
    kt.start()
    shutdown_event.set()  # and then end the program


def force_shutdown(delay: int = 10) -> None:
    time.sleep(delay)
    log_stats()
    log.error('Some child process or thread timed out during shutdown - killing process group')
    os.killpg(os.getpgid(0), SIGKILL)
    os._exit(0)


def delayed_exit(delay: int = 3) -> None:
    time.sleep(delay)
    os._exit(0)


def signal_handler(sig, frame) -> None:
    """Handles Ctrl+c by letting the Collector() know to shut down"""
    signal(SIGINT, original_sigint_handler)
    signal(SIGTERM, original_sigterm_handler)

    current_pid = os.getpid()
    if current_pid == parent_pid:
        if sig != SIGUSR1:
            reason = f'Received shutdown signal {sig}'
            log.debug(f'Parent caught signal {sig} - dispatching shutdown event')
            # Dispatch shutdown event in parent process which also causes SIGUSR1 to be sent to
            # the process group and in turn causes the shutdown event in all child processes.
            dispatch_event(Event(EventType.SHUTDOWN, {'reason': reason, 'emergency': False}))
        else:
            log.debug('Parent received SIGUSR1 and ignoring it')
    else:
        if sig != SIGUSR1:
            reason = f'Received unexpected shutdown signal {sig} of unknown origin - OOM killer?'
            log.error(reason)
        else:
            reason = f'Received shutdown signal {sig} from parent process'
        log.debug(f"Shutting down child process {current_pid} - you might see exceptions from interrupted worker threads")        
        # Child's threads have 3s to shut down before the following thread will shut them down hard.
        kt = threading.Thread(target=delayed_exit, name='shutdown')
        kt.start()
        # Dispatch shutdown event in child process
        dispatch_event(Event(EventType.SHUTDOWN, {'reason': reason, 'emergency': False}), blocking=False)
        sys.exit(0)


if __name__ == '__main__':
    main()
