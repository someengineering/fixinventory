import os
import sys
import threading
import multiprocessing
import cherrypy  # type: ignore
import time
import requests
import fixlib.proc
from functools import partial
from queue import Queue
from signal import SIGTERM
from typing import List, Dict, Type, Optional, Any, Callable
from multiprocessing.managers import SyncManager
from fixlib.args import ArgumentParser
from fixlib.baseplugin import BaseActionPlugin, BaseCollectorPlugin, PluginType
from fixlib.config import Config
from fixlib.core import add_args as core_add_args, fixcore, wait_for_fixcore
from fixlib.core.actions import CoreActions, CoreFeedback
from fixlib.core.ca import TLSData
from fixlib.core.tasks import CoreTasks, CoreTaskHandler
from fixlib.event import add_event_listener, Event, EventType, dispatch_event
from fixlib.jwt import add_args as jwt_add_args
from fixlib.logger import log, setup_logger, add_args as logging_add_args
from fixlib.core.custom_command import command_definitions
from fixlib.proc import log_stats
from fixlib.types import Json
from fixlib.web import WebServer
from fixlib.web.metrics import WebApp
from fixworker.cleanup import cleanup
from fixworker.collect import Collector
from fixworker.config import add_config
from fixworker.utils import write_files_to_home_dir, write_utf8_file
from fixworker.pluginloader import PluginLoader
from fixworker.fixcore import FixCore
from fixworker.tag import core_tag_tasks_processor
from fixworker.exceptions import DuplicateMessageError
from fixlib.utils import ensure_bw_compat

# This will be used in main() and shutdown()
shutdown_event = threading.Event()
collect_event = threading.Event()
exit_code = 0


def main() -> None:
    ensure_bw_compat()
    setup_logger("fixworker")
    # Try to run in a new process group and
    # ignore if not possible for whatever reason
    try:
        os.setpgid(0, 0)
    except Exception:
        pass

    fixlib.proc.parent_pid = os.getpid()

    arg_parser = ArgumentParser(
        description=("Fix Inventory Worker: Collects data from cloud providers and sends it to the Core"),
        env_args_prefix="FIXWORKER_",
    )
    add_args(arg_parser)
    jwt_add_args(arg_parser)
    logging_add_args(arg_parser)
    core_add_args(arg_parser)
    Config.add_args(arg_parser)
    TLSData.add_args(arg_parser)

    # Find fix Plugins in the fix.plugins module
    plugin_loader = PluginLoader()
    plugin_loader.add_plugin_args(arg_parser)

    # At this point the CLI, all Plugins as well as the WebServer have
    # added their args to the arg parser
    arg_parser.parse_args()

    # Register functions to detect system healthiness
    health_conditions: Dict[str, Callable[[], bool]] = {}

    try:
        wait_for_fixcore(fixcore.http_uri)
    except TimeoutError as e:
        log.fatal(f"Failed to connect to fixcore: {e}")
        sys.exit(1)

    tls_data: Optional[TLSData] = None
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
    health_conditions["Config Listener"] = config.connected

    add_config(config, plugin_loader.all_collector_plugins())
    plugin_loader.add_plugin_config(config)
    config.load_config()

    write_files_to_home_dir(config.fixworker.all_files_in_home_dir(), write_utf8_file)

    def send_request(request: requests.Request) -> requests.Response:
        prepared = request.prepare()
        s = requests.Session()
        verify = None
        if tls_data:
            verify = tls_data.verify
        return s.send(request=prepared, verify=verify)

    core = FixCore(send_request, config)

    # the multiprocessing manager is used to share data between processes
    ctx = multiprocessing.get_context("spawn")
    mp_manager = SyncManager(ctx=ctx)
    mp_manager.start(initializer=fixlib.proc.increase_limits)
    core_messages: Queue[Json] = mp_manager.Queue()

    collector = Collector(config, core, core_messages)

    # Handle Ctrl+c and other means of termination/shutdown
    fixlib.proc.initializer()
    add_event_listener(EventType.SHUTDOWN, shutdown, blocking=False)

    web_server_args = {}
    if tls_data and not Config.fixworker.no_tls:
        web_server_args = {
            "ssl_cert": tls_data.cert_path,
            "ssl_key": tls_data.key_path,
        }
    web_server = WebServer(
        WorkerWebApp(
            mountpoint=Config.fixworker.web_path,
            plugin_loader=plugin_loader,
            health_conditions=health_conditions,
        ),
        web_host=Config.fixworker.web_host,
        web_port=Config.fixworker.web_port,
        ssl_cert=web_server_args.get("ssl_cert"),
        ssl_key=web_server_args.get("ssl_key"),
    )
    web_server.daemon = True
    web_server.start()

    core_actions = CoreActions(
        identifier=f"{ArgumentParser.args.subscriber_id}-collector",
        fixcore_uri=fixcore.http_uri,
        fixcore_ws_uri=fixcore.ws_uri,
        actions={
            "collect": {
                "timeout": Config.fixworker.timeout,
                "wait_for_completion": True,
            },
            "cleanup": {
                "timeout": Config.fixworker.timeout,
                "wait_for_completion": True,
            },
        },
        message_processor=partial(core_actions_processor, config, plugin_loader, tls_data, collector),
        tls_data=tls_data,
        incoming_messages=core_messages,
    )
    health_conditions["CoreActions"] = core_actions.connected

    # make tagging by collectors available out of the box
    collect_plugins: List[BaseCollectorPlugin] = plugin_loader.plugins(PluginType.COLLECTOR)  # type: ignore
    task_handler = [
        CoreTaskHandler(
            name="tag",
            info="already provided",
            description="already provided",
            filter={"cloud": [plugin.cloud]},
            expect_node_result=True,
            handler=partial(core_tag_tasks_processor, plugin, config),
        )
        for plugin in collect_plugins
    ]
    # search all other plugins for possible task providers
    for plugin_clazz in plugin_loader.all_plugins():
        plugin = plugin_clazz()
        for wtd in command_definitions(plugin_clazz):
            handler = CoreTaskHandler.from_definition(plugin, wtd)
            log.info(f"Plugin {plugin.name}: Add task handler for task {handler.name} @ {handler.filter}")
            task_handler.append(handler)

    core_tasks = CoreTasks(
        identifier=f"{ArgumentParser.args.subscriber_id}-task-handler",
        fixcore_ws_uri=fixcore.ws_uri,
        task_handler=task_handler,
        tls_data=tls_data,
    )
    core_actions.start()
    core_tasks.start()
    health_conditions["CoreTasks"] = core_tasks.connected

    for plugin_class in plugin_loader.plugins(PluginType.ACTION):
        assert issubclass(plugin_class, BaseActionPlugin)
        try:
            log.debug(f"Starting action plugin {plugin_class}")
            plugin = plugin_class(tls_data=tls_data)
            plugin.start()
        except Exception as e:
            log.exception(f"Caught unhandled persistent Plugin exception {e}")

    wait_for_idle_timeout(ArgumentParser.args.idle_timeout)
    # We wait for the shutdown Event to be set() and then end the program
    # While doing so we print the list of active threads once per 15 minutes
    shutdown_event.wait()
    web_server.shutdown()
    time.sleep(1)  # everything gets 1000ms to shutdown gracefully before we force it
    mp_manager.shutdown()
    fixlib.proc.kill_children(SIGTERM, ensure_death=True)
    log.info("Shutdown complete")
    os._exit(exit_code)


def core_actions_processor(
    config: Config,
    plugin_loader: PluginLoader,
    tls_data: Optional[TLSData],
    collector: Collector,
    message: Dict[str, Any],
) -> Optional[Dict[str, Any]]:
    collectors: List[Type[BaseCollectorPlugin]] = plugin_loader.plugins(PluginType.COLLECTOR)  # type: ignore
    # todo: clean this up
    if not isinstance(message, dict):
        log.error(f"Invalid message: {message}")
        return None
    kind = message.get("kind")
    message_type = message.get("message_type")
    data = message.get("data") or {}
    task_id: str = data.get("task")  # type: ignore
    step_name: str = data.get("step")  # type: ignore

    log.debug(f"Received message of kind {kind}, type {message_type}, data: {data}")
    if kind == "action":
        try:
            if message_type == "collect":
                if len(collectors) == 0:
                    log.error("No collector plugins loaded or configured - skipping collect")
                    return None
                if config.fixworker.pool_size == 0:
                    log.error("Zero workers configured - skipping collect")
                    return None
                collect_event.set()
                start_time = time.time()
                collector.collect_and_send(collectors, task_data=data)
                run_time = int(time.time() - start_time)
                log.info(f"Collect ran for {run_time} seconds")
            elif message_type == "cleanup":
                if not Config.fixworker.cleanup:
                    log.info("Cleanup called but disabled in config (fixworker.cleanup) - skipping")
                else:
                    if Config.fixworker.cleanup_dry_run:
                        log.info("Cleanup called with dry run configured (fixworker.cleanup_dry_run)")
                    start_time = time.time()
                    feedback = CoreFeedback(task_id, step_name, "cleanup", collector.core_messages)
                    cleanup(
                        config,
                        {p.cloud: p for p in collectors},
                        feedback,
                        tls_data=tls_data,
                    )
                    run_time = int(time.time() - start_time)
                    log.info(f"Cleanup ran for {run_time} seconds")
            else:
                raise ValueError(f"Unknown message type {message_type}")
        except DuplicateMessageError as e:
            log.warning(e)
            return None
        except Exception as e:
            msg = f"Failed to {message_type}: {e}"
            data["error"] = msg
            log.exception(msg)
            reply_kind = "action_error"
        else:
            reply_kind = "action_done"

        reply_message = {
            "kind": reply_kind,
            "message_type": message_type,
            "data": data,
        }
        return reply_message
    return None


def shutdown(event: Event) -> None:
    reason = str(event.data.get("reason"))
    emergency = event.data.get("emergency")

    if emergency:
        fixlib.proc.emergency_shutdown(reason)

    current_pid = os.getpid()
    if current_pid != fixlib.proc.parent_pid:
        return

    if reason is None:
        reason = "unknown reason"
    log.info((f"Received shut down event {event.event_type}:" f" {reason} - killing all threads and child processes"))
    shutdown_event.set()  # and then end the program


def force_shutdown(delay: int = 10) -> None:
    time.sleep(delay)
    log_stats()
    log.error(("Some child process or thread timed out during shutdown" " - forcing shutdown completion"))
    os._exit(exit_code)


def wait_for_idle_timeout(idle_timeout: Optional[int]) -> None:
    def check_idle_timeout() -> None:
        global exit_code
        if not collect_event.is_set():
            log.warning("Idle timeout reached - shutting down")
            exit_code = 1
            dispatch_event(
                Event(EventType.SHUTDOWN, {"reason": "idle timeout reached", "emergency": False}),
                blocking=False,
            )

    if idle_timeout is None or idle_timeout <= 0:
        return

    log.debug(f"Running idle timeout check in {idle_timeout} seconds")
    threading.Timer(idle_timeout, check_idle_timeout).start()


def add_args(arg_parser: ArgumentParser) -> None:
    arg_parser.add_argument(
        "--subscriber-id",
        help="Unique subscriber ID (default: fix.worker)",
        default="fix.worker",
        dest="subscriber_id",
        type=str,
    )
    arg_parser.add_argument(
        "--idle-timeout",
        help="Time limit in seconds to wait for a collect task after startup (default: no limit)",
        dest="idle_timeout",
        type=int,
    )


class WorkerWebApp(WebApp):
    def __init__(self, *args, plugin_loader: PluginLoader, **kwargs) -> None:  # type: ignore
        super().__init__(*args, **kwargs)
        self.plugin_loader = plugin_loader

    @cherrypy.expose  # type: ignore
    @cherrypy.tools.json_out()  # type: ignore
    @cherrypy.tools.allow(methods=["GET"])  # type: ignore
    def info(self) -> Dict[str, List[str]]:
        active_collectors: List[str] = [
            plugin.cloud for plugin in self.plugin_loader.plugins(PluginType.COLLECTOR)  # type: ignore
        ]
        all_collectors: List[str] = [
            plugin.cloud for plugin in self.plugin_loader.all_plugins(PluginType.COLLECTOR)  # type: ignore
        ]
        return {"active_collectors": active_collectors, "all_collectors": all_collectors}


if __name__ == "__main__":
    main()
