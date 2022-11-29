import multiprocessing
import os
import sys
import threading
import cherrypy  # type: ignore
import time
from functools import partial
from queue import Queue
from signal import SIGTERM
from typing import List, Dict, Type, Optional, Any

import requests

import resotolib.proc
from resotolib.args import ArgumentParser
from resotolib.baseplugin import BaseActionPlugin, BasePostCollectPlugin, BaseCollectorPlugin, PluginType
from resotolib.config import Config
from resotolib.core import add_args as core_add_args, resotocore, wait_for_resotocore
from resotolib.core.actions import CoreActions, CoreFeedback
from resotolib.core.ca import TLSData
from resotolib.core.tasks import CoreTasks, CoreTaskHandler
from resotolib.event import (
    add_event_listener,
    Event,
    EventType,
)
from resotolib.jwt import add_args as jwt_add_args
from resotolib.logger import log, setup_logger, add_args as logging_add_args
from resotolib.core.custom_command import command_definitions
from resotolib.proc import log_stats, increase_limits
from resotolib.types import Json
from resotolib.web import WebServer
from resotolib.web.metrics import WebApp
from resotoworker.cleanup import cleanup
from resotoworker.collect import Collector
from resotoworker.config import add_config
from resotoworker.pluginloader import PluginLoader
from resotoworker.resotocore import Resotocore
from resotoworker.tag import core_tag_tasks_processor

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

    resotolib.proc.parent_pid = os.getpid()

    arg_parser = ArgumentParser(
        description="resoto worker",
        env_args_prefix="RESOTOWORKER_",
    )
    add_args(arg_parser)
    jwt_add_args(arg_parser)
    logging_add_args(arg_parser)
    core_add_args(arg_parser)
    Config.add_args(arg_parser)
    TLSData.add_args(arg_parser)

    # Find resoto Plugins in the resoto.plugins module
    plugin_loader = PluginLoader()
    plugin_loader.add_plugin_args(arg_parser)

    # At this point the CLI, all Plugins as well as the WebServer have
    # added their args to the arg parser
    arg_parser.parse_args()

    try:
        wait_for_resotocore(resotocore.http_uri)
    except TimeoutError as e:
        log.fatal(f"Failed to connect to resotocore: {e}")
        sys.exit(1)

    tls_data: Optional[TLSData] = None
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
    add_config(config)
    plugin_loader.add_plugin_config(config)
    config.load_config()

    def send_request(request: requests.Request) -> requests.Response:
        prepared = request.prepare()
        s = requests.Session()
        verify = None
        if tls_data:
            verify = tls_data.verify
        return s.send(request=prepared, verify=verify)

    core = Resotocore(send_request, config)

    # the multiprocessing manager is used to share data between processes
    mp_manager = multiprocessing.Manager()
    core_messages: Queue[Json] = mp_manager.Queue()

    collector = Collector(config, core.send_to_resotocore, core_messages)

    # Handle Ctrl+c and other means of termination/shutdown
    resotolib.proc.initializer()
    add_event_listener(EventType.SHUTDOWN, shutdown, blocking=False)

    # Try to increase nofile and nproc limits
    increase_limits()

    web_server_args = {}
    if tls_data and not Config.resotoworker.no_tls:
        web_server_args = {
            "ssl_cert": tls_data.cert_path,
            "ssl_key": tls_data.key_path,
        }
    web_server = WebServer(
        WorkerWebApp(mountpoint=Config.resotoworker.web_path, plugin_loader=plugin_loader),
        web_host=Config.resotoworker.web_host,
        web_port=Config.resotoworker.web_port,
        **web_server_args,
    )
    web_server.daemon = True
    web_server.start()

    core_actions = CoreActions(
        identifier=f"{ArgumentParser.args.subscriber_id}-collector",
        resotocore_uri=resotocore.http_uri,
        resotocore_ws_uri=resotocore.ws_uri,
        actions={
            "collect": {
                "timeout": Config.resotoworker.timeout,
                "wait_for_completion": True,
            },
            "cleanup": {
                "timeout": Config.resotoworker.timeout,
                "wait_for_completion": True,
            },
        },
        message_processor=partial(core_actions_processor, config, plugin_loader, tls_data, collector),
        tls_data=tls_data,
        incoming_messages=core_messages,
    )

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
        resotocore_ws_uri=resotocore.ws_uri,
        task_handler=task_handler,
        tls_data=tls_data,
    )
    core_actions.start()
    core_tasks.start()

    for plugin_class in plugin_loader.plugins(PluginType.ACTION):
        assert issubclass(plugin_class, BaseActionPlugin)
        try:
            log.debug(f"Starting action plugin {plugin_class}")
            plugin = plugin_class(tls_data=tls_data)
            plugin.start()
        except Exception as e:
            log.exception(f"Caught unhandled persistent Plugin exception {e}")

    # We wait for the shutdown Event to be set() and then end the program
    # While doing so we print the list of active threads once per 15 minutes
    shutdown_event.wait()
    web_server.shutdown()  # type: ignore
    time.sleep(1)  # everything gets 1000ms to shutdown gracefully before we force it
    resotolib.proc.kill_children(SIGTERM, ensure_death=True)
    log.info("Shutdown complete")
    os._exit(0)


def core_actions_processor(
    config: Config,
    plugin_loader: PluginLoader,
    tls_data: Optional[TLSData],
    collector: Collector,
    message: Dict[str, Any],
) -> Optional[Dict[str, Any]]:
    collectors: List[Type[BaseCollectorPlugin]] = plugin_loader.plugins(PluginType.COLLECTOR)  # type: ignore
    post_collectors: List[Type[BasePostCollectPlugin]] = plugin_loader.plugins(PluginType.POST_COLLECT)  # type: ignore
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
                start_time = time.time()
                collector.collect_and_send(collectors, post_collectors, task_id=task_id, step_name=step_name)
                run_time = int(time.time() - start_time)
                log.info(f"Collect ran for {run_time} seconds")
            elif message_type == "cleanup":
                if not Config.resotoworker.cleanup:
                    log.info("Cleanup called but disabled in config" " (resotoworker.cleanup) - skipping")
                else:
                    if Config.resotoworker.cleanup_dry_run:
                        log.info("Cleanup called with dry run configured" " (resotoworker.cleanup_dry_run)")
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
    reason = event.data.get("reason")
    emergency = event.data.get("emergency")

    if emergency:
        resotolib.proc.emergency_shutdown(reason)

    current_pid = os.getpid()
    if current_pid != resotolib.proc.parent_pid:
        return

    if reason is None:
        reason = "unknown reason"
    log.info((f"Received shut down event {event.event_type}:" f" {reason} - killing all threads and child processes"))
    shutdown_event.set()  # and then end the program


def force_shutdown(delay: int = 10) -> None:
    time.sleep(delay)
    log_stats()
    log.error(("Some child process or thread timed out during shutdown" " - forcing shutdown completion"))
    os._exit(0)


def add_args(arg_parser: ArgumentParser) -> None:
    arg_parser.add_argument(
        "--subscriber-id",
        help="Unique subscriber ID (default: resoto.worker)",
        default="resoto.worker",
        dest="subscriber_id",
        type=str,
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
