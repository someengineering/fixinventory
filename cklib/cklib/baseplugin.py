from abc import ABC, abstractmethod
from enum import Enum, auto
from cklib.graph import Graph
from cklib.core.actions import CoreActions
from cklib.args import ArgumentParser
from cklib.logging import log, setup_logger
from cklib.baseresources import Cloud
from threading import Thread, current_thread
from multiprocessing import Process
from prometheus_client import Counter
import cklib.signal
import time
from typing import Dict

metrics_unhandled_plugin_exceptions = Counter(
    "cloudkeeper_unhandled_plugin_exceptions_total",
    "Unhandled plugin exceptions",
    ["plugin"],
)


class PluginType(Enum):
    """Defines Plugin Type

    COLLECTOR is a cloud resource collector plugin that gets instantiated
    on each collect() run
    PERSISTENT is a persistent plugin that gets instantiated once upon startup
    """

    COLLECTOR = auto()
    ACTION = auto()
    PERSISTENT = auto()
    CLI = auto()


class BasePlugin(ABC, Thread):
    """A cloudkeeper Plugin is a thread that does some work.

    If the plugin_type is PluginType.COLLECTOR the Plugin gets instantiated each
    collect run.
    If the plugin_type is PluginType.PERSISTENT the Plugin gets instantiated upon
    startup and is expected to run forever. It may register to any events it's
    interested in and act upon them.

    Upon start the go() method is called. For COLLECTOR Plugins collect() is called.
    """

    plugin_type = PluginType.PERSISTENT

    def __init__(self) -> None:
        super().__init__()
        self.name = self.__class__.__name__
        self.finished = False

    def run(self) -> None:
        try:
            self.go()
        except Exception:
            metrics_unhandled_plugin_exceptions.labels(plugin=self.name).inc()
            log.exception(f"Caught unhandled plugin exception in {self.name}")
        else:
            self.finished = True

    @abstractmethod
    def go(self) -> None:
        """Do the Plugin work"""
        pass

    @staticmethod
    @abstractmethod
    def add_args(arg_parser: ArgumentParser) -> None:
        """Adds Plugin specific arguments to the global arg parser"""
        pass


class BaseActionPlugin(ABC, Process):
    plugin_type = PluginType.ACTION
    action = NotImplemented  # Name of the action this plugin implements

    def __init__(self) -> None:
        super().__init__()
        self.args = ArgumentParser.args
        self.name = self.__class__.__name__

        self.finished = False
        self.timeout = ArgumentParser.args.timeout
        self.wait_for_completion = True

    @abstractmethod
    def do_action(self, data: Dict):
        """Perform an action"""
        pass

    def action_processor(self, message: Dict) -> None:
        """Process incoming action messages"""
        if not isinstance(message, dict):
            log.error(f"Invalid message: {message}")
            return
        kind = message.get("kind")
        message_type = message.get("message_type")
        data = message.get("data")
        log.debug(f"Received message of kind {kind}, type {message_type}, data: {data}")
        if kind == "action":
            try:
                if message_type == self.action:
                    start_time = time.time()
                    self.do_action(data)
                    run_time = int(time.time() - start_time)
                    log.debug(f"{self.action} ran for {run_time} seconds")
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

    def run(self) -> None:
        try:
            ArgumentParser.args = self.args
            setup_logger("ckworker")
            cklib.signal.initializer()
            current_thread().name = self.name
            if self.bootstrap():
                self.go()
        except Exception:
            metrics_unhandled_plugin_exceptions.labels(plugin=self.name).inc()
            log.exception(f"Caught unhandled plugin exception in {self.name}")
        else:
            self.finished = True

    @abstractmethod
    def bootstrap(self) -> bool:
        """Bootstrap the plugin.

        If bootstrapping is successful the plugin is ready to run.
        """
        pass

    def go(self) -> None:
        core_actions = CoreActions(
            identifier=f"{ArgumentParser.args.ckcore_subscriber_id}-actions-{self.action}-{self.name}",
            ckcore_uri=ArgumentParser.args.ckcore_uri,
            ckcore_ws_uri=ArgumentParser.args.ckcore_ws_uri,
            actions={
                self.action: {
                    "timeout": self.timeout,
                    "wait_for_completion": self.wait_for_completion,
                },
            },
            message_processor=self.action_processor,
        )
        core_actions.start()
        core_actions.join()


class BaseCollectorPlugin(BasePlugin):
    """A cloudkeeper Collector plugin is a thread that collects cloud resources.

    Whenever the thread is started the collect() method is run. The collect() method
    is expected to add cloud resources to self.graph. Cloud resources must inherit
    the BaseResource or one of the more specific resource types like BaseAccount,
    BaseInstance, BaseNetwork, BaseLoadBalancer, etc.

    When the collect() method finishes, the Collector will retrieve the
    Plugins Graph and append it to the global Graph.
    """

    plugin_type = PluginType.COLLECTOR  # Type of the Plugin
    cloud = NotImplemented  # Name of the cloud this plugin implements

    def __init__(self) -> None:
        super().__init__()
        self.name = str(self.cloud)
        cloud = Cloud(self.cloud, _replace=True)
        self.root = cloud
        self.graph = Graph(root=self.root)

    @abstractmethod
    def collect(self) -> None:
        """Collects all the Cloud Resources"""
        pass

    def go(self) -> None:
        self.collect()


class BaseCliPlugin(ABC):
    """A cloudkeeper CLI plugin adds new commands to the built-in CLI.

    The plugin has references to the current graph, scheduler and CLI clipboard.
    Every function that is prefixed with the string 'cmd_' will become a new CLI
    command.

    Signature and example implementation is as follows:
        def cmd_example(self, items: Iterable, args: str) -> Iterable:
            '''Usage: | example <string>

            Example command that lists all resources whose name starts with <string>.
            '''
            for item in items:
                if isinstance(item, BaseResource) and item.name.startswith(args):
                    yield item

    items is usually a generator function being passed in from the previous command.
    If this is the first command in the chain then items contains all of the graphs
    resources.

    Args is the string that the user input after the command.
    For instance when calling `> example foo --bar` args of cmd_example would be
    'foo --bar'.

    The function has to take care of tokenizing the string if desired.
    The functions docstring is being displayed when the user enters `help example`.

    Like every plugin CLI plugins can specify cloudkeeper args by implementing
    the add_args() method.
    """

    plugin_type = PluginType.CLI

    def __init__(self, graph: Graph, scheduler, clipboard) -> None:
        super().__init__()
        self.graph = graph
        self.scheduler = scheduler
        self.clipboard = clipboard

    @staticmethod
    @abstractmethod
    def add_args(arg_parser: ArgumentParser) -> None:
        """Adds Plugin specific arguments to the global arg parser"""
        pass
