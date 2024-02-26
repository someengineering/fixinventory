import time
from abc import ABC, abstractmethod
from enum import Enum, auto
from queue import Queue
from threading import Thread, current_thread
from typing import Dict, Optional, Any

from prometheus_client import Counter

import fixlib.config
import fixlib.proc
from fixlib.args import ArgumentParser
from fixlib.baseresources import BaseResource, Cloud
from fixlib.config import Config
from fixlib.core import fixcore
from fixlib.core.actions import CoreActions
from fixlib.core.ca import TLSData
from fixlib.graph import Graph, GraphMergeKind
from fixlib.logger import log
from fixlib.types import Json

metrics_unhandled_plugin_exceptions = Counter(
    "fix_unhandled_plugin_exceptions_total",
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
    """A fix Plugin is a thread that does some work.

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
    def add_args(arg_parser: ArgumentParser) -> None:
        """Adds Plugin specific arguments to the global arg parser"""
        pass

    @staticmethod
    def add_config(config: Config) -> None:
        """Adds Plugin specific config options"""
        pass


class BaseActionPlugin(ABC, Thread):
    plugin_type = PluginType.ACTION
    action: str = NotImplemented  # Name of the action this plugin implements

    def __init__(self, tls_data: Optional[TLSData] = None) -> None:
        super().__init__()
        self._args = ArgumentParser.args
        self._config = fixlib.config._config
        self.name = self.__class__.__name__
        self.finished = False
        self.timeout = Config.fixworker.timeout
        self.wait_for_completion = True
        self.tls_data = tls_data

    @abstractmethod
    def do_action(self, data: Dict[str, Any]) -> None:
        """Perform an action"""
        pass

    def action_processor(self, message: Json) -> Optional[Json]:
        """Process incoming action messages"""
        if not isinstance(message, dict):
            log.error(f"Invalid message: {message}")
            return None
        kind = message.get("kind")
        message_type = message.get("message_type")
        data: Json = message.get("data", {})
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

            return {
                "kind": reply_kind,
                "message_type": message_type,
                "data": data,
            }
        else:
            return None

    def run(self) -> None:
        try:
            # ArgumentParser.args = self._args
            # fixlib.config._config = self._config
            # setup_logger("fixworker")
            # fixlib.proc.initializer()
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
            identifier=f"{ArgumentParser.args.subscriber_id}-actions-{self.action}-{self.name}",
            fixcore_uri=fixcore.http_uri,
            fixcore_ws_uri=fixcore.ws_uri,
            actions={
                self.action: {
                    "timeout": self.timeout,
                    "wait_for_completion": self.wait_for_completion,
                },
            },
            message_processor=self.action_processor,
            tls_data=self.tls_data,
        )
        core_actions.start()
        core_actions.join()

    @staticmethod
    def add_args(arg_parser: ArgumentParser) -> None:
        """Adds Plugin specific arguments to the global arg parser"""
        pass

    @staticmethod
    def add_config(config: Config) -> None:
        """Adds Plugin specific config options"""
        pass


class BaseCollectorPlugin(BasePlugin):
    """A fix Collector plugin is a thread that collects cloud resources.

    Whenever the thread is started the collect() method is run. The collect() method
    is expected to add cloud resources to self.graph. Cloud resources must inherit
    the BaseResource or one of the more specific resource types like BaseAccount,
    BaseInstance, BaseNetwork, BaseLoadBalancer, etc.

    When the collect() method finishes, the Collector will retrieve the
    Plugins Graph and append it to the global Graph.
    """

    plugin_type = PluginType.COLLECTOR  # Type of the Plugin
    cloud: str = NotImplemented  # Name of the cloud this plugin implements

    def __init__(
        self,
        graph_queue: Optional[Queue[Optional[Graph]]] = None,
        graph_merge_kind: GraphMergeKind = GraphMergeKind.cloud,
        task_data: Optional[Json] = None,
    ) -> None:
        super().__init__()
        self.name = str(self.cloud)
        cloud = Cloud(id=self.cloud)
        self.root = cloud
        self._graph_queue: Optional[Queue[Optional[Graph]]] = graph_queue
        self.graph_merge_kind: GraphMergeKind = graph_merge_kind
        self.graph = self.new_graph()
        self.task_data = task_data

    @abstractmethod
    def collect(self) -> None:
        """Collects all the Cloud Resources"""
        pass

    @staticmethod
    def auto_enableable() -> bool:
        """Should this collector be enabled by default?"""
        return False

    @staticmethod
    def update_tag(config: Config, resource: BaseResource, key: str, value: str) -> bool:
        """Update the tag of a resource"""
        return resource.update_tag(key, value)

    @staticmethod
    def delete_tag(config: Config, resource: BaseResource, key: str) -> bool:
        """Delete the tag of a resource"""
        return resource.delete_tag(key)

    @staticmethod
    def pre_cleanup(config: Config, resource: BaseResource, graph: Graph) -> bool:
        return resource.pre_cleanup(graph)

    @staticmethod
    def cleanup(config: Config, resource: BaseResource, graph: Graph) -> bool:
        return resource.cleanup(graph)

    def go(self) -> None:
        self.collect()
        if self.graph_merge_kind == GraphMergeKind.cloud or len(self.graph) > 1:
            if self.graph_merge_kind == GraphMergeKind.account:
                log.debug("Using backwards compatibility mode")
            assert isinstance(self.graph.root, BaseResource)
            log.debug(f"Sending graph of {self.graph.root.kdname} to queue")
            self.send_graph(self.graph)

    def new_graph(self) -> Graph:
        return Graph(root=self.root)

    def send_account_graph(self, graph: Graph) -> None:
        if not isinstance(graph, Graph):
            log.error(f"Expected Graph, got {type(graph)}")
            return

        if self.graph_merge_kind == GraphMergeKind.account:
            assert isinstance(graph.root, BaseResource)
            kdname = graph.root.kdname
            cloud_graph = self.new_graph()
            cloud_graph.merge(graph, skip_deferred_edges=True)
            log.debug(f"Sending graph of {kdname} to queue")
            self.send_graph(cloud_graph)
        elif self.graph_merge_kind == GraphMergeKind.cloud:
            self.graph.merge(graph, skip_deferred_edges=True)
        else:
            raise ValueError(f"Unknown graph merge kind {self.graph_merge_kind}")

    def send_graph(self, graph: Graph) -> None:
        if self._graph_queue is None:
            raise RuntimeError("Unable to send graph - no graph queue set")
        if not isinstance(graph, Graph):
            raise TypeError(f"Unable to send graph - expected type Graph, got {type(graph)}")
        self._graph_queue.put(graph)
