import time
from abc import ABC, abstractmethod
from enum import Enum, auto
from threading import Thread, current_thread
from typing import Dict, Optional, Set

from prometheus_client import Counter

import resotolib.config
import resotolib.proc
from resotolib.args import ArgumentParser
from resotolib.baseresources import BaseResource, Cloud
from resotolib.config import Config
from resotolib.core import resotocore
from resotolib.core.actions import CoreActions
from resotolib.core.ca import TLSData
from resotolib.graph import Graph
from resotolib.logger import log

# from multiprocessing import Process

metrics_unhandled_plugin_exceptions = Counter(
    "resoto_unhandled_plugin_exceptions_total",
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
    POST_COLLECT = auto()


class BasePlugin(ABC, Thread):
    """A resoto Plugin is a thread that does some work.

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
    action = NotImplemented  # Name of the action this plugin implements

    def __init__(self, tls_data: Optional[TLSData] = None) -> None:
        super().__init__()
        self._args = ArgumentParser.args
        self._config = resotolib.config._config
        self.name = self.__class__.__name__
        self.finished = False
        self.timeout = Config.resotoworker.timeout
        self.wait_for_completion = True
        self.tls_data = tls_data

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
            # ArgumentParser.args = self._args
            # resotolib.config._config = self._config
            # setup_logger("resotoworker")
            # resotolib.proc.initializer()
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
            resotocore_uri=resotocore.http_uri,
            resotocore_ws_uri=resotocore.ws_uri,
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
    """A resoto Collector plugin is a thread that collects cloud resources.

    Whenever the thread is started the collect() method is run. The collect() method
    is expected to add cloud resources to self.graph. Cloud resources must inherit
    the BaseResource or one of the more specific resource types like BaseAccount,
    BaseInstance, BaseNetwork, BaseLoadBalancer, etc.

    When the collect() method finishes, the Collector will retrieve the
    Plugins Graph and append it to the global Graph.
    """

    plugin_type = PluginType.COLLECTOR  # Type of the Plugin
    cloud: str = NotImplemented  # Name of the cloud this plugin implements

    def __init__(self) -> None:
        super().__init__()
        self.name = str(self.cloud)
        cloud = Cloud(id=self.cloud)
        self.root = cloud
        self.graph = Graph(root=self.root)

    @abstractmethod
    def collect(self) -> None:
        """Collects all the Cloud Resources"""
        pass

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


class BasePostCollectPlugin(ABC):
    """A resoto Post Collect plugin is a thread that runs after collection is done.

    Whenever the thread is started the post_collect() method is run. The post_collect() method
    is expected take the graph and perform operations on it, e.g. add the external edges or
    enritch the graph in some other way.
    """

    plugin_type = PluginType.POST_COLLECT  # Type of the Plugin
    name: str = NotImplemented  # Name of the cloud this plugin implements
    activate_with: Set[str]  # List of clouds this plugin should be activated on

    def __init__(self) -> None:
        super().__init__()
        self.name = self.name

    @abstractmethod
    def post_collect(self, graph: Graph) -> None:
        """Process the collected graph"""
        pass

    @staticmethod
    def add_args(arg_parser: ArgumentParser) -> None:
        """Adds Plugin specific arguments to the global arg parser"""
        pass

    @staticmethod
    def add_config(config: Config) -> None:
        """Adds Plugin specific config options"""
        pass
