import cloudkeeper.logging
from abc import ABC, abstractmethod
from enum import Enum, auto
from cloudkeeper.graph import Graph, get_resource_attributes
from cloudkeeper.args import ArgumentParser
from cloudkeeper.baseresources import Cloud
from threading import Thread
from prometheus_client import Counter

log = cloudkeeper.logging.getLogger(__name__)
metrics_unhandled_plugin_exceptions = Counter(
    "cloudkeeper_unhandled_plugin_exceptions_total", "Unhandled Plugin Exceptions", ["plugin"]
)


class PluginType(Enum):
    """Defines Plugin Type

    COLLECTOR is a Cloud Resource Collector Plugin that gets instantiated on each collect() run
    PERSISTENT is a Persistent Plugin that gets instantiated once upon startup
    """

    COLLECTOR = auto()
    PERSISTENT = auto()


class BasePlugin(ABC, Thread):
    """A cloudkeeper Plugin is a thread that does some work.

    If the plugin_type is PluginType.COLLECTOR the Plugin gets instantiated each collect run.
    If the plugin_type is PluginType.PERSISTENT the Plugin gets instantiated upon startup and is expected
    to run forever. It may register to any events it's interested in and act upon them.

    Upon start the go() method is called. For COLLECTOR Plugins collect() is called.
    """

    plugin_type = PluginType.PERSISTENT

    def __init__(self) -> None:
        super().__init__()
        self.name = __name__

    def run(self) -> None:
        try:
            self.go()
        except Exception:
            metrics_unhandled_plugin_exceptions.labels(plugin=self.name).inc()
            log.exception(f"Caught unhandled plugin exception in {self.name}")

    @abstractmethod
    def go(self) -> None:
        """Do the Plugin work"""
        pass

    @staticmethod
    @abstractmethod
    def add_args(arg_parser: ArgumentParser) -> None:
        """Adds Plugin specific arguments to the global arg parser"""
        pass


class BaseCollectorPlugin(BasePlugin):
    """A cloudkeeper Collector Plugin is a thread that collects cloud resources.

    Whenever the thread is started the collect() method is run. The collect() method is expected to add
    cloud resources to self.graph. Cloud resources must inherit the BaseResource or one of the more specific
    resource types like BaseAccount, BaseInstance, BaseNetwork, BaseLoadBalancer, etc.

    When the collect() method finishes, the Collector will retrieve the
    Plugins Graph and append it to the global Graph.
    """

    plugin_type = PluginType.COLLECTOR  # Type of the Plugin
    cloud = NotImplemented  # Name of the cloud this plugin implements

    def __init__(self) -> None:
        super().__init__()
        self.name = str(self.cloud)
        self.root = Cloud(self.cloud, {})
        self.graph = Graph()
        self.finished = False
        resource_attributes = get_resource_attributes(self.root)
        self.graph.add_node(self.root, label=self.root.id, **resource_attributes)

    @abstractmethod
    def collect(self) -> None:
        """Collects all the Cloud Resources"""
        pass

    def go(self) -> None:
        self.collect()
        self.finished = True
