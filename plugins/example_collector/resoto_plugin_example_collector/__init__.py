import resotolib.logging
from dataclasses import dataclass, field, InitVar
from datetime import datetime
from typing import ClassVar, Dict, List, Optional
from resotolib.baseplugin import BaseCollectorPlugin
from resotolib.graph import Graph, EdgeType
from resotolib.args import ArgumentParser
from resotolib.config import Config
from resotolib.baseresources import (
    BaseAccount,
    BaseRegion,
    BaseInstance,
    BaseNetwork,
    BaseResource,
    BaseVolume,
    InstanceStatus,
    VolumeStatus,
)

log = resotolib.logging.getLogger("resoto." + __name__)


class ExampleCollectorPlugin(BaseCollectorPlugin):
    cloud = "example"

    def collect(self) -> None:
        """This method is being called by resoto whenever the collector runs

        It is responsible for querying the cloud APIs for remote resources and adding
        them to the plugin graph.
        The graph root (self.graph.root) must always be followed by one or more
        accounts. An account must always be followed by a region.
        A region can contain arbitrary resources.
        """
        log.debug("plugin: collecting example resources")

        account = ExampleAccount("Example Account")
        self.graph.add_resource(self.graph.root, account)

        region1 = ExampleRegion(
            "us-west", name="US West", tags={"Some Tag": "Some Value"}
        )
        self.graph.add_resource(account, region1)

        region2 = ExampleRegion(
            "us-east", name="US East", tags={"Some Tag": "Some Value"}
        )
        self.graph.add_resource(account, region2)

        network1 = ExampleNetwork("someNetwork1", tags={"Name": "Example Network 1"})
        network2 = ExampleNetwork("someNetwork2", tags={"Name": "Example Network 2"})
        self.graph.add_resource(region1, network1)
        self.graph.add_resource(region2, network2)

        instance1 = ExampleInstance(
            "someInstance1",
            tags={"Name": "Example Instance 1", "expiration": "2d", "owner": "lukas"},
            ctime=datetime.utcnow(),
            atime=datetime.utcnow(),
            mtime=datetime.utcnow(),
            instance_cores=4,
            instance_memory=32,
            instance_status="running",
        )
        self.graph.add_resource(region1, instance1)
        self.graph.add_resource(network1, instance1)
        self.graph.add_resource(network1, instance1, edge_type=EdgeType.delete)

        instance2 = ExampleInstance(
            "someInstance2",
            {
                "Name": "Example Instance 2",
                "expiration": "36h",
                "resoto:ctime": "2019-09-05T10:40:11+00:00",
            },
            instance_status="stopped",
        )
        self.graph.add_resource(region2, instance2)
        self.graph.add_resource(network2, instance2)
        self.graph.add_resource(network2, instance2, edge_type=EdgeType.delete)

        volume1 = ExampleVolume(
            "someVolume1", tags={"Name": "Example Volume 1"}, volume_status="in-use"
        )
        self.graph.add_resource(region1, volume1)
        self.graph.add_edge(instance1, volume1)
        self.graph.add_edge(volume1, instance1, edge_type=EdgeType.delete)

        volume2 = ExampleVolume(
            "someVolume2", tags={"Name": "Example Volume 2"}, volume_status="available"
        )
        self.graph.add_resource(region2, volume2)
        self.graph.add_edge(instance2, volume2)
        self.graph.add_edge(volume2, instance2, edge_type=EdgeType.delete)

        custom_resource = ExampleCustomResource(
            "someExampleResource",
            custom_optional_float_attribute=10.0,
            custom_list_attribute=["foo", "bar"],
            init_only_attribute="Some Text",
        )
        self.graph.add_resource(region1, custom_resource)

    @staticmethod
    def add_args(arg_parser: ArgumentParser) -> None:
        """Example of how to use the ArgumentParser

        Can be accessed via ArgumentParser.args.example_arg
        Note: almost all plugin config should be done via add_config()
        so it can be changed centrally and at runtime.
        """
        arg_parser.add_argument(
            "--example-arg",
            help="Example Argument",
            dest="example_arg",
            type=str,
            default=None,
            nargs="+",
        )

    @staticmethod
    def add_config(config: Config) -> None:
        """Add any plugin config to the global config store.

        Method called by the PluginLoader upon plugin initialization.
        Can be used to introduce plugin config arguments to the global config store.
        """
        config.add_config(ExampleConfig)


@dataclass
class ExampleConfig:
    """Example of how to use the resotocore config service

    Can be accessed via Config.example.region
    """

    kind: ClassVar[str] = "example"
    region: Optional[List[str]] = field(
        default=None, metadata={"description": "Example Region"}
    )


@dataclass(eq=False)
class ExampleAccount(BaseAccount):
    """Some example account"""

    kind: ClassVar[str] = "example_account"

    def delete(self, graph: Graph) -> bool:
        return NotImplemented


@dataclass(eq=False)
class ExampleRegion(BaseRegion):
    """Some example region"""

    kind: ClassVar[str] = "example_region"

    def delete(self, graph: Graph) -> bool:
        """Regions can usually not be deleted so we return NotImplemented"""
        return NotImplemented


@dataclass(eq=False)
class ExampleResource:
    """A class that implements the abstract method delete() as well as update_tag()
    and delete_tag().

    delete() must be implemented. update_tag() and delete_tag() are optional.
    """

    kind: ClassVar[str] = "example_resource"

    def delete(self, graph: Graph) -> bool:
        """Delete a resource in the cloud"""
        log.debug(
            f"Deleting resource {self.id} in account {self.account(graph).id} region {self.region(graph).id}"
        )
        return True

    def update_tag(self, key, value) -> bool:
        """Update a resource tag in the cloud"""
        log.debug(f"Updating or setting tag {key}: {value} on resource {self.id}")
        return True

    def delete_tag(self, key) -> bool:
        """Delete a resource tag in the cloud"""
        log.debug(f"Deleting tag {key} on resource {self.id}")
        return True


@dataclass(eq=False)
class ExampleInstance(ExampleResource, BaseInstance):
    """An Example Instance Resource

    Instances have a class variable `instance_status_map` which contains
    a mapping from the instance status string the cloud API returns
    to our internal InstanceStatus state.
    """

    kind: ClassVar[str] = "example_instance"
    instance_status_map: ClassVar[Dict[str, InstanceStatus]] = {
        "pending": InstanceStatus.BUSY,
        "running": InstanceStatus.RUNNING,
        "shutting-down": InstanceStatus.BUSY,
        "terminated": InstanceStatus.TERMINATED,
        "stopping": InstanceStatus.BUSY,
        "stopped": InstanceStatus.STOPPED,
    }

    def _instance_status_setter(self, value: str) -> None:
        """Setter that looks up the instance status

        Based on the string that was give we're doing a dict lookup
        for the corresponding instance status and assign it or
        InstanceStatus.UNKNOWN.
        """
        self._instance_status = self.instance_status_map.get(
            value, InstanceStatus.UNKNOWN
        )


# Because we are using dataclasses and allow to supply the `instance_status`
# string to the constructor we can not use the normal @property decorator.
# Instead we assign the property once the class has been fully defined.
ExampleInstance.instance_status = property(
    ExampleInstance._instance_status_getter, ExampleInstance._instance_status_setter
)


@dataclass(eq=False)
class ExampleVolume(ExampleResource, BaseVolume):
    kind: ClassVar[str] = "example_volume"

    volume_status_map: ClassVar[Dict[str, VolumeStatus]] = {
        "creating": VolumeStatus.BUSY,
        "available": VolumeStatus.AVAILABLE,
        "in-use": VolumeStatus.IN_USE,
        "deleting": VolumeStatus.BUSY,
        "deleted": VolumeStatus.DELETED,
        "error": VolumeStatus.ERROR,
        "busy": VolumeStatus.BUSY,
    }

    def _volume_status_setter(self, value: str) -> None:
        self._volume_status = self.volume_status_map.get(value, VolumeStatus.UNKNOWN)


ExampleVolume.volume_status = property(
    ExampleVolume._volume_status_getter, ExampleVolume._volume_status_setter
)


@dataclass(eq=False)
class ExampleNetwork(ExampleResource, BaseNetwork):
    """Some example network

    This is what instances and other networking related resources might reside in.
    """

    kind: ClassVar[str] = "example_network"


@dataclass(eq=False)
class ExampleCustomResource(ExampleResource, BaseResource):
    """An example custom resource that only inherits the collectors
    ExampleResource class as well as the BaseResource base class.

    This is mainly an example of how to use typed Python dataclasses
    from which the resoto data model is being generated.
    """

    kind: ClassVar[str] = "example_custom_resource"

    custom_string_attribute: str = ""
    custom_int_attribute: int = 0
    custom_optional_float_attribute: Optional[float] = None
    custom_dict_attribute: Dict[str, str] = field(default_factory=dict)
    custom_list_attribute: List[str] = field(default_factory=list)
    init_only_attribute: InitVar[Optional[str]] = None

    def __post_init__(self, init_only_attribute: str) -> None:
        super().__post_init__()
        if init_only_attribute is not None:
            self.some_other_var = init_only_attribute
