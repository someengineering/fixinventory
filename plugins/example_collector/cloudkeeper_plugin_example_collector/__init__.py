import cloudkeeper.logging
from dataclasses import dataclass, field, InitVar
from datetime import datetime
from typing import ClassVar, Dict, List, Optional
from cloudkeeper.baseplugin import BaseCollectorPlugin
from cloudkeeper.graph import Graph
from cloudkeeper.args import ArgumentParser
from cloudkeeper.baseresources import (
    BaseAccount,
    BaseRegion,
    BaseInstance,
    BaseNetwork,
    BaseResource,
    InstanceStatus,
)

log = cloudkeeper.logging.getLogger("cloudkeeper." + __name__)


class ExampleCollectorPlugin(BaseCollectorPlugin):
    cloud = "example"

    def collect(self) -> None:
        """This method is being called by cloudkeeper whenever the collector runs

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

        network = ExampleNetwork("someNetwork", tags={"Name": "Example Network"})
        self.graph.add_resource(region1, network)

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
        self.graph.add_resource(network, instance1)

        instance2 = ExampleInstance(
            "someInstance2",
            {
                "Name": "Example Instance 2",
                "expiration": "36h",
                "cloudkeeper:ctime": "2019-09-05T10:40:11+00:00",
            },
            instance_status="stopped",
        )
        self.graph.add_resource(region2, instance2)

        custom_resource = ExampleCustomResource(
            "someExampleResource",
            custom_optional_float_attribute=10.0,
            custom_list_attribute=["foo", "bar"],
            init_only_attribute="Some Text",
        )
        self.graph.add_resource(region1, custom_resource)

    @staticmethod
    def add_args(arg_parser: ArgumentParser) -> None:
        arg_parser.add_argument(
            "--example-region",
            help="Example Region",
            dest="example_region",
            type=str,
            default=None,
            nargs="+",
        )


@dataclass(eq=False)
class ExampleAccount(BaseAccount):
    """Some example account"""

    resource_type: ClassVar[str] = "example_account"

    def delete(self, graph: Graph) -> bool:
        return NotImplemented


@dataclass(eq=False)
class ExampleRegion(BaseRegion):
    """Some example region"""

    resource_type: ClassVar[str] = "example_region"

    def delete(self, graph: Graph) -> bool:
        """Regions can usually not be deleted so we return NotImplemented"""
        return NotImplemented


@dataclass(eq=False)
class ExampleResource:
    """A class that implements the abstract method delete() as well as update_tag()
    and delete_tag().

    delete() must be implemented. update_tag() and delete_tag() are optional.
    """

    resource_type: ClassVar[str] = "example_resource"

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

    resource_type: ClassVar[str] = "example_instance"
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
class ExampleNetwork(ExampleResource, BaseNetwork):
    """Some example network

    This is what instances and other networking related resources might reside in.
    """

    resource_type: ClassVar[str] = "example_network"


@dataclass(eq=False)
class ExampleCustomResource(ExampleResource, BaseResource):
    """An example custom resource that only inherits the collectors
    ExampleResource class as well as the BaseResource base class.

    This is mainly an example of how to use typed Python dataclasses
    from which the cloudkeeper data model is being generated.
    """

    resource_type: ClassVar[str] = "example_custom_resource"

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
