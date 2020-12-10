import cloudkeeper.logging
from cloudkeeper.baseplugin import BaseCollectorPlugin
from cloudkeeper.graph import Graph
from cloudkeeper.args import ArgumentParser
from cloudkeeper.baseresources import (
    BaseAccount,
    BaseRegion,
    BaseResource,
    BaseInstance,
    BaseNetwork,
    InstanceStatus,
)

log = cloudkeeper.logging.getLogger("cloudkeeper." + __name__)


class ExampleCollectorPlugin(BaseCollectorPlugin):
    cloud = "example"

    def collect(self) -> None:
        log.debug("plugin: collecting example resources")

        account = ExampleAccount("Example Account", {})
        self.graph.add_resource(self.root, account)

        region1 = ExampleRegion("us-west", {"Some Tag": "Some Value"})
        self.graph.add_resource(account, region1)

        region2 = ExampleRegion("us-east", {"Some Tag": "Some Value"})
        self.graph.add_resource(account, region2)

        network = ExampleNetwork("someNetwork", {"Name": "Example Network"})
        self.graph.add_resource(region1, network)

        instance1 = ExampleInstance(
            "someInstance1",
            {"Name": "Example Instance 1", "expiration": "2d", "owner": "lukas"},
        )
        self.graph.add_resource(network, instance1)

        instance2 = ExampleInstance(
            "someInstance2",
            {
                "Name": "Example Instance 2",
                "expiration": "36h",
                "cloudkeeper:ctime": "2019-09-05T10:40:11+00:00",
            },
        )
        self.graph.add_resource(region2, instance2)

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


class ExampleAccount(BaseAccount):
    resource_type = "example_account"

    def delete(self, graph: Graph) -> bool:
        return NotImplemented


class ExampleRegion(BaseRegion):
    resource_type = "example_region"

    def delete(self, graph: Graph) -> bool:
        return NotImplemented


class ExampleResource(BaseResource):
    resource_type = "example_resource"

    def delete(self, graph: Graph) -> bool:
        log.debug(
            f"Deleting resource {self.id} in account {self.account(graph).id} region {self.region(graph).id}"
        )
        return True

    def update_tag(self, key, value) -> bool:
        log.debug(f"Updating or setting tag {key}: {value} on resource {self.id}")
        return True

    def delete_tag(self, key) -> bool:
        log.debug(f"Deleting tag {key} on resource {self.id}")
        return True


class ExampleInstance(BaseInstance, ExampleResource):
    resource_type = "example_instance"

    instance_status_map = {
        "pending": InstanceStatus.BUSY,
        "running": InstanceStatus.RUNNING,
        "shutting-down": InstanceStatus.BUSY,
        "terminated": InstanceStatus.TERMINATED,
        "stopping": InstanceStatus.BUSY,
        "stopped": InstanceStatus.STOPPED,
    }

    def delete(self, graph: Graph) -> bool:
        log.debug(
            f"Deleting resource {self.id} in account {self.account(graph).id} region {self.region(graph).id}"
        )
        return True

    @BaseInstance.instance_status.setter
    def instance_status(self, value: str) -> None:
        self._instance_status = self.instance_status_map.get(
            value, InstanceStatus.UNKNOWN
        )


class ExampleNetwork(BaseNetwork, ExampleResource):
    resource_type = "example_network"

    def delete(self, graph: Graph) -> bool:
        log.debug(
            f"Deleting resource {self.id} in account {self.account(graph).id} region {self.region(graph).id}"
        )
        return True
