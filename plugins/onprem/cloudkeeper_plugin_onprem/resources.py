import cloudkeeper.logging

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


class OnpremLocation(BaseAccount):
    resource_type = "onprem_location"

    def delete(self, graph: Graph) -> bool:
        return NotImplemented


class OnpremRegion(BaseRegion):
    resource_type = "onprem_region"

    def delete(self, graph: Graph) -> bool:
        return NotImplemented


class OnpremResource(BaseResource):
    resource_type = "onprem_resource"

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


class OnpremInstance(BaseInstance, OnpremResource):
    resource_type = "onprem_instance"

    instance_status_map = {
        "running": InstanceStatus.RUNNING,
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


class OnpremNetwork(BaseNetwork, OnpremResource):
    resource_type = "onprem_network"

    def delete(self, graph: Graph) -> bool:
        log.debug(
            f"Deleting resource {self.id} in account {self.account(graph).id} region {self.region(graph).id}"
        )
        return True
