import resotolib.logger
from dataclasses import dataclass
from typing import Optional, ClassVar
from resotolib.graph import Graph
from resotolib.baseresources import (
    BaseAccount,
    BaseRegion,
    BaseInstance,
    BaseNetwork,
    InstanceStatus,
)

log = resotolib.logger.getLogger("resoto." + __name__)


@dataclass(eq=False)
class OnpremLocation(BaseAccount):
    kind: ClassVar[str] = "onprem_location"

    def delete(self, graph: Graph) -> bool:
        return False


@dataclass(eq=False)
class OnpremRegion(BaseRegion):
    kind: ClassVar[str] = "onprem_region"

    def delete(self, graph: Graph) -> bool:
        return False


@dataclass(eq=False)
class OnpremResource:
    kind: ClassVar[str] = "onprem_resource"

    def delete(self, graph: Graph) -> bool:
        return False

    def update_tag(self, key, value) -> bool:
        return False

    def delete_tag(self, key) -> bool:
        return False


@dataclass(eq=False)
class OnpremInstance(OnpremResource, BaseInstance):
    kind: ClassVar[str] = "onprem_instance"
    network_device: Optional[str] = None
    network_ip4: Optional[str] = None
    network_ip6: Optional[str] = None

    instance_status_map = {
        "running": InstanceStatus.RUNNING,
    }

    def _instance_status_setter(self, value: str) -> None:
        self._instance_status = self.instance_status_map.get(
            value, InstanceStatus.UNKNOWN
        )


OnpremInstance.instance_status = property(
    OnpremInstance._instance_status_getter, OnpremInstance._instance_status_setter
)


@dataclass(eq=False)
class OnpremNetwork(OnpremResource, BaseNetwork):
    kind: ClassVar[str] = "onprem_network"
