import resotolib.logger
from attrs import define
from typing import Optional, ClassVar
from resotolib.graph import Graph
from resotolib.baseresources import (
    BaseAccount,
    BaseRegion,
    BaseInstance,
    BaseNetwork,
)

log = resotolib.logger.getLogger("resoto." + __name__)


@define(eq=False, slots=False)
class OnpremLocation(BaseAccount):
    kind: ClassVar[str] = "onprem_location"

    def delete(self, graph: Graph) -> bool:
        return False


@define(eq=False, slots=False)
class OnpremRegion(BaseRegion):
    kind: ClassVar[str] = "onprem_region"

    def delete(self, graph: Graph) -> bool:
        return False


@define(eq=False, slots=False)
class OnpremResource:
    kind: ClassVar[str] = "onprem_resource"

    def delete(self, graph: Graph) -> bool:
        return False

    def update_tag(self, key, value) -> bool:
        return False

    def delete_tag(self, key) -> bool:
        return False


@define(eq=False, slots=False)
class OnpremInstance(OnpremResource, BaseInstance):
    kind: ClassVar[str] = "onprem_instance"
    network_device: Optional[str] = None
    network_ip4: Optional[str] = None
    network_ip6: Optional[str] = None


@define(eq=False, slots=False)
class OnpremNetwork(OnpremResource, BaseNetwork):
    kind: ClassVar[str] = "onprem_network"
