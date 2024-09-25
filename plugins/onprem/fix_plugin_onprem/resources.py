from attrs import define
from typing import Optional, ClassVar
from fixlib.graph import Graph
from fixlib.baseresources import (
    BaseAccount,
    BaseRegion,
    BaseInstance,
    BaseNetwork,
)


@define(eq=False, slots=False)
class OnpremLocation(BaseAccount):
    kind: ClassVar[str] = "onprem_location"
    _kind_display: ClassVar[str] = "Onprem Location"
    _kind_description: ClassVar[str] = "An Onprem Location."

    def delete(self, graph: Graph) -> bool:
        return False


@define(eq=False, slots=False)
class OnpremRegion(BaseRegion):
    kind: ClassVar[str] = "onprem_region"
    _kind_display: ClassVar[str] = "Onprem Region"
    _kind_description: ClassVar[str] = "An Onprem Region."

    def delete(self, graph: Graph) -> bool:
        return False


@define(eq=False, slots=False)
class OnpremResource:
    kind: ClassVar[str] = "onprem_resource"
    kind_display: ClassVar[str] = "Onprem Resource"
    kind_description: ClassVar[str] = "An Onprem Resource."

    def delete(self, graph: Graph) -> bool:
        return False

    def update_tag(self, key, value) -> bool:
        return False

    def delete_tag(self, key) -> bool:
        return False


@define(eq=False, slots=False)
class OnpremInstance(OnpremResource, BaseInstance):
    kind: ClassVar[str] = "onprem_instance"
    _kind_display: ClassVar[str] = "Onprem Instance"
    _kind_description: ClassVar[str] = "An Onprem Instance."
    network_device: Optional[str] = None
    network_ip4: Optional[str] = None
    network_ip6: Optional[str] = None


@define(eq=False, slots=False)
class OnpremNetwork(OnpremResource, BaseNetwork):
    kind: ClassVar[str] = "onprem_network"
    _kind_display: ClassVar[str] = "Onprem Network"
    _kind_description: ClassVar[str] = "An Onprem Network."
