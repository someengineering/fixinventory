from resotolib.graph import Graph
import resotolib.logger
from resotolib.baseresources import (
    BaseAccount,
    BaseRegion,
    BaseInstance,
)
from attrs import define
from typing import ClassVar
from pyVmomi import vim
from .vsphere_client import get_vsphere_client, VSphereClient

log = resotolib.logger.getLogger("resoto." + __name__)


@define(eq=False, slots=False)
class VSphereCluster(BaseAccount):
    kind: ClassVar[str] = "vsphere_cluster"

    def delete(self, graph: Graph) -> bool:
        return NotImplemented


@define(eq=False, slots=False)
class VSphereDataCenter(BaseRegion):
    kind: ClassVar[str] = "vsphere_data_center"

    def delete(self, graph: Graph) -> bool:
        return NotImplemented


@define(eq=False, slots=False)
class VSphereResource:
    kind: ClassVar[str] = "vsphere_resource"

    def _vsphere_client(self) -> VSphereClient:
        return get_vsphere_client()


@define(eq=False, slots=False)
class VSphereInstance(BaseInstance, VSphereResource):
    kind: ClassVar[str] = "vsphere_instance"

    def _vm(self):
        return self._vsphere_client().get_object([vim.VirtualMachine], self.name)

    def delete(self, graph: Graph) -> bool:
        if self._vm() is None:
            log.error(f"could not find vm name {self.name} with id {self.id}")

        log.debug(f"Deleting resource {self.id} in account {self.account(graph).id} region {self.region(graph).id}")

        if self._vm().runtime.powerState == "poweredOn":
            task = self._vm().PowerOffVM_Task()
            self._vsphere_client().wait_for_tasks([task])
            log.debug(f"task finished - state: {task.info.state}")

        log.info(f"Destroying VM {self.id} with name {self.name}")
        task = self._vm().Destroy_Task()
        self._vsphere_client().wait_for_tasks([task])
        log.debug(f"task finished - state: {task.info.state}")
        return True

    def update_tag(self, key, value) -> bool:
        log.debug(f"Updating or setting tag {key}: {value} on resource {self.id}")
        self._vm().setCustomValue(key, value)
        return True

    def delete_tag(self, key) -> bool:
        log.debug(f"Deleting tag {key} on resource {self.id}")
        self._vm().setCustomValue(key, "")
        return True
