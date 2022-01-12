from resotolib.graph import Graph
import resotolib.logging
from resotolib.baseresources import (
    BaseAccount,
    BaseRegion,
    BaseInstance,
    InstanceStatus,
)
from dataclasses import dataclass
from typing import ClassVar, Dict
from pyVmomi import vim
from .vsphere_client import get_vsphere_client, VSphereClient

log = resotolib.logging.getLogger("cloudkeeper." + __name__)


@dataclass(eq=False)
class VSphereCluster(BaseAccount):
    kind: ClassVar[str] = "vsphere_cluster"

    def delete(self, graph: Graph) -> bool:
        return NotImplemented


@dataclass(eq=False)
class VSphereDataCenter(BaseRegion):
    kind: ClassVar[str] = "vsphere_data_center"

    def delete(self, graph: Graph) -> bool:
        return NotImplemented


@dataclass(eq=False)
class VSphereResource:
    kind: ClassVar[str] = "vsphere_resource"

    def _vsphere_client(self) -> VSphereClient:
        return get_vsphere_client()


@dataclass(eq=False)
class VSphereInstance(BaseInstance, VSphereResource):
    kind: ClassVar[str] = "vsphere_instance"

    instance_status_map: ClassVar[Dict[str, InstanceStatus]] = {
        "pending": InstanceStatus.BUSY,
        "running": InstanceStatus.RUNNING,
        "shutting-down": InstanceStatus.BUSY,
        "terminated": InstanceStatus.TERMINATED,
        "stopping": InstanceStatus.BUSY,
        "notRunning": InstanceStatus.STOPPED,
    }

    def _vm(self):
        return self._vsphere_client().get_object([vim.VirtualMachine], self.name)

    def delete(self, graph: Graph) -> bool:
        if self._vm() is None:
            log.error(f"could not find vm name {self.name} with id {self.id}")

        log.debug(
            f"Deleting resource {self.id} in account {self.account(graph).id} region {self.region(graph).id}"
        )

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

    def _instance_status_setter(self, value: str) -> None:
        self._instance_status = self.instance_status_map.get(
            value, InstanceStatus.UNKNOWN
        )


VSphereInstance.instance_status = property(
    VSphereInstance._instance_status_getter, VSphereInstance._instance_status_setter
)
