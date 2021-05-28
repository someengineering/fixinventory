from cloudkeeper.graph import Graph
from cloudkeeper.baseresources import (
    BaseAccount,
    BaseRegion,
    BaseResource,
    BaseInstance,
    BaseNetwork,
    InstanceStatus,
)

from pyVmomi import vim

from .vsphere_client import VSphereClient, new_vsphere_client


class VSphereCluster(BaseAccount):
    resource_type = "vsphere_cluster"

    def delete(self, graph: Graph) -> bool:
        return NotImplemented


class VSphereDataCenter(BaseRegion):
    resource_type = "vsphere_data_center"

    def delete(self, graph: Graph) -> bool:
        return NotImplemented


class VSphereResource(BaseResource):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

    resource_type = "vsphere_resource"

    @property
    def vsphere_client(self):
        return new_vsphere_client()

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


class VSphereInstance(BaseInstance, VSphereResource):
    resource_type = "vsphere_instance"

    instance_status_map = {
        "pending": InstanceStatus.BUSY,
        "running": InstanceStatus.RUNNING,
        "shutting-down": InstanceStatus.BUSY,
        "terminated": InstanceStatus.TERMINATED,
        "stopping": InstanceStatus.BUSY,
        "notRunning": InstanceStatus.STOPPED,
    }

    @property
    def vm(self):
        return self.vsphere_client.get_object([vim.VirtualMachine], self.name)

    def delete(self, graph: Graph) -> bool:
        if self.vm is None:
            log.error(f"could not find vm name {self.name} with id {self.id}")

        log.debug(
            f"Deleting resource {self.id} in account {self.account(graph).id} region {self.region(graph).id}"
        )

        if self.vm.runtime.powerState == "poweredOn":
            task = self.vm.PowerOffVM_Task()
            vsphere_client.wait_for_tasks([task])
            log.debug(f"task finished - state: {task.info.state}")

        log.info(f"Destroying VM {self.id} with name {self.name}")
        task = self.vm.Destroy_Task()
        vsphere_client.wait_for_tasks([task])
        log.debug(f"task finished - state: {task.info.state}")

        return True

    def update_tag(self, key, value) -> bool:
        log.debug(f"Updating or setting tag {key}: {value} on resource {self.id}")

        self.vm.setCustomValue(key, value)

        return True

    def delete_tag(self, key) -> bool:
        log.debug(f"Deleting tag {key} on resource {self.id}")

        self.vm.setCustomValue(key, "")
        return True

    @BaseInstance.instance_status.setter
    def instance_status(self, value: str) -> None:
        self._instance_status = self.instance_status_map.get(
            value, InstanceStatus.UNKNOWN
        )
