from fixlib.graph import Graph
import fixlib.logger
from fixlib.baseresources import (
    BaseResource,
    BaseAccount,
    BaseRegion,
    BaseZone,
    BaseInstance,
)
from attrs import define
from typing import ClassVar
from pyVmomi import vim
from .vsphere_client import get_vsphere_client, VSphereClient

log = fixlib.logger.getLogger("fix." + __name__)


@define(eq=False, slots=False)
class VSphereHost(BaseAccount):
    kind: ClassVar[str] = "vsphere_host"
    kind_display: ClassVar[str] = "vSphere Host"
    kind_description: ClassVar[str] = (
        "vSphere Host is a physical server that runs the VMware vSphere hypervisor,"
        " allowing for virtualization and management of multiple virtual machines."
    )

    def delete(self, graph: Graph) -> bool:
        return NotImplemented


@define(eq=False, slots=False)
class VSphereDataCenter(BaseRegion):
    kind: ClassVar[str] = "vsphere_data_center"
    kind_display: ClassVar[str] = "vSphere Data Center"
    kind_description: ClassVar[str] = (
        "vSphere Data Center is a virtualization platform provided by VMware for"
        " managing and organizing virtual resources in a data center environment."
    )

    def delete(self, graph: Graph) -> bool:
        return NotImplemented


@define(eq=False, slots=False)
class VSphereCluster(BaseZone):
    kind: ClassVar[str] = "vsphere_cluster"
    kind_display: ClassVar[str] = "vSphere Cluster"
    kind_description: ClassVar[str] = (
        "A vSphere Cluster is a group of ESXi hosts that work together to provide"
        " resource pooling and high availability for virtual machines."
    )

    def delete(self, graph: Graph) -> bool:
        return NotImplemented


@define(eq=False, slots=False)
class VSphereESXiHost(BaseResource):
    kind: ClassVar[str] = "vsphere_esxi_host"
    kind_display: ClassVar[str] = "vSphere ESXi Host"
    kind_description: ClassVar[str] = (
        "vSphere ESXi Host is a virtualization platform by VMware which allows users"
        " to run multiple virtual machines on a single physical server."
    )

    def delete(self, graph: Graph) -> bool:
        return NotImplemented


@define(eq=False, slots=False)
class VSphereDataStore(BaseResource):
    kind: ClassVar[str] = "vsphere_datastore"
    kind_display: ClassVar[str] = "vSphere Datastore"
    kind_description: ClassVar[str] = (
        "vSphere Datastore is a storage abstraction layer used in VMware vSphere to"
        " manage and store virtual machine files and templates."
    )

    def delete(self, graph: Graph) -> bool:
        return NotImplemented


@define(eq=False, slots=False)
class VSphereDataStoreCluster(BaseResource):
    kind: ClassVar[str] = "vsphere_datastore_cluster"
    kind_display: ClassVar[str] = "vSphere Datastore Cluster"
    kind_description: ClassVar[str] = (
        "vSphere Datastore Cluster is a feature in VMware's virtualization platform"
        " that allows users to combine multiple storage resources into a single"
        " datastore cluster, providing advanced management and high availability for"
        " virtual machine storage."
    )

    def delete(self, graph: Graph) -> bool:
        return NotImplemented


@define(eq=False, slots=False)
class VSphereResourcePool(BaseResource):
    kind: ClassVar[str] = "vsphere_resource_pool"
    kind_display: ClassVar[str] = "vSphere Resource Pool"
    kind_description: ClassVar[str] = (
        "vSphere Resource Pool is a feature in VMware's vSphere virtualization"
        " platform that allows for the efficient allocation and management of CPU,"
        " memory, and storage resources in a virtual datacenter."
    )

    def delete(self, graph: Graph) -> bool:
        return NotImplemented


@define(eq=False, slots=False)
class VSphereResource:
    kind: ClassVar[str] = "vsphere_resource"
    kind_display: ClassVar[str] = "vSphere Resource"
    kind_description: ClassVar[str] = (
        "vSphere is a virtualization platform by VMware that allows users to create,"
        " manage, and run virtual machines and other virtual infrastructure"
        " components."
    )

    def _vsphere_client(self) -> VSphereClient:
        return get_vsphere_client()


@define(eq=False, slots=False)
class VSphereInstance(BaseInstance, VSphereResource):
    kind: ClassVar[str] = "vsphere_instance"
    kind_display: ClassVar[str] = "vSphere Instance"
    kind_description: ClassVar[str] = (
        "vSphere Instances are virtual servers in VMware's cloud infrastructure,"
        " enabling users to run applications on VMware's virtualization platform."
    )

    def _vm(self):
        return self._vsphere_client().get_object([vim.VirtualMachine], self.name)

    def delete(self, graph: Graph) -> bool:
        if self._vm() is None:
            log.error(f"Could not find vm name {self.name} with id {self.id}")

        log.debug(f"Deleting resource {self.id} in account {self.account(graph).id} region {self.region(graph).id}")

        if self._vm().runtime.powerState == "poweredOn":
            task = self._vm().PowerOffVM_Task()
            self._vsphere_client().wait_for_tasks([task])
            log.debug(f"Task finished - state: {task.info.state}")

        log.info(f"Destroying VM {self.id} with name {self.name}")
        task = self._vm().Destroy_Task()
        self._vsphere_client().wait_for_tasks([task])
        log.debug(f"Task finished - state: {task.info.state}")
        return True

    def update_tag(self, key, value) -> bool:
        log.debug(f"Updating or setting tag {key}: {value} on resource {self.id}")
        self._vm().setCustomValue(key, value)
        return True

    def delete_tag(self, key) -> bool:
        log.debug(f"Deleting tag {key} on resource {self.id}")
        self._vm().setCustomValue(key, "")
        return True


@define(eq=False, slots=False)
class VSphereTemplate(BaseResource, VSphereResource):
    kind: ClassVar[str] = "vsphere_template"
    kind_display: ClassVar[str] = "vSphere Template"
    kind_description: ClassVar[str] = (
        "vSphere templates are pre-configured virtual machine images that can be used"
        " to deploy and scale virtual infrastructure within the VMware vSphere"
        " platform."
    )

    def _get_default_resource_pool(self) -> vim.ResourcePool:
        return self._vsphere_client().get_object([vim.ResourcePool], "Resources")

    def _template(self):
        return self._vsphere_client().get_object([vim.VirtualMachine], self.name)

    def delete(self, graph: Graph) -> bool:
        if self._template() is None:
            log.error(f"Could not find vm name {self.name} with id {self.id}")

        log.debug(f"Deleting resource {self.id} in account {self.account(graph).id} region {self.region(graph).id}")

        log.debug(f"Mark template {self.id} as vm")
        try:
            self._template().MarkAsVirtualMachine(host=None, pool=self._get_default_resource_pool())
        except vim.fault.NotFound:
            log.warning(f"Template {self.name} ({self.id}) not found - expecting we're done")
            return True
        except Exception as e:
            log.exception(f"Unexpected error: {e}")
            return False

        log.info(f"Destroying Template {self.id} with name {self.name}")
        task = self._template().Destroy_Task()
        self._vsphere_client().wait_for_tasks([task])
        log.debug(f"Task finished - state: {task.info.state}")
        return True

    def update_tag(self, key, value) -> bool:
        return NotImplemented

    def delete_tag(self, key) -> bool:
        return NotImplemented
