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
from .vsphere_client import VSphereClient

import atexit
from pyVmomi import vim, vmodl
from pyVim.connect import SmartConnect, Disconnect

log = cloudkeeper.logging.getLogger("cloudkeeper." + __name__)
vsphere_client = None

class VSphereCollectorPlugin(BaseCollectorPlugin):
    cloud = "vsphere"

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

        global vsphere_client
        vsphere_client = VSphereClient(host=ArgumentParser.args.vsphere_host,
                                       user=ArgumentParser.args.vsphere_user,
                                       pwd=ArgumentParser.args.vsphere_password,
                                       port=ArgumentParser.args.vsphere_port,
                                       insecure=ArgumentParser.args.vsphere_insecure)

    def getCluster(self) -> VSphereCluster:
        return VSphereCluster(ArgumentParser.args.vsphere_host, {})

    def get_keymap_from_vmlist(self, listVM) -> VSphereCluster:
        keyMap = {}
        for key in listVM[0].availableField:
            keyMap[key.key] = key.name

        return keyMap

    def get_custom_attributes(self, vm, keymap):
        attr = {}
        for value in vm.value:
            attr[keymap[value.key]] = value.value

        return attr

    def addInstances(self, parent: BaseResource) -> None:
        content = vsphere_client.client.RetrieveContent()

        container = content.rootFolder  # starting point to look into
        view_type = [vim.VirtualMachine]  # object types to look for
        recursive = True  # whether we should look into it recursively
        container_view = content.viewManager.CreateContainerView(
            container, view_type, recursive)

        VMs = container_view.view

        keys = self.get_keymap_from_vmlist(VMs)

        for listVM in VMs:
            tags = self.get_custom_attributes(listVM, keys)

            vm = VSphereInstance(listVM._moId,
                                 name=listVM.name,
                                 instance_cores=listVM.config.hardware.numCPU,
                                 instance_memory=int(listVM.config.hardware.memoryMB / 1024),
                                 tags=tags,
                                 ctime=listVM.config.createDate,
                                 )
            vm.instance_status = listVM.guest.guestState

            self.graph.add_resource(parent, vm)

    def collect(self) -> None:
        log.debug("plugin: collecting vsphere resources")

        cluster = self.getCluster()
        dc1 = VSphereDataCenter(
            "dc1", tags={}
        )

        self.graph.add_resource(self.graph.root, cluster)
        self.graph.add_resource(cluster, dc1)

        self.addInstances(dc1)

    @staticmethod
    def add_args(arg_parser: ArgumentParser) -> None:
        arg_parser.add_argument(
            "--vsphere-user",
            help="VSphere user name",
            dest="vsphere_user",
            type=str,
            default=None
        )

        arg_parser.add_argument(
            "--vsphere-password",
            help="VSphere user password",
            dest="vsphere_password",
            type=str,
            default=None
        )

        arg_parser.add_argument(
            "--vsphere-host",
            help="VSphere Host address",
            dest="vsphere_host",
            type=str,
            default=None
        )

        arg_parser.add_argument(
            "--vsphere-port",
            help="VSphere Region",
            dest="vsphere_port",
            type=int,
            default=443
        )

        arg_parser.add_argument(
            "--vsphere-insecure",
            help="VSphere insecure connection. Do not verify certificates",
            dest="vsphere_insecure",
            action="store_true"
        )

class VSphereCluster(BaseAccount):
    resource_type = "vsphere_cluster"

    def delete(self, graph: Graph) -> bool:
        return NotImplemented

class VSphereDataCenter(BaseRegion):
    resource_type = "vsphere_data_center"

    def delete(self, graph: Graph) -> bool:
        return NotImplemented


class VSphereResource(BaseResource):
    resource_type = "vsphere_resource"

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
        return vsphere_client.get_object([vim.VirtualMachine], self.name)

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
