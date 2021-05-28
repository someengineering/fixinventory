from datetime import datetime

import cloudkeeper.logging
from cloudkeeper.args import ArgumentParser
from cloudkeeper.baseplugin import BaseCollectorPlugin
from cloudkeeper.baseresources import BaseResource

from .vsphere_client import VSphereClient, new_vsphere_client
from .resources import VSphereCluster, VSphereInstance, VSphereDataCenter

import atexit
from pyVmomi import vim, vmodl
from pyVim.connect import SmartConnect, Disconnect

log = cloudkeeper.logging.getLogger("cloudkeeper." + __name__)


class VSphereCollectorPlugin(BaseCollectorPlugin):
    cloud = "vsphere"

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.vsphere_client = new_vsphere_client()

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
            attr[str(keymap[value.key])] = str(value.value)

        return attr

    def addInstances(self, parent: BaseResource) -> None:
        content = self.vsphere_client.client.RetrieveContent()

        container = content.rootFolder  # starting point to look into
        view_type = [vim.VirtualMachine]  # object types to look for
        recursive = True  # whether we should look into it recursively
        container_view = content.viewManager.CreateContainerView(
            container, view_type, recursive
        )

        VMs = container_view.view

        keys = self.get_keymap_from_vmlist(VMs)

        for listVM in VMs:
            tags = self.get_custom_attributes(listVM, keys)
            # get TS and create clean datetime
            ctime = datetime.fromtimestamp(listVM.config.createDate.timestamp())

            vm = VSphereInstance(
                listVM._moId,
                name=str(listVM.name),
                instance_cores=int(listVM.config.hardware.numCPU),
                instance_memory=int(listVM.config.hardware.memoryMB / 1024),
                tags=tags,
                ctime=ctime,
            )
            vm.instance_status = listVM.guest.guestState

            self.graph.add_resource(parent, vm)

    def collect(self) -> None:
        log.debug("plugin: collecting vsphere resources")

        cluster = self.getCluster()
        dc1 = VSphereDataCenter("dc1", tags={})

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
            default=None,
        )

        arg_parser.add_argument(
            "--vsphere-password",
            help="VSphere user password",
            dest="vsphere_password",
            type=str,
            default=None,
        )

        arg_parser.add_argument(
            "--vsphere-host",
            help="VSphere Host address",
            dest="vsphere_host",
            type=str,
            default=None,
        )

        arg_parser.add_argument(
            "--vsphere-port",
            help="VSphere Region",
            dest="vsphere_port",
            type=int,
            default=443,
        )

        arg_parser.add_argument(
            "--vsphere-insecure",
            help="VSphere insecure connection. Do not verify certificates",
            dest="vsphere_insecure",
            action="store_true",
        )
