from datetime import datetime
from typing import Any

import cloudkeeper.logging
from cloudkeeper.args import ArgumentParser
from cloudkeeper.baseplugin import BaseCollectorPlugin
from cloudkeeper.baseresources import BaseResource

from .vsphere_client import new_vsphere_client
from .resources import VSphereCluster, VSphereInstance, VSphereDataCenter

from pyVmomi import vim

log = cloudkeeper.logging.getLogger("cloudkeeper." + __name__)


class VSphereCollectorPlugin(BaseCollectorPlugin):
    cloud = "vsphere"

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.vsphere_client = new_vsphere_client()

    def get_cluster(self) -> VSphereCluster:
        """
        use --vsphere-host as the clustername
        """
        return VSphereCluster(ArgumentParser.args.vsphere_host, {})

    def get_keymap_from_vmlist(self, list_vm: list[Any]) -> VSphereCluster:
        """
        resolve custom key ID into a dict with its name
        """
        keyMap = {}
        for key in list_vm[0].availableField:
            keyMap[key.key] = key.name

        return keyMap

    def get_custom_attributes(self, vm, keymap: dict[int, str]) -> dict[str, str]:
        """
        use custom attribute keymap to resolve key IDs into a dict and
        assign custom value.
        """
        attr = {}
        for value in vm.value:
            attr[str(keymap[value.key])] = str(value.value)

        return attr

    def add_instances(self, parent: BaseResource) -> None:
        """
        loop over VMs and add them as VSphereInstance to parent
        """
        content = self.vsphere_client.client.RetrieveContent()

        container = content.rootFolder  # starting point to look into
        view_type = [vim.VirtualMachine]  # object types to look for
        recursive = True  # whether we should look into it recursively
        container_view = content.viewManager.CreateContainerView(
            container, view_type, recursive
        )

        vms = container_view.view

        keys = self.get_keymap_from_vmlist(vms)

        # loop over the list of VMs
        for list_vm in vms:
            tags = self.get_custom_attributes(list_vm, keys)
            # get TS and create clean datetime
            ctime = datetime.fromtimestamp(list_vm.config.createDate.timestamp())

            vm = VSphereInstance(
                list_vm._moId,
                name=str(list_vm.name),
                instance_cores=int(list_vm.config.hardware.numCPU),
                instance_memory=int(list_vm.config.hardware.memoryMB / 1024),
                tags=tags,
                ctime=ctime,
            )
            vm.instance_status = list_vm.guest.guestState

            self.graph.add_resource(parent, vm)

    def collect(self) -> None:
        log.debug("plugin: collecting vsphere resources")

        cluster = self.get_cluster()
        dc1 = VSphereDataCenter("dc1", tags={})

        self.graph.add_resource(self.graph.root, cluster)
        self.graph.add_resource(cluster, dc1)

        self.add_instances(dc1)

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
