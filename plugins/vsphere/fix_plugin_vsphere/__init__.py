from datetime import datetime

from fixlib.logger import log
from fixlib.config import Config
from fixlib.baseplugin import BaseCollectorPlugin
from fixlib.baseresources import InstanceStatus

from .vsphere_client import get_vsphere_client
from .resources import (
    VSphereCluster,
    VSphereInstance,
    VSphereDataCenter,
    VSphereTemplate,
    VSphereHost,
    VSphereESXiHost,
    VSphereDataStore,
    VSphereDataStoreCluster,
    VSphereResourcePool,
)
from .config import VSphereConfig
from typing import Dict

from pyVmomi import vim


class VSphereCollectorPlugin(BaseCollectorPlugin):
    cloud = "vsphere"
    instances_dict = {}

    def get_host(self) -> VSphereHost:
        return VSphereHost(id=Config.vsphere.host)

    def get_keymap_from_vmlist(self, list_vm) -> VSphereCluster:
        """
        resolve custom key ID into a dict with its name
        """
        keyMap = {}
        for key in list_vm[0].availableField:
            keyMap[key.key] = key.name

        return keyMap

    def get_custom_attributes(self, vm, keymap):
        """
        use custom attribute keymap to resolve key IDs into a dict and
        assign custom value.
        """
        attr = {}
        for value in vm.value:
            attr[str(keymap[value.key])] = str(value.value)

        return attr

    def resource_pool(self, resourcepool, predecessor):
        rpObj = VSphereResourcePool(id=resourcepool._moId, name=resourcepool.name)
        self.graph.add_resource(predecessor, rpObj)
        log.debug(f"Found ResourcePool - {resourcepool._moId} - {resourcepool.name}")
        for vm in resourcepool.vm:
            self.graph.add_edge(rpObj, self.instances_dict[vm._moId])

        for successorPool in resourcepool.resourcePool:
            log.debug(f"Found nested ResourcePool - {successorPool._moId} - {successorPool.name}")
            self.resource_pool(successorPool, rpObj)

    def get_instances(self) -> None:
        """
        loop over VMs and add them as VSphereInstance to parent
        """

        content = get_vsphere_client().client.RetrieveContent()

        container = content.rootFolder  # starting point to look into
        view_type = [vim.VirtualMachine]  # object types to look for
        recursive = True  # whether we should look into it recursively
        container_view = content.viewManager.CreateContainerView(container, view_type, recursive)

        vms = container_view.view

        keys = self.get_keymap_from_vmlist(vms)

        instance_status_map: Dict[str, InstanceStatus] = {
            "pending": InstanceStatus.BUSY,
            "running": InstanceStatus.RUNNING,
            "shutting-down": InstanceStatus.BUSY,
            "terminated": InstanceStatus.TERMINATED,
            "stopping": InstanceStatus.BUSY,
            "notRunning": InstanceStatus.STOPPED,
        }
        # loop over the list of VMs
        for list_vm in vms:
            try:
                tags = self.get_custom_attributes(list_vm, keys)

                try:
                    ctime = datetime.fromtimestamp(list_vm.config.createDate.timestamp())
                except AttributeError:
                    ctime = None

                if list_vm.config.template:
                    vm = VSphereTemplate(id=list_vm._moId, name=str(list_vm.name), ctime=ctime)
                else:
                    vm = VSphereInstance(
                        id=list_vm._moId,
                        name=str(list_vm.name),
                        instance_cores=int(list_vm.config.hardware.numCPU),
                        instance_memory=int(list_vm.config.hardware.memoryMB / 1024),
                        tags=tags,
                        ctime=ctime,
                        instance_status=instance_status_map.get(list_vm.guest.guestState, InstanceStatus.UNKNOWN),
                    )
            except Exception:
                log.exception(f"Error while collecting {list_vm}")
            else:
                log.debug(f"found {vm.id} - {vm}")
                self.instances_dict[vm.id] = vm
                self.graph.add_node(vm)

    def collect(self) -> None:
        log.debug("plugin: collecting vsphere resources")

        if not Config.vsphere.host:
            log.debug("no VSphere host given - skipping collection")
            return

        host = self.get_host()

        self.get_instances()
        log.debug(f"found {len(self.instances_dict)} instances and templates")

        self.graph.add_resource(self.graph.root, host)

        content = get_vsphere_client().client.RetrieveContent()
        datacenters = [entity for entity in content.rootFolder.childEntity if hasattr(entity, "vmFolder")]
        # datacenter are root folder objects
        for dc in datacenters:
            log.debug(f"Found datacenter - {dc._moId} - {dc.name}")
            dcObj = VSphereDataCenter(id=dc._moId, name=dc.name)
            self.graph.add_resource(host, dcObj)

            # get clusters in datacenter
            for cluster in dc.hostFolder.childEntity:
                log.debug(f"Found cluster - {cluster._moId} - {cluster.name}")
                clusterObj = VSphereCluster(id=cluster._moId, name=cluster.name)
                self.graph.add_resource(dcObj, clusterObj)
                try:
                    rpool = cluster.resourcePool
                    self.resource_pool(rpool, clusterObj)
                except Exception:
                    log.warning(f"Resourcepool error for cluster {cluster._moId} {cluster.name}")

                # get hosts from a cluster
                for host in cluster.host:  #
                    log.debug(f"Found host - {host._moId} - {host.name}")
                    hostObj = VSphereESXiHost(id=host._moId, name=host.name)
                    self.graph.add_resource(clusterObj, hostObj)
                    # get vms for each host and read from the vm list
                    for vm in host.vm:
                        if vm._moId in self.instances_dict:
                            vmObj = self.instances_dict[vm._moId]
                            log.debug(
                                f"lookup vm - {vm._moId} - {vmObj.name} and assign to host {host._moId} - {host.name}"
                            )
                            self.graph.add_edge(hostObj, vmObj)
                        else:
                            log.warning(f"host {host._moId} - {host.name} reports {vm._moId} but instance not found")

            for datastore in dc.datastoreFolder.childEntity:
                if datastore._wsdlName == "Datastore":
                    log.debug(f"Found Datastore - {datastore._moId} - {datastore.name}")
                    dsObj = VSphereDataStore(id=datastore._moId, name=datastore.name)
                    self.graph.add_resource(dcObj, dsObj)
                    for vm in datastore.vm:
                        vmObj = self.instances_dict[vm._moId]
                        self.graph.add_edge(dsObj, vmObj)
                elif datastore._wsdlName == "StoragePod":
                    log.debug(f"Found DatastoreCluster - {datastore._moId} - {datastore.name}")
                    dsc = VSphereDataStoreCluster(id=datastore._moId, name=datastore.name)
                    self.graph.add_resource(dcObj, dsc)
                    for store in datastore.childEntity:
                        log.debug(f"Found DatastoreCluster Datastore - {store._moId} - {store.name}")
                        if store._wsdlName == "Datastore":
                            dsObj = VSphereDataStore(id=store._moId, name=store.name)
                            self.graph.add_resource(dcObj, dsObj)
                            for vm in store.vm:
                                vmObj = self.instances_dict[vm._moId]
                                self.graph.add_edge(dsObj, vmObj)

    @staticmethod
    def add_config(config: Config) -> None:
        config.add_config(VSphereConfig)
