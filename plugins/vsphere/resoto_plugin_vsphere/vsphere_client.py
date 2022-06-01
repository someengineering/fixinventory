from resotolib.args import ArgumentParser

from pyVmomi import vim, vmodl
from pyVim.connect import SmartConnect


class VSphereClient:
    def __init__(self, host, user, pwd, port=443, insecure=False):
        self.host = host
        self.user = user
        self.pwd = pwd
        self.port = port
        self.insecure = insecure
        self._client = None

    def connect(self) -> None:
        if self.insecure:
            self._client = SmartConnect(
                host=self.host,
                user=self.user,
                pwd=self.pwd,
                port=self.port,
                disableSslCertValidation=True,
            )
        else:
            self._client = SmartConnect(host=self.host, user=self.user, pwd=self.pwd, port=self.port)

    @property
    def client(self):
        if self._client is None:
            self.connect()

        return self._client

    # taken from: https://github.com/vmware/
    # pyvmomi-community-samples/blob/
    # 889a2fadcb24e6b1bc1e30caab66f1a41a950988/
    # samples/tools/pchelper.py#L146
    def list_objects(self, type, folder=None, recurse=True):
        content = self.client.RetrieveContent()

        if folder is None:
            folder = content.rootFolder

        container = content.viewManager.CreateContainerView(folder, type, recurse)

        return container.view

    def search_object(self, type, name, folder=None, recurse=True):
        objects = self.list_objects(type, folder, recurse)

        for managed_object_ref in objects:
            if managed_object_ref.name == name:
                object = managed_object_ref
                break
        return object

    def get_object(self, type, name, folder=None, recurse=True):
        object = self.search_object(type, name, folder, recurse)

        if not object:
            raise RuntimeError("Managed Object " + name + " not found.")
        return object

    # taken from: https://github.com/vmware/
    # pyvmomi-community-samples/blob/master/
    # samples/tools/tasks.py
    def wait_for_tasks(self, tasks):
        """Given the service instance and tasks, it returns after all the
        tasks are complete"""

        property_collector = self.client.content.propertyCollector
        task_list = [str(task) for task in tasks]
        # Create filter
        obj_specs = [vmodl.query.PropertyCollector.ObjectSpec(obj=task) for task in tasks]
        property_spec = vmodl.query.PropertyCollector.PropertySpec(type=vim.Task, pathSet=[], all=True)
        filter_spec = vmodl.query.PropertyCollector.FilterSpec()
        filter_spec.objectSet = obj_specs
        filter_spec.propSet = [property_spec]
        pcfilter = property_collector.CreateFilter(filter_spec, True)
        try:
            version, state = None, None
            # Loop looking for updates till the state moves to a completed state.
            while task_list:
                update = property_collector.WaitForUpdates(version)
                for filter_set in update.filterSet:
                    for obj_set in filter_set.objectSet:
                        task = obj_set.obj
                        for change in obj_set.changeSet:
                            if change.name == "info":
                                state = change.val.state
                            elif change.name == "info.state":
                                state = change.val
                            else:
                                continue

                            if not str(task) in task_list:
                                continue

                            if state == vim.TaskInfo.State.success:
                                # Remove task from taskList
                                task_list.remove(str(task))
                            elif state == vim.TaskInfo.State.error:
                                raise task.info.error
                # Move to next version
                version = update.version
        finally:
            if pcfilter:
                pcfilter.Destroy()


def get_vsphere_client() -> VSphereClient:
    return VSphereClient(
        host=ArgumentParser.args.vsphere_host,
        user=ArgumentParser.args.vsphere_user,
        pwd=ArgumentParser.args.vsphere_password,
        port=ArgumentParser.args.vsphere_port,
        insecure=ArgumentParser.args.vsphere_insecure,
    )
