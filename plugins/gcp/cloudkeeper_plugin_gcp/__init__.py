import cloudkeeper.logging
import networkx
import multiprocessing
import cloudkeeper.signal
from pprint import pformat
from concurrent import futures
from typing import List, Dict, Type, Union
from cloudkeeper.baseresources import BaseResource
from cloudkeeper.baseplugin import BaseCollectorPlugin
from cloudkeeper.graph import Graph, get_resource_attributes
from cloudkeeper.args import ArgumentParser
from cloudkeeper.utils import log_runtime
from .resources import GCPProject, GCPRegion, GCPZone, GCPDiskType, GCPDisk, GCPInstance
from .utils import (
    compute_client,
    load_credentials,
    list_credential_projects,
    paginate,
    iso2datetime,
)

log = cloudkeeper.logging.getLogger("cloudkeeper." + __name__)


class GCPCollectorPlugin(BaseCollectorPlugin):
    cloud = "gcp"

    def collect(self) -> None:
        log.debug("plugin: GCP collecting resources")
        projects = self.load_projects()

        if len(ArgumentParser.args.gcp_project) > 0:
            for project in list(projects.keys()):
                if project not in ArgumentParser.args.gcp_project:
                    del projects[project]

        max_workers = (
            len(projects)
            if len(projects) < ArgumentParser.args.gcp_project_pool_size
            else ArgumentParser.args.gcp_project_pool_size
        )
        pool_args = {"max_workers": max_workers}
        if ArgumentParser.args.gcp_fork:
            pool_args["mp_context"] = multiprocessing.get_context("spawn")
            pool_args["initializer"] = cloudkeeper.signal.initializer
            pool_executor = futures.ProcessPoolExecutor
        else:
            pool_executor = futures.ThreadPoolExecutor

        with pool_executor(**pool_args) as executor:
            wait_for = [
                executor.submit(
                    self.collect_project,
                    project["resource"],
                    project["credentials"],
                    ArgumentParser.args,
                )
                for project in projects.values()
            ]
            for future in futures.as_completed(wait_for):
                res = future.result()
                gpc_root = res["root"]
                gpc_graph = res["graph"]
                gpc_project = res["project"]
                log.debug(
                    (
                        f"Merging graph of project {gpc_project.dname}"
                        f" with {self.cloud} plugin graph"
                    )
                )
                self.graph = networkx.compose(self.graph, gpc_graph)
                self.graph.add_edge(self.root, gpc_root)

    def load_projects(self) -> Dict:
        projects = {}
        for sa_file in ArgumentParser.args.gcp_service_account:
            c = load_credentials(sa_file)
            for project in list_credential_projects(c):
                p = GCPProject(
                    project["id"],
                    {},
                    name=project["name"],
                    ctime=project["ctime"],
                    lifecycle_status=project["lifecycle_status"],
                    project_number=project["project_number"],
                )
                if p.id not in projects:
                    projects[p.id] = {"resource": p, "credentials": c}
                else:
                    log.error(
                        f"Project {p.id} already in list of projects - ignoring redundant access"
                    )
        return projects

    @staticmethod
    @log_runtime
    def collect_project(project: GCPProject, credentials, args=None):
        collector_name = f"gcp_{project.id}"
        cloudkeeper.signal.set_thread_name(collector_name)

        if args is not None:
            ArgumentParser.args = args

        log.debug(f"Starting new collect process for project {project.dname}")

        gpc = GCPProjectCollector(project, credentials)
        try:
            gpc.collect()
        except Exception:
            log.exception(
                f"An unhandled error occurred while collecting {project.rtdname}"
            )

        return {"root": gpc.root, "graph": gpc.graph, "project": gpc.project}

    @staticmethod
    def add_args(arg_parser: ArgumentParser) -> None:
        arg_parser.add_argument(
            "--gcp-zone",
            help="GCP Zone",
            dest="gcp_zone",
            type=str,
            default=None,
            nargs="+",
        )
        arg_parser.add_argument(
            "--gcp-service-account",
            help="GCP Service Account File",
            dest="gcp_service_account",
            type=str,
            default=[],
            nargs="+",
        )
        arg_parser.add_argument(
            "--gcp-project",
            help="GCP Project",
            dest="gcp_project",
            type=str,
            default=[],
            nargs="+",
        )
        arg_parser.add_argument(
            "--gcp-project-pool-size",
            help="GCP Project Thread Pool Size (default: 5)",
            dest="gcp_project_pool_size",
            default=5,
            type=int,
        )
        arg_parser.add_argument(
            "--gcp-zone-pool-size",
            help="GCP Zone Thread Pool Size (default: 20)",
            dest="gcp_zone_pool_size",
            default=20,
            type=int,
        )
        arg_parser.add_argument(
            "--gcp-fork",
            help="GCP use forked process instead of threads (default: False)",
            dest="gcp_fork",
            action="store_true",
        )


class GCPProjectCollector:
    def __init__(self, project: GCPProject, credentials) -> None:
        self.project = project
        self.credentials = credentials
        self.root = self.project
        self.graph = Graph()
        resource_attr = get_resource_attributes(self.root)
        self.graph.add_node(self.root, label=self.root.name, **resource_attr)

    def collect(self) -> None:
        log.debug(f"Collecting {self.project.rtdname}")
        self.collect_regions()
        self.collect_zones()
        self.collect_instances()
        self.collect_disk_types()
        self.collect_disks()

    def default_attributes(
        self, result: Dict, attr_map: Dict = None, search_map: Dict = None
    ) -> Dict:
        ctime = (
            iso2datetime(result["creationTimestamp"])
            if "creationTimestamp" in result
            else None
        )
        kwargs = {
            "identifier": result.get("id", result.get("name", result.get("selfLink"))),
            "tags": result.get("labels", {}),
            "name": result.get("name"),
            "ctime": ctime,
            "link": result.get("selfLink"),
            "label_fingerprint": result.get("labelFingerprint"),
            "account": self.project,
        }
        if attr_map is not None:
            for map_to, map_from in attr_map.items():
                if map_from in result:
                    kwargs[map_to] = result[map_from]

        default_search_map = {"region": ["link", "region"], "zone": ["link", "zone"]}
        search_results = {}
        if search_map is None:
            search_map = dict(default_search_map)
        else:
            search_map.update(default_search_map)

        for map_to, search_data in search_map.items():
            search_attr = search_data[0]
            search_value_name = search_data[1]
            if not search_value_name in result:
                continue
            search_value = result[search_value_name]
            if isinstance(search_value, List):
                search_values = search_value
            else:
                search_values = [search_value]
            for search_value in search_values:
                search_result = self.graph.search_first(search_attr, search_value)
                if search_result:
                    if not map_to in search_results:
                        search_results[map_to] = []
                    search_results[map_to].append(search_result)
            if map_to not in kwargs and map_to in search_results and not str(map_to).startswith("__"):
                search_result = search_results[map_to]
                if len(search_result) == 1:
                    kwargs[map_to] = search_result[0]
                else:
                    kwargs[map_to] = list(search_result)
        if (
            "zone" in kwargs
            and "region" not in kwargs
            and isinstance(kwargs["zone"], BaseResource)
        ):
            region = kwargs["zone"].region(self.graph)
            if region:
                kwargs["region"] = region
                if "region" in search_map.keys() and "region" not in search_results:
                    search_results["region"] = region

        return kwargs, search_results

    def collect_something(
        self,
        client_method_name: str,
        resource_class: Type[BaseResource],
        paginate_method_name: str = "list",
        paginate_items_name: str = "items",
        parent_resource: Union[BaseResource, str] = None,
        attr_map: Dict = None,
        search_map: Dict = None,
        successors: List = None,
        predecessors: List = None,
        compute_client_kwargs: Dict = None,
        paginate_subitems_name: str = None,
        dump_resource: bool = False,
    ) -> List:
        log.info(f"Collecting {client_method_name}")
        if paginate_subitems_name is None:
            paginate_subitems_name = client_method_name
        if compute_client_kwargs is None:
            compute_client_kwargs = {}
        if successors is None:
            successors = []
        if predecessors is None:
            predecessors = []
        parent_map = {True: predecessors, False: successors}

        client = compute_client(credentials=self.credentials, **compute_client_kwargs)
        resources = getattr(client, client_method_name)
        if not callable(resources):
            raise RuntimeError(f"No method {client_method_name} on client {client}")

        for resource in paginate(
            resource=resources(),
            method_name=paginate_method_name,
            items_name=paginate_items_name,
            subitems_name=paginate_subitems_name,
            project=self.project.id,
        ):
            if dump_resource:
                log.debug(f"Resource Dump: {pformat(resource)}")

            kwargs, search_results = self.default_attributes(
                resource, attr_map=attr_map, search_map=search_map
            )
            r = resource_class(**kwargs)
            pr = parent_resource
            if isinstance(pr, str) and pr in search_results:
                pr = search_results[parent_resource][0]
                log.debug(f"Parent resource for {r.rtdname} set to {pr.rtdname}")

            if not isinstance(pr, BaseResource):
                pr = kwargs.get("zone", kwargs.get("region", self.root))
                log.debug(
                    f"Parent resource for {r.rtdname} automatically set to {pr.rtdname}"
                )

            log.debug(f"Adding {r.rtdname} to the graph")
            self.graph.add_resource(pr, r)
            for is_parent, sr_names in parent_map.items():
                for sr_name in sr_names:
                    if sr_name in search_results:
                        srs = search_results[sr_name]
                        for sr in srs:
                            if is_parent:
                                src = sr
                                dst = r
                            else:
                                src = r
                                dst = sr
                            if not self.graph.has_edge(src, dst):
                                log.debug(
                                    f"Adding edge from {src.rtdname} to {dst.rtdname}"
                                )
                                self.graph.add_edge(src, dst)
                            else:
                                log.error(
                                    (
                                        f"Edge from {src.rtdname} to {dst.rtdname}"
                                        " already exists in graph"
                                    )
                                )
                                continue
                    else:
                        if sr_name in search_map:
                            graph_search = search_map[sr_name]
                            attr = graph_search[0]
                            value_name = graph_search[1]
                            if value_name in resource:
                                value = resource[value_name]
                                if isinstance(value, List):
                                    values = value
                                    for value in values:
                                        r.add_deferred_connection(
                                            attr, value, is_parent
                                        )
                                elif isinstance(value, str):
                                    r.add_deferred_connection(attr, value, is_parent)
                                else:
                                    log.error(
                                        (
                                            "Unable to add deferred connection for"
                                            f" value {value} of type {type(value)}"
                                        )
                                    )
                        else:
                            log.error(f"Key {sr_name} is missing in search_map")

    def collect_regions(self) -> List:
        self.collect_something(
            client_method_name="regions",
            resource_class=GCPRegion,
            attr_map={"region_status": "status"},
        )

    def collect_zones(self) -> List:
        self.collect_something(
            client_method_name="zones",
            resource_class=GCPZone,
        )

    def collect_disks(self):
        self.collect_something(
            client_method_name="disks",
            paginate_method_name="aggregatedList",
            resource_class=GCPDisk,
            search_map={
                "volume_type": ["link", "type"],
                "__users": ["link", "users"],
            },
            attr_map={
                "volume_size": "sizeGb",
                "volume_status": "status",
            },
            predecessors=["volume_type"],
            successors=["__users"],
        )

    def collect_instances(self):
        self.collect_something(
            client_method_name="instances",
            paginate_method_name="aggregatedList",
            resource_class=GCPInstance,
        )

    def collect_disk_types(self):
        self.collect_something(
            client_method_name="diskTypes",
            paginate_method_name="aggregatedList",
            resource_class=GCPDiskType,
        )
