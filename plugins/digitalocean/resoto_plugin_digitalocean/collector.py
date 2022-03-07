from doctest import FAIL_FAST
from re import T
from resotolib.baseresources import BaseResource
import resotolib.logging
from retrying import retry
from resotolib.graph import Graph
from .client import StreamingWrapper
from resotolib.args import ArgumentParser
from prometheus_client import Summary
from typing import Tuple, Type, List, Dict, Union, Callable, Any
from resotolib.baseresources import BaseResource, EdgeType
from .resources import (
    DigitalOceanDroplet,
    DigitalOceanProject,
    DigitalOceanRegion,
    DigitalOceanTeam,
    DigitalOceanVolume,
    DigitalOceanDatabase,
    DigitalOceanNetwork,
    DigitalOceanKubernetesCluster,
    DigitalOceanSnapshot,
    DigitalOceanLoadBalancer,
    DigitalOceanFloatingIP,
)
from pprint import pformat
from .utils import (
    iso2datetime,
    get_result_data,
    region_id,
    project_id,
    droplet_id,
)


log = resotolib.logging.getLogger("resoto." + __name__)

metrics_collect_projects = Summary(
    "resoto_plugin_digitalocean_collect_projects_seconds",
    "Time it took the collect_projects() method",
)
metrics_collect_databases = Summary(
    "resoto_plugin_digitalocean_collect_databases_seconds",
    "Time it took the collect_databases() method",
)
metrics_collect_spaces = Summary(
    "resoto_plugin_digitalocean_collect_spaces_seconds",
    "Time it took the collect_spaces() method",
)
metrics_collect_intances = Summary(
    "resoto_plugin_digitalocean_collect_droplets_seconds",
    "Time it took the collect_droplets() method",
)
metrics_collect_regions = Summary(
    "resoto_plugin_digitalocean_collect_regions_seconds",
    "Time it took the collect_regions() method",
)
metrics_collect_volumes = Summary(
    "resoto_plugin_digitalocean_collect_volumes_seconds",
    "Time it took the collect_volumes() method",
)
metrics_collect_vpcs = Summary(
    "resoto_plugin_digitalocean_collect_vpcs_seconds",
    "Time it took the collect_vpcs() method",
)
metrics_collect_k8s_clusters = Summary(
    "resoto_plugin_digitalocean_collect_kubernetes_clusters_seconds",
    "Time it took the collect_kubernetes_clusters() method",
)
metrics_collect_snapshots = Summary(
    "resoto_plugin_digitalocean_collect_snapshots_seconds",
    "Time it took the collect_snapshots() method",
)
metrics_collect_load_balancers = Summary(
    "resoto_plugin_digitalocean_collect_load_balancers_seconds",
    "Time it took the collect_load_balancers() method",
)
metrics_collect_floating_ips = Summary(
    "resoto_plugin_digitalocean_collect_floating_ips_seconds",
    "Time it took the collect_floating_ips() method",
)


class DigitalOceanTeamCollector:
    """Collects a single DigitalOcean team

    Responsible for collecting all the resources of an individual team.
    Builds up its own local graph which is then taken by collect_project()
    and merged with the plugin graph.

    This way we can have many instances of DigitalOceanCollectorPlugin running in parallel.
    All building up indivetual graphs which in the end are merged to a final graph containing
    all DigitalOcean resources
    """

    def __init__(self, team: DigitalOceanTeam, client: StreamingWrapper) -> None:
        self.client = client
        self.team = team

        # Mandatory collectors are always collected regardless of whether
        # they were included by --do-collect or excluded by --do-no-collect
        self.mandatory_collectors: List[Tuple[str, Callable]] = [
            ("regions", self.collect_regions)
        ]
        # Global collectors are resources that are either specified on a global level
        # as opposed to a per zone or per region level or they are zone/region
        # resources that provide a aggregatedList() function returning all resources
        # for all zones/regions.
        self.global_collectors: List[Tuple[str, Callable]] = [
            ("vpcs", self.collect_vpcs),
            ("instances", self.collect_instances),
            ("volumes", self.collect_volumes),
            ("databases", self.collect_databases),
            ("project", self.collect_projects),
            ("k8s_clusters", self.collect_k8s_clusters),
            ("snapshots", self.collect_snapshots),
            ("load_balancers", self.collect_load_balancers),
            ("floating_ips", self.collect_floating_ips),
        ]
        self.all_collectors = dict(self.mandatory_collectors)
        self.all_collectors.update(self.global_collectors)
        self.collector_set = set(self.all_collectors.keys())


    def collect(self) -> None:
        """Runs the actual resource collection across all resource collectors.

        Resource collectors add their resources to the local `self.graph` graph.
        """
        log.info("Collecting DigitalOcean resources for team %s", self.team.id)

        self.graph = Graph(root=self.team)
        collectors = set(self.collector_set)

        log.debug(
            (
                f"Running the following collectors in {self.team.rtdname}:"
                f" {', '.join(collectors)}"
            )
        )

        for collector_name, collector in self.mandatory_collectors:
            if collector_name in collectors:
                log.info(f"Collecting {collector_name} in {self.team.rtdname}")
                collector()

        for collector_name, collector in self.global_collectors:
            if collector_name in collectors:
                log.info(f"Collecting {collector_name} in {self.team.rtdname}")
                collector()

        remove_nodes = set()

        def rmnodes(cls) -> None:
            for node in self.graph.nodes:
                if isinstance(node, cls) and not any(
                    True for _ in self.graph.successors(node)
                ):
                    remove_nodes.add(node)
            for node in remove_nodes:
                self.graph.remove_node(node)
            log.debug(f"Removing {len(remove_nodes)} unreferenced nodes of type {cls}")
            remove_nodes.clear()

        rmnodes(DigitalOceanRegion)


    def default_attributes(
        self, result: Dict, attr_map: Dict = None, search_map: Dict = None
    ) -> Dict:
        """See a similar method in the GCPCollectorPlugin"""
        # The following are default attributes that are passed to every
        # BaseResource() if found in `result`
        kwargs = {
            "id": str(result.get("id")),
            #"tags": dict([(tag,"") for tag in result.get("tags", [])]),
            "name": result.get("name"),
            "ctime": iso2datetime(result.get("created_at")),
            "mtime": iso2datetime(result.get("updated_at")),
            "_account": self.team,
        }

        if attr_map is not None:
            for map_to, map_from in attr_map.items():
                data = get_result_data(result, map_from)
                if data is None:
                    log.debug(f"Attribute {map_from} not in result")
                    continue
                log.debug(f"Found attribute {map_to}: {pformat(data)}")
                kwargs[map_to] = data

        # By default we search for a resources region and/or zone
        default_search_map = {}
        search_results = {}
        if search_map is None:
            search_map = dict(default_search_map)
        else:
            updated_search_map = dict(default_search_map)
            updated_search_map.update(search_map)
            search_map = updated_search_map

        for map_to, search_data in search_map.items():
            search_attr = search_data[0]
            search_value_name = search_data[1]
            search_value = get_result_data(result, search_value_name)
            if search_value is None:
                continue
            if isinstance(search_value, List):
                search_values = search_value
            else:
                search_values = [search_value]
            for search_value in search_values:
                search_result = self.graph.search_first(search_attr, search_value)
                if search_result:
                    if map_to not in search_results:
                        search_results[map_to] = []
                    search_results[map_to].append(search_result)
            if (
                map_to not in kwargs
                and map_to in search_results
                and not str(map_to).startswith("__")
            ):
                search_result = search_results[map_to]
                if len(search_result) == 1:
                    kwargs[map_to] = search_result[0]
                else:
                    kwargs[map_to] = list(search_result)

        # If the resource was referencing a zone but not a region we look up its
        # region based on the zone information we found.
        # E.g. if we know a disk is in zone us-central1-a then we can find
        # the region us-central1 from that.
        if (
            "_zone" in kwargs
            and "_region" not in kwargs
            and isinstance(kwargs["_zone"], BaseResource)
        ):
            region = kwargs["_zone"].region(self.graph)
            if region:
                kwargs["_region"] = region
                if "_region" in search_map.keys() and "_region" not in search_results:
                    search_results["_region"] = region

        return kwargs, search_results

    def collect_something(
        self,
        resources: List[Dict[str, Any]],
        resource_class: Type[BaseResource],
        parent_resource: Union[BaseResource, str] = None,
        attr_map: Dict = None,
        search_map: Dict = None,
        successors: Dict[EdgeType, List[str]] = None,
        predecessors: Dict[EdgeType, List[str]] = None,
        post_process: Callable = None,
        dump_resource: bool = False,
    ) -> List:

        if successors is None:
            successors = {}
        if predecessors is None:
            predecessors = {}
        parent_map = {True: predecessors, False: successors}


        for resource in resources:
            kwargs, search_results = self.default_attributes(
                resource, attr_map=attr_map, search_map=search_map
            )
            r = resource_class(**kwargs)
            pr = parent_resource
            log.debug(f"Adding {r.rtdname} to the graph")
            if dump_resource:
                log.debug(f"Resource Dump: {pformat(resource)}")

            if isinstance(pr, str) and pr in search_results:
                pr = search_results[parent_resource][0]
                log.debug(f"Parent resource for {r.rtdname} set to {pr.rtdname}")

            if not isinstance(pr, BaseResource):
                pr = kwargs.get("_zone", kwargs.get("_region", self.graph.root))
                log.debug(
                    f"Parent resource for {r.rtdname} automatically set to {pr.rtdname}"
                )
            self.graph.add_resource(pr, r, edge_type=EdgeType.default)

            for is_parent, edge_sr_names in parent_map.items():
                for edge_type, sr_names in edge_sr_names.items():
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
                                self.graph.add_edge(src, dst, edge_type=edge_type)
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
                                                attr,
                                                value,
                                                is_parent,
                                                edge_type=edge_type,
                                            )
                                    elif isinstance(value, str):
                                        r.add_deferred_connection(
                                            attr, value, is_parent, edge_type=edge_type
                                        )
                                    else:
                                        log.error(
                                            (
                                                "Unable to add deferred connection for"
                                                f" value {value} of type {type(value)}"
                                            )
                                        )
                            else:
                                log.error(f"Key {sr_name} is missing in search_map")
            if callable(post_process):
                post_process(r, self.graph)


        
    @metrics_collect_intances.time()
    def collect_instances(self) -> None:
        instances = self.client.list_droplets()
        self.collect_something(
            instances,
            resource_class=DigitalOceanDroplet,
            attr_map={
                "id": lambda d: droplet_id(d["id"]),
                "instance_status": "status",
                "instance_cores": "vcpus",
                "instance_memory": "memory",
                "backup_ids": "backup_ids",
                "locked": "locked",
                "features": "features",
                "image": lambda d: d["image"]["slug"],
            },
            search_map={
                "_region": ["id", lambda droplet: region_id(droplet['region']['slug'])],
                "__vpcs": ["id", lambda droplet: droplet['vpc_uuid']],

            },
            predecessors={EdgeType.default: ["__vpcs"]},
        )

    @metrics_collect_regions.time()
    def collect_regions(self) -> None:
        regions = self.client.list_regions()
        self.collect_something(
            regions,
            resource_class=DigitalOceanRegion,
            attr_map={
                "id": lambda r: region_id(r["slug"]),
                "name": "name",
                "slug": "slug",
                "features": "features",
                "available": "available",
                "sizes": "sizes", 
            },
            search_map={},
        )


    @metrics_collect_volumes.time()
    def collect_volumes(self) -> None:
        volumes = self.client.list_volumes()
        self.collect_something(
            volumes,
            resource_class=DigitalOceanVolume,
            attr_map={
                "volume_size": "size_gigabytes",
            },
            search_map={
                "__users": ["id", lambda vol: list(map(lambda id: droplet_id(id), vol["droplet_ids"]))],
            },
            predecessors={EdgeType.default: ["__users"]},
        )

    @metrics_collect_databases.time()
    def collect_databases(self) -> None:

        # this mapping was taken from the digitalocean web console.
        dbtype_to_size = {
            "db-s-1vcpu-1gb": 10,
            "db-s-1vcpu-2gb": 25,
            "db-s-2vcpu-4gb": 38,
            "db-s-4vcpu-8gb": 115,
            "db-s-6vcpu-16gb": 270,
            "db-s-8vcpu-32gb": 580,
            "db-s-16vcpu-64gb": 1012,
            "gd-2vcpu-8gb": 25,
            "gd-4vcpu-16gb": 60,
            "gd-8vcpu-32gb": 145,
            "gd-16vcpu-64gb": 325,
            "gd-32vcpu-128gb": 695,
            "gd-40vcpu-160gb": 875,
            "so1_5-2vcpu-16gb": 400,
            "so1_5-4vcpu-32gb": 845,
            "so1_5-8vcpu-64gb": 1680,
            "so1_5-16vcpu-128gb": 3410,
            "so1_5-24vcpu-192gb": 5140,
            "so1_5-32vcpu-256gb": 6860,
        }

        databases = self.client.list_databases()
        self.collect_something(
            databases,
            resource_class=DigitalOceanDatabase,
            attr_map={
                "db_type": "engine",
                "db_status": "status",
                "db_version": "version",
                "db_endpoint": lambda db: db.get("connection", {}).get("host", ""),
                "instance_type": "size",
                "volume_size": lambda db: dbtype_to_size.get(db.get("size", "") , 0),
            },
            search_map={
                "_region": ["id", lambda db: region_id(db["region"])],
                "__vpcs": ["id", lambda db: db["private_network_uuid"]],
            },
            predecessors={EdgeType.default: ["__vpcs"]},
        )

    @metrics_collect_vpcs.time()
    def collect_vpcs(self) -> None:
        vpcs = self.client.list_vpcs()
        self.collect_something(
            vpcs,
            resource_class=DigitalOceanNetwork,
            search_map={
                "_region": ["id", lambda vpc: region_id(vpc["region"])],
            },
        )

    @metrics_collect_projects.time()
    def collect_projects(self) -> None:
        def get_resource_id(resource):
            return resource["urn"].split(":")[-1]
        projects = self.client.list_projects()
        project_resources = [list(map(get_resource_id, self.client.list_project_resources(p['id']))) for p in projects]


        for project, resource_ids in zip(projects, project_resources):
            project['resource_ids'] = resource_ids

        self.collect_something(
            projects,
            resource_class=DigitalOceanProject,
            attr_map={
                "id": lambda p: project_id(p["id"]),
                "owner_uuid": "owner_uuid",
                "owner_id": lambda p: str(p["owner_id"]),
                "description": "description",
                "purpose": "purpose",
                "environment": "environment",
                "is_default": "is_default",
            },
            search_map={
                "__resources": ["id", lambda p: p["resource_ids"]],
            },
            successors={EdgeType.default: ["__resources"]},
        )

    @metrics_collect_k8s_clusters.time()
    def collect_k8s_clusters(self) -> None:
        clusters = self.client.list_kubernetes_clusters()
        self.collect_something(
            clusters,
            resource_class=DigitalOceanKubernetesCluster,
            search_map={
                "_region": ["id", lambda c: region_id(c["region"])],
                "__nodes" : ["id", lambda cluster: [droplet_id(node["droplet_id"]) for node_pool in cluster["node_pools"] for node in node_pool["nodes"]]],
            },
            successors={EdgeType.default: ["__nodes"]},
        )

    @metrics_collect_snapshots.time()
    def collect_snapshots(self) -> None:
        snapshots = self.client.list_snapshots()
        self.collect_something(
            snapshots,
            resource_class=DigitalOceanSnapshot,
            attr_map={
                "volume_size": lambda vol: vol["min_disk_size"],
            },
            search_map={
                "_region": ["id", lambda s: [region_id(region) for region in s["regions"]]],
                "__resource": ["id", "resource_id"],
            },
            predecessors={EdgeType.default: ["__resource"]},
        )

    @metrics_collect_load_balancers.time()
    def collect_load_balancers(self) -> None:
        loadbalancers = self.client.list_load_balancers()
        self.collect_something(
            loadbalancers,
            resource_class=DigitalOceanLoadBalancer,
            search_map={
                "_region": ["id", lambda lb: region_id(lb['region']['slug'])],
                "__vpcs": ["id", lambda lb: lb['vpc_uuid']],
                "__droplets": ["id", lambda lb: list(map(lambda id: droplet_id(id), lb["droplet_ids"]))],
            },
            predecessors={
                EdgeType.default: ["__vpcs"]
            },
            successors={
                EdgeType.default: ["__droplets"]
            }
        )

    @metrics_collect_floating_ips.time()
    def collect_floating_ips(self) -> None:
        floating_ips = self.client.list_floating_ips()
        self.collect_something(
            floating_ips,
            resource_class=DigitalOceanFloatingIP,
            attr_map={
                "ip_address": "ip",
            },
            search_map={
                "_region": ["id", lambda ip: region_id(ip['region']['slug'])],
                "__droplet": ["id", lambda ip: droplet_id(ip.get("droplet", {}).get("id", ""))],
            },
            predecessors={
                EdgeType.default: ["__droplet"]
            },
        )
