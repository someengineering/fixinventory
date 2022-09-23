import logging
import math
from pprint import pformat
from typing import Tuple, Type, List, Dict, Callable, Any, Optional, cast

from prometheus_client import Summary

from resotolib.baseresources import BaseResource, EdgeType, InstanceStatus, VolumeStatus
from resotolib.graph import Graph
from resotolib.types import Json
from .client import StreamingWrapper
from .resources import (
    DigitalOceanDroplet,
    DigitalOceanDropletSize,
    DigitalOceanProject,
    DigitalOceanRegion,
    DigitalOceanTeam,
    DigitalOceanVolume,
    DigitalOceanDatabase,
    DigitalOceanVPC,
    DigitalOceanKubernetesCluster,
    DigitalOceanSnapshot,
    DigitalOceanLoadBalancer,
    DigitalOceanFloatingIP,
    DigitalOceanImage,
    DigitalOceanSpace,
    DigitalOceanApp,
    DigitalOceanCdnEndpoint,
    DigitalOceanCertificate,
    DigitalOceanContainerRegistry,
    DigitalOceanContainerRegistryRepository,
    DigitalOceanContainerRegistryRepositoryTag,
    DigitalOceanSSHKey,
    DigitalOceanTag,
    DigitalOceanDomain,
    DigitalOceanDomainRecord,
    DigitalOceanFirewall,
    DigitalOceanAlertPolicy,
)
from .utils import (
    iso2datetime,
    get_result_data,
    kubernetes_id,
    region_id,
    project_id,
    droplet_id,
    volume_id,
    vpc_id,
    snapshot_id,
    loadbalancer_id,
    floatingip_id,
    database_id,
    image_id,
    size_id,
    space_id,
    app_id,
    cdn_endpoint_id,
    certificate_id,
    container_registry_id,
    container_registry_repository_id,
    container_registry_repository_tag_id,
    ssh_key_id,
    tag_id,
    domain_id,
    domain_record_id,
    firewall_id,
    alert_policy_id,
    parse_tag,
)

log = logging.getLogger("resoto." + __name__)

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
metrics_collect_droplets = Summary(
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
metrics_collect_apps = Summary(
    "resoto_plugin_digitalocean_collect_apps_seconds",
    "Time it took the collect_apps() method",
)
metrics_collect_cdn_endpoints = Summary(
    "resoto_plugin_digitalocean_collect_cdn_endpoints_seconds",
    "Time it took the collect_cdn_endpoints() method",
)
metrics_collect_certificates = Summary(
    "resoto_plugin_digitalocean_collect_certificates_seconds",
    "Time it took the collect_certificates() method",
)
metrics_collect_container_registry = Summary(
    "resoto_plugin_digitalocean_collect_container_registry_seconds",
    "Time it took the collect_container_registry() method",
)
metrics_collect_ssh_keys = Summary(
    "resoto_plugin_digitalocean_collect_ssh_keys_seconds",
    "Time it took the collect_ssh_keys() method",
)
metrics_collect_tags = Summary(
    "resoto_plugin_digitalocean_collect_tags_seconds",
    "Time it took the collect_tags() method",
)
metrics_collect_domains = Summary(
    "resoto_plugin_digitalocean_collect_domains_seconds",
    "Time it took the collect_domains() method",
)
metrics_collect_domains_records = Summary(
    "resoto_plugin_digitalocean_collect_domains_records_seconds",
    "Time it took the collect_domains_records() method",
)
metrics_collect_firewalls = Summary(
    "resoto_plugin_digitalocean_collect_firewalls_seconds",
    "Time it took the collect_firewalls() method",
)
metrics_collect_alert_policies = Summary(
    "resoto_plugin_digitalocean_collect_alert_policies_seconds",
    "Time it took the collect_alert_policies() method",
)
metrics_collect_droplet_sizes = Summary(
    "resoto_plugin_digitalocean_collect_droplet_sizes_seconds",
    "Time it took the collect_droplet_sizes() method",
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
        self.mandatory_collectors: List[Tuple[str, Callable[..., None]]] = [("regions", self.collect_regions)]
        # Global collectors are resources that are either specified on a global level
        # as opposed to a per zone or per region level or they are zone/region
        # resources that provide a aggregatedList() function returning all resources
        # for all zones/regions.
        self.global_collectors: List[Tuple[str, Callable[..., None]]] = [
            ("tags", self.collect_tags),
            ("vpcs", self.collect_vpcs),
            ("instances", self.collect_droplets),
            ("volumes", self.collect_volumes),
            ("databases", self.collect_databases),
            ("k8s_clusters", self.collect_k8s_clusters),
            ("snapshots", self.collect_snapshots),
            ("load_balancers", self.collect_load_balancers),
            ("floating_ips", self.collect_floating_ips),
            ("project", self.collect_projects),
            ("apps", self.collect_apps),
            ("cdn_endpoints", self.collect_cdn_endpoints),
            ("certificates", self.collect_certificates),
            ("container_registry", self.collect_container_registry),
            ("ssh_keys", self.collect_ssh_keys),
            ("domains", self.collect_domains),
            ("firewalls", self.collect_firewalls),
            ("alert_policies", self.collect_alert_policies),
        ]

        self.region_collectors: List[Tuple[str, Callable[..., None]]] = [
            ("spaces", self.collect_spaces),
        ]

        self.all_collectors = dict(self.mandatory_collectors)
        self.all_collectors.update(self.region_collectors)
        self.all_collectors.update(self.global_collectors)
        self.collector_set = set(self.all_collectors.keys())

    def collect(self) -> None:
        """Runs the actual resource collection across all resource collectors.

        Resource collectors add their resources to the local `self.graph` graph.
        """
        log.info("Collecting DigitalOcean resources for team %s", self.team.id)

        self.graph = Graph(root=self.team)
        collectors = set(self.collector_set)

        log.debug((f"Running the following collectors in {self.team.rtdname}:" f" {', '.join(collectors)}"))

        for collector_name, collector in self.mandatory_collectors:
            if collector_name in collectors:
                log.info(f"Collecting {collector_name} in {self.team.rtdname}")
                collector()

        regions = [r for r in self.graph.nodes if isinstance(r, DigitalOceanRegion)]

        for region in regions:
            for collector_name, collector in self.region_collectors:
                if collector_name in collectors:
                    log.info((f"Collecting {collector_name} in {region.rtdname}" f" {self.team.rtdname}"))
                    collector(region=region)

        for collector_name, collector in self.global_collectors:
            if collector_name in collectors:
                log.info(f"Collecting {collector_name} in {self.team.rtdname}")
                collector()

        remove_nodes = set()

        def rmnodes(cls: Any) -> None:
            for node in self.graph.nodes:
                if isinstance(node, cls) and not any(True for _ in self.graph.successors(node)):
                    remove_nodes.add(node)
            for node in remove_nodes:
                self.graph.remove_node(node)
            log.debug(f"Removing {len(remove_nodes)} unreferenced nodes of type {cls}")
            remove_nodes.clear()

        # since regions API will return all available regions, we need to remove
        # the regions that are not used by any resources
        rmnodes(DigitalOceanRegion)

    def default_attributes(
        self,
        result: Dict[str, Any],
        attr_map: Dict[str, Any],
        search_map: Dict[str, Any],
    ) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        """See a similar method in the GCPCollectorPlugin"""
        # The following are default attributes that are passed to every
        # BaseResource() if found in `result`
        def extract_tags(result: Dict[str, Any]) -> Dict[str, Optional[str]]:
            raw_tags = result.get("tags", [])
            raw_tags = raw_tags if raw_tags else []
            tags = [parse_tag(tag) for tag in raw_tags if tag]
            return dict(tags) if tags else {}

        kwargs = {
            "id": str(result.get("id")),
            "tags": extract_tags(result),
            "name": result.get("name"),
            "ctime": iso2datetime(result.get("created_at")),
            "mtime": iso2datetime(result.get("updated_at")),
            "_account": self.team,
        }

        if attr_map is not None:
            for map_to, attribute_selector in attr_map.items():
                data = get_result_data(result, attribute_selector)
                if data is None:
                    log.debug(f"Attribute {attribute_selector} not in result")
                    continue
                log.debug(f"Found attribute {map_to}: {pformat(data)}")
                kwargs[map_to] = data

        # By default we search for a resources region and/or zone
        default_search_map: Dict[str, Any] = {}
        search_results: Dict[str, Any] = {}
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
            if map_to not in kwargs and map_to in search_results and not str(map_to).startswith("__"):
                search_result = search_results[map_to]
                if len(search_result) == 1:
                    kwargs[map_to] = search_result[0]
                else:
                    kwargs[map_to] = list(search_result)

        # If the resource was referencing a zone but not a region we look up its
        # region based on the zone information we found.
        # E.g. if we know a disk is in zone us-central1-a then we can find
        # the region us-central1 from that.
        if "_zone" in kwargs and "_region" not in kwargs and isinstance(kwargs["_zone"], BaseResource):
            region = kwargs["_zone"].region(self.graph)
            if region:
                kwargs["_region"] = region
                if "_region" in search_map.keys() and "_region" not in search_results:
                    search_results["_region"] = region

        return kwargs, search_results

    def collect_resource(
        self,
        resources: List[Json],
        resource_class: Type[BaseResource],
        attr_map: Dict[str, Any],
        search_map: Optional[Dict[str, Any]] = None,
        successors: Optional[Dict[EdgeType, List[str]]] = None,
        predecessors: Optional[Dict[EdgeType, List[str]]] = None,
        dump_resource: bool = False,
    ) -> None:

        if successors is None:
            successors = {}
        if predecessors is None:
            predecessors = {}
        if search_map is None:
            search_map = {}
        parent_map = {True: predecessors, False: successors}

        for resource_json in resources:
            kwargs, search_results = self.default_attributes(resource_json, attr_map=attr_map, search_map=search_map)
            kwargs_no_underscore = {}
            for key, value in kwargs.items():
                if key.startswith("_"):
                    kwargs_no_underscore[key[1:]] = value
                else:
                    kwargs_no_underscore[key] = value
            resource_instance = resource_class(**kwargs_no_underscore)
            log.debug(f"Adding {resource_instance.rtdname} to the graph")
            if dump_resource:
                log.debug(f"Resource Dump: {pformat(resource_json)}")

            pr = kwargs.get("_region", self.graph.root)
            log.debug(f"Parent resource for {resource_instance.rtdname} automatically set to {pr.rtdname}")
            self.graph.add_resource(pr, resource_instance, edge_type=EdgeType.default)

            def add_deferred_connection(
                search_map: Dict[str, Any],
                search_map_key: str,
                is_parent: bool,
                edge_type: EdgeType,
            ) -> None:
                graph_search = search_map[search_map_key]
                attr = graph_search[0]
                value_name = graph_search[1]
                if value_name in resource_json:
                    value = resource_json[value_name]
                    if isinstance(value, List):
                        values = value
                        for value in values:
                            resource_instance.add_deferred_connection(
                                {attr: value},
                                is_parent,
                                edge_type=edge_type,
                            )
                    elif isinstance(value, str):
                        resource_instance.add_deferred_connection(
                            {attr: value},
                            is_parent,
                            edge_type=edge_type,
                        )
                    else:
                        log.error("Unable to add deferred connection for" f" value {value} of type {type(value)}")

            def add_edge(search_map_key: str, is_parent: bool) -> None:
                srs = search_results[search_map_key]
                for sr in srs:
                    if is_parent:
                        src = sr
                        dst = resource_instance
                    else:
                        src = resource_instance
                        dst = sr
                    self.graph.add_edge(src, dst, edge_type=edge_type)

            for is_parent, edge_sr_names in parent_map.items():
                for edge_type, search_result_names in edge_sr_names.items():
                    for search_result_name in search_result_names:
                        if search_result_name in search_results:
                            add_edge(search_result_name, is_parent)
                        else:
                            if search_result_name in search_map:
                                add_deferred_connection(search_map, search_result_name, is_parent, edge_type)
                            else:
                                log.error(f"Key {search_result_name} is missing in search_map")

    @metrics_collect_droplets.time()  # type: ignore
    def collect_droplets(self) -> None:
        instances = self.client.list_droplets()

        def get_image(droplet: Json) -> Json:
            image = droplet["image"]
            image["region"] = droplet["region"]["slug"]
            return cast(Json, image)

        def remove_duplicates(resources: List[Json], id_field: str) -> List[Json]:
            seen_ids = set()
            unique = []
            for resource in resources:
                if resource[id_field] not in seen_ids:
                    unique.append(resource)
                    seen_ids.add(resource[id_field])
            return unique

        images = [get_image(instance) for instance in instances]
        images = remove_duplicates(images, "id")

        self.collect_resource(
            images,
            resource_class=DigitalOceanImage,
            attr_map={
                "id": lambda i: str(i["id"]),
                "urn": lambda i: image_id(i["id"]),
                "distribution": "distribution",
                "image_slug": "slug",
                "is_public": "public",
                "min_disk_size": "min_disk_size",
                "image_type": "type",
                "size_gigabytes": lambda image: int(math.ceil(image.get("size_gigabytes"))),
                "description": "description",
                "image_status": "status",
            },
            search_map={
                "_region": ["urn", lambda image: region_id(image["region"])],
                "__tags": [
                    "urn",
                    lambda image: list(map(lambda tag: tag_id(tag), image.get("tags", []) or [])),
                ],
            },
            predecessors={
                EdgeType.default: ["__tags"],
            },
        )

        def get_size(droplet: Json) -> Json:
            size = droplet["size"]
            size["region"] = droplet["region"]["slug"]
            return cast(Json, size)

        sizes = [get_size(instance) for instance in instances]
        sizes = remove_duplicates(sizes, "slug")

        self.collect_resource(
            sizes,
            resource_class=DigitalOceanDropletSize,
            attr_map={
                "id": "slug",
                "urn": lambda s: size_id(s["slug"]),
                "instance_type": "slug",
                "instance_cores": "vcpus",
                "instance_memory": lambda d: d["memory"] / 1024.0,
                "ondemand_cost": "price_hourly",
            },
            search_map={
                "_region": ["urn", lambda image: region_id(image["region"])],
            },
        )

        instance_status_map: Dict[str, InstanceStatus] = {
            "new": InstanceStatus.BUSY,
            "active": InstanceStatus.RUNNING,
            "off": InstanceStatus.TERMINATED,
            "archive": InstanceStatus.TERMINATED,
        }
        self.collect_resource(
            instances,
            resource_class=DigitalOceanDroplet,
            attr_map={
                "id": lambda i: str(i["id"]),
                "urn": lambda d: droplet_id(d["id"]),
                "instance_status": lambda d: instance_status_map.get(d["status"], InstanceStatus.UNKNOWN),
                "instance_cores": "vcpus",
                "instance_memory": lambda d: d["memory"] / 1024.0,
                "droplet_backup_ids": lambda d: list(map(str, d.get("backup_ids", []) or [])),
                "is_locked": "locked",
                "droplet_features": "features",
                "droplet_image": lambda d: d["image"]["slug"],
            },
            search_map={
                "_region": [
                    "urn",
                    lambda droplet: region_id(droplet["region"]["slug"]),
                ],
                "__vpcs": ["urn", lambda droplet: vpc_id(droplet["vpc_uuid"])],
                "__images": ["urn", lambda droplet: image_id(droplet["image"]["id"])],
                "__sizes": ["urn", lambda droplet: size_id(droplet["size"]["slug"])],
                "__tags": [
                    "urn",
                    lambda d: list(map(lambda tag: tag_id(tag), d.get("tags", []))),
                ],
            },
            predecessors={
                EdgeType.default: ["__vpcs", "__images", "__sizes", "__tags"],
                EdgeType.delete: ["__vpcs"],
            },
        )

    @metrics_collect_regions.time()  # type: ignore
    def collect_regions(self) -> None:
        regions = self.client.list_regions()
        self.collect_resource(
            regions,
            resource_class=DigitalOceanRegion,
            attr_map={
                "id": "slug",
                "urn": lambda r: region_id(r["slug"]),
                "name": "name",
                "do_region_slug": "slug",
                "do_region_features": "features",
                "is_available": "available",
                "do_region_droplet_sizes": "sizes",
            },
        )

    @metrics_collect_volumes.time()  # type: ignore
    def collect_volumes(self) -> None:
        # taken from https://www.digitalocean.com/pricing/volumes
        DO_VOLUME_COST_GB_PER_HOUR = 0.000149
        volumes = self.client.list_volumes()

        def extract_volume_status(volume: Json) -> VolumeStatus:
            in_use = len(volume.get("droplet_ids", []) or []) > 0
            return VolumeStatus.IN_USE if in_use else VolumeStatus.AVAILABLE

        self.collect_resource(
            volumes,
            resource_class=DigitalOceanVolume,
            attr_map={
                "id": "id",
                "urn": lambda r: volume_id(r["id"]),
                "volume_size": "size_gigabytes",
                "description": "description",
                "filesystem_type": "filesystem_type",
                "filesystem_label": "filesystem_label",
                "volume_status": extract_volume_status,
                "ondemand_cost": lambda v: v["size_gigabytes"] * DO_VOLUME_COST_GB_PER_HOUR,
            },
            search_map={
                "__users": [
                    "urn",
                    lambda vol: list(map(lambda id: droplet_id(id), vol["droplet_ids"])),
                ],
                "__tags": [
                    "urn",
                    lambda v: list(map(lambda tag: tag_id(tag), v.get("tags", []))),
                ],
            },
            predecessors={EdgeType.default: ["__users", "__tags"]},
            successors={EdgeType.delete: ["__users"]},
        )

    @metrics_collect_databases.time()  # type: ignore
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
        self.collect_resource(
            databases,
            resource_class=DigitalOceanDatabase,
            attr_map={
                "id": "id",
                "urn": lambda db: database_id(db["id"]),
                "name": lambda db: database_id(db["name"]),
                "db_type": "engine",
                "db_status": "status",
                "db_version": "version",
                "db_endpoint": lambda db: db.get("connection", {}).get("host", ""),
                "instance_type": "size",
                "volume_size": lambda db: dbtype_to_size.get(db.get("size", ""), 0),
            },
            search_map={
                "_region": ["urn", lambda db: region_id(db["region"])],
                "__vpcs": ["urn", lambda db: vpc_id(db["private_network_uuid"])],
                "__tags": [
                    "urn",
                    lambda db: list(map(lambda tag: tag_id(tag), db.get("tags", []) or [])),
                ],
            },
            predecessors={
                EdgeType.default: ["__vpcs", "__tags"],
                EdgeType.delete: ["__vpcs"],
            },
        )

    @metrics_collect_vpcs.time()  # type: ignore
    def collect_vpcs(self) -> None:
        vpcs = self.client.list_vpcs()
        self.collect_resource(
            vpcs,
            resource_class=DigitalOceanVPC,
            attr_map={
                "id": "id",
                "urn": "urn",
                "ip_range": "ip_range",
                "description": "description",
                "is_default": "default",
            },
            search_map={
                "_region": ["urn", lambda vpc: region_id(vpc["region"])],
            },
        )

    @metrics_collect_projects.time()  # type: ignore
    def collect_projects(self) -> None:
        def get_resource_id(resource: Json) -> str:
            return cast(str, resource["urn"])

        projects = self.client.list_projects()
        project_resources = [list(map(get_resource_id, self.client.list_project_resources(p["id"]))) for p in projects]

        for project, resource_ids in zip(projects, project_resources):
            project["resource_ids"] = resource_ids

        self.collect_resource(
            projects,
            resource_class=DigitalOceanProject,
            attr_map={
                "id": "id",
                "urn": lambda p: project_id(p["id"]),
                "owner_uuid": "owner_uuid",
                "owner_id": lambda p: str(p["owner_id"]),
                "description": "description",
                "purpose": "purpose",
                "environment": "environment",
                "is_default": "is_default",
            },
            search_map={
                "__resources": ["urn", lambda p: p["resource_ids"]],
            },
            successors={
                EdgeType.default: ["__resources"],
                EdgeType.delete: ["__resources"],
            },
        )

    @metrics_collect_k8s_clusters.time()  # type: ignore
    def collect_k8s_clusters(self) -> None:
        clusters = self.client.list_kubernetes_clusters()
        self.collect_resource(
            clusters,
            resource_class=DigitalOceanKubernetesCluster,
            attr_map={
                "id": "id",
                "urn": lambda c: kubernetes_id(c["id"]),
                "k8s_version": "version",
                "k8s_cluster_subnet": "cluster_subnet",
                "k8s_service_subnet": "service_subnet",
                "ipv4_address": "ipv4",
                "endpoint": "endpoint",
                "auto_upgrade_enabled": "auto_upgrade",
                "cluster_status": lambda c: c["status"]["state"],
                "surge_upgrade_enabled": "surge_upgrade",
                "registry_enabled": "registry_enabled",
                "ha_enabled": "ha",
            },
            search_map={
                "_region": ["urn", lambda c: region_id(c["region"])],
                "__nodes": [
                    "urn",
                    lambda cluster: [
                        droplet_id(node["droplet_id"])
                        for node_pool in cluster["node_pools"]
                        for node in node_pool["nodes"]
                    ],
                ],
                "__vpcs": ["urn", lambda c: vpc_id(c["vpc_uuid"])],
            },
            successors={EdgeType.default: ["__nodes"], EdgeType.delete: ["__nodes"]},
            predecessors={EdgeType.default: ["__vpcs"], EdgeType.delete: ["__vpcs"]},
        )

    @metrics_collect_snapshots.time()  # type: ignore
    def collect_snapshots(self) -> None:
        def get_resource_id(snapshot: Json) -> str:
            if snapshot["resource_type"] == "droplet":
                return droplet_id(snapshot["resource_id"])
            else:
                return volume_id(snapshot["resource_id"])

        def get_region(snapshot: Json) -> str:
            resource_id = get_resource_id(snapshot)
            resource = self.graph.search_first("urn", resource_id)
            region = region_id(resource.region().id)
            return region

        snapshots = self.client.list_snapshots()
        self.collect_resource(
            snapshots,
            resource_class=DigitalOceanSnapshot,
            attr_map={
                "id": lambda s: str(s["id"]),
                "urn": lambda s: snapshot_id(s["id"]),
                "volume_size": lambda vol: vol["min_disk_size"],
                "snapshot_size_gigabytes": lambda vol: int(math.ceil(vol.get("size_gigabytes"))),
                "resource_id": "resource_id",
                "resource_type": "resource_type",
            },
            search_map={
                "_region": ["urn", lambda s: get_region(s)],
                "__available_regions": [
                    "urn",
                    lambda s: [region_id(region) for region in s["regions"]],
                ],
                "__resource": ["urn", lambda s: get_resource_id(s)],
                "__tags": [
                    "urn",
                    lambda s: list(map(lambda tag: tag_id(tag), s.get("tags", []) or [])),
                ],
            },
            predecessors={EdgeType.default: ["__resource", "__tags", "__available_regions"]},
        )

    @metrics_collect_load_balancers.time()  # type: ignore
    def collect_load_balancers(self) -> None:
        loadbalancers = self.client.list_load_balancers()

        def get_nr_nodes(lb: Json) -> int:
            size_to_nr_nodes = {
                "lb-small": 1,
                "lb-medium": 3,
                "lb-large": 3,
            }
            if lb["size_unit"]:
                return cast(int, lb["size_unit"])
            else:
                return size_to_nr_nodes.get(lb["size"], 1)

        self.collect_resource(
            loadbalancers,
            resource_class=DigitalOceanLoadBalancer,
            attr_map={
                "id": "id",
                "urn": lambda lb: loadbalancer_id(lb["id"]),
                "public_ip_address": "ip",
                "nr_nodes": get_nr_nodes,
                "loadbalancer_status": "status",
                "redirect_http_to_https": "redirect_http_to_https",
                "enable_proxy_protocol": "enable_proxy_protocol",
                "enable_backend_keepalive": "enable_backend_keepalive",
                "disable_lets_encrypt_dns_records": "disable_lets_encrypt_dns_records",
            },
            search_map={
                "_region": ["urn", lambda lb: region_id(lb["region"]["slug"])],
                "__vpcs": ["urn", lambda lb: vpc_id(lb["vpc_uuid"])],
                "__droplets": [
                    "urn",
                    lambda lb: list(map(lambda id: droplet_id(id), lb.get("droplet_ids", []) or [])),
                ],
            },
            predecessors={EdgeType.default: ["__vpcs"], EdgeType.delete: ["__vpcs"]},
            successors={EdgeType.default: ["__droplets"]},
        )

    @metrics_collect_floating_ips.time()  # type: ignore
    def collect_floating_ips(self) -> None:
        floating_ips = self.client.list_floating_ips()
        self.collect_resource(
            floating_ips,
            resource_class=DigitalOceanFloatingIP,
            attr_map={
                "id": "ip",
                "urn": lambda ip: floatingip_id(ip["ip"]),
                "ip_address": "ip",
                "ip_address_family": lambda ip: "ipv4",
                "is_locked": "locked",
            },
            search_map={
                "_region": ["urn", lambda ip: region_id(ip["region"]["slug"])],
                "__droplet": [
                    "urn",
                    lambda ip: droplet_id(ip.get("droplet", {}).get("id", "")),
                ],
            },
            predecessors={EdgeType.default: ["__droplet"]},
        )

    @metrics_collect_spaces.time()  # type: ignore
    def collect_spaces(self, region: DigitalOceanRegion) -> None:
        spaces = self.client.list_spaces(region.do_region_slug or "")
        self.collect_resource(
            spaces,
            resource_class=DigitalOceanSpace,
            attr_map={
                "id": "Name",
                "urn": lambda space: space_id(space["Name"]),
                "name": "Name",
                "ctime": "CreationDate",
            },
            search_map={
                "_region": [
                    "urn",
                    lambda space: region_id(region.do_region_slug or ""),
                ],
            },
        )

    @metrics_collect_apps.time()  # type: ignore
    def collect_apps(self) -> None:
        apps = self.client.list_apps()

        def extract_region(app: Json) -> Optional[str]:
            region_slug = next(iter(app.get("region", {}).get("data_centers", [])), None)
            if region_slug is None:
                return None
            return region_id(region_slug)

        def extract_databases(app: Json) -> List[str]:
            databases = app.get("spec", {}).get("databases", [])
            names = [database_id(database["name"]) for database in databases]
            return names

        self.collect_resource(
            apps,
            resource_class=DigitalOceanApp,
            attr_map={
                "id": "id",
                "urn": lambda app: app_id(app["id"]),
                "tier_slug": "tier_slug",
                "default_ingress": "default_ingress",
                "live_url": "live_url",
                "live_url_base": "live_url_base",
                "live_domain": "live_domain",
            },
            search_map={
                "_region": ["urn", extract_region],
                "__databases": ["name", extract_databases],
            },
            predecessors={EdgeType.default: ["__databases"]},
        )

    @metrics_collect_cdn_endpoints.time()  # type: ignore
    def collect_cdn_endpoints(self) -> None:
        endpoints = self.client.list_cdn_endpoints()
        self.collect_resource(
            endpoints,
            resource_class=DigitalOceanCdnEndpoint,
            attr_map={
                "id": "id",
                "urn": lambda endpoint: cdn_endpoint_id(endpoint["id"]),
                "origin": "origin",
                "endpoint": "endpoint",
                "certificate_id": "certificate_id",
                "custom_domain": "custom_domain",
                "ttl": "ttl",
            },
        )

    @metrics_collect_certificates.time()  # type: ignore
    def collect_certificates(self) -> None:
        certificates = self.client.list_certificates()
        self.collect_resource(
            certificates,
            resource_class=DigitalOceanCertificate,
            attr_map={
                "id": "id",
                "urn": lambda c: certificate_id(c["id"]),
                "expires": lambda c: iso2datetime(c.get("not_after")),
                "sha1_fingerprint": "sha1_fingerprint",
                "dns_names": "dns_names",
                "certificate_state": "state",
                "certificate_type": "type",
            },
        )

    @metrics_collect_container_registry.time()  # type: ignore
    def collect_container_registry(self) -> None:
        registries = self.client.get_registry_info()
        for registry in registries:
            registry["updated_at"] = registry["storage_usage_updated_at"]
            self.collect_resource(
                [registry],
                resource_class=DigitalOceanContainerRegistry,
                attr_map={
                    "id": "name",
                    "urn": lambda r: container_registry_id(r["name"]),
                    "storage_usage_bytes": "storage_usage_bytes",
                    "is_read_only": "read_only",
                },
                search_map={
                    "_region": ["urn", lambda registry: region_id(registry["region"])],
                },
            )
            repositories = self.client.list_registry_repositories(registry["name"])
            self.collect_resource(
                repositories,
                resource_class=DigitalOceanContainerRegistryRepository,
                attr_map={
                    "id": "name",
                    "urn": lambda r: container_registry_repository_id(r["registry_name"], r["name"]),
                    "name": "name",
                    "tag_count": "tag_count",
                    "manifest_count": "manifest_count",
                },
                search_map={
                    "__registry": [
                        "urn",
                        lambda r: container_registry_id(r["registry_name"]),
                    ],
                },
                predecessors={EdgeType.default: ["__registry"]},
            )

            tags = [
                tag
                for repository in repositories
                for tag in self.client.list_registry_repository_tags(registry["name"], repository["name"])
            ]

            self.collect_resource(
                tags,
                resource_class=DigitalOceanContainerRegistryRepositoryTag,
                attr_map={
                    "id": "tag",
                    "urn": lambda t: container_registry_repository_tag_id(
                        t["registry_name"], t["repository"], t["tag"]
                    ),
                    "registry_name": "registry_name",
                    "repository_name": "repository",
                    "name": "tag",
                    "manifest_digest": "manifest_digest",
                    "compressed_size_bytes": "compressed_size_bytes",
                    "size_bytes": "size_bytes",
                },
                search_map={
                    "__repository": [
                        "urn",
                        lambda t: container_registry_repository_id(t["registry_name"], t["repository"]),
                    ],
                    "__registry": [
                        "urn",
                        lambda t: container_registry_id(t["registry_name"]),
                    ],
                },
                predecessors={EdgeType.default: ["__repository", "__registry"]},
            )

    @metrics_collect_ssh_keys.time()  # type: ignore
    def collect_ssh_keys(self) -> None:
        ssh_keys = self.client.list_ssh_keys()
        self.collect_resource(
            ssh_keys,
            resource_class=DigitalOceanSSHKey,
            attr_map={
                "id": lambda k: str(k["id"]),
                "urn": lambda k: ssh_key_id(k["id"]),
                "public_key": "public_key",
                "fingerprint": "fingerprint",
            },
        )

    @metrics_collect_tags.time()  # type: ignore
    def collect_tags(self) -> None:
        tags = self.client.list_tags()
        self.collect_resource(
            tags,
            resource_class=DigitalOceanTag,
            attr_map={
                "id": "name",
                "urn": lambda t: tag_id(t["name"]),
            },
        )

    @metrics_collect_domains.time()  # type: ignore
    def collect_domains(self) -> None:
        domains = self.client.list_domains()
        self.collect_resource(
            domains,
            resource_class=DigitalOceanDomain,
            attr_map={
                "id": "name",
                "urn": lambda d: domain_id(d["name"]),
                "ttl": "ttl",
                "zone_file": "zone_file",
            },
        )

        def update_record(record: Json, domain: Json) -> Json:
            record["domain_name"] = domain["name"]
            return record

        domain_records = [
            update_record(record, domain)
            for domain in domains
            for record in self.client.list_domain_records(domain["name"])
        ]
        self.collect_resource(
            domain_records,
            resource_class=DigitalOceanDomainRecord,
            attr_map={
                "id": lambda r: str(r["id"]),
                "name": "name",
                "urn": lambda r: domain_record_id(r["id"]),
                "domain_name": "domain_name",
                "record_type": "type",
                "record_data": "data",
                "record_priority": "priority",
                "record_port": "port",
                "record_ttl": "ttl",
                "record_weight": "weight",
                "record_flags": "flags",
                "record_tag": "tag",
            },
            search_map={
                "__domain": ["urn", lambda r: domain_id(r["domain_name"])],
            },
            predecessors={EdgeType.default: ["__domain"]},
        )

    @metrics_collect_firewalls.time()  # type: ignore
    def collect_firewalls(self) -> None:
        firewalls = self.client.list_firewalls()
        self.collect_resource(
            firewalls,
            resource_class=DigitalOceanFirewall,
            attr_map={
                "id": "id",
                "urn": lambda f: firewall_id(f["id"]),
                "firewall_status": "status",
            },
            search_map={
                "__droplets": [
                    "urn",
                    lambda f: list(map(lambda id: droplet_id(id), f.get("droplet_ids", []) or [])),
                ],
                "__tags": [
                    "urn",
                    lambda f: list(map(lambda id: tag_id(id), f.get("tags", []) or [])),
                ],
            },
            predecessors={
                EdgeType.default: ["__tags"],
            },
            successors={
                EdgeType.default: ["__droplets"],
            },
        )

    @metrics_collect_alert_policies.time()  # type: ignore
    def collect_alert_policies(self) -> None:
        alert_policies = self.client.list_alert_policies()
        self.collect_resource(
            alert_policies,
            resource_class=DigitalOceanAlertPolicy,
            attr_map={
                "id": "uuid",
                "urn": lambda ap: alert_policy_id(ap["uuid"]),
                "description": "description",
                "policy_type": "type",
                "is_enabled": "enabled",
            },
        )
