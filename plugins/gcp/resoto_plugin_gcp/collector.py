import resotolib.logger
import socket
from pprint import pformat
from retrying import retry
from typing import Callable, List, Dict, Type, Union
from resotolib.baseresources import BaseResource, EdgeType, InstanceStatus, VolumeStatus
from resotolib.config import Config
from resotolib.graph import Graph
from resotolib.utils import except_log_and_pass
from prometheus_client import Summary
from .resources import (
    GCPGKECluster,
    GCPProject,
    GCPQuota,
    GCPRegion,
    GCPZone,
    GCPDiskType,
    GCPDisk,
    GCPInstance,
    GCPMachineType,
    GCPNetwork,
    GCPSubnetwork,
    GCPTargetVPNGateway,
    GCPVPNGateway,
    GCPVPNTunnel,
    GCPRouter,
    GCPRoute,
    GCPSecurityPolicy,
    GCPSnapshot,
    GCPSSLCertificate,
    GCPNetworkEndpointGroup,
    GCPGlobalNetworkEndpointGroup,
    GCPInstanceGroup,
    GCPInstanceGroupManager,
    GCPAutoscaler,
    GCPHealthCheck,
    GCPHTTPHealthCheck,
    GCPHTTPSHealthCheck,
    GCPUrlMap,
    GCPTargetPool,
    GCPTargetHttpProxy,
    GCPTargetHttpsProxy,
    GCPTargetSslProxy,
    GCPTargetTcpProxy,
    GCPTargetGrpcProxy,
    GCPTargetInstance,
    GCPBackendService,
    GCPForwardingRule,
    GCPGlobalForwardingRule,
    GCPBucket,
    GCPDatabase,
    GCPService,
    GCPServiceSKU,
    GCPInstanceTemplate,
)
from .utils import (
    Credentials,
    gcp_client,
    gcp_resource,
    paginate,
    iso2datetime,
    get_result_data,
    common_resource_kwargs,
    retry_on_error,
)

log = resotolib.logger.getLogger("resoto." + __name__)


metrics_collect_regions = Summary(
    "resoto_plugin_gcp_collect_regions_seconds",
    "Time it took the collect_regions() method",
)
metrics_collect_zones = Summary(
    "resoto_plugin_gcp_collect_zones_seconds",
    "Time it took the collect_zones() method",
)
metrics_collect_disks = Summary(
    "resoto_plugin_gcp_collect_disks_seconds",
    "Time it took the collect_disks() method",
)
metrics_collect_instances = Summary(
    "resoto_plugin_gcp_collect_instances_seconds",
    "Time it took the collect_instances() method",
)
metrics_collect_disk_types = Summary(
    "resoto_plugin_gcp_collect_disk_types_seconds",
    "Time it took the collect_disk_types() method",
)
metrics_collect_networks = Summary(
    "resoto_plugin_gcp_collect_networks_seconds",
    "Time it took the collect_networks() method",
)
metrics_collect_subnetworks = Summary(
    "resoto_plugin_gcp_collect_subnetworks_seconds",
    "Time it took the collect_subnetworks() method",
)
metrics_collect_vpn_tunnels = Summary(
    "resoto_plugin_gcp_collect_vpn_tunnels_seconds",
    "Time it took the collect_vpn_tunnels() method",
)
metrics_collect_vpn_gateways = Summary(
    "resoto_plugin_gcp_collect_vpn_gateways_seconds",
    "Time it took the collect_vpn_gateways() method",
)
metrics_collect_target_vpn_gateways = Summary(
    "resoto_plugin_gcp_collect_target_vpn_gateways_seconds",
    "Time it took the collect_target_vpn_gateways() method",
)
metrics_collect_routers = Summary(
    "resoto_plugin_gcp_collect_routers_seconds",
    "Time it took the collect_routers() method",
)
metrics_collect_routes = Summary(
    "resoto_plugin_gcp_collect_routes_seconds",
    "Time it took the collect_routes() method",
)
metrics_collect_security_policies = Summary(
    "resoto_plugin_gcp_collect_security_policies_seconds",
    "Time it took the collect_security_policies() method",
)
metrics_collect_snapshots = Summary(
    "resoto_plugin_gcp_collect_snapshots_seconds",
    "Time it took the collect_snapshots() method",
)
metrics_collect_ssl_certificates = Summary(
    "resoto_plugin_gcp_collect_ssl_certificates_seconds",
    "Time it took the collect_ssl_certificates() method",
)
metrics_collect_machine_types = Summary(
    "resoto_plugin_gcp_collect_machine_types_seconds",
    "Time it took the collect_machine_types() method",
)
metrics_collect_network_endpoint_groups = Summary(
    "resoto_plugin_gcp_collect_network_endpoint_groups_seconds",
    "Time it took the collect_network_endpoint_groups() method",
)
metrics_collect_global_network_endpoint_groups = Summary(
    "resoto_plugin_gcp_collect_global_network_endpoint_groups_seconds",
    "Time it took the collect_global_network_endpoint_groups() method",
)
metrics_collect_instance_groups = Summary(
    "resoto_plugin_gcp_collect_instance_groups_seconds",
    "Time it took the collect_instance_groups() method",
)
metrics_collect_instance_group_managers = Summary(
    "resoto_plugin_gcp_collect_instance_group_managers_seconds",
    "Time it took the collect_instance_group_managers() method",
)
metrics_collect_autoscalers = Summary(
    "resoto_plugin_gcp_collect_autoscalers_seconds",
    "Time it took the collect_autoscalers() method",
)
metrics_collect_health_checks = Summary(
    "resoto_plugin_gcp_collect_health_checks_seconds",
    "Time it took the collect_health_checks() method",
)
metrics_collect_http_health_checks = Summary(
    "resoto_plugin_gcp_collect_http_health_checks_seconds",
    "Time it took the collect_http_health_checks() method",
)
metrics_collect_https_health_checks = Summary(
    "resoto_plugin_gcp_collect_https_health_checks_seconds",
    "Time it took the collect_https_health_checks() method",
)
metrics_collect_url_maps = Summary(
    "resoto_plugin_gcp_collect_url_maps_seconds",
    "Time it took the collect_url_maps() method",
)
metrics_collect_target_pools = Summary(
    "resoto_plugin_gcp_collect_target_pools_seconds",
    "Time it took the collect_target_pools() method",
)
metrics_collect_target_instances = Summary(
    "resoto_plugin_gcp_collect_target_instances_seconds",
    "Time it took the collect_target_instances() method",
)
metrics_collect_target_http_proxies = Summary(
    "resoto_plugin_gcp_collect_target_http_proxies_seconds",
    "Time it took the collect_target_http_proxies() method",
)
metrics_collect_target_https_proxies = Summary(
    "resoto_plugin_gcp_collect_target_https_proxies_seconds",
    "Time it took the collect_target_https_proxies() method",
)
metrics_collect_target_ssl_proxies = Summary(
    "resoto_plugin_gcp_collect_target_ssl_proxies_seconds",
    "Time it took the collect_target_ssl_proxies() method",
)
metrics_collect_target_tcp_proxies = Summary(
    "resoto_plugin_gcp_collect_target_tcp_proxies_seconds",
    "Time it took the collect_target_tcp_proxies() method",
)
metrics_collect_target_grpc_proxies = Summary(
    "resoto_plugin_gcp_collect_target_grpc_proxies_seconds",
    "Time it took the collect_target_grpc_proxies() method",
)
metrics_collect_backend_services = Summary(
    "resoto_plugin_gcp_collect_backend_services_seconds",
    "Time it took the collect_backend_services() method",
)
metrics_collect_forwarding_rules = Summary(
    "resoto_plugin_gcp_collect_forwarding_rules_seconds",
    "Time it took the collect_forwarding_rules() method",
)
metrics_collect_global_forwarding_rules = Summary(
    "resoto_plugin_gcp_collect_global_forwarding_rules_seconds",
    "Time it took the collect_global_forwarding_rules() method",
)
metrics_collect_buckets = Summary(
    "resoto_plugin_gcp_collect_buckets_seconds",
    "Time it took the collect_buckets() method",
)
metrics_collect_databases = Summary(
    "resoto_plugin_gcp_collect_databases_seconds",
    "Time it took the collect_databases() method",
)
metrics_collect_services = Summary(
    "resoto_plugin_gcp_collect_services_seconds",
    "Time it took the collect_services() method",
)
metrics_collect_instance_templates = Summary(
    "resoto_plugin_gcp_collect_instance_templates_seconds",
    "Time it took the collect_instance_templates() method",
)
metrics_collect_gke_clusters = Summary(
    "resoto_plugin_gcp_collect_gke_clusters_seconds",
    "Time it took the collect_gke_clusters() method",
)


class GCPProjectCollector:
    """Collects a single GCP project.

    Responsible for collecting all the resources of an individual project.
    Builds up its own local graph which is then taken by collect_project()
    and merged with the plugin graph.

    This way we can have many instances of GCPProjectCollector running in parallel.
    All building up individual graphs which in the end are merged to a final graph
    containing all GCP resources.
    """

    def __init__(self, project: GCPProject) -> None:
        """
        Args:
            project: The GCP project resource object this project collector
                is going to collect.
        """
        self.project = project
        self.credentials = Credentials.get(self.project.id)
        self.graph = Graph(root=self.project)

        # Mandatory collectors are always collected regardless of whether
        # they were included by --gcp-collect or excluded by --gcp-no-collect
        self.mandatory_collectors = {
            "regions": self.collect_regions,
            "zones": self.collect_zones,
        }
        # Global collectors are resources that are either specified on a global level
        # as opposed to a per zone or per region level or they are zone/region
        # resources that provide a aggregatedList() function returning all resources
        # for all zones/regions.
        self.global_collectors = {
            "services": self.collect_services,
            "networks": self.collect_networks,
            "subnetworks": self.collect_subnetworks,
            "routers": self.collect_routers,
            "routes": self.collect_routes,
            "health_checks": self.collect_health_checks,
            "http_health_checks": self.collect_http_health_checks,
            "https_health_checks": self.collect_https_health_checks,
            "machine_types": self.collect_machine_types,
            "instances": self.collect_instances,
            "disk_types": self.collect_disk_types,
            "disks": self.collect_disks,
            "target_vpn_gateways": self.collect_target_vpn_gateways,
            "vpn_gateways": self.collect_vpn_gateways,
            "vpn_tunnels": self.collect_vpn_tunnels,
            "security_policies": self.collect_security_policies,
            "snapshots": self.collect_snapshots,
            "ssl_certificates": self.collect_ssl_certificates,
            "network_endpoint_groups": self.collect_network_endpoint_groups,
            "instance_groups": self.collect_instance_groups,
            "instance_group_managers": self.collect_instance_group_managers,
            "autoscalers": self.collect_autoscalers,
            "backend_services": self.collect_backend_services,
            "url_maps": self.collect_url_maps,
            "target_pools": self.collect_target_pools,
            "target_instances": self.collect_target_instances,
            "target_http_proxies": self.collect_target_http_proxies,
            "target_https_proxies": self.collect_target_https_proxies,
            "target_ssl_proxies": self.collect_target_ssl_proxies,
            "target_tcp_proxies": self.collect_target_tcp_proxies,
            "target_grpc_proxies": self.collect_target_grpc_proxies,
            "forwarding_rules": self.collect_forwarding_rules,
            "buckets": self.collect_buckets,
            "databases": self.collect_databases,
            "instance_templates": self.collect_instance_templates,
            "gke_clusters": self.collect_gke_clusters,
        }
        # Region collectors collect resources in a single region.
        # They are being passed the GCPRegion resource object as `region` arg.
        self.region_collectors = {}
        # Zone collectors are being called for each zone.
        # They are being passed the GCPZone resource object as `zone` arg.
        self.zone_collectors = {}
        self.all_collectors = dict(self.mandatory_collectors)
        self.all_collectors.update(self.global_collectors)
        self.all_collectors.update(self.region_collectors)
        self.all_collectors.update(self.zone_collectors)
        self.collector_set = set(self.all_collectors.keys())

    @retry(
        stop_max_attempt_number=10,
        wait_exponential_multiplier=3000,
        wait_exponential_max=300000,
        retry_on_exception=retry_on_error,
    )
    def collect(self) -> None:
        """Runs the actual resource collection across all resource collectors.

        Resource collectors add their resources to the local `self.graph` graph.
        """
        self.graph = Graph(root=self.project)
        collectors = set(self.collector_set)
        if len(Config.gcp.collect) > 0:
            collectors = set(Config.gcp.collect).intersection(collectors)
        if len(Config.gcp.no_collect) > 0:
            collectors = collectors - set(Config.gcp.no_collect)
        collectors = collectors.union(set(self.mandatory_collectors.keys()))

        log.debug((f"Running the following collectors in {self.project.rtdname}:" f" {', '.join(collectors)}"))
        for collector_name, collector in self.mandatory_collectors.items():
            if collector_name in collectors:
                log.info(f"Collecting {collector_name} in {self.project.rtdname}")
                collector()
        regions = [r for r in self.graph.nodes if isinstance(r, GCPRegion)]
        zones = [z for z in self.graph.nodes if isinstance(z, GCPZone)]

        log.debug(f"Found {len(zones)} zones in {len(regions)} regions")

        for collector_name, collector in self.global_collectors.items():
            if collector_name in collectors:
                log.info(f"Collecting {collector_name} in {self.project.rtdname}")
                collector()

        # Todo: parallelize region and zone collection
        for region in regions:
            for collector_name, collector in self.region_collectors.items():
                if collector_name in collectors:
                    log.info((f"Collecting {collector_name} in {region.rtdname}" f" {self.project.rtdname}"))
                    collector(region=region)

        for zone in zones:
            for collector_name, collector in self.zone_collectors.items():
                if collector_name in collectors:
                    log.info((f"Collecting {collector_name} in {zone.rtdname}" f" {self.project.rtdname}"))
                    collector(zone=zone)

        remove_nodes = set()

        def rmnodes(cls) -> None:
            for node in self.graph.nodes:
                if isinstance(node, cls) and not any(True for _ in self.graph.successors(node)):
                    remove_nodes.add(node)
            for node in remove_nodes:
                self.graph.remove_node(node)
            log.debug(f"Removing {len(remove_nodes)} unreferenced nodes of type {cls}")
            remove_nodes.clear()

        # nodes need to be removed in the correct order
        rmnodes((GCPMachineType, GCPDiskType))
        rmnodes(GCPServiceSKU)
        rmnodes(GCPService)

    def default_attributes(self, result: Dict, attr_map: Dict = None, search_map: Dict = None) -> Dict:
        """Finds resource attributes in the GCP API result data and returns
        them together with any graph search results.

        Args:
            result: Dict containing the result or a GCP API execute() call.
            attr_map: Dict of map_to: map_from pairs where map_to is the name of the arg
                that a resoto resource expects and map_from is the name of the key
                in the result dictionary.
            search_map: Dict of map_to: [search_attr, search_value_name]. Where map_to
                is the arg that a resoto resource expects. search_attr is the
                attribute name to search for in the graph and search_value_name is the
                name of the key in the result dictionary that is passed into the graph
                search as attribute value.

        Example:
            result:
            ```
            {
                'creationTimestamp': '2020-10-08T05:45:43.294-07:00',
                'id': '7684174949783877401',
                'kind': 'compute#disk',
                'labelFingerprint': '42WmSpB8rSM=',
                'lastAttachTimestamp': '2020-10-08T05:45:43.294-07:00',
                'name': 'instance-group-1-lnmq',
                'physicalBlockSizeBytes': '4096',
                'sizeGb': '10',
                'status': 'READY',
                'selfLink': 'https://www.googleapis.com/.../disks/instance-1-lnmq',
                'type': 'https://www.googleapis.com/.../diskTypes/pd-standard',
                'users': ['https://www.googleapis.com/.../instances/instance-1-lnmq'],
                'zone': 'https://www.googleapis.com/.../zones/europe-west1-d'
            }
            attr_map:
            {
                "volume_size": "sizeGb",
                "volume_status": "status",
            }
            search_map:
            {
                "volume_type": ["link", "type"],
                "__users": ["link", "users"],
            }
            ```
            This would create
            GCPDisk(
                identifier="7684174949783877401",
                name="instance-group-1-lnmq",
                ctime=iso2datetime("2020-10-08T05:45:43.294-07:00"),
                volume_size="10",
                volume_status="READY",
                volume_type=GCPDiskType()
                link="https://www.googleapis.com/.../disks/instance-1-lnmq"
            )
            Where the GCPDiskType() object would be one that was found in the graph
            with attribute "link": https://www.googleapis.com/.../diskTypes/pd-standard

            The map_from and search_value_name in attr_map and search_map respectively
            can also be a callable which is passed the entire result dict and then
            responsible for finding and returning the relevant data.
            E.g. the entry from above:
                "volume_size": "sizeGb",
            could also be written as:
                "volume_size": (lambda r: r.get("sizeGb")),
            This is mainly useful for searching deeply nested data.

            Any key in the search_map that starts with an underscore like _users
            in the example above will only be looked up and if found added to the
            search_results return value but not be added to kwargs.

            This returned search data can then be used to draw predecessor and successor
            edges in the graph.
        """
        # The following are default attributes that are passed to every
        # BaseResource() if found in `result`
        kwargs = {
            "id": result.get("id", result.get("name", result.get("selfLink"))),
            "tags": result.get("labels", {}),
            "name": result.get("name"),
            "ctime": iso2datetime(result.get("creationTimestamp")),
            "link": result.get("selfLink"),
            "label_fingerprint": result.get("labelFingerprint"),
            "_account": self.project,
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
        default_search_map = {"_region": ["link", "region"], "_zone": ["link", "zone"]}
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

    @except_log_and_pass(do_raise=socket.timeout)
    def collect_something(
        self,
        resource_class: Type[BaseResource],
        paginate_method_name: str = "list",
        paginate_items_name: str = "items",
        parent_resource: Union[BaseResource, str] = None,
        attr_map: Dict = None,
        search_map: Dict = None,
        successors: Dict[EdgeType, List[str]] = None,
        predecessors: Dict[EdgeType, List[str]] = None,
        client_kwargs: Dict = None,
        client_nested_callables: List[str] = None,
        resource_kwargs: Dict = None,
        paginate_subitems_name: str = None,
        post_process: Callable = None,
        dump_resource: bool = False,
    ) -> List:
        """Collects some resource and adds it to the graph.

        Args:
            resource_class: A GCP resource class name that inherits
                resoto's BaseResource
            paginate_method_name: usually "list" or "aggregatedList"
            paginate_items_name: key name that contains all the items
                of our list/aggregatedList request
            parent_resource: The resources parent resource in the graph.
                This defaults to the zone or region for local or the
                project for global resources.
            attr_map: Dict containing a mapping of GCP API result dict keys
                to resource_class attributes. See default_attributes()
                for a detailed description.
            search_map: Dict containing a mapping similar to attr_map except that
                any results get looked up in `self.graph` instead of just passing
                the result data as an attribute.
            successors: Dict of EdgeTypes with List of resource
                successors (child nodes)
            predecessors: Dict of EdgeTypes with List of resource
                predecessors (parent nodes)
            client_kwargs: **kwargs that get passed to the GCP client
            resource_kwargs: **kwargs that get passed to the GCP resource
            paginate_subitems_name: Name of a resource in a aggregatedList result set
                Defaults to be the name as the client method name. E.g. if we request
                all disks it'll be {"items": {'zones/...': {'disks': []}}
            post_process: Callable that is called after a resource has been added to
                the graph. The resource object and the graph are given as args.
            dump_resource: If True will log.debug() a dump of the API result.
        """
        client_method_name = resource_class(id="", tags={})._client_method
        default_resource_args = resource_class(id="", tags={}).resource_args
        log.debug(f"Collecting {client_method_name}")
        if paginate_subitems_name is None:
            paginate_subitems_name = client_method_name
        if client_kwargs is None:
            client_kwargs = {}
        if client_nested_callables is None:
            client_nested_callables = []
        if resource_kwargs is None:
            resource_kwargs = {}
        if successors is None:
            successors = {}
        if predecessors is None:
            predecessors = {}
        parent_map = {True: predecessors, False: successors}

        # For APIs that take a parent (`projects/*/locations/*`) parameter,
        # setting the project is not expected.
        if "parent" not in resource_kwargs and "project" in default_resource_args:
            resource_kwargs["project"] = self.project.id

        client = gcp_client(
            resource_class.client,
            resource_class.api_version,
            credentials=self.credentials,
            **client_kwargs,
        )

        # Some more recent client implementations have nested callables before
        # the actual client_method_name method,
        # e.g. discovery.build('container', 'v1').projects().locations().clusters()
        for client_nested_callable in client_nested_callables:
            client = getattr(client, client_nested_callable)()

        gcp_resource = getattr(client, client_method_name)
        if not callable(gcp_resource):
            raise RuntimeError(f"No method {client_method_name} on client {client}")

        for resource in paginate(
            gcp_resource=gcp_resource(),
            method_name=paginate_method_name,
            items_name=paginate_items_name,
            subitems_name=paginate_subitems_name,
            **resource_kwargs,
        ):
            kwargs, search_results = self.default_attributes(resource, attr_map=attr_map, search_map=search_map)
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
                log.debug(f"Parent resource for {r.rtdname} automatically set to {pr.rtdname}")
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
                                                {attr: value},
                                                is_parent,
                                                edge_type=edge_type,
                                            )
                                    elif isinstance(value, str):
                                        r.add_deferred_connection(
                                            {attr: value},
                                            is_parent,
                                            edge_type=edge_type,
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

    # All of the following methods just call collect_something() with some resource
    # specific options.
    @metrics_collect_regions.time()
    def collect_regions(self) -> List:
        def post_process(resource: GCPRegion, graph: Graph):
            for quota in resource._quotas:
                if set(["metric", "limit", "usage"]) == set(quota.keys()):
                    q = GCPQuota(
                        id=quota["metric"],
                        tags={},
                        quota=quota["limit"],
                        usage=quota["usage"],
                        region=resource.region(),
                        account=resource.account(),
                        zone=resource.zone(),
                        ctime=resource.ctime,
                    )
                    graph.add_resource(resource, q, edge_type=EdgeType.default)
            resource._quotas = None

        self.collect_something(
            resource_class=GCPRegion,
            attr_map={"region_status": "status", "quotas": "quotas"},
            post_process=post_process,
        )

    @metrics_collect_zones.time()
    def collect_zones(self) -> List:
        self.collect_something(
            resource_class=GCPZone,
        )

    @metrics_collect_disks.time()
    def collect_disks(self):
        volume_status_map: Dict[str, VolumeStatus] = {
            "CREATING": VolumeStatus.BUSY,
            "RESTORING": VolumeStatus.BUSY,
            "FAILED": VolumeStatus.ERROR,
            "READY": VolumeStatus.IN_USE,
            "AVAILABLE": VolumeStatus.AVAILABLE,
            "DELETING": VolumeStatus.BUSY,
            "busy": VolumeStatus.BUSY,
            "in-use": VolumeStatus.IN_USE,
            "available": VolumeStatus.AVAILABLE,
            "error": VolumeStatus.ERROR,
            "deleted": VolumeStatus.DELETED,
        }

        def volume_status(result):
            status = result.get("status")
            num_users = len(result.get("users", []))
            if num_users == 0 and status == "READY":
                status = "AVAILABLE"
            status = volume_status_map.get(status, VolumeStatus.UNKNOWN)
            return status

        self.collect_something(
            paginate_method_name="aggregatedList",
            resource_class=GCPDisk,
            search_map={
                "volume_type": ["link", "type"],
                "__users": ["link", "users"],
            },
            attr_map={
                "volume_size": (lambda r: int(r.get("sizeGb"))),
                "volume_status": volume_status,
                "last_attach_timestamp": (lambda r: iso2datetime(r.get("lastAttachTimestamp", r["creationTimestamp"]))),
                "last_detach_timestamp": (lambda r: iso2datetime(r.get("lastDetachTimestamp", r["creationTimestamp"]))),
            },
            predecessors={EdgeType.default: ["volume_type", "__users"]},
            successors={EdgeType.delete: ["__users"]},
        )

    @metrics_collect_instances.time()
    def collect_instances(self):
        def post_process(resource: GCPInstance, graph: Graph):
            """Post process instance resources

            The first time we encounter a custom machine type we will
            fetch its details. This is because the machineTypes API's
            list/aggregatedList functions only return predefined machine types.
            Custom ones have to be fetched individually when we encounter them
            on a instance.
            Once added to the graph resoto will find it for successive
            instances of the same machine type.
            """
            if resource.instance_type == "" and "custom" in resource._machine_type_link:
                if resource.instance_status == InstanceStatus.TERMINATED:
                    resource._cleaned = True
                log.debug(f"Fetching custom instance type for {resource.rtdname}")
                machine_type = GCPMachineType(
                    id=resource._machine_type_link.split("/")[-1],
                    tags={},
                    zone=resource.zone(graph),
                    account=resource.account(graph),
                    link=resource._machine_type_link,
                )
                resource._machine_type_link = None
                kwargs = {str(machine_type._get_identifier): machine_type.name}
                common_kwargs = common_resource_kwargs(machine_type)
                kwargs.update(common_kwargs)
                gr = gcp_resource(machine_type)
                request = gr.get(**kwargs)
                result = request.execute()
                machine_type.id = result.get("id")
                machine_type.instance_cores = float(result.get("guestCpus"))
                machine_type.instance_memory = float(result.get("memoryMb", 0) / 1024)
                graph.add_resource(machine_type.zone(graph), machine_type, edge_type=EdgeType.default)
                graph.add_edge(machine_type, resource, edge_type=EdgeType.default)
                self.post_process_machine_type(machine_type, graph)
                resource._machine_type = machine_type

        instance_status_map: Dict[str, InstanceStatus] = {
            "PROVISIONING": InstanceStatus.BUSY,
            "STAGING": InstanceStatus.BUSY,
            "RUNNING": InstanceStatus.RUNNING,
            "STOPPING": InstanceStatus.BUSY,
            "SUSPENDING": InstanceStatus.BUSY,
            "SUSPENDED": InstanceStatus.STOPPED,
            "REPAIRING": InstanceStatus.BUSY,
            "TERMINATED": InstanceStatus.TERMINATED,
            "busy": InstanceStatus.BUSY,
            "running": InstanceStatus.RUNNING,
            "stopped": InstanceStatus.STOPPED,
            "terminated": InstanceStatus.TERMINATED,
        }

        self.collect_something(
            paginate_method_name="aggregatedList",
            resource_class=GCPInstance,
            post_process=post_process,
            search_map={
                "__network": [
                    "link",
                    (lambda r: next(iter(r.get("networkInterfaces", [])), {}).get("network")),
                ],
                "__subnetwork": [
                    "link",
                    (lambda r: next(iter(r.get("networkInterfaces", [])), {}).get("subnetwork")),
                ],
                "machine_type": ["link", "machineType"],
            },
            attr_map={
                "instance_status": lambda i: instance_status_map.get(i["status"], InstanceStatus.UNKNOWN),
                "machine_type_link": "machineType",
            },
            predecessors={
                EdgeType.default: ["__network", "__subnetwork", "machine_type"],
                EdgeType.delete: ["__network", "__subnetwork"],
            },
        )

    @metrics_collect_disk_types.time()
    def collect_disk_types(self):
        def post_process(resource: GCPDiskType, graph: Graph):
            if resource.region(graph).name == "undefined" and resource.zone(graph).name == "undefined":
                log.debug(f"Resource {resource.rtdname} has no region or zone" " - removing from graph")
                graph.remove_node(resource)
                return

            log.debug((f"Looking up pricing for {resource.rtdname}" f" in {resource.location(graph).rtdname}"))
            resource_group_map = {
                "local-ssd": "LocalSSD",
                "pd-balanced": "SSD",
                "pd-ssd": "SSD",
                "pd-standard": "PDStandard",
            }
            resource_group = resource_group_map.get(resource.name)
            skus = []
            for sku in graph.searchall(
                {
                    "kind": "gcp_service_sku",
                    "resource_family": "Storage",
                    "usage_type": "OnDemand",
                    "resource_group": resource_group,
                }
            ):
                try:
                    if resource.region(graph).name not in sku.geo_taxonomy_regions:
                        continue
                except TypeError:
                    log.exception(
                        f"Problem accessing geo_taxonomy_regions in {sku.rtdname}:" f" {type(sku.geo_taxonomy_regions)}"
                    )
                if resource.name == "pd-balanced" and not sku.name.startswith("Balanced"):
                    continue
                if resource.name != "pd-balanced" and sku.name.startswith("Balanced"):
                    continue
                if resource.zone(graph).name != "undefined" and sku.name.startswith("Regional"):
                    continue
                if (
                    resource.zone(graph).name == "undefined"
                    and not sku.name.startswith("Regional")
                    and resource.name != "pd-balanced"
                ):
                    continue
                skus.append(sku)

            if len(skus) == 1:
                graph.add_edge(skus[0], resource, edge_type=EdgeType.default)
                resource.ondemand_cost = skus[0].usage_unit_nanos / 1000000000
            else:
                log.debug(f"Unable to determine SKU for {resource}")

        self.collect_something(
            paginate_method_name="aggregatedList",
            resource_class=GCPDiskType,
            post_process=post_process,
        )

    @metrics_collect_networks.time()
    def collect_networks(self):
        self.collect_something(
            resource_class=GCPNetwork,
        )

    @metrics_collect_subnetworks.time()
    def collect_subnetworks(self):
        self.collect_something(
            paginate_method_name="aggregatedList",
            resource_class=GCPSubnetwork,
            search_map={
                "__network": ["link", "network"],
            },
            predecessors={
                EdgeType.default: ["__network"],
                EdgeType.delete: ["__network"],
            },
        )

    @metrics_collect_vpn_tunnels.time()
    def collect_vpn_tunnels(self):
        self.collect_something(
            paginate_method_name="aggregatedList",
            resource_class=GCPVPNTunnel,
            search_map={
                "__vpn_gateway": ["link", "vpnGateway"],
                "__target_vpn_gateway": ["link", "targetVpnGateway"],
            },
            successors={
                EdgeType.default: ["__target_vpn_gateway", "__vpn_gateway"],
                EdgeType.delete: ["__target_vpn_gateway", "__vpn_gateway"],
            },
        )

    @metrics_collect_vpn_gateways.time()
    def collect_vpn_gateways(self):
        self.collect_something(
            paginate_method_name="aggregatedList",
            resource_class=GCPVPNGateway,
            search_map={
                "__network": ["link", "network"],
            },
            predecessors={
                EdgeType.default: ["__network"],
                EdgeType.delete: ["__network"],
            },
        )

    @metrics_collect_target_vpn_gateways.time()
    def collect_target_vpn_gateways(self):
        self.collect_something(
            paginate_method_name="aggregatedList",
            resource_class=GCPTargetVPNGateway,
            search_map={
                "__network": ["link", "network"],
            },
            predecessors={
                EdgeType.default: ["__network"],
                EdgeType.delete: ["__network"],
            },
        )

    @metrics_collect_routers.time()
    def collect_routers(self):
        self.collect_something(
            paginate_method_name="aggregatedList",
            resource_class=GCPRouter,
            search_map={
                "__network": ["link", "network"],
            },
            predecessors={
                EdgeType.default: ["__network"],
                EdgeType.delete: ["__network"],
            },
        )

    @metrics_collect_routes.time()
    def collect_routes(self):
        self.collect_something(
            resource_class=GCPRoute,
            search_map={
                "__network": ["link", "network"],
            },
            predecessors={
                EdgeType.default: ["__network"],
                EdgeType.delete: ["__network"],
            },
        )

    @metrics_collect_security_policies.time()
    def collect_security_policies(self):
        self.collect_something(resource_class=GCPSecurityPolicy)

    @metrics_collect_snapshots.time()
    def collect_snapshots(self):
        self.collect_something(
            resource_class=GCPSnapshot,
            search_map={
                "volume_id": ["link", "sourceDisk"],
            },
            attr_map={
                "volume_size": lambda r: int(r.get("diskSizeGb", -1)),
                "storage_bytes": lambda r: int(r.get("storageBytes", -1)),
            },
            predecessors={EdgeType.default: ["volume_id"]},
        )

    @metrics_collect_ssl_certificates.time()
    def collect_ssl_certificates(self):
        self.collect_something(
            paginate_method_name="aggregatedList",
            resource_class=GCPSSLCertificate,
            attr_map={
                "ctime": lambda r: iso2datetime(r.get("creationTimestamp")),
                "expires": lambda r: iso2datetime(r.get("expireTime")),
                "description": "description",
                "certificate": "certificate",
                "certificate_type": "type",
                "certificate_managed": "managed",
                "subject_alternative_names": "subjectAlternativeNames",
            },
            search_map={
                "__user": ["link", "user"],
            },
            predecessors={EdgeType.default: ["__user"]},
            successors={EdgeType.delete: ["__user"]},
        )

    @staticmethod
    def post_process_machine_type(resource: GCPMachineType, graph: Graph):
        """Adds edges from machine type to SKUs and determines ondemand pricing

        TODO: Implement GPU types
        """
        if resource.region(graph).name == "undefined" and resource.zone(graph).name == "undefined":
            log.debug(f"Resource {resource.rtdname} has no region or zone" " - removing from graph")
            graph.remove_node(resource)
            return

        log.debug((f"Looking up pricing for {resource.rtdname}" f" in {resource.location(graph).rtdname}"))
        skus = []
        for sku in graph.searchall(
            {
                "kind": "gcp_service_sku",
                "resource_family": "Compute",
                "usage_type": "OnDemand",
            }
        ):
            if sku.resource_group not in (
                "G1Small",
                "F1Micro",
                "N1Standard",
                "CPU",
                "RAM",
            ):
                continue
            if ("custom" not in resource.name and "Custom" in sku.name) or (
                "custom" in resource.name and "Custom" not in sku.name
            ):
                continue
            if resource.region(graph).name not in sku.geo_taxonomy_regions:
                continue
            if resource.name == "g1-small" and sku.resource_group != "G1Small":
                continue
            if resource.name == "f1-micro" and sku.resource_group != "F1Micro":
                continue
            if (resource.name.startswith("n2d-") and not sku.name.startswith("N2D AMD ")) or (
                not resource.name.startswith("n2d-") and sku.name.startswith("N2D AMD ")
            ):
                continue
            if (resource.name.startswith("n2-") and not sku.name.startswith("N2 ")) or (
                not resource.name.startswith("n2-") and sku.name.startswith("N2 ")
            ):
                continue
            if (resource.name.startswith("m1-") and not sku.name.startswith("Memory-optimized ")) or (
                not resource.name.startswith("m1-") and sku.name.startswith("Memory-optimized ")
            ):
                continue
            if (resource.name.startswith("c2-") and not sku.name.startswith("Compute optimized ")) or (
                not resource.name.startswith("c2-") and sku.name.startswith("Compute optimized ")
            ):
                continue
            if resource.name.startswith("n1-") and sku.resource_group != "N1Standard":
                continue
            if "custom" not in resource.name:
                if (resource.name.startswith("e2-") and not sku.name.startswith("E2 ")) or (
                    not resource.name.startswith("e2-") and sku.name.startswith("E2 ")
                ):
                    continue
            skus.append(sku)

        if len(skus) == 1 and resource.name in ("g1-small", "f1-micro"):
            graph.add_edge(skus[0], resource, edge_type=EdgeType.default)
            resource.ondemand_cost = skus[0].usage_unit_nanos / 1000000000
        elif len(skus) == 2 or (len(skus) == 3 and "custom" in resource.name):
            ondemand_cost = 0
            cores = resource.instance_cores
            ram = resource.instance_memory
            extended_memory_pricing = False
            if "custom" in resource.name:
                extended_memory_pricing = ram / cores > 8

            for sku in skus:
                if "Core" in sku.name:
                    ondemand_cost += sku.usage_unit_nanos * cores
                elif "Ram" in sku.name:
                    if (extended_memory_pricing and "Extended" not in sku.name) or (
                        not extended_memory_pricing and "Extended" in sku.name
                    ):
                        continue
                    ondemand_cost += sku.usage_unit_nanos * ram
                graph.add_edge(sku, resource, edge_type=EdgeType.default)
            if ondemand_cost > 0:
                resource.ondemand_cost = ondemand_cost / 1000000000
        else:
            log.debug((f"Unable to determine SKU(s) for {resource}:" f" {[sku.dname for sku in skus]}"))

    @metrics_collect_machine_types.time()
    def collect_machine_types(self):
        self.collect_something(
            resource_class=GCPMachineType,
            paginate_method_name="aggregatedList",
            search_map={
                "_zone": ["name", "zone"],
            },
            attr_map={
                "instance_cores": lambda r: float(r.get("guestCpus", 0)),
                "instance_memory": lambda r: float(r.get("memoryMb", 0) / 1024),
            },
            post_process=self.post_process_machine_type,
        )

    @metrics_collect_network_endpoint_groups.time()
    def collect_network_endpoint_groups(self):
        self.collect_something(
            resource_class=GCPNetworkEndpointGroup,
            paginate_method_name="aggregatedList",
            search_map={
                "__subnetwork": ["link", "subnetwork"],
                "__network": ["link", "network"],
            },
            attr_map={
                "default_port": "defaultPort",
                "neg_type": "networkEndpointType",
            },
            predecessors={
                EdgeType.default: ["__network", "__subnetwork"],
                EdgeType.delete: ["__network", "__subnetwork"],
            },
        )

    @metrics_collect_global_network_endpoint_groups.time()
    def collect_global_network_endpoint_groups(self):
        self.collect_something(
            resource_class=GCPGlobalNetworkEndpointGroup,
            search_map={
                "__subnetwork": ["link", "subnetwork"],
                "__network": ["link", "network"],
            },
            attr_map={
                "default_port": "defaultPort",
                "neg_type": "networkEndpointType",
            },
            predecessors={
                EdgeType.default: ["__network", "__subnetwork"],
                EdgeType.delete: ["__network", "__subnetwork"],
            },
        )

    @metrics_collect_instance_groups.time()
    def collect_instance_groups(self):
        def post_process(resource: GCPInstanceGroup, graph: Graph):
            kwargs = {"instanceGroup": resource.name}
            kwargs.update(common_resource_kwargs(resource))
            log.debug(f"Getting instances for {resource}")
            for r in paginate(
                gcp_resource=gcp_resource(resource, graph),
                method_name="listInstances",
                items_name="items",
                **kwargs,
            ):
                i = graph.search_first("link", r.get("instance"))
                if i:
                    graph.add_edge(resource, i, edge_type=EdgeType.default)
                    graph.add_edge(i, resource, edge_type=EdgeType.delete)

        self.collect_something(
            resource_class=GCPInstanceGroup,
            paginate_method_name="aggregatedList",
            search_map={
                "__subnetwork": ["link", "subnetwork"],
                "__network": ["link", "network"],
            },
            predecessors={
                EdgeType.default: ["__network", "__subnetwork"],
                EdgeType.delete: ["__network", "__subnetwork"],
            },
            post_process=post_process,
        )

    @metrics_collect_instance_group_managers.time()
    def collect_instance_group_managers(self):
        self.collect_something(
            resource_class=GCPInstanceGroupManager,
            paginate_method_name="aggregatedList",
            search_map={
                "__instance_group": ["link", "instanceGroup"],
                "__health_checks": [
                    "link",
                    (lambda r: [hc.get("healthCheck", "") for hc in r.get("autoHealingPolicies", [])]),
                ],
            },
            predecessors={
                EdgeType.default: ["__instance_group"],
                EdgeType.delete: ["__instance_group", "__health_checks"],
            },
            successors={EdgeType.default: ["__health_checks"]},
        )

    @metrics_collect_autoscalers.time()
    def collect_autoscalers(self):
        self.collect_something(
            resource_class=GCPAutoscaler,
            paginate_method_name="aggregatedList",
            search_map={
                "__instance_group_manager": ["link", "target"],
            },
            attr_map={
                "min_size": (lambda r: r.get("autoscalingPolicy", {}).get("minNumReplicas", -1)),
                "max_size": (lambda r: r.get("autoscalingPolicy", {}).get("maxNumReplicas", -1)),
            },
            successors={
                EdgeType.default: ["__instance_group_manager"],
                EdgeType.delete: ["__instance_group_manager"],
            },
        )

    @metrics_collect_health_checks.time()
    def collect_health_checks(self):
        self.collect_something(
            resource_class=GCPHealthCheck,
            paginate_method_name="aggregatedList",
            attr_map={
                "check_interval": "checkIntervalSec",
                "healthy_threshold": "healthyThreshold",
                "unhealthy_threshold": "unhealthyThreshold",
                "timeout": "timeoutSec",
                "health_check_type": "type",
            },
        )

    @metrics_collect_http_health_checks.time()
    def collect_http_health_checks(self):
        self.collect_something(
            resource_class=GCPHTTPHealthCheck,
            attr_map={
                "check_interval": "checkIntervalSec",
                "healthy_threshold": "healthyThreshold",
                "unhealthy_threshold": "unhealthyThreshold",
                "timeout": "timeoutSec",
                "host": "host",
                "request_path": "requestPath",
                "port": "port",
            },
        )

    @metrics_collect_https_health_checks.time()
    def collect_https_health_checks(self):
        self.collect_something(
            resource_class=GCPHTTPSHealthCheck,
            attr_map={
                "check_interval": "checkIntervalSec",
                "healthy_threshold": "healthyThreshold",
                "unhealthy_threshold": "unhealthyThreshold",
                "timeout": "timeoutSec",
                "health_check_type": "type",
                "host": "host",
                "request_path": "requestPath",
                "port": "port",
            },
        )

    @metrics_collect_url_maps.time()
    def collect_url_maps(self):
        self.collect_something(
            resource_class=GCPUrlMap,
            paginate_method_name="aggregatedList",
            search_map={
                "__default_service": ["link", "defaultService"],
            },
            successors={EdgeType.default: ["__default_service"]},
        )

    @metrics_collect_target_pools.time()
    def collect_target_pools(self):
        self.collect_something(
            resource_class=GCPTargetPool,
            paginate_method_name="aggregatedList",
            search_map={
                "__health_checks": ["link", "healthChecks"],
                "__instances": ["link", "instances"],
            },
            attr_map={
                "session_affinity": "sessionAffinity",
                "failover_ratio": "failoverRatio",
            },
            predecessors={EdgeType.delete: ["__instances", "__health_checks"]},
            successors={EdgeType.default: ["__instances", "__health_checks"]},
        )

    @metrics_collect_target_instances.time()
    def collect_target_instances(self):
        self.collect_something(
            resource_class=GCPTargetInstance,
            paginate_method_name="aggregatedList",
            search_map={
                "__instance": ["link", "instance"],
            },
            predecessors={EdgeType.delete: ["__instance"]},
            successors={EdgeType.default: ["__instance"]},
        )

    @metrics_collect_target_http_proxies.time()
    def collect_target_http_proxies(self):
        self.collect_something(
            resource_class=GCPTargetHttpProxy,
            paginate_method_name="aggregatedList",
            search_map={
                "__url_map": ["link", "urlMap"],
            },
            predecessors={EdgeType.delete: ["__url_map"]},
            successors={EdgeType.default: ["__url_map"]},
        )

    @metrics_collect_target_https_proxies.time()
    def collect_target_https_proxies(self):
        self.collect_something(
            resource_class=GCPTargetHttpsProxy,
            paginate_method_name="aggregatedList",
            search_map={
                "__url_map": ["link", "urlMap"],
                "__ssl_certificates": ["link", "sslCertificates"],
            },
            predecessors={EdgeType.delete: ["__url_map", "__ssl_certificates"]},
            successors={EdgeType.default: ["__url_map", "__ssl_certificates"]},
        )

    @metrics_collect_target_ssl_proxies.time()
    def collect_target_ssl_proxies(self):
        self.collect_something(
            resource_class=GCPTargetSslProxy,
            search_map={
                "__service": ["link", "service"],
                "__ssl_certificates": ["link", "sslCertificates"],
            },
            predecessors={EdgeType.delete: ["__service", "__ssl_certificates"]},
            successors={EdgeType.default: ["__service", "__ssl_certificates"]},
        )

    @metrics_collect_target_tcp_proxies.time()
    def collect_target_tcp_proxies(self):
        self.collect_something(
            resource_class=GCPTargetTcpProxy,
            search_map={
                "__service": ["link", "service"],
            },
            predecessors={EdgeType.delete: ["__service"]},
            successors={EdgeType.default: ["__service"]},
        )

    @metrics_collect_target_grpc_proxies.time()
    def collect_target_grpc_proxies(self):
        self.collect_something(
            resource_class=GCPTargetGrpcProxy,
            search_map={
                "__url_map": ["link", "urlMap"],
            },
            predecessors={EdgeType.delete: ["__url_map"]},
            successors={EdgeType.default: ["__url_map"]},
        )

    @metrics_collect_backend_services.time()
    def collect_backend_services(self):
        self.collect_something(
            resource_class=GCPBackendService,
            paginate_method_name="aggregatedList",
            search_map={
                "__health_checks": ["link", "healthChecks"],
                "__backends": [
                    "link",
                    (lambda r: [g.get("group", "") for g in r.get("backends", [])]),
                ],
            },
            predecessors={EdgeType.delete: ["__health_checks", "__backends"]},
            successors={EdgeType.default: ["__health_checks", "__backends"]},
        )

    @metrics_collect_forwarding_rules.time()
    def collect_forwarding_rules(self):
        def post_process(resource: GCPForwardingRule, graph: Graph):
            instances = [i.name for i in resource.ancestors(graph) if isinstance(i, GCPInstance)]
            if len(instances) > 0:
                resource.backends = sorted(instances)

        self.collect_something(
            resource_class=GCPForwardingRule,
            paginate_method_name="aggregatedList",
            attr_map={
                "ip_address": "IPAddress",
                "ip_protocol": "IPProtocol",
                "load_balancing_scheme": "loadBalancingScheme",
                "network_tier": "networkTier",
                "port_range": "portRange",
            },
            search_map={
                "__target": ["link", "target"],
            },
            predecessors={EdgeType.delete: ["__target"]},
            successors={EdgeType.default: ["__target"]},
            post_process=post_process,
        )

    @metrics_collect_global_forwarding_rules.time()
    def collect_global_forwarding_rules(self):
        self.collect_something(
            resource_class=GCPGlobalForwardingRule,
            attr_map={
                "ip_address": "IPAddress",
                "ip_protocol": "IPProtocol",
                "load_balancing_scheme": "loadBalancingScheme",
                "network_tier": "networkTier",
                "port_range": "portRange",
            },
            search_map={
                "__target": ["link", "target"],
            },
            predecessors={EdgeType.delete: ["__target"]},
            successors={EdgeType.default: ["__target"]},
        )

    @metrics_collect_buckets.time()
    def collect_buckets(self):
        self.collect_something(
            resource_class=GCPBucket,
            attr_map={
                "ctime": lambda r: iso2datetime(r.get("timeCreated")),
                "mtime": lambda r: iso2datetime(r.get("updated")),
                "bucket_location": "location",
                "bucket_location_type": "locationType",
                "storage_class": "storageClass",
                "zone_separation": "zoneSeparation",
            },
        )

    @metrics_collect_databases.time()
    def collect_databases(self):
        self.collect_something(
            resource_class=GCPDatabase,
            attr_map={
                "db_type": "databaseVersion",
                "db_status": "state",
                "db_endpoint": lambda r: next(
                    iter([ip["ipAddress"] for ip in r.get("ipAddresses", []) if ip.get("type") == "PRIMARY"]),
                    None,
                ),
                "instance_type": lambda r: r.get("settings", {}).get("tier"),
                "volume_size": lambda r: int(r.get("settings", {}).get("dataDiskSizeGb", -1)),
                "tags": lambda r: r.get("settings", {}).get("userLabels", {}),
            },
            search_map={
                "_region": ["name", "region"],
                "_zone": ["name", "gceZone"],
            },
        )

    @metrics_collect_services.time()
    def collect_services(self):
        def post_process(service: GCPService, graph: Graph):
            # Right now we are only interested in Compute Engine pricing
            if service.name != "Compute Engine":
                return
            gs = gcp_client("cloudbilling", "v1", credentials=self.credentials)
            kwargs = {"parent": f"services/{service.id}"}
            for r in paginate(
                gcp_resource=gs.services().skus(),
                method_name="list",
                items_name="skus",
                **kwargs,
            ):
                sku = GCPServiceSKU(
                    id=r["skuId"],
                    tags={},
                    name=r.get("description"),
                    service=r.get("category", {}).get("serviceDisplayName"),
                    resource_family=r.get("category", {}).get("resourceFamily"),
                    resource_group=r.get("category", {}).get("resourceGroup"),
                    usage_type=r.get("category", {}).get("usageType"),
                    pricing_info=r.get("pricingInfo"),
                    service_provider_name=r.get("serviceProviderName"),
                    geo_taxonomy_type=r.get("geoTaxonomy", {}).get("type"),
                    geo_taxonomy_regions=r.get("geoTaxonomy", {}).get("regions"),
                    link=(f"https://{service.client}.googleapis.com/" f"{service.api_version}/{r.get('name')}"),
                    account=service.account(graph),
                    region=service.region(graph),
                    zone=service.zone(graph),
                )
                graph.add_resource(service, sku, edge_type=EdgeType.default)

        self.collect_something(
            resource_class=GCPService,
            paginate_method_name="list",
            paginate_items_name="services",
            attr_map={
                "id": "serviceId",
                "name": "displayName",
            },
            post_process=post_process,
        )

    @metrics_collect_instance_templates.time()
    def collect_instance_templates(self):
        self.collect_something(
            resource_class=GCPInstanceTemplate,
            search_map={
                "__machine_type": ["link", "machineType"],
            },
            predecessors={EdgeType.default: ["__machine_type"]},
        )

    @metrics_collect_gke_clusters.time()
    def collect_gke_clusters(self):
        self.collect_something(
            resource_class=GCPGKECluster,
            resource_kwargs={"parent": f"projects/{self.project.id}/locations/-"},
            client_nested_callables=["projects", "locations"],
            paginate_items_name="clusters",
            attr_map={
                "ctime": lambda r: iso2datetime(r.get("createTime")),
                "initial_cluster_version": "initialClusterVersion",
                "current_master_version": "currentMasterVersion",
                "cluster_status": "status",
                "current_node_count": "currentNodeCount",
            },
        )
