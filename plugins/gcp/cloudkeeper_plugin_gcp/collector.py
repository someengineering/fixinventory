import cloudkeeper.logging
import cloudkeeper.signal
from pprint import pformat
from typing import List, Dict, Type, Union
from cloudkeeper.baseresources import BaseResource
from cloudkeeper.graph import Graph, get_resource_attributes
from cloudkeeper.args import ArgumentParser
from .resources import (
    GCPProject,
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
    GCPRegionSSLCertificate,
    GCPRegionTargetHttpProxy,
    GCPRegionTargetHttpsProxy,
)
from .utils import (
    Credentials,
    compute_client,
    paginate,
    iso2datetime,
    get_result_data,
)

log = cloudkeeper.logging.getLogger("cloudkeeper." + __name__)


class GCPProjectCollector:
    def __init__(self, project: GCPProject) -> None:
        self.project = project
        self.credentials = Credentials.get(self.project.id)
        self.root = self.project
        self.graph = Graph()
        resource_attr = get_resource_attributes(self.root)
        self.graph.add_node(self.root, label=self.root.name, **resource_attr)

        self.mandatory_collectors = {
            "regions": self.collect_regions,
            "zones": self.collect_zones,
        }
        self.global_collectors = {
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
            #            "global_network_endpoint_groups": self.collect_global_network_endpoint_groups,
            "instance_groups": self.collect_instance_groups,
            "instance_group_managers": self.collect_instance_group_managers,
            "autoscalers": self.collect_autoscalers,
            "target_pools": self.collect_target_pools,
            "target_instances": self.collect_target_instances,
            "target_http_proxies": self.collect_target_http_proxies,
            "target_https_proxies": self.collect_target_https_proxies,
            "target_ssl_proxies": self.collect_target_ssl_proxies,
            "target_tcp_proxies": self.collect_target_tcp_proxies,
            "target_grpc_proxies": self.collect_target_grpc_proxies,
            "backend_services": self.collect_backend_services,
            "url_maps": self.collect_url_maps,
            "forwarding_rules": self.collect_forwarding_rules,
            #            "global_forwarding_rules": self.collect_global_forwarding_rules,
        }
        self.region_collectors = {
            "region_ssl_certificates": self.collect_region_ssl_certificates,
            "region_target_http_proxies": self.collect_region_target_http_proxies,
            "region_target_https_proxies": self.collect_region_target_https_proxies,
        }
        self.zone_collectors = {}
        self.all_collectors = dict(self.mandatory_collectors)
        self.all_collectors.update(self.global_collectors)
        self.all_collectors.update(self.region_collectors)
        self.all_collectors.update(self.zone_collectors)
        self.collector_set = set(self.all_collectors.keys())

    def collect(self) -> None:
        collectors = set(self.collector_set)
        if len(ArgumentParser.args.gcp_collect) > 0:
            collectors = set(ArgumentParser.args.gcp_collect).intersection(collectors)
        if len(ArgumentParser.args.gcp_no_collect) > 0:
            collectors = collectors - set(ArgumentParser.args.gcp_no_collect)
        collectors = collectors.union(set(self.mandatory_collectors.keys()))

        log.debug(
            (
                f"Running the following collectors in {self.project.rtdname}:"
                f" {', '.join(collectors)}"
            )
        )
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

        for region in regions:
            for collector_name, collector in self.region_collectors.items():
                if collector_name in collectors:
                    log.info(
                        f"Collecting {collector_name} in {region.rtdname} {self.project.rtdname}"
                    )
                    collector(region=region)

        for zone in zones:
            for collector_name, collector in self.zone_collectors.items():
                if collector_name in collectors:
                    log.info(
                        f"Collecting {collector_name} in {zone.rtdname} {self.project.rtdname}"
                    )
                    collector(zone=zone)

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
                data = get_result_data(result, map_from)
                if data is None:
                    log.error(f"Attribute {map_from} not in result")
                    continue
                log.debug(f"Found attribute {map_to}: {pformat(data)}")
                kwargs[map_to] = data

        default_search_map = {"region": ["link", "region"], "zone": ["link", "zone"]}
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
                and not str(map_to).startswith("_")
            ):
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
        resource_class: Type[BaseResource],
        paginate_method_name: str = "list",
        paginate_items_name: str = "items",
        parent_resource: Union[BaseResource, str] = None,
        attr_map: Dict = None,
        search_map: Dict = None,
        successors: List = None,
        predecessors: List = None,
        compute_client_kwargs: Dict = None,
        resource_kwargs: Dict = None,
        paginate_subitems_name: str = None,
        dump_resource: bool = False,
    ) -> List:
        client_method_name = resource_class("", {})._client_method
        log.debug(f"Collecting {client_method_name}")
        if paginate_subitems_name is None:
            paginate_subitems_name = client_method_name
        if compute_client_kwargs is None:
            compute_client_kwargs = {}
        if resource_kwargs is None:
            resource_kwargs = {}
        if successors is None:
            successors = []
        if predecessors is None:
            predecessors = []
        parent_map = {True: predecessors, False: successors}

        client = compute_client(credentials=self.credentials, **compute_client_kwargs)
        gcp_resource = getattr(client, client_method_name)
        if not callable(gcp_resource):
            raise RuntimeError(f"No method {client_method_name} on client {client}")

        for resource in paginate(
            gcp_resource=gcp_resource(),
            method_name=paginate_method_name,
            items_name=paginate_items_name,
            subitems_name=paginate_subitems_name,
            project=self.project.id,
            **resource_kwargs,
        ):
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
                pr = kwargs.get("zone", kwargs.get("region", self.root))
                log.debug(
                    f"Parent resource for {r.rtdname} automatically set to {pr.rtdname}"
                )
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
            resource_class=GCPRegion,
            attr_map={"region_status": "status"},
        )

    def collect_zones(self) -> List:
        self.collect_something(
            resource_class=GCPZone,
        )

    def collect_disks(self):
        def volume_status(result):
            status = result.get("status")
            num_users = len(result.get("users", []))
            if num_users == 0 and status == "READY":
                status = "AVAILABLE"
            return status

        self.collect_something(
            paginate_method_name="aggregatedList",
            resource_class=GCPDisk,
            search_map={
                "volume_type": ["link", "type"],
                "_users": ["link", "users"],
            },
            attr_map={
                "volume_size": "sizeGb",
                "volume_status": volume_status,
                "last_attach_timestamp": (
                    lambda r: iso2datetime(
                        r.get("lastAttachTimestamp", r["creationTimestamp"])
                    )
                ),
                "last_detach_timestamp": (
                    lambda r: iso2datetime(
                        r.get("lastDetachTimestamp", r["creationTimestamp"])
                    )
                ),
            },
            predecessors=["volume_type"],
            successors=["_users"],
        )

    def collect_instances(self):
        self.collect_something(
            paginate_method_name="aggregatedList",
            resource_class=GCPInstance,
            search_map={
                "_network": [
                    "link",
                    (
                        lambda r: next(iter(r.get("networkInterfaces", [])), {}).get(
                            "network"
                        )
                    ),
                ],
                "_subnetwork": [
                    "link",
                    (
                        lambda r: next(iter(r.get("networkInterfaces", [])), {}).get(
                            "subnetwork"
                        )
                    ),
                ],
                "instance_type": ["link", "machineType"],
            },
            attr_map={
                "instance_status": "status",
            },
            predecessors=["_network", "_subnetwork", "instance_type"],
        )

    def collect_disk_types(self):
        self.collect_something(
            paginate_method_name="aggregatedList",
            resource_class=GCPDiskType,
        )

    def collect_networks(self):
        self.collect_something(
            resource_class=GCPNetwork,
        )

    def collect_subnetworks(self):
        self.collect_something(
            paginate_method_name="aggregatedList",
            resource_class=GCPSubnetwork,
            search_map={
                "_network": ["link", "network"],
            },
            predecessors=["_network"],
        )

    def collect_vpn_tunnels(self):
        self.collect_something(
            paginate_method_name="aggregatedList",
            resource_class=GCPVPNTunnel,
            search_map={
                "_vpn_gateway": ["link", "vpnGateway"],
                "_target_vpn_gateway": ["link", "targetVpnGateway"],
            },
            successors=["_target_vpn_gateway", "_vpn_gateway"],
        )

    def collect_vpn_gateways(self):
        self.collect_something(
            paginate_method_name="aggregatedList",
            resource_class=GCPVPNGateway,
            search_map={
                "_network": ["link", "network"],
            },
            predecessors=["_network"],
        )

    def collect_target_vpn_gateways(self):
        self.collect_something(
            paginate_method_name="aggregatedList",
            resource_class=GCPTargetVPNGateway,
            search_map={
                "_network": ["link", "network"],
            },
            predecessors=["_network"],
        )

    def collect_routers(self):
        self.collect_something(
            paginate_method_name="aggregatedList",
            resource_class=GCPRouter,
            search_map={
                "_network": ["link", "network"],
            },
            predecessors=["_network"],
        )

    def collect_routes(self):
        self.collect_something(
            resource_class=GCPRoute,
            search_map={
                "_network": ["link", "network"],
            },
            predecessors=["_network"],
        )

    def collect_security_policies(self):
        self.collect_something(resource_class=GCPSecurityPolicy)

    def collect_snapshots(self):
        self.collect_something(
            resource_class=GCPSnapshot,
            search_map={
                "volume_id": ["link", "sourceDisk"],
            },
            attr_map={
                "volume_size": "diskSizeGb",
                "storage_bytes": "storageBytes",
            },
        )

    def collect_ssl_certificates(self):
        self.collect_something(
            paginate_method_name="aggregatedList",
            resource_class=GCPSSLCertificate,
            search_map={
                "_user": ["link", "user"],
            },
            successors=["_user"],
        )

    def collect_region_ssl_certificates(self, region: GCPRegion):
        self.collect_something(
            resource_kwargs={"region": region.name},
            resource_class=GCPRegionSSLCertificate,
            search_map={
                "_user": ["link", "user"],
            },
            successors=["_user"],
        )

    def collect_machine_types(self):
        self.collect_something(
            resource_class=GCPMachineType,
            paginate_method_name="aggregatedList",
            search_map={
                "zone": ["name", "zone"],
            },
            attr_map={
                "instance_cores": "guestCpus",
                "instance_memory": "memoryMb",
            },
        )

    def collect_network_endpoint_groups(self):
        self.collect_something(
            resource_class=GCPNetworkEndpointGroup,
            paginate_method_name="aggregatedList",
            search_map={
                "_subnetwork": ["link", "subnetwork"],
                "_network": ["link", "network"],
            },
            attr_map={
                "default_port": "defaultPort",
                "neg_type": "networkEndpointType",
            },
            predecessors=["_network", "_subnetwork"],
        )

    def collect_global_network_endpoint_groups(self):
        self.collect_something(
            resource_class=GCPGlobalNetworkEndpointGroup,
            search_map={
                "_subnetwork": ["link", "subnetwork"],
                "_network": ["link", "network"],
            },
            attr_map={
                "default_port": "defaultPort",
                "neg_type": "networkEndpointType",
            },
            predecessors=["_network", "_subnetwork"],
        )

    def collect_instance_groups(self):
        self.collect_something(
            resource_class=GCPInstanceGroup,
            paginate_method_name="aggregatedList",
            search_map={
                "_subnetwork": ["link", "subnetwork"],
                "_network": ["link", "network"],
            },
            predecessors=["_network", "_subnetwork"],
        )

    def collect_instance_group_managers(self):
        self.collect_something(
            resource_class=GCPInstanceGroupManager,
            paginate_method_name="aggregatedList",
            search_map={
                "_instance_group": ["link", "instanceGroup"],
                "_health_checks": [
                    "link",
                    (
                        lambda r: [
                            hc.get("healthCheck", "")
                            for hc in r.get("autoHealingPolicies", [])
                        ]
                    ),
                ],
            },
            predecessors=["_instance_group", "_health_checks"],
        )

    def collect_autoscalers(self):
        self.collect_something(
            resource_class=GCPAutoscaler,
            paginate_method_name="aggregatedList",
            search_map={
                "_instance_group_manager": ["link", "target"],
            },
            attr_map={
                "min_size": (
                    lambda r: r.get("autoscalingPolicy", {}).get("minNumReplicas", -1)
                ),
                "max_size": (
                    lambda r: r.get("autoscalingPolicy", {}).get("maxNumReplicas", -1)
                ),
            },
            successors=["_instance_group_manager"],
        )

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

    def collect_url_maps(self):
        self.collect_something(
            resource_class=GCPUrlMap,
            paginate_method_name="aggregatedList",
            search_map={
                "_default_service": ["link", "defaultService"],
            },
            successors=["_default_service"],
            dump_resource=True,
        )

    def collect_target_pools(self):
        self.collect_something(
            resource_class=GCPTargetPool,
            paginate_method_name="aggregatedList",
            search_map={
                "_health_checks": ["link", "healthChecks"],
                "_instances": ["link", "instances"],
            },
            attr_map={
                "session_affinity": "sessionAffinity",
                "failover_ratio": "failoverRatio",
            },
            predecessors=["_instances", "_health_checks"],
            dump_resource=True,
        )

    def collect_target_instances(self):
        self.collect_something(
            resource_class=GCPTargetInstance,
            paginate_method_name="aggregatedList",
            dump_resource=True,
        )

    def collect_target_http_proxies(self):
        self.collect_something(
            resource_class=GCPTargetHttpProxy,
            paginate_method_name="aggregatedList",
            dump_resource=True,
        )

    def collect_target_https_proxies(self):
        self.collect_something(
            resource_class=GCPTargetHttpsProxy,
            paginate_method_name="aggregatedList",
            dump_resource=True,
        )

    def collect_region_target_http_proxies(self, region: GCPRegion):
        self.collect_something(
            resource_kwargs={"region": region.name},
            resource_class=GCPRegionTargetHttpProxy,
            dump_resource=True,
        )

    def collect_region_target_https_proxies(self, region: GCPRegion):
        self.collect_something(
            resource_kwargs={"region": region.name},
            resource_class=GCPRegionTargetHttpsProxy,
            dump_resource=True,
        )

    def collect_target_ssl_proxies(self):
        self.collect_something(
            resource_class=GCPTargetSslProxy,
            dump_resource=True,
        )

    def collect_target_tcp_proxies(self):
        self.collect_something(
            resource_class=GCPTargetTcpProxy,
            dump_resource=True,
        )

    def collect_target_grpc_proxies(self):
        self.collect_something(
            resource_class=GCPTargetGrpcProxy,
            dump_resource=True,
        )

    def collect_backend_services(self):
        self.collect_something(
            resource_class=GCPBackendService,
            paginate_method_name="aggregatedList",
            search_map={
                "_health_checks": ["link", "healthChecks"],
                "_backends": [
                    "link",
                    (lambda r: [g.get("group", "") for g in r.get("backends", [])]),
                ],
            },
            predecessors=["_health_checks", "_backends"],
            dump_resource=True,
        )

    def collect_forwarding_rules(self):
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
                "_target": ["link", "target"],
            },
            predecessors=["_target"],
            dump_resource=True,
        )

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
                "_target": ["link", "target"],
            },
            predecessors=["_target"],
            dump_resource=True,
        )
