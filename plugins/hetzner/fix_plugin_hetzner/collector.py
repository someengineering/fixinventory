from typing import Optional
from fixlib.logger import log
from fixlib.core.actions import CoreFeedback
from fixlib.baseresources import Cloud, VolumeStatus
from fixlib.graph import Graph
from .resources import (
    HcloudProject,
    HcloudLocation,
    HcloudDatacenter,
    HcloudServer,
    HcloudVolume,
    HcloudNetwork,
    HcloudSubnet,
    HcloudRoute,
    HcloudIso,
    HcloudDeprecationInfo,
    HcloudServerType,
    HcloudFloatingIP,
    HcloudPrimaryIP,
    HcloudPrivateNetwork,
    HcloudPublicNetwork,
    HcloudIPv4Address,
    HcloudIPv6Network,
    HcloudFirewall,
    HcloudFirewallRule,
)
from .client import get_client


class HcloudCollector:
    def __init__(
        self,
        cloud: Cloud,
        project: HcloudProject,
        api_token: str,
        core_feedback: CoreFeedback,
        max_resources_per_account: Optional[int] = None,
    ) -> None:
        self.cloud = cloud
        self.core_feedback = core_feedback
        self.api_token = api_token
        self.project = project
        self.api_token = api_token
        self.graph = Graph(root=self.project, max_nodes=max_resources_per_account)

    def collect(self):
        log.info(f"Collecting resources in {self.project.kdname}")
        self.add_locations()
        self.add_datacenters()
        self.add_server_types()
        self.add_isos()
        self.add_primary_ips()
        self.add_volumes()
        self.add_servers()
        self.add_networks()
        self.add_floating_ips()
        self.add_firewalls()

    def add_locations(self):
        log.info(f"Collecting locations in {self.project.kdname}")
        client = get_client(self.api_token)
        for location in client.locations.get_all():
            hcl = HcloudLocation(
                hcloud_id=location.id,
                id=location.name,
                name=location.name,
                long_name=location.description,
                latitude=location.latitude,
                longitude=location.longitude,
                cloud=self.cloud,
                account=self.project,
            )
            self.graph.add_resource(self.project, hcl)

    def add_datacenters(self):
        log.info(f"Collecting datacenters in {self.project.kdname}")
        client = get_client(self.api_token)
        for datacenter in client.datacenters.get_all():
            hcl = self.graph.search_first_all({"kind": "hcloud_location", "id": datacenter.location.name})
            if not hcl:
                log.error(f"Location {datacenter.location.name} not found for datacenter {datacenter.name}")
                continue
            d = HcloudDatacenter(
                hcloud_id=datacenter.id,
                id=datacenter.name,
                name=datacenter.name,
                long_name=datacenter.description,
                cloud=self.cloud,
                account=self.project,
                region=hcl,
            )
            self.graph.add_resource(hcl, d)

    def add_networks(self):
        log.info(f"Collecting networks in {self.project.kdname}")
        client = get_client(self.api_token)
        for network in client.networks.get_all():
            hcn = HcloudNetwork(
                hcloud_id=network.id,
                id=network.name,
                name=network.name,
                tags=network.labels,
                cloud=self.cloud,
                account=self.project,
                ip_range=network.ip_range,
                network_subnets=[
                    HcloudSubnet(
                        type=s.type,
                        ip_range=s.ip_range,
                        network_zone=s.network_zone,
                        gateway=s.gateway,
                        vswitch_id=s.vswitch_id,
                    )
                    for s in network.subnets
                ],
                network_routes=[HcloudRoute(destination=r.destination, gateway=r.gateway) for r in network.routes],
                expose_routes_to_vswitch=network.expose_routes_to_vswitch,
                protection=network.protection,
            )
            self.graph.add_resource(self.project, hcn)
            for server in network.servers:
                hcs = self.graph.search_first_all({"kind": "hcloud_server", "id": server.name})
                if not hcs:
                    log.error(f"Server {server.name} not found for network {network.name}")
                    continue
                self.graph.add_edge(hcn, hcs)

    def add_volumes(self):
        log.info(f"Collecting volumes in {self.project.kdname}")
        client = get_client(self.api_token)
        for volume in client.volumes.get_all():
            hcl = self.graph.search_first_all({"kind": "hcloud_location", "id": volume.location.name})
            if not hcl:
                log.error(f"Location {volume.location.name} not found for volume {volume.name}")
                continue

            volume_status = VolumeStatus.UNKNOWN
            if volume.status == "available":
                if volume.server is None:
                    volume_status = VolumeStatus.AVAILABLE
                else:
                    volume_status = VolumeStatus.IN_USE
            elif volume.status == "creating":
                volume_status = VolumeStatus.BUSY

            hcv = HcloudVolume(
                hcloud_id=volume.id,
                id=volume.name,
                name=volume.name,
                tags=volume.labels,
                ctime=volume.created,
                volume_size=volume.size,
                volume_status=volume_status,
                linux_device=volume.linux_device,
                protection=volume.protection,
                format=volume.format,
                cloud=self.cloud,
                account=self.project,
                region=hcl,
            )
            self.graph.add_resource(hcl, hcv)

    def add_servers(self):
        log.info(f"Collecting servers in {self.project.kdname}")
        client = get_client(self.api_token)
        for server in client.servers.get_all():
            hcd = self.graph.search_first_all({"kind": "hcloud_datacenter", "id": server.datacenter.name})
            if not hcd:
                log.error(f"Datacenter {server.datacenter.name} not found for server {server.name}")
                continue
            hcl = hcd.region()

            public_net = None
            instance_cores = None
            instance_memory = None
            instance_type = None
            if server.public_net:
                ipv4 = None
                ipv6 = None
                primary_ipv4 = None
                primary_ipv6 = None
                if server.public_net.ipv4:
                    ipv4 = HcloudIPv4Address(
                        ip_address=server.public_net.ipv4.ip,
                        blocked=server.public_net.ipv4.blocked,
                        dns_ptr=server.public_net.ipv4.dns_ptr,
                    )
                if server.public_net.ipv6:
                    ipv6 = HcloudIPv6Network(
                        ip_address=server.public_net.ipv6.ip,
                        blocked=server.public_net.ipv6.blocked,
                        dns_ptr=server.public_net.ipv6.dns_ptr,
                        network=server.public_net.ipv6.network,
                        network_mask=server.public_net.ipv6.network_mask,
                    )
                public_net = HcloudPublicNetwork(
                    ipv4=ipv4,
                    ipv6=ipv6,
                )

            private_net = None
            if server.private_net:
                for pnet in server.private_net:
                    pn = HcloudPrivateNetwork(
                        ip_address=pnet.ip,
                        alias_ips=pnet.alias_ips,
                        mac_address=pnet.mac_address,
                    )
                    if not private_net:
                        private_net = []
                    private_net.append(pn)

            st = None
            if server.server_type:
                st: HcloudServerType = self.graph.search_first_all(
                    {"kind": "hcloud_server_type", "id": server.server_type.name}
                )
                if st:
                    instance_cores = st.instance_cores
                    instance_memory = st.instance_memory
                    instance_type = st.name
            s = HcloudServer(
                hcloud_id=server.id,
                id=server.name,
                name=server.name,
                ctime=server.created,
                tags=server.labels,
                instance_cores=instance_cores,
                instance_memory=instance_memory,
                instance_type=instance_type,
                public_net=public_net,
                private_net=private_net,
                rescue_enabled=server.rescue_enabled,
                locked=server.locked,
                backup_window=server.backup_window,
                outgoing_traffic=server.outgoing_traffic,
                ingoing_traffic=server.ingoing_traffic,
                included_traffic=server.included_traffic,
                primary_disk_size=server.primary_disk_size,
                protection=server.protection,
                cloud=self.cloud,
                account=self.project,
                region=hcl,
                zone=hcd,
            )
            self.graph.add_resource(hcl, s)
            self.graph.add_edge(hcd, s)
            if st:
                self.graph.add_edge(st, s)
            for volume in server.volumes:
                v = self.graph.search_first_all({"kind": "hcloud_volume", "id": volume.name})
                if not v:
                    log.error(f"Volume {volume.name} not found for server {server.name}")
                    continue
                self.graph.add_edge(s, v)

            if server.public_net:
                if server.public_net.primary_ipv4:
                    primary_ipv4 = self.graph.search_first_all(
                        {"kind": "hcloud_primary_ip", "id": server.public_net.primary_ipv4.ip}
                    )
                    if primary_ipv4:
                        self.graph.add_edge(s, primary_ipv4)
                if server.public_net.primary_ipv6:
                    primary_ipv6 = self.graph.search_first_all(
                        {"kind": "hcloud_primary_ip", "id": server.public_net.primary_ipv6.ip}
                    )
                    if primary_ipv6:
                        self.graph.add_edge(s, primary_ipv6)

    def add_isos(self):
        log.info(f"Collecting ISOs in {self.project.kdname}")
        client = get_client(self.api_token)
        for iso in client.isos.get_all():
            deprecation = None
            if iso.deprecation:
                deprecation = HcloudDeprecationInfo(
                    announced_at=iso.deprecation.announced,
                    unavailable_after=iso.deprecation.unavailable_after,
                )
            i = HcloudIso(
                hcloud_id=iso.id,
                id=iso.name,
                name=iso.name,
                cloud=self.cloud,
                account=self.project,
                description=iso.description,
                type=iso.type,
                deprecated_at=iso.deprecated,
                deprecation=deprecation,
            )
            self.graph.add_resource(self.project, i)

    def add_server_types(self):
        log.info(f"Collecting server types in {self.project.kdname}")
        client = get_client(self.api_token)
        for server_type in client.server_types.get_all():
            deprecation = None
            if server_type.deprecation:
                deprecation = HcloudDeprecationInfo(
                    announced_at=server_type.deprecation.announced,
                    unavailable_after=server_type.deprecation.unavailable_after,
                )
            st = HcloudServerType(
                hcloud_id=server_type.id,
                id=server_type.name,
                name=server_type.name,
                cloud=self.cloud,
                account=self.project,
                description=server_type.description,
                instance_cores=server_type.cores,
                instance_memory=server_type.memory,
                volume_size=server_type.disk,
                prices=server_type.prices,
                storage_type=server_type.storage_type,
                cpu_type=server_type.cpu_type,
                architecture=server_type.architecture,
                deprecated=server_type.deprecated,
                deprecation=deprecation,
            )
            self.graph.add_resource(self.project, st)

    def add_floating_ips(self):
        log.info(f"Collecting floating IPs in {self.project.kdname}")
        client = get_client(self.api_token)
        for floating_ip in client.floating_ips.get_all():
            hcl = self.graph.search_first_all({"kind": "hcloud_location", "id": floating_ip.home_location.name})
            fi = HcloudFloatingIP(
                hcloud_id=floating_ip.id,
                id=floating_ip.ip,
                name=floating_ip.name,
                tags=floating_ip.labels,
                ctime=floating_ip.created,
                cloud=self.cloud,
                account=self.project,
                region=hcl,
                description=floating_ip.description,
                ip_address=floating_ip.ip,
                ip_address_family=floating_ip.type,
                blocked=floating_ip.blocked,
                dns_ptr=floating_ip.dns_ptr,
                protection=floating_ip.protection,
            )
            self.graph.add_resource(hcl, fi)
            if floating_ip.server:
                s = self.graph.search_first_all({"kind": "hcloud_server", "id": floating_ip.server.name})
                if s:
                    self.graph.add_edge(s, fi)

    def add_primary_ips(self):
        log.info(f"Collecting primary IPs in {self.project.kdname}")
        client = get_client(self.api_token)
        for primary_ip in client.primary_ips.get_all():
            d = self.graph.search_first_all({"kind": "hcloud_datacenter", "id": primary_ip.datacenter.name})
            r = d.region()
            p = HcloudPrimaryIP(
                hcloud_id=primary_ip.id,
                id=primary_ip.ip,
                name=primary_ip.name,
                tags=primary_ip.labels,
                ctime=primary_ip.created,
                cloud=self.cloud,
                account=self.project,
                region=r,
                zone=d,
                ip_address=primary_ip.ip,
                ip_address_family=primary_ip.type,
                blocked=primary_ip.blocked,
                dns_ptr=primary_ip.dns_ptr,
                assignee_id=primary_ip.assignee_id,
                assigneer_type=primary_ip.assignee_type,
                auto_delete=primary_ip.auto_delete,
                protection=primary_ip.protection,
            )
            self.graph.add_resource(r, p)

    def add_firewalls(self):
        log.info(f"Collecting firewalls in {self.project.kdname}")
        client = get_client(self.api_token)
        for firewall in client.firewalls.get_all():
            if firewall.rules:
                firewall_rules = [
                    HcloudFirewallRule(
                        direction=r.direction,
                        port=r.port,
                        protocol=r.protocol,
                        source_ips=r.source_ips,
                        destination_ips=r.destination_ips,
                        description=r.description,
                    )
                    for r in firewall.rules
                ]
            f = HcloudFirewall(
                hcloud_id=firewall.id,
                id=firewall.name,
                name=firewall.name,
                tags=firewall.labels,
                ctime=firewall.created,
                cloud=self.cloud,
                account=self.project,
                firewall_rules=firewall_rules,
            )
            self.graph.add_resource(self.project, f)
            if firewall.applied_to:
                for firewall_resource in firewall.applied_to:
                    if firewall_resource.type == "server":
                        s = self.graph.search_first_all({"kind": "hcloud_server", "id": firewall_resource.server.name})
                        if s:
                            self.graph.add_edge(f, s)
