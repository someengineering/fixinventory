from typing import Optional
from fixlib.logger import log
from fixlib.core.actions import CoreFeedback
from fixlib.baseresources import Cloud, VolumeStatus
from fixlib.graph import Graph
from .resources import HcloudProject, HcloudLocation, HcloudDatacenter, HcloudServer, HcloudVolume
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
        self.add_volumes()
        self.add_servers()

    def add_locations(self):
        client = get_client(self.api_token)
        for location in client.locations.get_all():
            l = HcloudLocation(
                id=location.name,
                name=location.name,
                long_name=location.description,
                latitude=location.latitude,
                longitude=location.longitude,
                cloud=self.cloud,
                account=self.project,
            )
            self.graph.add_resource(self.project, l)

    def add_datacenters(self):
        client = get_client(self.api_token)
        for datacenter in client.datacenters.get_all():
            l = self.graph.search_first_all({"kind": "hcloud_location", "id": datacenter.location.name})
            if not l:
                log.error(f"Location {datacenter.location.name} not found for datacenter {datacenter.name}")
                continue
            d = HcloudDatacenter(
                id=datacenter.name,
                name=datacenter.name,
                long_name=datacenter.description,
                cloud=self.cloud,
                account=self.project,
                region=l,
            )
            self.graph.add_resource(l, d)

    def add_volumes(self):
        client = get_client(self.api_token)
        for volume in client.volumes.get_all():
            l = self.graph.search_first_all({"kind": "hcloud_location", "id": volume.location.name})
            if not l:
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

            v = HcloudVolume(
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
                region=l,
            )
            self.graph.add_resource(l, v)

    def add_servers(self):
        client = get_client(self.api_token)
        for server in client.servers.get_all():
            d = self.graph.search_first_all({"kind": "hcloud_datacenter", "id": server.datacenter.name})
            if not d:
                log.error(f"Datacenter {server.datacenter.name} not found for server {server.name}")
                continue
            l = d.region()
            s = HcloudServer(
                id=server.name,
                name=server.name,
                ctime=server.created,
                tags=server.labels,
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
                region=l,
                zone=d,
            )
            self.graph.add_resource(l, s)
            self.graph.add_edge(d, s)
            for volume in server.volumes:
                v = self.graph.search_first_all({"kind": "hcloud_volume", "id": volume.name})
                if not v:
                    log.error(f"Volume {volume.name} not found for server {server.name}")
                    continue
                self.graph.add_edge(s, v)
