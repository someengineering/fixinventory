from dataclasses import dataclass
from typing import ClassVar, Dict, List, Optional

import resotolib.logging
from resotolib.baseresources import (
    BaseAccount,
    BaseDatabase,
    BaseInstance,
    BaseIPAddress,
    BaseLoadBalancer,
    BaseNetwork,
    BaseRegion,
    BaseResource,
    BaseSnapshot,
    BaseVolume,
    InstanceStatus,
    VolumeStatus,
    BaseBucket,
    BaseEndpoint,
    BaseCertificate,
    BaseKeyPair,
    BaseDomain,
    BaseDomainRecord,
)
from resotolib.graph import Graph
from resoto_plugin_digitalocean.client import get_team_credentials
from resoto_plugin_digitalocean.client import StreamingWrapper

log = resotolib.logging.getLogger("resoto." + __name__)


@dataclass(eq=False)
class DigitalOceanResource(BaseResource):
    """A class that implements the abstract method delete() as well as update_tag()
    and delete_tag().

    delete() must be implemented. update_tag() and delete_tag() are optional.
    """

    kind: ClassVar[str] = "digitalocean_resource"
    urn: str = ""

    def delete_uri_path(self) -> Optional[str]:
        return None

    def tag_resource_name(self) -> Optional[str]:
        return None

    def delete(self, graph: Graph) -> bool:
        """Delete a resource in the cloud"""
        if self.delete_uri_path():
            log.debug(
                f"Deleting resource {self.id} in account {self.account(graph).id} region {self.region(graph).id}"
            )
            team = self.account(graph)
            credentials = get_team_credentials(team.id)
            client = StreamingWrapper(
                credentials.api_token,
                credentials.spaces_access_key,
                credentials.spaces_secret_key,
            )
            return client.delete(self.delete_uri_path(), self.id)

        raise NotImplementedError

    def update_tag(self, key, value) -> bool:

        if self.tag_resource_name():
            log.debug(f"Updating tag {key} on resource {self.id}")
            if value:
                log.warning(
                    "DigitalOcean does not support tag values. It will be ignored."
                )
            team = self._account
            credentials = get_team_credentials(team.id)
            client = StreamingWrapper(
                credentials.api_token,
                credentials.spaces_access_key,
                credentials.spaces_secret_key,
            )

            tag_ready: bool = True

            tag_count = client.get_tag_count(key)
            # tag count call failed unrecoverably, we can't continue
            if tag_count is None:
                return False
            # tag does not exist, create it
            if tag_count == -1:
                tag_ready = client.create_tag(key)

            return tag_ready and client.tag_resource(
                key, self.tag_resource_name(), self.id
            )

        raise NotImplementedError

    def delete_tag(self, key) -> bool:
        if self.tag_resource_name():
            log.debug(f"Deleting tag {key} on resource {self.id}")
            team = self._account
            credentials = get_team_credentials(team.id)
            client = StreamingWrapper(
                credentials.api_token,
                credentials.spaces_access_key,
                credentials.spaces_secret_key,
            )
            untagged = client.untag_resource(key, self.tag_resource_name(), self.id)
            if not untagged:
                return False
            tag_count = client.get_tag_count(key)
            if tag_count == 0:
                return client.delete("/tags", key)
            return True
        raise NotImplementedError


@dataclass(eq=False)
class DigitalOceanTeam(DigitalOceanResource, BaseAccount):
    """DigitalOcean Team"""

    kind: ClassVar[str] = "digitalocean_team"


@dataclass(eq=False)
class DigitalOceanRegion(DigitalOceanResource, BaseRegion):
    """DigitalOcean region"""

    kind: ClassVar[str] = "digitalocean_region"

    do_region_slug: Optional[str] = None
    do_region_features: Optional[List[str]] = None
    is_available: Optional[bool] = None
    do_region_droplet_sizes: Optional[List[str]] = None


@dataclass(eq=False)
class DigitalOceanProject(DigitalOceanResource, BaseResource):
    """DigitalOcean project"""

    kind: ClassVar[str] = "digitalocean_project"
    owner_uuid: Optional[str] = None
    owner_id: Optional[str] = None
    description: Optional[str] = None
    purpose: Optional[str] = None
    environment: Optional[str] = None
    is_default: Optional[bool] = None

    def delete_uri_path(self):
        return "/projects"


@dataclass(eq=False)
class DigitalOceanDroplet(DigitalOceanResource, BaseInstance):
    """A DigitalOcean Droplet Resource

    Droplet have a class variable `instance_status_map` which contains
    a mapping from the droplet status string the cloud API returns
    to our internal InstanceStatus state.
    """

    kind: ClassVar[str] = "digitalocean_droplet"
    instance_status_map: ClassVar[Dict[str, InstanceStatus]] = {
        "new": InstanceStatus.BUSY,
        "active": InstanceStatus.RUNNING,
        "off": InstanceStatus.TERMINATED,
        "archive": InstanceStatus.TERMINATED,
    }
    droplet_backup_ids: Optional[List[str]] = None
    is_locked: Optional[bool] = None
    droplet_features: Optional[List[str]] = None
    droplet_image: Optional[str] = None

    def delete_uri_path(self) -> Optional[str]:
        return "/droplets"

    def _instance_status_setter(self, value: str) -> None:
        """Setter that looks up the instance status

        Based on the string that was give we're doing a dict lookup
        for the corresponding instance status and assign it or
        InstanceStatus.UNKNOWN.
        """
        self._instance_status = self.instance_status_map.get(
            value, InstanceStatus.UNKNOWN
        )

    def tag_resource_name(self) -> Optional[str]:
        return "droplet"


# Because we are using dataclasses and allow to supply the `instance_status`
# string to the constructor we can not use the normal @property decorator.
# Instead we assign the property once the class has been fully defined.
DigitalOceanDroplet.instance_status = property(
    DigitalOceanDroplet._instance_status_getter,
    DigitalOceanDroplet._instance_status_setter,
)


@dataclass(eq=False)
class DigitalOceanKubernetesCluster(DigitalOceanResource, BaseResource):
    """DigitalOcean Kubernetes Cluster"""

    kind: ClassVar[str] = "digitalocean_kubernetes_cluster"

    k8s_version: Optional[str] = None
    k8s_cluster_subnet: Optional[str] = None
    k8s_service_subnet: Optional[str] = None
    ipv4_address: Optional[str] = None
    endpoint: Optional[str] = None
    auto_upgrade_enabled: Optional[bool] = None
    cluster_status: Optional[str] = None
    surge_upgrade_enabled: Optional[bool] = None
    registry_enabled: Optional[bool] = None
    ha_enabled: Optional[bool] = None

    def delete_uri_path(self) -> Optional[str]:
        return "/kubernetes/clusters"


@dataclass(eq=False)
class DigitalOceanVolume(DigitalOceanResource, BaseVolume):
    kind: ClassVar[str] = "digitalocean_volume"

    volume_status_map: ClassVar[Dict[str, VolumeStatus]] = {
        "creating": VolumeStatus.BUSY,
        "available": VolumeStatus.AVAILABLE,
        "in-use": VolumeStatus.IN_USE,
        "deleting": VolumeStatus.BUSY,
        "deleted": VolumeStatus.DELETED,
        "error": VolumeStatus.ERROR,
        "busy": VolumeStatus.BUSY,
    }

    description: Optional[str] = None
    filesystem_type: Optional[str] = None
    filesystem_label: Optional[str] = None

    def delete_uri_path(self) -> Optional[str]:
        return "/volumes"

    def _volume_status_setter(self, value: str) -> None:
        self._volume_status = self.volume_status_map.get(value, VolumeStatus.UNKNOWN)

    def tag_resource_name(self) -> Optional[str]:
        return "volume"


DigitalOceanVolume.volume_status = property(
    DigitalOceanVolume._volume_status_getter, DigitalOceanVolume._volume_status_setter
)


@dataclass(eq=False)
class DigitalOceanDatabase(DigitalOceanResource, BaseDatabase):
    kind: ClassVar[str] = "digitalocean_database"

    def delete_uri_path(self) -> Optional[str]:
        return "/databases"

    def tag_resource_name(self) -> Optional[str]:
        return "database"


@dataclass(eq=False)
class DigitalOceanNetwork(DigitalOceanResource, BaseNetwork):
    """DigitalOcean network

    This is what instances and other networking related resources might reside in.
    """

    kind: ClassVar[str] = "digitalocean_network"

    ip_range: Optional[str] = None
    description: Optional[str] = None
    is_default: Optional[bool] = None

    def delete_uri_path(self) -> Optional[str]:
        return "/vpcs"


@dataclass(eq=False)
class DigitalOceanSnapshot(DigitalOceanResource, BaseSnapshot):
    """DigitalOcean snapshot"""

    kind: ClassVar[str] = "digitalocean_snapshot"
    snapshot_size_gigabytes: Optional[int] = None
    resource_id: Optional[str] = None
    resource_type: Optional[str] = None

    def delete_uri_path(self) -> Optional[str]:
        return "/snapshots"

    def tag_resource_name(self) -> Optional[str]:
        return "volume_snapshot"


@dataclass(eq=False)
class DigitalOceanLoadBalancer(DigitalOceanResource, BaseLoadBalancer):
    """DigitalOcean load balancer"""

    kind: ClassVar[str] = "digitalocean_load_balancer"

    nr_nodes: Optional[int] = None
    loadbalancer_status: Optional[str] = None
    redirect_http_to_https: Optional[bool] = None
    enable_proxy_protocol: Optional[bool] = None
    enable_backend_keepalive: Optional[bool] = None
    disable_lets_encrypt_dns_records: Optional[bool] = None

    def delete_uri_path(self) -> Optional[str]:
        return "/load_balancers"


@dataclass(eq=False)
class DigitalOceanFloatingIP(DigitalOceanResource, BaseIPAddress):
    """DigitalOcean floating IP"""

    kind: ClassVar[str] = "digitalocean_floating_ip"

    is_locked: Optional[bool] = None

    def delete(self, graph: Graph) -> bool:
        log.debug(
            f"Deleting resource {self.id} in account {self.account(graph).id} region {self.region(graph).id}"
        )
        team = self.account(graph)
        credentials = get_team_credentials(team.id)
        client = StreamingWrapper(
            credentials.api_token,
            credentials.spaces_access_key,
            credentials.spaces_secret_key,
        )
        # un-assign the ip just in case it's still assigned to a droplet
        client.unassign_floating_ip(self.id)
        return client.delete("/floating_ips", self.id)


@dataclass(eq=False)
class DigitalOceanImage(DigitalOceanResource, BaseResource):
    """DigitalOcean image"""

    kind: ClassVar[str] = "digitalocean_image"

    distribution: Optional[str] = None
    image_slug: Optional[str] = None
    is_public: Optional[bool] = None
    min_disk_size: Optional[int] = None
    image_type: Optional[str] = None
    size_gigabytes: Optional[int] = None
    description: Optional[str] = None
    image_status: Optional[str] = None

    def delete_uri_path(self) -> Optional[str]:
        return "/images"

    def tag_resource_name(self) -> Optional[str]:
        return "image"


@dataclass(eq=False)
class DigitalOceanSpace(DigitalOceanResource, BaseBucket):
    """DigitalOcean space"""

    kind: ClassVar[str] = "digitalocean_space"

    def delete(self, graph: Graph) -> bool:
        log.debug(
            f"Deleting space {self.id} in account {self.account(graph).id} region {self.region(graph).id}"
        )
        team = self.account(graph)
        credentials = get_team_credentials(team.id)
        client = StreamingWrapper(
            credentials.api_token,
            credentials.spaces_access_key,
            credentials.spaces_secret_key,
        )
        return client.delete_space(self.region(graph).id, self.id)


@dataclass(eq=False)
class DigitalOceanApp(DigitalOceanResource, BaseResource):
    """DigitalOcean app"""

    kind: ClassVar[str] = "digitalocean_app"

    tier_slug: Optional[str] = None
    default_ingress: Optional[str] = None
    live_url: Optional[str] = None
    live_url_base: Optional[str] = None
    live_domain: Optional[str] = None

    def delete_uri_path(self):
        return "/apps"


@dataclass(eq=False)
class DigitalOceanCdnEndpoint(DigitalOceanResource, BaseEndpoint):
    """DigitalOcean CDN endpoint"""

    kind = "digitalocean_cdn_endpoint"

    origin: Optional[str] = None
    endpoint: Optional[str] = None
    certificate_id: Optional[str] = None
    custom_domain: Optional[str] = None
    ttl: Optional[int] = None

    def delete_uri_path(self) -> Optional[str]:
        return "/cdn/endpoints"


@dataclass(eq=False)
class DigitalOceanCertificate(DigitalOceanResource, BaseCertificate):
    """DigitalOcean certificate"""

    kind = "digitalocean_certificate"

    certificate_state: Optional[str] = None
    certificate_type: Optional[str] = None

    def delete_uri_path(self) -> Optional[str]:
        return "/certificates"


@dataclass(eq=False)
class DigitalOceanContainerRegistry(DigitalOceanResource, BaseResource):
    """DigitalOcean container registry"""

    kind = "digitalocean_container_registry"
    storage_usage_bytes: Optional[int] = None
    is_read_only: Optional[bool] = None

    def delete(self, graph: Graph) -> bool:
        """Delete the container registry from the cloud"""

        log.debug(
            f"Deleting registry {self.id} in account {self.account(graph).id} region {self.region(graph).id}"
        )
        team = self.account(graph)
        credentials = get_team_credentials(team.id)
        client = StreamingWrapper(
            credentials.api_token,
            credentials.spaces_access_key,
            credentials.spaces_secret_key,
        )
        return client.delete("/registry", None)


@dataclass(eq=False)
class DigitalOceanContainerRegistryRepository(DigitalOceanResource, BaseResource):
    """DigitalOcean container registry repository"""

    kind = "digitalocean_container_registry_repository"

    tag_count: Optional[int] = None
    manifest_count: Optional[int] = None


@dataclass(eq=False)
class DigitalOceanContainerRegistryRepositoryTag(DigitalOceanResource, BaseResource):
    """DigitalOcean container registry repository tag"""

    kind = "digitalocean_container_registry_repository_tag"
    registry_name: Optional[str] = None
    repository_name: Optional[str] = None
    manifest_digest: Optional[str] = None
    compressed_size_bytes: Optional[int] = None
    size_bytes: Optional[int] = None

    def delete_uri_path(self) -> Optional[str]:
        return (
            f"/registry/{self.registry_name}/repositories/{self.repository_name}/tags"
        )


@dataclass(eq=False)
class DigitalOceanSSHKey(DigitalOceanResource, BaseKeyPair):
    """DigitalOcean ssh key"""

    kind = "digitalocean_ssh_key"

    public_key: Optional[str] = None

    def delete_uri_path(self) -> Optional[str]:
        return "/account/keys"


@dataclass(eq=False)
class DigitalOceanTag(DigitalOceanResource, BaseResource):
    """DigitalOcean tag"""

    kind = "digitalocean_tag"

    def delete_uri_path(self) -> Optional[str]:
        return "/tags"


@dataclass(eq=False)
class DigitalOceanDomain(DigitalOceanResource, BaseDomain):
    """DigitalOcean domain"""

    kind = "digitalocean_domain"

    def delete_uri_path(self) -> Optional[str]:
        return "/domains"


@dataclass(eq=False)
class DigitalOceanDomainRecord(DigitalOceanResource, BaseDomainRecord):
    """DigitalOcean domain record"""

    kind = "digitalocean_domain_record"
    domain_name: Optional[str] = None

    def delete_uri_path(self) -> Optional[str]:
        return f"/domains/{self.domain_name}/records"


@dataclass(eq=False)
class DigitalOceanFirewall(DigitalOceanResource, BaseResource):
    """DigitalOcean firewall"""

    kind = "digitalocean_firewall"
    firewall_status: Optional[str] = None

    def delete_uri_path(self) -> Optional[str]:
        return "/firewalls"


@dataclass(eq=False)
class DigitalOceanAlertPolicy(DigitalOceanResource, BaseResource):
    """DigitalOcean alert policy"""

    kind = "digitalocean_alert_policy"

    policy_type: Optional[str] = None
    description: Optional[str] = None
    is_enabled: Optional[bool] = None

    def delete_uri_path(self) -> Optional[str]:
        return "/monitoring/alerts"
