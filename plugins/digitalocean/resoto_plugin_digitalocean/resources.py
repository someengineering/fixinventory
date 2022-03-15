from dataclasses import dataclass, field
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
)
from resotolib.graph import Graph

log = resotolib.logging.getLogger("resoto." + __name__)


@dataclass(eq=False)
class DigitalOceanResource(BaseResource):
    """A class that implements the abstract method delete() as well as update_tag()
    and delete_tag().

    delete() must be implemented. update_tag() and delete_tag() are optional.
    """

    kind: ClassVar[str] = "digitalocean_resource"

    def delete(self, graph: Graph) -> bool:
        """Delete a resource in the cloud"""
        log.debug(
            f"Deleting resource {self.id} in account {self.account(graph).id} region {self.region(graph).id}"
        )
        return True

    def update_tag(self, key, value) -> bool:
        """Update a resource tag in the cloud"""
        log.debug(f"Updating or setting tag {key}: {value} on resource {self.id}")
        return True

    def delete_tag(self, key) -> bool:
        """Delete a resource tag in the cloud"""
        log.debug(f"Deleting tag {key} on resource {self.id}")
        return True


@dataclass(eq=False)
class DigitalOceanTeam(DigitalOceanResource, BaseAccount):
    """DigitalOcean Team"""

    kind: ClassVar[str] = "digitalocean_team"

    def delete(self, graph: Graph) -> bool:
        return NotImplemented  # DO does not have a team API yet


@dataclass(eq=False)
class DigitalOceanRegion(DigitalOceanResource, BaseRegion):
    """DigitalOcean region"""

    kind: ClassVar[str] = "digitalocean_region"

    do_region_slug: str = field(default="")
    do_region_features: List[str] = field(default_factory=list)
    is_available: bool = field(default=True)
    do_region_sizes: List[str] = field(default_factory=list)

    def delete(self, graph: Graph) -> bool:
        """Regions can usually not be deleted so we return NotImplemented"""
        return NotImplemented


@dataclass(eq=False)
class DigitalOceanProject(DigitalOceanResource, BaseAccount):
    """DigitalOcean project"""

    kind: ClassVar[str] = "digitalocean_project"
    do_project_owner_uuid: str = field(default="")
    do_project_owner_id: str = field(default="")
    do_project_description: str = field(default="")
    do_project_purpose: str = field(default="")
    do_project_environment: str = field(default="")
    is_default: bool = field(default=False)

    def delete(self, graph: Graph) -> bool:
        return NotImplemented


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
    do_droplet_backup_ids: List[str] = field(default_factory=list)
    is_locked: bool = field(default=False)
    do_droplet_features: List[str] = field(default_factory=list)
    do_droplet_image: str = field(default="")

    def _instance_status_setter(self, value: str) -> None:
        """Setter that looks up the instance status

        Based on the string that was give we're doing a dict lookup
        for the corresponding instance status and assign it or
        InstanceStatus.UNKNOWN.
        """
        self._instance_status = self.instance_status_map.get(
            value, InstanceStatus.UNKNOWN
        )


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

    do_k8s_version: str = field(default="")
    do_k8s_cluster_subnet: str = field(default="")
    do_k8s_service_subnet: str = field(default="")
    do_k8s_ipv4: str = field(default="")
    do_k8s_endpoint: str = field(default="")
    do_k8s_auto_upgrade: bool = field(default=False)
    do_k8s_status: str = field(default="")
    do_k8s_surge_upgrade: bool = field(default=False)
    do_k8s_registry_enabled: bool = field(default=False)
    do_k8s_ha: bool = field(default=False)

    def delete(self, graph: Graph) -> bool:
        return NotImplemented


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

    do_volume_description: str = field(default="")
    do_volume_filesystem_type: str = field(default="")
    do_volume_filesystem_label: str = field(default="")

    def _volume_status_setter(self, value: str) -> None:
        self._volume_status = self.volume_status_map.get(value, VolumeStatus.UNKNOWN)


DigitalOceanVolume.volume_status = property(
    DigitalOceanVolume._volume_status_getter, DigitalOceanVolume._volume_status_setter
)


@dataclass(eq=False)
class DigitalOceanDatabase(DigitalOceanResource, BaseDatabase):
    kind: ClassVar[str] = "digitalocean_database"


@dataclass(eq=False)
class DigitalOceanNetwork(DigitalOceanResource, BaseNetwork):
    """DigitalOcean network

    This is what instances and other networking related resources might reside in.
    """

    kind: ClassVar[str] = "digitalocean_network"

    do_vpc_ip_range: str = field(default="")
    do_vpc_description: str = field(default="")
    is_default: bool = field(default=False)


@dataclass(eq=False)
class DigitalOceanSnapshot(DigitalOceanResource, BaseSnapshot):
    """DigitalOcean snapshot"""

    kind: ClassVar[str] = "digitalocean_snapshot"

    do_snapshot_size_gigabytes: float = field(default=0.0)
    do_snapshot_resource_id: str = field(default="")
    do_snapshot_resource_type: str = field(default="")

    def delete(self, graph: Graph) -> bool:
        return NotImplemented


@dataclass(eq=False)
class DigitalOceanLoadBalancer(DigitalOceanResource, BaseLoadBalancer):
    """DigitalOcean load balancer"""

    kind: ClassVar[str] = "digitalocean_load_balancer"

    do_lb_ip: str = field(default="")
    do_lb_size_unit: int = field(default=1)
    do_lb_size: str = field(default="")
    do_lb_status: str = field(default="")
    do_lb_redirect_http_to_https: bool = field(default=False)
    do_lb_enable_proxy_protocol: bool = field(default=False)
    do_lb_enable_backend_keepalive: bool = field(default=False)
    do_lb_disable_lets_encrypt_dns_records: bool = field(default=False)

    def delete(self, graph: Graph) -> bool:
        return NotImplemented


@dataclass(eq=False)
class DigitalOceanFloatingIP(DigitalOceanResource, BaseIPAddress):
    """DigitalOcean floating IP"""

    kind: ClassVar[str] = "digitalocean_floating_ip"

    is_locked: bool = field(default=False)

    def delete(self, graph: Graph) -> bool:
        return NotImplemented


@dataclass(eq=False)
class DigitalOceanImage(DigitalOceanResource, BaseResource):
    """DigitalOcean image"""

    kind: ClassVar[str] = "digitalocean_image"

    do_image_distribution: str = field(default="")
    do_image_slug: str = field(default="")
    do_image_public: bool = field(default=False)
    do_image_min_disk_size: int = field(default=0)
    do_image_type: str = field(default="")
    do_image_size_gigabytes: int = field(default=0)
    do_image_description: str = field(default="")
    do_image_status: str = field(default="")


@dataclass(eq=False)
class DigitalOceanSpace(DigitalOceanResource, BaseBucket):
    """DigitalOcean space"""

    kind: ClassVar[str] = "digitalocean_space"


@dataclass(eq=False)
class DigitalOceanApp(DigitalOceanResource, BaseResource):
    """DigitalOcean app"""

    kind: ClassVar[str] = "digitalocean_app"

    do_app_service_names: List[str] = field(default_factory=list)
    do_app_service_ports: List[int] = field(default_factory=list)
    do_app_tier_slug: str = field(default="")
    do_app_default_ingress: Optional[str] = None
    do_app_live_url: Optional[str] = None
    do_app_live_url_base: Optional[str] = None
    do_app_live_domain: Optional[str] = None


@dataclass(eq=False)
class DigitalOceanCdnEndpoint(DigitalOceanResource, BaseEndpoint):
    """DigitalOcean CDN endpoint"""

    kind = "digitalocean_cdn_endpoint"

    do_cdn_origin: Optional[str] = None
    do_cdn_endpoint: Optional[str] = None
    do_cdn_created_at: Optional[str] = None
    do_cdn_certificate_id: Optional[str] = None
    do_cdn_custom_domain: Optional[str] = None
    do_cdn_ttl: Optional[int] = None


@dataclass(eq=False)
class DigitalOceanCertificate(DigitalOceanResource, BaseCertificate):
    """DigitalOcean certificate"""

    kind = "digitalocean_certificate"

    do_cert_sha1_fingerprint: Optional[str] = None
    do_cert_dns_names: Optional[List[str]] = None
    do_cert_state: Optional[str] = None
    do_cert_type: Optional[str] = None


@dataclass(eq=False)
class DigitalOceanContainerRegistry(DigitalOceanResource, BaseResource):
    """DigitalOcean container registry"""

    kind = "digitalocean_container_registry"

    storage_usage_bytes: Optional[int] = None
    is_read_only: Optional[bool] = None


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

    do_cr_tag: Optional[str] = None
    do_cr_manifest_digest: Optional[str] = None
    do_cr_compressed_size_bytes: Optional[int] = None
    do_cr_size_bytes: Optional[int] = None


@dataclass(eq=False)
class DigitalOceanSSHKey(DigitalOceanResource, BaseKeyPair):
    """DigitalOcean ssh key"""

    kind = "digitalocean_ssh_key"

    do_ssh_public_key: Optional[str] = None


@dataclass(eq=False)
class DigitalOceanTag(DigitalOceanResource, BaseResource):
    """DigitalOcean tag"""

    kind = "digitalocean_tag"


@dataclass(eq=False)
class DigitalOceanDomain(DigitalOceanResource, BaseResource):
    """DigitalOcean domain"""

    kind = "digitalocean_domain"

    ttl: Optional[int] = None
    zone_file: Optional[str] = None


@dataclass(eq=False)
class DigitalOceanDomainRecord(DigitalOceanResource, BaseResource):
    """DigitalOcean domain record"""

    kind = "digitalocean_domain_record"

    do_domain_record_type: Optional[str] = None
    do_domain_record_name: Optional[str] = None
    do_domain_record_data: Optional[str] = None
    do_domain_record_priority: Optional[int] = None
    do_domain_record_port: Optional[int] = None
    do_domain_record_ttl: Optional[int] = None
    do_domain_record_weight: Optional[int] = None
    do_domain_record_flags: Optional[int] = None
    do_domain_record_tag: Optional[str] = None


@dataclass(eq=False)
class DigitalOceanFirewall(DigitalOceanResource, BaseResource):
    """DigitalOcean firewall"""

    kind = "digitalocean_firewall"

    do_firewall_status: Optional[str] = None
