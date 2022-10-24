import logging
from attrs import define
from typing import ClassVar, Dict, List, Optional

from resoto_plugin_digitalocean.client import StreamingWrapper
from resoto_plugin_digitalocean.client import get_team_credentials
from resotolib.baseresources import (
    BaseAccount,
    BaseDatabase,
    BaseInstance,
    BaseIPAddress,
    BaseInstanceType,
    BaseLoadBalancer,
    BaseNetwork,
    BaseRegion,
    BaseResource,
    BaseSnapshot,
    BaseVolume,
    VolumeStatus,
    BaseBucket,
    BaseEndpoint,
    BaseCertificate,
    BaseKeyPair,
    BaseDNSZone,
    BaseDNSRecord,
    ModelReference,
)
from resotolib.graph import Graph
import time

log = logging.getLogger("resoto." + __name__)


@define(eq=False, slots=False)
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
        """Resource name in case tagging is supported by digitalocean.
        Not all resources support tagging.
        """
        return None

    def delete(self, graph: Graph) -> bool:
        """Delete a resource in the cloud"""
        delete_uri_path = self.delete_uri_path()
        if delete_uri_path:
            log.debug(f"Deleting resource {self.id} in account {self.account(graph).id} region {self.region(graph).id}")
            team = self.account(graph)
            ten_minutes_bucket = int(time.time()) // 600
            credentials = get_team_credentials(team.id, ten_minutes_bucket)
            if credentials is None:
                raise RuntimeError(f"Cannot delete resource {self.id}, credentials not found for team {team.id}")
            client = StreamingWrapper(
                credentials.api_token,
                credentials.spaces_access_key,
                credentials.spaces_secret_key,
            )
            return client.delete(delete_uri_path, self.id)

        raise NotImplementedError


@define(eq=False, slots=False)
class DigitalOceanTeam(DigitalOceanResource, BaseAccount):
    """DigitalOcean Team"""

    kind: ClassVar[str] = "digitalocean_team"
    reference_kinds: ClassVar[ModelReference] = {
        "successors": {
            "default": [
                "digitalocean_alert_policy",
                "digitalocean_app",
                "digitalocean_cdn_endpoint",
                "digitalocean_certificate",
                "digitalocean_container_registry",
                "digitalocean_container_registry_repository",
                "digitalocean_container_registry_repository_tag",
                "digitalocean_database",
                "digitalocean_domain",
                "digitalocean_domain_record",
                "digitalocean_droplet",
                "digitalocean_firewall",
                "digitalocean_floating_ip",
                "digitalocean_image",
                "digitalocean_kubernetes_cluster",
                "digitalocean_load_balancer",
                "digitalocean_vpc",
                "digitalocean_project",
                "digitalocean_region",
                "digitalocean_resource",
                "digitalocean_snapshot",
                "digitalocean_space",
                "digitalocean_ssh_key",
                "digitalocean_tag",
                "digitalocean_volume",
            ],
            "delete": [],
        }
    }


@define(eq=False, slots=False)
class DigitalOceanRegion(DigitalOceanResource, BaseRegion):
    """DigitalOcean region"""

    kind: ClassVar[str] = "digitalocean_region"
    reference_kinds: ClassVar[ModelReference] = {
        "successors": {
            "default": [
                "digitalocean_app",
                "digitalocean_container_registry",
                "digitalocean_database",
                "digitalocean_droplet",
                "digitalocean_floating_ip",
                "digitalocean_image",
                "digitalocean_kubernetes_cluster",
                "digitalocean_load_balancer",
                "digitalocean_vpc",
                "digitalocean_snapshot",
                "digitalocean_space",
            ],
            "delete": [],
        }
    }

    do_region_slug: Optional[str] = None
    do_region_features: Optional[List[str]] = None
    is_available: Optional[bool] = None
    do_region_droplet_sizes: Optional[List[str]] = None


@define(eq=False, slots=False)
class DigitalOceanProject(DigitalOceanResource, BaseResource):
    """DigitalOcean project"""

    kind: ClassVar[str] = "digitalocean_project"
    reference_kinds: ClassVar[ModelReference] = {
        "successors": {
            "default": [
                "digitalocean_database",
                "digitalocean_domain",
                "digitalocean_droplet",
                "digitalocean_floating_ip",
                "digitalocean_kubernetes_cluster",
                "digitalocean_load_balancer",
                "digitalocean_space",
                "digitalocean_volume",
            ],
            "delete": [
                "digitalocean_database",
                "digitalocean_domain",
                "digitalocean_droplet",
                "digitalocean_floating_ip",
                "digitalocean_kubernetes_cluster",
                "digitalocean_load_balancer",
                "digitalocean_space",
                "digitalocean_volume",
            ],
        }
    }

    owner_uuid: Optional[str] = None
    owner_id: Optional[str] = None
    description: Optional[str] = None
    purpose: Optional[str] = None
    environment: Optional[str] = None
    is_default: Optional[bool] = None

    def delete_uri_path(self) -> Optional[str]:
        return "/projects"


@define(eq=False, slots=False)
class DigitalOceanDropletSize(DigitalOceanResource, BaseInstanceType):
    kind: ClassVar[str] = "digitalocean_droplet_size"
    reference_kinds: ClassVar[ModelReference] = {
        "successors": {
            "default": [
                "digitalocean_droplet",
            ]
        }
    }


@define(eq=False, slots=False)
class DigitalOceanDroplet(DigitalOceanResource, BaseInstance):
    """A DigitalOcean Droplet Resource

    Droplet have a class variable `instance_status_map` which contains
    a mapping from the droplet status string the cloud API returns
    to our internal InstanceStatus state.
    """

    kind: ClassVar[str] = "digitalocean_droplet"
    reference_kinds: ClassVar[ModelReference] = {
        "successors": {
            "default": [
                "digitalocean_floating_ip",
                "digitalocean_snapshot",
                "digitalocean_volume",
            ],
            "delete": [],
        }
    }

    droplet_backup_ids: Optional[List[str]] = None
    is_locked: Optional[bool] = None
    droplet_features: Optional[List[str]] = None
    droplet_image: Optional[str] = None

    def delete_uri_path(self) -> Optional[str]:
        return "/droplets"

    def tag_resource_name(self) -> Optional[str]:
        return "droplet"


@define(eq=False, slots=False)
class DigitalOceanKubernetesCluster(DigitalOceanResource, BaseResource):
    """DigitalOcean Kubernetes Cluster"""

    kind: ClassVar[str] = "digitalocean_kubernetes_cluster"
    reference_kinds: ClassVar[ModelReference] = {
        "successors": {
            "default": ["digitalocean_droplet"],
            "delete": [],
        }
    }

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


@define(eq=False, slots=False)
class DigitalOceanVolume(DigitalOceanResource, BaseVolume):
    kind: ClassVar[str] = "digitalocean_volume"
    reference_kinds: ClassVar[ModelReference] = {
        "successors": {
            "default": ["digitalocean_snapshot"],
            "delete": ["digitalocean_droplet"],
        }
    }

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
    ondemand_cost: Optional[float] = None

    def delete_uri_path(self) -> Optional[str]:
        return "/volumes"

    def tag_resource_name(self) -> Optional[str]:
        return "volume"


@define(eq=False, slots=False)
class DigitalOceanDatabase(DigitalOceanResource, BaseDatabase):
    kind: ClassVar[str] = "digitalocean_database"
    reference_kinds: ClassVar[ModelReference] = {
        "successors": {
            "default": ["digitalocean_app"],
            "delete": [],
        }
    }

    def delete_uri_path(self) -> Optional[str]:
        return "/databases"

    def tag_resource_name(self) -> Optional[str]:
        return "database"


@define(eq=False, slots=False)
class DigitalOceanVPC(DigitalOceanResource, BaseNetwork):
    """DigitalOcean network

    This is what instances and other networking related resources might reside in.
    """

    kind: ClassVar[str] = "digitalocean_vpc"
    reference_kinds: ClassVar[ModelReference] = {
        "successors": {
            "default": [
                "digitalocean_load_balancer",
                "digitalocean_kubernetes_cluster",
                "digitalocean_droplet",
                "digitalocean_database",
            ],
            "delete": [
                "digitalocean_database",
                "digitalocean_droplet",
                "digitalocean_kubernetes_cluster",
            ],
        }
    }

    ip_range: Optional[str] = None
    description: Optional[str] = None
    is_default: Optional[bool] = None

    def delete_uri_path(self) -> Optional[str]:
        return "/vpcs"


@define(eq=False, slots=False)
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


@define(eq=False, slots=False)
class DigitalOceanLoadBalancer(DigitalOceanResource, BaseLoadBalancer):
    """DigitalOcean load balancer"""

    kind: ClassVar[str] = "digitalocean_load_balancer"
    reference_kinds: ClassVar[ModelReference] = {
        "successors": {
            "default": ["digitalocean_droplet"],
            "delete": [],
        }
    }

    nr_nodes: Optional[int] = None
    loadbalancer_status: Optional[str] = None
    redirect_http_to_https: Optional[bool] = None
    enable_proxy_protocol: Optional[bool] = None
    enable_backend_keepalive: Optional[bool] = None
    disable_lets_encrypt_dns_records: Optional[bool] = None

    def delete_uri_path(self) -> Optional[str]:
        return "/load_balancers"


@define(eq=False, slots=False)
class DigitalOceanFloatingIP(DigitalOceanResource, BaseIPAddress):
    """DigitalOcean floating IP"""

    kind: ClassVar[str] = "digitalocean_floating_ip"

    is_locked: Optional[bool] = None

    def delete(self, graph: Graph) -> bool:
        log.debug(f"Deleting resource {self.id} in account {self.account(graph).id} region {self.region(graph).id}")
        team = self.account(graph)
        ten_minutes_bucket = int(time.time()) // 600
        credentials = get_team_credentials(team.id, ten_minutes_bucket)
        if credentials is None:
            raise RuntimeError(f"Cannot delete resource {self.id}, credentials not found for team {team.id}")
        client = StreamingWrapper(
            credentials.api_token,
            credentials.spaces_access_key,
            credentials.spaces_secret_key,
        )
        # un-assign the ip just in case it's still assigned to a droplet
        client.unassign_floating_ip(self.id)
        return client.delete("/floating_ips", self.id)


@define(eq=False, slots=False)
class DigitalOceanImage(DigitalOceanResource, BaseResource):
    """DigitalOcean image"""

    kind: ClassVar[str] = "digitalocean_image"
    reference_kinds: ClassVar[ModelReference] = {
        "successors": {
            "default": ["digitalocean_droplet"],
            "delete": [],
        }
    }

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


@define(eq=False, slots=False)
class DigitalOceanSpace(DigitalOceanResource, BaseBucket):
    """DigitalOcean space"""

    kind: ClassVar[str] = "digitalocean_space"

    def delete(self, graph: Graph) -> bool:
        log.debug(f"Deleting space {self.id} in account {self.account(graph).id} region {self.region(graph).id}")
        team = self.account(graph)
        ten_minutes_bucket = int(time.time()) // 600
        credentials = get_team_credentials(team.id, ten_minutes_bucket)
        if credentials is None:
            raise RuntimeError(f"Cannot delete resource {self.id}, credentials not found for team {team.id}")
        client = StreamingWrapper(
            credentials.api_token,
            credentials.spaces_access_key,
            credentials.spaces_secret_key,
        )
        return client.delete_space(self.region(graph).id, self.id)


@define(eq=False, slots=False)
class DigitalOceanApp(DigitalOceanResource, BaseResource):
    """DigitalOcean app"""

    kind: ClassVar[str] = "digitalocean_app"

    tier_slug: Optional[str] = None
    default_ingress: Optional[str] = None
    live_url: Optional[str] = None
    live_url_base: Optional[str] = None
    live_domain: Optional[str] = None

    def delete_uri_path(self) -> Optional[str]:
        return "/apps"


@define(eq=False, slots=False)
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


@define(eq=False, slots=False)
class DigitalOceanCertificate(DigitalOceanResource, BaseCertificate):
    """DigitalOcean certificate"""

    kind = "digitalocean_certificate"

    certificate_state: Optional[str] = None
    certificate_type: Optional[str] = None

    def delete_uri_path(self) -> Optional[str]:
        return "/certificates"


@define(eq=False, slots=False)
class DigitalOceanContainerRegistry(DigitalOceanResource, BaseResource):
    """DigitalOcean container registry"""

    kind = "digitalocean_container_registry"
    reference_kinds: ClassVar[ModelReference] = {
        "successors": {
            "default": ["digitalocean_container_registry_repository"],
            "delete": [],
        }
    }

    storage_usage_bytes: Optional[int] = None
    is_read_only: Optional[bool] = None

    def delete(self, graph: Graph) -> bool:
        """Delete the container registry from the cloud"""

        log.debug(f"Deleting registry {self.id} in account {self.account(graph).id} region {self.region(graph).id}")
        team = self.account(graph)
        ten_minutes_bucket = int(time.time()) // 600
        credentials = get_team_credentials(team.id, ten_minutes_bucket)
        if credentials is None:
            raise RuntimeError(f"Cannot delete resource {self.id}, credentials not found for team {team.id}")
        client = StreamingWrapper(
            credentials.api_token,
            credentials.spaces_access_key,
            credentials.spaces_secret_key,
        )
        return client.delete("/registry", None)


@define(eq=False, slots=False)
class DigitalOceanContainerRegistryRepository(DigitalOceanResource, BaseResource):
    """DigitalOcean container registry repository"""

    kind = "digitalocean_container_registry_repository"
    reference_kinds: ClassVar[ModelReference] = {
        "successors": {
            "default": ["digitalocean_container_registry_repository_tag"],
            "delete": [],
        }
    }

    tag_count: Optional[int] = None
    manifest_count: Optional[int] = None


@define(eq=False, slots=False)
class DigitalOceanContainerRegistryRepositoryTag(DigitalOceanResource, BaseResource):
    """DigitalOcean container registry repository tag"""

    kind = "digitalocean_container_registry_repository_tag"
    registry_name: Optional[str] = None
    repository_name: Optional[str] = None
    manifest_digest: Optional[str] = None
    compressed_size_bytes: Optional[int] = None
    size_bytes: Optional[int] = None

    def delete_uri_path(self) -> Optional[str]:
        return f"/registry/{self.registry_name}/repositories/{self.repository_name}/tags"


@define(eq=False, slots=False)
class DigitalOceanSSHKey(DigitalOceanResource, BaseKeyPair):
    """DigitalOcean ssh key"""

    kind = "digitalocean_ssh_key"

    public_key: Optional[str] = None

    def delete_uri_path(self) -> Optional[str]:
        return "/account/keys"


@define(eq=False, slots=False)
class DigitalOceanTag(DigitalOceanResource, BaseResource):
    """DigitalOcean tag"""

    kind = "digitalocean_tag"

    def delete_uri_path(self) -> Optional[str]:
        return "/tags"


@define(eq=False, slots=False)
class DigitalOceanDomain(DigitalOceanResource, BaseDNSZone):
    """DigitalOcean domain"""

    kind = "digitalocean_domain"
    reference_kinds: ClassVar[ModelReference] = {
        "successors": {
            "default": ["digitalocean_domain_record"],
            "delete": [],
        }
    }
    ttl: Optional[int] = None
    zone_file: Optional[str] = None

    def delete_uri_path(self) -> Optional[str]:
        return "/domains"


@define(eq=False, slots=False)
class DigitalOceanDomainRecord(DigitalOceanResource, BaseDNSRecord):
    """DigitalOcean domain record"""

    kind = "digitalocean_domain_record"
    domain_name: Optional[str] = None

    def delete_uri_path(self) -> Optional[str]:
        return f"/domains/{self.domain_name}/records"


@define(eq=False, slots=False)
class DigitalOceanFirewall(DigitalOceanResource, BaseResource):
    """DigitalOcean firewall"""

    kind = "digitalocean_firewall"
    reference_kinds: ClassVar[ModelReference] = {
        "successors": {
            "default": ["digitalocean_droplet"],
            "delete": [],
        }
    }

    firewall_status: Optional[str] = None

    def delete_uri_path(self) -> Optional[str]:
        return "/firewalls"


@define(eq=False, slots=False)
class DigitalOceanAlertPolicy(DigitalOceanResource, BaseResource):
    """DigitalOcean alert policy"""

    kind = "digitalocean_alert_policy"

    policy_type: Optional[str] = None
    description: Optional[str] = None
    is_enabled: Optional[bool] = None

    def delete_uri_path(self) -> Optional[str]:
        return "/monitoring/alerts"
