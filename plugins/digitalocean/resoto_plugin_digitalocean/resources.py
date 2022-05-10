from dataclasses import dataclass
from typing import ClassVar, Dict, List, Optional

import resotolib.logger
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
from .utils import dump_tag

log = resotolib.logger.getLogger("resoto." + __name__)


@dataclass(eq=False)
class DigitalOceanResource(BaseResource):  # type: ignore
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
            log.debug(
                f"Deleting resource {self.id} in account {self.account(graph).id} region {self.region(graph).id}"
            )
            team = self.account(graph)
            credentials = get_team_credentials(team.id)
            if credentials is None:
                raise RuntimeError(
                    f"Cannot delete resource {self.id}, credentials not found for team {team.id}"
                )
            client = StreamingWrapper(
                credentials.api_token,
                credentials.spaces_access_key,
                credentials.spaces_secret_key,
            )
            return client.delete(delete_uri_path, self.id)

        raise NotImplementedError

    def update_tag(self, key: str, value: str) -> bool:

        tag_resource_name = self.tag_resource_name()
        if tag_resource_name:

            log.debug(f"Updating tag {key} on resource {self.id}")
            team = self._account
            credentials = get_team_credentials(team.id)
            if credentials is None:
                raise RuntimeError(
                    f"Cannot update tag on resource {self.id}, credentials not found for team {team.id}"
                )
            client = StreamingWrapper(
                credentials.api_token,
                credentials.spaces_access_key,
                credentials.spaces_secret_key,
            )

            if key in self.tags:
                # resotocore knows about the tag. Therefore we need to clean it first
                tag_key = dump_tag(key, self.tags.get(key))
                client.untag_resource(tag_key, tag_resource_name, self.id)

            # we tag the resource using the key-value formatted tag
            tag_kv = dump_tag(key, value)
            tag_ready: bool = True
            tag_count = client.get_tag_count(tag_kv)
            # tag count call failed irrecoverably, we can't continue
            if isinstance(tag_count, str):
                raise RuntimeError(f"Tag update failed. Reason: {tag_count}")
            # tag does not exist, create it
            if tag_count is None:
                tag_ready = client.create_tag(tag_kv)

            return tag_ready and client.tag_resource(tag_kv, tag_resource_name, self.id)
        else:
            raise NotImplementedError(f"resource {self.kind} does not support tagging")

    def delete_tag(self, key: str) -> bool:
        tag_resource_name = self.tag_resource_name()
        if tag_resource_name:
            log.debug(f"Deleting tag {key} on resource {self.id}")
            team = self._account
            credentials = get_team_credentials(team.id)
            if credentials is None:
                raise RuntimeError(
                    f"Cannot update tag on resource {self.id}, credentials not found for team {team.id}"
                )
            client = StreamingWrapper(
                credentials.api_token,
                credentials.spaces_access_key,
                credentials.spaces_secret_key,
            )

            if key not in self.tags:
                # tag does not exist, nothing to do
                return False

            tag_key = dump_tag(key, self.tags.get(key))
            untagged = client.untag_resource(tag_key, tag_resource_name, self.id)
            if not untagged:
                return False
            tag_count = client.get_tag_count(tag_key)
            if tag_count == 0:
                return client.delete("/tags", tag_key)
            return True
        else:
            raise NotImplementedError(f"resource {self.kind} does not support tagging")


@dataclass(eq=False)
class DigitalOceanTeam(DigitalOceanResource, BaseAccount):  # type: ignore
    """DigitalOcean Team"""

    kind: ClassVar[str] = "digitalocean_team"
    successor_kinds: ClassVar[Dict[str, List[str]]] = {
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
            "digitalocean_network",
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


@dataclass(eq=False)
class DigitalOceanRegion(DigitalOceanResource, BaseRegion):  # type: ignore
    """DigitalOcean region"""

    kind: ClassVar[str] = "digitalocean_region"
    successor_kinds: ClassVar[Dict[str, List[str]]] = {
        "default": [
            "digitalocean_app",
            "digitalocean_container_registry",
            "digitalocean_database",
            "digitalocean_droplet",
            "digitalocean_floating_ip",
            "digitalocean_image",
            "digitalocean_kubernetes_cluster",
            "digitalocean_load_balancer",
            "digitalocean_network",
            "digitalocean_snapshot",
            "digitalocean_space",
        ],
        "delete": [],
    }

    do_region_slug: Optional[str] = None
    do_region_features: Optional[List[str]] = None
    is_available: Optional[bool] = None
    do_region_droplet_sizes: Optional[List[str]] = None


@dataclass(eq=False)
class DigitalOceanProject(DigitalOceanResource, BaseResource):  # type: ignore
    """DigitalOcean project"""

    kind: ClassVar[str] = "digitalocean_project"
    successor_kinds: ClassVar[Dict[str, List[str]]] = {
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

    owner_uuid: Optional[str] = None
    owner_id: Optional[str] = None
    description: Optional[str] = None
    purpose: Optional[str] = None
    environment: Optional[str] = None
    is_default: Optional[bool] = None

    def delete_uri_path(self) -> Optional[str]:
        return "/projects"


@dataclass(eq=False)
class DigitalOceanDroplet(DigitalOceanResource, BaseInstance):  # type: ignore
    """A DigitalOcean Droplet Resource

    Droplet have a class variable `instance_status_map` which contains
    a mapping from the droplet status string the cloud API returns
    to our internal InstanceStatus state.
    """

    kind: ClassVar[str] = "digitalocean_droplet"
    successor_kinds: ClassVar[Dict[str, List[str]]] = {
        "default": [
            "digitalocean_floating_ip",
            "digitalocean_snapshot",
            "digitalocean_volume",
        ],
        "delete": [],
    }

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
class DigitalOceanKubernetesCluster(DigitalOceanResource, BaseResource):  # type: ignore
    """DigitalOcean Kubernetes Cluster"""

    kind: ClassVar[str] = "digitalocean_kubernetes_cluster"
    successor_kinds: ClassVar[Dict[str, List[str]]] = {
        "default": ["digitalocean_droplet"],
        "delete": [],
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


@dataclass(eq=False)
class DigitalOceanVolume(DigitalOceanResource, BaseVolume):  # type: ignore
    kind: ClassVar[str] = "digitalocean_volume"
    successor_kinds: ClassVar[Dict[str, List[str]]] = {
        "default": ["digitalocean_snapshot"],
        "delete": ["digitalocean_droplet"],
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
class DigitalOceanDatabase(DigitalOceanResource, BaseDatabase):  # type: ignore
    kind: ClassVar[str] = "digitalocean_database"
    successor_kinds: ClassVar[Dict[str, List[str]]] = {
        "default": ["digitalocean_app"],
        "delete": [],
    }

    def delete_uri_path(self) -> Optional[str]:
        return "/databases"

    def tag_resource_name(self) -> Optional[str]:
        return "database"


@dataclass(eq=False)
class DigitalOceanNetwork(DigitalOceanResource, BaseNetwork):  # type: ignore
    """DigitalOcean network

    This is what instances and other networking related resources might reside in.
    """

    kind: ClassVar[str] = "digitalocean_network"
    successor_kinds: ClassVar[Dict[str, List[str]]] = {
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

    ip_range: Optional[str] = None
    description: Optional[str] = None
    is_default: Optional[bool] = None

    def delete_uri_path(self) -> Optional[str]:
        return "/vpcs"


@dataclass(eq=False)
class DigitalOceanSnapshot(DigitalOceanResource, BaseSnapshot):  # type: ignore
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
class DigitalOceanLoadBalancer(DigitalOceanResource, BaseLoadBalancer):  # type: ignore
    """DigitalOcean load balancer"""

    kind: ClassVar[str] = "digitalocean_load_balancer"
    successor_kinds: ClassVar[Dict[str, List[str]]] = {
        "default": ["digitalocean_droplet"],
        "delete": [],
    }

    nr_nodes: Optional[int] = None
    loadbalancer_status: Optional[str] = None
    redirect_http_to_https: Optional[bool] = None
    enable_proxy_protocol: Optional[bool] = None
    enable_backend_keepalive: Optional[bool] = None
    disable_lets_encrypt_dns_records: Optional[bool] = None

    def delete_uri_path(self) -> Optional[str]:
        return "/load_balancers"


@dataclass(eq=False)
class DigitalOceanFloatingIP(DigitalOceanResource, BaseIPAddress):  # type: ignore
    """DigitalOcean floating IP"""

    kind: ClassVar[str] = "digitalocean_floating_ip"

    is_locked: Optional[bool] = None

    def delete(self, graph: Graph) -> bool:
        log.debug(
            f"Deleting resource {self.id} in account {self.account(graph).id} region {self.region(graph).id}"
        )
        team = self.account(graph)
        credentials = get_team_credentials(team.id)
        if credentials is None:
            raise RuntimeError(
                f"Cannot delete resource {self.id}, credentials not found for team {team.id}"
            )
        client = StreamingWrapper(
            credentials.api_token,
            credentials.spaces_access_key,
            credentials.spaces_secret_key,
        )
        # un-assign the ip just in case it's still assigned to a droplet
        client.unassign_floating_ip(self.id)
        return client.delete("/floating_ips", self.id)


@dataclass(eq=False)
class DigitalOceanImage(DigitalOceanResource, BaseResource):  # type: ignore
    """DigitalOcean image"""

    kind: ClassVar[str] = "digitalocean_image"
    successor_kinds: ClassVar[Dict[str, List[str]]] = {
        "default": ["digitalocean_droplet"],
        "delete": [],
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


@dataclass(eq=False)
class DigitalOceanSpace(DigitalOceanResource, BaseBucket):  # type: ignore
    """DigitalOcean space"""

    kind: ClassVar[str] = "digitalocean_space"

    def delete(self, graph: Graph) -> bool:
        log.debug(
            f"Deleting space {self.id} in account {self.account(graph).id} region {self.region(graph).id}"
        )
        team = self.account(graph)
        credentials = get_team_credentials(team.id)
        if credentials is None:
            raise RuntimeError(
                f"Cannot delete resource {self.id}, credentials not found for team {team.id}"
            )
        client = StreamingWrapper(
            credentials.api_token,
            credentials.spaces_access_key,
            credentials.spaces_secret_key,
        )
        return client.delete_space(self.region(graph).id, self.id)


@dataclass(eq=False)
class DigitalOceanApp(DigitalOceanResource, BaseResource):  # type: ignore
    """DigitalOcean app"""

    kind: ClassVar[str] = "digitalocean_app"

    tier_slug: Optional[str] = None
    default_ingress: Optional[str] = None
    live_url: Optional[str] = None
    live_url_base: Optional[str] = None
    live_domain: Optional[str] = None

    def delete_uri_path(self) -> Optional[str]:
        return "/apps"


@dataclass(eq=False)
class DigitalOceanCdnEndpoint(DigitalOceanResource, BaseEndpoint):  # type: ignore
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
class DigitalOceanCertificate(DigitalOceanResource, BaseCertificate):  # type: ignore
    """DigitalOcean certificate"""

    kind = "digitalocean_certificate"

    certificate_state: Optional[str] = None
    certificate_type: Optional[str] = None

    def delete_uri_path(self) -> Optional[str]:
        return "/certificates"


@dataclass(eq=False)
class DigitalOceanContainerRegistry(DigitalOceanResource, BaseResource):  # type: ignore
    """DigitalOcean container registry"""

    kind = "digitalocean_container_registry"
    successor_kinds: ClassVar[Dict[str, List[str]]] = {
        "default": ["digitalocean_container_registry_repository"],
        "delete": [],
    }

    storage_usage_bytes: Optional[int] = None
    is_read_only: Optional[bool] = None

    def delete(self, graph: Graph) -> bool:
        """Delete the container registry from the cloud"""

        log.debug(
            f"Deleting registry {self.id} in account {self.account(graph).id} region {self.region(graph).id}"
        )
        team = self.account(graph)
        credentials = get_team_credentials(team.id)
        if credentials is None:
            raise RuntimeError(
                f"Cannot delete resource {self.id}, credentials not found for team {team.id}"
            )
        client = StreamingWrapper(
            credentials.api_token,
            credentials.spaces_access_key,
            credentials.spaces_secret_key,
        )
        return client.delete("/registry", None)


@dataclass(eq=False)
class DigitalOceanContainerRegistryRepository(DigitalOceanResource, BaseResource):  # type: ignore
    """DigitalOcean container registry repository"""

    kind = "digitalocean_container_registry_repository"
    successor_kinds: ClassVar[Dict[str, List[str]]] = {
        "default": ["digitalocean_container_registry_repository_tag"],
        "delete": [],
    }

    tag_count: Optional[int] = None
    manifest_count: Optional[int] = None


@dataclass(eq=False)
class DigitalOceanContainerRegistryRepositoryTag(DigitalOceanResource, BaseResource):  # type: ignore
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
class DigitalOceanSSHKey(DigitalOceanResource, BaseKeyPair):  # type: ignore
    """DigitalOcean ssh key"""

    kind = "digitalocean_ssh_key"

    public_key: Optional[str] = None

    def delete_uri_path(self) -> Optional[str]:
        return "/account/keys"


@dataclass(eq=False)
class DigitalOceanTag(DigitalOceanResource, BaseResource):  # type: ignore
    """DigitalOcean tag"""

    kind = "digitalocean_tag"

    def delete_uri_path(self) -> Optional[str]:
        return "/tags"


@dataclass(eq=False)
class DigitalOceanDomain(DigitalOceanResource, BaseDomain):  # type: ignore
    """DigitalOcean domain"""

    kind = "digitalocean_domain"
    successor_kinds: ClassVar[Dict[str, List[str]]] = {
        "default": ["digitalocean_domain_record"],
        "delete": [],
    }

    def delete_uri_path(self) -> Optional[str]:
        return "/domains"


@dataclass(eq=False)
class DigitalOceanDomainRecord(DigitalOceanResource, BaseDomainRecord):  # type: ignore
    """DigitalOcean domain record"""

    kind = "digitalocean_domain_record"
    domain_name: Optional[str] = None

    def delete_uri_path(self) -> Optional[str]:
        return f"/domains/{self.domain_name}/records"


@dataclass(eq=False)
class DigitalOceanFirewall(DigitalOceanResource, BaseResource):  # type: ignore
    """DigitalOcean firewall"""

    kind = "digitalocean_firewall"
    successor_kinds: ClassVar[Dict[str, List[str]]] = {
        "default": ["digitalocean_droplet"],
        "delete": [],
    }

    firewall_status: Optional[str] = None

    def delete_uri_path(self) -> Optional[str]:
        return "/firewalls"


@dataclass(eq=False)
class DigitalOceanAlertPolicy(DigitalOceanResource, BaseResource):  # type: ignore
    """DigitalOcean alert policy"""

    kind = "digitalocean_alert_policy"

    policy_type: Optional[str] = None
    description: Optional[str] = None
    is_enabled: Optional[bool] = None

    def delete_uri_path(self) -> Optional[str]:
        return "/monitoring/alerts"
