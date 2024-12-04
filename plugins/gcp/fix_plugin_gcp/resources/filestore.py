from datetime import datetime
import logging
from typing import ClassVar, Dict, Optional, List, Type, Any

from attr import define, field

from fix_plugin_gcp.gcp_client import GcpApiSpec
from fix_plugin_gcp.resources.base import GraphBuilder, GcpErrorHandler, GcpResource, GcpDeprecationStatus
from fixlib.baseresources import BaseNetworkShare, ModelReference
from fixlib.json_bender import Bender, S, Bend, ForallBend
from fixlib.types import Json

log = logging.getLogger("fix.plugins.gcp")


service_name = "filestore"


@define(eq=False, slots=False)
class GcpFilestoreBackup(GcpResource):
    kind: ClassVar[str] = "gcp_filestore_backup"
    _kind_display: ClassVar[str] = "GCP Filestore Backup"
    _kind_description: ClassVar[str] = (
        "GCP Filestore Backup is a service that allows you to create backups of your Filestore instances."
        " It provides a way to protect your data and restore it in case of data loss."
    )
    _docs_url: ClassVar[str] = "https://cloud.google.com/filestore/docs/backups"
    _kind_service: ClassVar[Optional[str]] = "filestore"
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "backup", "group": "storage"}
    api_spec: ClassVar[GcpApiSpec] = GcpApiSpec(
        service="file",
        version="v1",
        accessors=["projects", "locations", "backups"],
        action="list",
        request_parameter={"parent": "projects/{project}/locations/-"},
        request_parameter_in={"project"},
        response_path="backups",
        response_regional_sub_path=None,
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("name").or_else(S("id")).or_else(S("selfLink")),
        "name": S("name"),
        "ctime": S("creationTimestamp"),
        "description": S("description"),
        "link": S("selfLink"),
        "label_fingerprint": S("labelFingerprint"),
        "deprecation_status": S("deprecated", default={}) >> Bend(GcpDeprecationStatus.mapping),
        "capacity_gb": S("capacityGb"),
        "create_time": S("createTime"),
        "download_bytes": S("downloadBytes"),
        "file_system_protocol": S("fileSystemProtocol"),
        "kms_key": S("kmsKey"),
        "satisfies_pzi": S("satisfiesPzi"),
        "satisfies_pzs": S("satisfiesPzs"),
        "source_file_share": S("sourceFileShare"),
        "source_instance": S("sourceInstance"),
        "source_instance_tier": S("sourceInstanceTier"),
        "state": S("state"),
        "storage_bytes": S("storageBytes"),
        "tags": S("tags", default={}),
    }
    capacity_gb: Optional[str] = field(default=None)
    create_time: Optional[datetime] = field(default=None)
    download_bytes: Optional[str] = field(default=None)
    file_system_protocol: Optional[str] = field(default=None)
    kms_key: Optional[str] = field(default=None)
    satisfies_pzi: Optional[bool] = field(default=None)
    satisfies_pzs: Optional[bool] = field(default=None)
    source_file_share: Optional[str] = field(default=None)
    source_instance: Optional[str] = field(default=None)
    source_instance_tier: Optional[str] = field(default=None)
    state: Optional[str] = field(default=None)
    storage_bytes: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpNfsExportOptions:
    kind: ClassVar[str] = "gcp_nfs_export_options"
    mapping: ClassVar[Dict[str, Bender]] = {
        "access_mode": S("accessMode"),
        "anon_gid": S("anonGid"),
        "anon_uid": S("anonUid"),
        "ip_ranges": S("ipRanges", default=[]),
        "squash_mode": S("squashMode"),
    }
    access_mode: Optional[str] = field(default=None)
    anon_gid: Optional[str] = field(default=None)
    anon_uid: Optional[str] = field(default=None)
    ip_ranges: Optional[List[str]] = field(default=None)
    squash_mode: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpFileShareConfig:
    kind: ClassVar[str] = "gcp_file_share_config"
    mapping: ClassVar[Dict[str, Bender]] = {
        "capacity_gb": S("capacityGb"),
        "name": S("name"),
        "nfs_export_options": S("nfsExportOptions", default=[]) >> ForallBend(GcpNfsExportOptions.mapping),
        "source_backup": S("sourceBackup"),
    }
    capacity_gb: Optional[str] = field(default=None)
    name: Optional[str] = field(default=None)
    nfs_export_options: Optional[List[GcpNfsExportOptions]] = field(default=None)
    source_backup: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpNetworkConfig:
    kind: ClassVar[str] = "gcp_network_config"
    mapping: ClassVar[Dict[str, Bender]] = {
        "connect_mode": S("connectMode"),
        "ip_addresses": S("ipAddresses", default=[]),
        "modes": S("modes", default=[]),
        "network": S("network"),
        "reserved_ip_range": S("reservedIpRange"),
    }
    connect_mode: Optional[str] = field(default=None)
    ip_addresses: Optional[List[str]] = field(default=None)
    modes: Optional[List[str]] = field(default=None)
    network: Optional[str] = field(default=None)
    reserved_ip_range: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpPerformanceConfig:
    kind: ClassVar[str] = "gcp_performance_config"
    mapping: ClassVar[Dict[str, Bender]] = {
        "fixed_iops": S("fixedIops", "maxReadIops"),
        "iops_per_tb": S("iopsPerTb", "maxReadIopsPerTb"),
    }
    fixed_iops: Optional[str] = field(default=None)
    iops_per_tb: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpPerformanceLimits:
    kind: ClassVar[str] = "gcp_performance_limits"
    mapping: ClassVar[Dict[str, Bender]] = {
        "max_read_iops": S("maxReadIops"),
        "max_read_throughput_bps": S("maxReadThroughputBps"),
        "max_write_iops": S("maxWriteIops"),
        "max_write_throughput_bps": S("maxWriteThroughputBps"),
    }
    max_read_iops: Optional[str] = field(default=None)
    max_read_throughput_bps: Optional[str] = field(default=None)
    max_write_iops: Optional[str] = field(default=None)
    max_write_throughput_bps: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpReplicaConfig:
    kind: ClassVar[str] = "gcp_replica_config"
    mapping: ClassVar[Dict[str, Bender]] = {
        "last_active_sync_time": S("lastActiveSyncTime"),
        "peer_instance": S("peerInstance"),
        "state": S("state"),
        "state_reasons": S("stateReasons", default=[]),
    }
    last_active_sync_time: Optional[datetime] = field(default=None)
    peer_instance: Optional[str] = field(default=None)
    state: Optional[str] = field(default=None)
    state_reasons: Optional[List[str]] = field(default=None)


@define(eq=False, slots=False)
class GcpReplication:
    kind: ClassVar[str] = "gcp_replication"
    mapping: ClassVar[Dict[str, Bender]] = {
        "replicas": S("replicas", default=[]) >> ForallBend(GcpReplicaConfig.mapping),
        "role": S("role"),
    }
    replicas: Optional[List[GcpReplicaConfig]] = field(default=None)
    role: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpFilestoreInstance(GcpResource, BaseNetworkShare):
    kind: ClassVar[str] = "gcp_filestore_instance"
    _kind_display: ClassVar[str] = "GCP Filestore Instance"
    _kind_description: ClassVar[str] = (
        "GCP Filestore Instance is a fully managed file storage service that provides scalable and high-performance"
        " file systems for applications running on Google Cloud."
    )
    _docs_url: ClassVar[str] = "https://cloud.google.com/filestore/docs/instances"
    _kind_service: ClassVar[Optional[str]] = "filestore"
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "network_share", "group": "storage"}
    _reference_kinds: ClassVar[ModelReference] = {
        "successors": {
            "default": [
                "gcp_filestore_instance_snapshot",
            ],
        },
    }
    api_spec: ClassVar[GcpApiSpec] = GcpApiSpec(
        service="file",
        version="v1",
        accessors=["projects", "locations", "instances"],
        action="list",
        request_parameter={"parent": "projects/{project}/locations/-"},
        request_parameter_in={"project"},
        response_path="instances",
        response_regional_sub_path=None,
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("name").or_else(S("id")).or_else(S("selfLink")),
        "name": S("name"),
        "ctime": S("creationTimestamp"),
        "description": S("description"),
        "link": S("selfLink"),
        "label_fingerprint": S("labelFingerprint"),
        "deprecation_status": S("deprecated", default={}) >> Bend(GcpDeprecationStatus.mapping),
        "configurable_performance_enabled": S("configurablePerformanceEnabled"),
        "create_time": S("createTime"),
        "deletion_protection_enabled": S("deletionProtectionEnabled"),
        "deletion_protection_reason": S("deletionProtectionReason"),
        "etag": S("etag"),
        "file_shares": S("fileShares", default=[]) >> ForallBend(GcpFileShareConfig.mapping),
        "kms_key_name": S("kmsKeyName"),
        "networks": S("networks", default=[]) >> ForallBend(GcpNetworkConfig.mapping),
        "performance_config": S("performanceConfig", default={}) >> Bend(GcpPerformanceConfig.mapping),
        "performance_limits": S("performanceLimits", default={}) >> Bend(GcpPerformanceLimits.mapping),
        "protocol": S("protocol"),
        "replication": S("replication", default={}) >> Bend(GcpReplication.mapping),
        "satisfies_pzi": S("satisfiesPzi"),
        "satisfies_pzs": S("satisfiesPzs"),
        "state": S("state"),
        "status_message": S("statusMessage"),
        "suspension_reasons": S("suspensionReasons", default=[]),
        "tags": S("tags", default={}),
        "tier": S("tier"),
    }
    configurable_performance_enabled: Optional[bool] = field(default=None)
    create_time: Optional[datetime] = field(default=None)
    deletion_protection_enabled: Optional[bool] = field(default=None)
    deletion_protection_reason: Optional[str] = field(default=None)
    etag: Optional[str] = field(default=None)
    file_shares: Optional[List[GcpFileShareConfig]] = field(default=None)
    kms_key_name: Optional[str] = field(default=None)
    networks: Optional[List[GcpNetworkConfig]] = field(default=None)
    performance_config: Optional[GcpPerformanceConfig] = field(default=None)
    performance_limits: Optional[GcpPerformanceLimits] = field(default=None)
    protocol: Optional[str] = field(default=None)
    replication: Optional[GcpReplication] = field(default=None)
    satisfies_pzi: Optional[bool] = field(default=None)
    satisfies_pzs: Optional[bool] = field(default=None)
    state: Optional[str] = field(default=None)
    status_message: Optional[str] = field(default=None)
    suspension_reasons: Optional[List[str]] = field(default=None)
    tier: Optional[str] = field(default=None)

    @classmethod
    def called_collect_apis(cls) -> List[GcpApiSpec]:
        return [
            cls.api_spec,
            GcpApiSpec(
                service="file",
                version="v1",
                accessors=["projects", "locations", "instances", "snapshots"],
                action="list",
                request_parameter={"parent": "projects/{project}/locations/{location}/instances/{instanceId}"},
                request_parameter_in={"project", "location", "instanceId"},
                response_path="snapshots",
                response_regional_sub_path=None,
            ),
        ]

    def post_process(self, graph_builder: GraphBuilder, source: Json) -> None:
        def collect_snapshots() -> None:
            spec = GcpApiSpec(
                service="file",
                version="v1",
                accessors=["projects", "locations", "instances", "snapshots"],
                action="list",
                request_parameter={"parent": f"{self.id}"},
                request_parameter_in=set(),
                response_path="snapshots",
                response_regional_sub_path=None,
            )
            with GcpErrorHandler(
                spec.action,
                graph_builder.error_accumulator,
                spec.service,
                graph_builder.region.safe_name if graph_builder.region else None,
                set(),
                f" in {graph_builder.project.id} kind {GcpFilestoreInstanceSnapshot.kind}",
            ):
                items = graph_builder.client.list(spec)
                snapshots = GcpFilestoreInstanceSnapshot.collect(items, graph_builder)
                for snapshot in snapshots:
                    graph_builder.add_edge(self, node=snapshot)
                log.info(
                    f"[GCP:{graph_builder.project.id}:{graph_builder.region.safe_name if graph_builder.region else "global"}] finished collecting: {GcpFilestoreInstanceSnapshot.kind}"
                )

        graph_builder.submit_work(collect_snapshots)


@define(eq=False, slots=False)
class GcpFilestoreInstanceSnapshot(GcpResource):
    # collected via GcpFilestoreInstance()
    kind: ClassVar[str] = "gcp_filestore_instance_snapshot"
    _kind_display: ClassVar[str] = "GCP Filestore Snapshot"
    _kind_description: ClassVar[str] = (
        "GCP Filestore Snapshot is a point-in-time copy of a Filestore instance, allowing you to restore"
        " data to a previous state or create new instances from the snapshot."
    )
    _docs_url: ClassVar[str] = "https://cloud.google.com/filestore/docs/snapshots"
    _kind_service: ClassVar[Optional[str]] = "filestore"
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "snapshot", "group": "storage"}
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("name").or_else(S("id")).or_else(S("selfLink")),
        "name": S("name"),
        "ctime": S("creationTimestamp"),
        "description": S("description"),
        "link": S("selfLink"),
        "label_fingerprint": S("labelFingerprint"),
        "deprecation_status": S("deprecated", default={}) >> Bend(GcpDeprecationStatus.mapping),
        "create_time": S("createTime"),
        "filesystem_used_bytes": S("filesystemUsedBytes"),
        "state": S("state"),
        "tags": S("tags", default={}),
    }
    create_time: Optional[datetime] = field(default=None)
    filesystem_used_bytes: Optional[str] = field(default=None)
    state: Optional[str] = field(default=None)


resources: List[Type[GcpResource]] = [GcpFilestoreBackup, GcpFilestoreInstance, GcpFilestoreInstanceSnapshot]
