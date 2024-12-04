from datetime import datetime
import logging
from typing import ClassVar, Dict, Optional, List, Any, Type

from attr import define, field

from fix_plugin_gcp.gcp_client import GcpApiSpec
from fix_plugin_gcp.resources.base import GcpErrorHandler, GcpResource, GcpDeprecationStatus, GraphBuilder
from fixlib.baseresources import BaseDatabase, ModelReference
from fixlib.json_bender import Bender, S, Bend, MapDict
from fixlib.types import Json

log = logging.getLogger("fix.plugins.gcp")


# https://cloud.google.com/firestore/docs

service_name = "firestore"


@define(eq=False, slots=False)
class GcpFirestoreCmekConfig:
    kind: ClassVar[str] = "gcp_firestore_cmek_config"
    mapping: ClassVar[Dict[str, Bender]] = {
        "active_key_version": S("activeKeyVersion", default=[]),
        "kms_key_name": S("kmsKeyName"),
    }
    active_key_version: Optional[List[str]] = field(default=None)
    kms_key_name: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpFirestoreSourceInfo:
    kind: ClassVar[str] = "gcp_firestore_source_info"
    mapping: ClassVar[Dict[str, Bender]] = {"backup": S("backup", "backup"), "operation": S("operation")}
    backup: Optional[str] = field(default=None)
    operation: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpFirestoreDatabase(GcpResource, BaseDatabase):
    kind: ClassVar[str] = "gcp_firestore_database"
    _kind_display: ClassVar[str] = "GCP Firestore Database"
    _kind_description: ClassVar[str] = (
        "A Firestore Database in GCP, which is a scalable NoSQL cloud database to store and sync data for client- and server-side development."
    )
    _kind_service: ClassVar[Optional[str]] = service_name
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "database", "group": "storage"}
    _reference_kinds: ClassVar[ModelReference] = {
        "successors": {
            "default": [
                "gcp_firestore_document",
            ],
        },
    }
    api_spec: ClassVar[GcpApiSpec] = GcpApiSpec(
        service="firestore",
        version="v1",
        accessors=["projects", "databases"],
        action="list",
        request_parameter={"parent": "projects/{project}"},
        request_parameter_in={"project"},
        response_path="databases",
        response_regional_sub_path=None,
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("name").or_else(S("id")).or_else(S("selfLink")),
        "tags": S("labels", default={}),
        "name": S("name"),
        "ctime": S("creationTimestamp"),
        "description": S("description"),
        "link": S("selfLink"),
        "label_fingerprint": S("labelFingerprint"),
        "deprecation_status": S("deprecated", default={}) >> Bend(GcpDeprecationStatus.mapping),
        "app_engine_integration_mode": S("appEngineIntegrationMode"),
        "cmek_config": S("cmekConfig", default={}) >> Bend(GcpFirestoreCmekConfig.mapping),
        "concurrency_mode": S("concurrencyMode"),
        "create_time": S("createTime"),
        "delete_protection_state": S("deleteProtectionState"),
        "delete_time": S("deleteTime"),
        "earliest_version_time": S("earliestVersionTime"),
        "etag": S("etag"),
        "key_prefix": S("keyPrefix"),
        "location_id": S("locationId"),
        "point_in_time_recovery_enablement": S("pointInTimeRecoveryEnablement"),
        "previous_id": S("previousId"),
        "source_info": S("sourceInfo", default={}) >> Bend(GcpFirestoreSourceInfo.mapping),
        "type": S("type"),
        "uid": S("uid"),
        "update_time": S("updateTime"),
        "version_retention_period": S("versionRetentionPeriod"),
    }
    app_engine_integration_mode: Optional[str] = field(default=None)
    cmek_config: Optional[GcpFirestoreCmekConfig] = field(default=None)
    concurrency_mode: Optional[str] = field(default=None)
    create_time: Optional[datetime] = field(default=None)
    delete_protection_state: Optional[str] = field(default=None)
    delete_time: Optional[datetime] = field(default=None)
    earliest_version_time: Optional[datetime] = field(default=None)
    etag: Optional[str] = field(default=None)
    key_prefix: Optional[str] = field(default=None)
    location_id: Optional[str] = field(default=None)
    point_in_time_recovery_enablement: Optional[str] = field(default=None)
    previous_id: Optional[str] = field(default=None)
    source_info: Optional[GcpFirestoreSourceInfo] = field(default=None)
    type: Optional[str] = field(default=None)
    uid: Optional[str] = field(default=None)
    update_time: Optional[datetime] = field(default=None)
    version_retention_period: Optional[str] = field(default=None)

    @classmethod
    def called_collect_apis(cls) -> List[GcpApiSpec]:
        return [
            cls.api_spec,
            GcpApiSpec(
                service="firestore",
                version="v1",
                accessors=["projects", "databases", "documents"],
                action="list",
                request_parameter={"parent": "projects/{project}/databases/{databaseId}/documents"},
                request_parameter_in={"project", "databaseId"},
                response_path="documents",
                response_regional_sub_path=None,
            ),
        ]

    def post_process(self, graph_builder: GraphBuilder, source: Json) -> None:
        def collect_documents() -> None:
            spec = GcpApiSpec(
                service="firestore",
                version="v1",
                accessors=["projects", "databases", "documents"],
                action="list",
                request_parameter={"parent": f"{self.id}/documents"},
                request_parameter_in=set(),
                response_path="documents",
                response_regional_sub_path=None,
            )
            with GcpErrorHandler(
                spec.action,
                graph_builder.error_accumulator,
                spec.service,
                graph_builder.region.safe_name if graph_builder.region else None,
                set(),
                f" in {graph_builder.project.id} kind {GcpFirestoreDocument.kind}",
            ):
                items = graph_builder.client.list(spec)
                documents = GcpFirestoreDocument.collect(items, graph_builder)
                for document in documents:
                    graph_builder.add_edge(self, node=document)
                log.info(
                    f"[GCP:{graph_builder.project.id}:{graph_builder.region.safe_name if graph_builder.region else "global"}] finished collecting: {GcpFirestoreDocument.kind}"
                )

        graph_builder.submit_work(collect_documents)


@define(eq=False, slots=False)
class GcpArrayValue:
    kind: ClassVar[str] = "gcp_array_value"
    mapping: ClassVar[Dict[str, Bender]] = {"values": S("values", default=[])}
    values: Optional[List[Any]] = field(default=None)


@define(eq=False, slots=False)
class GcpLatLng:
    kind: ClassVar[str] = "gcp_lat_lng"
    mapping: ClassVar[Dict[str, Bender]] = {"latitude": S("latitude"), "longitude": S("longitude")}
    latitude: Optional[float] = field(default=None)
    longitude: Optional[float] = field(default=None)


@define(eq=False, slots=False)
class GcpMapValue:
    kind: ClassVar[str] = "gcp_map_value"
    mapping: ClassVar[Dict[str, Bender]] = {"fields": S("fields", default={})}
    fields: Optional[Dict[str, Any]] = field(default=None)


@define(eq=False, slots=False)
class GcpValue:
    kind: ClassVar[str] = "gcp_value"
    mapping: ClassVar[Dict[str, Bender]] = {
        "array_value": S("arrayValue", default={}) >> Bend(GcpArrayValue.mapping),
        "boolean_value": S("booleanValue"),
        "bytes_value": S("bytesValue"),
        "double_value": S("doubleValue"),
        "geo_point_value": S("geoPointValue", default={}) >> Bend(GcpLatLng.mapping),
        "integer_value": S("integerValue"),
        "map_value": S("mapValue", default={}) >> Bend(GcpMapValue.mapping),
        "null_value": S("nullValue"),
        "reference_value": S("referenceValue"),
        "string_value": S("stringValue"),
        "timestamp_value": S("timestampValue"),
    }
    array_value: Optional[GcpArrayValue] = field(default=None)
    boolean_value: Optional[bool] = field(default=None)
    bytes_value: Optional[str] = field(default=None)
    double_value: Optional[float] = field(default=None)
    geo_point_value: Optional[GcpLatLng] = field(default=None)
    integer_value: Optional[str] = field(default=None)
    map_value: Optional[GcpMapValue] = field(default=None)
    null_value: Optional[str] = field(default=None)
    reference_value: Optional[str] = field(default=None)
    string_value: Optional[str] = field(default=None)
    timestamp_value: Optional[datetime] = field(default=None)


@define(eq=False, slots=False)
class GcpFirestoreDocument(GcpResource):
    kind: ClassVar[str] = "gcp_firestore_document"
    _kind_display: ClassVar[str] = "GCP Firestore Document"
    _kind_description: ClassVar[str] = (
        "A Firestore Document in GCP, representing a single document in a Firestore database, which can contain fields and subcollections."
    )
    _kind_service: ClassVar[Optional[str]] = service_name
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "database", "group": "storage"}
    # collected via GcpFirestoreDatabase()
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("name").or_else(S("id")).or_else(S("selfLink")),
        "tags": S("labels", default={}),
        "name": S("name"),
        "ctime": S("creationTimestamp"),
        "description": S("description"),
        "link": S("selfLink"),
        "label_fingerprint": S("labelFingerprint"),
        "deprecation_status": S("deprecated", default={}) >> Bend(GcpDeprecationStatus.mapping),
        "create_time": S("createTime"),
        "fields": S("fields", default={}) >> MapDict(value_bender=Bend(GcpValue.mapping)),
        "update_time": S("updateTime"),
    }
    create_time: Optional[datetime] = field(default=None)
    fields: Optional[Dict[str, GcpValue]] = field(default=None)
    update_time: Optional[datetime] = field(default=None)


@define(eq=False, slots=False)
class GcpFirestoreStats:
    kind: ClassVar[str] = "gcp_firestore_stats"
    mapping: ClassVar[Dict[str, Bender]] = {
        "document_count": S("documentCount"),
        "index_count": S("indexCount"),
        "size_bytes": S("sizeBytes"),
    }
    document_count: Optional[str] = field(default=None)
    index_count: Optional[str] = field(default=None)
    size_bytes: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpFirestoreBackup(GcpResource):
    kind: ClassVar[str] = "gcp_firestore_backup"
    _kind_display: ClassVar[str] = "GCP Firestore Backup"
    _kind_description: ClassVar[str] = (
        "A Firestore Backup in GCP, which provides a way to back up and restore Firestore databases to protect against data loss."
    )
    _kind_service: ClassVar[Optional[str]] = service_name
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "backup", "group": "storage"}
    api_spec: ClassVar[GcpApiSpec] = GcpApiSpec(
        service="firestore",
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
        "tags": S("labels", default={}),
        "name": S("name"),
        "ctime": S("creationTimestamp"),
        "description": S("description"),
        "link": S("selfLink"),
        "label_fingerprint": S("labelFingerprint"),
        "deprecation_status": S("deprecated", default={}) >> Bend(GcpDeprecationStatus.mapping),
        "database_name": S("database"),
        "database_uid": S("databaseUid"),
        "expire_time": S("expireTime"),
        "snapshot_time": S("snapshotTime"),
        "state": S("state"),
        "backup_stats": S("stats", default={}) >> Bend(GcpFirestoreStats.mapping),
    }
    database_name: Optional[str] = field(default=None)
    database_uid: Optional[str] = field(default=None)
    expire_time: Optional[datetime] = field(default=None)
    snapshot_time: Optional[datetime] = field(default=None)
    state: Optional[str] = field(default=None)
    backup_stats: Optional[GcpFirestoreStats] = field(default=None)


resources: List[Type[GcpResource]] = [GcpFirestoreDatabase, GcpFirestoreDocument, GcpFirestoreBackup]
