from typing import ClassVar, Dict, Optional, List

from attr import define, field

from resoto_plugin_gcp.gcp_client import GcpApiSpec
from resoto_plugin_gcp.resources.base import GcpResource, GcpDeprecationStatus, GraphBuilder
from resoto_plugin_gcp.resources.compute import GcpSslCertificate
from resotolib.baseresources import ModelReference
from resotolib.json_bender import Bender, S, Bend, ForallBend
from resotolib.types import Json


@define(eq=False, slots=False)
class GcpSqlOperationError:
    kind: ClassVar[str] = "gcp_sql_operation_error"
    mapping: ClassVar[Dict[str, Bender]] = {"code": S("code"), "message": S("message")}
    code: Optional[str] = field(default=None)
    message: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpSqlBackupRun(GcpResource):
    kind: ClassVar[str] = "gcp_sql_backup_run"
    reference_kinds: ClassVar[ModelReference] = {"predecessors": {"default": ["gcp_database_instance"]}}
    api_spec: ClassVar[GcpApiSpec] = GcpApiSpec(
        service="sqladmin",
        version="v1",
        accessors=["backupRuns"],
        action="list",
        request_parameter={"instance": "{instance}", "project": "{project}"},
        request_parameter_in={"instance", "project"},
        response_path="items",
        response_regional_sub_path=None,
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id").or_else(S("name")).or_else(S("selfLink")),
        "tags": S("labels", default={}),
        "name": S("name"),
        "ctime": S("creationTimestamp"),
        "description": S("description"),
        "link": S("selfLink"),
        "label_fingerprint": S("labelFingerprint"),
        "deprecation_status": S("deprecated", default={}) >> Bend(GcpDeprecationStatus.mapping),
        "run_backup_kind": S("backupKind"),
        "run_disk_encryption_configuration": S("diskEncryptionConfiguration", "kmsKeyName"),
        "run_disk_encryption_status": S("diskEncryptionStatus", "kmsKeyVersionName"),
        "run_end_time": S("endTime"),
        "run_enqueued_time": S("enqueuedTime"),
        "run_error": S("error", default={}) >> Bend(GcpSqlOperationError.mapping),
        "run_instance": S("instance"),
        "run_location": S("location"),
        "run_start_time": S("startTime"),
        "run_status": S("status"),
        "run_time_zone": S("timeZone"),
        "run_type": S("type"),
        "run_window_start_time": S("windowStartTime"),
    }
    run_backup_kind: Optional[str] = field(default=None)
    run_disk_encryption_configuration: Optional[str] = field(default=None)
    run_disk_encryption_status: Optional[str] = field(default=None)
    run_end_time: Optional[str] = field(default=None)
    run_enqueued_time: Optional[str] = field(default=None)
    run_error: Optional[GcpSqlOperationError] = field(default=None)
    run_instance: Optional[str] = field(default=None)
    run_location: Optional[str] = field(default=None)
    run_start_time: Optional[str] = field(default=None)
    run_status: Optional[str] = field(default=None)
    run_time_zone: Optional[str] = field(default=None)
    run_type: Optional[str] = field(default=None)
    run_window_start_time: Optional[str] = field(default=None)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if self.run_instance:
            builder.add_edge(self, reverse=True, clazz=GcpSqlDatabaseInstance, name=self.run_instance)


@define(eq=False, slots=False)
class GcpSqlSqlServerDatabaseDetails:
    kind: ClassVar[str] = "gcp_sql_sql_server_database_details"
    mapping: ClassVar[Dict[str, Bender]] = {
        "compatibility_level": S("compatibilityLevel"),
        "recovery_model": S("recoveryModel"),
    }
    compatibility_level: Optional[int] = field(default=None)
    recovery_model: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpSqlDatabase(GcpResource):
    kind: ClassVar[str] = "gcp_sql_database"
    api_spec: ClassVar[GcpApiSpec] = GcpApiSpec(
        service="sqladmin",
        version="v1",
        accessors=["databases"],
        action="list",
        request_parameter={"instance": "{instance}", "project": "{project}"},
        request_parameter_in={"instance", "project"},
        response_path="items",
        response_regional_sub_path=None,
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id").or_else(S("name")).or_else(S("selfLink")),
        "tags": S("labels", default={}),
        "name": S("name"),
        "ctime": S("creationTimestamp"),
        "description": S("description"),
        "link": S("selfLink"),
        "label_fingerprint": S("labelFingerprint"),
        "deprecation_status": S("deprecated", default={}) >> Bend(GcpDeprecationStatus.mapping),
        "database_charset": S("charset"),
        "database_collation": S("collation"),
        "database_etag": S("etag"),
        "database_instance": S("instance"),
        "database_project": S("project"),
        "database_sqlserver_database_details": S("sqlserverDatabaseDetails", default={})
        >> Bend(GcpSqlSqlServerDatabaseDetails.mapping),
    }
    database_charset: Optional[str] = field(default=None)
    database_collation: Optional[str] = field(default=None)
    database_etag: Optional[str] = field(default=None)
    database_instance: Optional[str] = field(default=None)
    database_project: Optional[str] = field(default=None)
    database_sqlserver_database_details: Optional[GcpSqlSqlServerDatabaseDetails] = field(default=None)


@define(eq=False, slots=False)
class GcpSqlFlag(GcpResource):
    kind: ClassVar[str] = "gcp_sql_flag"
    api_spec: ClassVar[GcpApiSpec] = GcpApiSpec(
        service="sqladmin",
        version="v1",
        accessors=["flags"],
        action="list",
        request_parameter={},
        request_parameter_in=set(),
        response_path="items",
        response_regional_sub_path=None,
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id").or_else(S("name")).or_else(S("selfLink")),
        "tags": S("labels", default={}),
        "name": S("name"),
        "ctime": S("creationTimestamp"),
        "description": S("description"),
        "link": S("selfLink"),
        "label_fingerprint": S("labelFingerprint"),
        "deprecation_status": S("deprecated", default={}) >> Bend(GcpDeprecationStatus.mapping),
        "flag_allowed_int_values": S("allowedIntValues", default=[]),
        "flag_allowed_string_values": S("allowedStringValues", default=[]),
        "flag_applies_to": S("appliesTo", default=[]),
        "flag_in_beta": S("inBeta"),
        "flag_max_value": S("maxValue"),
        "flag_min_value": S("minValue"),
        "flag_requires_restart": S("requiresRestart"),
        "flag_type": S("type"),
    }
    flag_allowed_int_values: Optional[List[str]] = field(default=None)
    flag_allowed_string_values: Optional[List[str]] = field(default=None)
    flag_applies_to: Optional[List[str]] = field(default=None)
    flag_in_beta: Optional[bool] = field(default=None)
    flag_max_value: Optional[str] = field(default=None)
    flag_min_value: Optional[str] = field(default=None)
    flag_requires_restart: Optional[bool] = field(default=None)
    flag_type: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpSqlFailoverreplica:
    kind: ClassVar[str] = "gcp_sql_failoverreplica"
    mapping: ClassVar[Dict[str, Bender]] = {"available": S("available"), "name": S("name")}
    available: Optional[bool] = field(default=None)
    name: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpSqlIpMapping:
    kind: ClassVar[str] = "gcp_sql_ip_mapping"
    mapping: ClassVar[Dict[str, Bender]] = {
        "ip_address": S("ipAddress"),
        "time_to_retire": S("timeToRetire"),
        "type": S("type"),
    }
    ip_address: Optional[str] = field(default=None)
    time_to_retire: Optional[str] = field(default=None)
    type: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpSqlInstanceReference:
    kind: ClassVar[str] = "gcp_sql_instance_reference"
    mapping: ClassVar[Dict[str, Bender]] = {"name": S("name"), "project": S("project"), "region": S("region")}
    name: Optional[str] = field(default=None)
    project: Optional[str] = field(default=None)
    region: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpSqlOnPremisesConfiguration:
    kind: ClassVar[str] = "gcp_sql_on_premises_configuration"
    mapping: ClassVar[Dict[str, Bender]] = {
        "ca_certificate": S("caCertificate"),
        "client_certificate": S("clientCertificate"),
        "client_key": S("clientKey"),
        "dump_file_path": S("dumpFilePath"),
        "host_port": S("hostPort"),
        "password": S("password"),
        "source_instance": S("sourceInstance", default={}) >> Bend(GcpSqlInstanceReference.mapping),
        "username": S("username"),
    }
    ca_certificate: Optional[str] = field(default=None)
    client_certificate: Optional[str] = field(default=None)
    client_key: Optional[str] = field(default=None)
    dump_file_path: Optional[str] = field(default=None)
    host_port: Optional[str] = field(default=None)
    password: Optional[str] = field(default=None)
    source_instance: Optional[GcpSqlInstanceReference] = field(default=None)
    username: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpSqlSqlOutOfDiskReport:
    kind: ClassVar[str] = "gcp_sql_sql_out_of_disk_report"
    mapping: ClassVar[Dict[str, Bender]] = {
        "sql_min_recommended_increase_size_gb": S("sqlMinRecommendedIncreaseSizeGb"),
        "sql_out_of_disk_state": S("sqlOutOfDiskState"),
    }
    sql_min_recommended_increase_size_gb: Optional[int] = field(default=None)
    sql_out_of_disk_state: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpSqlMySqlReplicaConfiguration:
    kind: ClassVar[str] = "gcp_sql_my_sql_replica_configuration"
    mapping: ClassVar[Dict[str, Bender]] = {
        "ca_certificate": S("caCertificate"),
        "client_certificate": S("clientCertificate"),
        "client_key": S("clientKey"),
        "connect_retry_interval": S("connectRetryInterval"),
        "dump_file_path": S("dumpFilePath"),
        "master_heartbeat_period": S("masterHeartbeatPeriod"),
        "password": S("password"),
        "ssl_cipher": S("sslCipher"),
        "username": S("username"),
        "verify_server_certificate": S("verifyServerCertificate"),
    }
    ca_certificate: Optional[str] = field(default=None)
    client_certificate: Optional[str] = field(default=None)
    client_key: Optional[str] = field(default=None)
    connect_retry_interval: Optional[int] = field(default=None)
    dump_file_path: Optional[str] = field(default=None)
    master_heartbeat_period: Optional[str] = field(default=None)
    password: Optional[str] = field(default=None)
    ssl_cipher: Optional[str] = field(default=None)
    username: Optional[str] = field(default=None)
    verify_server_certificate: Optional[bool] = field(default=None)


@define(eq=False, slots=False)
class GcpSqlReplicaConfiguration:
    kind: ClassVar[str] = "gcp_sql_replica_configuration"
    mapping: ClassVar[Dict[str, Bender]] = {
        "failover_target": S("failoverTarget"),
        "mysql_replica_configuration": S("mysqlReplicaConfiguration", default={})
        >> Bend(GcpSqlMySqlReplicaConfiguration.mapping),
    }
    failover_target: Optional[bool] = field(default=None)
    mysql_replica_configuration: Optional[GcpSqlMySqlReplicaConfiguration] = field(default=None)


@define(eq=False, slots=False)
class GcpSqlSqlScheduledMaintenance:
    kind: ClassVar[str] = "gcp_sql_sql_scheduled_maintenance"
    mapping: ClassVar[Dict[str, Bender]] = {
        "can_defer": S("canDefer"),
        "can_reschedule": S("canReschedule"),
        "schedule_deadline_time": S("scheduleDeadlineTime"),
        "start_time": S("startTime"),
    }
    can_defer: Optional[bool] = field(default=None)
    can_reschedule: Optional[bool] = field(default=None)
    schedule_deadline_time: Optional[str] = field(default=None)
    start_time: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpSqlSslCert:
    kind: ClassVar[str] = "gcp_sql_ssl_cert"
    mapping: ClassVar[Dict[str, Bender]] = {
        "cert": S("cert"),
        "cert_serial_number": S("certSerialNumber"),
        "common_name": S("commonName"),
        "create_time": S("createTime"),
        "expiration_time": S("expirationTime"),
        "instance": S("instance"),
        "self_link": S("selfLink"),
        "sha1_fingerprint": S("sha1Fingerprint"),
    }
    cert: Optional[str] = field(default=None)
    cert_serial_number: Optional[str] = field(default=None)
    common_name: Optional[str] = field(default=None)
    create_time: Optional[str] = field(default=None)
    expiration_time: Optional[str] = field(default=None)
    instance: Optional[str] = field(default=None)
    self_link: Optional[str] = field(default=None)
    sha1_fingerprint: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpSqlBackupRetentionSettings:
    kind: ClassVar[str] = "gcp_sql_backup_retention_settings"
    mapping: ClassVar[Dict[str, Bender]] = {
        "retained_backups": S("retainedBackups"),
        "retention_unit": S("retentionUnit"),
    }
    retained_backups: Optional[int] = field(default=None)
    retention_unit: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpSqlBackupConfiguration:
    kind: ClassVar[str] = "gcp_sql_backup_configuration"
    mapping: ClassVar[Dict[str, Bender]] = {
        "backup_retention_settings": S("backupRetentionSettings", default={})
        >> Bend(GcpSqlBackupRetentionSettings.mapping),
        "binary_log_enabled": S("binaryLogEnabled"),
        "enabled": S("enabled"),
        "location": S("location"),
        "point_in_time_recovery_enabled": S("pointInTimeRecoveryEnabled"),
        "replication_log_archiving_enabled": S("replicationLogArchivingEnabled"),
        "start_time": S("startTime"),
        "transaction_log_retention_days": S("transactionLogRetentionDays"),
    }
    backup_retention_settings: Optional[GcpSqlBackupRetentionSettings] = field(default=None)
    binary_log_enabled: Optional[bool] = field(default=None)
    enabled: Optional[bool] = field(default=None)
    location: Optional[str] = field(default=None)
    point_in_time_recovery_enabled: Optional[bool] = field(default=None)
    replication_log_archiving_enabled: Optional[bool] = field(default=None)
    start_time: Optional[str] = field(default=None)
    transaction_log_retention_days: Optional[int] = field(default=None)


@define(eq=False, slots=False)
class GcpSqlDatabaseFlags:
    kind: ClassVar[str] = "gcp_sql_database_flags"
    mapping: ClassVar[Dict[str, Bender]] = {"name": S("name"), "value": S("value")}
    name: Optional[str] = field(default=None)
    value: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpSqlDenyMaintenancePeriod:
    kind: ClassVar[str] = "gcp_sql_deny_maintenance_period"
    mapping: ClassVar[Dict[str, Bender]] = {"end_date": S("endDate"), "start_date": S("startDate"), "time": S("time")}
    end_date: Optional[str] = field(default=None)
    start_date: Optional[str] = field(default=None)
    time: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpSqlInsightsConfig:
    kind: ClassVar[str] = "gcp_sql_insights_config"
    mapping: ClassVar[Dict[str, Bender]] = {
        "query_insights_enabled": S("queryInsightsEnabled"),
        "query_plans_per_minute": S("queryPlansPerMinute"),
        "query_string_length": S("queryStringLength"),
        "record_application_tags": S("recordApplicationTags"),
        "record_client_address": S("recordClientAddress"),
    }
    query_insights_enabled: Optional[bool] = field(default=None)
    query_plans_per_minute: Optional[int] = field(default=None)
    query_string_length: Optional[int] = field(default=None)
    record_application_tags: Optional[bool] = field(default=None)
    record_client_address: Optional[bool] = field(default=None)


@define(eq=False, slots=False)
class GcpSqlAclEntry:
    kind: ClassVar[str] = "gcp_sql_acl_entry"
    mapping: ClassVar[Dict[str, Bender]] = {
        "expiration_time": S("expirationTime"),
        "name": S("name"),
        "value": S("value"),
    }
    expiration_time: Optional[str] = field(default=None)
    name: Optional[str] = field(default=None)
    value: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpSqlIpConfiguration:
    kind: ClassVar[str] = "gcp_sql_ip_configuration"
    mapping: ClassVar[Dict[str, Bender]] = {
        "allocated_ip_range": S("allocatedIpRange"),
        "authorized_networks": S("authorizedNetworks", default=[]) >> ForallBend(GcpSqlAclEntry.mapping),
        "ipv4_enabled": S("ipv4Enabled"),
        "private_network": S("privateNetwork"),
        "require_ssl": S("requireSsl"),
    }
    allocated_ip_range: Optional[str] = field(default=None)
    authorized_networks: Optional[List[GcpSqlAclEntry]] = field(default=None)
    ipv4_enabled: Optional[bool] = field(default=None)
    private_network: Optional[str] = field(default=None)
    require_ssl: Optional[bool] = field(default=None)


@define(eq=False, slots=False)
class GcpSqlLocationPreference:
    kind: ClassVar[str] = "gcp_sql_location_preference"
    mapping: ClassVar[Dict[str, Bender]] = {
        "follow_gae_application": S("followGaeApplication"),
        "secondary_zone": S("secondaryZone"),
        "zone": S("zone"),
    }
    follow_gae_application: Optional[str] = field(default=None)
    secondary_zone: Optional[str] = field(default=None)
    zone: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpSqlMaintenanceWindow:
    kind: ClassVar[str] = "gcp_sql_maintenance_window"
    mapping: ClassVar[Dict[str, Bender]] = {"day": S("day"), "hour": S("hour"), "update_track": S("updateTrack")}
    day: Optional[int] = field(default=None)
    hour: Optional[int] = field(default=None)
    update_track: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpSqlPasswordValidationPolicy:
    kind: ClassVar[str] = "gcp_sql_password_validation_policy"
    mapping: ClassVar[Dict[str, Bender]] = {
        "complexity": S("complexity"),
        "disallow_username_substring": S("disallowUsernameSubstring"),
        "enable_password_policy": S("enablePasswordPolicy"),
        "min_length": S("minLength"),
        "password_change_interval": S("passwordChangeInterval"),
        "reuse_interval": S("reuseInterval"),
    }
    complexity: Optional[str] = field(default=None)
    disallow_username_substring: Optional[bool] = field(default=None)
    enable_password_policy: Optional[bool] = field(default=None)
    min_length: Optional[int] = field(default=None)
    password_change_interval: Optional[str] = field(default=None)
    reuse_interval: Optional[int] = field(default=None)


@define(eq=False, slots=False)
class GcpSqlSqlServerAuditConfig:
    kind: ClassVar[str] = "gcp_sql_sql_server_audit_config"
    mapping: ClassVar[Dict[str, Bender]] = {
        "bucket": S("bucket"),
        "retention_interval": S("retentionInterval"),
        "upload_interval": S("uploadInterval"),
    }
    bucket: Optional[str] = field(default=None)
    retention_interval: Optional[str] = field(default=None)
    upload_interval: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpSqlSettings:
    kind: ClassVar[str] = "gcp_sql_settings"
    mapping: ClassVar[Dict[str, Bender]] = {
        "activation_policy": S("activationPolicy"),
        "active_directory_config": S("activeDirectoryConfig", "domain"),
        "authorized_gae_applications": S("authorizedGaeApplications", default=[]),
        "availability_type": S("availabilityType"),
        "backup_configuration": S("backupConfiguration", default={}) >> Bend(GcpSqlBackupConfiguration.mapping),
        "collation": S("collation"),
        "connector_enforcement": S("connectorEnforcement"),
        "crash_safe_replication_enabled": S("crashSafeReplicationEnabled"),
        "data_disk_size_gb": S("dataDiskSizeGb"),
        "data_disk_type": S("dataDiskType"),
        "database_flags": S("databaseFlags", default=[]) >> ForallBend(GcpSqlDatabaseFlags.mapping),
        "database_replication_enabled": S("databaseReplicationEnabled"),
        "deletion_protection_enabled": S("deletionProtectionEnabled"),
        "deny_maintenance_periods": S("denyMaintenancePeriods", default=[])
        >> ForallBend(GcpSqlDenyMaintenancePeriod.mapping),
        "insights_config": S("insightsConfig", default={}) >> Bend(GcpSqlInsightsConfig.mapping),
        "ip_configuration": S("ipConfiguration", default={}) >> Bend(GcpSqlIpConfiguration.mapping),
        "location_preference": S("locationPreference", default={}) >> Bend(GcpSqlLocationPreference.mapping),
        "maintenance_window": S("maintenanceWindow", default={}) >> Bend(GcpSqlMaintenanceWindow.mapping),
        "password_validation_policy": S("passwordValidationPolicy", default={})
        >> Bend(GcpSqlPasswordValidationPolicy.mapping),
        "pricing_plan": S("pricingPlan"),
        "replication_type": S("replicationType"),
        "settings_version": S("settingsVersion"),
        "sql_server_audit_config": S("sqlServerAuditConfig", default={}) >> Bend(GcpSqlSqlServerAuditConfig.mapping),
        "storage_auto_resize": S("storageAutoResize"),
        "storage_auto_resize_limit": S("storageAutoResizeLimit"),
        "tier": S("tier"),
        "time_zone": S("timeZone"),
        "user_labels": S("userLabels"),
    }
    activation_policy: Optional[str] = field(default=None)
    active_directory_config: Optional[str] = field(default=None)
    authorized_gae_applications: Optional[List[str]] = field(default=None)
    availability_type: Optional[str] = field(default=None)
    backup_configuration: Optional[GcpSqlBackupConfiguration] = field(default=None)
    collation: Optional[str] = field(default=None)
    connector_enforcement: Optional[str] = field(default=None)
    crash_safe_replication_enabled: Optional[bool] = field(default=None)
    data_disk_size_gb: Optional[str] = field(default=None)
    data_disk_type: Optional[str] = field(default=None)
    database_flags: Optional[List[GcpSqlDatabaseFlags]] = field(default=None)
    database_replication_enabled: Optional[bool] = field(default=None)
    deletion_protection_enabled: Optional[bool] = field(default=None)
    deny_maintenance_periods: Optional[List[GcpSqlDenyMaintenancePeriod]] = field(default=None)
    insights_config: Optional[GcpSqlInsightsConfig] = field(default=None)
    ip_configuration: Optional[GcpSqlIpConfiguration] = field(default=None)
    location_preference: Optional[GcpSqlLocationPreference] = field(default=None)
    maintenance_window: Optional[GcpSqlMaintenanceWindow] = field(default=None)
    password_validation_policy: Optional[GcpSqlPasswordValidationPolicy] = field(default=None)
    pricing_plan: Optional[str] = field(default=None)
    replication_type: Optional[str] = field(default=None)
    settings_version: Optional[str] = field(default=None)
    sql_server_audit_config: Optional[GcpSqlSqlServerAuditConfig] = field(default=None)
    storage_auto_resize: Optional[bool] = field(default=None)
    storage_auto_resize_limit: Optional[str] = field(default=None)
    tier: Optional[str] = field(default=None)
    time_zone: Optional[str] = field(default=None)
    user_labels: Optional[Dict[str, str]] = field(default=None)


@define(eq=False, slots=False)
class GcpSqlDatabaseInstance(GcpResource):
    kind: ClassVar[str] = "gcp_sql_database_instance"
    reference_kinds: ClassVar[ModelReference] = {"predecessors": {"default": ["gcp_ssl_certificate"]}}
    api_spec: ClassVar[GcpApiSpec] = GcpApiSpec(
        service="sqladmin",
        version="v1",
        accessors=["instances"],
        action="list",
        request_parameter={"project": "{project}"},
        request_parameter_in={"project"},
        response_path="items",
        response_regional_sub_path=None,
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id").or_else(S("name")).or_else(S("selfLink")),
        "tags": S("labels", default={}),
        "name": S("name"),
        "ctime": S("creationTimestamp"),
        "description": S("description"),
        "link": S("selfLink"),
        "label_fingerprint": S("labelFingerprint"),
        "deprecation_status": S("deprecated", default={}) >> Bend(GcpDeprecationStatus.mapping),
        "instance_available_maintenance_versions": S("availableMaintenanceVersions", default=[]),
        "instance_backend_type": S("backendType"),
        "instance_connection_name": S("connectionName"),
        "instance_create_time": S("createTime"),
        "instance_current_disk_size": S("currentDiskSize"),
        "instance_database_installed_version": S("databaseInstalledVersion"),
        "instance_database_version": S("databaseVersion"),
        "instance_disk_encryption_configuration": S("diskEncryptionConfiguration", "kmsKeyName"),
        "instance_disk_encryption_status": S("diskEncryptionStatus", "kmsKeyVersionName"),
        "instance_etag": S("etag"),
        "instance_failover_replica": S("failoverReplica", default={}) >> Bend(GcpSqlFailoverreplica.mapping),
        "instance_gce_zone": S("gceZone"),
        "instance_instance_type": S("instanceType"),
        "instance_ip_addresses": S("ipAddresses", default=[]) >> ForallBend(GcpSqlIpMapping.mapping),
        "instance_ipv6_address": S("ipv6Address"),
        "instance_maintenance_version": S("maintenanceVersion"),
        "instance_master_instance_name": S("masterInstanceName"),
        "instance_max_disk_size": S("maxDiskSize"),
        "instance_on_premises_configuration": S("onPremisesConfiguration", default={})
        >> Bend(GcpSqlOnPremisesConfiguration.mapping),
        "instance_out_of_disk_report": S("outOfDiskReport", default={}) >> Bend(GcpSqlSqlOutOfDiskReport.mapping),
        "instance_project": S("project"),
        "instance_replica_configuration": S("replicaConfiguration", default={})
        >> Bend(GcpSqlReplicaConfiguration.mapping),
        "instance_replica_names": S("replicaNames", default=[]),
        "instance_satisfies_pzs": S("satisfiesPzs"),
        "instance_scheduled_maintenance": S("scheduledMaintenance", default={})
        >> Bend(GcpSqlSqlScheduledMaintenance.mapping),
        "instance_secondary_gce_zone": S("secondaryGceZone"),
        "instance_server_ca_cert": S("serverCaCert", default={}) >> Bend(GcpSqlSslCert.mapping),
        "instance_service_account_email_address": S("serviceAccountEmailAddress"),
        "instance_settings": S("settings", default={}) >> Bend(GcpSqlSettings.mapping),
        "instance_state": S("state"),
        "instance_suspension_reason": S("suspensionReason", default=[]),
    }
    instance_available_maintenance_versions: Optional[List[str]] = field(default=None)
    instance_backend_type: Optional[str] = field(default=None)
    instance_connection_name: Optional[str] = field(default=None)
    instance_create_time: Optional[str] = field(default=None)
    instance_current_disk_size: Optional[str] = field(default=None)
    instance_database_installed_version: Optional[str] = field(default=None)
    instance_database_version: Optional[str] = field(default=None)
    instance_disk_encryption_configuration: Optional[str] = field(default=None)
    instance_disk_encryption_status: Optional[str] = field(default=None)
    instance_etag: Optional[str] = field(default=None)
    instance_failover_replica: Optional[GcpSqlFailoverreplica] = field(default=None)
    instance_gce_zone: Optional[str] = field(default=None)
    instance_instance_type: Optional[str] = field(default=None)
    instance_ip_addresses: Optional[List[GcpSqlIpMapping]] = field(default=None)
    instance_ipv6_address: Optional[str] = field(default=None)
    instance_maintenance_version: Optional[str] = field(default=None)
    instance_master_instance_name: Optional[str] = field(default=None)
    instance_max_disk_size: Optional[str] = field(default=None)
    instance_on_premises_configuration: Optional[GcpSqlOnPremisesConfiguration] = field(default=None)
    instance_out_of_disk_report: Optional[GcpSqlSqlOutOfDiskReport] = field(default=None)
    instance_project: Optional[str] = field(default=None)
    instance_replica_configuration: Optional[GcpSqlReplicaConfiguration] = field(default=None)
    instance_replica_names: Optional[List[str]] = field(default=None)
    instance_root_password: Optional[str] = field(default=None)
    instance_satisfies_pzs: Optional[bool] = field(default=None)
    instance_scheduled_maintenance: Optional[GcpSqlSqlScheduledMaintenance] = field(default=None)
    instance_secondary_gce_zone: Optional[str] = field(default=None)
    instance_server_ca_cert: Optional[GcpSqlSslCert] = field(default=None)
    instance_service_account_email_address: Optional[str] = field(default=None)
    instance_settings: Optional[GcpSqlSettings] = field(default=None)
    instance_state: Optional[str] = field(default=None)
    instance_suspension_reason: Optional[List[str]] = field(default=None)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if cert := self.instance_server_ca_cert:
            if cert.self_link:
                builder.add_edge(self, reverse=True, clazz=GcpSslCertificate, link=cert.self_link)


@define(eq=False, slots=False)
class GcpSqlOperationErrors:
    kind: ClassVar[str] = "gcp_sql_operation_errors"
    mapping: ClassVar[Dict[str, Bender]] = {
        "errors": S("errors", default=[]) >> ForallBend(GcpSqlOperationError.mapping)
    }
    errors: Optional[List[GcpSqlOperationError]] = field(default=None)


@define(eq=False, slots=False)
class GcpSqlCsvexportoptions:
    kind: ClassVar[str] = "gcp_sql_csvexportoptions"
    mapping: ClassVar[Dict[str, Bender]] = {
        "escape_character": S("escapeCharacter"),
        "fields_terminated_by": S("fieldsTerminatedBy"),
        "lines_terminated_by": S("linesTerminatedBy"),
        "quote_character": S("quoteCharacter"),
        "select_query": S("selectQuery"),
    }
    escape_character: Optional[str] = field(default=None)
    fields_terminated_by: Optional[str] = field(default=None)
    lines_terminated_by: Optional[str] = field(default=None)
    quote_character: Optional[str] = field(default=None)
    select_query: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpSqlMysqlexportoptions:
    kind: ClassVar[str] = "gcp_sql_mysqlexportoptions"
    mapping: ClassVar[Dict[str, Bender]] = {"master_data": S("masterData")}
    master_data: Optional[int] = field(default=None)


@define(eq=False, slots=False)
class GcpSqlSqlexportoptions:
    kind: ClassVar[str] = "gcp_sql_sqlexportoptions"
    mapping: ClassVar[Dict[str, Bender]] = {
        "mysql_export_options": S("mysqlExportOptions", default={}) >> Bend(GcpSqlMysqlexportoptions.mapping),
        "schema_only": S("schemaOnly"),
        "tables": S("tables", default=[]),
    }
    mysql_export_options: Optional[GcpSqlMysqlexportoptions] = field(default=None)
    schema_only: Optional[bool] = field(default=None)
    tables: Optional[List[str]] = field(default=None)


@define(eq=False, slots=False)
class GcpSqlExportContext:
    kind: ClassVar[str] = "gcp_sql_export_context"
    mapping: ClassVar[Dict[str, Bender]] = {
        "csv_export_options": S("csvExportOptions", default={}) >> Bend(GcpSqlCsvexportoptions.mapping),
        "databases": S("databases", default=[]),
        "file_type": S("fileType"),
        "offload": S("offload"),
        "sql_export_options": S("sqlExportOptions", default={}) >> Bend(GcpSqlSqlexportoptions.mapping),
        "uri": S("uri"),
    }
    csv_export_options: Optional[GcpSqlCsvexportoptions] = field(default=None)
    databases: Optional[List[str]] = field(default=None)
    file_type: Optional[str] = field(default=None)
    offload: Optional[bool] = field(default=None)
    sql_export_options: Optional[GcpSqlSqlexportoptions] = field(default=None)
    uri: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpSqlEncryptionoptions:
    kind: ClassVar[str] = "gcp_sql_encryptionoptions"
    mapping: ClassVar[Dict[str, Bender]] = {
        "cert_path": S("certPath"),
        "pvk_password": S("pvkPassword"),
        "pvk_path": S("pvkPath"),
    }
    cert_path: Optional[str] = field(default=None)
    pvk_password: Optional[str] = field(default=None)
    pvk_path: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpSqlBakimportoptions:
    kind: ClassVar[str] = "gcp_sql_bakimportoptions"
    mapping: ClassVar[Dict[str, Bender]] = {
        "encryption_options": S("encryptionOptions", default={}) >> Bend(GcpSqlEncryptionoptions.mapping)
    }
    encryption_options: Optional[GcpSqlEncryptionoptions] = field(default=None)


@define(eq=False, slots=False)
class GcpSqlCsvimportoptions:
    kind: ClassVar[str] = "gcp_sql_csvimportoptions"
    mapping: ClassVar[Dict[str, Bender]] = {
        "columns": S("columns", default=[]),
        "escape_character": S("escapeCharacter"),
        "fields_terminated_by": S("fieldsTerminatedBy"),
        "lines_terminated_by": S("linesTerminatedBy"),
        "quote_character": S("quoteCharacter"),
        "table": S("table"),
    }
    columns: Optional[List[str]] = field(default=None)
    escape_character: Optional[str] = field(default=None)
    fields_terminated_by: Optional[str] = field(default=None)
    lines_terminated_by: Optional[str] = field(default=None)
    quote_character: Optional[str] = field(default=None)
    table: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpSqlImportContext:
    kind: ClassVar[str] = "gcp_sql_import_context"
    mapping: ClassVar[Dict[str, Bender]] = {
        "bak_import_options": S("bakImportOptions", default={}) >> Bend(GcpSqlBakimportoptions.mapping),
        "csv_import_options": S("csvImportOptions", default={}) >> Bend(GcpSqlCsvimportoptions.mapping),
        "database": S("database"),
        "file_type": S("fileType"),
        "import_user": S("importUser"),
        "uri": S("uri"),
    }
    bak_import_options: Optional[GcpSqlBakimportoptions] = field(default=None)
    csv_import_options: Optional[GcpSqlCsvimportoptions] = field(default=None)
    database: Optional[str] = field(default=None)
    file_type: Optional[str] = field(default=None)
    import_user: Optional[str] = field(default=None)
    uri: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpSqlOperation(GcpResource):
    kind: ClassVar[str] = "gcp_sql_operation"
    reference_kinds: ClassVar[ModelReference] = {"predecessors": {"default": ["gcp_sql_database_instance"]}}
    api_spec: ClassVar[GcpApiSpec] = GcpApiSpec(
        service="sqladmin",
        version="v1",
        accessors=["operations"],
        action="list",
        request_parameter={"project": "{project}"},
        request_parameter_in={"project"},
        response_path="items",
        response_regional_sub_path=None,
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id").or_else(S("name")).or_else(S("selfLink")),
        "tags": S("labels", default={}),
        "name": S("name"),
        "ctime": S("creationTimestamp"),
        "description": S("description"),
        "link": S("selfLink"),
        "label_fingerprint": S("labelFingerprint"),
        "deprecation_status": S("deprecated", default={}) >> Bend(GcpDeprecationStatus.mapping),
        "operation_backup_context": S("backupContext", "backupId"),
        "operation_end_time": S("endTime"),
        "operation_error": S("error", default={}) >> Bend(GcpSqlOperationErrors.mapping),
        "operation_export_context": S("exportContext", default={}) >> Bend(GcpSqlExportContext.mapping),
        "operation_import_context": S("importContext", default={}) >> Bend(GcpSqlImportContext.mapping),
        "operation_insert_time": S("insertTime"),
        "operation_operation_type": S("operationType"),
        "operation_start_time": S("startTime"),
        "operation_status": S("status"),
        "operation_target_id": S("targetId"),
        "operation_target_link": S("targetLink"),
        "operation_target_project": S("targetProject"),
        "operation_user": S("user"),
    }
    operation_backup_context: Optional[str] = field(default=None)
    operation_end_time: Optional[str] = field(default=None)
    operation_error: Optional[GcpSqlOperationErrors] = field(default=None)
    operation_export_context: Optional[GcpSqlExportContext] = field(default=None)
    operation_import_context: Optional[GcpSqlImportContext] = field(default=None)
    operation_insert_time: Optional[str] = field(default=None)
    operation_operation_type: Optional[str] = field(default=None)
    operation_start_time: Optional[str] = field(default=None)
    operation_status: Optional[str] = field(default=None)
    operation_target_id: Optional[str] = field(default=None)
    operation_target_link: Optional[str] = field(default=None)
    operation_target_project: Optional[str] = field(default=None)
    operation_user: Optional[str] = field(default=None)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if self.operation_target_id:
            builder.add_edge(self, reverse=True, clazz=GcpSqlDatabaseInstance, name=self.operation_target_id)


@define(eq=False, slots=False)
class GcpSqlPasswordStatus:
    kind: ClassVar[str] = "gcp_sql_password_status"
    mapping: ClassVar[Dict[str, Bender]] = {
        "locked": S("locked"),
        "password_expiration_time": S("passwordExpirationTime"),
    }
    locked: Optional[bool] = field(default=None)
    password_expiration_time: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpSqlUserPasswordValidationPolicy:
    kind: ClassVar[str] = "gcp_sql_user_password_validation_policy"
    mapping: ClassVar[Dict[str, Bender]] = {
        "allowed_failed_attempts": S("allowedFailedAttempts"),
        "enable_failed_attempts_check": S("enableFailedAttemptsCheck"),
        "enable_password_verification": S("enablePasswordVerification"),
        "password_expiration_duration": S("passwordExpirationDuration"),
        "status": S("status", default={}) >> Bend(GcpSqlPasswordStatus.mapping),
    }
    allowed_failed_attempts: Optional[int] = field(default=None)
    enable_failed_attempts_check: Optional[bool] = field(default=None)
    enable_password_verification: Optional[bool] = field(default=None)
    password_expiration_duration: Optional[str] = field(default=None)
    status: Optional[GcpSqlPasswordStatus] = field(default=None)


@define(eq=False, slots=False)
class GcpSqlSqlServerUserDetails:
    kind: ClassVar[str] = "gcp_sql_sql_server_user_details"
    mapping: ClassVar[Dict[str, Bender]] = {"disabled": S("disabled"), "server_roles": S("serverRoles", default=[])}
    disabled: Optional[bool] = field(default=None)
    server_roles: Optional[List[str]] = field(default=None)


@define(eq=False, slots=False)
class GcpSqlUser(GcpResource):
    kind: ClassVar[str] = "gcp_sql_user"
    api_spec: ClassVar[GcpApiSpec] = GcpApiSpec(
        service="sqladmin",
        version="v1",
        accessors=["users"],
        action="list",
        request_parameter={"instance": "{instance}", "project": "{project}"},
        request_parameter_in={"instance", "project"},
        response_path="items",
        response_regional_sub_path=None,
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id").or_else(S("name")).or_else(S("selfLink")),
        "tags": S("labels", default={}),
        "name": S("name"),
        "ctime": S("creationTimestamp"),
        "description": S("description"),
        "link": S("selfLink"),
        "label_fingerprint": S("labelFingerprint"),
        "deprecation_status": S("deprecated", default={}) >> Bend(GcpDeprecationStatus.mapping),
        "user_dual_password_type": S("dualPasswordType"),
        "user_etag": S("etag"),
        "user_host": S("host"),
        "user_instance": S("instance"),
        "user_password": S("password"),
        "user_password_policy": S("passwordPolicy", default={}) >> Bend(GcpSqlUserPasswordValidationPolicy.mapping),
        "user_project": S("project"),
        "user_sqlserver_user_details": S("sqlserverUserDetails", default={})
        >> Bend(GcpSqlSqlServerUserDetails.mapping),
        "user_type": S("type"),
    }
    user_dual_password_type: Optional[str] = field(default=None)
    user_etag: Optional[str] = field(default=None)
    user_host: Optional[str] = field(default=None)
    user_instance: Optional[str] = field(default=None)
    user_password: Optional[str] = field(default=None)
    user_password_policy: Optional[GcpSqlUserPasswordValidationPolicy] = field(default=None)
    user_project: Optional[str] = field(default=None)
    user_sqlserver_user_details: Optional[GcpSqlSqlServerUserDetails] = field(default=None)
    user_type: Optional[str] = field(default=None)


# TODO: GcpSqlBackupRun for every instance
# TODO: GcpSqlDatabase for every instance
# TODO: GcpSqlUser for every instance
# TODO: GcpSqlOperation of every instance
resources = [GcpSqlFlag, GcpSqlDatabaseInstance]
