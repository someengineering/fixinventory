import logging
from datetime import datetime
from typing import ClassVar, Dict, Optional, List, Type

from attr import define, field

from fix_plugin_gcp.gcp_client import GcpApiSpec
from fix_plugin_gcp.resources.base import GcpResource, GcpDeprecationStatus, GraphBuilder
from fix_plugin_gcp.resources.compute import GcpSslCertificate
from fixlib.baseresources import ModelReference
from fixlib.json_bender import Bender, S, Bend, ForallBend, K
from fixlib.types import Json

log = logging.getLogger("fix.plugins.gcp")


@define(eq=False, slots=False)
class GcpSqlOperationError:
    kind: ClassVar[str] = "gcp_sql_operation_error"
    kind_display: ClassVar[str] = "GCP SQL Operation Error"
    kind_description: ClassVar[str] = (
        "This error refers to an error that occurred during an operation related to"
        " Google Cloud SQL, which is a fully managed relational database service"
        " provided by Google Cloud Platform."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"code": S("code"), "message": S("message")}
    code: Optional[str] = field(default=None)
    message: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpSqlBackupRun(GcpResource):
    # collected via GcpSqlDatabaseInstance
    kind: ClassVar[str] = "gcp_sql_backup_run"
    kind_display: ClassVar[str] = "GCP SQL Backup Run"
    kind_description: ClassVar[str] = (
        "GCP SQL Backup Run is a feature in Google Cloud Platform that allows users"
        " to schedule and execute automated backups of their SQL databases."
    )
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
        required_iam_permissions=["cloudsql.backupRuns.list"],
        mutate_iam_permissions=["cloudsql.backupRuns.delete"],
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
        "backup_kind": S("backupKind"),
        "disk_encryption_configuration": S("diskEncryptionConfiguration", "kmsKeyName"),
        "disk_encryption_status": S("diskEncryptionStatus", "kmsKeyVersionName"),
        "end_time": S("endTime"),
        "enqueued_time": S("enqueuedTime"),
        "sql_operation_error": S("error", default={}) >> Bend(GcpSqlOperationError.mapping),
        "instance": S("instance"),
        "location": S("location"),
        "start_time": S("startTime"),
        "status": S("status"),
        "time_zone": S("timeZone"),
        "type": S("type"),
        "window_start_time": S("windowStartTime"),
    }
    backup_kind: Optional[str] = field(default=None)
    disk_encryption_configuration: Optional[str] = field(default=None)
    disk_encryption_status: Optional[str] = field(default=None)
    end_time: Optional[datetime] = field(default=None)
    enqueued_time: Optional[datetime] = field(default=None)
    sql_operation_error: Optional[GcpSqlOperationError] = field(default=None)
    instance: Optional[str] = field(default=None)
    location: Optional[str] = field(default=None)
    start_time: Optional[datetime] = field(default=None)
    status: Optional[str] = field(default=None)
    time_zone: Optional[str] = field(default=None)
    type: Optional[str] = field(default=None)
    window_start_time: Optional[datetime] = field(default=None)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if self.instance:
            builder.add_edge(self, reverse=True, clazz=GcpSqlDatabaseInstance, name=self.instance)


@define(eq=False, slots=False)
class GcpSqlSqlServerDatabaseDetails:
    kind: ClassVar[str] = "gcp_sql_sql_server_database_details"
    kind_display: ClassVar[str] = "GCP SQL SQL Server Database Details"
    kind_description: ClassVar[str] = (
        "This resource provides details and information about a Microsoft SQL Server"
        " database in the Google Cloud Platform's SQL service."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "compatibility_level": S("compatibilityLevel"),
        "recovery_model": S("recoveryModel"),
    }
    compatibility_level: Optional[int] = field(default=None)
    recovery_model: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpSqlDatabase(GcpResource):
    # collected via GcpSqlDatabaseInstance
    kind: ClassVar[str] = "gcp_sql_database"
    kind_display: ClassVar[str] = "GCP SQL Database"
    kind_description: ClassVar[str] = (
        "GCP SQL Database is a managed relational database service provided by Google Cloud Platform."
    )
    api_spec: ClassVar[GcpApiSpec] = GcpApiSpec(
        service="sqladmin",
        version="v1",
        accessors=["databases"],
        action="list",
        request_parameter={"instance": "{instance}", "project": "{project}"},
        request_parameter_in={"instance", "project"},
        response_path="items",
        response_regional_sub_path=None,
        required_iam_permissions=["cloudsql.databases.list"],
        mutate_iam_permissions=["cloudsql.databases.update", "cloudsql.databases.delete"],
    )
    reference_kinds: ClassVar[ModelReference] = {"predecessors": {"default": ["gcp_sql_database_instance"]}}
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("name").or_else(S("id")).or_else(S("selfLink")),
        "tags": S("labels", default={}),
        "name": S("name"),
        "ctime": S("creationTimestamp"),
        "description": S("description"),
        "link": S("selfLink"),
        "label_fingerprint": S("labelFingerprint"),
        "deprecation_status": S("deprecated", default={}) >> Bend(GcpDeprecationStatus.mapping),
        "charset": S("charset"),
        "collation": S("collation"),
        "etag": S("etag"),
        "instance": S("instance"),
        "project": S("project"),
        "sqlserver_database_details": S("sqlserverDatabaseDetails", default={})
        >> Bend(GcpSqlSqlServerDatabaseDetails.mapping),
    }
    charset: Optional[str] = field(default=None)
    collation: Optional[str] = field(default=None)
    etag: Optional[str] = field(default=None)
    instance: Optional[str] = field(default=None)
    project: Optional[str] = field(default=None)
    sqlserver_database_details: Optional[GcpSqlSqlServerDatabaseDetails] = field(default=None)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if self.instance:
            builder.add_edge(self, reverse=True, clazz=GcpSqlDatabaseInstance, name=self.instance)


@define(eq=False, slots=False)
class GcpSqlFailoverreplica:
    kind: ClassVar[str] = "gcp_sql_failoverreplica"
    kind_display: ClassVar[str] = "GCP SQL Failover Replica"
    kind_description: ClassVar[str] = (
        "A GCP SQL Failover Replica is a secondary replica database that can be"
        " promoted to the primary database in case of a primary database failure,"
        " ensuring high availability and data redundancy for Google Cloud SQL."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"available": S("available"), "name": S("name")}
    available: Optional[bool] = field(default=None)
    name: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpSqlIpMapping:
    kind: ClassVar[str] = "gcp_sql_ip_mapping"
    kind_display: ClassVar[str] = "GCP SQL IP Mapping"
    kind_description: ClassVar[str] = (
        "The GCP SQL IP Mapping configures the IP address allocation for a Cloud SQL database instance, detailing"
        " the assigned IP, its type, and any scheduled retirement."
    )
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
    kind_display: ClassVar[str] = "GCP Cloud SQL Instance Reference"
    kind_description: ClassVar[str] = (
        "Cloud SQL is a fully-managed relational database service provided by Google"
        " Cloud Platform, allowing users to create and manage MySQL or PostgreSQL"
        " databases in the cloud."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"name": S("name"), "project": S("project"), "region": S("region")}
    name: Optional[str] = field(default=None)
    project: Optional[str] = field(default=None)
    region: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpSqlOnPremisesConfiguration:
    kind: ClassVar[str] = "gcp_sql_on_premises_configuration"
    kind_display: ClassVar[str] = "GCP SQL On-Premises Configuration"
    kind_description: ClassVar[str] = (
        "The GCP SQL On-Premises Configuration is used for setting up secure connections and credentials for migrating"
        " or syncing data between an on-premises database and a GCP SQL Database Instance."
    )
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
    kind_display: ClassVar[str] = "GCP SQL Out of Disk Report"
    kind_description: ClassVar[str] = (
        "The GCP SQL Out of Disk Report provides insights into the storage status of a SQL database instance,"
        " including recommendations on the minimum size increase necessary to prevent running out of disk space."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "sql_min_recommended_increase_size_gb": S("sqlMinRecommendedIncreaseSizeGb"),
        "sql_out_of_disk_state": S("sqlOutOfDiskState"),
    }
    sql_min_recommended_increase_size_gb: Optional[int] = field(default=None)
    sql_out_of_disk_state: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpSqlMySqlReplicaConfiguration:
    kind: ClassVar[str] = "gcp_sql_my_sql_replica_configuration"
    kind_display: ClassVar[str] = "GCP SQL MySQL Replica Configuration"
    kind_description: ClassVar[str] = (
        "MySQL Replica Configuration is a feature in Google Cloud SQL that enables"
        " the creation and management of replicas for high availability and fault"
        " tolerance of MySQL databases."
    )
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
    kind_display: ClassVar[str] = "GCP SQL Replica Configuration"
    kind_description: ClassVar[str] = (
        "SQL replica configuration in Google Cloud Platform (GCP) allows users to"
        " create and manage replica instances of a SQL database for improved"
        " scalability and high availability."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "failover_target": S("failoverTarget"),
        "mysql_replica_configuration": S("mysqlReplicaConfiguration", default={})
        >> Bend(GcpSqlMySqlReplicaConfiguration.mapping),
    }
    failover_target: Optional[bool] = field(default=None)
    mysql_replica_configuration: Optional[GcpSqlMySqlReplicaConfiguration] = field(default=None)


@define(eq=False, slots=False)
class GcpSqlScheduledMaintenance:
    kind: ClassVar[str] = "gcp_sql_scheduled_maintenance"
    kind_display: ClassVar[str] = "GCP SQL Scheduled Maintenance"
    kind_description: ClassVar[str] = (
        "GCP SQL Scheduled Maintenance is a feature that allows database administrators to schedule maintenance"
        " operations for a SQL database instance, with options to defer and reschedule within a specified deadline."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "can_defer": S("canDefer"),
        "can_reschedule": S("canReschedule"),
        "schedule_deadline_time": S("scheduleDeadlineTime"),
        "start_time": S("startTime"),
    }
    can_defer: Optional[bool] = field(default=None)
    can_reschedule: Optional[bool] = field(default=None)
    schedule_deadline_time: Optional[datetime] = field(default=None)
    start_time: Optional[datetime] = field(default=None)


@define(eq=False, slots=False)
class GcpSqlSslCert:
    kind: ClassVar[str] = "gcp_sql_ssl_cert"
    kind_display: ClassVar[str] = "GCP SQL SSL Certificate"
    kind_description: ClassVar[str] = (
        "GCP SQL SSL Certificates are used to secure connections between applications"
        " and Google Cloud SQL databases, ensuring that data exchanged between them is"
        " encrypted."
    )
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
    create_time: Optional[datetime] = field(default=None)
    expiration_time: Optional[datetime] = field(default=None)
    instance: Optional[str] = field(default=None)
    self_link: Optional[str] = field(default=None)
    sha1_fingerprint: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpSqlBackupRetentionSettings:
    kind: ClassVar[str] = "gcp_sql_backup_retention_settings"
    kind_display: ClassVar[str] = "GCP SQL Backup Retention Settings"
    kind_description: ClassVar[str] = (
        "GCP SQL Backup Retention Settings is a feature in Google Cloud Platform that"
        " allows you to configure the backup retention policy for your SQL databases."
        " It lets you set the duration for which backups should be retained before"
        " being automatically deleted."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "retained_backups": S("retainedBackups"),
        "retention_unit": S("retentionUnit"),
    }
    retained_backups: Optional[int] = field(default=None)
    retention_unit: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpSqlBackupConfiguration:
    kind: ClassVar[str] = "gcp_sql_backup_configuration"
    kind_display: ClassVar[str] = "GCP SQL Backup Configuration"
    kind_description: ClassVar[str] = (
        "GCP SQL Backup Configuration is a resource in Google Cloud Platform that"
        " allows users to configure and manage backups for their SQL databases."
    )
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
    kind_display: ClassVar[str] = "GCP SQL Database Flags"
    kind_description: ClassVar[str] = (
        "GCP SQL Database Flags are configuration settings that can be applied to"
        " Google Cloud Platform's SQL databases to customize their behavior."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"name": S("name"), "value": S("value")}
    name: Optional[str] = field(default=None)
    value: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpSqlDenyMaintenancePeriod:
    kind: ClassVar[str] = "gcp_sql_deny_maintenance_period"
    kind_display: ClassVar[str] = "GCP SQL Deny Maintenance Period"
    kind_description: ClassVar[str] = (
        "GCP SQL Deny Maintenance Period specifies a time frame during which maintenance activities by GCP on a SQL"
        " database instance are not allowed, ensuring uninterrupted service during critical business periods."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"end_date": S("endDate"), "start_date": S("startDate"), "time": S("time")}
    end_date: Optional[str] = field(default=None)
    start_date: Optional[str] = field(default=None)
    time: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpSqlInsightsConfig:
    kind: ClassVar[str] = "gcp_sql_insights_config"
    kind_display: ClassVar[str] = "GCP SQL Insights Config"
    kind_description: ClassVar[str] = (
        "GCP SQL Insights Config is a feature in Google Cloud Platform that allows"
        " users to configure and customize their SQL database insights and monitoring."
    )
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
    kind_display: ClassVar[str] = "GCP SQL ACL Entry"
    kind_description: ClassVar[str] = (
        "GCP SQL ACL Entry is a resource in Google Cloud Platform that represents an"
        " access control list entry for a Cloud SQL instance. It defines policies for"
        " granting or denying network access to the SQL instance."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "expiration_time": S("expirationTime"),
        "name": S("name"),
        "value": S("value"),
    }
    expiration_time: Optional[datetime] = field(default=None)
    name: Optional[str] = field(default=None)
    value: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpSqlIpConfiguration:
    kind: ClassVar[str] = "gcp_sql_ip_configuration"
    kind_display: ClassVar[str] = "GCP SQL IP Configuration"
    kind_description: ClassVar[str] = (
        "IP Configuration refers to the settings for managing IP addresses associated"
        " with Google Cloud Platform(SQL) instances, allowing users to control network"
        " access to their databases."
    )
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
    kind_display: ClassVar[str] = "GCP SQL Location Preference"
    kind_description: ClassVar[str] = (
        "GCP SQL Location Preference allows users to specify the preferred location"
        " for their Google Cloud SQL database instances, helping them ensure optimal"
        " performance and compliance with data sovereignty requirements."
    )
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
    kind_display: ClassVar[str] = "GCP SQL Maintenance Window"
    kind_description: ClassVar[str] = (
        "A maintenance window is a predefined time period when Google Cloud SQL"
        " performs system updates and maintenance tasks on your databases."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"day": S("day"), "hour": S("hour"), "update_track": S("updateTrack")}
    day: Optional[int] = field(default=None)
    hour: Optional[int] = field(default=None)
    update_track: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpSqlPasswordValidationPolicy:
    kind: ClassVar[str] = "gcp_sql_password_validation_policy"
    kind_display: ClassVar[str] = "GCP SQL Password Validation Policy"
    kind_description: ClassVar[str] = (
        "GCP SQL Password Validation Policy is a feature in Google Cloud Platform"
        " that enforces strong password policies for SQL databases, ensuring better"
        " security and compliance with password requirements."
    )
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
    kind_display: ClassVar[str] = "GCP SQL Server Audit Configuration"
    kind_description: ClassVar[str] = (
        "GCP SQL Server Audit Configuration provides a way to enable and configure"
        " SQL Server auditing for Google Cloud Platform (GCP) SQL Server instances."
        " Auditing allows users to monitor and record database activities and events"
        " for security and compliance purposes."
    )
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
    kind_display: ClassVar[str] = "GCP SQL Settings"
    kind_description: ClassVar[str] = (
        "GCP SQL Settings refers to the configuration and customization options for"
        " managing SQL databases in Google Cloud Platform (GCP). It includes various"
        " settings related to database performance, security, availability, and"
        " monitoring."
    )
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
    kind_display: ClassVar[str] = "GCP SQL Database Instance"
    kind_description: ClassVar[str] = (
        "GCP SQL Database Instance is a resource provided by Google Cloud Platform"
        " that allows users to create and manage relational databases in the cloud."
    )
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
        required_iam_permissions=["cloudsql.instances.list"],
        mutate_iam_permissions=["cloudsql.instances.update", "cloudsql.instances.delete"],
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("name").or_else(S("id")).or_else(S("selfLink")),
        "tags": S("labels", default={}),
        "name": S("name"),
        "ctime": S("createTime"),
        "description": S("description"),
        "link": S("selfLink"),
        "label_fingerprint": S("labelFingerprint"),
        "deprecation_status": S("deprecated", default={}) >> Bend(GcpDeprecationStatus.mapping),
        "available_maintenance_versions": S("availableMaintenanceVersions", default=[]),
        "backend_type": S("backendType"),
        "connection_name": S("connectionName"),
        "create_time": S("createTime"),
        "current_disk_size": S("currentDiskSize"),
        "database_installed_version": S("databaseInstalledVersion"),
        "database_version": S("databaseVersion"),
        "disk_encryption_configuration": S("diskEncryptionConfiguration", "kmsKeyName"),
        "disk_encryption_status": S("diskEncryptionStatus", "kmsKeyVersionName"),
        "etag": S("etag"),
        "failover_replica": S("failoverReplica", default={}) >> Bend(GcpSqlFailoverreplica.mapping),
        "gce_zone": S("gceZone"),
        "instance_type": S("instanceType"),
        "instance_ip_addresses": S("ipAddresses", default=[]) >> ForallBend(GcpSqlIpMapping.mapping),
        "ipv6_address": S("ipv6Address"),
        "maintenance_version": S("maintenanceVersion"),
        "master_instance_name": S("masterInstanceName"),
        "max_disk_size": S("maxDiskSize"),
        "on_premises_configuration": S("onPremisesConfiguration", default={})
        >> Bend(GcpSqlOnPremisesConfiguration.mapping),
        "out_of_disk_report": S("outOfDiskReport", default={}) >> Bend(GcpSqlSqlOutOfDiskReport.mapping),
        "project": S("project"),
        "replica_configuration": S("replicaConfiguration", default={}) >> Bend(GcpSqlReplicaConfiguration.mapping),
        "replica_names": S("replicaNames", default=[]),
        "root_password": S("rootPassword"),
        "satisfies_pzs": S("satisfiesPzs"),
        "scheduled_maintenance": S("scheduledMaintenance", default={}) >> Bend(GcpSqlScheduledMaintenance.mapping),
        "secondary_gce_zone": S("secondaryGceZone"),
        "server_ca_cert": S("serverCaCert", default={}) >> Bend(GcpSqlSslCert.mapping),
        "service_account_email_address": S("serviceAccountEmailAddress"),
        "settings": S("settings", default={}) >> Bend(GcpSqlSettings.mapping),
        "sql_database_instance_state": S("state"),
        "suspension_reason": S("suspensionReason", default=[]),
    }
    available_maintenance_versions: Optional[List[str]] = field(default=None)
    backend_type: Optional[str] = field(default=None)
    connection_name: Optional[str] = field(default=None)
    create_time: Optional[datetime] = field(default=None)
    current_disk_size: Optional[str] = field(default=None)
    database_installed_version: Optional[str] = field(default=None)
    database_version: Optional[str] = field(default=None)
    disk_encryption_configuration: Optional[str] = field(default=None)
    disk_encryption_status: Optional[str] = field(default=None)
    etag: Optional[str] = field(default=None)
    failover_replica: Optional[GcpSqlFailoverreplica] = field(default=None)
    gce_zone: Optional[str] = field(default=None)
    instance_type: Optional[str] = field(default=None)
    instance_ip_addresses: Optional[List[GcpSqlIpMapping]] = field(default=None)
    ipv6_address: Optional[str] = field(default=None)
    maintenance_version: Optional[str] = field(default=None)
    master_instance_name: Optional[str] = field(default=None)
    max_disk_size: Optional[str] = field(default=None)
    on_premises_configuration: Optional[GcpSqlOnPremisesConfiguration] = field(default=None)
    out_of_disk_report: Optional[GcpSqlSqlOutOfDiskReport] = field(default=None)
    project: Optional[str] = field(default=None)
    replica_configuration: Optional[GcpSqlReplicaConfiguration] = field(default=None)
    replica_names: Optional[List[str]] = field(default=None)
    root_password: Optional[str] = field(default=None)
    satisfies_pzs: Optional[bool] = field(default=None)
    scheduled_maintenance: Optional[GcpSqlScheduledMaintenance] = field(default=None)
    secondary_gce_zone: Optional[str] = field(default=None)
    server_ca_cert: Optional[GcpSqlSslCert] = field(default=None)
    service_account_email_address: Optional[str] = field(default=None)
    settings: Optional[GcpSqlSettings] = field(default=None)
    sql_database_instance_state: Optional[str] = field(default=None)
    suspension_reason: Optional[List[str]] = field(default=None)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if cert := self.server_ca_cert:
            if cert.self_link:
                builder.add_edge(self, reverse=True, clazz=GcpSslCertificate, link=cert.self_link)

    def post_process(self, graph_builder: GraphBuilder, source: Json) -> None:
        classes: List[Type[GcpResource]] = [GcpSqlBackupRun, GcpSqlDatabase, GcpSqlUser, GcpSqlOperation]
        for cls in classes:
            if spec := cls.api_spec:
                items = graph_builder.client.list(spec, instance=self.name, project=self.project)
                cls.collect(items, graph_builder)

    @classmethod
    def called_collect_apis(cls) -> List[GcpApiSpec]:
        return [
            cls.api_spec,
            GcpSqlBackupRun.api_spec,
            GcpSqlDatabase.api_spec,
            GcpSqlUser.api_spec,
            GcpSqlOperation.api_spec,
        ]


@define(eq=False, slots=False)
class GcpSqlCsvexportoptions:
    kind: ClassVar[str] = "gcp_sql_csvexportoptions"
    kind_display: ClassVar[str] = "GCP SQL CSV Export Options"
    kind_description: ClassVar[str] = (
        "CSV Export Options for Google Cloud Platform's SQL allows users to export"
        " SQL query results into CSV format for further analysis or data manipulation."
    )
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
    kind_display: ClassVar[str] = "GCP SQL MySQL Export Options"
    kind_description: ClassVar[str] = (
        "GCP SQL MySQL Export Options are features provided by Google Cloud Platform"
        " that allow users to export data from MySQL databases hosted on GCP SQL."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"master_data": S("masterData")}
    master_data: Optional[int] = field(default=None)


@define(eq=False, slots=False)
class GcpSqlSqlexportoptions:
    kind: ClassVar[str] = "gcp_sql_sqlexportoptions"
    kind_display: ClassVar[str] = "GCP SQL SQLExportOptions"
    kind_description: ClassVar[str] = (
        "GCP SQL SQLExportOptions is a set of configurations for exporting data from a SQL database instance,"
        " including options for MySQL specific exports, schema-only exports, and selecting specific tables to export."
    )
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
    kind_display: ClassVar[str] = "GCP SQL Export Context"
    kind_description: ClassVar[str] = (
        "GCP SQL Export Context defines the parameters and settings for exporting data from a SQL database instance"
        " in GCP, including the data format, destination URI, database selection, and whether the operation should"
        " be offloaded to avoid impacting database performance."
    )
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
    kind_display: ClassVar[str] = "GCP SQL Encryption Options"
    kind_description: ClassVar[str] = (
        "GCP SQL Encryption Options refers to the various methods available for"
        " encrypting data in Google Cloud Platform's SQL databases, such as Cloud SQL"
        " and SQL Server on GCE."
    )
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
    kind_display: ClassVar[str] = "GCP SQL Backup Import Options"
    kind_description: ClassVar[str] = (
        "GCP SQL Backup Import Options provide configuration settings and options for"
        " importing backed up data into Google Cloud Platform SQL databases."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "encryption_options": S("encryptionOptions", default={}) >> Bend(GcpSqlEncryptionoptions.mapping)
    }
    encryption_options: Optional[GcpSqlEncryptionoptions] = field(default=None)


@define(eq=False, slots=False)
class GcpSqlCsvimportoptions:
    kind: ClassVar[str] = "gcp_sql_csvimportoptions"
    kind_display: ClassVar[str] = "GCP SQL CSV Import Options"
    kind_description: ClassVar[str] = (
        "CSV Import Options in GCP SQL enables users to efficiently import CSV data into Google Cloud SQL databases."
    )
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
    kind_display: ClassVar[str] = "GCP SQL Import Context"
    kind_description: ClassVar[str] = (
        "GCP SQL Import Context defines the settings for importing data into a Cloud SQL database,"
        " including file type and source URI."
    )
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
    kind_display: ClassVar[str] = "GCP SQL Operation"
    kind_description: ClassVar[str] = (
        "The GCP SQL Operation is a representation of an administrative operation performed on a GCP SQL Database"
        " instance, such as backups, imports, and exports, including details about execution times, status, and any"
        " errors encountered."
    )
    reference_kinds: ClassVar[ModelReference] = {"predecessors": {"default": ["gcp_sql_database_instance"]}}
    api_spec: ClassVar[GcpApiSpec] = GcpApiSpec(
        service="sqladmin",
        version="v1",
        accessors=["operations"],
        action="list",
        request_parameter={"instance": "{instance}", "project": "{project}"},
        request_parameter_in={"project"},
        response_path="items",
        response_regional_sub_path=None,
        required_iam_permissions=["cloudsql.instances.get"],
        mutate_iam_permissions=["cloudsql.instances.update", "cloudsql.instances.delete"],
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
        "backup_context": S("backupContext", "backupId"),
        "end_time": S("endTime"),
        "sql_operation_errors": S("error", "errors", default=[]) >> ForallBend(GcpSqlOperationError.mapping),
        "export_context": S("exportContext", default={}) >> Bend(GcpSqlExportContext.mapping),
        "import_context": S("importContext", default={}) >> Bend(GcpSqlImportContext.mapping),
        "insert_time": S("insertTime"),
        "operation_type": S("operationType"),
        "start_time": S("startTime"),
        "status": S("status"),
        "target_id": S("targetId"),
        "target_link": S("targetLink"),
        "target_project": S("targetProject"),
        "user": S("user"),
    }
    backup_context: Optional[str] = field(default=None)
    end_time: Optional[datetime] = field(default=None)
    sql_operation_errors: List[GcpSqlOperationError] = field(factory=list)
    export_context: Optional[GcpSqlExportContext] = field(default=None)
    import_context: Optional[GcpSqlImportContext] = field(default=None)
    insert_time: Optional[datetime] = field(default=None)
    operation_type: Optional[str] = field(default=None)
    start_time: Optional[datetime] = field(default=None)
    status: Optional[str] = field(default=None)
    target_id: Optional[str] = field(default=None)
    target_link: Optional[str] = field(default=None)
    target_project: Optional[str] = field(default=None)
    user: Optional[str] = field(default=None)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if self.target_id:
            builder.add_edge(self, reverse=True, clazz=GcpSqlDatabaseInstance, name=self.target_id)


@define(eq=False, slots=False)
class GcpSqlPasswordStatus:
    kind: ClassVar[str] = "gcp_sql_password_status"
    kind_display: ClassVar[str] = "GCP SQL Password Status"
    kind_description: ClassVar[str] = (
        "GCP SQL Password Status refers to the current state of the password used for"
        " SQL database access in Google Cloud Platform. It indicates whether the"
        " password is active or inactive."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "locked": S("locked"),
        "password_expiration_time": S("passwordExpirationTime"),
    }
    locked: Optional[bool] = field(default=None)
    password_expiration_time: Optional[datetime] = field(default=None)


@define(eq=False, slots=False)
class GcpSqlUserPasswordValidationPolicy:
    kind: ClassVar[str] = "gcp_sql_user_password_validation_policy"
    kind_display: ClassVar[str] = "GCP SQL User Password Validation Policy"
    kind_description: ClassVar[str] = (
        "GCP SQL User Password Validation Policy is a feature in Google Cloud"
        " Platform's SQL service that enforces specific rules and requirements for"
        " creating and managing user passwords in SQL databases."
    )
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
    kind_display: ClassVar[str] = "GCP SQL SQL Server User Details"
    kind_description: ClassVar[str] = (
        "GCP SQL SQL Server User Details provides information about the users and"
        " their access privileges in a SQL Server instance on Google Cloud Platform."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"disabled": S("disabled"), "server_roles": S("serverRoles", default=[])}
    disabled: Optional[bool] = field(default=None)
    server_roles: Optional[List[str]] = field(default=None)


@define(eq=False, slots=False)
class GcpSqlUser(GcpResource):
    # collected via GcpSqlDatabaseInstance
    kind: ClassVar[str] = "gcp_sql_user"
    kind_display: ClassVar[str] = "GCP SQL User"
    kind_description: ClassVar[str] = (
        "A GCP SQL User refers to a user account that can access and manage databases"
        " in Google Cloud SQL, a fully-managed relational database service."
    )
    api_spec: ClassVar[GcpApiSpec] = GcpApiSpec(
        service="sqladmin",
        version="v1",
        accessors=["users"],
        action="list",
        request_parameter={"instance": "{instance}", "project": "{project}"},
        request_parameter_in={"instance", "project"},
        response_path="items",
        response_regional_sub_path=None,
        required_iam_permissions=["cloudsql.users.list"],
        mutate_iam_permissions=["cloudsql.users.update", "cloudsql.users.delete"],
    )
    reference_kinds: ClassVar[ModelReference] = {"predecessors": {"default": ["gcp_sql_database_instance"]}}
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("name").or_else(K("(anonymous)@") + S("host", default="localhost")),
        "tags": S("labels", default={}),
        "name": S("name", default="(anonymous)"),
        "ctime": S("creationTimestamp"),
        "description": S("description"),
        "link": S("selfLink"),
        "label_fingerprint": S("labelFingerprint"),
        "deprecation_status": S("deprecated", default={}) >> Bend(GcpDeprecationStatus.mapping),
        "dual_password_type": S("dualPasswordType"),
        "etag": S("etag"),
        "host": S("host", default="localhost"),
        "instance": S("instance"),
        "password": S("password"),
        "password_policy": S("passwordPolicy", default={}) >> Bend(GcpSqlUserPasswordValidationPolicy.mapping),
        "project": S("project"),
        "sqlserver_user_details": S("sqlserverUserDetails", default={}) >> Bend(GcpSqlSqlServerUserDetails.mapping),
        "type": S("type"),
    }
    dual_password_type: Optional[str] = field(default=None)
    etag: Optional[str] = field(default=None)
    host: Optional[str] = field(default=None)
    instance: Optional[str] = field(default=None)
    password: Optional[str] = field(default=None)
    password_policy: Optional[GcpSqlUserPasswordValidationPolicy] = field(default=None)
    project: Optional[str] = field(default=None)
    sqlserver_user_details: Optional[GcpSqlSqlServerUserDetails] = field(default=None)
    type: Optional[str] = field(default=None)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if self.instance:
            builder.add_edge(self, reverse=True, clazz=GcpSqlDatabaseInstance)


resources = [GcpSqlDatabaseInstance]
