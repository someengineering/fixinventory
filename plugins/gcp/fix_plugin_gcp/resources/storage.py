from datetime import datetime
from typing import ClassVar, Dict, Optional, List

from attr import define, field

from fix_plugin_gcp.gcp_client import GcpApiSpec
from fix_plugin_gcp.resources.base import GcpResource, GcpDeprecationStatus, get_client
from fixlib.graph import Graph
from fixlib.json_bender import Bender, S, Bend, ForallBend


@define(eq=False, slots=False)
class GcpProjectteam:
    kind: ClassVar[str] = "gcp_projectteam"
    kind_display: ClassVar[str] = "GCP Project Team"
    kind_description: ClassVar[str] = (
        "GCP Project Teams are groups of users who work together on a Google Cloud"
        " Platform project, allowing them to collaborate and manage resources within"
        " the project."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"project_number": S("projectNumber"), "team": S("team")}
    project_number: Optional[str] = field(default=None)
    team: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpBucketAccessControl:
    kind: ClassVar[str] = "gcp_bucket_access_control"
    kind_display: ClassVar[str] = "GCP Bucket Access Control"
    kind_description: ClassVar[str] = (
        "Bucket Access Control is a feature in the Google Cloud Platform that allows"
        " you to manage and control access to your storage buckets. It provides fine-"
        " grained access control, allowing you to specify who can read, write, or"
        " delete objects within a bucket."
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
        "bucket": S("bucket"),
        "domain": S("domain"),
        "email": S("email"),
        "entity": S("entity"),
        "entity_id": S("entityId"),
        "etag": S("etag"),
        "project_team": S("projectTeam", default={}) >> Bend(GcpProjectteam.mapping),
        "role": S("role"),
    }
    bucket: Optional[str] = field(default=None)
    domain: Optional[str] = field(default=None)
    email: Optional[str] = field(default=None)
    entity: Optional[str] = field(default=None)
    entity_id: Optional[str] = field(default=None)
    etag: Optional[str] = field(default=None)
    project_team: Optional[GcpProjectteam] = field(default=None)
    role: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpAutoclass:
    kind: ClassVar[str] = "gcp_autoclass"
    kind_display: ClassVar[str] = "GCP Autoclass"
    kind_description: ClassVar[str] = (
        "GCP Autoclass for a bucket indicates if automatic data classification is enabled"
        " and the timestamp when this setting was last changed."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"enabled": S("enabled"), "toggle_time": S("toggleTime")}
    enabled: Optional[bool] = field(default=None)
    toggle_time: Optional[datetime] = field(default=None)


@define(eq=False, slots=False)
class GcpCors:
    kind: ClassVar[str] = "gcp_cors"
    kind_display: ClassVar[str] = "GCP CORS"
    kind_description: ClassVar[str] = (
        "GCP CORS settings for a bucket in Google Cloud Storage define which origins can access resources"
        " in the bucket, what HTTP methods are allowed, and which response headers can be exposed to the client."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "max_age_seconds": S("maxAgeSeconds"),
        "method": S("method", default=[]),
        "origin": S("origin", default=[]),
        "response_header": S("responseHeader", default=[]),
    }
    max_age_seconds: Optional[int] = field(default=None)
    method: Optional[List[str]] = field(default=None)
    origin: Optional[List[str]] = field(default=None)
    response_header: Optional[List[str]] = field(default=None)


@define(eq=False, slots=False)
class GcpObjectAccessControl:
    kind: ClassVar[str] = "gcp_object_access_control"
    kind_display: ClassVar[str] = "GCP Object Access Control"
    kind_description: ClassVar[str] = (
        "GCP Object Access Control is a feature in Google Cloud Platform that allows"
        " users to control access to their storage objects (such as files, images,"
        " videos) by specifying permissions and policies."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "bucket": S("bucket"),
        "domain": S("domain"),
        "email": S("email"),
        "entity": S("entity"),
        "entity_id": S("entityId"),
        "etag": S("etag"),
        "generation": S("generation"),
        "id": S("id"),
        "object": S("object"),
        "project_team": S("projectTeam", default={}) >> Bend(GcpProjectteam.mapping),
        "role": S("role"),
        "self_link": S("selfLink"),
    }
    bucket: Optional[str] = field(default=None)
    domain: Optional[str] = field(default=None)
    email: Optional[str] = field(default=None)
    entity: Optional[str] = field(default=None)
    entity_id: Optional[str] = field(default=None)
    etag: Optional[str] = field(default=None)
    generation: Optional[str] = field(default=None)
    id: Optional[str] = field(default=None)
    object: Optional[str] = field(default=None)
    project_team: Optional[GcpProjectteam] = field(default=None)
    role: Optional[str] = field(default=None)
    self_link: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpBucketpolicyonly:
    kind: ClassVar[str] = "gcp_bucketpolicyonly"
    kind_display: ClassVar[str] = "GCP Bucket Policy Only"
    kind_description: ClassVar[str] = (
        "GCP Bucket Policy Only is a feature in Google Cloud Platform that enforces"
        " the use of IAM policies for bucket access control and disables any ACL-based"
        " access control."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"enabled": S("enabled"), "locked_time": S("lockedTime")}
    enabled: Optional[bool] = field(default=None)
    locked_time: Optional[datetime] = field(default=None)


@define(eq=False, slots=False)
class GcpUniformbucketlevelaccess:
    kind: ClassVar[str] = "gcp_uniformbucketlevelaccess"
    kind_display: ClassVar[str] = "GCP Uniform Bucket Level Access"
    kind_description: ClassVar[str] = (
        "GCP Uniform Bucket Level Access is a Google Cloud Storage feature that, when enabled, applies consistent"
        " IAM policies across all objects in a bucket, eliminating the need for individual object permissions."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"enabled": S("enabled"), "locked_time": S("lockedTime")}
    enabled: Optional[bool] = field(default=None)
    locked_time: Optional[datetime] = field(default=None)


@define(eq=False, slots=False)
class GcpIamconfiguration:
    kind: ClassVar[str] = "gcp_iamconfiguration"
    kind_display: ClassVar[str] = "GCP IAM Configuration"
    kind_description: ClassVar[str] = (
        "IAM (Identity and Access Management) Configuration in Google Cloud Platform,"
        " which allows users to control access to their cloud resources and manage"
        " permissions for users and service accounts."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "bucket_policy_only": S("bucketPolicyOnly", default={}) >> Bend(GcpBucketpolicyonly.mapping),
        "public_access_prevention": S("publicAccessPrevention"),
        "uniform_bucket_level_access": S("uniformBucketLevelAccess", default={})
        >> Bend(GcpUniformbucketlevelaccess.mapping),
    }
    bucket_policy_only: Optional[GcpBucketpolicyonly] = field(default=None)
    public_access_prevention: Optional[str] = field(default=None)
    uniform_bucket_level_access: Optional[GcpUniformbucketlevelaccess] = field(default=None)


@define(eq=False, slots=False)
class GcpAction:
    kind: ClassVar[str] = "gcp_action"
    kind_display: ClassVar[str] = "GCP Action"
    kind_description: ClassVar[str] = (
        "GCP Action refers to a specific action or operation performed on resources"
        " in Google Cloud Platform (GCP), such as creating, deleting, or modifying"
        " cloud resources."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"storage_class": S("storageClass"), "type": S("type")}
    storage_class: Optional[str] = field(default=None)
    type: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpCondition:
    kind: ClassVar[str] = "gcp_condition"
    kind_display: ClassVar[str] = "GCP Condition"
    kind_description: ClassVar[str] = (
        "Conditions in Google Cloud Platform (GCP) are used to define rules and"
        " policies for resource usage and access control."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "age": S("age"),
        "created_before": S("createdBefore"),
        "custom_time_before": S("customTimeBefore"),
        "days_since_custom_time": S("daysSinceCustomTime"),
        "days_since_noncurrent_time": S("daysSinceNoncurrentTime"),
        "is_live": S("isLive"),
        "matches_pattern": S("matchesPattern"),
        "matches_prefix": S("matchesPrefix", default=[]),
        "matches_storage_class": S("matchesStorageClass", default=[]),
        "matches_suffix": S("matchesSuffix", default=[]),
        "noncurrent_time_before": S("noncurrentTimeBefore"),
        "num_newer_versions": S("numNewerVersions"),
    }
    age: Optional[int] = field(default=None)
    created_before: Optional[str] = field(default=None)
    custom_time_before: Optional[str] = field(default=None)
    days_since_custom_time: Optional[datetime] = field(default=None)  # should be int
    days_since_noncurrent_time: Optional[datetime] = field(default=None)  # should be int
    is_live: Optional[bool] = field(default=None)
    matches_pattern: Optional[str] = field(default=None)
    matches_prefix: Optional[List[str]] = field(default=None)
    matches_storage_class: Optional[List[str]] = field(default=None)
    matches_suffix: Optional[List[str]] = field(default=None)
    noncurrent_time_before: Optional[str] = field(default=None)
    num_newer_versions: Optional[int] = field(default=None)


@define(eq=False, slots=False)
class GcpRule:
    kind: ClassVar[str] = "gcp_rule"
    kind_display: ClassVar[str] = "GCP Rule"
    kind_description: ClassVar[str] = (
        "A GCP Rule for a Bucket refers to an object lifecycle management rule, which automates the deletion"
        " or transition of objects to less expensive storage classes based on specified conditions and actions."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "action": S("action", default={}) >> Bend(GcpAction.mapping),
        "condition": S("condition", default={}) >> Bend(GcpCondition.mapping),
    }
    action: Optional[GcpAction] = field(default=None)
    condition: Optional[GcpCondition] = field(default=None)


@define(eq=False, slots=False)
class GcpLogging:
    kind: ClassVar[str] = "gcp_logging"
    kind_display: ClassVar[str] = "GCP Logging"
    kind_description: ClassVar[str] = (
        "GCP Logging is a service provided by Google Cloud Platform that allows users"
        " to collect, store, and analyze logs from various resources in their cloud"
        " environment."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"log_bucket": S("logBucket"), "log_object_prefix": S("logObjectPrefix")}
    log_bucket: Optional[str] = field(default=None)
    log_object_prefix: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpOwner:
    kind: ClassVar[str] = "gcp_owner"
    kind_display: ClassVar[str] = "GCP Owner"
    kind_description: ClassVar[str] = (
        "GCP Owner refers to the owner of a Google Cloud Platform (GCP) resource or"
        " project, who has full control and access to manage and configure the"
        " resource or project."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"entity": S("entity"), "entity_id": S("entityId")}
    entity: Optional[str] = field(default=None)
    entity_id: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpRetentionpolicy:
    kind: ClassVar[str] = "gcp_retentionpolicy"
    kind_display: ClassVar[str] = "GCP Retention Policy"
    kind_description: ClassVar[str] = (
        "GCP Retention Policy is a feature in Google Cloud Platform that allows users"
        " to set and manage rules for data retention, specifying how long data should"
        " be kept before it is automatically deleted."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "effective_time": S("effectiveTime"),
        "is_locked": S("isLocked"),
        "retention_period": S("retentionPeriod"),
    }
    effective_time: Optional[datetime] = field(default=None)
    is_locked: Optional[bool] = field(default=None)
    retention_period: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpWebsite:
    kind: ClassVar[str] = "gcp_website"
    kind_display: ClassVar[str] = "GCP Website"
    kind_description: ClassVar[str] = (
        "GCP Website refers to the official website of Google Cloud Platform where"
        " users can access information, documentation, and resources related to"
        " Google's cloud services and products."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "main_page_suffix": S("mainPageSuffix"),
        "not_found_page": S("notFoundPage"),
    }
    main_page_suffix: Optional[str] = field(default=None)
    not_found_page: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpObject(GcpResource):
    # GcpObjects are necessary to empty buckets before deletion
    # they are not intended to be collected and stored in the graph
    kind: ClassVar[str] = "gcp_object"
    kind_display: ClassVar[str] = "GCP Object"
    kind_description: ClassVar[str] = (
        "GCP Object, specifically referring to the Google Cloud Storage, is a basic unit of data that is stored"
        " in Google Cloud Storage, often matching to an individual file."
    )
    api_spec: ClassVar[GcpApiSpec] = GcpApiSpec(
        service="storage",
        version="v1",
        accessors=["objects"],
        action="list",
        request_parameter={"bucket": "{bucket}"},
        request_parameter_in={"bucket"},
        response_path="items",
        response_regional_sub_path=None,
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("name").or_else(S("id")).or_else(S("selfLink")),
        "name": S("name"),
    }


@define(eq=False, slots=False)
class GcpBucket(GcpResource):
    kind: ClassVar[str] = "gcp_bucket"
    kind_display: ClassVar[str] = "GCP Bucket"
    kind_description: ClassVar[str] = (
        "A GCP Bucket is a cloud storage container provided by Google Cloud Platform,"
        " allowing users to store and access data in a scalable and durable manner."
    )
    api_spec: ClassVar[GcpApiSpec] = GcpApiSpec(
        service="storage",
        version="v1",
        accessors=["buckets"],
        action="list",
        request_parameter={"project": "{project}"},
        request_parameter_in={"project"},
        # single_request_parameter={"project": "{project}"},
        # single_request_parameter_in={"project"},
        response_path="items",
        response_regional_sub_path=None,
        mutate_iam_permissions=["storage.buckets.update", "storage.buckets.delete"],
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("name").or_else(S("id")).or_else(S("selfLink")),
        "tags": S("labels", default={}),
        "name": S("name"),
        "ctime": S("creationTimestamp"),
        "mtime": S("updated"),
        "description": S("description"),
        "link": S("selfLink"),
        "label_fingerprint": S("labelFingerprint"),
        "deprecation_status": S("deprecated", default={}) >> Bend(GcpDeprecationStatus.mapping),
        "acl": S("acl", default=[]) >> ForallBend(GcpBucketAccessControl.mapping),
        "autoclass": S("autoclass", default={}) >> Bend(GcpAutoclass.mapping),
        "requester_pays": S("billing", "requesterPays"),
        "cors": S("cors", default=[]) >> ForallBend(GcpCors.mapping),
        "custom_placement_config": S("customPlacementConfig", "data_locations", default=[]),
        "default_event_based_hold": S("defaultEventBasedHold"),
        "default_object_acl": S("defaultObjectAcl", default=[]) >> ForallBend(GcpObjectAccessControl.mapping),
        "encryption_default_kms_key_name": S("encryption", "defaultKmsKeyName"),
        "etag": S("etag"),
        "iam_configuration": S("iamConfiguration", default={}) >> Bend(GcpIamconfiguration.mapping),
        "lifecycle_rule": S("lifecycle", "rule", default=[]) >> ForallBend(GcpRule.mapping),
        "location": S("location"),
        "location_type": S("locationType"),
        "logging": S("logging", default={}) >> Bend(GcpLogging.mapping),
        "metageneration": S("metageneration"),
        "bucket_owner": S("owner", default={}) >> Bend(GcpOwner.mapping),
        "project_number": S("projectNumber"),
        "retention_policy": S("retentionPolicy", default={}) >> Bend(GcpRetentionpolicy.mapping),
        "rpo": S("rpo"),
        "satisfies_pzs": S("satisfiesPZS"),
        "storage_class": S("storageClass"),
        "time_created": S("timeCreated"),
        "updated": S("updated"),
        "versioning_enabled": S("versioning", "enabled"),
        "bucket_website": S("website", default={}) >> Bend(GcpWebsite.mapping),
    }
    acl: Optional[List[GcpBucketAccessControl]] = field(default=None)
    autoclass: Optional[GcpAutoclass] = field(default=None)
    cors: Optional[List[GcpCors]] = field(default=None)
    custom_placement_config_data_locations: Optional[List[str]] = field(default=None)
    default_event_based_hold: Optional[bool] = field(default=None)
    default_object_acl: Optional[List[GcpObjectAccessControl]] = field(default=None)
    encryption_default_kms_key_name: Optional[str] = field(default=None)
    etag: Optional[str] = field(default=None)
    iam_configuration: Optional[GcpIamconfiguration] = field(default=None)
    location: Optional[str] = field(default=None)
    location_type: Optional[str] = field(default=None)
    logging: Optional[GcpLogging] = field(default=None)
    metageneration: Optional[str] = field(default=None)
    bucket_owner: Optional[GcpOwner] = field(default=None)
    project_number: Optional[str] = field(default=None)
    retention_policy: Optional[GcpRetentionpolicy] = field(default=None)
    rpo: Optional[str] = field(default=None)
    satisfies_pzs: Optional[bool] = field(default=None)
    storage_class: Optional[str] = field(default=None)
    time_created: Optional[datetime] = field(default=None)
    updated: Optional[datetime] = field(default=None)
    bucket_website: Optional[GcpWebsite] = field(default=None)
    requester_pays: Optional[bool] = field(default=None)
    versioning_enabled: Optional[bool] = field(default=None)
    lifecycle_rule: List[GcpRule] = field(factory=list)

    def pre_delete(self, graph: Graph) -> bool:
        client = get_client(self)
        objects = client.list(GcpObject.api_spec, bucket=self.name)
        for obj in objects:
            object_in_bucket = GcpObject.from_api(obj)
            client.delete(
                object_in_bucket.api_spec.for_delete(),
                bucket=self.name,
                resource=object_in_bucket.name,
            )
        return True

    def delete(self, graph: Graph) -> bool:
        client = get_client(self)
        api_spec = self.api_spec.for_delete()
        api_spec.request_parameter = {"bucket": "{bucket}"}
        client.delete(
            api_spec,
            bucket=self.name,
        )
        return True

    def update_tag(self, key: str, value: Optional[str]) -> bool:
        client = get_client(self)

        labels = dict(self.tags)
        if value is None:
            if key in labels:
                del labels[key]
            else:
                return False
        else:
            labels.update({key: value})

        api_spec = self.api_spec.for_set_labels()
        api_spec.action = "patch"
        api_spec.request_parameter = {"bucket": "{bucket}"}
        client.set_labels(
            api_spec,
            body={"labels": labels},
            bucket=self.name,
        )
        return True

    def delete_tag(self, key: str) -> bool:
        return self.update_tag(key, None)


resources = [GcpBucket]
