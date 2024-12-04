from datetime import datetime
from functools import partial
from typing import ClassVar, Dict, Optional, List, Type, Any

from attr import define, field

from fix_plugin_gcp.gcp_client import GcpApiSpec
from fix_plugin_gcp.resources.base import GcpResource, GraphBuilder, GcpErrorHandler, GcpProject, GcpExpectedErrorCodes
from fixlib.baseresources import SEVERITY_MAPPING, Finding, Severity
from fixlib.json_bender import Bender, S, Bend, ForallBend, MapDict
from fixlib.types import Json


@define(eq=False, slots=False)
class GcpFolder:
    kind: ClassVar[str] = "gcp_folder"
    mapping: ClassVar[Dict[str, Bender]] = {
        "resource_folder": S("resourceFolder"),
        "resource_folder_display_name": S("resourceFolderDisplayName"),
    }
    resource_folder: Optional[str] = field(default=None)
    resource_folder_display_name: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpSecurityMarks:
    kind: ClassVar[str] = "gcp_security_marks"
    mapping: ClassVar[Dict[str, Bender]] = {
        "canonical_name": S("canonicalName"),
        "marks": S("marks"),
        "name": S("name"),
    }
    canonical_name: Optional[str] = field(default=None)
    marks: Optional[Dict[str, str]] = field(default=None)
    name: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpServiceAccountDelegationInfo:
    kind: ClassVar[str] = "gcp_service_account_delegation_info"
    mapping: ClassVar[Dict[str, Bender]] = {
        "principal_email": S("principalEmail"),
        "principal_subject": S("principalSubject"),
    }
    principal_email: Optional[str] = field(default=None)
    principal_subject: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpAccess:
    kind: ClassVar[str] = "gcp_access"
    mapping: ClassVar[Dict[str, Bender]] = {
        "caller_ip": S("callerIp"),
        "caller_ip_geo": S("callerIpGeo", "regionCode"),
        "method_name": S("methodName"),
        "principal_email": S("principalEmail"),
        "principal_subject": S("principalSubject"),
        "service_account_delegation_info": S("serviceAccountDelegationInfo", default=[])
        >> ForallBend(GcpServiceAccountDelegationInfo.mapping),
        "service_account_key_name": S("serviceAccountKeyName"),
        "service_name": S("serviceName"),
        "user_agent": S("userAgent"),
        "user_agent_family": S("userAgentFamily"),
        "user_name": S("userName"),
    }
    caller_ip: Optional[str] = field(default=None)
    caller_ip_geo: Optional[str] = field(default=None)
    method_name: Optional[str] = field(default=None)
    principal_email: Optional[str] = field(default=None)
    principal_subject: Optional[str] = field(default=None)
    service_account_delegation_info: Optional[List[GcpServiceAccountDelegationInfo]] = field(default=None)
    service_account_key_name: Optional[str] = field(default=None)
    service_name: Optional[str] = field(default=None)
    user_agent: Optional[str] = field(default=None)
    user_agent_family: Optional[str] = field(default=None)
    user_name: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpApplication:
    kind: ClassVar[str] = "gcp_application"
    mapping: ClassVar[Dict[str, Bender]] = {"base_uri": S("baseUri"), "full_uri": S("fullUri")}
    base_uri: Optional[str] = field(default=None)
    full_uri: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpAttackExposure:
    kind: ClassVar[str] = "gcp_attack_exposure"
    mapping: ClassVar[Dict[str, Bender]] = {
        "attack_exposure_result": S("attackExposureResult"),
        "exposed_high_value_resources_count": S("exposedHighValueResourcesCount"),
        "exposed_low_value_resources_count": S("exposedLowValueResourcesCount"),
        "exposed_medium_value_resources_count": S("exposedMediumValueResourcesCount"),
        "latest_calculation_time": S("latestCalculationTime"),
        "score": S("score"),
        "state": S("state"),
    }
    attack_exposure_result: Optional[str] = field(default=None)
    exposed_high_value_resources_count: Optional[int] = field(default=None)
    exposed_low_value_resources_count: Optional[int] = field(default=None)
    exposed_medium_value_resources_count: Optional[int] = field(default=None)
    latest_calculation_time: Optional[datetime] = field(default=None)
    score: Optional[float] = field(default=None)
    state: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpBackupDisasterRecovery:
    kind: ClassVar[str] = "gcp_backup_disaster_recovery"
    mapping: ClassVar[Dict[str, Bender]] = {
        "appliance": S("appliance"),
        "applications": S("applications", default=[]),
        "backup_create_time": S("backupCreateTime"),
        "backup_template": S("backupTemplate"),
        "backup_type": S("backupType"),
        "host": S("host"),
        "policies": S("policies", default=[]),
        "policy_options": S("policyOptions", default=[]),
        "profile": S("profile"),
        "storage_pool": S("storagePool"),
    }
    appliance: Optional[str] = field(default=None)
    applications: Optional[List[str]] = field(default=None)
    backup_create_time: Optional[datetime] = field(default=None)
    backup_template: Optional[str] = field(default=None)
    backup_type: Optional[str] = field(default=None)
    host: Optional[str] = field(default=None)
    policies: Optional[List[str]] = field(default=None)
    policy_options: Optional[List[str]] = field(default=None)
    profile: Optional[str] = field(default=None)
    storage_pool: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpAttack:
    kind: ClassVar[str] = "gcp_attack"
    mapping: ClassVar[Dict[str, Bender]] = {
        "classification": S("classification"),
        "volume_bps": S("volumeBps"),
        "volume_pps": S("volumePps"),
    }
    classification: Optional[str] = field(default=None)
    volume_bps: Optional[int] = field(default=None)
    volume_pps: Optional[int] = field(default=None)


@define(eq=False, slots=False)
class GcpRequests:
    kind: ClassVar[str] = "gcp_requests"
    mapping: ClassVar[Dict[str, Bender]] = {
        "long_term_allowed": S("longTermAllowed"),
        "long_term_denied": S("longTermDenied"),
        "ratio": S("ratio"),
        "short_term_allowed": S("shortTermAllowed"),
    }
    long_term_allowed: Optional[int] = field(default=None)
    long_term_denied: Optional[int] = field(default=None)
    ratio: Optional[float] = field(default=None)
    short_term_allowed: Optional[int] = field(default=None)


@define(eq=False, slots=False)
class GcpSecurityPolicy:
    kind: ClassVar[str] = "gcp_security_policy"
    mapping: ClassVar[Dict[str, Bender]] = {"name": S("name"), "preview": S("preview"), "type": S("type")}
    name: Optional[str] = field(default=None)
    preview: Optional[bool] = field(default=None)
    type: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpCloudArmor:
    kind: ClassVar[str] = "gcp_cloud_armor"
    mapping: ClassVar[Dict[str, Bender]] = {
        "adaptive_protection": S("adaptiveProtection", "confidence"),
        "attack": S("attack", default={}) >> Bend(GcpAttack.mapping),
        "duration": S("duration"),
        "requests": S("requests", default={}) >> Bend(GcpRequests.mapping),
        "security_policy": S("securityPolicy", default={}) >> Bend(GcpSecurityPolicy.mapping),
        "threat_vector": S("threatVector"),
    }
    adaptive_protection: Optional[float] = field(default=None)
    attack: Optional[GcpAttack] = field(default=None)
    duration: Optional[str] = field(default=None)
    requests: Optional[GcpRequests] = field(default=None)
    security_policy: Optional[GcpSecurityPolicy] = field(default=None)
    threat_vector: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpCloudDlpDataProfile:
    kind: ClassVar[str] = "gcp_cloud_dlp_data_profile"
    mapping: ClassVar[Dict[str, Bender]] = {"data_profile": S("dataProfile"), "parent_type": S("parentType")}
    data_profile: Optional[str] = field(default=None)
    parent_type: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpCloudDlpInspection:
    kind: ClassVar[str] = "gcp_cloud_dlp_inspection"
    mapping: ClassVar[Dict[str, Bender]] = {
        "full_scan": S("fullScan"),
        "info_type": S("infoType"),
        "info_type_count": S("infoTypeCount"),
        "inspect_job": S("inspectJob"),
    }
    full_scan: Optional[bool] = field(default=None)
    info_type: Optional[str] = field(default=None)
    info_type_count: Optional[str] = field(default=None)
    inspect_job: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpCompliance:
    kind: ClassVar[str] = "gcp_compliance"
    mapping: ClassVar[Dict[str, Bender]] = {
        "ids": S("ids", default=[]),
        "standard": S("standard"),
        "version": S("version"),
    }
    ids: Optional[List[str]] = field(default=None)
    standard: Optional[str] = field(default=None)
    version: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpConnection:
    kind: ClassVar[str] = "gcp_connection"
    mapping: ClassVar[Dict[str, Bender]] = {
        "destination_ip": S("destinationIp"),
        "destination_port": S("destinationPort"),
        "protocol": S("protocol"),
        "source_ip": S("sourceIp"),
        "source_port": S("sourcePort"),
    }
    destination_ip: Optional[str] = field(default=None)
    destination_port: Optional[int] = field(default=None)
    protocol: Optional[str] = field(default=None)
    source_ip: Optional[str] = field(default=None)
    source_port: Optional[int] = field(default=None)


@define(eq=False, slots=False)
class GcpContactDetails:
    kind: ClassVar[str] = "gcp_contact_details"
    mapping: ClassVar[Dict[str, Bender]] = {"contacts": S("contacts", default=[]) >> ForallBend(S("email"))}
    contacts: Optional[List[str]] = field(default=None)


@define(eq=False, slots=False)
class GcpLabel:
    kind: ClassVar[str] = "gcp_label"
    mapping: ClassVar[Dict[str, Bender]] = {"name": S("name"), "value": S("value")}
    name: Optional[str] = field(default=None)
    value: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpContainer:
    kind: ClassVar[str] = "gcp_container"
    mapping: ClassVar[Dict[str, Bender]] = {
        "create_time": S("createTime"),
        "image_id": S("imageId"),
        "labels": S("labels", default=[]) >> ForallBend(GcpLabel.mapping),
        "name": S("name"),
        "uri": S("uri"),
    }
    create_time: Optional[datetime] = field(default=None)
    image_id: Optional[str] = field(default=None)
    labels: Optional[List[GcpLabel]] = field(default=None)
    name: Optional[str] = field(default=None)
    uri: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpDataAccessEvent:
    kind: ClassVar[str] = "gcp_data_access_event"
    mapping: ClassVar[Dict[str, Bender]] = {
        "event_id": S("eventId"),
        "event_time": S("eventTime"),
        "operation": S("operation"),
        "principal_email": S("principalEmail"),
    }
    event_id: Optional[str] = field(default=None)
    event_time: Optional[datetime] = field(default=None)
    operation: Optional[str] = field(default=None)
    principal_email: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpDataFlowEvent:
    kind: ClassVar[str] = "gcp_data_flow_event"
    mapping: ClassVar[Dict[str, Bender]] = {
        "event_id": S("eventId"),
        "event_time": S("eventTime"),
        "operation": S("operation"),
        "principal_email": S("principalEmail"),
        "violated_location": S("violatedLocation"),
    }
    event_id: Optional[str] = field(default=None)
    event_time: Optional[datetime] = field(default=None)
    operation: Optional[str] = field(default=None)
    principal_email: Optional[str] = field(default=None)
    violated_location: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpDatabase:
    kind: ClassVar[str] = "gcp_database"
    mapping: ClassVar[Dict[str, Bender]] = {
        "display_name": S("displayName"),
        "grantees": S("grantees", default=[]),
        "name": S("name"),
        "query": S("query"),
        "user_name": S("userName"),
        "version": S("version"),
    }
    display_name: Optional[str] = field(default=None)
    grantees: Optional[List[str]] = field(default=None)
    name: Optional[str] = field(default=None)
    query: Optional[str] = field(default=None)
    user_name: Optional[str] = field(default=None)
    version: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpExfilResource:
    kind: ClassVar[str] = "gcp_exfil_resource"
    mapping: ClassVar[Dict[str, Bender]] = {"components": S("components", default=[]), "name": S("name")}
    components: Optional[List[str]] = field(default=None)
    name: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpExfiltration:
    kind: ClassVar[str] = "gcp_exfiltration"
    mapping: ClassVar[Dict[str, Bender]] = {
        "sources": S("sources", default=[]) >> ForallBend(GcpExfilResource.mapping),
        "targets": S("targets", default=[]) >> ForallBend(GcpExfilResource.mapping),
        "total_exfiltrated_bytes": S("totalExfiltratedBytes"),
    }
    sources: Optional[List[GcpExfilResource]] = field(default=None)
    targets: Optional[List[GcpExfilResource]] = field(default=None)
    total_exfiltrated_bytes: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpTicketInfo:
    kind: ClassVar[str] = "gcp_ticket_info"
    mapping: ClassVar[Dict[str, Bender]] = {
        "assignee": S("assignee"),
        "description": S("description"),
        "id": S("id"),
        "status": S("status"),
        "update_time": S("updateTime"),
        "uri": S("uri"),
    }
    assignee: Optional[str] = field(default=None)
    description: Optional[str] = field(default=None)
    id: Optional[str] = field(default=None)
    status: Optional[str] = field(default=None)
    update_time: Optional[datetime] = field(default=None)
    uri: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpGoogleCloudSecuritycenterV1ExternalSystem:
    kind: ClassVar[str] = "gcp_google_cloud_securitycenter_v1_external_system"
    mapping: ClassVar[Dict[str, Bender]] = {
        "assignees": S("assignees", default=[]),
        "case_close_time": S("caseCloseTime"),
        "case_create_time": S("caseCreateTime"),
        "case_priority": S("casePriority"),
        "case_sla": S("caseSla"),
        "case_uri": S("caseUri"),
        "external_system_update_time": S("externalSystemUpdateTime"),
        "external_uid": S("externalUid"),
        "name": S("name"),
        "status": S("status"),
        "ticket_info": S("ticketInfo", default={}) >> Bend(GcpTicketInfo.mapping),
    }
    assignees: Optional[List[str]] = field(default=None)
    case_close_time: Optional[datetime] = field(default=None)
    case_create_time: Optional[datetime] = field(default=None)
    case_priority: Optional[str] = field(default=None)
    case_sla: Optional[datetime] = field(default=None)
    case_uri: Optional[str] = field(default=None)
    external_system_update_time: Optional[datetime] = field(default=None)
    external_uid: Optional[str] = field(default=None)
    name: Optional[str] = field(default=None)
    status: Optional[str] = field(default=None)
    ticket_info: Optional[GcpTicketInfo] = field(default=None)


@define(eq=False, slots=False)
class GcpDiskPath:
    kind: ClassVar[str] = "gcp_disk_path"
    mapping: ClassVar[Dict[str, Bender]] = {"partition_uuid": S("partitionUuid"), "relative_path": S("relativePath")}
    partition_uuid: Optional[str] = field(default=None)
    relative_path: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpFile:
    kind: ClassVar[str] = "gcp_file"
    mapping: ClassVar[Dict[str, Bender]] = {
        "contents": S("contents"),
        "disk_path": S("diskPath", default={}) >> Bend(GcpDiskPath.mapping),
        "hashed_size": S("hashedSize"),
        "partially_hashed": S("partiallyHashed"),
        "path": S("path"),
        "sha256": S("sha256"),
        "size": S("size"),
    }
    contents: Optional[str] = field(default=None)
    disk_path: Optional[GcpDiskPath] = field(default=None)
    hashed_size: Optional[str] = field(default=None)
    partially_hashed: Optional[bool] = field(default=None)
    path: Optional[str] = field(default=None)
    sha256: Optional[str] = field(default=None)
    size: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpGroupMembership:
    kind: ClassVar[str] = "gcp_group_membership"
    mapping: ClassVar[Dict[str, Bender]] = {"group_id": S("groupId"), "group_type": S("groupType")}
    group_id: Optional[str] = field(default=None)
    group_type: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpIamBinding:
    kind: ClassVar[str] = "gcp_iam_binding"
    mapping: ClassVar[Dict[str, Bender]] = {"action": S("action"), "member": S("member"), "role": S("role")}
    action: Optional[str] = field(default=None)
    member: Optional[str] = field(default=None)
    role: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpDetection:
    kind: ClassVar[str] = "gcp_detection"
    mapping: ClassVar[Dict[str, Bender]] = {"binary": S("binary"), "percent_pages_matched": S("percentPagesMatched")}
    binary: Optional[str] = field(default=None)
    percent_pages_matched: Optional[float] = field(default=None)


@define(eq=False, slots=False)
class GcpMemoryHashSignature:
    kind: ClassVar[str] = "gcp_memory_hash_signature"
    mapping: ClassVar[Dict[str, Bender]] = {
        "binary_family": S("binaryFamily"),
        "detections": S("detections", default=[]) >> ForallBend(GcpDetection.mapping),
    }
    binary_family: Optional[str] = field(default=None)
    detections: Optional[List[GcpDetection]] = field(default=None)


@define(eq=False, slots=False)
class GcpProcessSignature:
    kind: ClassVar[str] = "gcp_process_signature"
    mapping: ClassVar[Dict[str, Bender]] = {
        "memory_hash_signature": S("memoryHashSignature", default={}) >> Bend(GcpMemoryHashSignature.mapping),
        "signature_type": S("signatureType"),
        "yara_rule_signature": S("yaraRuleSignature", "yaraRule"),
    }
    memory_hash_signature: Optional[GcpMemoryHashSignature] = field(default=None)
    signature_type: Optional[str] = field(default=None)
    yara_rule_signature: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpIndicator:
    kind: ClassVar[str] = "gcp_indicator"
    mapping: ClassVar[Dict[str, Bender]] = {
        "domains": S("domains", default=[]),
        "ip_addresses": S("ipAddresses", default=[]),
        "signatures": S("signatures", default=[]) >> ForallBend(GcpProcessSignature.mapping),
        "uris": S("uris", default=[]),
    }
    domains: Optional[List[str]] = field(default=None)
    ip_addresses: Optional[List[str]] = field(default=None)
    signatures: Optional[List[GcpProcessSignature]] = field(default=None)
    uris: Optional[List[str]] = field(default=None)


@define(eq=False, slots=False)
class GcpKernelRootkit:
    kind: ClassVar[str] = "gcp_kernel_rootkit"
    mapping: ClassVar[Dict[str, Bender]] = {
        "name": S("name"),
        "unexpected_code_modification": S("unexpectedCodeModification"),
        "unexpected_ftrace_handler": S("unexpectedFtraceHandler"),
        "unexpected_interrupt_handler": S("unexpectedInterruptHandler"),
        "unexpected_kernel_code_pages": S("unexpectedKernelCodePages"),
        "unexpected_kprobe_handler": S("unexpectedKprobeHandler"),
        "unexpected_processes_in_runqueue": S("unexpectedProcessesInRunqueue"),
        "unexpected_read_only_data_modification": S("unexpectedReadOnlyDataModification"),
        "unexpected_system_call_handler": S("unexpectedSystemCallHandler"),
    }
    name: Optional[str] = field(default=None)
    unexpected_code_modification: Optional[bool] = field(default=None)
    unexpected_ftrace_handler: Optional[bool] = field(default=None)
    unexpected_interrupt_handler: Optional[bool] = field(default=None)
    unexpected_kernel_code_pages: Optional[bool] = field(default=None)
    unexpected_kprobe_handler: Optional[bool] = field(default=None)
    unexpected_processes_in_runqueue: Optional[bool] = field(default=None)
    unexpected_read_only_data_modification: Optional[bool] = field(default=None)
    unexpected_system_call_handler: Optional[bool] = field(default=None)


@define(eq=False, slots=False)
class GcpAccessReview:
    kind: ClassVar[str] = "gcp_access_review"
    mapping: ClassVar[Dict[str, Bender]] = {
        "group": S("group"),
        "name": S("name"),
        "ns": S("ns"),
        "resource": S("resource"),
        "subresource": S("subresource"),
        "verb": S("verb"),
        "version": S("version"),
    }
    group: Optional[str] = field(default=None)
    name: Optional[str] = field(default=None)
    ns: Optional[str] = field(default=None)
    resource: Optional[str] = field(default=None)
    subresource: Optional[str] = field(default=None)
    verb: Optional[str] = field(default=None)
    version: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpRole:
    kind: ClassVar[str] = "gcp_role"
    mapping: ClassVar[Dict[str, Bender]] = {"name": S("name"), "ns": S("ns")}
    name: Optional[str] = field(default=None)
    ns: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpSubject:
    kind: ClassVar[str] = "gcp_subject"
    mapping: ClassVar[Dict[str, Bender]] = {"name": S("name"), "ns": S("ns")}
    name: Optional[str] = field(default=None)
    ns: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpGoogleCloudSecuritycenterV1Binding:
    kind: ClassVar[str] = "gcp_google_cloud_securitycenter_v1_binding"
    mapping: ClassVar[Dict[str, Bender]] = {
        "name": S("name"),
        "ns": S("ns"),
        "role": S("role", default={}) >> Bend(GcpRole.mapping),
        "subjects": S("subjects", default=[]) >> ForallBend(GcpSubject.mapping),
    }
    name: Optional[str] = field(default=None)
    ns: Optional[str] = field(default=None)
    role: Optional[GcpRole] = field(default=None)
    subjects: Optional[List[GcpSubject]] = field(default=None)


@define(eq=False, slots=False)
class GcpNodePool:
    kind: ClassVar[str] = "gcp_node_pool"
    mapping: ClassVar[Dict[str, Bender]] = {"name": S("name"), "nodes": S("nodes", default=[]) >> ForallBend(S("name"))}
    name: Optional[str] = field(default=None)
    nodes: Optional[List[str]] = field(default=None)


@define(eq=False, slots=False)
class GcpObject:
    kind: ClassVar[str] = "gcp_object"
    mapping: ClassVar[Dict[str, Bender]] = {
        "containers": S("containers", default=[]) >> ForallBend(GcpContainer.mapping),
        "group": S("group"),
        "name": S("name"),
        "ns": S("ns"),
    }
    containers: Optional[List[GcpContainer]] = field(default=None)
    group: Optional[str] = field(default=None)
    name: Optional[str] = field(default=None)
    ns: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpPod:
    kind: ClassVar[str] = "gcp_pod"
    mapping: ClassVar[Dict[str, Bender]] = {
        "containers": S("containers", default=[]) >> ForallBend(GcpContainer.mapping),
        "labels": S("labels", default=[]) >> ForallBend(GcpLabel.mapping),
        "name": S("name"),
        "ns": S("ns"),
    }
    containers: Optional[List[GcpContainer]] = field(default=None)
    labels: Optional[List[GcpLabel]] = field(default=None)
    name: Optional[str] = field(default=None)
    ns: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpKubernetes:
    kind: ClassVar[str] = "gcp_kubernetes"
    mapping: ClassVar[Dict[str, Bender]] = {
        "access_reviews": S("accessReviews", default=[]) >> ForallBend(GcpAccessReview.mapping),
        "bindings": S("bindings", default=[]) >> ForallBend(GcpGoogleCloudSecuritycenterV1Binding.mapping),
        "node_pools": S("nodePools", default=[]) >> ForallBend(GcpNodePool.mapping),
        "nodes": S("nodes", default=[]) >> ForallBend(S("name")),
        "objects": S("objects", default=[]) >> ForallBend(GcpObject.mapping),
        "pods": S("pods", default=[]) >> ForallBend(GcpPod.mapping),
        "roles": S("roles", default=[]) >> ForallBend(GcpRole.mapping),
    }
    access_reviews: Optional[List[GcpAccessReview]] = field(default=None)
    bindings: Optional[List[GcpGoogleCloudSecuritycenterV1Binding]] = field(default=None)
    node_pools: Optional[List[GcpNodePool]] = field(default=None)
    nodes: Optional[List[str]] = field(default=None)
    objects: Optional[List[GcpObject]] = field(default=None)
    pods: Optional[List[GcpPod]] = field(default=None)
    roles: Optional[List[GcpRole]] = field(default=None)


@define(eq=False, slots=False)
class GcpCloudLoggingEntry:
    kind: ClassVar[str] = "gcp_cloud_logging_entry"
    mapping: ClassVar[Dict[str, Bender]] = {
        "insert_id": S("insertId"),
        "log_id": S("logId"),
        "resource_container": S("resourceContainer"),
        "timestamp": S("timestamp"),
    }
    insert_id: Optional[str] = field(default=None)
    log_id: Optional[str] = field(default=None)
    resource_container: Optional[str] = field(default=None)
    timestamp: Optional[datetime] = field(default=None)


@define(eq=False, slots=False)
class GcpLogEntry:
    kind: ClassVar[str] = "gcp_log_entry"
    mapping: ClassVar[Dict[str, Bender]] = {
        "cloud_logging_entry": S("cloudLoggingEntry", default={}) >> Bend(GcpCloudLoggingEntry.mapping)
    }
    cloud_logging_entry: Optional[GcpCloudLoggingEntry] = field(default=None)


@define(eq=False, slots=False)
class GcpMitreAttack:
    kind: ClassVar[str] = "gcp_mitre_attack"
    mapping: ClassVar[Dict[str, Bender]] = {
        "additional_tactics": S("additionalTactics", default=[]),
        "additional_techniques": S("additionalTechniques", default=[]),
        "primary_tactic": S("primaryTactic"),
        "primary_techniques": S("primaryTechniques", default=[]),
        "version": S("version"),
    }
    additional_tactics: Optional[List[str]] = field(default=None)
    additional_techniques: Optional[List[str]] = field(default=None)
    primary_tactic: Optional[str] = field(default=None)
    primary_techniques: Optional[List[str]] = field(default=None)
    version: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpDynamicMuteRecord:
    kind: ClassVar[str] = "gcp_dynamic_mute_record"
    mapping: ClassVar[Dict[str, Bender]] = {"match_time": S("matchTime"), "mute_config": S("muteConfig")}
    match_time: Optional[datetime] = field(default=None)
    mute_config: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpStaticMute:
    kind: ClassVar[str] = "gcp_static_mute"
    mapping: ClassVar[Dict[str, Bender]] = {"apply_time": S("applyTime"), "state": S("state")}
    apply_time: Optional[datetime] = field(default=None)
    state: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpMuteInfo:
    kind: ClassVar[str] = "gcp_mute_info"
    mapping: ClassVar[Dict[str, Bender]] = {
        "dynamic_mute_records": S("dynamicMuteRecords", default=[]) >> ForallBend(GcpDynamicMuteRecord.mapping),
        "static_mute": S("staticMute", default={}) >> Bend(GcpStaticMute.mapping),
    }
    dynamic_mute_records: Optional[List[GcpDynamicMuteRecord]] = field(default=None)
    static_mute: Optional[GcpStaticMute] = field(default=None)


@define(eq=False, slots=False)
class GcpNotebook:
    kind: ClassVar[str] = "gcp_notebook"
    mapping: ClassVar[Dict[str, Bender]] = {
        "last_author": S("lastAuthor"),
        "name": S("name"),
        "notebook_update_time": S("notebookUpdateTime"),
        "service": S("service"),
    }
    last_author: Optional[str] = field(default=None)
    name: Optional[str] = field(default=None)
    notebook_update_time: Optional[datetime] = field(default=None)
    service: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpEnvironmentVariable:
    kind: ClassVar[str] = "gcp_environment_variable"
    mapping: ClassVar[Dict[str, Bender]] = {"name": S("name"), "val": S("val")}
    name: Optional[str] = field(default=None)
    val: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpProcess:
    kind: ClassVar[str] = "gcp_process"
    mapping: ClassVar[Dict[str, Bender]] = {
        "args": S("args", default=[]),
        "arguments_truncated": S("argumentsTruncated"),
        "binary": S("binary", default={}) >> Bend(GcpFile.mapping),
        "env_variables": S("envVariables", default=[]) >> ForallBend(GcpEnvironmentVariable.mapping),
        "env_variables_truncated": S("envVariablesTruncated"),
        "libraries": S("libraries", default=[]) >> ForallBend(GcpFile.mapping),
        "name": S("name"),
        "parent_pid": S("parentPid"),
        "pid": S("pid"),
        "script": S("script", default={}) >> Bend(GcpFile.mapping),
    }
    args: Optional[List[str]] = field(default=None)
    arguments_truncated: Optional[bool] = field(default=None)
    binary: Optional[GcpFile] = field(default=None)
    env_variables: Optional[List[GcpEnvironmentVariable]] = field(default=None)
    env_variables_truncated: Optional[bool] = field(default=None)
    libraries: Optional[List[GcpFile]] = field(default=None)
    name: Optional[str] = field(default=None)
    parent_pid: Optional[str] = field(default=None)
    pid: Optional[str] = field(default=None)
    script: Optional[GcpFile] = field(default=None)


@define(eq=False, slots=False)
class GcpPolicyDriftDetails:
    kind: ClassVar[str] = "gcp_policy_drift_details"
    mapping: ClassVar[Dict[str, Bender]] = {
        "detected_value": S("detectedValue"),
        "expected_value": S("expectedValue"),
        "field": S("field"),
    }
    detected_value: Optional[str] = field(default=None)
    expected_value: Optional[str] = field(default=None)
    field: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpSecurityPosture:
    kind: ClassVar[str] = "gcp_security_posture"
    mapping: ClassVar[Dict[str, Bender]] = {
        "changed_policy": S("changedPolicy"),
        "name": S("name"),
        "policy": S("policy"),
        "policy_drift_details": S("policyDriftDetails", default=[]) >> ForallBend(GcpPolicyDriftDetails.mapping),
        "policy_set": S("policySet"),
        "posture_deployment": S("postureDeployment"),
        "posture_deployment_resource": S("postureDeploymentResource"),
        "revision_id": S("revisionId"),
    }
    changed_policy: Optional[str] = field(default=None)
    name: Optional[str] = field(default=None)
    policy: Optional[str] = field(default=None)
    policy_drift_details: Optional[List[GcpPolicyDriftDetails]] = field(default=None)
    policy_set: Optional[str] = field(default=None)
    posture_deployment: Optional[str] = field(default=None)
    posture_deployment_resource: Optional[str] = field(default=None)
    revision_id: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpSourceProperties:
    kind: ClassVar[str] = "gcp_source_properties"
    mapping: ClassVar[Dict[str, Bender]] = {
        "recommendation": S("Recommendation"),
    }
    recommendation: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpToxicCombination:
    kind: ClassVar[str] = "gcp_toxic_combination"
    mapping: ClassVar[Dict[str, Bender]] = {
        "attack_exposure_score": S("attackExposureScore"),
        "related_findings": S("relatedFindings", default=[]),
    }
    attack_exposure_score: Optional[float] = field(default=None)
    related_findings: Optional[List[str]] = field(default=None)


@define(eq=False, slots=False)
class GcpCvssv3:
    kind: ClassVar[str] = "gcp_cvssv3"
    mapping: ClassVar[Dict[str, Bender]] = {
        "attack_complexity": S("attackComplexity"),
        "attack_vector": S("attackVector"),
        "availability_impact": S("availabilityImpact"),
        "base_score": S("baseScore"),
        "confidentiality_impact": S("confidentialityImpact"),
        "integrity_impact": S("integrityImpact"),
        "privileges_required": S("privilegesRequired"),
        "scope": S("scope"),
        "user_interaction": S("userInteraction"),
    }
    attack_complexity: Optional[str] = field(default=None)
    attack_vector: Optional[str] = field(default=None)
    availability_impact: Optional[str] = field(default=None)
    base_score: Optional[float] = field(default=None)
    confidentiality_impact: Optional[str] = field(default=None)
    integrity_impact: Optional[str] = field(default=None)
    privileges_required: Optional[str] = field(default=None)
    scope: Optional[str] = field(default=None)
    user_interaction: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpReference:
    kind: ClassVar[str] = "gcp_reference"
    mapping: ClassVar[Dict[str, Bender]] = {"source": S("source"), "uri": S("uri")}
    source: Optional[str] = field(default=None)
    uri: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpCve:
    kind: ClassVar[str] = "gcp_cve"
    mapping: ClassVar[Dict[str, Bender]] = {
        "cvssv3": S("cvssv3", default={}) >> Bend(GcpCvssv3.mapping),
        "exploit_release_date": S("exploitReleaseDate"),
        "exploitation_activity": S("exploitationActivity"),
        "first_exploitation_date": S("firstExploitationDate"),
        "id": S("id"),
        "impact": S("impact"),
        "observed_in_the_wild": S("observedInTheWild"),
        "references": S("references", default=[]) >> ForallBend(GcpReference.mapping),
        "upstream_fix_available": S("upstreamFixAvailable"),
        "zero_day": S("zeroDay"),
    }
    cvssv3: Optional[GcpCvssv3] = field(default=None)
    exploit_release_date: Optional[datetime] = field(default=None)
    exploitation_activity: Optional[str] = field(default=None)
    first_exploitation_date: Optional[datetime] = field(default=None)
    id: Optional[str] = field(default=None)
    impact: Optional[str] = field(default=None)
    observed_in_the_wild: Optional[bool] = field(default=None)
    references: Optional[List[GcpReference]] = field(default=None)
    upstream_fix_available: Optional[bool] = field(default=None)
    zero_day: Optional[bool] = field(default=None)


@define(eq=False, slots=False)
class GcpPackage:
    kind: ClassVar[str] = "gcp_package"
    mapping: ClassVar[Dict[str, Bender]] = {
        "cpe_uri": S("cpeUri"),
        "package_name": S("packageName"),
        "package_type": S("packageType"),
        "package_version": S("packageVersion"),
    }
    cpe_uri: Optional[str] = field(default=None)
    package_name: Optional[str] = field(default=None)
    package_type: Optional[str] = field(default=None)
    package_version: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpSecurityBulletin:
    kind: ClassVar[str] = "gcp_security_bulletin"
    mapping: ClassVar[Dict[str, Bender]] = {
        "bulletin_id": S("bulletinId"),
        "submission_time": S("submissionTime"),
        "suggested_upgrade_version": S("suggestedUpgradeVersion"),
    }
    bulletin_id: Optional[str] = field(default=None)
    submission_time: Optional[datetime] = field(default=None)
    suggested_upgrade_version: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpVulnerability:
    kind: ClassVar[str] = "gcp_vulnerability"
    mapping: ClassVar[Dict[str, Bender]] = {
        "cve": S("cve", default={}) >> Bend(GcpCve.mapping),
        "fixed_package": S("fixedPackage", default={}) >> Bend(GcpPackage.mapping),
        "offending_package": S("offendingPackage", default={}) >> Bend(GcpPackage.mapping),
        "security_bulletin": S("securityBulletin", default={}) >> Bend(GcpSecurityBulletin.mapping),
    }
    cve: Optional[GcpCve] = field(default=None)
    fixed_package: Optional[GcpPackage] = field(default=None)
    offending_package: Optional[GcpPackage] = field(default=None)
    security_bulletin: Optional[GcpSecurityBulletin] = field(default=None)


@define(eq=False, slots=False)
class GcpFinding:
    kind: ClassVar[str] = "gcp_finding"
    mapping: ClassVar[Dict[str, Bender]] = {
        "access": S("access", default={}) >> Bend(GcpAccess.mapping),
        "application": S("application", default={}) >> Bend(GcpApplication.mapping),
        "attack_exposure": S("attackExposure", default={}) >> Bend(GcpAttackExposure.mapping),
        "backup_disaster_recovery": S("backupDisasterRecovery", default={}) >> Bend(GcpBackupDisasterRecovery.mapping),
        "canonical_name": S("canonicalName"),
        "category": S("category"),
        "cloud_armor": S("cloudArmor", default={}) >> Bend(GcpCloudArmor.mapping),
        "cloud_dlp_data_profile": S("cloudDlpDataProfile", default={}) >> Bend(GcpCloudDlpDataProfile.mapping),
        "cloud_dlp_inspection": S("cloudDlpInspection", default={}) >> Bend(GcpCloudDlpInspection.mapping),
        "compliances": S("compliances", default=[]) >> ForallBend(GcpCompliance.mapping),
        "connections": S("connections", default=[]) >> ForallBend(GcpConnection.mapping),
        "contacts": S("contacts", default={}) >> MapDict(value_bender=Bend(GcpContactDetails.mapping)),
        "containers": S("containers", default=[]) >> ForallBend(GcpContainer.mapping),
        "create_time": S("createTime"),
        "data_access_events": S("dataAccessEvents", default=[]) >> ForallBend(GcpDataAccessEvent.mapping),
        "data_flow_events": S("dataFlowEvents", default=[]) >> ForallBend(GcpDataFlowEvent.mapping),
        "database": S("database", default={}) >> Bend(GcpDatabase.mapping),
        "description": S("description"),
        "event_time": S("eventTime"),
        "exfiltration": S("exfiltration", default={}) >> Bend(GcpExfiltration.mapping),
        "external_systems": S("externalSystems", default={})
        >> MapDict(value_bender=Bend(GcpGoogleCloudSecuritycenterV1ExternalSystem.mapping)),
        "external_uri": S("externalUri"),
        "files": S("files", default=[]) >> ForallBend(GcpFile.mapping),
        "finding_class": S("findingClass"),
        "group_memberships": S("groupMemberships", default=[]) >> ForallBend(GcpGroupMembership.mapping),
        "iam_bindings": S("iamBindings", default=[]) >> ForallBend(GcpIamBinding.mapping),
        "indicator": S("indicator", default={}) >> Bend(GcpIndicator.mapping),
        "kernel_rootkit": S("kernelRootkit", default={}) >> Bend(GcpKernelRootkit.mapping),
        "kubernetes": S("kubernetes", default={}) >> Bend(GcpKubernetes.mapping),
        "load_balancers": S("loadBalancers", default=[]) >> ForallBend(S("name")),
        "log_entries": S("logEntries", default=[]) >> ForallBend(GcpLogEntry.mapping),
        "mitre_attack": S("mitreAttack", default={}) >> Bend(GcpMitreAttack.mapping),
        "module_name": S("moduleName"),
        "mute": S("mute"),
        "mute_info": S("muteInfo", default={}) >> Bend(GcpMuteInfo.mapping),
        "mute_initiator": S("muteInitiator"),
        "mute_update_time": S("muteUpdateTime"),
        "name": S("name"),
        "next_steps": S("nextSteps"),
        "notebook": S("notebook", default={}) >> Bend(GcpNotebook.mapping),
        "org_policies": S("orgPolicies", default=[]) >> ForallBend(S("name")),
        "parent": S("parent"),
        "parent_display_name": S("parentDisplayName"),
        "processes": S("processes", default=[]) >> ForallBend(GcpProcess.mapping),
        "resource_name": S("resourceName"),
        "security_marks": S("securityMarks", default={}) >> Bend(GcpSecurityMarks.mapping),
        "security_posture": S("securityPosture", default={}) >> Bend(GcpSecurityPosture.mapping),
        "severity": S("severity"),
        "source_properties": S("sourceProperties", default={}) >> Bend(GcpSourceProperties.mapping),
        "state": S("state"),
        "toxic_combination": S("toxicCombination", default={}) >> Bend(GcpToxicCombination.mapping),
        "vulnerability": S("vulnerability", default={}) >> Bend(GcpVulnerability.mapping),
    }
    access: Optional[GcpAccess] = field(default=None)
    application: Optional[GcpApplication] = field(default=None)
    attack_exposure: Optional[GcpAttackExposure] = field(default=None)
    backup_disaster_recovery: Optional[GcpBackupDisasterRecovery] = field(default=None)
    canonical_name: Optional[str] = field(default=None)
    category: Optional[str] = field(default=None)
    cloud_armor: Optional[GcpCloudArmor] = field(default=None)
    cloud_dlp_data_profile: Optional[GcpCloudDlpDataProfile] = field(default=None)
    cloud_dlp_inspection: Optional[GcpCloudDlpInspection] = field(default=None)
    compliances: Optional[List[GcpCompliance]] = field(default=None)
    connections: Optional[List[GcpConnection]] = field(default=None)
    contacts: Optional[Dict[str, GcpContactDetails]] = field(default=None)
    containers: Optional[List[GcpContainer]] = field(default=None)
    create_time: Optional[datetime] = field(default=None)
    data_access_events: Optional[List[GcpDataAccessEvent]] = field(default=None)
    data_flow_events: Optional[List[GcpDataFlowEvent]] = field(default=None)
    database: Optional[GcpDatabase] = field(default=None)
    description: Optional[str] = field(default=None)
    event_time: Optional[datetime] = field(default=None)
    exfiltration: Optional[GcpExfiltration] = field(default=None)
    external_systems: Optional[Dict[str, GcpGoogleCloudSecuritycenterV1ExternalSystem]] = field(default=None)
    external_uri: Optional[str] = field(default=None)
    files: Optional[List[GcpFile]] = field(default=None)
    finding_class: Optional[str] = field(default=None)
    group_memberships: Optional[List[GcpGroupMembership]] = field(default=None)
    iam_bindings: Optional[List[GcpIamBinding]] = field(default=None)
    indicator: Optional[GcpIndicator] = field(default=None)
    kernel_rootkit: Optional[GcpKernelRootkit] = field(default=None)
    kubernetes: Optional[GcpKubernetes] = field(default=None)
    load_balancers: Optional[List[str]] = field(default=None)
    log_entries: Optional[List[GcpLogEntry]] = field(default=None)
    mitre_attack: Optional[GcpMitreAttack] = field(default=None)
    module_name: Optional[str] = field(default=None)
    mute: Optional[str] = field(default=None)
    mute_info: Optional[GcpMuteInfo] = field(default=None)
    mute_initiator: Optional[str] = field(default=None)
    mute_update_time: Optional[datetime] = field(default=None)
    name: Optional[str] = field(default=None)
    next_steps: Optional[str] = field(default=None)
    notebook: Optional[GcpNotebook] = field(default=None)
    org_policies: Optional[List[str]] = field(default=None)
    parent: Optional[str] = field(default=None)
    parent_display_name: Optional[str] = field(default=None)
    processes: Optional[List[GcpProcess]] = field(default=None)
    resource_name: Optional[str] = field(default=None)
    security_marks: Optional[GcpSecurityMarks] = field(default=None)
    security_posture: Optional[GcpSecurityPosture] = field(default=None)
    severity: Optional[str] = field(default=None)
    source_properties: Optional[GcpSourceProperties] = field(default=None)
    state: Optional[str] = field(default=None)
    toxic_combination: Optional[GcpToxicCombination] = field(default=None)
    vulnerability: Optional[GcpVulnerability] = field(default=None)


@define(eq=False, slots=False)
class GcpAwsAccount:
    kind: ClassVar[str] = "gcp_aws_account"
    mapping: ClassVar[Dict[str, Bender]] = {"id": S("id"), "name": S("name")}
    id: Optional[str] = field(default=None)
    name: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpAwsOrganizationalUnit:
    kind: ClassVar[str] = "gcp_aws_organizational_unit"
    mapping: ClassVar[Dict[str, Bender]] = {"id": S("id"), "name": S("name")}
    id: Optional[str] = field(default=None)
    name: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpAwsMetadata:
    kind: ClassVar[str] = "gcp_aws_metadata"
    mapping: ClassVar[Dict[str, Bender]] = {
        "account": S("account", default={}) >> Bend(GcpAwsAccount.mapping),
        "organization": S("organization", "id"),
        "organizational_units": S("organizationalUnits", default=[]) >> ForallBend(GcpAwsOrganizationalUnit.mapping),
    }
    account: Optional[GcpAwsAccount] = field(default=None)
    organization: Optional[str] = field(default=None)
    organizational_units: Optional[List[GcpAwsOrganizationalUnit]] = field(default=None)


@define(eq=False, slots=False)
class GcpAzureManagementGroup:
    kind: ClassVar[str] = "gcp_azure_management_group"
    mapping: ClassVar[Dict[str, Bender]] = {"display_name": S("displayName"), "id": S("id")}
    display_name: Optional[str] = field(default=None)
    id: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpAzureResourceGroup:
    kind: ClassVar[str] = "gcp_azure_resource_group"
    mapping: ClassVar[Dict[str, Bender]] = {"id": S("id"), "name": S("name")}
    id: Optional[str] = field(default=None)
    name: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpAzureSubscription:
    kind: ClassVar[str] = "gcp_azure_subscription"
    mapping: ClassVar[Dict[str, Bender]] = {"display_name": S("displayName"), "id": S("id")}
    display_name: Optional[str] = field(default=None)
    id: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpAzureTenant:
    kind: ClassVar[str] = "gcp_azure_tenant"
    mapping: ClassVar[Dict[str, Bender]] = {"display_name": S("displayName"), "id": S("id")}
    display_name: Optional[str] = field(default=None)
    id: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpAzureMetadata:
    kind: ClassVar[str] = "gcp_azure_metadata"
    mapping: ClassVar[Dict[str, Bender]] = {
        "management_groups": S("managementGroups", default=[]) >> ForallBend(GcpAzureManagementGroup.mapping),
        "resource_group": S("resourceGroup", default={}) >> Bend(GcpAzureResourceGroup.mapping),
        "subscription": S("subscription", default={}) >> Bend(GcpAzureSubscription.mapping),
        "tenant": S("tenant", default={}) >> Bend(GcpAzureTenant.mapping),
    }
    management_groups: Optional[List[GcpAzureManagementGroup]] = field(default=None)
    resource_group: Optional[GcpAzureResourceGroup] = field(default=None)
    subscription: Optional[GcpAzureSubscription] = field(default=None)
    tenant: Optional[GcpAzureTenant] = field(default=None)


@define(eq=False, slots=False)
class GcpResourcePathNode:
    kind: ClassVar[str] = "gcp_resource_path_node"
    mapping: ClassVar[Dict[str, Bender]] = {"display_name": S("displayName"), "id": S("id"), "node_type": S("nodeType")}
    display_name: Optional[str] = field(default=None)
    id: Optional[str] = field(default=None)
    node_type: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpResourcePath:
    kind: ClassVar[str] = "gcp_resource_path"
    mapping: ClassVar[Dict[str, Bender]] = {"nodes": S("nodes", default=[]) >> ForallBend(GcpResourcePathNode.mapping)}
    nodes: Optional[List[GcpResourcePathNode]] = field(default=None)


@define(eq=False, slots=False)
class GcpFindingResource:
    kind: ClassVar[str] = "gcp_fingding_resource"
    mapping: ClassVar[Dict[str, Bender]] = {
        "aws_metadata": S("awsMetadata", default={}) >> Bend(GcpAwsMetadata.mapping),
        "azure_metadata": S("azureMetadata", default={}) >> Bend(GcpAzureMetadata.mapping),
        "cloud_provider": S("cloudProvider"),
        "display_name": S("displayName"),
        "folders": S("folders", default=[]) >> ForallBend(GcpFolder.mapping),
        "location": S("location"),
        "name": S("name"),
        "organization": S("organization"),
        "parent_display_name": S("parentDisplayName"),
        "parent_name": S("parentName"),
        "project_display_name": S("projectDisplayName"),
        "project_name": S("projectName"),
        "resource_path": S("resourcePath", default={}) >> Bend(GcpResourcePath.mapping),
        "resource_path_string": S("resourcePathString"),
        "service": S("service"),
        "type": S("type"),
    }
    aws_metadata: Optional[GcpAwsMetadata] = field(default=None)
    azure_metadata: Optional[GcpAzureMetadata] = field(default=None)
    cloud_provider: Optional[str] = field(default=None)
    display_name: Optional[str] = field(default=None)
    folders: Optional[List[GcpFolder]] = field(default=None)
    location: Optional[str] = field(default=None)
    name: Optional[str] = field(default=None)
    organization: Optional[str] = field(default=None)
    parent_display_name: Optional[str] = field(default=None)
    parent_name: Optional[str] = field(default=None)
    project_display_name: Optional[str] = field(default=None)
    project_name: Optional[str] = field(default=None)
    resource_path: Optional[GcpResourcePath] = field(default=None)
    resource_path_string: Optional[str] = field(default=None)
    service: Optional[str] = field(default=None)
    type: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpSccFinding(GcpResource):
    kind: ClassVar[str] = "gcp_scc_finding"
    _model_export: ClassVar[bool] = False
    api_spec: ClassVar[GcpApiSpec] = GcpApiSpec(
        service="securitycenter",
        version="v1",
        accessors=["projects", "sources", "findings"],
        action="list",
        request_parameter={"parent": "projects/{project}/sources/-", "filter": 'state="ACTIVE"'},
        request_parameter_in={"project"},
        response_path="listFindingsResults",
        response_regional_sub_path=None,
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("finding", "name"),
        "tags": S("labels", default={}),
        "name": S("finding", "name"),
        "ctime": S("creationTimestamp"),
        "finding_information": S("finding", default={}) >> Bend(GcpFinding.mapping),
        "resource_information": S("resource", default={}) >> Bend(GcpFindingResource.mapping),
        "state_change": S("stateChange"),
    }
    finding_information: Optional[GcpFinding] = field(default=None)
    resource_information: Optional[GcpFindingResource] = field(default=None)
    state_change: Optional[str] = field(default=None)

    def parse_finding(self, source: Json) -> Optional[Finding]:
        if finding := self.finding_information:
            description = finding.description
            title = finding.parent_display_name or ""
            if finding.source_properties:
                remediation = finding.source_properties.recommendation
            else:
                remediation = None
            details = (source.get("finding") or {}).get("sourceProperties", None)
            severity = SEVERITY_MAPPING.get(finding.severity or "") or Severity.medium
            return Finding(title, severity, description, remediation, finding.event_time, details)
        return None

    @classmethod
    def collect_resources(cls, builder: GraphBuilder, **kwargs: Any) -> List[GcpResource]:
        def add_finding(
            provider: str, finding: Finding, clazz: Optional[Type[GcpResource]] = None, **node: Any
        ) -> None:
            if resource := builder.node(clazz=clazz or GcpResource, **node):
                resource.add_finding(provider, finding)

        if spec := cls.api_spec:
            with GcpErrorHandler(
                spec.action,
                builder.error_accumulator,
                spec.service,
                builder.region.safe_name if builder.region else None,
                GcpExpectedErrorCodes,
                f" in {builder.project.id} kind {cls.kind}",
            ):
                for item in builder.client.list(spec, **kwargs):
                    if finding := GcpSccFinding.from_api(item, builder):
                        if (ri := finding.resource_information) and (r_name := ri.display_name):
                            provider = ri.cloud_provider or "google_cloud_scc"
                            parsed_finding = finding.parse_finding(item)
                            if not parsed_finding:
                                continue
                            if r_name == builder.project.id and ri.location is None:
                                builder.after_collect_actions.append(
                                    partial(
                                        add_finding,
                                        provider.lower(),
                                        parsed_finding,
                                        GcpProject,
                                        id=r_name,
                                    )
                                )
                            elif ri.location:
                                if zone := builder.zone_by_name.get(ri.location):
                                    builder.after_collect_actions.append(
                                        partial(
                                            add_finding,
                                            provider.lower(),
                                            parsed_finding,
                                            GcpResource,
                                            id=r_name,
                                            _zone=zone,
                                        )
                                    )
                                if region := builder.region_by_name.get(ri.location):
                                    builder.after_collect_actions.append(
                                        partial(
                                            add_finding,
                                            provider.lower(),
                                            parsed_finding,
                                            GcpResource,
                                            id=r_name,
                                            _region=region,
                                        )
                                    )
        return []


resources: List[Type[GcpResource]] = [GcpSccFinding]
