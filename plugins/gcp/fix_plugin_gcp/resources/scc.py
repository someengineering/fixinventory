from datetime import datetime
from functools import partial
from typing import ClassVar, Dict, Optional, List, Tuple, Type, Any

from attr import define, field

from fix_plugin_gcp.gcp_client import GcpApiSpec
from fix_plugin_gcp.resources.base import (
    GcpRegion,
    GcpResource,
    GcpZone,
    GraphBuilder,
    GcpErrorHandler,
    GcpProject,
    GcpExpectedErrorCodes,
)
from fixlib.baseresources import SEVERITY_MAPPING, Finding, Severity
from fixlib.json_bender import Bender, S, Bend
from fixlib.types import Json


@define(eq=False, slots=False)
class GcpSourceProperties:
    kind: ClassVar[str] = "gcp_source_properties"
    mapping: ClassVar[Dict[str, Bender]] = {
        "recommendation": S("Recommendation"),
        "explanation": S("Explanation"),
    }
    recommendation: Optional[str] = field(default=None)
    explanation: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpFinding:
    kind: ClassVar[str] = "gcp_finding"
    mapping: ClassVar[Dict[str, Bender]] = {
        "severity": S("severity"),
        "source_properties": S("sourceProperties", default={}) >> Bend(GcpSourceProperties.mapping),
        "description": S("description"),
        "event_time": S("eventTime"),
        "parent_display_name": S("parentDisplayName"),
        # "access": S("access", default={}) >> Bend(GcpAccess.mapping),
        # "application": S("application", default={}) >> Bend(GcpApplication.mapping),
        # "attack_exposure": S("attackExposure", default={}) >> Bend(GcpAttackExposure.mapping),
        # "backup_disaster_recovery": S("backupDisasterRecovery", default={}) >> Bend(GcpBackupDisasterRecovery.mapping),
        # "canonical_name": S("canonicalName"),
        # "category": S("category"),
        # "cloud_armor": S("cloudArmor", default={}) >> Bend(GcpCloudArmor.mapping),
        # "cloud_dlp_data_profile": S("cloudDlpDataProfile", default={}) >> Bend(GcpCloudDlpDataProfile.mapping),
        # "cloud_dlp_inspection": S("cloudDlpInspection", default={}) >> Bend(GcpCloudDlpInspection.mapping),
        # "compliances": S("compliances", default=[]) >> ForallBend(GcpCompliance.mapping),
        # "connections": S("connections", default=[]) >> ForallBend(GcpConnection.mapping),
        # "contacts": S("contacts", default={}) >> MapDict(value_bender=Bend(GcpContactDetails.mapping)),
        # "containers": S("containers", default=[]) >> ForallBend(GcpContainer.mapping),
        # "create_time": S("createTime"),
        # "data_access_events": S("dataAccessEvents", default=[]) >> ForallBend(GcpDataAccessEvent.mapping),
        # "data_flow_events": S("dataFlowEvents", default=[]) >> ForallBend(GcpDataFlowEvent.mapping),
        # "database": S("database", default={}) >> Bend(GcpDatabase.mapping),
        # "exfiltration": S("exfiltration", default={}) >> Bend(GcpExfiltration.mapping),
        # "external_systems": S("externalSystems", default={})
        # >> MapDict(value_bender=Bend(GcpGoogleCloudSecuritycenterV1ExternalSystem.mapping)),
        # "external_uri": S("externalUri"),
        # "files": S("files", default=[]) >> ForallBend(GcpFile.mapping),
        # "finding_class": S("findingClass"),
        # "group_memberships": S("groupMemberships", default=[]) >> ForallBend(GcpGroupMembership.mapping),
        # "iam_bindings": S("iamBindings", default=[]) >> ForallBend(GcpIamBinding.mapping),
        # "indicator": S("indicator", default={}) >> Bend(GcpIndicator.mapping),
        # "kernel_rootkit": S("kernelRootkit", default={}) >> Bend(GcpKernelRootkit.mapping),
        # "kubernetes": S("kubernetes", default={}) >> Bend(GcpKubernetes.mapping),
        # "load_balancers": S("loadBalancers", default=[]) >> ForallBend(S("name")),
        # "log_entries": S("logEntries", default=[]) >> ForallBend(GcpLogEntry.mapping),
        # "mitre_attack": S("mitreAttack", default={}) >> Bend(GcpMitreAttack.mapping),
        # "module_name": S("moduleName"),
        # "mute": S("mute"),
        # "mute_info": S("muteInfo", default={}) >> Bend(GcpMuteInfo.mapping),
        # "mute_initiator": S("muteInitiator"),
        # "mute_update_time": S("muteUpdateTime"),
        # "name": S("name"),
        # "next_steps": S("nextSteps"),
        # "notebook": S("notebook", default={}) >> Bend(GcpNotebook.mapping),
        # "org_policies": S("orgPolicies", default=[]) >> ForallBend(S("name")),
        # "parent": S("parent"),
        # "processes": S("processes", default=[]) >> ForallBend(GcpProcess.mapping),
        # "resource_name": S("resourceName"),
        # "security_marks": S("securityMarks", default={}) >> Bend(GcpSecurityMarks.mapping),
        # "security_posture": S("securityPosture", default={}) >> Bend(GcpSecurityPosture.mapping),
        # "state": S("state"),
        # "toxic_combination": S("toxicCombination", default={}) >> Bend(GcpToxicCombination.mapping),
        # "vulnerability": S("vulnerability", default={}) >> Bend(GcpVulnerability.mapping),
    }
    description: Optional[str] = field(default=None)
    event_time: Optional[datetime] = field(default=None)
    parent_display_name: Optional[str] = field(default=None)
    severity: Optional[str] = field(default=None)
    source_properties: Optional[GcpSourceProperties] = field(default=None)


@define(eq=False, slots=False)
class GcpFindingResource:
    kind: ClassVar[str] = "gcp_fingding_resource"
    mapping: ClassVar[Dict[str, Bender]] = {
        "cloud_provider": S("cloudProvider"),
        "display_name": S("displayName"),
        "location": S("location"),
        # "aws_metadata": S("awsMetadata", default={}) >> Bend(GcpAwsMetadata.mapping),
        # "azure_metadata": S("azureMetadata", default={}) >> Bend(GcpAzureMetadata.mapping),
        # "folders": S("folders", default=[]) >> ForallBend(GcpFolder.mapping),
        # "name": S("name"),
        # "organization": S("organization"),
        # "parent_display_name": S("parentDisplayName"),
        # "parent_name": S("parentName"),
        # "project_display_name": S("projectDisplayName"),
        # "project_name": S("projectName"),
        # "resource_path": S("resourcePath", default={}) >> Bend(GcpResourcePath.mapping),
        # "resource_path_string": S("resourcePathString"),
        # "service": S("service"),
        # "type": S("type"),
    }
    cloud_provider: Optional[str] = field(default=None)
    display_name: Optional[str] = field(default=None)
    location: Optional[str] = field(default=None)


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
            if finding.source_properties:
                remediation = finding.source_properties.recommendation
                title = finding.source_properties.explanation or "unknown"
            else:
                remediation = None
                title = "unknown"
            source_finding = source.get("finding", {})
            source_resource = source.get("resource", {})
            details = source_finding.get("sourceProperties", {})
            aws_metadata = source_resource.get("awsMetadata", {})
            azure_metadata = source_resource.get("azureMetadata", {})
            severity = SEVERITY_MAPPING.get(finding.severity or "") or Severity.medium
            return Finding(
                title, severity, description, remediation, finding.event_time, details | aws_metadata | azure_metadata
            )
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

                            def resolve_location(
                                builder: GraphBuilder, location: str
                            ) -> Tuple[Optional[GcpZone], Optional[GcpRegion]]:
                                zone = builder.zone_by_name.get(location)
                                region = builder.region_by_name.get(location)
                                return zone, region

                            if ri.location:
                                zone, region = resolve_location(builder, ri.location)
                                if zone:
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
                                elif region:
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
