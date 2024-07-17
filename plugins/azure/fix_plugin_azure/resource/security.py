from datetime import datetime
from typing import ClassVar, Dict, Optional, List, Any, Type

from attr import define, field

from fix_plugin_azure.azure_client import AzureResourceSpec
from fix_plugin_azure.resource.base import MicrosoftResource, AzureSystemData, GraphBuilder
from fixlib.json_bender import Bender, S, Bend, ForallBend
from fixlib.types import Json


@define(eq=False, slots=False)
class AzureSecurityOperationStatus:
    kind: ClassVar[str] = "azure_security_operation_status"
    mapping: ClassVar[Dict[str, Bender]] = {"code": S("code"), "message": S("message")}
    code: Optional[str] = field(default=None, metadata={"description": "The operation status code."})
    message: Optional[str] = field(default=None, metadata={'description': 'Additional information regarding the success/failure of the operation.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureSecurityExtension:
    kind: ClassVar[str] = "azure_security_extension"
    mapping: ClassVar[Dict[str, Bender]] = {
        "additional_extension_properties": S("additionalExtensionProperties"),
        "is_enabled": S("isEnabled"),
        "name": S("name"),
        "operation_status": S("operationStatus") >> Bend(AzureSecurityOperationStatus.mapping),
    }
    additional_extension_properties: Optional[Dict[str, Any]] = field(default=None, metadata={'description': 'Property values associated with the extension.'})  # fmt: skip
    is_enabled: Optional[str] = field(default=None, metadata={'description': 'Indicates whether the extension is enabled.'})  # fmt: skip
    name: Optional[str] = field(default=None, metadata={'description': 'The extension name. Supported values are: **AgentlessDiscoveryForKubernetes** - API-based discovery of information about Kubernetes cluster architecture, workload objects, and setup. Required for Kubernetes inventory, identity and network exposure detection, attack path analysis and risk hunting as part of the cloud security explorer. Available for CloudPosture plan. **OnUploadMalwareScanning** - Limits the GB to be scanned per month for each storage account within the subscription. Once this limit reached on a given storage account, Blobs won t be scanned during current calendar month. Available for StorageAccounts plan. **SensitiveDataDiscovery** - Sensitive data discovery identifies Blob storage container with sensitive data such as credentials, credit cards, and more, to help prioritize and investigate security events. Available for StorageAccounts and CloudPosture plans. **ContainerRegistriesVulnerabilityAssessments** - Provides vulnerability management for images stored in your container registries. Available for CloudPosture and Containers plans.'})  # fmt: skip
    operation_status: Optional[AzureSecurityOperationStatus] = field(default=None, metadata={'description': 'A status describing the success/failure of the extension s enablement/disablement operation.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureSecurityPricing(MicrosoftResource):
    kind: ClassVar[str] = "azure_security_pricing"
    api_spec: ClassVar[AzureResourceSpec] = AzureResourceSpec(
        service="security",
        version="2023-01-01",
        path="/subscriptions/{subscriptionId}/providers/Microsoft.Security/pricings",
        path_parameters=["subscriptionId"],
        query_parameters=["api-version"],
        access_path="value",
        expect_array=True,
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "deprecated": S("properties", "deprecated"),
        "enablement_time": S("properties", "enablementTime"),
        "extensions": S("properties", "extensions") >> ForallBend(AzureSecurityExtension.mapping),
        "free_trial_remaining_time": S("properties", "freeTrialRemainingTime"),
        "pricing_tier": S("properties", "pricingTier"),
        "replaced_by": S("properties", "replacedBy"),
        "sub_plan": S("properties", "subPlan"),
    }
    deprecated: Optional[bool] = field(default=None, metadata={'description': 'Optional. True if the plan is deprecated. If there are replacing plans they will appear in `replacedBy` property'})  # fmt: skip
    enablement_time: Optional[datetime] = field(default=None, metadata={'description': 'Optional. If `pricingTier` is `Standard` then this property holds the date of the last time the `pricingTier` was set to `Standard`, when available (e.g 2023-03-01T12:42:42.1921106Z).'})  # fmt: skip
    extensions: Optional[List[AzureSecurityExtension]] = field(default=None, metadata={'description': 'Optional. List of extensions offered under a plan.'})  # fmt: skip
    free_trial_remaining_time: Optional[str] = field(default=None, metadata={'description': 'The duration left for the subscriptions free trial period - in ISO 8601 format (e.g. P3Y6M4DT12H30M5S).'})  # fmt: skip
    pricing_tier: Optional[str] = field(default=None, metadata={'description': 'The pricing tier value. Microsoft Defender for Cloud is provided in two pricing tiers: free and standard. The standard tier offers advanced security capabilities, while the free tier offers basic security features.'})  # fmt: skip
    replaced_by: Optional[List[str]] = field(default=None, metadata={'description': 'Optional. List of plans that replace this plan. This property exists only if this plan is deprecated.'})  # fmt: skip
    sub_plan: Optional[str] = field(default=None, metadata={'description': 'The sub-plan selected for a Standard pricing configuration, when more than one sub-plan is available. Each sub-plan enables a set of security features. When not specified, full plan is applied.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureAssessmentStatus:
    kind: ClassVar[str] = "azure_assessment_status"
    mapping: ClassVar[Dict[str, Bender]] = {
        "cause": S("cause"),
        "code": S("code"),
        "description": S("description"),
        "first_evaluation_date": S("firstEvaluationDate"),
        "status_change_date": S("statusChangeDate"),
    }

    cause: Optional[str] = field(default=None, metadata={'description': 'Programmatic code for the cause of the assessment status'})  # fmt: skip
    code: Optional[str] = field(default=None, metadata={'description': 'Programmatic code for the status of the assessment'})  # fmt: skip
    description: Optional[str] = field(default=None, metadata={'description': 'Human readable description of the assessment status'})  # fmt: skip
    first_evaluation_date: Optional[datetime] = field(default=None, metadata={'description': 'The time that the assessment was created and first evaluated. Returned as UTC time in ISO 8601 format'})  # fmt: skip
    status_change_date: Optional[datetime] = field(default=None, metadata={'description': 'The time that the status of the assessment last changed. Returned as UTC time in ISO 8601 format'})  # fmt: skip


@define(eq=False, slots=False)
class AzureSecurityAssessment(MicrosoftResource):
    kind: ClassVar[str] = "azure_security_assessment"
    api_spec: ClassVar[AzureResourceSpec] = AzureResourceSpec(
        service="security",
        version="2021-06-01",
        path="/subscriptions/{subscriptionId}/providers/Microsoft.Security/assessments",
        path_parameters=["subscriptionId"],
        query_parameters=["api-version"],
        access_path="value",
        expect_array=True,
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "name": S("properties", "displayName"),
        "tags": S("tags", default={}),
        "assessment_status": S("properties", "status") >> Bend(AzureAssessmentStatus.mapping),
        "resource_source": S("properties", "resourceDetails", "Source"),
        "resource_id": S("properties", "resourceDetails", "ResourceId"),
        "additional_date": S("properties", "additionalData"),
        "azurePortalUri": S("properties", "links", "azurePortalUri"),
    }
    assessment_status: Optional[AzureAssessmentStatus] = field(default=None, metadata={'description': 'The result of the assessment'})  # fmt: skip
    resource_source: Optional[str] = field(default=None, metadata={'description': 'The source of the resource that the assessment is performed on'})  # fmt: skip
    resource_id: Optional[str] = field(default=None, metadata={'description': 'The id of the resource that the assessment is performed on'})  # fmt: skip
    additional_data: Optional[Dict[str, Any]] = field(default=None, metadata={'description': 'Additional data for the assessment'})  # fmt: skip
    subscription_issue: Optional[bool] = field(default=False, metadata={'description': 'Indicates if the assessment is a subscription issue'})  # fmt: skip

    def post_process(self, builder: GraphBuilder, source: Json) -> None:
        # mark as subscription issue, when the resource id is the same as the account id
        if (rid := self.resource_id) and (sub := self._account):
            self.subscription_issue = rid.split("/")[-1] == sub.id

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        # this will not connect subscription issues.
        if self.resource_source == "Azure" and (rid := self.resource_id):
            builder.add_edge(self, clazz=MicrosoftResource, id=rid)


@define(eq=False, slots=False)
class AzureSecurityServerVulnerabilityAssessmentsSetting(MicrosoftResource):
    kind: ClassVar[str] = "azure_security_server_vulnerability_assessments_setting"
    api_spec: ClassVar[AzureResourceSpec] = AzureResourceSpec(
        service="security",
        version="2023-05-01",
        path="/subscriptions/{subscriptionId}/providers/Microsoft.Security/serverVulnerabilityAssessmentsSettings",
        path_parameters=["subscriptionId"],
        query_parameters=["api-version"],
        access_path="value",
        expect_array=True,
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "ctime": S("systemData", "createdAt"),
        "mtime": S("systemData", "lastModifiedAt"),
        "setting_kind": S("kind"),
        "system_data": S("systemData") >> Bend(AzureSystemData.mapping),
    }
    setting_kind: Optional[str] = field(default=None, metadata={'description': 'The kind of the server vulnerability assessments setting'})  # fmt: skip
    system_data: Optional[AzureSystemData] = field(default=None, metadata={'description': 'Metadata pertaining to creation and last modification of the resource.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureSecuritySetting(MicrosoftResource):
    kind: ClassVar[str] = "azure_security_setting"
    api_spec: ClassVar[AzureResourceSpec] = AzureResourceSpec(
        service="security",
        version="2022-05-01",
        path="/subscriptions/{subscriptionId}/providers/Microsoft.Security/settings",
        path_parameters=["subscriptionId"],
        query_parameters=["api-version"],
        access_path="value",
        expect_array=True,
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "setting": S("kind"),
        "enabled": S("properties", "enabled"),
    }
    setting: Optional[str] = field(default=None, metadata={"description": "the kind of the settings string"})
    enabled: Optional[bool] = field(default=None, metadata={"description": "Indicates whether the setting is enabled."})


resources: List[Type[MicrosoftResource]] = [
    AzureSecurityAssessment,
    AzureSecurityPricing,
    AzureSecurityServerVulnerabilityAssessmentsSetting,
    AzureSecuritySetting,
]
