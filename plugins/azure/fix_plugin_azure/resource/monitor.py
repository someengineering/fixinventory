from __future__ import annotations

import logging
from datetime import datetime
from typing import ClassVar, Dict, Optional, List, Type, Any

from attr import define, field
from jsons import snakecase

from fix_plugin_azure.azure_client import AzureResourceSpec
from fix_plugin_azure.resource.base import (
    MicrosoftResource,
    AzureSystemData,
    AzureManagedServiceIdentity,
    AzureExtendedLocation,
    GraphBuilder,
    AzurePrivateEndpointConnection,
)
from fix_plugin_azure.resource.storage import AzureStorageAccount
from fixlib.baseresources import ModelReference
from fixlib.json_bender import Bender, S, ForallBend, Bend, K, MapDict, F
from fixlib.types import Json

log = logging.getLogger("fix.plugins.azure")
service_name = "monitor"


@define(eq=False, slots=False)
class AzureMonitorEmailReceiver:
    kind: ClassVar[str] = "azure_monitor_email_receiver"
    mapping: ClassVar[Dict[str, Bender]] = {
        "email_address": S("emailAddress"),
        "name": S("name"),
        "status": S("status"),
        "use_common_alert_schema": S("useCommonAlertSchema"),
    }
    email_address: Optional[str] = field(default=None, metadata={"description": "The email address of this receiver."})
    name: Optional[str] = field(default=None, metadata={'description': 'The name of the email receiver. Names must be unique across all receivers within an action group.'})  # fmt: skip
    status: Optional[str] = field(default=None, metadata={'description': 'Indicates the status of the receiver. Receivers that are not Enabled will not receive any communications.'})  # fmt: skip
    use_common_alert_schema: Optional[bool] = field(default=None, metadata={'description': 'Indicates whether to use common alert schema.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureMonitorSmsReceiver:
    kind: ClassVar[str] = "azure_monitor_sms_receiver"
    mapping: ClassVar[Dict[str, Bender]] = {
        "country_code": S("countryCode"),
        "name": S("name"),
        "phone_number": S("phoneNumber"),
        "status": S("status"),
    }
    country_code: Optional[str] = field(default=None, metadata={'description': 'The country code of the SMS receiver.'})  # fmt: skip
    name: Optional[str] = field(default=None, metadata={'description': 'The name of the SMS receiver. Names must be unique across all receivers within an action group.'})  # fmt: skip
    phone_number: Optional[str] = field(default=None, metadata={'description': 'The phone number of the SMS receiver.'})  # fmt: skip
    status: Optional[str] = field(default=None, metadata={'description': 'Indicates the status of the receiver. Receivers that are not Enabled will not receive any communications.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureMonitorWebhookReceiver:
    kind: ClassVar[str] = "azure_monitor_webhook_receiver"
    mapping: ClassVar[Dict[str, Bender]] = {
        "identifier_uri": S("identifierUri"),
        "name": S("name"),
        "object_id": S("objectId"),
        "service_uri": S("serviceUri"),
        "tenant_id": S("tenantId"),
        "use_aad_auth": S("useAadAuth"),
        "use_common_alert_schema": S("useCommonAlertSchema"),
    }
    identifier_uri: Optional[str] = field(default=None, metadata={'description': 'Indicates the identifier uri for aad auth.'})  # fmt: skip
    name: Optional[str] = field(default=None, metadata={'description': 'The name of the webhook receiver. Names must be unique across all receivers within an action group.'})  # fmt: skip
    object_id: Optional[str] = field(default=None, metadata={'description': 'Indicates the webhook app object Id for aad auth.'})  # fmt: skip
    service_uri: Optional[str] = field(default=None, metadata={'description': 'The URI where webhooks should be sent.'})  # fmt: skip
    tenant_id: Optional[str] = field(default=None, metadata={"description": "Indicates the tenant id for aad auth."})
    use_aad_auth: Optional[bool] = field(default=None, metadata={'description': 'Indicates whether or not use AAD authentication.'})  # fmt: skip
    use_common_alert_schema: Optional[bool] = field(default=None, metadata={'description': 'Indicates whether to use common alert schema.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureMonitorItsmReceiver:
    kind: ClassVar[str] = "azure_monitor_itsm_receiver"
    mapping: ClassVar[Dict[str, Bender]] = {
        "connection_id": S("connectionId"),
        "name": S("name"),
        "region": S("region"),
        "ticket_configuration": S("ticketConfiguration"),
        "workspace_id": S("workspaceId"),
    }
    connection_id: Optional[str] = field(default=None, metadata={'description': 'Unique identification of ITSM connection among multiple defined in above workspace.'})  # fmt: skip
    name: Optional[str] = field(default=None, metadata={'description': 'The name of the Itsm receiver. Names must be unique across all receivers within an action group.'})  # fmt: skip
    region: Optional[str] = field(default=None, metadata={'description': 'Region in which workspace resides. Supported values: centralindia , japaneast , southeastasia , australiasoutheast , uksouth , westcentralus , canadacentral , eastus , westeurope '})  # fmt: skip
    ticket_configuration: Optional[str] = field(default=None, metadata={'description': 'JSON blob for the configurations of the ITSM action. CreateMultipleWorkItems option will be part of this blob as well.'})  # fmt: skip
    workspace_id: Optional[str] = field(default=None, metadata={"description": "OMS LA instance identifier."})


@define(eq=False, slots=False)
class AzureMonitorAppPushReceiver:
    kind: ClassVar[str] = "azure_monitor_app_push_receiver"
    mapping: ClassVar[Dict[str, Bender]] = {"email_address": S("emailAddress"), "name": S("name")}
    email_address: Optional[str] = field(default=None, metadata={'description': 'The email address registered for the Azure mobile app.'})  # fmt: skip
    name: Optional[str] = field(default=None, metadata={'description': 'The name of the Azure mobile app push receiver. Names must be unique across all receivers within an action group.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureMonitorAutomationRunbookReceiver:
    kind: ClassVar[str] = "azure_monitor_automation_runbook_receiver"
    mapping: ClassVar[Dict[str, Bender]] = {
        "automation_account_id": S("automationAccountId"),
        "is_global_runbook": S("isGlobalRunbook"),
        "name": S("name"),
        "runbook_name": S("runbookName"),
        "service_uri": S("serviceUri"),
        "use_common_alert_schema": S("useCommonAlertSchema"),
        "webhook_resource_id": S("webhookResourceId"),
    }
    automation_account_id: Optional[str] = field(default=None, metadata={'description': 'The Azure automation account Id which holds this runbook and authenticate to Azure resource.'})  # fmt: skip
    is_global_runbook: Optional[bool] = field(default=None, metadata={'description': 'Indicates whether this instance is global runbook.'})  # fmt: skip
    name: Optional[str] = field(default=None, metadata={"description": "Indicates name of the webhook."})
    runbook_name: Optional[str] = field(default=None, metadata={"description": "The name for this runbook."})
    service_uri: Optional[str] = field(default=None, metadata={'description': 'The URI where webhooks should be sent.'})  # fmt: skip
    use_common_alert_schema: Optional[bool] = field(default=None, metadata={'description': 'Indicates whether to use common alert schema.'})  # fmt: skip
    webhook_resource_id: Optional[str] = field(default=None, metadata={'description': 'The resource id for webhook linked to this runbook.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureMonitorVoiceReceiver:
    kind: ClassVar[str] = "azure_monitor_voice_receiver"
    mapping: ClassVar[Dict[str, Bender]] = {
        "country_code": S("countryCode"),
        "name": S("name"),
        "phone_number": S("phoneNumber"),
    }
    country_code: Optional[str] = field(default=None, metadata={'description': 'The country code of the voice receiver.'})  # fmt: skip
    name: Optional[str] = field(default=None, metadata={'description': 'The name of the voice receiver. Names must be unique across all receivers within an action group.'})  # fmt: skip
    phone_number: Optional[str] = field(default=None, metadata={'description': 'The phone number of the voice receiver.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureMonitorLogicAppReceiver:
    kind: ClassVar[str] = "azure_monitor_logic_app_receiver"
    mapping: ClassVar[Dict[str, Bender]] = {
        "callback_url": S("callbackUrl"),
        "name": S("name"),
        "resource_id": S("resourceId"),
        "use_common_alert_schema": S("useCommonAlertSchema"),
    }
    callback_url: Optional[str] = field(default=None, metadata={'description': 'The callback url where http request sent to.'})  # fmt: skip
    name: Optional[str] = field(default=None, metadata={'description': 'The name of the logic app receiver. Names must be unique across all receivers within an action group.'})  # fmt: skip
    resource_id: Optional[str] = field(default=None, metadata={'description': 'The azure resource id of the logic app receiver.'})  # fmt: skip
    use_common_alert_schema: Optional[bool] = field(default=None, metadata={'description': 'Indicates whether to use common alert schema.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureMonitorFunctionReceiver:
    kind: ClassVar[str] = "azure_monitor_function_receiver"
    mapping: ClassVar[Dict[str, Bender]] = {
        "function_app_resource_id": S("functionAppResourceId"),
        "function_name": S("functionName"),
        "http_trigger_url": S("httpTriggerUrl"),
        "name": S("name"),
        "use_common_alert_schema": S("useCommonAlertSchema"),
    }
    function_app_resource_id: Optional[str] = field(default=None, metadata={'description': 'The azure resource id of the function app.'})  # fmt: skip
    function_name: Optional[str] = field(default=None, metadata={'description': 'The function name in the function app.'})  # fmt: skip
    http_trigger_url: Optional[str] = field(default=None, metadata={'description': 'The http trigger url where http request sent to.'})  # fmt: skip
    name: Optional[str] = field(default=None, metadata={'description': 'The name of the azure function receiver. Names must be unique across all receivers within an action group.'})  # fmt: skip
    use_common_alert_schema: Optional[bool] = field(default=None, metadata={'description': 'Indicates whether to use common alert schema.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureMonitorArmRoleReceiver:
    kind: ClassVar[str] = "azure_monitor_arm_role_receiver"
    mapping: ClassVar[Dict[str, Bender]] = {
        "name": S("name"),
        "role_id": S("roleId"),
        "use_common_alert_schema": S("useCommonAlertSchema"),
    }
    name: Optional[str] = field(default=None, metadata={'description': 'The name of the arm role receiver. Names must be unique across all receivers within an action group.'})  # fmt: skip
    role_id: Optional[str] = field(default=None, metadata={"description": "The arm role id."})
    use_common_alert_schema: Optional[bool] = field(default=None, metadata={'description': 'Indicates whether to use common alert schema.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureMonitorEventHubReceiver:
    kind: ClassVar[str] = "azure_monitor_event_hub_receiver"
    mapping: ClassVar[Dict[str, Bender]] = {
        "event_hub_name": S("eventHubName"),
        "event_hub_name_space": S("eventHubNameSpace"),
        "name": S("name"),
        "subscription_id": S("subscriptionId"),
        "tenant_id": S("tenantId"),
        "use_common_alert_schema": S("useCommonAlertSchema"),
    }
    event_hub_name: Optional[str] = field(default=None, metadata={'description': 'The name of the specific Event Hub queue'})  # fmt: skip
    event_hub_name_space: Optional[str] = field(default=None, metadata={"description": "The Event Hub namespace"})
    name: Optional[str] = field(default=None, metadata={'description': 'The name of the Event hub receiver. Names must be unique across all receivers within an action group.'})  # fmt: skip
    subscription_id: Optional[str] = field(default=None, metadata={'description': 'The Id for the subscription containing this event hub'})  # fmt: skip
    tenant_id: Optional[str] = field(default=None, metadata={'description': 'The tenant Id for the subscription containing this event hub'})  # fmt: skip
    use_common_alert_schema: Optional[bool] = field(default=None, metadata={'description': 'Indicates whether to use common alert schema.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureMonitorActionGroup(MicrosoftResource):
    kind: ClassVar[str] = "azure_monitor_action_group"
    _kind_display: ClassVar[str] = "Azure Monitor Action Group"
    _kind_service: ClassVar[Optional[str]] = service_name
    _kind_description: ClassVar[str] = "Azure Monitor Action Group is a configuration service for automated responses to monitoring alerts. It defines a set of actions to be executed when specific conditions are met. These actions can include sending notifications via email, SMS, or voice calls, triggering automated processes, or integrating with external systems to manage and respond to issues in Azure resources."  # fmt: skip
    _docs_url: ClassVar[str] = "https://learn.microsoft.com/en-us/azure/azure-monitor/alerts/action-groups"
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "group", "group": "management"}
    _create_provider_link: ClassVar[bool] = False
    api_spec: ClassVar[AzureResourceSpec] = AzureResourceSpec(
        service="monitor",
        version="2023-01-01",
        path="/subscriptions/{subscriptionId}/providers/Microsoft.Insights/actionGroups",
        path_parameters=["subscriptionId"],
        query_parameters=["api-version"],
        access_path="value",
        expect_array=True,
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "tags": S("tags").or_else(K({})),
        "name": S("name"),
        "arm_role_receivers": S("properties", "armRoleReceivers") >> ForallBend(AzureMonitorArmRoleReceiver.mapping),
        "automation_runbook_receivers": S("properties", "automationRunbookReceivers")
        >> ForallBend(AzureMonitorAutomationRunbookReceiver.mapping),
        "azure_app_push_receivers": S("properties", "azureAppPushReceivers")
        >> ForallBend(AzureMonitorAppPushReceiver.mapping),
        "azure_function_receivers": S("properties", "azureFunctionReceivers")
        >> ForallBend(AzureMonitorFunctionReceiver.mapping),
        "email_receivers": S("properties", "emailReceivers") >> ForallBend(AzureMonitorEmailReceiver.mapping),
        "enabled": S("properties", "enabled"),
        "event_hub_receivers": S("properties", "eventHubReceivers") >> ForallBend(AzureMonitorEventHubReceiver.mapping),
        "group_short_name": S("properties", "groupShortName"),
        "itsm_receivers": S("properties", "itsmReceivers") >> ForallBend(AzureMonitorItsmReceiver.mapping),
        "logic_app_receivers": S("properties", "logicAppReceivers") >> ForallBend(AzureMonitorLogicAppReceiver.mapping),
        "sms_receivers": S("properties", "smsReceivers") >> ForallBend(AzureMonitorSmsReceiver.mapping),
        "voice_receivers": S("properties", "voiceReceivers") >> ForallBend(AzureMonitorVoiceReceiver.mapping),
        "webhook_receivers": S("properties", "webhookReceivers") >> ForallBend(AzureMonitorWebhookReceiver.mapping),
    }
    arm_role_receivers: Optional[List[AzureMonitorArmRoleReceiver]] = field(default=None, metadata={'description': 'The list of ARM role receivers that are part of this action group. Roles are Azure RBAC roles and only built-in roles are supported.'})  # fmt: skip
    automation_runbook_receivers: Optional[List[AzureMonitorAutomationRunbookReceiver]] = field(default=None, metadata={'description': 'The list of AutomationRunbook receivers that are part of this action group.'})  # fmt: skip
    azure_app_push_receivers: Optional[List[AzureMonitorAppPushReceiver]] = field(default=None, metadata={'description': 'The list of AzureAppPush receivers that are part of this action group.'})  # fmt: skip
    azure_function_receivers: Optional[List[AzureMonitorFunctionReceiver]] = field(default=None, metadata={'description': 'The list of azure function receivers that are part of this action group.'})  # fmt: skip
    email_receivers: Optional[List[AzureMonitorEmailReceiver]] = field(default=None, metadata={'description': 'The list of email receivers that are part of this action group.'})  # fmt: skip
    enabled: Optional[bool] = field(default=None, metadata={'description': 'Indicates whether this action group is enabled. If an action group is not enabled, then none of its receivers will receive communications.'})  # fmt: skip
    event_hub_receivers: Optional[List[AzureMonitorEventHubReceiver]] = field(default=None, metadata={'description': 'The list of event hub receivers that are part of this action group.'})  # fmt: skip
    group_short_name: Optional[str] = field(default=None, metadata={'description': 'The short name of the action group. This will be used in SMS messages.'})  # fmt: skip
    itsm_receivers: Optional[List[AzureMonitorItsmReceiver]] = field(default=None, metadata={'description': 'The list of ITSM receivers that are part of this action group.'})  # fmt: skip
    logic_app_receivers: Optional[List[AzureMonitorLogicAppReceiver]] = field(default=None, metadata={'description': 'The list of logic app receivers that are part of this action group.'})  # fmt: skip
    sms_receivers: Optional[List[AzureMonitorSmsReceiver]] = field(default=None, metadata={'description': 'The list of SMS receivers that are part of this action group.'})  # fmt: skip
    voice_receivers: Optional[List[AzureMonitorVoiceReceiver]] = field(default=None, metadata={'description': 'The list of voice receivers that are part of this action group.'})  # fmt: skip
    webhook_receivers: Optional[List[AzureMonitorWebhookReceiver]] = field(default=None, metadata={'description': 'The list of webhook receivers that are part of this action group.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureMonitorAlertRuleLeafCondition:
    kind: ClassVar[str] = "azure_monitor_alert_rule_leaf_condition"
    mapping: ClassVar[Dict[str, Bender]] = {
        "contains_any": S("containsAny"),
        "equals": S("equals"),
        "field": S("field"),
    }
    contains_any: Optional[List[str]] = field(default=None, metadata={'description': 'The value of the event s field will be compared to the values in this array (case-insensitive) to determine if the condition is met.'})  # fmt: skip
    equals: Optional[str] = field(default=None, metadata={'description': 'The value of the event s field will be compared to this value (case-insensitive) to determine if the condition is met.'})  # fmt: skip
    field: Optional[str] = field(default=None, metadata={'description': 'The name of the Activity Log event s field that this condition will examine. The possible values for this field are (case-insensitive): resourceId , category , caller , level , operationName , resourceGroup , resourceProvider , status , subStatus , resourceType , or anything beginning with properties .'})  # fmt: skip


@define(eq=False, slots=False)
class AzureMonitorAlertRuleAnyOfOrLeafCondition(AzureMonitorAlertRuleLeafCondition):
    kind: ClassVar[str] = "azure_monitor_alert_rule_any_of_or_leaf_condition"
    mapping: ClassVar[Dict[str, Bender]] = AzureMonitorAlertRuleLeafCondition.mapping | {
        "any_of": S("anyOf") >> ForallBend(AzureMonitorAlertRuleLeafCondition.mapping)
    }
    any_of: Optional[List[AzureMonitorAlertRuleLeafCondition]] = field(default=None, metadata={'description': 'An Activity Log Alert rule condition that is met when at least one of its member leaf conditions are met.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureMonitorAlertRuleAllOfCondition:
    kind: ClassVar[str] = "azure_monitor_alert_rule_all_of_condition"
    mapping: ClassVar[Dict[str, Bender]] = {
        "all_of": S("allOf") >> ForallBend(AzureMonitorAlertRuleAnyOfOrLeafCondition.mapping)
    }
    all_of: Optional[List[AzureMonitorAlertRuleAnyOfOrLeafCondition]] = field(default=None, metadata={'description': 'The list of Activity Log Alert rule conditions.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureMonitorActionGroupRef:
    kind: ClassVar[str] = "azure_monitor_action_group_ref"
    mapping: ClassVar[Dict[str, Bender]] = {
        "action_group_id": S("actionGroupId"),
        "webhook_properties": S("webhookProperties"),
    }
    action_group_id: Optional[str] = field(default=None, metadata={'description': 'The resource ID of the Action Group. This cannot be null or empty.'})  # fmt: skip
    webhook_properties: Optional[Dict[str, str]] = field(default=None, metadata={'description': 'the dictionary of custom properties to include with the post operation. These data are appended to the webhook payload.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureMonitorActivityLogAlert(MicrosoftResource):
    kind: ClassVar[str] = "azure_monitor_activity_log_alert"
    _kind_display: ClassVar[str] = "Azure Monitor Activity Log Alert"
    _kind_service: ClassVar[Optional[str]] = service_name
    _kind_description: ClassVar[str] = "Azure Monitor Activity Log Alert is a service that monitors and notifies users about specific events or changes in Azure resources. It tracks operations performed on Azure services, including resource creation, modification, or deletion. Users can set up custom alerts based on defined criteria and receive notifications through various channels when those conditions are met."  # fmt: skip
    _docs_url: ClassVar[str] = "https://docs.microsoft.com/en-us/azure/azure-monitor/alerts/alerts-activity-log"
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "alarm", "group": "management"}
    _reference_kinds: ClassVar[ModelReference] = {
        "predecessors": {"default": [AzureMonitorActionGroup.kind]},
        "successors": {"default": [MicrosoftResource.kind]},
    }
    _create_provider_link: ClassVar[bool] = False
    api_spec: ClassVar[AzureResourceSpec] = AzureResourceSpec(
        service="monitor",
        version="2020-10-01",
        path="/subscriptions/{subscriptionId}/providers/Microsoft.Insights/activityLogAlerts",
        path_parameters=["subscriptionId"],
        query_parameters=["api-version"],
        access_path="value",
        expect_array=True,
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "tags": S("tags").or_else(K({})),
        "name": S("name"),
        "action_groups": S("properties", "actions", "actionGroups") >> ForallBend(AzureMonitorActionGroupRef.mapping),
        "log_alert_condition": S("properties", "condition") >> Bend(AzureMonitorAlertRuleAllOfCondition.mapping),
        "description": S("properties", "description"),
        "enabled": S("properties", "enabled"),
        "scopes": S("properties", "scopes"),
    }
    action_groups: Optional[List[AzureMonitorActionGroupRef]] = field(default=None, metadata={'description': 'The list of the Action Groups.'})  # fmt: skip
    log_alert_condition: Optional[AzureMonitorAlertRuleAllOfCondition] = field(default=None, metadata={'description': 'An Activity Log Alert rule condition that is met when all its member conditions are met.'})  # fmt: skip
    description: Optional[str] = field(default=None, metadata={'description': 'A description of this Activity Log Alert rule.'})  # fmt: skip
    enabled: Optional[bool] = field(default=None, metadata={'description': 'Indicates whether this Activity Log Alert rule is enabled. If an Activity Log Alert rule is not enabled, then none of its actions will be activated.'})  # fmt: skip
    scopes: Optional[List[str]] = field(default=None, metadata={'description': 'A list of resource IDs that will be used as prefixes. The alert will only apply to Activity Log events with resource IDs that fall under one of these prefixes. This list must include at least one item.'})  # fmt: skip

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        for ref in self.action_groups or []:
            builder.add_edge(self, reverse=True, clazz=AzureMonitorActionGroup, id=ref.action_group_id)

        if scopes := self.scopes:
            for scope_id in scopes:
                builder.add_edge(
                    self,
                    clazz=MicrosoftResource,
                    id=scope_id,
                )


@define(eq=False, slots=False)
class AzureMonitorAccessModeSettingsExclusion:
    kind: ClassVar[str] = "azure_monitor_access_mode_settings_exclusion"
    mapping: ClassVar[Dict[str, Bender]] = {
        "ingestion_access_mode": S("ingestionAccessMode"),
        "private_endpoint_connection_name": S("privateEndpointConnectionName"),
        "query_access_mode": S("queryAccessMode"),
    }
    ingestion_access_mode: Optional[str] = field(default=None, metadata={"description": "Access mode types."})
    private_endpoint_connection_name: Optional[str] = field(default=None, metadata={'description': 'The private endpoint connection name associated to the private endpoint on which we want to apply the specific access mode settings.'})  # fmt: skip
    query_access_mode: Optional[str] = field(default=None, metadata={"description": "Access mode types."})


@define(eq=False, slots=False)
class AzureMonitorAccessModeSettings:
    kind: ClassVar[str] = "azure_monitor_access_mode_settings"
    mapping: ClassVar[Dict[str, Bender]] = {
        "exclusions": S("exclusions") >> ForallBend(AzureMonitorAccessModeSettingsExclusion.mapping),
        "ingestion_access_mode": S("ingestionAccessMode"),
        "query_access_mode": S("queryAccessMode"),
    }
    exclusions: Optional[List[AzureMonitorAccessModeSettingsExclusion]] = field(default=None, metadata={'description': 'List of exclusions that override the default access mode settings for specific private endpoint connections.'})  # fmt: skip
    ingestion_access_mode: Optional[str] = field(default=None, metadata={"description": "Access mode types."})
    query_access_mode: Optional[str] = field(default=None, metadata={"description": "Access mode types."})


@define(eq=False, slots=False)
class AzureMonitorPrivateLinkScope(MicrosoftResource):
    kind: ClassVar[str] = "azure_monitor_private_link_scope"
    _kind_display: ClassVar[str] = "Azure Monitor Private Link Scope"
    _kind_service: ClassVar[Optional[str]] = service_name
    _kind_description: ClassVar[str] = "Azure Monitor Private Link Scope is a networking feature that creates a private endpoint for Azure Monitor services. It restricts access to Azure Monitor data to specific virtual networks, enhancing security by eliminating public internet exposure. This service integrates with Azure Private Link to ensure data transfer occurs over Microsoft's private network infrastructure."  # fmt: skip
    _docs_url: ClassVar[str] = "https://learn.microsoft.com/en-us/azure/azure-monitor/logs/private-link-security"
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "config", "group": "management"}
    _create_provider_link: ClassVar[bool] = False
    api_spec: ClassVar[AzureResourceSpec] = AzureResourceSpec(
        service="monitor",
        version="2021-07-01-preview",
        path="/subscriptions/{subscriptionId}/providers/microsoft.insights/privateLinkScopes",
        path_parameters=["subscriptionId"],
        query_parameters=["api-version"],
        access_path="value",
        expect_array=True,
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "location": S("location"),
        "name": S("name"),
        "tags": S("tags").or_else(K({})),
        "ctime": S("systemData", "createdAt"),
        "mtime": S("systemData", "lastModifiedAt"),
        "access_mode_settings": S("properties", "accessModeSettings") >> Bend(AzureMonitorAccessModeSettings.mapping),
        "link_private_endpoint_connections": S("properties", "privateEndpointConnections")
        >> ForallBend(AzurePrivateEndpointConnection.mapping),
        "provisioning_state": S("properties", "provisioningState"),
        "system_data": S("systemData") >> Bend(AzureSystemData.mapping),
    }
    access_mode_settings: Optional[AzureMonitorAccessModeSettings] = field(default=None, metadata={'description': 'Properties that define the scope private link mode settings.'})  # fmt: skip
    link_private_endpoint_connections: Optional[List[AzurePrivateEndpointConnection]] = field(default=None, metadata={'description': 'List of private endpoint connections.'})  # fmt: skip
    system_data: Optional[AzureSystemData] = field(default=None, metadata={'description': 'Metadata pertaining to creation and last modification of the resource.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureMonitorMetrics:
    kind: ClassVar[str] = "azure_monitor_metrics"
    mapping: ClassVar[Dict[str, Bender]] = {
        "internal_id": S("internalId"),
        "prometheus_query_endpoint": S("prometheusQueryEndpoint"),
    }
    internal_id: Optional[str] = field(default=None, metadata={'description': 'An internal identifier for the metrics container. Only to be used by the system'})  # fmt: skip
    prometheus_query_endpoint: Optional[str] = field(default=None, metadata={'description': 'The Prometheus query endpoint for the Azure Monitor Workspace'})  # fmt: skip


@define(eq=False, slots=False)
class AzureMonitorIngestionSettings:
    kind: ClassVar[str] = "azure_monitor_ingestion_settings"
    mapping: ClassVar[Dict[str, Bender]] = {
        "data_collection_endpoint_resource_id": S("dataCollectionEndpointResourceId"),
        "data_collection_rule_resource_id": S("dataCollectionRuleResourceId"),
    }
    data_collection_endpoint_resource_id: Optional[str] = field(default=None, metadata={'description': 'The Azure resource Id of the default data collection endpoint for this Azure Monitor Workspace.'})  # fmt: skip
    data_collection_rule_resource_id: Optional[str] = field(default=None, metadata={'description': 'The Azure resource Id of the default data collection rule for this Azure Monitor Workspace.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureMetadata:
    kind: ClassVar[str] = "azure_metadata"
    mapping: ClassVar[Dict[str, Bender]] = {
        "provisioned_by": S("provisionedBy"),
        "provisioned_by_immutable_id": S("provisionedByImmutableId"),
        "provisioned_by_resource_id": S("provisionedByResourceId"),
    }
    provisioned_by: Optional[str] = field(default=None, metadata={'description': 'Azure offering managing this resource on-behalf-of customer.'})  # fmt: skip
    provisioned_by_immutable_id: Optional[str] = field(default=None, metadata={'description': 'Immutable Id of azure offering managing this resource on-behalf-of customer.'})  # fmt: skip
    provisioned_by_resource_id: Optional[str] = field(default=None, metadata={'description': 'Resource Id of azure offering managing this resource on-behalf-of customer.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureMonitorEndpointsSpec:
    kind: ClassVar[str] = "azure_monitor_endpoints_spec"
    mapping: ClassVar[Dict[str, Bender]] = {
        "logs_ingestion": S("logsIngestion"),
        "metrics_ingestion": S("metricsIngestion"),
    }
    logs_ingestion: Optional[str] = field(default=None, metadata={"description": "The ingestion endpoint for logs"})
    metrics_ingestion: Optional[str] = field(default=None, metadata={'description': 'The ingestion endpoint for metrics'})  # fmt: skip


@define(eq=False, slots=False)
class AzureMonitorStorageBlob:
    kind: ClassVar[str] = "azure_monitor_storage_blob"
    mapping: ClassVar[Dict[str, Bender]] = {
        "blob_url": S("blobUrl"),
        "lookup_type": S("lookupType"),
        "name": S("name"),
        "resource_id": S("resourceId"),
    }
    blob_url: Optional[str] = field(default=None, metadata={"description": "Url of the storage blob"})
    lookup_type: Optional[str] = field(default=None, metadata={'description': 'The type of lookup to perform on the blob'})  # fmt: skip
    name: Optional[str] = field(default=None, metadata={'description': 'The name of the enrichment data source used as an alias when referencing this data source in data flows'})  # fmt: skip
    resource_id: Optional[str] = field(default=None, metadata={'description': 'Resource Id of the storage account that hosts the blob'})  # fmt: skip


@define(eq=False, slots=False)
class AzureMonitorEnrichmentData:
    kind: ClassVar[str] = "azure_monitor_enrichment_data"
    mapping: ClassVar[Dict[str, Bender]] = {
        "storage_blobs": S("storageBlobs") >> ForallBend(AzureMonitorStorageBlob.mapping)
    }
    storage_blobs: Optional[List[AzureMonitorStorageBlob]] = field(default=None, metadata={'description': 'All the storage blobs used as enrichment data sources'})  # fmt: skip


@define(eq=False, slots=False)
class AzureMonitorReferencesSpec:
    kind: ClassVar[str] = "azure_monitor_references_spec"
    mapping: ClassVar[Dict[str, Bender]] = {
        "enrichment_data": S("enrichmentData") >> Bend(AzureMonitorEnrichmentData.mapping)
    }
    enrichment_data: Optional[AzureMonitorEnrichmentData] = field(default=None, metadata={'description': 'All the enrichment data sources referenced in data flows'})  # fmt: skip


@define(eq=False, slots=False)
class AzureMonitorAgentSetting:
    kind: ClassVar[str] = "azure_monitor_agent_setting"
    mapping: ClassVar[Dict[str, Bender]] = {"name": S("name"), "value": S("value")}
    name: Optional[str] = field(default=None, metadata={'description': 'The name of the setting. Must be part of the list of supported settings'})  # fmt: skip
    value: Optional[str] = field(default=None, metadata={"description": "The value of the setting"})


@define(eq=False, slots=False)
class AzureMonitorColumnDefinition:
    kind: ClassVar[str] = "azure_monitor_column_definition"
    mapping: ClassVar[Dict[str, Bender]] = {"name": S("name"), "type": S("type")}
    name: Optional[str] = field(default=None, metadata={"description": "The name of the column."})
    type: Optional[str] = field(default=None, metadata={"description": "The type of the column data."})


@define(eq=False, slots=False)
class AzureMonitorStreamDeclaration:
    kind: ClassVar[str] = "azure_monitor_stream_declaration"
    mapping: ClassVar[Dict[str, Bender]] = {"columns": S("columns") >> ForallBend(AzureMonitorColumnDefinition.mapping)}
    columns: Optional[List[AzureMonitorColumnDefinition]] = field(default=None, metadata={'description': 'List of columns used by data in this stream.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureMonitorLogAnalyticsDestination:
    kind: ClassVar[str] = "azure_monitor_log_analytics_destination"
    mapping: ClassVar[Dict[str, Bender]] = {
        "name": S("name"),
        "workspace_id": S("workspaceId"),
        "workspace_resource_id": S("workspaceResourceId"),
    }
    name: Optional[str] = field(default=None, metadata={'description': 'A friendly name for the destination. This name should be unique across all destinations (regardless of type) within the data collection rule.'})  # fmt: skip
    workspace_id: Optional[str] = field(default=None, metadata={'description': 'The Customer ID of the Log Analytics workspace.'})  # fmt: skip
    workspace_resource_id: Optional[str] = field(default=None, metadata={'description': 'The resource ID of the Log Analytics workspace.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureMonitoringAccountDestination:
    kind: ClassVar[str] = "azure_monitoring_account_destination"
    mapping: ClassVar[Dict[str, Bender]] = {
        "account_id": S("accountId"),
        "account_resource_id": S("accountResourceId"),
        "name": S("name"),
    }
    account_id: Optional[str] = field(default=None, metadata={"description": "The immutable ID of the account."})
    account_resource_id: Optional[str] = field(default=None, metadata={'description': 'The resource ID of the monitoring account.'})  # fmt: skip
    name: Optional[str] = field(default=None, metadata={'description': 'A friendly name for the destination. This name should be unique across all destinations (regardless of type) within the data collection rule.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureMonitorEventHubDestination:
    kind: ClassVar[str] = "azure_monitor_event_hub_destination"
    mapping: ClassVar[Dict[str, Bender]] = {"event_hub_resource_id": S("eventHubResourceId"), "name": S("name")}
    event_hub_resource_id: Optional[str] = field(default=None, metadata={'description': 'The resource ID of the event hub.'})  # fmt: skip
    name: Optional[str] = field(default=None, metadata={'description': 'A friendly name for the destination. This name should be unique across all destinations (regardless of type) within the data collection rule.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureMonitorEventHubDirectDestination:
    kind: ClassVar[str] = "azure_monitor_event_hub_direct_destination"
    mapping: ClassVar[Dict[str, Bender]] = {"event_hub_resource_id": S("eventHubResourceId"), "name": S("name")}
    event_hub_resource_id: Optional[str] = field(default=None, metadata={'description': 'The resource ID of the event hub.'})  # fmt: skip
    name: Optional[str] = field(default=None, metadata={'description': 'A friendly name for the destination. This name should be unique across all destinations (regardless of type) within the data collection rule.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureMonitorStorageBlobDestination:
    kind: ClassVar[str] = "azure_monitor_storage_blob_destination"
    mapping: ClassVar[Dict[str, Bender]] = {
        "container_name": S("containerName"),
        "name": S("name"),
        "storage_account_resource_id": S("storageAccountResourceId"),
    }
    container_name: Optional[str] = field(default=None, metadata={'description': 'The container name of the Storage Blob.'})  # fmt: skip
    name: Optional[str] = field(default=None, metadata={'description': 'A friendly name for the destination. This name should be unique across all destinations (regardless of type) within the data collection rule.'})  # fmt: skip
    storage_account_resource_id: Optional[str] = field(default=None, metadata={'description': 'The resource ID of the storage account.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureMonitorStorageTableDestination:
    kind: ClassVar[str] = "azure_monitor_storage_table_destination"
    mapping: ClassVar[Dict[str, Bender]] = {
        "name": S("name"),
        "storage_account_resource_id": S("storageAccountResourceId"),
        "table_name": S("tableName"),
    }
    name: Optional[str] = field(default=None, metadata={'description': 'A friendly name for the destination. This name should be unique across all destinations (regardless of type) within the data collection rule.'})  # fmt: skip
    storage_account_resource_id: Optional[str] = field(default=None, metadata={'description': 'The resource ID of the storage account.'})  # fmt: skip
    table_name: Optional[str] = field(default=None, metadata={"description": "The name of the Storage Table."})


@define(eq=False, slots=False)
class AzureMicrosoftFabricDestination:
    kind: ClassVar[str] = "azure_microsoft_fabric_destination"
    mapping: ClassVar[Dict[str, Bender]] = {
        "artifact_id": S("artifactId"),
        "database_name": S("databaseName"),
        "ingestion_uri": S("ingestionUri"),
        "name": S("name"),
        "tenant_id": S("tenantId"),
    }
    artifact_id: Optional[str] = field(default=None, metadata={'description': 'The artifact id of the Microsoft Fabric resource.'})  # fmt: skip
    database_name: Optional[str] = field(default=None, metadata={'description': 'The name of the database to which data will be ingested.'})  # fmt: skip
    ingestion_uri: Optional[str] = field(default=None, metadata={'description': 'The ingestion uri of the Microsoft Fabric resource.'})  # fmt: skip
    name: Optional[str] = field(default=None, metadata={'description': 'A friendly name for the destination. This name should be unique across all destinations (regardless of type) within the data collection rule.'})  # fmt: skip
    tenant_id: Optional[str] = field(default=None, metadata={'description': 'The tenant id of the Microsoft Fabric resource.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureMonitorAdxDestination:
    kind: ClassVar[str] = "azure_monitor_adx_destination"
    mapping: ClassVar[Dict[str, Bender]] = {
        "database_name": S("databaseName"),
        "ingestion_uri": S("ingestionUri"),
        "name": S("name"),
        "resource_id": S("resourceId"),
    }
    database_name: Optional[str] = field(default=None, metadata={'description': 'The name of the database to which data will be ingested.'})  # fmt: skip
    ingestion_uri: Optional[str] = field(default=None, metadata={'description': 'The ingestion uri of the Adx resource.'})  # fmt: skip
    name: Optional[str] = field(default=None, metadata={'description': 'A friendly name for the destination. This name should be unique across all destinations (regardless of type) within the data collection rule.'})  # fmt: skip
    resource_id: Optional[str] = field(default=None, metadata={'description': 'The ARM resource id of the Adx resource.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureMonitorDestinationsSpec:
    kind: ClassVar[str] = "azure_monitor_destinations_spec"
    mapping: ClassVar[Dict[str, Bender]] = {
        "azure_data_explorer": S("azureDataExplorer") >> ForallBend(AzureMonitorAdxDestination.mapping),
        "azure_monitor_metrics": S("azureMonitorMetrics") >> Bend(AzureMonitorMetrics.mapping),
        "event_hubs": S("eventHubs") >> ForallBend(AzureMonitorEventHubDestination.mapping),
        "event_hubs_direct": S("eventHubsDirect") >> ForallBend(AzureMonitorEventHubDirectDestination.mapping),
        "log_analytics": S("logAnalytics") >> ForallBend(AzureMonitorLogAnalyticsDestination.mapping),
        "microsoft_fabric": S("microsoftFabric") >> ForallBend(AzureMicrosoftFabricDestination.mapping),
        "monitoring_accounts": S("monitoringAccounts") >> ForallBend(AzureMonitoringAccountDestination.mapping),
        "storage_accounts": S("storageAccounts") >> ForallBend(AzureMonitorStorageBlobDestination.mapping),
        "storage_blobs_direct": S("storageBlobsDirect") >> ForallBend(AzureMonitorStorageBlobDestination.mapping),
        "storage_tables_direct": S("storageTablesDirect") >> ForallBend(AzureMonitorStorageTableDestination.mapping),
    }
    azure_data_explorer: Optional[List[AzureMonitorAdxDestination]] = field(default=None, metadata={'description': 'List of Azure Data Explorer destinations.'})  # fmt: skip
    azure_monitor_metrics: Optional[AzureMonitorMetrics] = field(default=None, metadata={'description': 'Azure Monitor Metrics destination.'})  # fmt: skip
    event_hubs: Optional[List[AzureMonitorEventHubDestination]] = field(default=None, metadata={'description': 'List of Event Hubs destinations.'})  # fmt: skip
    event_hubs_direct: Optional[List[AzureMonitorEventHubDirectDestination]] = field(default=None, metadata={'description': 'List of Event Hubs Direct destinations.'})  # fmt: skip
    log_analytics: Optional[List[AzureMonitorLogAnalyticsDestination]] = field(default=None, metadata={'description': 'List of Log Analytics destinations.'})  # fmt: skip
    microsoft_fabric: Optional[List[AzureMicrosoftFabricDestination]] = field(default=None, metadata={'description': 'List of Microsoft Fabric destinations.'})  # fmt: skip
    monitoring_accounts: Optional[List[AzureMonitoringAccountDestination]] = field(default=None, metadata={'description': 'List of monitoring account destinations.'})  # fmt: skip
    storage_accounts: Optional[List[AzureMonitorStorageBlobDestination]] = field(default=None, metadata={'description': 'List of storage accounts destinations.'})  # fmt: skip
    storage_blobs_direct: Optional[List[AzureMonitorStorageBlobDestination]] = field(default=None, metadata={'description': 'List of Storage Blob Direct destinations. To be used only for sending data directly to store from the agent.'})  # fmt: skip
    storage_tables_direct: Optional[List[AzureMonitorStorageTableDestination]] = field(default=None, metadata={'description': 'List of Storage Table Direct destinations.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureMonitorDataFlow:
    kind: ClassVar[str] = "azure_monitor_data_flow"
    mapping: ClassVar[Dict[str, Bender]] = {
        "built_in_transform": S("builtInTransform"),
        "capture_overflow": S("captureOverflow"),
        "destinations": S("destinations"),
        "output_stream": S("outputStream"),
        "streams": S("streams"),
        "transform_kql": S("transformKql"),
    }
    built_in_transform: Optional[str] = field(default=None, metadata={'description': 'The builtIn transform to transform stream data'})  # fmt: skip
    capture_overflow: Optional[bool] = field(default=None, metadata={'description': 'Flag to enable overflow column in LA destinations'})  # fmt: skip
    destinations: Optional[List[str]] = field(default=None, metadata={'description': 'List of destinations for this data flow.'})  # fmt: skip
    output_stream: Optional[str] = field(default=None, metadata={'description': 'The output stream of the transform. Only required if the transform changes data to a different stream.'})  # fmt: skip
    streams: Optional[List[str]] = field(default=None, metadata={"description": "List of streams for this data flow."})
    transform_kql: Optional[str] = field(default=None, metadata={'description': 'The KQL query to transform stream data.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureMonitorWorkspace(MicrosoftResource):
    kind: ClassVar[str] = "azure_monitor_workspace"
    _kind_display: ClassVar[str] = "Azure Monitor Workspace"
    _kind_service: ClassVar[Optional[str]] = service_name
    _kind_description: ClassVar[str] = "Azure Monitor Workspace is a centralized data storage and analysis solution for Azure resources. It collects logs, metrics, and traces from multiple sources, providing a unified view of operational data. Users can query, visualize, and analyze this data to gain insights into application performance, infrastructure health, and security events across their Azure environment."  # fmt: skip
    _docs_url: ClassVar[str] = (
        "https://learn.microsoft.com/en-us/azure/azure-monitor/logs/log-analytics-workspace-overview"
    )
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "resource", "group": "management"}
    _create_provider_link: ClassVar[bool] = False
    api_spec: ClassVar[AzureResourceSpec] = AzureResourceSpec(
        service="monitor",
        version="2023-04-03",
        path="/subscriptions/{subscriptionId}/providers/Microsoft.Monitor/accounts",
        path_parameters=["subscriptionId"],
        query_parameters=["api-version"],
        access_path="value",
        expect_array=True,
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "location": S("location"),
        "name": S("name"),
        "tags": S("tags").or_else(K({})),
        "etag": S("etag"),
        "account_id": S("properties", "accountId"),
        "default_ingestion_settings": S("properties", "defaultIngestionSettings")
        >> Bend(AzureMonitorIngestionSettings.mapping),
        "metrics": S("properties", "metrics") >> Bend(AzureMonitorMetrics.mapping),
        "workspace_private_endpoint_connections": S("properties", "privateEndpointConnections")
        >> ForallBend(AzurePrivateEndpointConnection.mapping),
        "provisioning_state": S("properties", "provisioningState"),
        "workspace_public_network_access": S("properties", "publicNetworkAccess"),
    }
    account_id: Optional[str] = field(default=None, metadata={'description': 'The immutable Id of the Azure Monitor Workspace. This property is read-only.'})  # fmt: skip
    default_ingestion_settings: Optional[AzureMonitorIngestionSettings] = field(default=None, metadata={'description': 'The Data Collection Rule and Endpoint used for ingestion by default.'})  # fmt: skip
    metrics: Optional[AzureMonitorMetrics] = field(default=None, metadata={'description': 'Properties related to the metrics container in the Azure Monitor Workspace'})  # fmt: skip
    workspace_private_endpoint_connections: Optional[List[AzurePrivateEndpointConnection]] = field(default=None, metadata={'description': 'List of private endpoint connections'})  # fmt: skip
    workspace_public_network_access: Optional[str] = field(default=None, metadata={'description': 'Gets or sets allow or disallow public network access to Azure Monitor Workspace'})  # fmt: skip


@define(eq=False, slots=False)
class AzureMonitorDataCollectionRule(MicrosoftResource):
    kind: ClassVar[str] = "azure_monitor_data_collection_rule"
    _kind_display: ClassVar[str] = "Azure Monitor Data Collection Rule"
    _kind_service: ClassVar[Optional[str]] = service_name
    _kind_description: ClassVar[str] = "Azure Monitor Data Collection Rule is a configuration resource that defines how monitoring data is collected and processed in Azure. It specifies the data sources, collection settings, and destinations for log and metric data. Data Collection Rules help manage and organize monitoring across multiple resources, ensuring consistent data collection and routing within Azure environments."  # fmt: skip
    _docs_url: ClassVar[str] = (
        "https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/data-collection-rule-overview"
    )
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "config", "group": "management"}
    _create_provider_link: ClassVar[bool] = False
    api_spec: ClassVar[AzureResourceSpec] = AzureResourceSpec(
        service="monitor",
        version="2023-03-11",
        path="/subscriptions/{subscriptionId}/providers/Microsoft.Insights/dataCollectionRules",
        path_parameters=["subscriptionId"],
        query_parameters=["api-version"],
        access_path="value",
        expect_array=True,
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "name": S("name"),
        "ctime": S("systemData", "createdAt"),
        "mtime": S("systemData", "lastModifiedAt"),
        "agent_settings": S("agentSettings", "logs") >> ForallBend(AzureMonitorAgentSetting.mapping),
        "data_collection_endpoint_id": S("dataCollectionEndpointId"),
        "data_flows": S("properties", "dataFlows") >> ForallBend(AzureMonitorDataFlow.mapping),
        # "data_sources": S("properties", "dataSources") # fix model gen
        "description": S("properties", "description"),
        "destinations": S("properties", "destinations") >> Bend(AzureMonitorDestinationsSpec.mapping),
        "endpoints": S("properties", "endpoints") >> Bend(AzureMonitorEndpointsSpec.mapping),
        "immutable_id": S("properties", "immutableId"),
        "rule_metadata": S("properties", "metadata") >> Bend(AzureMetadata.mapping),
        "provisioning_state": S("provisioningState"),
        "references": S("properties", "references") >> Bend(AzureMonitorReferencesSpec.mapping),
        "stream_declarations": S("properties", "streamDeclarations"),
        "etag": S("etag"),
        "identity": S("properties", "identity") >> Bend(AzureManagedServiceIdentity.mapping),
        "rule_kind": S("properties", "kind"),
        "system_data": S("systemData") >> Bend(AzureSystemData.mapping),
    }
    agent_settings: Optional[List[AzureMonitorAgentSetting]] = field(default=None, metadata={'description': 'All the settings that are applicable to the logs agent (AMA)'})  # fmt: skip
    data_collection_endpoint_id: Optional[str] = field(default=None, metadata={'description': 'The resource ID of the data collection endpoint that this rule can be used with.'})  # fmt: skip
    data_flows: Optional[List[AzureMonitorDataFlow]] = field(default=None, metadata={'description': 'The specification of data flows.'})  # fmt: skip
    description: Optional[str] = field(default=None, metadata={'description': 'Description of the data collection rule.'})  # fmt: skip
    destinations: Optional[AzureMonitorDestinationsSpec] = field(default=None, metadata={'description': 'The specification of destinations.'})  # fmt: skip
    endpoints: Optional[AzureMonitorEndpointsSpec] = field(default=None, metadata={'description': 'Defines the ingestion endpoints to send data to via this rule.'})  # fmt: skip
    immutable_id: Optional[str] = field(default=None, metadata={'description': 'The immutable ID of this data collection rule. This property is READ-ONLY.'})  # fmt: skip
    rule_metadata: Optional[AzureMetadata] = field(default=None, metadata={"description": "Metadata about the resource"})  # fmt: skip
    references: Optional[AzureMonitorReferencesSpec] = field(default=None, metadata={'description': 'Defines all the references that may be used in other sections of the DCR'})  # fmt: skip
    stream_declarations: Optional[Dict[str, AzureMonitorStreamDeclaration]] = field(default=None, metadata={'description': 'Declaration of custom streams used in this rule.'})  # fmt: skip
    identity: Optional[AzureManagedServiceIdentity] = field(default=None, metadata={'description': 'Managed service identity of the resource.'})  # fmt: skip
    rule_kind: Optional[str] = field(default=None, metadata={"description": "The kind of the resource."})
    system_data: Optional[AzureSystemData] = field(default=None, metadata={'description': 'Metadata pertaining to creation and last modification of the resource.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureMonitorRetentionPolicy:
    kind: ClassVar[str] = "azure_monitor_retention_policy"
    mapping: ClassVar[Dict[str, Bender]] = {"days": S("days"), "enabled": S("enabled")}
    days: Optional[int] = field(default=None, metadata={'description': 'the number of days for the retention in days. A value of 0 will retain the events indefinitely.'})  # fmt: skip
    enabled: Optional[bool] = field(default=None, metadata={'description': 'a value indicating whether the retention policy is enabled.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureMonitorLogProfile(MicrosoftResource):
    kind: ClassVar[str] = "azure_monitor_log_profile"
    _kind_display: ClassVar[str] = "Azure Monitor Log Profile"
    _kind_service: ClassVar[Optional[str]] = service_name
    _kind_description: ClassVar[str] = "Azure Monitor Log Profile is a configuration setting that defines how activity logs are collected and stored in Azure. It specifies which log categories to capture, the retention period for logs, and the destination for log data. This profile helps organizations manage their Azure resource monitoring and maintain compliance with data retention policies."  # fmt: skip
    _docs_url: ClassVar[str] = "https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/activity-log"
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "log", "group": "management"}
    _create_provider_link: ClassVar[bool] = False
    api_spec: ClassVar[AzureResourceSpec] = AzureResourceSpec(
        service="monitor",
        version="2016-03-01",
        path="/subscriptions/{subscriptionId}/providers/Microsoft.Insights/logprofiles",
        path_parameters=["subscriptionId"],
        query_parameters=["api-version"],
        access_path="value",
        expect_array=True,
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "tags": S("tags").or_else(K({})),
        "name": S("name"),
        "profile_categories": S("properties", "categories"),
        "locations": S("properties", "locations"),
        "log_retention_policy": S("properties", "retentionPolicy") >> Bend(AzureMonitorRetentionPolicy.mapping),
        "service_bus_rule_id": S("properties", "serviceBusRuleId"),
        "storage_account_id": S("properties", "storageAccountId"),
    }
    profile_categories: Optional[List[str]] = field(default=None, metadata={'description': 'the categories of the logs. These categories are created as is convenient to the user. Some values are: Write , Delete , and/or Action. '})  # fmt: skip
    locations: Optional[List[str]] = field(default=None, metadata={'description': 'List of regions for which Activity Log events should be stored or streamed. It is a comma separated list of valid ARM locations including the global location.'})  # fmt: skip
    log_retention_policy: Optional[AzureMonitorRetentionPolicy] = field(default=None, metadata={'description': 'Specifies the retention policy for the log.'})  # fmt: skip
    service_bus_rule_id: Optional[str] = field(default=None, metadata={'description': 'The service bus rule ID of the service bus namespace in which you would like to have Event Hubs created for streaming the Activity Log. The rule ID is of the format: {service bus resource ID}/authorizationrules/{key name} .'})  # fmt: skip
    storage_account_id: Optional[str] = field(default=None, metadata={'description': 'the resource id of the storage account to which you would like to send the Activity Log.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureMetricAlertAction:
    kind: ClassVar[str] = "azure_metric_alert_action"
    mapping: ClassVar[Dict[str, Bender]] = {
        "action_group_id": S("actionGroupId"),
        "web_hook_properties": S("webHookProperties"),
    }
    action_group_id: Optional[str] = field(default=None, metadata={'description': 'the id of the action group to use.'})  # fmt: skip
    web_hook_properties: Optional[Dict[str, str]] = field(default=None, metadata={'description': 'This field allows specifying custom properties, which would be appended to the alert payload sent as input to the webhook.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureMonitorMetricAlert(MicrosoftResource):
    kind: ClassVar[str] = "azure_monitor_metric_alert"
    _kind_display: ClassVar[str] = "Azure Metric Alert"
    _kind_service: ClassVar[Optional[str]] = service_name
    _kind_description: ClassVar[str] = "Azure Metric Alert is a monitoring service in Microsoft Azure that tracks specified metrics for resources. It evaluates data against predefined thresholds and triggers notifications when these thresholds are breached. Users can configure alerts for various metrics, set custom conditions, and define actions such as sending emails or executing automated responses when alert conditions are met."  # fmt: skip
    _docs_url: ClassVar[str] = "https://learn.microsoft.com/en-us/azure/azure-monitor/alerts/alerts-metric-overview"
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "alarm", "group": "management"}
    _create_provider_link: ClassVar[bool] = False
    _reference_kinds: ClassVar[ModelReference] = {
        "predecessors": {
            "default": [
                AzureMonitorActionGroup.kind,
            ]
        },
        "successors": {"default": [MicrosoftResource.kind]},
    }
    api_spec: ClassVar[AzureResourceSpec] = AzureResourceSpec(
        service="monitor",
        version="2018-03-01",
        path="/subscriptions/{subscriptionId}/providers/Microsoft.Insights/metricAlerts",
        path_parameters=["subscriptionId"],
        query_parameters=["api-version"],
        access_path="value",
        expect_array=True,
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "tags": S("tags").or_else(K({})),
        "name": S("name"),
        "alert_actions": S("properties", "actions") >> ForallBend(AzureMetricAlertAction.mapping),
        "auto_mitigate": S("properties", "autoMitigate"),
        # "criteria": S("properties", "criteria", "odata.type"),
        "description": S("properties", "description"),
        "enabled": S("properties", "enabled"),
        "evaluation_frequency": S("properties", "evaluationFrequency"),
        "is_migrated": S("properties", "isMigrated"),
        "last_updated_time": S("properties", "lastUpdatedTime"),
        "scopes": S("properties", "scopes"),
        "severity": S("properties", "severity"),
        "target_resource_region": S("properties", "targetResourceRegion"),
        "target_resource_type": S("properties", "targetResourceType"),
        "window_size": S("properties", "windowSize"),
    }
    alert_actions: Optional[List[AzureMetricAlertAction]] = field(default=None, metadata={'description': 'the array of actions that are performed when the alert rule becomes active, and when an alert condition is resolved.'})  # fmt: skip
    auto_mitigate: Optional[bool] = field(default=None, metadata={'description': 'the flag that indicates whether the alert should be auto resolved or not. The default is true.'})  # fmt: skip
    description: Optional[str] = field(default=None, metadata={'description': 'the description of the metric alert that will be included in the alert email.'})  # fmt: skip
    enabled: Optional[bool] = field(default=None, metadata={'description': 'the flag that indicates whether the metric alert is enabled.'})  # fmt: skip
    evaluation_frequency: Optional[str] = field(default=None, metadata={'description': 'how often the metric alert is evaluated represented in ISO 8601 duration format.'})  # fmt: skip
    is_migrated: Optional[bool] = field(default=None, metadata={'description': 'the value indicating whether this alert rule is migrated.'})  # fmt: skip
    last_updated_time: Optional[datetime] = field(default=None, metadata={'description': 'Last time the rule was updated in ISO8601 format.'})  # fmt: skip
    scopes: Optional[List[str]] = field(default=None, metadata={'description': 'the list of resource id s that this metric alert is scoped to.'})  # fmt: skip
    severity: Optional[int] = field(default=None, metadata={"description": "Alert severity {0, 1, 2, 3, 4}"})
    target_resource_region: Optional[str] = field(default=None, metadata={'description': 'the region of the target resource(s) on which the alert is created/updated. Mandatory if the scope contains a subscription, resource group, or more than one resource.'})  # fmt: skip
    target_resource_type: Optional[str] = field(default=None, metadata={'description': 'the resource type of the target resource(s) on which the alert is created/updated. Mandatory if the scope contains a subscription, resource group, or more than one resource.'})  # fmt: skip
    window_size: Optional[str] = field(default=None, metadata={'description': 'the period of time (in ISO 8601 duration format) that is used to monitor alert activity based on the threshold.'})  # fmt: skip

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if alert_actions := self.alert_actions:
            for alert_action in alert_actions:
                if a_group_id := alert_action.action_group_id:
                    builder.add_edge(self, clazz=AzureMonitorActionGroup, reverse=True, id=a_group_id)
        if scopes := self.scopes:
            for scope_id in scopes:
                builder.add_edge(
                    self,
                    clazz=MicrosoftResource,
                    id=scope_id,
                )


@define(eq=False, slots=False)
class AzureMonitorSyslogReceiver:
    kind: ClassVar[str] = "azure_monitor_syslog_receiver"
    mapping: ClassVar[Dict[str, Bender]] = {"endpoint": S("endpoint"), "protocol": S("protocol")}
    endpoint: Optional[str] = field(default=None, metadata={'description': 'Syslog receiver endpoint definition. Example: 0.0.0.0:<port>.'})  # fmt: skip
    protocol: Optional[str] = field(default=None, metadata={'description': 'Protocol to parse syslog messages. Default rfc3164'})  # fmt: skip


@define(eq=False, slots=False)
class AzureMonitorUdpReceiver:
    kind: ClassVar[str] = "azure_monitor_udp_receiver"
    mapping: ClassVar[Dict[str, Bender]] = {
        "encoding": S("encoding"),
        "endpoint": S("endpoint"),
        "read_queue_length": S("readQueueLength"),
    }
    encoding: Optional[str] = field(default=None, metadata={'description': 'The encoding of the stream being received.'})  # fmt: skip
    endpoint: Optional[str] = field(default=None, metadata={'description': 'TCP endpoint definition. Example: 0.0.0.0:<port>.'})  # fmt: skip
    read_queue_length: Optional[int] = field(default=None, metadata={"description": "Max read queue length."})


@define(eq=False, slots=False)
class AzureMonitorReceiver:
    kind: ClassVar[str] = "azure_monitor_receiver"
    mapping: ClassVar[Dict[str, Bender]] = {
        "name": S("name"),
        "otlp": S("otlp", "endpoint"),
        "syslog": S("syslog") >> Bend(AzureMonitorSyslogReceiver.mapping),
        "type": S("type"),
        "udp": S("udp") >> Bend(AzureMonitorUdpReceiver.mapping),
    }
    name: Optional[str] = field(default=None, metadata={"description": "The name of receiver."})
    otlp: Optional[str] = field(default=None, metadata={"description": "OTLP Receiver."})
    syslog: Optional[AzureMonitorSyslogReceiver] = field(default=None, metadata={'description': 'Base receiver using TCP as transport protocol.'})  # fmt: skip
    type: Optional[str] = field(default=None, metadata={"description": "The receiver type."})
    udp: Optional[AzureMonitorUdpReceiver] = field(default=None, metadata={'description': 'Receiver using UDP as transport protocol.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureMonitorBatchProcessor:
    kind: ClassVar[str] = "azure_monitor_batch_processor"
    mapping: ClassVar[Dict[str, Bender]] = {"batch_size": S("batchSize"), "timeout": S("timeout")}
    batch_size: Optional[int] = field(default=None, metadata={"description": "Size of the batch."})
    timeout: Optional[int] = field(default=None, metadata={"description": "Timeout in milliseconds."})


@define(eq=False, slots=False)
class AzureMonitorProcessor:
    kind: ClassVar[str] = "azure_monitor_processor"
    mapping: ClassVar[Dict[str, Bender]] = {
        "batch": S("batch") >> Bend(AzureMonitorBatchProcessor.mapping),
        "name": S("name"),
        "type": S("type"),
    }
    batch: Optional[AzureMonitorBatchProcessor] = field(default=None, metadata={"description": "Batch processor."})
    name: Optional[str] = field(default=None, metadata={"description": "The name of processor."})
    type: Optional[str] = field(default=None, metadata={"description": "The processor type."})


@define(eq=False, slots=False)
class AzureMonitorRecordMap:
    kind: ClassVar[str] = "azure_monitor_record_map"
    mapping: ClassVar[Dict[str, Bender]] = {"from": S("from"), "to": S("to")}
    key_from: Optional[str] = field(default=None, metadata={"description": "Record Map Key."})
    key_to: Optional[str] = field(default=None, metadata={"description": "Record Map Value."})


@define(eq=False, slots=False)
class AzureMonitorResourceMap:
    kind: ClassVar[str] = "azure_monitor_resource_map"
    mapping: ClassVar[Dict[str, Bender]] = {"from": S("from"), "to": S("to")}
    key_from: Optional[str] = field(default=None, metadata={"description": "Resource Map Key."})
    key_to: Optional[str] = field(default=None, metadata={"description": "Resource Map Value."})


@define(eq=False, slots=False)
class AzureMonitorScopeMap:
    kind: ClassVar[str] = "azure_monitor_scope_map"
    mapping: ClassVar[Dict[str, Bender]] = {"from": S("from"), "to": S("to")}
    key_from: Optional[str] = field(default=None, metadata={"description": "Scope Map Key."})
    key_to: Optional[str] = field(default=None, metadata={"description": "Scope Map Value."})


@define(eq=False, slots=False)
class AzureMonitorSchemaMap:
    kind: ClassVar[str] = "azure_monitor_schema_map"
    mapping: ClassVar[Dict[str, Bender]] = {
        "record_map": S("recordMap") >> ForallBend(AzureMonitorRecordMap.mapping),
        "resource_map": S("resourceMap") >> ForallBend(AzureMonitorResourceMap.mapping),
        "scope_map": S("scopeMap") >> ForallBend(AzureMonitorScopeMap.mapping),
    }
    record_map: Optional[List[AzureMonitorRecordMap]] = field(default=None, metadata={"description": "Record Map."})
    resource_map: Optional[List[AzureMonitorResourceMap]] = field(default=None, metadata={'description': 'Resource Map captures information about the entity for which telemetry is recorded. For example, metrics exposed by a Kubernetes container can be linked to a resource that specifies the cluster, namespace, pod, and container name.Resource may capture an entire hierarchy of entity identification. It may describe the host in the cloud and specific container or an application running in the process.'})  # fmt: skip
    scope_map: Optional[List[AzureMonitorScopeMap]] = field(default=None, metadata={'description': 'A scope map is a logical unit of the application code with which the emitted telemetry can be associated.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureMonitorWorkspaceLogsApiConfig:
    kind: ClassVar[str] = "azure_monitor_workspace_logs_api_config"
    mapping: ClassVar[Dict[str, Bender]] = {
        "data_collection_endpoint_url": S("dataCollectionEndpointUrl"),
        "data_collection_rule": S("dataCollectionRule"),
        "schema": S("schema") >> Bend(AzureMonitorSchemaMap.mapping),
        "stream": S("stream"),
    }
    data_collection_endpoint_url: Optional[str] = field(default=None, metadata={'description': 'Data collection endpoint ingestion url.'})  # fmt: skip
    data_collection_rule: Optional[str] = field(default=None, metadata={'description': 'Data Collection Rule (DCR) immutable id.'})  # fmt: skip
    schema: Optional[AzureMonitorSchemaMap] = field(default=None, metadata={'description': 'Schema map for azure monitor for logs.'})  # fmt: skip
    stream: Optional[str] = field(default=None, metadata={'description': 'Stream name in destination. Azure Monitor stream is related to the destination table.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureMonitorConcurrencyConfiguration:
    kind: ClassVar[str] = "azure_monitor_concurrency_configuration"
    mapping: ClassVar[Dict[str, Bender]] = {"batch_queue_size": S("batchQueueSize"), "worker_count": S("workerCount")}
    batch_queue_size: Optional[int] = field(default=None, metadata={'description': 'Size of the queue for log batches.'})  # fmt: skip
    worker_count: Optional[int] = field(default=None, metadata={'description': 'Number of parallel workers processing the log queues.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureMonitorCacheConfiguration:
    kind: ClassVar[str] = "azure_monitor_cache_configuration"
    mapping: ClassVar[Dict[str, Bender]] = {
        "max_storage_usage": S("maxStorageUsage"),
        "retention_period": S("retentionPeriod"),
    }
    max_storage_usage: Optional[int] = field(default=None, metadata={"description": "Max storage usage in megabytes."})
    retention_period: Optional[int] = field(default=None, metadata={"description": "Retention period in minutes."})


@define(eq=False, slots=False)
class AzureMonitorWorkspaceLogsExporter:
    kind: ClassVar[str] = "azure_monitor_workspace_logs_exporter"
    mapping: ClassVar[Dict[str, Bender]] = {
        "api": S("api") >> Bend(AzureMonitorWorkspaceLogsApiConfig.mapping),
        "cache": S("cache") >> Bend(AzureMonitorCacheConfiguration.mapping),
        "concurrency": S("concurrency") >> Bend(AzureMonitorConcurrencyConfiguration.mapping),
    }
    api: Optional[AzureMonitorWorkspaceLogsApiConfig] = field(default=None, metadata={'description': 'Azure Monitor Workspace Logs Api configurations.'})  # fmt: skip
    cache: Optional[AzureMonitorCacheConfiguration] = field(
        default=None, metadata={"description": "Cache configurations."}
    )
    concurrency: Optional[AzureMonitorConcurrencyConfiguration] = field(default=None, metadata={'description': 'Concurrent publishing configuration.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureMonitorExporter:
    kind: ClassVar[str] = "azure_monitor_exporter"
    mapping: ClassVar[Dict[str, Bender]] = {
        "azure_monitor_workspace_logs": S("azureMonitorWorkspaceLogs")
        >> Bend(AzureMonitorWorkspaceLogsExporter.mapping),
        "name": S("name"),
        "tcp": S("tcp", "url"),
        "type": S("type"),
    }
    azure_monitor_workspace_logs: Optional[AzureMonitorWorkspaceLogsExporter] = field(default=None, metadata={'description': 'Azure Monitor Workspace Logs specific configurations.'})  # fmt: skip
    name: Optional[str] = field(default=None, metadata={"description": "The name of exporter."})
    tcp: Optional[str] = field(default=None, metadata={'description': 'Base exporter using TCP as transport protocol.'})  # fmt: skip
    type: Optional[str] = field(default=None, metadata={"description": "The exporter type."})


@define(eq=False, slots=False)
class AzureMonitorPipeline:
    kind: ClassVar[str] = "azure_monitor_pipeline"
    mapping: ClassVar[Dict[str, Bender]] = {
        "exporters": S("exporters"),
        "name": S("name"),
        "processors": S("processors"),
        "receivers": S("receivers"),
        "type": S("type"),
    }
    exporters: Optional[List[str]] = field(default=None, metadata={'description': 'Reference to exporters configured for the pipeline.'})  # fmt: skip
    name: Optional[str] = field(default=None, metadata={"description": "Name of the pipeline."})
    processors: Optional[List[str]] = field(default=None, metadata={'description': 'Reference to processors configured for the pipeline.'})  # fmt: skip
    receivers: Optional[List[str]] = field(default=None, metadata={'description': 'Reference to receivers configured for the pipeline.'})  # fmt: skip
    type: Optional[str] = field(default=None, metadata={"description": "The pipeline type."})


@define(eq=False, slots=False)
class AzureMonitorService:
    kind: ClassVar[str] = "azure_monitor_service"
    mapping: ClassVar[Dict[str, Bender]] = {
        "persistence": S("persistence", "persistentVolumeName"),
        "pipelines": S("pipelines") >> ForallBend(AzureMonitorPipeline.mapping),
    }
    persistence: Optional[str] = field(default=None, metadata={'description': 'Persistence options to all pipelines in the instance.'})  # fmt: skip
    pipelines: Optional[List[AzureMonitorPipeline]] = field(default=None, metadata={'description': 'Pipelines belonging to a given pipeline group.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureMonitorNetworkingRoute:
    kind: ClassVar[str] = "azure_monitor_networking_route"
    mapping: ClassVar[Dict[str, Bender]] = {
        "path": S("path"),
        "port": S("port"),
        "receiver": S("receiver"),
        "subdomain": S("subdomain"),
    }
    path: Optional[str] = field(default=None, metadata={"description": "Route path."})
    port: Optional[int] = field(default=None, metadata={'description': 'The port that will be configured externally. If not specified, it will use the port from the receiver definition.'})  # fmt: skip
    receiver: Optional[str] = field(default=None, metadata={'description': 'The name of the previously defined receiver.'})  # fmt: skip
    subdomain: Optional[str] = field(default=None, metadata={"description": "Route subdomain."})


@define(eq=False, slots=False)
class AzureMonitorNetworkingConfiguration:
    kind: ClassVar[str] = "azure_monitor_networking_configuration"
    mapping: ClassVar[Dict[str, Bender]] = {
        "external_networking_mode": S("externalNetworkingMode"),
        "host": S("host"),
        "routes": S("routes") >> ForallBend(AzureMonitorNetworkingRoute.mapping),
    }
    external_networking_mode: Optional[str] = field(default=None, metadata={'description': 'The mode of the external networking.'})  # fmt: skip
    host: Optional[str] = field(default=None, metadata={'description': 'The address exposed on the cluster. Example: azuremonitorpipeline.contoso.com.'})  # fmt: skip
    routes: Optional[List[AzureMonitorNetworkingRoute]] = field(default=None, metadata={'description': 'Networking routes configuration.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureMonitorPipelineGroup(MicrosoftResource):
    kind: ClassVar[str] = "azure_monitor_pipeline_group"
    _kind_display: ClassVar[str] = "Azure Monitor Pipeline Group"
    _kind_description: ClassVar[str] = "Azure Monitor Pipeline Group is a feature in Azure Monitor that organizes and manages multiple data pipelines. It collects, processes, and routes telemetry data from various sources to different destinations. Users can configure, monitor, and control multiple pipelines within a single group, simplifying management and providing a unified view of data flow across Azure resources."  # fmt: skip
    _docs_url: ClassVar[str] = "https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/pipeline-groups"
    _kind_service: ClassVar[Optional[str]] = service_name
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "group", "group": "management"}
    _create_provider_link: ClassVar[bool] = False
    api_spec: ClassVar[AzureResourceSpec] = AzureResourceSpec(
        service="monitor",
        version="2023-10-01-preview",
        path="/subscriptions/{subscriptionId}/providers/Microsoft.Monitor/pipelineGroups",
        path_parameters=["subscriptionId"],
        query_parameters=["api-version"],
        access_path="value",
        expect_array=True,
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "location": S("location"),
        "name": S("name"),
        "tags": S("tags").or_else(K({})),
        "exporters": S("properties", "exporters") >> ForallBend(AzureMonitorExporter.mapping),
        "extended_location": S("extendedLocation") >> Bend(AzureExtendedLocation.mapping),
        "networking_configurations": S("properties", "networkingConfigurations")
        >> ForallBend(AzureMonitorNetworkingConfiguration.mapping),
        "processors": S("properties", "processors") >> ForallBend(AzureMonitorProcessor.mapping),
        "provisioning_state": S("properties", "provisioningState"),
        "receivers": S("properties", "receivers") >> ForallBend(AzureMonitorReceiver.mapping),
        "replicas": S("properties", "replicas"),
        "monitor_service": S("properties", "service") >> Bend(AzureMonitorService.mapping),
    }
    exporters: Optional[List[AzureMonitorExporter]] = field(default=None, metadata={'description': 'The exporters specified for a pipeline group instance.'})  # fmt: skip
    extended_location: Optional[AzureExtendedLocation] = field(default=None, metadata={'description': 'The extended location info.'})  # fmt: skip
    networking_configurations: Optional[List[AzureMonitorNetworkingConfiguration]] = field(default=None, metadata={'description': 'Networking configurations for the pipeline group instance.'})  # fmt: skip
    processors: Optional[List[AzureMonitorProcessor]] = field(default=None, metadata={'description': 'The processors specified for a pipeline group instance.'})  # fmt: skip
    receivers: Optional[List[AzureMonitorReceiver]] = field(default=None, metadata={'description': 'The receivers specified for a pipeline group instance.'})  # fmt: skip
    replicas: Optional[int] = field(default=None, metadata={'description': 'Defines the amount of replicas of the pipeline group instance.'})  # fmt: skip
    monitor_service: Optional[AzureMonitorService] = field(default=None, metadata={"description": "Service Info."})


@define(eq=False, slots=False)
class AzureMonitorDimension:
    kind: ClassVar[str] = "azure_monitor_dimension"
    mapping: ClassVar[Dict[str, Bender]] = {"name": S("name"), "operator": S("operator"), "values": S("values")}
    name: Optional[str] = field(default=None, metadata={"description": "Name of the dimension"})
    operator: Optional[str] = field(default=None, metadata={"description": "Operator for dimension values"})
    values: Optional[List[str]] = field(default=None, metadata={"description": "List of dimension values"})


@define(eq=False, slots=False)
class AzureMonitorEvaluationsToAlert:
    kind: ClassVar[str] = "azure_monitor_evaluations_to_alert"
    mapping: ClassVar[Dict[str, Bender]] = {
        "min_failing_periods_to_alert": S("minFailingPeriodsToAlert"),
        "number_of_evaluation_periods": S("numberOfEvaluationPeriods"),
    }
    min_failing_periods_to_alert: Optional[int] = field(default=None, metadata={'description': 'The number of violations to trigger an alert. Should be smaller or equal to numberOfEvaluationPeriods. Default value is 1'})  # fmt: skip
    number_of_evaluation_periods: Optional[int] = field(default=None, metadata={'description': 'The number of aggregated lookback points. The lookback time window is calculated based on the aggregation granularity (windowSize) and the selected number of aggregated points. Default value is 1'})  # fmt: skip


@define(eq=False, slots=False)
class AzureMonitorCondition:
    kind: ClassVar[str] = "azure_monitor_condition"
    mapping: ClassVar[Dict[str, Bender]] = {
        "dimensions": S("dimensions") >> ForallBend(AzureMonitorDimension.mapping),
        "failing_periods": S("failingPeriods") >> Bend(AzureMonitorEvaluationsToAlert.mapping),
        "metric_measure_column": S("metricMeasureColumn"),
        "metric_name": S("metricName"),
        "operator": S("operator"),
        "query": S("query"),
        "resource_id_column": S("resourceIdColumn"),
        "threshold": S("threshold"),
        "time_aggregation": S("timeAggregation"),
    }
    dimensions: Optional[List[AzureMonitorDimension]] = field(default=None, metadata={'description': 'List of Dimensions conditions'})  # fmt: skip
    failing_periods: Optional[AzureMonitorEvaluationsToAlert] = field(default=None, metadata={'description': 'The minimum number of violations required within the selected lookback time window required to raise an alert. Relevant only for rules of the kind LogAlert.'})  # fmt: skip
    metric_measure_column: Optional[str] = field(default=None, metadata={'description': 'The column containing the metric measure number. Relevant only for rules of the kind LogAlert.'})  # fmt: skip
    metric_name: Optional[str] = field(default=None, metadata={'description': 'The name of the metric to be sent. Relevant and required only for rules of the kind LogToMetric.'})  # fmt: skip
    operator: Optional[str] = field(default=None, metadata={'description': 'The criteria operator. Relevant and required only for rules of the kind LogAlert.'})  # fmt: skip
    query: Optional[str] = field(default=None, metadata={"description": "Log query alert"})
    resource_id_column: Optional[str] = field(default=None, metadata={'description': 'The column containing the resource id. The content of the column must be a uri formatted as resource id. Relevant only for rules of the kind LogAlert.'})  # fmt: skip
    threshold: Optional[float] = field(default=None, metadata={'description': 'the criteria threshold value that activates the alert. Relevant and required only for rules of the kind LogAlert.'})  # fmt: skip
    time_aggregation: Optional[str] = field(default=None, metadata={'description': 'Aggregation type. Relevant and required only for rules of the kind LogAlert.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureMonitorScheduledQueryRuleCriteria:
    kind: ClassVar[str] = "azure_monitor_scheduled_query_rule_criteria"
    mapping: ClassVar[Dict[str, Bender]] = {"all_of": S("allOf") >> ForallBend(AzureMonitorCondition.mapping)}
    all_of: Optional[List[AzureMonitorCondition]] = field(default=None, metadata={'description': 'A list of conditions to evaluate against the specified scopes'})  # fmt: skip


@define(eq=False, slots=False)
class AzureMonitorActions:
    kind: ClassVar[str] = "azure_monitor_actions"
    mapping: ClassVar[Dict[str, Bender]] = {
        "action_groups": S("actionGroups"),
        "action_properties": S("actionProperties"),
        "custom_properties": S("customProperties"),
    }
    action_groups: Optional[List[str]] = field(default=None, metadata={'description': 'Action Group resource Ids to invoke when the alert fires.'})  # fmt: skip
    action_properties: Optional[Dict[str, str]] = field(default=None, metadata={'description': 'The properties of an action properties.'})  # fmt: skip
    custom_properties: Optional[Dict[str, str]] = field(default=None, metadata={'description': 'The properties of an alert payload.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureMonitorRuleResolveConfiguration:
    kind: ClassVar[str] = "azure_monitor_rule_resolve_configuration"
    mapping: ClassVar[Dict[str, Bender]] = {"auto_resolved": S("autoResolved"), "time_to_resolve": S("timeToResolve")}
    auto_resolved: Optional[bool] = field(default=None, metadata={'description': 'The flag that indicates whether or not to auto resolve a fired alert.'})  # fmt: skip
    time_to_resolve: Optional[str] = field(default=None, metadata={'description': 'The duration a rule must evaluate as healthy before the fired alert is automatically resolved represented in ISO 8601 duration format.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureMonitorScheduledQueryRule(MicrosoftResource):
    kind: ClassVar[str] = "azure_monitor_scheduled_query_rule"
    _kind_display: ClassVar[str] = "Azure Monitor Scheduled Query Rule"
    _kind_service: ClassVar[Optional[str]] = service_name
    _kind_description: ClassVar[str] = "Azure Monitor Scheduled Query Rule is a feature that executes predefined queries on log data at specified intervals. It evaluates the query results against set thresholds and triggers alerts when conditions are met. This tool helps users monitor their Azure resources and applications, detect issues, and respond to potential problems based on collected telemetry data."  # fmt: skip
    _docs_url: ClassVar[str] = "https://learn.microsoft.com/en-us/azure/azure-monitor/alerts/alerts-scheduled-query"
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "config", "group": "management"}
    _create_provider_link: ClassVar[bool] = False
    _reference_kinds: ClassVar[ModelReference] = {
        "successors": {"default": [MicrosoftResource.kind]},
    }
    api_spec: ClassVar[AzureResourceSpec] = AzureResourceSpec(
        service="monitor",
        version="2024-01-01-preview",
        path="/subscriptions/{subscriptionId}/providers/Microsoft.Insights/scheduledQueryRules",
        path_parameters=["subscriptionId"],
        query_parameters=["api-version"],
        access_path="value",
        expect_array=True,
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "tags": S("tags").or_else(K({})),
        "name": S("name"),
        "ctime": S("systemData", "createdAt"),
        "mtime": S("systemData", "lastModifiedAt"),
        "actions": S("properties", "actions") >> Bend(AzureMonitorActions.mapping),
        "auto_mitigate": S("properties", "autoMitigate"),
        "check_workspace_alerts_storage_configured": S("properties", "checkWorkspaceAlertsStorageConfigured"),
        "created_with_api_version": S("properties", "createdWithApiVersion"),
        "criteria": S("properties", "criteria") >> Bend(AzureMonitorScheduledQueryRuleCriteria.mapping),
        "description": S("properties", "description"),
        "display_name": S("properties", "displayName"),
        "enabled": S("properties", "enabled"),
        "etag": S("etag"),
        "evaluation_frequency": S("properties", "evaluationFrequency"),
        "identity": S("identity") >> Bend(AzureManagedServiceIdentity.mapping),
        "is_legacy_log_analytics_rule": S("properties", "isLegacyLogAnalyticsRule"),
        "is_workspace_alerts_storage_configured": S("properties", "isWorkspaceAlertsStorageConfigured"),
        "rule_kind": S("kind"),
        "mute_actions_duration": S("properties", "muteActionsDuration"),
        "override_query_time_range": S("properties", "overrideQueryTimeRange"),
        "rule_resolve_configuration": S("properties", "ruleResolveConfiguration")
        >> Bend(AzureMonitorRuleResolveConfiguration.mapping),
        "scopes": S("properties", "scopes"),
        "severity": S("properties", "severity"),
        "skip_query_validation": S("properties", "skipQueryValidation"),
        "system_data": S("systemData") >> Bend(AzureSystemData.mapping),
        "target_resource_types": S("properties", "targetResourceTypes"),
        "window_size": S("properties", "windowSize"),
    }
    actions: Optional[AzureMonitorActions] = field(default=None, metadata={'description': 'Actions to invoke when the alert fires.'})  # fmt: skip
    auto_mitigate: Optional[bool] = field(default=None, metadata={'description': 'The flag that indicates whether the alert should be automatically resolved or not. The default is true. Relevant only for rules of the kind LogAlert.'})  # fmt: skip
    check_workspace_alerts_storage_configured: Optional[bool] = field(default=None, metadata={'description': 'The flag which indicates whether this scheduled query rule should be stored in the customer s storage. The default is false. Relevant only for rules of the kind LogAlert.'})  # fmt: skip
    created_with_api_version: Optional[str] = field(default=None, metadata={'description': 'The api-version used when creating this alert rule'})  # fmt: skip
    criteria: Optional[AzureMonitorScheduledQueryRuleCriteria] = field(default=None, metadata={'description': 'The rule criteria that defines the conditions of the scheduled query rule.'})  # fmt: skip
    description: Optional[str] = field(default=None, metadata={'description': 'The description of the scheduled query rule.'})  # fmt: skip
    display_name: Optional[str] = field(default=None, metadata={"description": "The display name of the alert rule"})
    enabled: Optional[bool] = field(default=None, metadata={'description': 'The flag which indicates whether this scheduled query rule is enabled. Value should be true or false'})  # fmt: skip
    evaluation_frequency: Optional[str] = field(default=None, metadata={'description': 'How often the scheduled query rule is evaluated represented in ISO 8601 duration format. Relevant and required only for rules of the kind LogAlert.'})  # fmt: skip
    identity: Optional[AzureManagedServiceIdentity] = field(
        default=None, metadata={"description": "Identity for the resource."}
    )
    is_legacy_log_analytics_rule: Optional[bool] = field(default=None, metadata={'description': 'True if alert rule is legacy Log Analytic rule'})  # fmt: skip
    is_workspace_alerts_storage_configured: Optional[bool] = field(default=None, metadata={'description': 'The flag which indicates whether this scheduled query rule has been configured to be stored in the customer s storage. The default is false.'})  # fmt: skip
    rule_kind: Optional[str] = field(default=None, metadata={'description': 'Indicates the type of scheduled query rule. The default is LogAlert.'})  # fmt: skip
    mute_actions_duration: Optional[str] = field(default=None, metadata={'description': 'Mute actions for the chosen period of time (in ISO 8601 duration format) after the alert is fired. Relevant only for rules of the kind LogAlert.'})  # fmt: skip
    override_query_time_range: Optional[str] = field(default=None, metadata={'description': 'If specified then overrides the query time range (default is WindowSize*NumberOfEvaluationPeriods). Relevant only for rules of the kind LogAlert.'})  # fmt: skip
    rule_resolve_configuration: Optional[AzureMonitorRuleResolveConfiguration] = field(default=None, metadata={'description': 'TBD. Relevant only for rules of the kind LogAlert.'})  # fmt: skip
    scopes: Optional[List[str]] = field(default=None, metadata={'description': 'The list of resource id s that this scheduled query rule is scoped to.'})  # fmt: skip
    severity: Optional[int] = field(default=None, metadata={'description': 'Severity of the alert. Should be an integer between [0-4]. Value of 0 is severest. Relevant and required only for rules of the kind LogAlert.'})  # fmt: skip
    skip_query_validation: Optional[bool] = field(default=None, metadata={'description': 'The flag which indicates whether the provided query should be validated or not. The default is false. Relevant only for rules of the kind LogAlert.'})  # fmt: skip
    system_data: Optional[AzureSystemData] = field(default=None, metadata={'description': 'Metadata pertaining to creation and last modification of the resource.'})  # fmt: skip
    target_resource_types: Optional[List[str]] = field(default=None, metadata={'description': 'List of resource type of the target resource(s) on which the alert is created/updated. For example if the scope is a resource group and targetResourceTypes is Microsoft.Compute/virtualMachines, then a different alert will be fired for each virtual machine in the resource group which meet the alert criteria. Relevant only for rules of the kind LogAlert'})  # fmt: skip
    window_size: Optional[str] = field(default=None, metadata={'description': 'The period of time (in ISO 8601 duration format) on which the Alert query will be executed (bin size). Relevant and required only for rules of the kind LogAlert.'})  # fmt: skip

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if scopes := self.scopes:
            for scope_id in scopes:
                builder.add_edge(
                    self,
                    clazz=MicrosoftResource,
                    id=scope_id,
                )


@define(eq=False, slots=True)
class AzureDiagnosticLogRetentionPolicy:
    kind: ClassVar[str] = "azure_diagnostic_retention_policy"
    mapping: ClassVar[Dict[str, Bender]] = {"days": S("category"), "enabled": S("enabled")}
    days: Optional[int] = field(default=None, metadata={'description': 'The number of days to keep the logs.'})  # fmt: skip
    enabled: Optional[bool] = field(default=None, metadata={'description': 'The flag which indicates whether the retention policy is enabled.'})  # fmt: skip


@define(eq=False, slots=True)
class AzureDiagnosticLogSetting:
    kind: ClassVar[str] = "azure_diagnostic_log_setting"
    mapping: ClassVar[Dict[str, Bender]] = {
        "category": S("category"),
        "category_group": S("categoryGroup"),
        "enabled": S("enabled"),
        "retention_policy": S("retentionPolicy") >> Bend(AzureDiagnosticLogRetentionPolicy.mapping),
    }
    category: Optional[str] = field(default=None, metadata={'description': 'The category of the log setting.'})  # fmt: skip
    category_group: Optional[str] = field(default=None, metadata={'description': 'The category group of the log setting.'})  # fmt: skip
    enabled: Optional[bool] = field(default=None, metadata={'description': 'The flag which indicates whether the log setting is enabled.'})  # fmt: skip
    retention_policy: Optional[AzureDiagnosticLogRetentionPolicy] = field(default=None, metadata={'description': 'The retention policy of the log setting.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureMonitorDiagnosticSettings(MicrosoftResource):
    kind: ClassVar[str] = "azure_monitor_diagnostic_settings"
    _kind_display: ClassVar[str] = "Azure Monitor Diagnostic Settings"
    _kind_service: ClassVar[Optional[str]] = service_name
    _kind_description: ClassVar[str] = "Azure Monitor Diagnostic Settings is a feature that collects and routes platform logs and metrics from Azure resources to specified destinations. It supports sending data to Log Analytics workspaces, storage accounts, and event hubs. Users can configure multiple settings per resource, selecting specific log categories and metrics to capture, aiding in monitoring and analysis of Azure resources."  # fmt: skip
    _docs_url: ClassVar[str] = "https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/diagnostic-settings"
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "config", "group": "management"}
    _create_provider_link: ClassVar[bool] = False
    api_spec: ClassVar[AzureResourceSpec] = AzureResourceSpec(
        service="monitor",
        version="2021-05-01-preview",
        path="/subscriptions/{subscriptionId}/providers/Microsoft.Insights/diagnosticSettings",
        path_parameters=["subscriptionId"],
        query_parameters=["api-version"],
        access_path="value",
        expect_array=True,
    )
    _reference_kinds: ClassVar[ModelReference] = {
        "successors": {"default": [AzureStorageAccount.kind, AzureMonitorWorkspace.kind]},
    }
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "ctime": S("systemData", "createdAt"),
        "mtime": S("systemData", "lastModifiedAt"),
        "tags": S("tags").or_else(K({})),
        "name": S("name"),
        "event_hub_authorization_rule_id": S("properties", "eventHubAuthorizationRuleId"),
        "event_hub_name": S("properties", "eventHubName"),
        "logs": S("properties", "logs")
        >> MapDict(S("category").or_else(S("categoryGroup")) >> F(snakecase), Bend(AzureDiagnosticLogSetting.mapping)),
        "marketplace_partner_id": S("properties", "marketplacePartnerId"),
        "service_bus_rule_id": S("properties", "serviceBusRuleId"),
        "storage_account_id": S("properties", "storageAccountId"),
        "system_data": S("systemData") >> Bend(AzureSystemData.mapping),
        "workspace_id": S("properties", "workspaceId"),
    }
    event_hub_authorization_rule_id: Optional[str] = field(default=None, metadata={'description': 'The resource Id for the event hub authorization rule.'})  # fmt: skip
    event_hub_name: Optional[str] = field(default=None, metadata={'description': 'The name of the event hub. If none is specified, the default event hub will be selected.'})  # fmt: skip
    logs: Optional[Dict[str, AzureDiagnosticLogSetting]] = field(default=None, metadata={'description': 'The list of logs settings.'})  # fmt: skip
    marketplace_partner_id: Optional[str] = field(default=None, metadata={'description': 'The full ARM resource ID of the Marketplace resource to which you would like to send Diagnostic Logs.'})  # fmt: skip
    service_bus_rule_id: Optional[str] = field(default=None, metadata={'description': 'The service bus rule Id of the diagnostic setting. This is here to maintain backwards compatibility.'})  # fmt: skip
    storage_account_id: Optional[str] = field(default=None, metadata={'description': 'The resource ID of the storage account to which you would like to send Diagnostic Logs.'})  # fmt: skip
    system_data: Optional[AzureSystemData] = field(default=None, metadata={'description': 'Metadata pertaining to creation and last modification of the resource.'})  # fmt: skip
    workspace_id: Optional[str] = field(default=None, metadata={'description': 'The full ARM resource ID of the Log Analytics workspace to which you would like to send Diagnostic Logs. Example: /subscriptions/4b9e8510-67ab-4e9a-95a9-e2f1e570ea9c/resourceGroups/insights-integration/providers/Microsoft.OperationalInsights/workspaces/viruela2'})  # fmt: skip

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if rid := self.storage_account_id:
            builder.add_edge(self, clazz=AzureStorageAccount, id=rid)
        if rid := self.workspace_id:
            builder.add_edge(self, clazz=AzureMonitorWorkspace, id=rid)

    @staticmethod
    def fetch_diagnostics(builder: GraphBuilder, resource: MicrosoftResource) -> None:
        def execute() -> None:
            for setting in builder.client.list(
                AzureResourceSpec(
                    service="monitor",
                    version="2021-05-01-preview",
                    path=f"{resource.id}/providers/Microsoft.Insights/diagnosticSettings",
                    query_parameters=["api-version"],
                    access_path="value",
                    expect_array=True,
                )
            ):
                if instance := AzureMonitorDiagnosticSettings.from_api(setting, builder):
                    builder.add_node(instance, setting)
                    builder.add_edge(resource, node=instance)

        builder.submit_work(service_name, execute)


resources: List[Type[MicrosoftResource]] = [
    AzureMonitorActionGroup,
    AzureMonitorActivityLogAlert,
    AzureMonitorDataCollectionRule,
    AzureMonitorLogProfile,
    AzureMonitorMetricAlert,
    AzureMonitorPrivateLinkScope,
    AzureMonitorWorkspace,
    AzureMonitorPipelineGroup,
    AzureMonitorScheduledQueryRule,
    AzureMonitorDiagnosticSettings,
]
