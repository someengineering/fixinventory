from __future__ import annotations

import logging
from datetime import datetime
from typing import ClassVar, Dict, Optional, List, Type, Any

from attr import define, field
from isodate import parse_datetime

from fix_plugin_azure.azure_client import RestApiSpec, MicrosoftRestSpec
from fix_plugin_azure.resource.base import GraphBuilder, MicrosoftResource
from fixlib.baseresources import BaseGroup, BaseRole, BaseAccount, BaseRegion, ModelReference, BaseUser
from fixlib.graph import BySearchCriteria, ByNodeId
from fixlib.json_bender import Bender, S, ForallBend, Bend, F, MapDict, reformat_keys_to_snake
from fixlib.types import Json

log = logging.getLogger("fix.plugins.azure")


@define(eq=False, slots=False)
class MicrosoftGraphEntity(MicrosoftResource):
    kind: ClassVar[str] = "microsoft_graph_entity"
    _kind_display: ClassVar[str] = "Microsoft Graph Entity"
    _kind_service: ClassVar[Optional[str]] = "graph"
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "deleted_date_time": S("deletedDateTime"),
    }
    _create_provider_link: ClassVar[bool] = False
    deleted_date_time: Optional[datetime] = field(default=None, metadata={'description': 'Date and time when this object was deleted. Always null when the object hasn\'t been deleted.'})  # fmt: skip


@define(eq=False, slots=False)
class MicrosoftGraphAssignedLicense:
    kind: ClassVar[str] = "microsoft_graph_assigned_license"
    mapping: ClassVar[Dict[str, Bender]] = {"disabled_plans": S("disabledPlans"), "sku_id": S("skuId")}

    disabled_plans: Optional[List[str]] = field(default=None, metadata={'description': 'A collection of the unique identifiers for plans that have been disabled.'})  # fmt: skip
    sku_id: Optional[str] = field(default=None, metadata={"description": "The unique identifier for the SKU."})


@define(eq=False, slots=False)
class MicrosoftGraphOnPremisesProvisioningError:
    kind: ClassVar[str] = "microsoft_graph_on_premises_provisioning_error"
    mapping: ClassVar[Dict[str, Bender]] = {
        "category": S("category"),
        "occurred_date_time": S("occurredDateTime"),
        "property_causing_error": S("propertyCausingError"),
        "value": S("value"),
    }

    category: Optional[str] = field(default=None, metadata={'description': 'Category of the provisioning error. Note: Currently, there is only one possible value. Possible value: PropertyConflict - indicates a property value is not unique. Other objects contain the same value for the property.'})  # fmt: skip
    occurred_date_time: Optional[datetime] = field(default=None, metadata={'description': 'The date and time at which the error occurred.'})  # fmt: skip
    property_causing_error: Optional[str] = field(default=None, metadata={'description': 'Name of the directory property causing the error. Current possible values: UserPrincipalName or ProxyAddress'})  # fmt: skip
    value: Optional[str] = field(default=None, metadata={"description": "Value of the property causing the error."})


@define(eq=False, slots=False)
class MicrosoftGraphWritebackConfiguration:
    kind: ClassVar[str] = "microsoft_graph_writeback_configuration"
    mapping: ClassVar[Dict[str, Bender]] = {"is_enabled": S("isEnabled")}
    is_enabled: Optional[bool] = field(default=None, metadata={'description': 'Indicates whether writeback of cloud groups to on-premise Active Directory is enabled. Default value is true for Microsoft 365 groups and false for security groups.'})  # fmt: skip


@define(eq=False, slots=False)
class MicrosoftGraphGroupWritebackConfiguration(MicrosoftGraphWritebackConfiguration):
    kind: ClassVar[str] = "microsoft_graph_group_writeback_configuration"
    mapping: ClassVar[Dict[str, Bender]] = MicrosoftGraphWritebackConfiguration.mapping | {
        "on_premises_group_type": S("onPremisesGroupType")
    }
    on_premises_group_type: Optional[str] = field(default=None, metadata={'description': 'Indicates the target on-premises group type the cloud object is written back as. Nullable. The possible values are: universalDistributionGroup, universalSecurityGroup, universalMailEnabledSecurityGroup.If the cloud group is a unified (Microsoft 365) group, this property can be one of the following: universalDistributionGroup, universalSecurityGroup, universalMailEnabledSecurityGroup. Microsoft Entra security groups can be written back as universalSecurityGroup. If isEnabled or the NewUnifiedGroupWritebackDefault group setting is true but this property isn t explicitly configured: Microsoft 365 groups are written back as universalDistributionGroup by defaultSecurity groups are written back as universalSecurityGroup by default'})  # fmt: skip


@define(eq=False, slots=False)
class MicrosoftGraphMembershipRuleProcessingStatus:
    kind: ClassVar[str] = "microsoft_graph_membership_rule_processing_status"
    mapping: ClassVar[Dict[str, Bender]] = {
        "error_message": S("errorMessage"),
        "last_membership_updated": S("lastMembershipUpdated"),
        "status": S("status"),
    }
    error_message: Optional[str] = field(default=None, metadata={'description': 'Detailed error message if dynamic group processing ran into an error. Optional. Read-only.'})  # fmt: skip
    last_membership_updated: Optional[str] = field(default=None, metadata={'description': 'Most recent date and time when membership of a dynamic group was updated. Optional. Read-only.'})  # fmt: skip
    status: Optional[str] = field(default=None, metadata={'description': 'Current status of a dynamic group processing. Possible values are: NotStarted, Running, Succeeded, Failed, and UnknownFutureValue. Required. Read-only.'})  # fmt: skip


@define(eq=False, slots=False)
class MicrosoftGraphLicenseProcessingState:
    kind: ClassVar[str] = "microsoft_graph_license_processing_state"
    mapping: ClassVar[Dict[str, Bender]] = {"state": S("state")}
    state: Optional[str] = field(default=None, metadata={"description": ""})


@define(eq=False, slots=False)
class MicrosoftGraphAssignedLabel:
    kind: ClassVar[str] = "microsoft_graph_assigned_label"
    mapping: ClassVar[Dict[str, Bender]] = {"display_name": S("displayName"), "label_id": S("labelId")}
    display_name: Optional[str] = field(default=None, metadata={'description': 'The display name of the label. Read-only.'})  # fmt: skip
    label_id: Optional[str] = field(default=None, metadata={"description": "The unique identifier of the label."})


@define(eq=False, slots=False)
class MicrosoftGraphUnifiedRolePermission:
    kind: ClassVar[str] = "microsoft_graph_unified_role_permission"
    mapping: ClassVar[Dict[str, Bender]] = {
        "allowed_resource_actions": S("allowedResourceActions"),
        "condition": S("condition"),
        "excluded_resource_actions": S("excludedResourceActions"),
    }
    allowed_resource_actions: Optional[List[str]] = field(default=None, metadata={'description': 'Set of tasks that can be performed on a resource.'})  # fmt: skip
    condition: Optional[str] = field(default=None, metadata={'description': 'Optional constraints that must be met for the permission to be effective. Not supported for custom roles.'})  # fmt: skip
    excluded_resource_actions: Optional[List[str]] = field(default=None, metadata={"description": ""})


@define(eq=False, slots=False)
class MicrosoftGraphServiceProvisioningError:
    kind: ClassVar[str] = "microsoft_graph_service_provisioning_error"
    mapping: ClassVar[Dict[str, Bender]] = {
        "created_date_time": S("createdDateTime"),
        "is_resolved": S("isResolved"),
        "service_instance": S("serviceInstance"),
    }
    created_date_time: Optional[datetime] = field(default=None, metadata={'description': 'The date and time at which the error occurred.'})  # fmt: skip
    is_resolved: Optional[bool] = field(default=None, metadata={'description': 'Indicates whether the Error has been attended to.'})  # fmt: skip
    service_instance: Optional[str] = field(default=None, metadata={'description': 'Qualified service instance (for example, SharePoint/Dublin ) that published the service error information.'})  # fmt: skip


@define(eq=False, slots=False)
class MicrosoftGraphProvisionedPlan:
    kind: ClassVar[str] = "microsoft_graph_provisioned_plan"
    mapping: ClassVar[Dict[str, Bender]] = {
        "capability_status": S("capabilityStatus"),
        "provisioning_status": S("provisioningStatus"),
        "service": S("service"),
    }
    capability_status: Optional[str] = field(default=None, metadata={"description": "For example, Enabled ."})
    provisioning_status: Optional[str] = field(default=None, metadata={"description": "For example, Success ."})
    service: Optional[str] = field(default=None, metadata={'description': 'The name of the service; for example, AccessControlS2S '})  # fmt: skip


@define(eq=False, slots=False)
class MicrosoftGraphPasswordProfile:
    kind: ClassVar[str] = "microsoft_graph_password_profile"
    mapping: ClassVar[Dict[str, Bender]] = {
        "force_change_password_next_sign_in": S("forceChangePasswordNextSignIn"),
        "force_change_password_next_sign_in_with_mfa": S("forceChangePasswordNextSignInWithMfa"),
        "password": S("password"),
    }
    force_change_password_next_sign_in: Optional[bool] = field(default=None, metadata={'description': 'true if the user must change their password on the next sign-in; otherwise false. If not set, default is false.'})  # fmt: skip
    force_change_password_next_sign_in_with_mfa: Optional[bool] = field(default=None, metadata={'description': 'If true, at next sign-in, the user must perform a multi-factor authentication (MFA) before being forced to change their password. The behavior is identical to forceChangePasswordNextSignIn except that the user is required to first perform a multi-factor authentication before password change. After a password change, this property will be automatically reset to false. If not set, default is false.'})  # fmt: skip
    password: Optional[str] = field(default=None, metadata={'description': 'The password for the user. This property is required when a user is created. It can be updated, but the user will be required to change the password on the next sign-in. The password must satisfy minimum requirements as specified by the user s passwordPolicies property. By default, a strong password is required.'})  # fmt: skip


@define(eq=False, slots=False)
class MicrosoftGraphOnPremisesSipInfo:
    kind: ClassVar[str] = "microsoft_graph_on_premises_sip_info"
    mapping: ClassVar[Dict[str, Bender]] = {
        "is_sip_enabled": S("isSipEnabled"),
        "sip_deployment_location": S("sipDeploymentLocation"),
        "sip_primary_address": S("sipPrimaryAddress"),
    }
    is_sip_enabled: Optional[bool] = field(default=None, metadata={'description': 'Indicates whether the user is currently enabled for on-premises Skype for Business.'})  # fmt: skip
    sip_deployment_location: Optional[str] = field(default=None, metadata={'description': 'Indicates a fully qualified DNS name of the Microsoft Online Communications Server deployment.'})  # fmt: skip
    sip_primary_address: Optional[str] = field(default=None, metadata={'description': 'Serves as a unique identifier for each user on the on-premises Skype for Business.'})  # fmt: skip


@define(eq=False, slots=False)
class MicrosoftGraphLicenseAssignmentState:
    kind: ClassVar[str] = "microsoft_graph_license_assignment_state"
    mapping: ClassVar[Dict[str, Bender]] = {
        "assigned_by_group": S("assignedByGroup"),
        "disabled_plans": S("disabledPlans"),
        "error": S("error"),
        "last_updated_date_time": S("lastUpdatedDateTime"),
        "sku_id": S("skuId"),
        "state": S("state"),
    }
    assigned_by_group: Optional[str] = field(default=None, metadata={'description': 'Indicates whether the license is directly-assigned or inherited from a group. If directly-assigned, this field is null; if inherited through a group membership, this field contains the ID of the group. Read-Only.'})  # fmt: skip
    disabled_plans: Optional[List[str]] = field(default=None, metadata={'description': 'The service plans that are disabled in this assignment. Read-Only.'})  # fmt: skip
    error: Optional[str] = field(default=None, metadata={'description': 'License assignment failure error. If the license is assigned successfully, this field will be Null. Read-Only. The possible values are CountViolation, MutuallyExclusiveViolation, DependencyViolation, ProhibitedInUsageLocationViolation, UniquenessViolation, and Other. For more information on how to identify and resolve license assignment errors, see here.'})  # fmt: skip
    last_updated_date_time: Optional[datetime] = field(default=None, metadata={'description': 'The timestamp when the state of the license assignment was last updated.'})  # fmt: skip
    sku_id: Optional[str] = field(default=None, metadata={'description': 'The unique identifier for the SKU. Read-Only.'})  # fmt: skip
    state: Optional[str] = field(default=None, metadata={'description': 'Indicate the current state of this assignment. Read-Only. The possible values are Active, ActiveWithError, Disabled, and Error.'})  # fmt: skip


@define(eq=False, slots=False)
class MicrosoftGraphObjectIdentity:
    kind: ClassVar[str] = "microsoft_graph_object_identity"
    mapping: ClassVar[Dict[str, Bender]] = {
        "issuer": S("issuer"),
        "issuer_assigned_id": S("issuerAssignedId"),
        "sign_in_type": S("signInType"),
    }
    issuer: Optional[str] = field(default=None, metadata={'description': 'Specifies the issuer of the identity, for example facebook.com. 512 character limit. For local accounts (where signInType isn t federated), this property is the local default domain name for the tenant, for example contoso.com. For guests from other Microsoft Entra organizations, this is the domain of the federated organization, for example contoso.com. For more information about filtering behavior for this property, see Filtering on the identities property of a user.'})  # fmt: skip
    issuer_assigned_id: Optional[str] = field(default=None, metadata={'description': 'Specifies the unique identifier assigned to the user by the issuer. 64 character limit. The combination of issuer and issuerAssignedId must be unique within the organization. Represents the sign-in name for the user, when signInType is set to emailAddress or userName (also known as local accounts).When signInType is set to: emailAddress (or a custom string that starts with emailAddress like emailAddress1), issuerAssignedId must be a valid email addressuserName, issuerAssignedId must begin with an alphabetical character or number, and can only contain alphanumeric characters and the following symbols: - or _ For more information about filtering behavior for this property, see Filtering on the identities property of a user.'})  # fmt: skip
    sign_in_type: Optional[str] = field(default=None, metadata={'description': 'Specifies the user sign-in types in your directory, such as emailAddress, userName, federated, or userPrincipalName. federated represents a unique identifier for a user from an issuer that can be in any format chosen by the issuer. Setting or updating a userPrincipalName identity updates the value of the userPrincipalName property on the user object. The validations performed on the userPrincipalName property on the user object, for example, verified domains and acceptable characters, are performed when setting or updating a userPrincipalName identity. Extra validation is enforced on issuerAssignedId when the sign-in type is set to emailAddress or userName. This property can also be set to any custom string. For more information about filtering behavior for this property, see Filtering on the identities property of a user.'})  # fmt: skip


@define(eq=False, slots=False)
class MicrosoftGraphEmployeeOrgData:
    kind: ClassVar[str] = "microsoft_graph_employee_org_data"
    mapping: ClassVar[Dict[str, Bender]] = {"cost_center": S("costCenter"), "division": S("division")}
    cost_center: Optional[str] = field(default=None, metadata={'description': 'The cost center associated with the user. Returned only on $select. Supports $filter.'})  # fmt: skip
    division: Optional[str] = field(default=None, metadata={'description': 'The name of the division in which the user works. Returned only on $select. Supports $filter.'})  # fmt: skip


@define(eq=False, slots=False)
class MicrosoftGraphDeviceKey:
    kind: ClassVar[str] = "microsoft_graph_device_key"
    mapping: ClassVar[Dict[str, Bender]] = {
        "device_id": S("deviceId"),
        "key_material": S("keyMaterial"),
        "key_type": S("keyType"),
    }
    device_id: Optional[str] = field(default=None, metadata={"description": ""})
    key_material: Optional[str] = field(default=None, metadata={"description": ""})
    key_type: Optional[str] = field(default=None, metadata={"description": ""})


@define(eq=False, slots=False)
class MicrosoftGraphCloudRealtimeCommunicationInfo:
    kind: ClassVar[str] = "microsoft_graph_cloud_realtime_communication_info"
    mapping: ClassVar[Dict[str, Bender]] = {"is_sip_enabled": S("isSipEnabled")}
    is_sip_enabled: Optional[bool] = field(default=None, metadata={'description': 'Indicates whether the user has a SIP-enabled client registered for them. Read-only.'})  # fmt: skip


@define(eq=False, slots=False)
class MicrosoftGraphAuthorizationInfo:
    kind: ClassVar[str] = "microsoft_graph_authorization_info"
    mapping: ClassVar[Dict[str, Bender]] = {"certificate_user_ids": S("certificateUserIds")}
    certificate_user_ids: Optional[List[str]] = field(default=None, metadata={'description': 'The collection of unique identifiers that can be associated with a user and can be used to bind the Microsoft Entra user to a certificate for authentication and authorization into non-Azure AD environments. The identifiers must be unique in the tenant.'})  # fmt: skip


@define(eq=False, slots=False)
class MicrosoftGraphAssignedPlan:
    kind: ClassVar[str] = "microsoft_graph_assigned_plan"
    mapping: ClassVar[Dict[str, Bender]] = {
        "assigned_date_time": S("assignedDateTime"),
        "capability_status": S("capabilityStatus"),
        "service": S("service"),
        "service_plan_id": S("servicePlanId"),
    }
    assigned_date_time: Optional[datetime] = field(default=None, metadata={'description': 'The date and time at which the plan was assigned; for example: 2013-01-02T19:32:30Z. The Timestamp type represents date and time information using ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 is 2014-01-01T00:00:00Z'})  # fmt: skip
    capability_status: Optional[str] = field(default=None, metadata={'description': 'Condition of the capability assignment. The possible values are Enabled, Warning, Suspended, Deleted, LockedOut.'})  # fmt: skip
    service: Optional[str] = field(default=None, metadata={'description': 'The name of the service; for example, exchange.'})  # fmt: skip
    service_plan_id: Optional[str] = field(default=None, metadata={'description': 'A GUID that identifies the service plan. For a complete list of GUIDs and their equivalent friendly service names, see Product names and service plan identifiers for licensing.'})  # fmt: skip


@define(eq=False, slots=False)
class MicrosoftGraphRole(MicrosoftGraphEntity, BaseRole):
    kind: ClassVar[str] = "microsoft_graph_role"
    _kind_service: ClassVar[Optional[str]] = "entra_id"
    _kind_display: ClassVar[str] = "Microsoft Graph Role"
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "role", "group": "access_control"}
    api_spec: ClassVar[MicrosoftRestSpec] = RestApiSpec(
        "graph",
        "https://graph.microsoft.com/beta/roleManagement/directory/roleDefinitions",
        parameters={
            "$expand": "inheritsPermissionsFrom($select=id)",
            "$select": "allowedPrincipalTypes,description,displayName,id,isBuiltIn,isEnabled,isPrivileged,resourceScopes,rolePermissions,templateId,version",
        },
        access_path="value",
    )
    _reference_kinds: ClassVar[ModelReference] = {"predecessors": {"default": ["microsoft_graph_role"]}}

    mapping: ClassVar[Dict[str, Bender]] = MicrosoftGraphEntity.mapping | {
        "id": S("id"),
        "name": S("displayName"),
        "allowed_principal_types": S("allowedPrincipalTypes"),
        "assignment_mode": S("assignmentMode"),
        "role_categories": S("categories"),
        "description": S("description"),
        "display_name": S("displayName"),
        "is_built_in": S("isBuiltIn"),
        "is_enabled": S("isEnabled"),
        "is_privileged": S("isPrivileged"),
        "resource_scopes": S("resourceScopes"),
        "rich_description": S("richDescription"),
        "graph_role_permissions": S("rolePermissions") >> ForallBend(MicrosoftGraphUnifiedRolePermission.mapping),
        "template_id": S("templateId"),
        "version": S("version"),
    }
    allowed_principal_types: Optional[str] = field(default=None, metadata={'description': 'Types of principals that can be assigned the role. Read-only. The possible values are: user, servicePrincipal, group, unknownFutureValue. This is a multi-valued enumeration that can contain up to three values as a comma-separated string. For example, user, group. Supports $filter (eq).'})  # fmt: skip
    assignment_mode: Optional[str] = field(default=None, metadata={'description': 'Indicates the assignment mode for the role.'})  # fmt: skip
    role_categories: Optional[str] = field(default=None, metadata={'description': 'Categories of the role.'})  # fmt: skip
    description: Optional[str] = field(default=None, metadata={'description': 'The description for the unifiedRoleDefinition. Read-only when isBuiltIn is true.'})  # fmt: skip
    display_name: Optional[str] = field(default=None, metadata={'description': 'The display name for the unifiedRoleDefinition. Read-only when isBuiltIn is true. Required. Supports $filter (eq and startsWith).'})  # fmt: skip
    is_built_in: Optional[bool] = field(default=None, metadata={'description': 'Flag indicating if the unifiedRoleDefinition is part of the default set included with the product or custom. Read-only. Supports $filter (eq).'})  # fmt: skip
    is_enabled: Optional[bool] = field(default=None, metadata={'description': 'Flag indicating if the role is enabled for assignment. If false the role is not available for assignment. Read-only when isBuiltIn is true.'})  # fmt: skip
    is_privileged: Optional[bool] = field(default=None, metadata={'description': 'Flag indicating if the role is privileged. Microsoft Entra ID defines a role as privileged if it contains at least one sensitive resource action in the rolePermissions and allowedResourceActions objects. Applies only for actions in the microsoft.directory resource namespace. Read-only. Supports $filter (eq).'})  # fmt: skip
    resource_scopes: Optional[List[str]] = field(default=None, metadata={'description': 'List of scopes permissions granted by the role definition apply to. Currently only / is supported. Read-only when isBuiltIn is true. DO NOT USE. This will be deprecated soon. Attach scope to role assignment.'})  # fmt: skip
    rich_description: Optional[str] = field(default=None, metadata={'description': 'The description for the unifiedRoleDefinition. Read-only when isBuiltIn is true.'})  # fmt: skip
    graph_role_permissions: Optional[List[MicrosoftGraphUnifiedRolePermission]] = field(default=None, metadata={'description': 'List of permissions included in the role. Read-only when isBuiltIn is true. Required.'})  # fmt: skip
    template_id: Optional[str] = field(default=None, metadata={'description': 'Custom template identifier that can be set when isBuiltIn is false. This identifier is typically used if one needs an identifier to be the same across different directories. Read-only when isBuiltIn is true.'})  # fmt: skip
    version: Optional[str] = field(default=None, metadata={'description': 'Indicates the version of the unifiedRoleDefinition object. Read-only when isBuiltIn is true.'})  # fmt: skip

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        for src in source.get("inheritsPermissionsFrom", []):
            if sid := src.get("id"):
                builder.add_edge(self, reverse=True, clazz=MicrosoftGraphRole, id=sid)


@define(eq=False, slots=False)
class MicrosoftGraphVerifiedPublisher:
    kind: ClassVar[str] = "microsoft_graph_verified_publisher"
    mapping: ClassVar[Dict[str, Bender]] = {
        "added_date_time": S("addedDateTime"),
        "display_name": S("displayName"),
        "verified_publisher_id": S("verifiedPublisherId"),
    }
    added_date_time: Optional[datetime] = field(default=None, metadata={'description': 'The timestamp when the verified publisher was first added or most recently updated.'})  # fmt: skip
    display_name: Optional[str] = field(default=None, metadata={'description': 'The verified publisher name from the app publisher s Microsoft Partner Network (MPN) account.'})  # fmt: skip
    verified_publisher_id: Optional[str] = field(default=None, metadata={'description': 'The ID of the verified publisher from the app publisher s Partner Center account.'})  # fmt: skip


@define(eq=False, slots=False)
class MicrosoftGraphSamlSingleSignOnSettings:
    kind: ClassVar[str] = "microsoft_graph_saml_single_sign_on_settings"
    mapping: ClassVar[Dict[str, Bender]] = {"relay_state": S("relayState")}
    relay_state: Optional[str] = field(default=None, metadata={'description': 'The relative URI the service provider would redirect to after completion of the single sign-on flow.'})  # fmt: skip


@define(eq=False, slots=False)
class MicrosoftGraphPermissionScope:
    kind: ClassVar[str] = "microsoft_graph_permission_scope"
    mapping: ClassVar[Dict[str, Bender]] = {
        "admin_consent_description": S("adminConsentDescription"),
        "admin_consent_display_name": S("adminConsentDisplayName"),
        "id": S("id"),
        "is_enabled": S("isEnabled"),
        "origin": S("origin"),
        "type": S("type"),
        "user_consent_description": S("userConsentDescription"),
        "user_consent_display_name": S("userConsentDisplayName"),
        "value": S("value"),
    }
    admin_consent_description: Optional[str] = field(default=None, metadata={'description': 'A description of the delegated permissions, intended to be read by an administrator granting the permission on behalf of all users. This text appears in tenant-wide admin consent experiences.'})  # fmt: skip
    admin_consent_display_name: Optional[str] = field(default=None, metadata={'description': 'The permission s title, intended to be read by an administrator granting the permission on behalf of all users.'})  # fmt: skip
    id: Optional[str] = field(default=None, metadata={'description': 'Unique delegated permission identifier inside the collection of delegated permissions defined for a resource application.'})  # fmt: skip
    is_enabled: Optional[bool] = field(default=None, metadata={'description': 'When you create or update a permission, this property must be set to true (which is the default). To delete a permission, this property must first be set to false. At that point, in a subsequent call, the permission may be removed.'})  # fmt: skip
    origin: Optional[str] = field(default=None, metadata={"description": ""})
    type: Optional[str] = field(default=None, metadata={'description': 'The possible values are: User and Admin. Specifies whether this delegated permission should be considered safe for non-admin users to consent to on behalf of themselves, or whether an administrator consent should always be required. While Microsoft Graph defines the default consent requirement for each permission, the tenant administrator may override the behavior in their organization (by allowing, restricting, or limiting user consent to this delegated permission). For more information, see Configure how users consent to applications.'})  # fmt: skip
    user_consent_description: Optional[str] = field(default=None, metadata={'description': 'A description of the delegated permissions, intended to be read by a user granting the permission on their own behalf. This text appears in consent experiences where the user is consenting only on behalf of themselves.'})  # fmt: skip
    user_consent_display_name: Optional[str] = field(default=None, metadata={'description': 'A title for the permission, intended to be read by a user granting the permission on their own behalf. This text appears in consent experiences where the user is consenting only on behalf of themselves.'})  # fmt: skip
    value: Optional[str] = field(default=None, metadata={'description': 'Specifies the value to include in the scp (scope) claim in access tokens. Must not exceed 120 characters in length. Allowed characters are : ! # $ % & ( ) * + , - . / : ; = ? @ [ ] ^ + _ { } ~, and characters in the ranges 0-9, A-Z and a-z. Any other character, including the space character, aren t allowed. May not begin with ..'})  # fmt: skip


@define(eq=False, slots=False)
class MicrosoftGraphPasswordSingleSignOnField:
    kind: ClassVar[str] = "microsoft_graph_password_single_sign_on_field"
    mapping: ClassVar[Dict[str, Bender]] = {
        "customized_label": S("customizedLabel"),
        "default_label": S("defaultLabel"),
        "field_id": S("fieldId"),
        "type": S("type"),
    }
    customized_label: Optional[str] = field(default=None, metadata={'description': 'Title/label override for customization.'})  # fmt: skip
    default_label: Optional[str] = field(default=None, metadata={'description': 'Label that would be used if no customizedLabel is provided. Read only.'})  # fmt: skip
    field_id: Optional[str] = field(default=None, metadata={'description': 'Id used to identity the field type. This is an internal ID and possible values are param1, param2, paramuserName, parampassword.'})  # fmt: skip
    type: Optional[str] = field(default=None, metadata={'description': 'Type of the credential. The values can be text, password.'})  # fmt: skip


@define(eq=False, slots=False)
class MicrosoftGraphPasswordCredential:
    kind: ClassVar[str] = "microsoft_graph_password_credential"
    mapping: ClassVar[Dict[str, Bender]] = {
        "custom_key_identifier": S("customKeyIdentifier"),
        "display_name": S("displayName"),
        "end_date_time": S("endDateTime"),
        "hint": S("hint"),
        "key_id": S("keyId"),
        "secret_text": S("secretText"),
        "start_date_time": S("startDateTime"),
    }
    custom_key_identifier: Optional[str] = field(default=None, metadata={"description": "Do not use."})
    display_name: Optional[str] = field(default=None, metadata={'description': 'Friendly name for the password. Optional.'})  # fmt: skip
    end_date_time: Optional[datetime] = field(default=None, metadata={'description': 'The date and time at which the password expires represented using ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 is 2014-01-01T00:00:00Z. Optional.'})  # fmt: skip
    hint: Optional[str] = field(default=None, metadata={'description': 'Contains the first three characters of the password. Read-only.'})  # fmt: skip
    key_id: Optional[str] = field(default=None, metadata={"description": "The unique identifier for the password."})
    secret_text: Optional[str] = field(default=None, metadata={'description': 'Read-only; Contains the strong passwords generated by Microsoft Entra ID that are 16-64 characters in length. The generated password value is only returned during the initial POST request to addPassword. There is no way to retrieve this password in the future.'})  # fmt: skip
    start_date_time: Optional[datetime] = field(default=None, metadata={'description': 'The date and time at which the password becomes valid. The Timestamp type represents date and time information using ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 is 2014-01-01T00:00:00Z. Optional.'})  # fmt: skip


@define(eq=False, slots=False)
class MicrosoftGraphKeyCredential:
    kind: ClassVar[str] = "microsoft_graph_key_credential"
    mapping: ClassVar[Dict[str, Bender]] = {
        "custom_key_identifier": S("customKeyIdentifier"),
        "display_name": S("displayName"),
        "end_date_time": S("endDateTime"),
        "key": S("key"),
        "key_id": S("keyId"),
        "start_date_time": S("startDateTime"),
        "type": S("type"),
        "usage": S("usage"),
    }
    custom_key_identifier: Optional[str] = field(default=None, metadata={'description': 'A 40-character binary type that can be used to identify the credential. Optional. When not provided in the payload, defaults to the thumbprint of the certificate.'})  # fmt: skip
    display_name: Optional[str] = field(default=None, metadata={"description": "Friendly name for the key. Optional."})
    end_date_time: Optional[datetime] = field(default=None, metadata={'description': 'The date and time at which the credential expires. The DateTimeOffset type represents date and time information using ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 is 2014-01-01T00:00:00Z.'})  # fmt: skip
    key: Optional[str] = field(default=None, metadata={'description': 'Value for the key credential. Should be a Base64 encoded value. Returned only on $select for a single object, that is, GET applications/{applicationId}?$select=keyCredentials or GET servicePrincipals/{servicePrincipalId}?$select=keyCredentials; otherwise, it is always null. From a .cer certificate, you can read the key using the Convert.ToBase64String() method. For more information, see Get the certificate key.'})  # fmt: skip
    key_id: Optional[str] = field(default=None, metadata={"description": "The unique identifier for the key."})
    start_date_time: Optional[datetime] = field(default=None, metadata={'description': 'The date and time at which the credential becomes valid.The Timestamp type represents date and time information using ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 is 2014-01-01T00:00:00Z.'})  # fmt: skip
    type: Optional[str] = field(default=None, metadata={'description': 'The type of key credential; for example, Symmetric, AsymmetricX509Cert, or X509CertAndPassword.'})  # fmt: skip
    usage: Optional[str] = field(default=None, metadata={'description': 'A string that describes the purpose for which the key can be used; for example, None​, Verify​, PairwiseIdentifier​, Delegation​, Decrypt​, Encrypt​, HashedIdentifier​, SelfSignedTls, or Sign. If usage is Sign​, the type should be X509CertAndPassword​, and the passwordCredentials​ for signing should be defined.'})  # fmt: skip


@define(eq=False, slots=False)
class MicrosoftGraphInformationalUrl:
    kind: ClassVar[str] = "microsoft_graph_informational_url"
    mapping: ClassVar[Dict[str, Bender]] = {
        "logo_url": S("logoUrl"),
        "marketing_url": S("marketingUrl"),
        "privacy_statement_url": S("privacyStatementUrl"),
        "support_url": S("supportUrl"),
        "terms_of_service_url": S("termsOfServiceUrl"),
    }
    logo_url: Optional[str] = field(default=None, metadata={'description': 'CDN URL to the application s logo, Read-only.'})  # fmt: skip
    marketing_url: Optional[str] = field(default=None, metadata={'description': 'Link to the application s marketing page. For example, https://www.contoso.com/app/marketing'})  # fmt: skip
    privacy_statement_url: Optional[str] = field(default=None, metadata={'description': 'Link to the application s privacy statement. For example, https://www.contoso.com/app/privacy'})  # fmt: skip
    support_url: Optional[str] = field(default=None, metadata={'description': 'Link to the application s support page. For example, https://www.contoso.com/app/support'})  # fmt: skip
    terms_of_service_url: Optional[str] = field(default=None, metadata={'description': 'Link to the application s terms of service statement. For example, https://www.contoso.com/app/termsofservice'})  # fmt: skip


@define(eq=False, slots=False)
class MicrosoftGraphAppRole:
    kind: ClassVar[str] = "microsoft_graph_app_role"
    mapping: ClassVar[Dict[str, Bender]] = {
        "allowed_member_types": S("allowedMemberTypes"),
        "description": S("description"),
        "display_name": S("displayName"),
        "id": S("id"),
        "is_enabled": S("isEnabled"),
        "origin": S("origin"),
        "value": S("value"),
    }
    allowed_member_types: Optional[List[str]] = field(default=None, metadata={'description': 'Specifies whether this app role can be assigned to users and groups (by setting to [ User ]), to other application s (by setting to [ Application ], or both (by setting to [ User , Application ]). App roles supporting assignment to other applications service principals are also known as application permissions. The Application value is only supported for app roles defined on application entities.'})  # fmt: skip
    description: Optional[str] = field(default=None, metadata={'description': 'The description for the app role. This is displayed when the app role is being assigned and, if the app role functions as an application permission, during consent experiences.'})  # fmt: skip
    display_name: Optional[str] = field(default=None, metadata={'description': 'Display name for the permission that appears in the app role assignment and consent experiences.'})  # fmt: skip
    id: Optional[str] = field(default=None, metadata={'description': 'Unique role identifier inside the appRoles collection. You must specify a new GUID identifier when you create a new app role.'})  # fmt: skip
    is_enabled: Optional[bool] = field(default=None, metadata={'description': 'When creating or updating an app role, this must be set to true (which is the default). To delete a role, this must first be set to false. At that point, in a subsequent call, this role may be removed.'})  # fmt: skip
    origin: Optional[str] = field(default=None, metadata={'description': 'Specifies if the app role is defined on the application object or on the servicePrincipal entity. Must not be included in any POST or PATCH requests. Read-only.'})  # fmt: skip
    value: Optional[str] = field(default=None, metadata={'description': 'Specifies the value to include in the roles claim in ID tokens and access tokens authenticating an assigned user or service principal. Must not exceed 120 characters in length. Allowed characters are : ! # $ % & ( ) * + , - . / : ; = ? @ [ ] ^ + _ { } ~, and characters in the ranges 0-9, A-Z and a-z. Any other character, including the space character, aren t allowed. May not begin with ..'})  # fmt: skip


@define(eq=False, slots=False)
class MicrosoftGraphAddIn:
    kind: ClassVar[str] = "microsoft_graph_add_in"
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "properties": S("properties") >> MapDict(S("key"), S("value")),
        "type": S("type"),
    }
    id: Optional[str] = field(default=None, metadata={"description": "The unique identifier for the addIn object."})
    properties: Optional[List[Dict[str, str]]] = field(default=None, metadata={'description': 'The collection of key-value pairs that define parameters that the consuming service can use or call. You must specify this property when performing a POST or a PATCH operation on the addIns collection. Required.'})  # fmt: skip
    type: Optional[str] = field(default=None, metadata={'description': 'The unique name for the functionality exposed by the app.'})  # fmt: skip


@define(eq=False, slots=False)
class MicrosoftGraphAlternativeSecurityId:
    kind: ClassVar[str] = "microsoft_graph_alternative_security_id"
    mapping: ClassVar[Dict[str, Bender]] = {
        "identity_provider": S("identityProvider"),
        "key": S("key"),
        "type": S("type"),
    }
    identity_provider: Optional[str] = field(default=None, metadata={"description": "For internal use only."})
    key: Optional[str] = field(default=None, metadata={"description": "For internal use only."})
    type: Optional[int] = field(default=None, metadata={"description": "For internal use only."})


@define(eq=False, slots=False)
class MicrosoftGraphPrivacyProfile:
    kind: ClassVar[str] = "microsoft_graph_privacy_profile"

    mapping: ClassVar[Dict[str, Bender]] = {"contact_email": S("contactEmail"), "statement_url": S("statementUrl")}
    contact_email: Optional[str] = field(default=None, metadata={'description': 'A valid smtp email address for the privacy statement contact. Not required.'})  # fmt: skip
    statement_url: Optional[str] = field(default=None, metadata={'description': 'A valid URL format that begins with http:// or https://. Maximum length is 255 characters. The URL that directs to the company s privacy statement. Not required.'})  # fmt: skip


@define(eq=False, slots=False)
class MicrosoftGraphDirectorySizeQuota:
    kind: ClassVar[str] = "microsoft_graph_directory_size_quota"

    mapping: ClassVar[Dict[str, Bender]] = {"total": S("total"), "used": S("used")}
    total: Optional[int] = field(default=None, metadata={"description": "Total amount of the directory quota."})
    used: Optional[int] = field(default=None, metadata={"description": "Used amount of the directory quota."})


@define(eq=False, slots=False)
class MicrosoftGraphCertificateConnectorSetting:
    kind: ClassVar[str] = "microsoft_graph_certificate_connector_setting"

    mapping: ClassVar[Dict[str, Bender]] = {
        "cert_expiry_time": S("certExpiryTime"),
        "connector_version": S("connectorVersion"),
        "enrollment_error": S("enrollmentError"),
        "last_connector_connection_time": S("lastConnectorConnectionTime"),
        "last_upload_version": S("lastUploadVersion"),
        "status": S("status"),
    }
    cert_expiry_time: Optional[str] = field(default=None, metadata={"description": "Certificate expire time"})
    connector_version: Optional[str] = field(default=None, metadata={'description': 'Version of certificate connector'})  # fmt: skip
    enrollment_error: Optional[str] = field(default=None, metadata={'description': 'Certificate connector enrollment error'})  # fmt: skip
    last_connector_connection_time: Optional[str] = field(default=None, metadata={'description': 'Last time certificate connector connected'})  # fmt: skip
    last_upload_version: Optional[int] = field(default=None, metadata={'description': 'Version of last uploaded certificate connector'})  # fmt: skip
    status: Optional[int] = field(default=None, metadata={"description": "Certificate connector status"})


@define(eq=False, slots=False)
class MicrosoftGraphVerifiedDomain:
    kind: ClassVar[str] = "microsoft_graph_verified_domain"

    mapping: ClassVar[Dict[str, Bender]] = {
        "capabilities": S("capabilities"),
        "is_default": S("isDefault"),
        "is_initial": S("isInitial"),
        "name": S("name"),
        "type": S("type"),
    }
    capabilities: Optional[str] = field(default=None, metadata={'description': 'For example, Email, OfficeCommunicationsOnline.'})  # fmt: skip
    is_default: Optional[bool] = field(default=None, metadata={'description': 'true if this is the default domain associated with the tenant; otherwise, false.'})  # fmt: skip
    is_initial: Optional[bool] = field(default=None, metadata={'description': 'true if this is the initial domain associated with the tenant; otherwise, false.'})  # fmt: skip
    name: Optional[str] = field(default=None, metadata={"description": "The domain name; for example, contoso.com."})
    type: Optional[str] = field(default=None, metadata={"description": "For example, Managed."})


@define(eq=False, slots=False)
class MicrosoftGraphServicePrincipal(MicrosoftGraphEntity):
    kind: ClassVar[str] = "microsoft_graph_service_principal"
    _kind_service: ClassVar[Optional[str]] = "entra_id"
    _kind_display: ClassVar[str] = "Microsoft Graph Service Principal"
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "user", "group": "access_control"}
    api_spec: ClassVar[MicrosoftRestSpec] = RestApiSpec(
        "graph",
        "https://graph.microsoft.com/v1.0/serviceprincipals",
        parameters={
            "$expand": "memberOf($select=id,roleTemplateId)",  # only look at roles
            "$select": "accountEnabled,addIns,alternativeNames,appDescription,appDisplayName,appId,appOwnerOrganizationId,appRoleAssignmentRequired,appRoles,applicationTemplateId,customSecurityAttributes,deletedDateTime,description,disabledByMicrosoftStatus,displayName,errorUrl,homepage,id,info,keyCredentials,loginUrl,logoutUrl,notes,notificationEmailAddresses,passwordCredentials,passwordSingleSignOnSettings,preferredSingleSignOnMode,preferredTokenSigningKeyEndDateTime,preferredTokenSigningKeyThumbprint,publishedPermissionScopes,publisherName,replyUrls,samlMetadataUrl,samlSingleSignOnSettings,servicePrincipalNames,servicePrincipalType,signInAudience,tags,tokenEncryptionKeyId,verifiedPublisher",
        },
        access_path="value",
    )
    _reference_kinds: ClassVar[ModelReference] = {"successors": {"default": ["microsoft_graph_role"]}}
    mapping: ClassVar[Dict[str, Bender]] = MicrosoftGraphEntity.mapping | {
        "id": S("id"),
        "name": S("displayName"),
        "tags": S("tags") >> F(lambda ts: {t: "yes" for t in ts}),  # transform the array of string into tags dict
        "device_tags": S("tags"),
        "account_enabled": S("accountEnabled"),
        "add_ins": S("addIns") >> ForallBend(MicrosoftGraphAddIn.mapping),
        "alternative_names": S("alternativeNames"),
        "app_description": S("appDescription"),
        "app_display_name": S("appDisplayName"),
        "app_id": S("appId"),
        "app_owner_organization_id": S("appOwnerOrganizationId"),
        "app_role_assignment_required": S("appRoleAssignmentRequired"),
        "app_roles": S("appRoles") >> ForallBend(MicrosoftGraphAppRole.mapping),
        "application_template_id": S("applicationTemplateId"),
        "custom_security_attributes": S("customSecurityAttributes"),
        "description": S("description"),
        "disabled_by_microsoft_status": S("disabledByMicrosoftStatus"),
        "display_name": S("displayName"),
        "error_url": S("errorUrl"),
        "homepage": S("homepage"),
        "info": S("info") >> Bend(MicrosoftGraphInformationalUrl.mapping),
        "key_credentials": S("keyCredentials") >> ForallBend(MicrosoftGraphKeyCredential.mapping),
        "login_url": S("loginUrl"),
        "logout_url": S("logoutUrl"),
        "notes": S("notes"),
        "notification_email_addresses": S("notificationEmailAddresses"),
        "password_credentials": S("passwordCredentials") >> ForallBend(MicrosoftGraphPasswordCredential.mapping),
        "password_single_sign_on_settings": S("passwordSingleSignOnSettings")
        >> S("fields")
        >> ForallBend(MicrosoftGraphPasswordSingleSignOnField.mapping),
        "preferred_single_sign_on_mode": S("preferredSingleSignOnMode"),
        "preferred_token_signing_key_end_date_time": S("preferredTokenSigningKeyEndDateTime"),
        "preferred_token_signing_key_thumbprint": S("preferredTokenSigningKeyThumbprint"),
        "published_permission_scopes": S("publishedPermissionScopes")
        >> ForallBend(MicrosoftGraphPermissionScope.mapping),
        "publisher_name": S("publisherName"),
        "reply_urls": S("replyUrls"),
        "saml_metadata_url": S("samlMetadataUrl"),
        "saml_single_sign_on_settings": S("samlSingleSignOnSettings")
        >> Bend(MicrosoftGraphSamlSingleSignOnSettings.mapping),
        "service_principal_names": S("servicePrincipalNames"),
        "service_principal_type": S("servicePrincipalType"),
        "sign_in_audience": S("signInAudience"),
        "token_encryption_key_id": S("tokenEncryptionKeyId"),
        "verified_publisher": S("verifiedPublisher") >> Bend(MicrosoftGraphVerifiedPublisher.mapping),
        "access_key_status": S("disabledByMicrosoftStatus"),
    }
    account_enabled: Optional[bool] = field(default=None, metadata={'description': 'true if the service principal account is enabled; otherwise, false. If set to false, then no users are able to sign in to this app, even if they re assigned to it. Supports $filter (eq, ne, not, in).'})  # fmt: skip
    add_ins: Optional[List[MicrosoftGraphAddIn]] = field(default=None, metadata={'description': 'Defines custom behavior that a consuming service can use to call an app in specific contexts. For example, applications that can render file streams may set the addIns property for its FileHandler functionality. This lets services like Microsoft 365 call the application in the context of a document the user is working on.'})  # fmt: skip
    alternative_names: Optional[List[str]] = field(default=None, metadata={'description': 'Used to retrieve service principals by subscription, identify resource group and full resource IDs for managed identities. Supports $filter (eq, not, ge, le, startsWith).'})  # fmt: skip
    app_description: Optional[str] = field(default=None, metadata={'description': 'The description exposed by the associated application.'})  # fmt: skip
    app_display_name: Optional[str] = field(default=None, metadata={'description': 'The display name exposed by the associated application.'})  # fmt: skip
    app_id: Optional[str] = field(default=None, metadata={'description': 'The unique identifier for the associated application (its appId property). Alternate key. Supports $filter (eq, ne, not, in, startsWith).'})  # fmt: skip
    app_owner_organization_id: Optional[str] = field(default=None, metadata={'description': 'Contains the tenant ID where the application is registered. This is applicable only to service principals backed by applications. Supports $filter (eq, ne, NOT, ge, le).'})  # fmt: skip
    app_role_assignment_required: Optional[bool] = field(default=None, metadata={'description': 'Specifies whether users or other service principals need to be granted an app role assignment for this service principal before users can sign in or apps can get tokens. The default value is false. Not nullable. Supports $filter (eq, ne, NOT).'})  # fmt: skip
    app_roles: Optional[List[MicrosoftGraphAppRole]] = field(default=None, metadata={'description': 'The roles exposed by the application, which this service principal represents. For more information, see the appRoles property definition on the application entity. Not nullable.'})  # fmt: skip
    application_template_id: Optional[str] = field(default=None, metadata={'description': 'Unique identifier of the applicationTemplate. Supports $filter (eq, not, ne). Read-only. null if the app wasn\'t created from an application template.'})  # fmt: skip
    custom_security_attributes: Optional[Dict[str, str]] = field(default=None, metadata={'description': 'An open complex type that holds the value of a custom security attribute that is assigned to a directory object. Nullable. Returned only on $select. Supports $filter (eq, ne, not, startsWith). Filter value is case sensitive.'})  # fmt: skip
    description: Optional[str] = field(default=None, metadata={'description': 'Free text field to provide an internal end-user facing description of the service principal. End-user portals such MyApps displays the application description in this field. The maximum allowed size is 1,024 characters. Supports $filter (eq, ne, not, ge, le, startsWith) and $search.'})  # fmt: skip
    disabled_by_microsoft_status: Optional[str] = field(default=None, metadata={'description': 'Specifies whether Microsoft has disabled the registered application. Possible values are: null (default value), NotDisabled, and DisabledDueToViolationOfServicesAgreement (reasons may include suspicious, abusive, or malicious activity, or a violation of the Microsoft Services Agreement). Supports $filter (eq, ne, not).'})  # fmt: skip
    display_name: Optional[str] = field(default=None, metadata={'description': 'The display name for the service principal. Supports $filter (eq, ne, not, ge, le, in, startsWith, and eq on null values), $search, and $orderby.'})  # fmt: skip
    error_url: Optional[str] = field(default=None, metadata={"description": "Deprecated. Don t use."})
    homepage: Optional[str] = field(default=None, metadata={'description': 'Home page or landing page of the application.'})  # fmt: skip
    info: Optional[MicrosoftGraphInformationalUrl] = field(default=None, metadata={'description': 'Basic profile information of the acquired application such as app s marketing, support, terms of service and privacy statement URLs. The terms of service and privacy statement are surfaced to users through the user consent experience. For more info, see How to: Add Terms of service and privacy statement for registered Microsoft Entra apps. Supports $filter (eq, ne, not, ge, le, and eq on null values).'})  # fmt: skip
    key_credentials: Optional[List[MicrosoftGraphKeyCredential]] = field(default=None, metadata={'description': 'The collection of key credentials associated with the service principal. Not nullable. Supports $filter (eq, not, ge, le).'})  # fmt: skip
    login_url: Optional[str] = field(default=None, metadata={'description': 'Specifies the URL where the service provider redirects the user to Microsoft Entra ID to authenticate. Microsoft Entra ID uses the URL to launch the application from Microsoft 365 or the Microsoft Entra My Apps. When blank, Microsoft Entra ID performs IdP-initiated sign-on for applications configured with SAML-based single sign-on. The user launches the application from Microsoft 365, the Microsoft Entra My Apps, or the Microsoft Entra SSO URL.'})  # fmt: skip
    logout_url: Optional[str] = field(default=None, metadata={'description': 'Specifies the URL that the Microsoft s authorization service uses to sign out a user using OpenId Connect front-channel, back-channel, or SAML sign out protocols.'})  # fmt: skip
    notes: Optional[str] = field(default=None, metadata={'description': 'Free text field to capture information about the service principal, typically used for operational purposes. Maximum allowed size is 1,024 characters.'})  # fmt: skip
    notification_email_addresses: Optional[List[str]] = field(default=None, metadata={'description': 'Specifies the list of email addresses where Microsoft Entra ID sends a notification when the active certificate is near the expiration date. This is only for the certificates used to sign the SAML token issued for Microsoft Entra Gallery applications.'})  # fmt: skip
    password_credentials: Optional[List[MicrosoftGraphPasswordCredential]] = field(default=None, metadata={'description': 'The collection of password credentials associated with the service principal. Not nullable.'})  # fmt: skip
    password_single_sign_on_settings: Optional[List[MicrosoftGraphPasswordSingleSignOnField]] = field(default=None, metadata={'description': 'The collection for settings related to password single sign-on. Use $select=passwordSingleSignOnSettings to read the property. Read-only for applicationTemplates except for custom applicationTemplates.'})  # fmt: skip
    preferred_single_sign_on_mode: Optional[str] = field(default=None, metadata={'description': 'Specifies the single sign-on mode configured for this application. Microsoft Entra ID uses the preferred single sign-on mode to launch the application from Microsoft 365 or the Microsoft Entra My Apps. The supported values are password, saml, notSupported, and oidc.'})  # fmt: skip
    preferred_token_signing_key_end_date_time: Optional[datetime] = field(default=None, metadata={'description': 'Specifies the expiration date of the keyCredential used for token signing, marked by preferredTokenSigningKeyThumbprint. Updating this attribute isn t currently supported. For details, see ServicePrincipal property differences.'})  # fmt: skip
    preferred_token_signing_key_thumbprint: Optional[str] = field(default=None, metadata={'description': 'This property can be used on SAML applications (apps that have preferredSingleSignOnMode set to saml) to control which certificate is used to sign the SAML responses. For applications that aren t SAML, don t write or otherwise rely on this property.'})  # fmt: skip
    published_permission_scopes: Optional[List[MicrosoftGraphPermissionScope]] = field(default=None, metadata={'description': 'The delegated permissions exposed by the application. For more information, see the oauth2PermissionScopes property on the application entity s api property. Not nullable. Note: This property is named oauth2PermissionScopes in v1.0.'})  # fmt: skip
    publisher_name: Optional[str] = field(default=None, metadata={'description': 'The name of the Microsoft Entra tenant that published the application.'})  # fmt: skip
    reply_urls: Optional[List[str]] = field(default=None, metadata={'description': 'The URLs that user tokens are sent to for sign in with the associated application, or the redirect URIs that OAuth 2.0 authorization codes and access tokens are sent to for the associated application. Not nullable.'})  # fmt: skip
    saml_metadata_url: Optional[str] = field(default=None, metadata={'description': 'The url where the service exposes SAML metadata for federation.'})  # fmt: skip
    saml_single_sign_on_settings: Optional[MicrosoftGraphSamlSingleSignOnSettings] = field(default=None, metadata={'description': 'The collection for settings related to saml single sign-on.'})  # fmt: skip
    service_principal_names: Optional[List[str]] = field(default=None, metadata={'description': 'Contains the list of identifiersUris, copied over from the associated application. More values can be added to hybrid applications. These values can be used to identify the permissions exposed by this app within Microsoft Entra ID. For example,Client apps can specify a resource URI that is based on the values of this property to acquire an access token, which is the URI returned in the aud claim.The any operator is required for filter expressions on multi-valued properties. Not nullable. Supports $filter (eq, not, ge, le, startsWith).'})  # fmt: skip
    service_principal_type: Optional[str] = field(default=None, metadata={'description': 'Identifies if the service principal represents an application or a managed identity. This is set by Microsoft Entra ID internally. For a service principal that represents an application this is set as Application. For a service principal that represents a managed identity this is set as ManagedIdentity. The SocialIdp type is for internal use.'})  # fmt: skip
    sign_in_audience: Optional[str] = field(default=None, metadata={'description': 'Specifies the Microsoft accounts that are supported for the current application. Read-only. Supported values are:AzureADMyOrg: Users with a Microsoft work or school account in my organization s Microsoft Entra tenant (single-tenant).AzureADMultipleOrgs: Users with a Microsoft work or school account in any organization s Microsoft Entra tenant (multitenant).AzureADandPersonalMicrosoftAccount: Users with a personal Microsoft account, or a work or school account in any organization s Microsoft Entra tenant.PersonalMicrosoftAccount: Users with a personal Microsoft account only.'})  # fmt: skip
    device_tags: Optional[List[str]] = field(default=None, metadata={'description': 'Custom strings that can be used to categorize and identify the service principal. Not nullable. The value is the union of strings set here and on the associated application entity s tags property.Supports $filter (eq, not, ge, le, startsWith).'})  # fmt: skip
    token_encryption_key_id: Optional[str] = field(default=None, metadata={'description': 'Specifies the keyId of a public key from the keyCredentials collection. When configured, Microsoft Entra ID issues tokens for this application encrypted using the key specified by this property. The application code that receives the encrypted token must use the matching private key to decrypt the token before it can be used for the signed-in user.'})  # fmt: skip
    verified_publisher: Optional[MicrosoftGraphVerifiedPublisher] = field(default=None, metadata={'description': 'Specifies the verified publisher of the application that s linked to this service principal.'})  # fmt: skip

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        for member in source.get("memberOf", []):
            if member.get("@odata.type") == "#microsoft.graph.directoryRole" and (rid := member.get("roleTemplateId")):
                builder.add_edge(self, clazz=MicrosoftGraphRole, template_id=rid)


@define(eq=False, slots=False)
class MicrosoftGraphDevice(MicrosoftGraphEntity):
    kind: ClassVar[str] = "microsoft_graph_device"
    _kind_service: ClassVar[Optional[str]] = "entra_id"
    _kind_display: ClassVar[str] = "Microsoft Graph Device"
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "resource", "group": "access_control"}
    api_spec: ClassVar[MicrosoftRestSpec] = RestApiSpec(
        "graph",
        "https://graph.microsoft.com/v1.0/devices",
        parameters={
            "$expand": "memberOf($select=id,roleTemplateId)",  # only look at roles
            "$select": "accountEnabled,alternativeSecurityIds,approximateLastSignInDateTime,complianceExpirationDateTime,deletedDateTime,deviceCategory,deviceId,deviceMetadata,deviceOwnership,deviceVersion,displayName,domainName,enrollmentProfileName,enrollmentType,extensionAttributes,hostnames,id,isCompliant,isManaged,isManagementRestricted,isRooted,kind,managementType,manufacturer,mdmAppId,model,name,onPremisesLastSyncDateTime,onPremisesSecurityIdentifier,onPremisesSyncEnabled,operatingSystem,operatingSystemVersion,physicalIds,platform,profileType,registrationDateTime,status,systemLabels,trustType",
        },
        access_path="value",
    )
    _reference_kinds: ClassVar[ModelReference] = {"successors": {"default": ["microsoft_graph_role"]}}
    mapping: ClassVar[Dict[str, Bender]] = MicrosoftGraphEntity.mapping | {
        "id": S("id"),
        "name": S("name"),
        "account_enabled": S("accountEnabled"),
        "alternative_security_ids": S("alternativeSecurityIds")
        >> ForallBend(MicrosoftGraphAlternativeSecurityId.mapping),
        "approximate_last_sign_in_date_time": S("approximateLastSignInDateTime"),
        "compliance_expiration_date_time": S("complianceExpirationDateTime"),
        "device_category": S("deviceCategory"),
        "device_id": S("deviceId"),
        "device_metadata": S("deviceMetadata"),
        "device_ownership": S("deviceOwnership"),
        "device_version": S("deviceVersion"),
        "display_name": S("displayName"),
        "domain_name": S("domainName"),
        "enrollment_profile_name": S("enrollmentProfileName"),
        "enrollment_type": S("enrollmentType"),
        "extension_attributes": S("extensionAttributes"),
        "hostnames": S("hostnames"),
        "is_compliant": S("isCompliant"),
        "is_managed": S("isManaged"),
        "is_management_restricted": S("isManagementRestricted"),
        "is_rooted": S("isRooted"),
        "device_kind": S("kind"),
        "management_type": S("managementType"),
        "manufacturer": S("manufacturer"),
        "mdm_app_id": S("mdmAppId"),
        "model": S("model"),
        "on_premises_last_sync_date_time": S("onPremisesLastSyncDateTime"),
        "on_premises_security_identifier": S("onPremisesSecurityIdentifier"),
        "on_premises_sync_enabled": S("onPremisesSyncEnabled"),
        "operating_system": S("operatingSystem"),
        "operating_system_version": S("operatingSystemVersion"),
        "physical_ids": S("physicalIds"),
        "platform": S("platform"),
        "profile_type": S("profileType"),
        "registration_date_time": S("registrationDateTime"),
        "status": S("status"),
        "system_labels": S("systemLabels"),
        "trust_type": S("trustType"),
    }
    account_enabled: Optional[bool] = field(default=None, metadata={'description': 'true if the account is enabled; otherwise, false. Default is true. Supports $filter (eq, ne, not, in). Only callers with at least the Cloud Device Administrator role can set this property.'})  # fmt: skip
    alternative_security_ids: Optional[List[MicrosoftGraphAlternativeSecurityId]] = field(default=None, metadata={'description': 'For internal use only. Not nullable. Supports $filter (eq, not, ge, le).'})  # fmt: skip
    approximate_last_sign_in_date_time: Optional[datetime] = field(default=None, metadata={'description': 'The timestamp type represents date and time information using ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 is 2014-01-01T00:00:00Z. Read-only. Supports $filter (eq, ne, not, ge, le, and eq on null values) and $orderby.'})  # fmt: skip
    compliance_expiration_date_time: Optional[datetime] = field(default=None, metadata={'description': 'The timestamp when the device is no longer deemed compliant. The timestamp type represents date and time information using ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 is 2014-01-01T00:00:00Z. Read-only.'})  # fmt: skip
    device_category: Optional[str] = field(default=None, metadata={'description': 'User-defined property set by Intune to automatically add devices to groups and simplify managing devices.'})  # fmt: skip
    device_id: Optional[str] = field(default=None, metadata={'description': 'Unique Identifier set by Azure Device Registration Service at the time of registration. This is an alternate key that can be used to reference the device object. Also Supports $filter (eq, ne, not, startsWith).'})  # fmt: skip
    device_metadata: Optional[str] = field(default=None, metadata={'description': 'For internal use only. Set to null.'})  # fmt: skip
    device_ownership: Optional[str] = field(default=None, metadata={'description': 'Ownership of the device. This property is set by Intune. Possible values are: unknown, company, personal.'})  # fmt: skip
    device_version: Optional[int] = field(default=None, metadata={"description": "For internal use only."})
    display_name: Optional[str] = field(default=None, metadata={'description': 'The display name for the device. Required. Supports $filter (eq, ne, not, ge, le, in, startsWith, and eq on null values), $search, and $orderby.'})  # fmt: skip
    domain_name: Optional[str] = field(default=None, metadata={'description': 'The on-premises domain name of Microsoft Entra hybrid joined devices. This property is set by Intune.'})  # fmt: skip
    enrollment_profile_name: Optional[str] = field(default=None, metadata={'description': 'Enrollment profile applied to the device. For example, Apple Device Enrollment Profile, Device enrollment - Corporate device identifiers, or Windows Autopilot profile name. This property is set by Intune.'})  # fmt: skip
    enrollment_type: Optional[str] = field(default=None, metadata={'description': 'Enrollment type of the device. This property is set by Intune. Possible values are: unknown, userEnrollment, deviceEnrollmentManager, appleBulkWithUser, appleBulkWithoutUser, windowsAzureADJoin, windowsBulkUserless, windowsAutoEnrollment, windowsBulkAzureDomainJoin, windowsCoManagement.'})  # fmt: skip
    extension_attributes: Optional[Dict[str, str]] = field(default=None, metadata={'description': 'Contains extension attributes 1-15 for the device. The individual extension attributes aren t selectable. These properties are mastered in cloud and can be set during creation or update of a device object in Microsoft Entra ID. Supports $filter (eq, not, startsWith, and eq on null values).'})  # fmt: skip
    hostnames: Optional[List[str]] = field(default=None, metadata={"description": "List of host names for the device."})
    is_compliant: Optional[bool] = field(default=None, metadata={'description': 'true if the device complies with Mobile Device Management (MDM) policies; otherwise, false. Read-only. This can only be updated by Intune for any device OS type or by an approved MDM app for Windows OS devices. Supports $filter (eq, ne, not).'})  # fmt: skip
    is_managed: Optional[bool] = field(default=None, metadata={'description': 'true if the device is managed by a Mobile Device Management (MDM) app; otherwise, false. This can only be updated by Intune for any device OS type or by an approved MDM app for Windows OS devices. Supports $filter (eq, ne, not).'})  # fmt: skip
    is_management_restricted: Optional[bool] = field(default=None, metadata={'description': 'Indicates whether the device is a member of a restricted management administrative unit, in which case it requires a role scoped to the restricted administrative unit to manage. The default value is false. Read-only. To manage a device that s a member of a restricted administrative unit, the calling app must be assigned the Directory.Write.Restricted permission. For delegated scenarios, the administrators must also be explicitly assigned supported roles at the restricted administrative unit scope.'})  # fmt: skip
    is_rooted: Optional[bool] = field(default=None, metadata={'description': 'true if the device is rooted or jail-broken. This property can only be updated by Intune.'})  # fmt: skip
    device_kind: Optional[str] = field(default=None, metadata={'description': 'Form factor of the device. Only returned if the user signs in with a Microsoft account as part of Project Rome.'})  # fmt: skip
    management_type: Optional[str] = field(default=None, metadata={'description': 'Management channel of the device. This property is set by Intune. Possible values are: eas, mdm, easMdm, intuneClient, easIntuneClient, configurationManagerClient, configurationManagerClientMdm, configurationManagerClientMdmEas, unknown, jamf, googleCloudDevicePolicyController.'})  # fmt: skip
    manufacturer: Optional[str] = field(default=None, metadata={'description': 'Manufacturer of the device. Read-only.'})  # fmt: skip
    mdm_app_id: Optional[str] = field(default=None, metadata={'description': 'Application identifier used to register device into MDM. Read-only. Supports $filter (eq, ne, not, startsWith).'})  # fmt: skip
    model: Optional[str] = field(default=None, metadata={"description": "Model of the device. Read-only."})
    on_premises_last_sync_date_time: Optional[datetime] = field(default=None, metadata={'description': 'The last time at which the object was synced with the on-premises directory. The Timestamp type represents date and time information using ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 is 2014-01-01T00:00:00Z Read-only. Supports $filter (eq, ne, not, ge, le, in).'})  # fmt: skip
    on_premises_security_identifier: Optional[str] = field(default=None, metadata={'description': 'The on-premises security identifier (SID) for the user who was synchronized from on-premises to the cloud. Read-only. Returned only on $select. Supports $filter (eq).'})  # fmt: skip
    on_premises_sync_enabled: Optional[bool] = field(default=None, metadata={'description': 'true if this object is synced from an on-premises directory; false if this object was originally synced from an on-premises directory but is no longer synced; null if this object has never been synced from an on-premises directory (default). Read-only. Supports $filter (eq, ne, not, in, and eq on null values).'})  # fmt: skip
    operating_system: Optional[str] = field(default=None, metadata={'description': 'The type of operating system on the device. Required. Supports $filter (eq, ne, not, ge, le, startsWith, and eq on null values).'})  # fmt: skip
    operating_system_version: Optional[str] = field(default=None, metadata={'description': 'Operating system version of the device. Required. Supports $filter (eq, ne, not, ge, le, startsWith, and eq on null values).'})  # fmt: skip
    physical_ids: Optional[List[str]] = field(default=None, metadata={'description': 'For internal use only. Not nullable. Supports $filter (eq, not, ge, le, startsWith, /$count eq 0, /$count ne 0.'})  # fmt: skip
    platform: Optional[str] = field(default=None, metadata={'description': 'Platform of device. Only returned if the user signs in with a Microsoft account as part of Project Rome.'})  # fmt: skip
    profile_type: Optional[str] = field(default=None, metadata={'description': 'The profile type of the device. Possible values: RegisteredDevice (default), SecureVM, Printer, Shared, IoT.'})  # fmt: skip
    registration_date_time: Optional[datetime] = field(default=None, metadata={'description': 'Date and time of when the device was registered. The timestamp type represents date and time information using ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 is 2014-01-01T00:00:00Z. Read-only.'})  # fmt: skip
    status: Optional[str] = field(default=None, metadata={'description': 'Device is online or offline. Only returned if user signs in with a Microsoft account as part of Project Rome.'})  # fmt: skip
    system_labels: Optional[List[str]] = field(default=None, metadata={'description': 'List of labels applied to the device by the system. Supports $filter (/$count eq 0, /$count ne 0).'})  # fmt: skip
    trust_type: Optional[str] = field(default=None, metadata={'description': 'Type of trust for the joined device. Read-only. Possible values: Workplace (indicates bring your own personal devices), AzureAd (Cloud only joined devices), ServerAd (on-premises domain joined devices joined to Microsoft Entra ID). For more information, see Introduction to device management in Microsoft Entra ID.'})  # fmt: skip

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        for member in source.get("memberOf", []):
            if member.get("@odata.type") == "#microsoft.graph.directoryRole" and (rid := member.get("roleTemplateId")):
                builder.add_edge(self, clazz=MicrosoftGraphRole, template_id=rid)


@define(eq=False, slots=False)
class MicrosoftGraphUser(MicrosoftGraphEntity, BaseUser):
    kind: ClassVar[str] = "microsoft_graph_user"
    _kind_service: ClassVar[Optional[str]] = "entra_id"
    _kind_display: ClassVar[str] = "Microsoft Graph User"
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "user", "group": "access_control"}
    api_spec: ClassVar[MicrosoftRestSpec] = RestApiSpec(
        "graph",
        "https://graph.microsoft.com/v1.0/users",
        parameters={
            "$expand": "memberOf($select=id,roleTemplateId)",  # only look at roles
            "$select": "accountEnabled,ageGroup,assignedLicenses,assignedPlans,authorizationInfo,businessPhones,city,cloudRealtimeCommunicationInfo,companyName,consentProvidedForMinor,country,createdDateTime,creationType,customSecurityAttributes,deletedDateTime,department,deviceKeys,displayName,employeeHireDate,employeeId,employeeLeaveDateTime,employeeOrgData,employeeType,externalUserState,externalUserStateChangeDateTime,faxNumber,givenName,id,identities,imAddresses,infoCatalogs,isManagementRestricted,isResourceAccount,jobTitle,lastPasswordChangeDateTime,legalAgeGroupClassification,licenseAssignmentStates,mail,mailNickname,mobilePhone,officeLocation,onPremisesDistinguishedName,onPremisesDomainName,onPremisesExtensionAttributes,onPremisesImmutableId,onPremisesLastSyncDateTime,onPremisesProvisioningErrors,onPremisesSamAccountName,onPremisesSecurityIdentifier,onPremisesSipInfo,onPremisesSyncEnabled,onPremisesUserPrincipalName,otherMails,passwordPolicies,passwordProfile,postalCode,preferredDataLocation,preferredLanguage,provisionedPlans,proxyAddresses,refreshTokensValidFromDateTime,securityIdentifier,serviceProvisioningErrors,showInAddressList,signInSessionsValidFromDateTime,state,streetAddress,surname,usageLocation,userPrincipalName,userType",
        },
        access_path="value",
    )
    _reference_kinds: ClassVar[ModelReference] = {"successors": {"default": ["microsoft_graph_role"]}}
    mapping: ClassVar[Dict[str, Bender]] = MicrosoftGraphEntity.mapping | {
        "id": S("id"),
        "name": S("displayName"),
        "ctime": S("createdDateTime"),
        "account_enabled": S("accountEnabled"),
        "age_group": S("ageGroup"),
        "assigned_licenses": S("assignedLicenses") >> ForallBend(MicrosoftGraphAssignedLicense.mapping),
        "assigned_plans": S("assignedPlans") >> ForallBend(MicrosoftGraphAssignedPlan.mapping),
        "authorization_info": S("authorizationInfo") >> Bend(MicrosoftGraphAuthorizationInfo.mapping),
        "business_phones": S("businessPhones"),
        "city": S("city"),
        "cloud_realtime_communication_info": S("cloudRealtimeCommunicationInfo")
        >> Bend(MicrosoftGraphCloudRealtimeCommunicationInfo.mapping),
        "company_name": S("companyName"),
        "consent_provided_for_minor": S("consentProvidedForMinor"),
        "country": S("country"),
        "created_date_time": S("createdDateTime"),
        "creation_type": S("creationType"),
        "custom_security_attributes": S("customSecurityAttributes"),
        "department": S("department"),
        "device_keys": S("deviceKeys") >> ForallBend(MicrosoftGraphDeviceKey.mapping),
        "display_name": S("displayName"),
        "employee_hire_date": S("employeeHireDate"),
        "employee_id": S("employeeId"),
        "employee_leave_date_time": S("employeeLeaveDateTime"),
        "employee_org_data": S("employeeOrgData") >> Bend(MicrosoftGraphEmployeeOrgData.mapping),
        "employee_type": S("employeeType"),
        "external_user_state": S("externalUserState"),
        "external_user_state_change_date_time": S("externalUserStateChangeDateTime"),
        "fax_number": S("faxNumber"),
        "given_name": S("givenName"),
        "identities": S("identities") >> ForallBend(MicrosoftGraphObjectIdentity.mapping),
        "im_addresses": S("imAddresses"),
        "info_catalogs": S("infoCatalogs"),
        "is_management_restricted": S("isManagementRestricted"),
        "is_resource_account": S("isResourceAccount"),
        "job_title": S("jobTitle"),
        "last_password_change_date_time": S("lastPasswordChangeDateTime"),
        "legal_age_group_classification": S("legalAgeGroupClassification"),
        "license_assignment_states": S("licenseAssignmentStates")
        >> ForallBend(MicrosoftGraphLicenseAssignmentState.mapping),
        "mail": S("mail"),
        "mail_nickname": S("mailNickname"),
        "mobile_phone": S("mobilePhone"),
        "office_location": S("officeLocation"),
        "on_premises_distinguished_name": S("onPremisesDistinguishedName"),
        "on_premises_domain_name": S("onPremisesDomainName"),
        "on_premises_extension_attributes": S("onPremisesExtensionAttributes"),
        "on_premises_immutable_id": S("onPremisesImmutableId"),
        "on_premises_last_sync_date_time": S("onPremisesLastSyncDateTime"),
        "on_premises_provisioning_errors": S("onPremisesProvisioningErrors")
        >> ForallBend(MicrosoftGraphOnPremisesProvisioningError.mapping),
        "on_premises_sam_account_name": S("onPremisesSamAccountName"),
        "on_premises_security_identifier": S("onPremisesSecurityIdentifier"),
        "on_premises_sip_info": S("onPremisesSipInfo") >> Bend(MicrosoftGraphOnPremisesSipInfo.mapping),
        "on_premises_sync_enabled": S("onPremisesSyncEnabled"),
        "on_premises_user_principal_name": S("onPremisesUserPrincipalName"),
        "other_mails": S("otherMails"),
        "password_policies": S("passwordPolicies"),
        "password_profile": S("passwordProfile") >> Bend(MicrosoftGraphPasswordProfile.mapping),
        "postal_code": S("postalCode"),
        "preferred_data_location": S("preferredDataLocation"),
        "preferred_language": S("preferredLanguage"),
        "provisioned_plans": S("provisionedPlans") >> ForallBend(MicrosoftGraphProvisionedPlan.mapping),
        "proxy_addresses": S("proxyAddresses"),
        "refresh_tokens_valid_from_date_time": S("refreshTokensValidFromDateTime"),
        "security_identifier": S("securityIdentifier"),
        "service_provisioning_errors": S("serviceProvisioningErrors")
        >> ForallBend(MicrosoftGraphServiceProvisioningError.mapping),
        "show_in_address_list": S("showInAddressList"),
        "sign_in_sessions_valid_from_date_time": S("signInSessionsValidFromDateTime"),
        "state": S("state"),
        "street_address": S("streetAddress"),
        "surname": S("surname"),
        "usage_location": S("usageLocation"),
        "user_principal_name": S("userPrincipalName"),
        "user_type": S("userType"),
        "username": S("displayName"),
    }
    account_enabled: Optional[bool] = field(default=None, metadata={'description': 'true if the account is enabled; otherwise, false. This property is required when a user is created. Supports $filter (eq, ne, not, and in).'})  # fmt: skip
    age_group: Optional[str] = field(default=None, metadata={'description': 'Sets the age group of the user. Allowed values: null, Minor, NotAdult, and Adult. For more information, see legal age group property definitions. Supports $filter (eq, ne, not, and in).'})  # fmt: skip
    assigned_licenses: Optional[List[MicrosoftGraphAssignedLicense]] = field(default=None, metadata={'description': 'The licenses that are assigned to the user, including inherited (group-based) licenses. This property doesn t differentiate between directly assigned and inherited licenses. Use the licenseAssignmentStates property to identify the directly assigned and inherited licenses. Not nullable. Supports $filter (eq, not, /$count eq 0, /$count ne 0).'})  # fmt: skip
    assigned_plans: Optional[List[MicrosoftGraphAssignedPlan]] = field(default=None, metadata={'description': 'The plans that are assigned to the user. Read-only. Not nullable.Supports $filter (eq and not).'})  # fmt: skip
    authorization_info: Optional[MicrosoftGraphAuthorizationInfo] = field(default=None, metadata={'description': 'Identifiers that can be used to identify and authenticate a user in non-Azure AD environments. This property can store identifiers for smartcard-based certificates that users use to access on-premises Active Directory deployments or federated access. It can also be used to store the Subject Alternate Name (SAN) that s associated with a Common Access Card (CAC). Nullable.Supports $filter (eq and startsWith).'})  # fmt: skip
    business_phones: Optional[List[str]] = field(default=None, metadata={'description': 'The telephone numbers for the user. Only one number can be set for this property. Read-only for users synced from on-premises directory. Supports $filter (eq, not, ge, le, startsWith).'})  # fmt: skip
    city: Optional[str] = field(default=None, metadata={'description': 'The city where the user is located. Maximum length is 128 characters. Supports $filter (eq, ne, not, ge, le, in, startsWith, and eq on null values).'})  # fmt: skip
    cloud_realtime_communication_info: Optional[MicrosoftGraphCloudRealtimeCommunicationInfo] = field(default=None, metadata={'description': 'Microsoft realtime communication information related to the user. Supports $filter (eq, ne,not).'})  # fmt: skip
    company_name: Optional[str] = field(default=None, metadata={'description': 'The name of the company the user is associated with. This property can be useful for describing the company that an external user comes from. The maximum length is 64 characters.Supports $filter (eq, ne, not, ge, le, in, startsWith, and eq on null values).'})  # fmt: skip
    consent_provided_for_minor: Optional[str] = field(default=None, metadata={'description': 'Sets whether consent has been obtained for minors. Allowed values: null, Granted, Denied and NotRequired. Refer to the legal age group property definitions for further information. Supports $filter (eq, ne, not, and in).'})  # fmt: skip
    country: Optional[str] = field(default=None, metadata={'description': 'The country or region where the user is located; for example, US or UK. Maximum length is 128 characters. Supports $filter (eq, ne, not, ge, le, in, startsWith, and eq on null values).'})  # fmt: skip
    created_date_time: Optional[datetime] = field(default=None, metadata={'description': 'The date and time the user was created in ISO 8601 format and UTC. The value cannot be modified and is automatically populated when the entity is created. Nullable. For on-premises users, the value represents when they were first created in Microsoft Entra ID. Property is null for some users created before June 2018 and on-premises users synced to Microsoft Entra ID before June 2018. Read-only. Supports $filter (eq, ne, not , ge, le, in).'})  # fmt: skip
    creation_type: Optional[str] = field(default=None, metadata={'description': 'Indicates whether the user account was created through one of the following methods: As a regular school or work account (null). As an external account (Invitation). As a local account for an Azure Active Directory B2C tenant (LocalAccount). Through self-service sign-up by an internal user using email verification (EmailVerified). Through self-service sign-up by an external user signing up through a link that is part of a user flow (SelfServiceSignUp). Read-only.Supports $filter (eq, ne, not, and in).'})  # fmt: skip
    custom_security_attributes: Optional[Dict[str, str]] = field(default=None, metadata={'description': 'An open complex type that holds the value of a custom security attribute that is assigned to a directory object. Nullable. Returned only on $select. Supports $filter (eq, ne, not, startsWith). The filter value is case-sensitive.'})  # fmt: skip
    department: Optional[str] = field(default=None, metadata={'description': 'The name of the department where the user works. Maximum length is 64 characters.Supports $filter (eq, ne, not , ge, le, in, and eq on null values).'})  # fmt: skip
    device_keys: Optional[List[MicrosoftGraphDeviceKey]] = field(default=None, metadata={"description": ""})
    display_name: Optional[str] = field(default=None, metadata={'description': 'The name displayed in the address book for the user. This value is usually the combination of the user s first name, middle initial, and last name. This property is required when a user is created, and it cannot be cleared during updates. Maximum length is 256 characters. Supports $filter (eq, ne, not , ge, le, in, startsWith, and eq on null values), $orderby, and $search.'})  # fmt: skip
    employee_hire_date: Optional[str] = field(default=None, metadata={'description': 'The date and time when the user was hired or will start work if there is a future hire. Supports $filter (eq, ne, not , ge, le, in).'})  # fmt: skip
    employee_id: Optional[str] = field(default=None, metadata={'description': 'The employee identifier assigned to the user by the organization. The maximum length is 16 characters.Supports $filter (eq, ne, not , ge, le, in, startsWith, and eq on null values).'})  # fmt: skip
    employee_leave_date_time: Optional[datetime] = field(default=None, metadata={'description': 'The date and time when the user left or will leave the organization. To read this property, the calling app must be assigned the User-LifeCycleInfo.Read.All permission. To write this property, the calling app must be assigned the User.Read.All and User-LifeCycleInfo.ReadWrite.All permissions. To read this property in delegated scenarios, the admin needs at least one of the following Microsoft Entra roles: Lifecycle Workflows Administrator, Global Reader. To write this property in delegated scenarios, the admin needs the Global Administrator role. Supports $filter (eq, ne, not , ge, le, in). For more information, see Configure the employeeLeaveDateTime property for a user.'})  # fmt: skip
    employee_org_data: Optional[MicrosoftGraphEmployeeOrgData] = field(default=None, metadata={'description': 'Represents organization data (for example, division and costCenter) associated with a user. Supports $filter (eq, ne, not , ge, le, in).'})  # fmt: skip
    employee_type: Optional[str] = field(default=None, metadata={'description': 'Captures enterprise worker type. For example, Employee, Contractor, Consultant, or Vendor. Supports $filter (eq, ne, not , ge, le, in, startsWith).'})  # fmt: skip
    external_user_state: Optional[str] = field(default=None, metadata={'description': 'For an external user invited to the tenant using the invitation API, this property represents the invited user s invitation status. For invited users, the state can be PendingAcceptance or Accepted, or null for all other users. Supports $filter (eq, ne, not , in).'})  # fmt: skip
    external_user_state_change_date_time: Optional[datetime] = field(default=None, metadata={'description': 'Shows the timestamp for the latest change to the externalUserState property. Supports $filter (eq, ne, not , in).'})  # fmt: skip
    fax_number: Optional[str] = field(default=None, metadata={'description': 'The fax number of the user. Supports $filter (eq, ne, not , ge, le, in, startsWith, and eq on null values).'})  # fmt: skip
    given_name: Optional[str] = field(default=None, metadata={'description': 'The given name (first name) of the user. Maximum length is 64 characters. Supports $filter (eq, ne, not , ge, le, in, startsWith, and eq on null values).'})  # fmt: skip
    identities: Optional[List[MicrosoftGraphObjectIdentity]] = field(default=None, metadata={'description': 'Represents the identities that can be used to sign in to this user account. An identity can be provided by Microsoft (also known as a local account), by organizations, or by social identity providers such as Facebook, Google, and Microsoft and tied to a user account. It may contain multiple items with the same signInType value. Supports $filter (eq) with limitations.'})  # fmt: skip
    im_addresses: Optional[List[str]] = field(default=None, metadata={'description': 'The instant message voice-over IP (VOIP) session initiation protocol (SIP) addresses for the user. Read-only. Supports $filter (eq, not, ge, le, startsWith).'})  # fmt: skip
    info_catalogs: Optional[List[str]] = field(default=None, metadata={'description': 'Identifies the info segments assigned to the user. Supports $filter (eq, not, ge, le, startsWith).'})  # fmt: skip
    is_management_restricted: Optional[bool] = field(default=None, metadata={'description': 'true if the user is a member of a restricted management administrative unit, which requires a role scoped to the restricted administrative unit to manage. Default value is false. Read-only. To manage a user who is a member of a restricted administrative unit, the calling app must be assigned the Directory.Write.Restricted permission. For delegated scenarios, the administrators must also be explicitly assigned supported roles at the restricted administrative unit scope.'})  # fmt: skip
    is_resource_account: Optional[bool] = field(default=None, metadata={'description': 'Do not use – reserved for future use.'})  # fmt: skip
    job_title: Optional[str] = field(default=None, metadata={'description': 'The user s job title. Maximum length is 128 characters. Supports $filter (eq, ne, not , ge, le, in, startsWith, and eq on null values).'})  # fmt: skip
    last_password_change_date_time: Optional[datetime] = field(default=None, metadata={'description': 'When this Microsoft Entra user last changed their password or when their password was created, whichever date the latest action was performed. The Timestamp type represents date and time information using ISO 8601 format and is always in UTC. For example, midnight UTC on Jan 1, 2014 is 2014-01-01T00:00:00Z. Read-only. Returned only on $select.'})  # fmt: skip
    legal_age_group_classification: Optional[str] = field(default=None, metadata={'description': 'Used by enterprise applications to determine the legal age group of the user. This property is read-only and calculated based on ageGroup and consentProvidedForMinor properties. Allowed values: null, MinorWithOutParentalConsent, MinorWithParentalConsent, MinorNoParentalConsentRequired, NotAdult, and Adult. For more information, see legal age group property definitions. Returned only on $select.'})  # fmt: skip
    license_assignment_states: Optional[List[MicrosoftGraphLicenseAssignmentState]] = field(default=None, metadata={'description': 'State of license assignments for this user. It also indicates licenses that are directly assigned and the ones the user inherited through group memberships. Read-only. Returned only on $select.'})  # fmt: skip
    mail: Optional[str] = field(default=None, metadata={'description': 'The SMTP address for the user, for example, admin@contoso.com. Changes to this property also update the user s proxyAddresses collection to include the value as an SMTP address. This property can t contain accent characters. NOTE: We don t recommend updating this property for Azure AD B2C user profiles. Use the otherMails property instead. Supports $filter (eq, ne, not, ge, le, in, startsWith, endsWith, and eq on null values).'})  # fmt: skip
    mail_nickname: Optional[str] = field(default=None, metadata={'description': 'The mail alias for the user. This property must be specified when a user is created. Maximum length is 64 characters. Supports $filter (eq, ne, not, ge, le, in, startsWith, and eq on null values).'})  # fmt: skip
    mobile_phone: Optional[str] = field(default=None, metadata={'description': 'The primary cellular telephone number for the user. Read-only for users synced from the on-premises directory. Supports $filter (eq, ne, not, ge, le, in, startsWith, and eq on null values) and $search.'})  # fmt: skip
    office_location: Optional[str] = field(default=None, metadata={'description': 'The office location in the user s place of business. Maximum length is 128 characters. Supports $filter (eq, ne, not, ge, le, in, startsWith, and eq on null values).'})  # fmt: skip
    on_premises_distinguished_name: Optional[str] = field(default=None, metadata={'description': 'Contains the on-premises Active Directory distinguished name or DN. The property is only populated for customers synchronizing their on-premises directory to Microsoft Entra ID via Microsoft Entra Connect. Read-only.'})  # fmt: skip
    on_premises_domain_name: Optional[str] = field(default=None, metadata={'description': 'Contains the on-premises domainFQDN, also called dnsDomainName synchronized from the on-premises directory. The property is only populated for customers synchronizing their on-premises directory to Microsoft Entra ID via Microsoft Entra Connect. Read-only.'})  # fmt: skip
    on_premises_extension_attributes: Optional[Dict[str, str]] = field(default=None, metadata={'description': 'Contains extensionAttributes1-15 for the user. These extension attributes are also known as Exchange custom attributes 1-15. For an onPremisesSyncEnabled user, the source of authority for this set of properties is the on-premises and is read-only. For a cloud-only user (where onPremisesSyncEnabled is false), these properties can be set during the creation or update of a user object. For a cloud-only user previously synced from on-premises Active Directory, these properties are read-only in Microsoft Graph but can be fully managed through the Exchange Admin Center or the Exchange Online V2 module in PowerShell. Supports $filter (eq, ne, not, in).'})  # fmt: skip
    on_premises_immutable_id: Optional[str] = field(default=None, metadata={'description': 'This property associates an on-premises Active Directory user account to their Microsoft Entra user object. This property must be specified when creating a new user account in the Graph if you re using a federated domain for the user s userPrincipalName (UPN) property. Note: The $ and _ characters can t be used when specifying this property. Supports $filter (eq, ne, not, ge, le, in).'})  # fmt: skip
    on_premises_last_sync_date_time: Optional[datetime] = field(default=None, metadata={'description': 'Indicates the last time at which the object was synced with the on-premises directory; for example: 2013-02-16T03:04:54Z . The Timestamp type represents date and time information using ISO 8601 format and is always in UTC. For example, midnight UTC on Jan 1, 2014 is 2014-01-01T00:00:00Z. Read-only. Supports $filter (eq, ne, not, ge, le, in).'})  # fmt: skip
    on_premises_provisioning_errors: Optional[List[MicrosoftGraphOnPremisesProvisioningError]] = field(default=None, metadata={'description': 'Errors when using Microsoft synchronization product during provisioning. Supports $filter (eq, not, ge, le).'})  # fmt: skip
    on_premises_sam_account_name: Optional[str] = field(default=None, metadata={'description': 'Contains the on-premises sAMAccountName synchronized from the on-premises directory. The property is only populated for customers synchronizing their on-premises directory to Microsoft Entra ID via Microsoft Entra Connect. Read-only. Supports $filter (eq, ne, not, ge, le, in, startsWith).'})  # fmt: skip
    on_premises_security_identifier: Optional[str] = field(default=None, metadata={'description': 'Contains the on-premises security identifier (SID) for the user synchronized from on-premises to the cloud. Read-only. Supports $filter (eq including on null values).'})  # fmt: skip
    on_premises_sip_info: Optional[MicrosoftGraphOnPremisesSipInfo] = field(default=None, metadata={'description': 'Contains all on-premises Session Initiation Protocol (SIP) information related to the user. Read-only.'})  # fmt: skip
    on_premises_sync_enabled: Optional[bool] = field(default=None, metadata={'description': 'true if this user object is currently being synced from an on-premises Active Directory (AD); otherwise, the user isn t being synced and can be managed in Microsoft Entra ID. Read-only. Supports $filter (eq, ne, not, in, and eq on null values).'})  # fmt: skip
    on_premises_user_principal_name: Optional[str] = field(default=None, metadata={'description': 'Contains the on-premises userPrincipalName synchronized from the on-premises directory. The property is only populated for customers synchronizing their on-premises directory to Microsoft Entra ID via Microsoft Entra Connect. Read-only. Supports $filter (eq, ne, not, ge, le, in, startsWith).'})  # fmt: skip
    other_mails: Optional[List[str]] = field(default=None, metadata={'description': 'A list of additional email addresses for the user; for example: [ bob@contoso.com , Robert@fabrikam.com ].NOTE: This property can t contain accent characters.Supports $filter (eq, not, ge, le, in, startsWith, endsWith, /$count eq 0, /$count ne 0).'})  # fmt: skip
    password_policies: Optional[str] = field(default=None, metadata={'description': 'Specifies password policies for the user. This value is an enumeration with one possible value being DisableStrongPassword, which allows weaker passwords than the default policy to be specified. DisablePasswordExpiration can also be specified. The two may be specified together; for example: DisablePasswordExpiration, DisableStrongPassword. For more information on the default password policies, see Microsoft Entra password policies. Supports $filter (ne, not, and eq on null values).'})  # fmt: skip
    password_profile: Optional[MicrosoftGraphPasswordProfile] = field(default=None, metadata={'description': 'Specifies the password profile for the user. The profile contains the user s password. This property is required when a user is created. The password in the profile must satisfy minimum requirements as specified by the passwordPolicies property. By default, a strong password is required. Supports $filter (eq, ne, not, in, and eq on null values).'})  # fmt: skip
    postal_code: Optional[str] = field(default=None, metadata={'description': 'The postal code for the user s postal address. The postal code is specific to the user s country/region. In the United States of America, this attribute contains the ZIP code. Maximum length is 40 characters. Supports $filter (eq, ne, not, ge, le, in, startsWith, and eq on null values).'})  # fmt: skip
    preferred_data_location: Optional[str] = field(default=None, metadata={'description': 'The preferred data location for the user. For more information, see OneDrive Online Multi-Geo.'})  # fmt: skip
    preferred_language: Optional[str] = field(default=None, metadata={'description': 'The preferred language for the user. The preferred language format is based on RFC 4646. The name combines an ISO 639 two-letter lowercase culture code associated with the language and an ISO 3166 two-letter uppercase subculture code associated with the country or region. Example: en-US , or es-ES . Supports $filter (eq, ne, not, ge, le, in, startsWith, and eq on null values).'})  # fmt: skip
    provisioned_plans: Optional[List[MicrosoftGraphProvisionedPlan]] = field(default=None, metadata={'description': 'The plans that are provisioned for the user. Read-only. Not nullable. Supports $filter (eq, not, ge, le).'})  # fmt: skip
    proxy_addresses: Optional[List[str]] = field(default=None, metadata={'description': 'For example: [ SMTP: bob@contoso.com , smtp: bob@sales.contoso.com ]. Changes to the mail property also update this collection to include the value as an SMTP address. For more information, see mail and proxyAddresses properties. The proxy address prefixed with SMTP (capitalized) is the primary proxy address, while the ones prefixed with smtp are the secondary proxy addresses. For Azure AD B2C accounts, this property has a limit of 10 unique addresses. Read-only in Microsoft Graph; you can update this property only through the Microsoft 365 admin center. Not nullable. Supports $filter (eq, not, ge, le, startsWith, endsWith, /$count eq 0, /$count ne 0).'})  # fmt: skip
    refresh_tokens_valid_from_date_time: Optional[datetime] = field(default=None, metadata={'description': 'Any refresh tokens or sessions tokens (session cookies) issued before this time are invalid, and applications get an error when using an invalid refresh or sessions token to acquire a delegated access token (to access APIs such as Microsoft Graph). If it happens, the application must acquire a new refresh token by requesting the authorized endpoint. Read-only. Use invalidateAllRefreshTokens to reset.'})  # fmt: skip
    security_identifier: Optional[str] = field(default=None, metadata={'description': 'Security identifier (SID) of the user, used in Windows scenarios. Read-only. Returned by default. Supports $select and $filter (eq, not, ge, le, startsWith).'})  # fmt: skip
    service_provisioning_errors: Optional[List[MicrosoftGraphServiceProvisioningError]] = field(default=None, metadata={'description': 'Errors published by a federated service describing a nontransient, service-specific error regarding the properties or link from a user object.'})  # fmt: skip
    show_in_address_list: Optional[bool] = field(default=None, metadata={'description': 'Do not use in Microsoft Graph. Manage this property through the Microsoft 365 admin center instead. Represents whether the user should be included in the Outlook global address list. See Known issue.'})  # fmt: skip
    sign_in_sessions_valid_from_date_time: Optional[datetime] = field(default=None, metadata={'description': 'Any refresh tokens or sessions tokens (session cookies) issued before this time are invalid, and applications get an error when using an invalid refresh or sessions token to acquire a delegated access token (to access APIs such as Microsoft Graph). If this happens, the application must acquire a new refresh token by requesting the authorized endpoint. Read-only. Use revokeSignInSessions to reset.'})  # fmt: skip
    state: Optional[str] = field(default=None, metadata={'description': 'The state or province in the user s address. Maximum length is 128 characters. Supports $filter (eq, ne, not, ge, le, in, startsWith, and eq on null values).'})  # fmt: skip
    street_address: Optional[str] = field(default=None, metadata={'description': 'The street address of the user s place of business. Maximum length is 1024 characters. Supports $filter (eq, ne, not, ge, le, in, startsWith, and eq on null values).'})  # fmt: skip
    surname: Optional[str] = field(default=None, metadata={'description': 'The user s surname (family name or last name). Maximum length is 64 characters. Supports $filter (eq, ne, not, ge, le, in, startsWith, and eq on null values).'})  # fmt: skip
    usage_location: Optional[str] = field(default=None, metadata={'description': 'A two-letter country code (ISO standard 3166). Required for users that are assigned licenses due to legal requirements to check for availability of services in countries. Examples include: US, JP, and GB. Not nullable. Supports $filter (eq, ne, not, ge, le, in, startsWith, and eq on null values).'})  # fmt: skip
    user_principal_name: Optional[str] = field(default=None, metadata={'description': 'The user principal name (UPN) of the user. The UPN is an Internet-style sign-in name for the user based on the Internet standard RFC 822. By convention, this should map to the user s email name. The general format is alias@domain, where the domain must be present in the tenant s verified domain collection. This property is required when a user is created. The verified domains for the tenant can be accessed from the verifiedDomains property of organization.NOTE: This property can t contain accent characters. Only the following characters are allowed A - Z, a - z, 0 - 9, . - _ ! # ^ ~. For the complete list of allowed characters, see username policies. Supports $filter (eq, ne, not, ge, le, in, startsWith, endsWith) and $orderby.'})  # fmt: skip
    user_type: Optional[str] = field(default=None, metadata={'description': 'A String value that can be used to classify user types in your directory. The possible values are Member and Guest. Supports $filter (eq, ne, not, in, and eq on null values). NOTE: For more information about the permissions for member and guest users, see What are the default user permissions in Microsoft Entra ID?'})  # fmt: skip

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        for member in source.get("memberOf", []):
            if member.get("@odata.type") == "#microsoft.graph.directoryRole" and (rid := member.get("roleTemplateId")):
                builder.add_edge(self, clazz=MicrosoftGraphRole, template_id=rid)


@define(eq=False, slots=False)
class MicrosoftGraphGroup(MicrosoftGraphEntity, BaseGroup):
    kind: ClassVar[str] = "microsoft_graph_group"
    _kind_service: ClassVar[Optional[str]] = "entra_id"
    _kind_display: ClassVar[str] = "Microsoft Graph Group"
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "group", "group": "access_control"}
    api_spec: ClassVar[MicrosoftRestSpec] = RestApiSpec(
        "graph",
        "https://graph.microsoft.com/v1.0/groups",
        parameters={
            "$expand": "transitiveMembers($select=id)",  # will select: users, groups, devices and enterprise applications
            "$select": "accessType,assignedLabels,assignedLicenses,classification,createdByAppId,createdDateTime,deletedDateTime,description,displayName,expirationDateTime,groupTypes,id,infoCatalogs,isAssignableToRole,isFavorite,isManagementRestricted,licenseProcessingState,mail,mailEnabled,mailNickname,membershipRule,membershipRuleProcessingState,membershipRuleProcessingStatus,onPremisesDomainName,onPremisesLastSyncDateTime,onPremisesNetBiosName,onPremisesProvisioningErrors,onPremisesSamAccountName,onPremisesSecurityIdentifier,onPremisesSyncEnabled,organizationId,preferredDataLocation,preferredLanguage,proxyAddresses,renewedDateTime,resourceBehaviorOptions,resourceProvisioningOptions,securityEnabled,securityIdentifier,serviceProvisioningErrors,theme,uniqueName,unseenConversationsCount,unseenMessagesCount,visibility,writebackConfiguration",
        },
        access_path="value",
    )
    _reference_kinds: ClassVar[ModelReference] = {
        "successors": {
            "default": ["microsoft_graph_device", "microsoft_graph_service_principal", "microsoft_graph_user"]
        }
    }
    mapping: ClassVar[Dict[str, Bender]] = MicrosoftGraphEntity.mapping | {
        "id": S("id"),
        "name": S("displayName"),
        "access_type": S("accessType"),
        "assigned_labels": S("assignedLabels") >> ForallBend(MicrosoftGraphAssignedLabel.mapping),
        "assigned_licenses": S("assignedLicenses") >> ForallBend(MicrosoftGraphAssignedLicense.mapping),
        "classification": S("classification"),
        "created_by_app_id": S("createdByAppId"),
        "created_date_time": S("createdDateTime"),
        "description": S("description"),
        "display_name": S("displayName"),
        "expiration_date_time": S("expirationDateTime"),
        "group_types": S("groupTypes"),
        "info_catalogs": S("infoCatalogs"),
        "is_assignable_to_role": S("isAssignableToRole"),
        "is_favorite": S("isFavorite"),
        "is_management_restricted": S("isManagementRestricted"),
        "license_processing_state": S("licenseProcessingState") >> Bend(MicrosoftGraphLicenseProcessingState.mapping),
        "mail": S("mail"),
        "mail_enabled": S("mailEnabled"),
        "mail_nickname": S("mailNickname"),
        "membership_rule": S("membershipRule"),
        "membership_rule_processing_state": S("membershipRuleProcessingState"),
        "membership_rule_processing_status": S("membershipRuleProcessingStatus")
        >> Bend(MicrosoftGraphMembershipRuleProcessingStatus.mapping),
        "on_premises_domain_name": S("onPremisesDomainName"),
        "on_premises_last_sync_date_time": S("onPremisesLastSyncDateTime"),
        "on_premises_net_bios_name": S("onPremisesNetBiosName"),
        "on_premises_provisioning_errors": S("onPremisesProvisioningErrors")
        >> ForallBend(MicrosoftGraphOnPremisesProvisioningError.mapping),
        "on_premises_sam_account_name": S("onPremisesSamAccountName"),
        "on_premises_security_identifier": S("onPremisesSecurityIdentifier"),
        "on_premises_sync_enabled": S("onPremisesSyncEnabled"),
        "organization_id": S("organizationId"),
        "preferred_data_location": S("preferredDataLocation"),
        "preferred_language": S("preferredLanguage"),
        "proxy_addresses": S("proxyAddresses"),
        "renewed_date_time": S("renewedDateTime"),
        "resource_behavior_options": S("resourceBehaviorOptions"),
        "resource_provisioning_options": S("resourceProvisioningOptions"),
        "security_enabled": S("securityEnabled"),
        "security_identifier": S("securityIdentifier"),
        "service_provisioning_errors": S("serviceProvisioningErrors")
        >> ForallBend(MicrosoftGraphServiceProvisioningError.mapping),
        "theme": S("theme"),
        "unique_name": S("uniqueName"),
        "unseen_conversations_count": S("unseenConversationsCount"),
        "unseen_messages_count": S("unseenMessagesCount"),
        "visibility": S("visibility"),
        "writeback_configuration": S("writebackConfiguration")
        >> Bend(MicrosoftGraphGroupWritebackConfiguration.mapping),
        "_transitive_members": S("transitiveMembers") >> MapDict(S("id"), S("@odata.type")),
    }
    access_type: Optional[str] = field(default=None, metadata={'description': 'Indicates the type of access to the group. Possible values are none, private, secret, and public.'})  # fmt: skip
    assigned_labels: Optional[List[MicrosoftGraphAssignedLabel]] = field(default=None, metadata={'description': 'The list of sensitivity label pairs (label ID, label name) associated with a Microsoft 365 group. Returned only on $select.'})  # fmt: skip
    assigned_licenses: Optional[List[MicrosoftGraphAssignedLicense]] = field(default=None, metadata={'description': 'The licenses that are assigned to the group. Returned only on $select. Supports $filter (eq). Read-only.'})  # fmt: skip
    classification: Optional[str] = field(default=None, metadata={'description': 'Describes a classification for the group (such as low, medium or high business impact). Valid values for this property are defined by creating a ClassificationList setting value, based on the template definition.Returned by default. Supports $filter (eq, ne, not, ge, le, startsWith).'})  # fmt: skip
    created_by_app_id: Optional[str] = field(default=None, metadata={'description': 'App ID of the app used to create the group. Can be null for some groups. Returned by default. Read-only. Supports $filter (eq, ne, not, in, startsWith).'})  # fmt: skip
    created_date_time: Optional[datetime] = field(default=None, metadata={'description': 'Timestamp of when the group was created. The value can t be modified and is automatically populated when the group is created. The Timestamp type represents date and time information using ISO 8601 format and is always in UTC. For example, midnight UTC on Jan 1, 2014 is 2014-01-01T00:00:00Z. Returned by default. Read-only.'})  # fmt: skip
    description: Optional[str] = field(default=None, metadata={'description': 'An optional description for the group. Returned by default. Supports $filter (eq, ne, not, ge, le, startsWith) and $search.'})  # fmt: skip
    display_name: Optional[str] = field(default=None, metadata={'description': 'The display name for the group. Required. Maximum length is 256 characters. Returned by default. Supports $filter (eq, ne, not, ge, le, in, startsWith, and eq on null values), $search, and $orderby.'})  # fmt: skip
    expiration_date_time: Optional[datetime] = field(default=None, metadata={'description': 'Timestamp of when the group is set to expire. It is null for security groups, but for Microsoft 365 groups, it represents when the group is set to expire as defined in the groupLifecyclePolicy. The Timestamp type represents date and time information using ISO 8601 format and is always in UTC. For example, midnight UTC on Jan 1, 2014 is 2014-01-01T00:00:00Z. Returned by default. Supports $filter (eq, ne, not, ge, le, in). Read-only.'})  # fmt: skip
    group_types: Optional[List[str]] = field(default=None, metadata={'description': 'Specifies the group type and its membership. If the collection contains Unified, the group is a Microsoft 365 group; otherwise, it s either a security group or a distribution group. For details, see groups overview.If the collection includes DynamicMembership, the group has dynamic membership; otherwise, membership is static. Returned by default. Supports $filter (eq, not).'})  # fmt: skip
    info_catalogs: Optional[List[str]] = field(default=None, metadata={'description': 'Identifies the info segments assigned to the group. Returned by default. Supports $filter (eq, not, ge, le, startsWith).'})  # fmt: skip
    is_assignable_to_role: Optional[bool] = field(default=None, metadata={'description': 'Indicates whether this group can be assigned to a Microsoft Entra role. Optional. This property can only be set while creating the group and is immutable. If set to true, the securityEnabled property must also be set to true, visibility must be Hidden, and the group cannot be a dynamic group (that is, groupTypes can t contain DynamicMembership). Only callers with at least the Privileged Role Administrator role can set this property. The caller must also be assigned the RoleManagement.ReadWrite.Directory permission to set this property or update the membership of such groups. For more, see Using a group to manage Microsoft Entra role assignmentsUsing this feature requires a Microsoft Entra ID P1 license. Returned by default. Supports $filter (eq, ne, not).'})  # fmt: skip
    is_favorite: Optional[bool] = field(default=None, metadata={'description': 'Indicates whether the user marked the group as favorite.'})  # fmt: skip
    is_management_restricted: Optional[bool] = field(default=None, metadata={'description': 'Indicates whether the group is a member of a restricted management administrative unit, in which case it requires a role scoped to the restricted administrative unit to manage. The default value is false. Read-only. To manage a group member of a restricted administrative unit, the calling app must be assigned the Directory.Write.Restricted permission. For delegated scenarios, the administrators must also be explicitly assigned supported roles at the restricted administrative unit scope.'})  # fmt: skip
    license_processing_state: Optional[MicrosoftGraphLicenseProcessingState] = field(default=None, metadata={'description': 'Indicates the status of the group license assignment to all group members. Possible values: QueuedForProcessing, ProcessingInProgress, and ProcessingComplete. Returned only on $select. Read-only.'})  # fmt: skip
    mail: Optional[str] = field(default=None, metadata={'description': 'The SMTP address for the group, for example, serviceadmins@contoso.com . Returned by default. Read-only. Supports $filter (eq, ne, not, ge, le, in, startsWith, and eq on null values).'})  # fmt: skip
    mail_enabled: Optional[bool] = field(default=None, metadata={'description': 'Specifies whether the group is mail-enabled. Required. Returned by default. Supports $filter (eq, ne, not, and eq on null values).'})  # fmt: skip
    mail_nickname: Optional[str] = field(default=None, metadata={'description': 'The mail alias for the group, unique for Microsoft 365 groups in the organization. Maximum length is 64 characters. This property can contain only characters in the ASCII character set 0 - 127 except the following: @ () / [] ; : <> , SPACE. Returned by default. Supports $filter (eq, ne, not, ge, le, in, startsWith).'})  # fmt: skip
    membership_rule: Optional[str] = field(default=None, metadata={'description': 'The rule that determines members for this group if the group is a dynamic group (groupTypes contains DynamicMembership). For more information about the syntax of the membership rule, see Membership Rules syntax. Returned by default. Supports $filter (eq, ne, not, ge, le, startsWith).'})  # fmt: skip
    membership_rule_processing_state: Optional[str] = field(default=None, metadata={'description': 'Indicates whether the dynamic membership processing is on or paused. Possible values are On or Paused. Returned by default. Supports $filter (eq, ne, not, in).'})  # fmt: skip
    membership_rule_processing_status: Optional[MicrosoftGraphMembershipRuleProcessingStatus] = field(default=None, metadata={'description': 'Describes the processing status for rules-based dynamic groups. The property is null for non-rule-based dynamic groups or if the dynamic group processing has been paused. Returned only on $select. Supported only on the Get group API (GET /groups/{ID}). Read-only.'})  # fmt: skip
    on_premises_domain_name: Optional[str] = field(default=None, metadata={'description': 'Contains the on-premises domain FQDN, also called dnsDomainName synchronized from the on-premises directory. The property is only populated for customers synchronizing their on-premises directory to Microsoft Entra ID via Microsoft Entra Connect.Returned by default. Read-only.'})  # fmt: skip
    on_premises_last_sync_date_time: Optional[datetime] = field(default=None, metadata={'description': 'Indicates the last time at which the group was synced with the on-premises directory.The Timestamp type represents date and time information using ISO 8601 format and is always in UTC. For example, midnight UTC on Jan 1, 2014 is 2014-01-01T00:00:00Z. Returned by default. Read-only. Supports $filter (eq, ne, not, ge, le, in).'})  # fmt: skip
    on_premises_net_bios_name: Optional[str] = field(default=None, metadata={'description': 'Contains the on-premises netBios name synchronized from the on-premises directory. The property is only populated for customers synchronizing their on-premises directory to Microsoft Entra ID via Microsoft Entra Connect.Returned by default. Read-only.'})  # fmt: skip
    on_premises_provisioning_errors: Optional[List[MicrosoftGraphOnPremisesProvisioningError]] = field(default=None, metadata={'description': 'Errors when using Microsoft synchronization product during provisioning. Returned by default. Supports $filter (eq, not).'})  # fmt: skip
    on_premises_sam_account_name: Optional[str] = field(default=None, metadata={'description': 'Contains the on-premises SAM account name synchronized from the on-premises directory. The property is only populated for customers synchronizing their on-premises directory to Microsoft Entra ID via Microsoft Entra Connect.Returned by default. Supports $filter (eq, ne, not, ge, le, in, startsWith). Read-only.'})  # fmt: skip
    on_premises_security_identifier: Optional[str] = field(default=None, metadata={'description': 'Contains the on-premises security identifier (SID) for the group synchronized from on-premises to the cloud. Read-only. Returned by default. Supports $filter (eq including on null values). Read-only.'})  # fmt: skip
    on_premises_sync_enabled: Optional[bool] = field(default=None, metadata={'description': 'true if this group is synced from an on-premises directory; false if this group was originally synced from an on-premises directory but is no longer synced; null if this object has never been synced from an on-premises directory (default). Returned by default. Read-only. Supports $filter (eq, ne, not, in, and eq on null values).'})  # fmt: skip
    organization_id: Optional[str] = field(default=None, metadata={"description": ""})
    preferred_data_location: Optional[str] = field(default=None, metadata={'description': 'The preferred data location for the Microsoft 365 group. By default, the group inherits the group creator s preferred data location. To set this property, the calling app must be granted the Directory.ReadWrite.All permission and the user be assigned at least one of the following Microsoft Entra roles: User Account Administrator Directory Writer Exchange Administrator SharePoint Administrator For more information about this property, see OneDrive Online Multi-Geo and Create a Microsoft 365 group with a specific PDL. Nullable. Returned by default.'})  # fmt: skip
    preferred_language: Optional[str] = field(default=None, metadata={'description': 'The preferred language for a Microsoft 365 group. Should follow ISO 639-1 Code; for example, en-US. Returned by default. Supports $filter (eq, ne, not, ge, le, in, startsWith, and eq on null values).'})  # fmt: skip
    proxy_addresses: Optional[List[str]] = field(default=None, metadata={'description': 'Email addresses for the group that direct to the same group mailbox. For example: [ SMTP: bob@contoso.com , smtp: bob@sales.contoso.com ]. The any operator is required for filter expressions on multi-valued properties. Returned by default. Read-only. Not nullable. Supports $filter (eq, not, ge, le, startsWith, endsWith, /$count eq 0, /$count ne 0).'})  # fmt: skip
    renewed_date_time: Optional[datetime] = field(default=None, metadata={'description': 'Timestamp of when the group was last renewed. This cannot be modified directly and is only updated via the renew service action. The Timestamp type represents date and time information using ISO 8601 format and is always in UTC. For example, midnight UTC on Jan 1, 2014 is 2014-01-01T00:00:00Z. Returned by default. Supports $filter (eq, ne, not, ge, le, in). Read-only.'})  # fmt: skip
    resource_behavior_options: Optional[List[str]] = field(default=None, metadata={'description': 'Specifies the group behaviors that can be set for a Microsoft 365 group during creation. This property can be set only as part of creation (POST). For the list of possible values, see Microsoft 365 group behaviors and provisioning options.'})  # fmt: skip
    resource_provisioning_options: Optional[List[str]] = field(default=None, metadata={'description': 'Specifies the group resources that are associated with the Microsoft 365 group. The possible value is Team. For more information, see Microsoft 365 group behaviors and provisioning options. Returned by default. Supports $filter (eq, not, startsWith.'})  # fmt: skip
    security_enabled: Optional[bool] = field(default=None, metadata={'description': 'Specifies whether the group is a security group. Required.Returned by default. Supports $filter (eq, ne, not, in).'})  # fmt: skip
    security_identifier: Optional[str] = field(default=None, metadata={'description': 'Security identifier of the group, used in Windows scenarios. Read-only. Returned by default.'})  # fmt: skip
    service_provisioning_errors: Optional[List[MicrosoftGraphServiceProvisioningError]] = field(default=None, metadata={'description': 'Errors published by a federated service describing a non-transient, service-specific error regarding the properties or link from a group object.'})  # fmt: skip
    theme: Optional[str] = field(default=None, metadata={'description': 'Specifies a Microsoft 365 group s color theme. Possible values are Teal, Purple, Green, Blue, Pink, Orange or Red. Returned by default.'})  # fmt: skip
    unique_name: Optional[str] = field(default=None, metadata={'description': 'The unique identifier that can be assigned to a group and used as an alternate key. Immutable. Read-only.'})  # fmt: skip
    unseen_conversations_count: Optional[int] = field(default=None, metadata={'description': 'Count of conversations delivered one or more new posts since the signed-in user s last visit to the group. This property is the same as unseenCount. Returned only on $select.'})  # fmt: skip
    unseen_messages_count: Optional[int] = field(default=None, metadata={'description': 'Count of new posts that have been delivered to the group s conversations since the signed-in user s last visit to the group. Returned only on $select.'})  # fmt: skip
    visibility: Optional[str] = field(default=None, metadata={'description': 'Specifies the group join policy and group content visibility for groups. Possible values are: Private, Public, or HiddenMembership. HiddenMembership can be set only for Microsoft 365 groups when the groups are created. It can t be updated later. Other values of visibility can be updated after group creation. If visibility value isn t specified during group creation on Microsoft Graph, a security group is created as Private by default, and Microsoft 365 group is Public. Groups assignable to roles are always Private. To learn more, see group visibility options. Returned by default. Nullable.'})  # fmt: skip
    writeback_configuration: Optional[MicrosoftGraphGroupWritebackConfiguration] = field(default=None, metadata={'description': 'Specifies whether or not a group is configured to write back group object properties to on-premises Active Directory. These properties are used when group writeback is configured in the Microsoft Entra Connect sync client.'})  # fmt: skip
    _transitive_members: Optional[Dict[str, str]] = None

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        groups = {n.id: n for n in builder.nodes(MicrosoftGraphGroup)}
        visited = set()
        dependant = {}

        def add_transitive(gp: MicrosoftGraphGroup) -> None:
            if gp.id not in visited and gp._transitive_members:
                visited.add(gp.id)
                for mid, mtype in gp._transitive_members.items():
                    if mtype == "#microsoft.graph.group":
                        if g := groups.get(mid):
                            add_transitive(g)
                    else:
                        dependant[mid] = mtype

        # walk all transitive members and collect all dependant nodes
        add_transitive(self)
        # create an edge to all transitively dependant node
        for mid, mtype in dependant.items():
            if clazz := KindLookup.get(mtype):
                builder.add_edge(self, clazz=clazz, id=mid)


@define(eq=False, slots=False)
class MicrosoftGraphOrganization(MicrosoftGraphEntity, BaseAccount):
    kind: ClassVar[str] = "microsoft_graph_organization"
    _kind_service: ClassVar[Optional[str]] = "entra_id"
    _kind_display: ClassVar[str] = "Microsoft Graph Organization"
    api_spec: ClassVar[MicrosoftRestSpec] = RestApiSpec(
        "graph",
        "https://graph.microsoft.com/v1.0/organization",
        parameters={
            "$select": "assignedPlans,businessPhones,certificateConnectorSetting,city,country,countryLetterCode,createdDateTime,defaultUsageLocation,deletedDateTime,directorySizeQuota,displayName,id,isMultipleDataLocationsForServicesEnabled,marketingNotificationEmails,onPremisesLastPasswordSyncDateTime,onPremisesLastSyncDateTime,onPremisesSyncEnabled,partnerTenantType,postalCode,preferredLanguage,privacyProfile,provisionedPlans,securityComplianceNotificationMails,securityComplianceNotificationPhones,state,street,technicalNotificationMails,tenantType,verifiedDomains"
        },
        access_path="value",
    )
    mapping: ClassVar[Dict[str, Bender]] = MicrosoftGraphEntity.mapping | {
        "id": S("id"),
        "name": S("displayName"),
        "ctime": S("createdDateTime"),
        "assigned_plans": S("assignedPlans") >> ForallBend(MicrosoftGraphAssignedPlan.mapping),
        "business_phones": S("businessPhones"),
        "certificate_connector_setting": S("certificateConnectorSetting")
        >> Bend(MicrosoftGraphCertificateConnectorSetting.mapping),
        "city": S("city"),
        "country": S("country"),
        "country_letter_code": S("countryLetterCode"),
        "created_date_time": S("createdDateTime"),
        "default_usage_location": S("defaultUsageLocation"),
        "directory_size_quota": S("directorySizeQuota") >> Bend(MicrosoftGraphDirectorySizeQuota.mapping),
        "display_name": S("displayName"),
        "is_multiple_data_locations_for_services_enabled": S("isMultipleDataLocationsForServicesEnabled"),
        "marketing_notification_emails": S("marketingNotificationEmails"),
        "on_premises_last_password_sync_date_time": S("onPremisesLastPasswordSyncDateTime"),
        "on_premises_last_sync_date_time": S("onPremisesLastSyncDateTime"),
        "on_premises_sync_enabled": S("onPremisesSyncEnabled"),
        "partner_tenant_type": S("partnerTenantType"),
        "postal_code": S("postalCode"),
        "preferred_language": S("preferredLanguage"),
        "privacy_profile": S("privacyProfile") >> Bend(MicrosoftGraphPrivacyProfile.mapping),
        "provisioned_plans": S("provisionedPlans") >> ForallBend(MicrosoftGraphProvisionedPlan.mapping),
        "security_compliance_notification_mails": S("securityComplianceNotificationMails"),
        "security_compliance_notification_phones": S("securityComplianceNotificationPhones"),
        "state": S("state"),
        "street": S("street"),
        "technical_notification_mails": S("technicalNotificationMails"),
        "tenant_type": S("tenantType"),
        "verified_domains": S("verifiedDomains") >> ForallBend(MicrosoftGraphVerifiedDomain.mapping),
    }
    assigned_plans: Optional[List[MicrosoftGraphAssignedPlan]] = field(default=None, metadata={'description': 'The collection of service plans associated with the tenant. Not nullable.'})  # fmt: skip
    business_phones: Optional[List[str]] = field(default=None, metadata={'description': 'Telephone number for the organization. Although this property is a string collection, only one number can be set.'})  # fmt: skip
    certificate_connector_setting: Optional[MicrosoftGraphCertificateConnectorSetting] = field(default=None, metadata={'description': 'Certificate connector setting.'})  # fmt: skip
    city: Optional[str] = field(default=None, metadata={'description': 'City name of the address for the organization.'})  # fmt: skip
    country: Optional[str] = field(default=None, metadata={'description': 'Country/region name of the address for the organization.'})  # fmt: skip
    country_letter_code: Optional[str] = field(default=None, metadata={'description': 'Country or region abbreviation for the organization in ISO 3166-2 format.'})  # fmt: skip
    created_date_time: Optional[datetime] = field(default=None, metadata={'description': 'Timestamp of when the organization was created. The value can t be modified and is automatically populated when the organization is created. The Timestamp type represents date and time information using ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 is 2014-01-01T00:00:00Z. Read-only.'})  # fmt: skip
    default_usage_location: Optional[str] = field(default=None, metadata={'description': 'Two-letter ISO 3166 country code indicating the default service usage location of an organization.'})  # fmt: skip
    directory_size_quota: Optional[MicrosoftGraphDirectorySizeQuota] = field(default=None, metadata={'description': 'The directory size quota information of an organization.'})  # fmt: skip
    display_name: Optional[str] = field(default=None, metadata={"description": "The display name for the tenant."})
    is_multiple_data_locations_for_services_enabled: Optional[bool] = field(default=None, metadata={'description': 'true if organization is Multi-Geo enabled; false if organization isn t Multi-Geo enabled; null (default). Read-only. For more information, see OneDrive Online Multi-Geo.'})  # fmt: skip
    marketing_notification_emails: Optional[List[str]] = field(default=None, metadata={"description": "Not nullable."})
    on_premises_last_password_sync_date_time: Optional[datetime] = field(default=None, metadata={'description': 'The last time a password sync request was received for the tenant.'})  # fmt: skip
    on_premises_last_sync_date_time: Optional[datetime] = field(default=None, metadata={'description': 'The time and date at which the tenant was last synced with the on-premises directory. The Timestamp type represents date and time information using ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 is 2014-01-01T00:00:00Z.'})  # fmt: skip
    on_premises_sync_enabled: Optional[bool] = field(default=None, metadata={'description': 'true if this object is synced from an on-premises directory; false if this object was originally synced from an on-premises directory but is no longer synced; Nullable. null, if this object isn t synced from on-premises active directory (default).'})  # fmt: skip
    partner_tenant_type: Optional[str] = field(default=None, metadata={'description': 'The type of partnership this tenant has with Microsoft. The possible values are: microsoftSupport, syndicatePartner, breadthPartner, breadthPartnerDelegatedAdmin, resellerPartnerDelegatedAdmin, valueAddedResellerPartnerDelegatedAdmin, unknownFutureValue. Nullable. For more information about the possible types, see partnerTenantType values.'})  # fmt: skip
    postal_code: Optional[str] = field(default=None, metadata={'description': 'Postal code of the address for the organization.'})  # fmt: skip
    preferred_language: Optional[str] = field(default=None, metadata={'description': 'The preferred language for the organization. Should follow ISO 639-1 code; for example, en.'})  # fmt: skip
    privacy_profile: Optional[MicrosoftGraphPrivacyProfile] = field(default=None, metadata={'description': 'The privacy profile of an organization.'})  # fmt: skip
    provisioned_plans: Optional[List[MicrosoftGraphProvisionedPlan]] = field(
        default=None, metadata={"description": "Not nullable."}
    )
    security_compliance_notification_mails: Optional[List[str]] = field(default=None, metadata={'description': 'Not nullable.'})  # fmt: skip
    security_compliance_notification_phones: Optional[List[str]] = field(default=None, metadata={'description': 'Not nullable.'})  # fmt: skip
    state: Optional[str] = field(default=None, metadata={'description': 'State name of the address for the organization.'})  # fmt: skip
    street: Optional[str] = field(default=None, metadata={'description': 'Street name of the address for organization.'})  # fmt: skip
    technical_notification_mails: Optional[List[str]] = field(default=None, metadata={"description": "Not nullable."})
    tenant_type: Optional[str] = field(default=None, metadata={'description': 'Not nullable. Can be one of the following types: AAD - An enterprise identity access management (IAM) service that serves business-to-employee and business-to-business (B2B) scenarios. AAD B2C An identity access management (IAM) service that serves business-to-consumer (B2C) scenarios. CIAM - A customer identity & access management (CIAM) solution that provides an integrated platform to serve consumers, partners, and citizen scenarios.'})  # fmt: skip
    verified_domains: Optional[List[MicrosoftGraphVerifiedDomain]] = field(default=None, metadata={'description': 'The collection of domains associated with this tenant. Not nullable.'})  # fmt: skip

    @classmethod
    def deferred_edge_to_subscription(cls, builder: GraphBuilder) -> None:
        for js in builder.client.list(cls.api_spec):
            if org := cls.from_api(js, builder):
                builder.add_deferred_edge(
                    BySearchCriteria(f'is({cls.kind}) and reported.id=="{org.id}"'), ByNodeId(builder.account.chksum)
                )


@define(eq=False, slots=False)
class MicrosoftGraphOrganizationRoot(MicrosoftGraphEntity, BaseRegion):
    kind: ClassVar[str] = "microsoft_graph_organization_root"
    _kind_service: ClassVar[Optional[str]] = "entra_id"
    _kind_display: ClassVar[str] = "Microsoft Graph Organization Root"


@define(eq=False, slots=False)
class MicrosoftGraphPolicy(MicrosoftGraphEntity):
    kind: ClassVar[str] = "microsoft_graph_policy"
    _kind_service: ClassVar[Optional[str]] = "entra_id"
    _kind_display: ClassVar[str] = "Microsoft Graph Policy"
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "policy", "group": "access_control"}

    policy_kind: Optional[str] = field(default=None, metadata={"description": "The kind of policy."})
    enabled: Optional[bool] = field(default=None, metadata={"description": "Indicates whether the policy is enabled."})
    description: Optional[str] = field(default=None, metadata={"description": "Description of the policy."})
    policy: Optional[Json] = field(default=None, metadata={"description": "The policy."})

    @classmethod
    def collect_resources(cls, builder: GraphBuilder, **kwargs: Any) -> List[MicrosoftGraphPolicy]:
        base = "https://graph.microsoft.com/v1.0/policies"
        policies = {
            "admin_consent request": RestApiSpec("graph", f"{base}/adminConsentRequestPolicy"),
            "authorization": RestApiSpec("graph", f"{base}/authorizationPolicy"),
            "authentication_flow": RestApiSpec("graph", f"{base}/authenticationFlowsPolicy"),
            "authentication_method": RestApiSpec("graph", f"{base}/authenticationMethodsPolicy"),
            "cross_tenant_access": RestApiSpec("graph", f"{base}/crossTenantAccessPolicy"),
            "default_app_management": RestApiSpec("graph", f"{base}/defaultAppManagementPolicy"),
            "device_registration": RestApiSpec("graph", f"{base}/deviceRegistrationPolicy"),
            "identity_security_defaults_enforcement": RestApiSpec(
                "graph", f"{base}/identitySecurityDefaultsEnforcementPolicy"
            ),
            "activity_based_timeout": RestApiSpec(
                "graph", f"{base}/activityBasedTimeoutPolicies", expect_array=True, access_path="value"
            ),
            "app_management": RestApiSpec(
                "graph", f"{base}/appManagementPolicies", expect_array=True, access_path="value"
            ),
            "authentication_strength": RestApiSpec(
                "graph", f"{base}/authenticationStrengthPolicies", expect_array=True, access_path="value"
            ),
            "claims_mapping": RestApiSpec(
                "graph", f"{base}/claimsMappingPolicies", expect_array=True, access_path="value"
            ),
            "conditional_access": RestApiSpec(
                "graph", f"{base}/conditionalAccessPolicies", expect_array=True, access_path="value"
            ),
            "feature_rollout": RestApiSpec(
                "graph", f"{base}/featureRolloutPolicies", expect_array=True, access_path="value"
            ),
            "home_realm_discovery": RestApiSpec(
                "graph", f"{base}/homeRealmDiscoveryPolicies", expect_array=True, access_path="value"
            ),
            "token_issuance": RestApiSpec(
                "graph", f"{base}/tokenIssuancePolicies", expect_array=True, access_path="value"
            ),
        }
        result = []
        for policy_kind, spec in policies.items():
            try:
                for response in builder.client.list(spec, **kwargs):
                    rid = response.pop("id", policy_kind)
                    name = response.pop("displayName", policy_kind)
                    description = response.pop("description", None)
                    enabled = response.pop("isEnabled", None) or response.pop("state", None) == "enabled" or True
                    created = response.pop("createdDateTime", None)
                    updated = response.pop("modifiedDateTime", None)
                    policy = reformat_keys_to_snake({k: v for k, v in response.items() if not k.startswith("@odata")})
                    gp = MicrosoftGraphPolicy(
                        id=rid,
                        policy_kind=policy_kind,
                        name=name,
                        ctime=parse_datetime(created) if created else None,
                        mtime=parse_datetime(updated) if updated else None,
                        description=description,
                        policy=policy,  # type: ignore
                        enabled=enabled,
                    )
                    builder.add_node(gp)
                    result.append(gp)

            except Exception as e:
                log.warning(f"Error while collecting policies with service {spec.service}: {e}")
        return result


KindLookup = {
    "#microsoft.graph.user": MicrosoftGraphUser,
    "#microsoft.graph.group": MicrosoftGraphGroup,
    "#microsoft.graph.role": MicrosoftGraphRole,
}
MicrosoftGraphPrincipalTypes: List[Type[MicrosoftGraphEntity]] = [
    MicrosoftGraphUser,
    MicrosoftGraphDevice,
    MicrosoftGraphServicePrincipal,
    MicrosoftGraphGroup,
]


resources: List[Type[MicrosoftResource]] = [
    MicrosoftGraphPolicy,
    MicrosoftGraphDevice,
    MicrosoftGraphServicePrincipal,
    MicrosoftGraphGroup,
    MicrosoftGraphRole,
    MicrosoftGraphUser,
]
