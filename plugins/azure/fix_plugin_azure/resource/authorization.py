from datetime import datetime
from typing import ClassVar, Dict, Optional, List, Type

from attr import define, field

from fix_plugin_azure.azure_client import AzureResourceSpec
from fix_plugin_azure.resource.base import (
    MicrosoftResource,
    GraphBuilder,
    AzureSubscription,
)
from fixlib.baseresources import BaseRole
from fixlib.graph import BySearchCriteria
from fixlib.json_bender import Bender, S, ForallBend
from fixlib.types import Json


@define(eq=False, slots=False)
class AzureDenyAssignmentPermission:
    kind: ClassVar[str] = "azure_deny_assignment_permission"
    mapping: ClassVar[Dict[str, Bender]] = {
        "actions": S("actions"),
        "condition": S("condition"),
        "condition_version": S("conditionVersion"),
        "data_actions": S("dataActions"),
        "not_actions": S("notActions"),
        "not_data_actions": S("notDataActions"),
    }
    actions: Optional[List[str]] = field(default=None, metadata={'description': 'Actions to which the deny assignment does not grant access.'})  # fmt: skip
    condition: Optional[str] = field(default=None, metadata={'description': 'The conditions on the Deny assignment permission. This limits the resources it applies to.'})  # fmt: skip
    condition_version: Optional[str] = field(default=None, metadata={"description": "Version of the condition."})
    data_actions: Optional[List[str]] = field(default=None, metadata={'description': 'Data actions to which the deny assignment does not grant access.'})  # fmt: skip
    not_actions: Optional[List[str]] = field(default=None, metadata={'description': 'Actions to exclude from that the deny assignment does not grant access.'})  # fmt: skip
    not_data_actions: Optional[List[str]] = field(default=None, metadata={'description': 'Data actions to exclude from that the deny assignment does not grant access.'})  # fmt: skip


@define(eq=False, slots=False)
class AzurePrincipal:
    kind: ClassVar[str] = "azure_principal"
    mapping: ClassVar[Dict[str, Bender]] = {
        "display_name": S("displayName"),
        "email": S("email"),
        "id": S("id"),
        "type": S("type"),
    }
    display_name: Optional[str] = field(default=None, metadata={'description': 'The name of the principal made changes'})  # fmt: skip
    email: Optional[str] = field(default=None, metadata={"description": "Email of principal"})
    id: Optional[str] = field(default=None, metadata={"description": "The id of the principal made changes"})
    type: Optional[str] = field(default=None, metadata={"description": "Type of principal such as user , group etc"})


@define(eq=False, slots=False)
class AzureDenyAssignment(MicrosoftResource):
    kind: ClassVar[str] = "azure_deny_assignment"
    api_spec: ClassVar[AzureResourceSpec] = AzureResourceSpec(
        service="authorization",
        version="2022-04-01",
        path="/subscriptions/{subscriptionId}/providers/Microsoft.Authorization/denyAssignments",
        path_parameters=["subscriptionId"],
        query_parameters=["api-version"],
        access_path="value",
        expect_array=True,
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "ctime": S("properties", "createdOn"),
        "mtime": S("properties", "updatedOn"),
        "condition": S("properties", "condition"),
        "condition_version": S("properties", "conditionVersion"),
        "created_by": S("properties", "createdBy"),
        "created_on": S("properties", "createdOn"),
        "deny_assignment_name": S("properties", "denyAssignmentName"),
        "description": S("properties", "description"),
        "do_not_apply_to_child_scopes": S("properties", "doNotApplyToChildScopes"),
        "exclude_principals": S("properties", "excludePrincipals") >> ForallBend(AzurePrincipal.mapping),
        "is_system_protected": S("properties", "isSystemProtected"),
        "permissions": S("properties", "permissions") >> ForallBend(AzureDenyAssignmentPermission.mapping),
        "principals": S("properties", "principals") >> ForallBend(AzurePrincipal.mapping),
        "scope": S("properties", "scope"),
        "updated_by": S("properties", "updatedBy"),
        "updated_on": S("properties", "updatedOn"),
    }
    condition: Optional[str] = field(default=None, metadata={'description': 'The conditions on the deny assignment. This limits the resources it can be assigned to. e.g.: @Resource[Microsoft.Storage/storageAccounts/blobServices/containers:ContainerName] StringEqualsIgnoreCase foo_storage_container '})  # fmt: skip
    condition_version: Optional[str] = field(default=None, metadata={"description": "Version of the condition."})
    created_by: Optional[str] = field(default=None, metadata={'description': 'Id of the user who created the assignment'})  # fmt: skip
    created_on: Optional[datetime] = field(default=None, metadata={"description": "Time it was created"})
    deny_assignment_name: Optional[str] = field(default=None, metadata={'description': 'The display name of the deny assignment.'})  # fmt: skip
    description: Optional[str] = field(default=None, metadata={'description': 'The description of the deny assignment.'})  # fmt: skip
    do_not_apply_to_child_scopes: Optional[bool] = field(default=None, metadata={'description': 'Determines if the deny assignment applies to child scopes. Default value is false.'})  # fmt: skip
    exclude_principals: Optional[List[AzurePrincipal]] = field(default=None, metadata={'description': 'Array of principals to which the deny assignment does not apply.'})  # fmt: skip
    is_system_protected: Optional[bool] = field(default=None, metadata={'description': 'Specifies whether this deny assignment was created by Azure and cannot be edited or deleted.'})  # fmt: skip
    permissions: Optional[List[AzureDenyAssignmentPermission]] = field(default=None, metadata={'description': 'An array of permissions that are denied by the deny assignment.'})  # fmt: skip
    principals: Optional[List[AzurePrincipal]] = field(default=None, metadata={'description': 'Array of principals to which the deny assignment applies.'})  # fmt: skip
    scope: Optional[str] = field(default=None, metadata={"description": "The deny assignment scope."})
    updated_by: Optional[str] = field(default=None, metadata={'description': 'Id of the user who updated the assignment'})  # fmt: skip
    updated_on: Optional[datetime] = field(default=None, metadata={"description": "Time it was updated"})


@define(eq=False, slots=False)
class AzureRoleAssignment(MicrosoftResource):
    kind: ClassVar[str] = "azure_role_assignment"
    api_spec: ClassVar[AzureResourceSpec] = AzureResourceSpec(
        service="authorization",
        version="2022-04-01",
        path="/subscriptions/{subscriptionId}/providers/Microsoft.Authorization/roleAssignments",
        path_parameters=["subscriptionId"],
        query_parameters=["api-version"],
        access_path="value",
        expect_array=True,
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "ctime": S("properties", "createdOn"),
        "mtime": S("properties", "updatedOn"),
        "condition": S("properties", "condition"),
        "condition_version": S("properties", "conditionVersion"),
        "created_by": S("properties", "createdBy"),
        "created_on": S("properties", "createdOn"),
        "delegated_managed_identity_resource_id": S("properties", "delegatedManagedIdentityResourceId"),
        "description": S("properties", "description"),
        "principal_id": S("properties", "principalId"),
        "principal_type": S("properties", "principalType"),
        "role_definition_id": S("properties", "roleDefinitionId"),
        "scope": S("properties", "scope"),
        "updated_by": S("properties", "updatedBy"),
        "updated_on": S("properties", "updatedOn"),
    }
    kind_lookup: ClassVar[Dict[str, str]] = {
        "User": "microsoft_graph_user",
        "Device": "microsoft_graph_device",
        "ServicePrincipal": "microsoft_graph_service_principal",
        "Group": "microsoft_graph_group",
        "Subscription": "azure_subscription",
        "ResourceGroup": "azure_resource_group",
        "Resource": "azure_resource",
    }

    condition: Optional[str] = field(default=None, metadata={'description': 'The conditions on the role assignment. This limits the resources it can be assigned to. e.g.: @Resource[Microsoft.Storage/storageAccounts/blobServices/containers:ContainerName] StringEqualsIgnoreCase foo_storage_container '})  # fmt: skip
    condition_version: Optional[str] = field(default=None, metadata={'description': 'Version of the condition. Currently the only accepted value is 2.0 '})  # fmt: skip
    created_by: Optional[str] = field(default=None, metadata={'description': 'Id of the user who created the assignment'})  # fmt: skip
    created_on: Optional[datetime] = field(default=None, metadata={"description": "Time it was created"})
    delegated_managed_identity_resource_id: Optional[str] = field(default=None, metadata={'description': 'Id of the delegated managed identity resource'})  # fmt: skip
    description: Optional[str] = field(default=None, metadata={"description": "Description of role assignment"})
    principal_id: Optional[str] = field(default=None, metadata={"description": "The principal ID."})
    principal_type: Optional[str] = field(default=None, metadata={'description': 'The principal type of the assigned principal ID.'})  # fmt: skip
    role_definition_id: Optional[str] = field(default=None, metadata={"description": "The role definition ID."})
    scope: Optional[str] = field(default=None, metadata={"description": "The role assignment scope."})
    updated_by: Optional[str] = field(default=None, metadata={'description': 'Id of the user who updated the assignment'})  # fmt: skip
    updated_on: Optional[datetime] = field(default=None, metadata={"description": "Time it was updated"})

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        # role definition
        if rid := self.role_definition_id:
            builder.add_edge(self, clazz=AzureRoleDefinition, id=rid)

        # scope
        if scope := self.scope:
            scope_parts = scope.split("/")
            if scope.startswith("/providers/Microsoft.Management/managementGroups/"):  # management group
                pass
            elif len(scope_parts) == 2:  # subscription
                builder.add_edge(self, reverse=True, clazz=AzureSubscription, id=scope_parts[-1])
            else:  # resource group or resource
                builder.add_edge(self, reverse=True, id=scope)

        # principal: collected via ms graph -> create a deferred edge
        if (pt := self.principal_type) and (pt_kind := self.kind_lookup.get(pt)) and (pid := self.principal_id):
            builder.add_deferred_edge(from_node=self, to_node=BySearchCriteria(f'is({pt_kind}) and id=="{pid}"'))


@define(eq=False, slots=False)
class AzurePermission:
    kind: ClassVar[str] = "azure_permission"
    mapping: ClassVar[Dict[str, Bender]] = {
        "actions": S("actions"),
        "data_actions": S("dataActions"),
        "not_actions": S("notActions"),
        "not_data_actions": S("notDataActions"),
    }
    actions: Optional[List[str]] = field(default=None, metadata={"description": "Allowed actions."})
    data_actions: Optional[List[str]] = field(default=None, metadata={"description": "Allowed Data actions."})
    not_actions: Optional[List[str]] = field(default=None, metadata={"description": "Denied actions."})
    not_data_actions: Optional[List[str]] = field(default=None, metadata={"description": "Denied Data actions."})


@define(eq=False, slots=False)
class AzureRoleDefinition(MicrosoftResource, BaseRole):
    kind: ClassVar[str] = "azure_role_definition"
    api_spec: ClassVar[AzureResourceSpec] = AzureResourceSpec(
        service="authorization",
        version="2022-04-01",
        path="/{subscriptionId}/providers/Microsoft.Authorization/roleDefinitions",
        path_parameters=["subscriptionId"],
        query_parameters=["api-version"],
        access_path="value",
        expect_array=True,
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "name": S("name"),
        "ctime": S("properties", "createdOn"),
        "mtime": S("properties", "updatedOn"),
        "assignable_scopes": S("properties", "assignableScopes"),
        "created_by": S("properties", "createdBy"),
        "created_on": S("properties", "createdOn"),
        "description": S("properties", "description"),
        "permissions": S("properties", "permissions") >> ForallBend(AzurePermission.mapping),
        "role_name": S("properties", "roleName"),
        "updated_by": S("properties", "updatedBy"),
        "updated_on": S("properties", "updatedOn"),
    }
    assignable_scopes: Optional[List[str]] = field(default=None, metadata={'description': 'Role definition assignable scopes.'})  # fmt: skip
    created_by: Optional[str] = field(default=None, metadata={'description': 'Id of the user who created the assignment'})  # fmt: skip
    created_on: Optional[datetime] = field(default=None, metadata={"description": "Time it was created"})
    description: Optional[str] = field(default=None, metadata={"description": "The role definition description."})
    permissions: Optional[List[AzurePermission]] = field(default=None, metadata={'description': 'Role definition permissions.'})  # fmt: skip
    role_name: Optional[str] = field(default=None, metadata={"description": "The role name."})
    updated_by: Optional[str] = field(default=None, metadata={'description': 'Id of the user who updated the assignment'})  # fmt: skip
    updated_on: Optional[datetime] = field(default=None, metadata={"description": "Time it was updated"})


resources: List[Type[MicrosoftResource]] = [
    AzureDenyAssignment,
    AzureRoleAssignment,
    AzureRoleDefinition,
]
