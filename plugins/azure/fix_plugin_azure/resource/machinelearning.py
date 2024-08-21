from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, ClassVar, Dict, Optional, List, Type

from attr import define, field

from fix_plugin_azure.azure_client import AzureResourceSpec
from fix_plugin_azure.resource.base import (
    AzureProxyResource,
    AzureTrackedResource,
    MicrosoftResource,
    AzureSystemData,
    AzureSku,
    AzureManagedServiceIdentity,
    GraphBuilder,
    AzureBaseUsage,
)
from fixlib.json_bender import Bender, S, ForallBend, Bend, K
from fixlib.types import Json

log = logging.getLogger("fix.plugins.azure")
service_name = "azure_machinelearning"


@define(eq=False, slots=False)
class AzureEndpointAuthKeys:
    kind: ClassVar[str] = "azure_endpoint_auth_keys"
    mapping: ClassVar[Dict[str, Bender]] = {"primary_key": S("primaryKey"), "secondary_key": S("secondaryKey")}
    primary_key: Optional[str] = field(default=None, metadata={"description": "The primary key."})
    secondary_key: Optional[str] = field(default=None, metadata={"description": "The secondary key."})


@define(eq=False, slots=False)
class AzureMachineLearningBatchEndpoint(MicrosoftResource, AzureTrackedResource):
    kind: ClassVar[str] = "azure_machine_learning_batch_endpoint"
    api_spec: ClassVar[AzureResourceSpec] = AzureResourceSpec(
        service="machinelearningservices",
        version="2024-04-01",
        path="/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.MachineLearningServices/workspaces/{workspaceName}/batchEndpoints",
        path_parameters=["subscriptionId", "resourceGroupName", "workspaceName"],
        query_parameters=["api-version"],
        access_path="value",
        expect_array=True,
    )
    mapping: ClassVar[Dict[str, Bender]] = AzureTrackedResource.mapping | {
        "id": K(None),
        "tags": S("tags", default={}),
        "name": K(None),
        "ctime": K(None),
        "mtime": K(None),
        "atime": K(None),
        "auth_mode": S("properties", "authMode"),
        "description": S("properties", "description"),
        "keys": S("properties", "keys") >> Bend(AzureEndpointAuthKeys.mapping),
        "properties": S("properties", "properties"),
        "scoring_uri": S("properties", "scoringUri"),
        "swagger_uri": S("properties", "swaggerUri"),
        "defaults": S("properties", "defaults", "deploymentName"),
        "identity": S("identity") >> Bend(AzureManagedServiceIdentity.mapping),
        "azure_kind": S("kind"),
        "provisioning_state": S("properties", "provisioningState"),
        "sku": S("sku") >> Bend(AzureSku.mapping),
    }
    auth_mode: Optional[str] = field(default=None, metadata={'description': 'Enum to determine endpoint authentication mode.'})  # fmt: skip
    description: Optional[str] = field(default=None, metadata={'description': 'Description of the inference endpoint.'})  # fmt: skip
    keys: Optional[AzureEndpointAuthKeys] = field(default=None, metadata={'description': 'Keys for endpoint authentication.'})  # fmt: skip
    properties: Optional[Dict[str, str]] = field(default=None, metadata={'description': 'Property dictionary. Properties can be added, but not removed or altered.'})  # fmt: skip
    scoring_uri: Optional[str] = field(default=None, metadata={"description": "Endpoint URI."})
    swagger_uri: Optional[str] = field(default=None, metadata={"description": "Endpoint Swagger URI."})
    defaults: Optional[str] = field(default=None, metadata={"description": "Batch endpoint default values"})
    identity: Optional[AzureManagedServiceIdentity] = field(default=None, metadata={'description': 'Managed service identity (system assigned and/or user assigned identities)'})  # fmt: skip
    azure_kind: Optional[str] = field(default=None, metadata={'description': 'Metadata used by portal/tooling/etc to render different UX experiences for resources of the same type.'})  # fmt: skip
    provisioning_state: Optional[str] = field(default=None, metadata={'description': 'State of endpoint provisioning.'})  # fmt: skip
    sku: Optional[AzureSku] = field(default=None, metadata={'description': 'The resource model definition representing SKU'})  # fmt: skip


@define(eq=False, slots=False)
class AzureMachineLearningCodeVersion(MicrosoftResource, AzureProxyResource):
    kind: ClassVar[str] = "azure_machine_learning_code_version"
    api_spec: ClassVar[AzureResourceSpec] = AzureResourceSpec(
        service="machinelearningservices",
        version="2024-04-01",
        path="/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.MachineLearningServices/workspaces/{workspaceName}/codes/{name}/versions",
        path_parameters=["subscriptionId", "resourceGroupName", "workspaceName", "name"],
        query_parameters=["api-version"],
        access_path="value",
        expect_array=True,
    )
    mapping: ClassVar[Dict[str, Bender]] = AzureProxyResource.mapping | {
        "id": K(None),
        "name": K(None),
        "ctime": K(None),
        "mtime": K(None),
        "atime": K(None),
        "tags": S("properties", "tags", default={}),
        "code_uri": S("properties", "codeUri"),
        "provisioning_state": S("properties", "provisioningState"),
        "description": S("properties", "description"),
        "properties": S("properties", "properties"),
        "is_anonymous": S("properties", "isAnonymous"),
        "is_archived": S("properties", "isArchived"),
    }
    description: Optional[str] = field(default=None, metadata={"description": "The asset description text."})
    properties: Optional[Dict[str, str]] = field(default=None, metadata={'description': 'The asset property dictionary.'})  # fmt: skip
    is_anonymous: Optional[bool] = field(default=None, metadata={'description': 'If the name version are system generated (anonymous registration).'})  # fmt: skip
    is_archived: Optional[bool] = field(default=None, metadata={"description": "Is the asset archived?"})
    code_uri: Optional[str] = field(default=None, metadata={"description": "Uri where code is located"})
    provisioning_state: Optional[str] = field(default=None, metadata={'description': 'Provisioning state of registry asset.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureMachineLearningComponentVersion(MicrosoftResource, AzureProxyResource):
    kind: ClassVar[str] = "azure_machine_learning_component_version"
    api_spec: ClassVar[AzureResourceSpec] = AzureResourceSpec(
        service="machinelearningservices",
        version="2024-04-01",
        path="/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.MachineLearningServices/workspaces/{workspaceName}/components/{name}/versions",
        path_parameters=["subscriptionId", "resourceGroupName", "workspaceName", "name"],
        query_parameters=["api-version"],
        access_path="value",
        expect_array=True,
    )
    mapping: ClassVar[Dict[str, Bender]] = AzureProxyResource.mapping | {
        "id": K(None),
        "name": K(None),
        "ctime": K(None),
        "mtime": K(None),
        "atime": K(None),
        "component_spec": S("properties", "componentSpec"),
        "tags": S("properties", "tags", default={}),
        "code_uri": S("properties", "codeUri"),
        "provisioning_state": S("properties", "provisioningState"),
        "description": S("properties", "description"),
        "properties": S("properties", "properties"),
        "is_anonymous": S("properties", "isAnonymous"),
        "is_archived": S("properties", "isArchived"),
    }
    description: Optional[str] = field(default=None, metadata={"description": "The asset description text."})
    properties: Optional[Dict[str, str]] = field(default=None, metadata={'description': 'The asset property dictionary.'})  # fmt: skip
    is_anonymous: Optional[bool] = field(default=None, metadata={'description': 'If the name version are system generated (anonymous registration).'})  # fmt: skip
    is_archived: Optional[bool] = field(default=None, metadata={"description": "Is the asset archived?"})
    component_spec: Optional[Any] = field(default=None, metadata={'description': 'Defines Component definition details. <see href= https://docs.microsoft.com/en-us/azure/machine-learning/reference-yaml-component-command />'})  # fmt: skip
    provisioning_state: Optional[str] = field(default=None, metadata={'description': 'Provisioning state of registry asset.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureErrorDetail:
    kind: ClassVar[str] = "azure_error_detail"
    mapping: ClassVar[Dict[str, Bender]] = {"code": S("code"), "message": S("message"), "target": S("target")}
    code: Optional[str] = field(default=None, metadata={"description": "The error code."})
    message: Optional[str] = field(default=None, metadata={"description": "The error message."})
    target: Optional[str] = field(default=None, metadata={"description": "The error target."})


@define(eq=False, slots=False)
class AzureErrorResponse:
    kind: ClassVar[str] = "azure_error_response"
    mapping: ClassVar[Dict[str, Bender]] = {"error": S("error") >> Bend(AzureErrorDetail.mapping)}
    error: Optional[AzureErrorDetail] = field(default=None, metadata={"description": "The error detail."})


@define(eq=False, slots=False)
class AzureMachineLearningCompute(MicrosoftResource):
    kind: ClassVar[str] = "azure_machine_learning_compute"
    api_spec: ClassVar[AzureResourceSpec] = AzureResourceSpec(
        service="machinelearningservices",
        version="2024-04-01",
        path="/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.MachineLearningServices/workspaces/{workspaceName}/computes",
        path_parameters=["subscriptionId", "resourceGroupName", "workspaceName"],
        query_parameters=["api-version"],
        access_path="value",
        expect_array=True,
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "ctime": K(None),
        "mtime": K(None),
        "atime": K(None),
        "compute_location": S("properties", "computeLocation"),
        "compute_type": S("properties", "computeType"),
        "created_on": S("properties", "createdOn"),
        "description": S("properties", "description"),
        "disable_local_auth": S("properties", "disableLocalAuth"),
        "is_attached_compute": S("properties", "isAttachedCompute"),
        "modified_on": S("properties", "modifiedOn"),
        "provisioning_errors": S("properties", "provisioningErrors") >> ForallBend(AzureErrorResponse.mapping),
        "provisioning_state": S("properties", "provisioningState"),
        "resource_id": S("properties", "resourceId"),
        "identity": S("identity") >> Bend(AzureManagedServiceIdentity.mapping),
        "sku": S("sku") >> Bend(AzureSku.mapping),
        "system_data": S("systemData") >> Bend(AzureSystemData.mapping),
    }
    compute_location: Optional[str] = field(default=None, metadata={'description': 'Location for the underlying compute'})  # fmt: skip
    compute_type: Optional[str] = field(default=None, metadata={"description": "The type of compute"})
    created_on: Optional[datetime] = field(default=None, metadata={'description': 'The time at which the compute was created.'})  # fmt: skip
    description: Optional[str] = field(default=None, metadata={'description': 'The description of the Machine Learning compute.'})  # fmt: skip
    disable_local_auth: Optional[bool] = field(default=None, metadata={'description': 'Opt-out of local authentication and ensure customers can use only MSI and AAD exclusively for authentication.'})  # fmt: skip
    is_attached_compute: Optional[bool] = field(default=None, metadata={'description': 'Indicating whether the compute was provisioned by user and brought from outside if true, or machine learning service provisioned it if false.'})  # fmt: skip
    modified_on: Optional[datetime] = field(default=None, metadata={'description': 'The time at which the compute was last modified.'})  # fmt: skip
    provisioning_errors: Optional[List[AzureErrorResponse]] = field(default=None, metadata={'description': 'Errors during provisioning'})  # fmt: skip
    provisioning_state: Optional[str] = field(default=None, metadata={'description': 'The provision state of the cluster. Valid values are Unknown, Updating, Provisioning, Succeeded, and Failed.'})  # fmt: skip
    resource_id: Optional[str] = field(default=None, metadata={'description': 'ARM resource id of the underlying compute'})  # fmt: skip
    identity: Optional[AzureManagedServiceIdentity] = field(default=None, metadata={'description': 'Managed service identity (system assigned and/or user assigned identities)'})  # fmt: skip
    sku: Optional[AzureSku] = field(default=None, metadata={'description': 'The resource model definition representing SKU'})  # fmt: skip
    system_data: Optional[AzureSystemData] = field(default=None, metadata={'description': 'Metadata pertaining to creation and last modification of the resource.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureClientCredentials:
    kind: ClassVar[str] = "azure_client_credentials"
    mapping: ClassVar[Dict[str, Bender]] = {
        "authority_url": S("authorityUrl"),
        "certificate": S("certificate"),
        "client_id": S("clientId"),
        "client_secret": S("clientSecret"),
        "is_cert_auth": S("isCertAuth"),
        "resource_group": S("resourceGroup"),
        "resource_uri": S("resourceUri"),
        "subscription_id": S("subscriptionId"),
        "tenant_id": S("tenantId"),
        "thumbprint": S("thumbprint"),
    }
    authority_url: Optional[str] = field(default=None, metadata={'description': 'The authority URL used for authentication'})  # fmt: skip
    certificate: Optional[str] = field(default=None, metadata={'description': 'The content of the certificate used for authentication'})  # fmt: skip
    client_id: Optional[str] = field(default=None, metadata={"description": "The Client ID/Application ID"})
    client_secret: Optional[str] = field(default=None, metadata={"description": "The client secret"})
    is_cert_auth: Optional[bool] = field(default=None, metadata={'description': 'Is it using certificate to authenticate. If false then use client secret'})  # fmt: skip
    resource_group: Optional[str] = field(default=None, metadata={"description": "Resource Group Name"})
    resource_uri: Optional[str] = field(default=None, metadata={'description': 'The resource the service principal/app has access to'})  # fmt: skip
    subscription_id: Optional[str] = field(default=None, metadata={"description": "Subscription Id"})
    tenant_id: Optional[str] = field(default=None, metadata={'description': 'The ID of the tenant the service principal/app belongs to'})  # fmt: skip
    thumbprint: Optional[str] = field(default=None, metadata={'description': 'The thumbprint of the certificate above'})  # fmt: skip


@define(eq=False, slots=False)
class AzureAzureStorage:
    kind: ClassVar[str] = "azure_azure_storage"
    mapping: ClassVar[Dict[str, Bender]] = {
        "account_key": S("accountKey"),
        "account_name": S("accountName"),
        "are_workspace_managed_identities_allowed": S("areWorkspaceManagedIdentitiesAllowed"),
        "blob_cache_timeout": S("blobCacheTimeout"),
        "client_credentials": S("clientCredentials") >> Bend(AzureClientCredentials.mapping),
        "container_name": S("containerName"),
        "credential": S("credential"),
        "credential_type": S("credentialType"),
        "endpoint": S("endpoint"),
        "is_sas": S("isSas"),
        "protocol": S("protocol"),
        "resource_group": S("resourceGroup"),
        "sas_token": S("sasToken"),
        "subscription_id": S("subscriptionId"),
    }
    account_key: Optional[str] = field(default=None, metadata={"description": "Storage Account Key (Deprecated)"})
    account_name: Optional[str] = field(default=None, metadata={"description": "Storage Account Name"})
    are_workspace_managed_identities_allowed: Optional[bool] = field(default=None, metadata={'description': 'Indicate if we are using Workspace ManagedIdentities/MSI token'})  # fmt: skip
    blob_cache_timeout: Optional[int] = field(default=None, metadata={'description': 'If this is an Microsoft.MachineLearning.DataStore.Contracts.DataStoreType.AzureBlob, the length of time (in seconds) to cache files locally after they are accessed (downloaded).'})  # fmt: skip
    client_credentials: Optional[AzureClientCredentials] = field(default=None, metadata={"description": ""})
    container_name: Optional[str] = field(default=None, metadata={"description": "The storage container name"})
    credential: Optional[str] = field(default=None, metadata={"description": "The credential"})
    credential_type: Optional[str] = field(default=None, metadata={"description": "The credential type"})
    endpoint: Optional[str] = field(default=None, metadata={"description": "The host of the container"})
    is_sas: Optional[bool] = field(default=None, metadata={'description': 'Indicate if we are using SAS token or Account Key (Deprecated)'})  # fmt: skip
    protocol: Optional[str] = field(default=None, metadata={"description": "The protocol to use. Defaults to https"})
    resource_group: Optional[str] = field(default=None, metadata={"description": "Resource Group Name"})
    sas_token: Optional[str] = field(default=None, metadata={'description': 'SAS Token for the container (Deprecated)'})  # fmt: skip
    subscription_id: Optional[str] = field(default=None, metadata={"description": "Subscription Id"})


@define(eq=False, slots=False)
class AzureAzureDataLake:
    kind: ClassVar[str] = "azure_azure_data_lake"
    mapping: ClassVar[Dict[str, Bender]] = {
        "authority_url": S("authorityUrl"),
        "certificate": S("certificate"),
        "client_id": S("clientId"),
        "client_secret": S("clientSecret"),
        "is_cert_auth": S("isCertAuth"),
        "resource_group": S("resourceGroup"),
        "resource_uri": S("resourceUri"),
        "store_name": S("storeName"),
        "subscription_id": S("subscriptionId"),
        "tenant_id": S("tenantId"),
        "thumbprint": S("thumbprint"),
    }
    authority_url: Optional[str] = field(default=None, metadata={'description': 'The authority URL used for authentication'})  # fmt: skip
    certificate: Optional[str] = field(default=None, metadata={'description': 'The content of the certificate used for authentication'})  # fmt: skip
    client_id: Optional[str] = field(default=None, metadata={"description": "The Client ID/Application ID"})
    client_secret: Optional[str] = field(default=None, metadata={"description": "The client secret"})
    is_cert_auth: Optional[bool] = field(default=None, metadata={'description': 'Is it using certificate to authenticate. If false then use client secret'})  # fmt: skip
    resource_group: Optional[str] = field(default=None, metadata={"description": "Resource Group Name"})
    resource_uri: Optional[str] = field(default=None, metadata={'description': 'The resource the service principal/app has access to'})  # fmt: skip
    store_name: Optional[str] = field(default=None, metadata={"description": "The Azure Data Lake store name"})
    subscription_id: Optional[str] = field(default=None, metadata={"description": "Subscription Id"})
    tenant_id: Optional[str] = field(default=None, metadata={'description': 'The ID of the tenant the service principal/app belongs to'})  # fmt: skip
    thumbprint: Optional[str] = field(default=None, metadata={'description': 'The thumbprint of the certificate above'})  # fmt: skip


@define(eq=False, slots=False)
class AzureAzureSqlDatabase:
    kind: ClassVar[str] = "azure_azure_sql_database"
    mapping: ClassVar[Dict[str, Bender]] = {
        "authority_url": S("authorityUrl"),
        "certificate": S("certificate"),
        "client_id": S("clientId"),
        "client_secret": S("clientSecret"),
        "database_name": S("databaseName"),
        "endpoint": S("endpoint"),
        "is_cert_auth": S("isCertAuth"),
        "resource_group": S("resourceGroup"),
        "resource_uri": S("resourceUri"),
        "server_name": S("serverName"),
        "subscription_id": S("subscriptionId"),
        "tenant_id": S("tenantId"),
        "thumbprint": S("thumbprint"),
    }
    authority_url: Optional[str] = field(default=None, metadata={'description': 'The authority URL used for authentication'})  # fmt: skip
    certificate: Optional[str] = field(default=None, metadata={'description': 'The content of the certificate used for authentication'})  # fmt: skip
    client_id: Optional[str] = field(default=None, metadata={"description": "The Client ID/Application ID"})
    client_secret: Optional[str] = field(default=None, metadata={"description": "The client secret"})
    database_name: Optional[str] = field(default=None, metadata={"description": "The Azure SQL database name"})
    endpoint: Optional[str] = field(default=None, metadata={"description": "The server host endpoint"})
    is_cert_auth: Optional[bool] = field(default=None, metadata={'description': 'Is it using certificate to authenticate. If false then use client secret'})  # fmt: skip
    resource_group: Optional[str] = field(default=None, metadata={"description": "Resource Group Name"})
    resource_uri: Optional[str] = field(default=None, metadata={'description': 'The resource the service principal/app has access to'})  # fmt: skip
    server_name: Optional[str] = field(default=None, metadata={"description": "The Azure SQL server name"})
    subscription_id: Optional[str] = field(default=None, metadata={"description": "Subscription Id"})
    tenant_id: Optional[str] = field(default=None, metadata={'description': 'The ID of the tenant the service principal/app belongs to'})  # fmt: skip
    thumbprint: Optional[str] = field(default=None, metadata={'description': 'The thumbprint of the certificate above'})  # fmt: skip


@define(eq=False, slots=False)
class AzureAzurePostgreSql:
    kind: ClassVar[str] = "azure_azure_postgre_sql"
    mapping: ClassVar[Dict[str, Bender]] = {
        "database_name": S("databaseName"),
        "endpoint": S("endpoint"),
        "port_number": S("portNumber"),
        "resource_group": S("resourceGroup"),
        "server_name": S("serverName"),
        "subscription_id": S("subscriptionId"),
        "user_id": S("userId"),
        "user_password": S("userPassword"),
    }
    database_name: Optional[str] = field(default=None, metadata={"description": "The Azure PostgreSQL database name"})
    endpoint: Optional[str] = field(default=None, metadata={'description': 'The Azure PostgreSQL server host endpoint'})  # fmt: skip
    port_number: Optional[str] = field(default=None, metadata={"description": "The Azure PostgreSQL port number"})
    resource_group: Optional[str] = field(default=None, metadata={"description": "Resource Group Name"})
    server_name: Optional[str] = field(default=None, metadata={"description": "The Azure PostgreSQL server name"})
    subscription_id: Optional[str] = field(default=None, metadata={"description": "Subscription Id"})
    user_id: Optional[str] = field(default=None, metadata={"description": "The Azure PostgreSQL user id"})
    user_password: Optional[str] = field(default=None, metadata={"description": "The Azure PostgreSQL user password"})


@define(eq=False, slots=False)
class AzureGlusterFs:
    kind: ClassVar[str] = "azure_gluster_fs"
    mapping: ClassVar[Dict[str, Bender]] = {"server_address": S("serverAddress"), "volume_name": S("volumeName")}
    server_address: Optional[str] = field(default=None, metadata={'description': 'The server address of one of the servers that hosts the GlusterFS. Can be either the IP address or server name.'})  # fmt: skip
    volume_name: Optional[str] = field(default=None, metadata={'description': 'The name of the created GlusterFS volume.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureDataStore:
    kind: ClassVar[str] = "azure_data_store"
    mapping: ClassVar[Dict[str, Bender]] = {
        "azure_data_lake_section": S("azureDataLakeSection") >> Bend(AzureAzureDataLake.mapping),
        "azure_postgre_sql_section": S("azurePostgreSqlSection") >> Bend(AzureAzurePostgreSql.mapping),
        "azure_sql_database_section": S("azureSqlDatabaseSection") >> Bend(AzureAzureSqlDatabase.mapping),
        "azure_storage_section": S("azureStorageSection") >> Bend(AzureAzureStorage.mapping),
        "data_store_type": S("dataStoreType"),
        "gluster_fs_section": S("glusterFsSection") >> Bend(AzureGlusterFs.mapping),
        "has_been_validated": S("hasBeenValidated"),
        "name": S("name"),
        "tags": S("tags"),
    }
    azure_data_lake_section: Optional[AzureAzureDataLake] = field(default=None, metadata={"description": ""})
    azure_postgre_sql_section: Optional[AzureAzurePostgreSql] = field(default=None, metadata={"description": ""})
    azure_sql_database_section: Optional[AzureAzureSqlDatabase] = field(default=None, metadata={"description": ""})
    azure_storage_section: Optional[AzureAzureStorage] = field(default=None, metadata={"description": ""})
    data_store_type: Optional[str] = field(default=None, metadata={'description': 'The Azure storage service this datastore points to.'})  # fmt: skip
    gluster_fs_section: Optional[AzureGlusterFs] = field(default=None, metadata={"description": ""})
    has_been_validated: Optional[bool] = field(default=None, metadata={'description': 'A read only property that denotes whether the service datastore has been validated with credentials.'})  # fmt: skip
    name: Optional[str] = field(default=None, metadata={"description": "Name of the datastore"})
    tags: Optional[Dict[str, str]] = field(default=None, metadata={"description": "Tags to datastore"})


@define(eq=False, slots=False)
class AzureMachineLearningDataVersion(MicrosoftResource, AzureProxyResource):
    kind: ClassVar[str] = "azure_machine_learning_data_version"
    api_spec: ClassVar[AzureResourceSpec] = AzureResourceSpec(
        service="machinelearningservices",
        version="2024-04-01",
        path="/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.MachineLearningServices/workspaces/{workspaceName}/data/{name}/versions",
        path_parameters=["subscriptionId", "resourceGroupName", "workspaceName", "name"],
        query_parameters=["api-version"],
        access_path="value",
        expect_array=True,
    )
    mapping: ClassVar[Dict[str, Bender]] = AzureProxyResource.mapping | {
        "id": K(None),
        "name": K(None),
        "ctime": K(None),
        "mtime": K(None),
        "atime": K(None),
        "data_type": S("properties", "dataType"),
        "data_uri": S("properties", "dataUri"),
        "tags": S("properties", "tags", default={}),
        "code_uri": S("properties", "codeUri"),
        "provisioning_state": S("properties", "provisioningState"),
        "description": S("properties", "description"),
        "properties": S("properties", "properties"),
        "is_anonymous": S("properties", "isAnonymous"),
        "is_archived": S("properties", "isArchived"),
    }
    description: Optional[str] = field(default=None, metadata={"description": "The asset description text."})
    properties: Optional[Dict[str, str]] = field(default=None, metadata={'description': 'The asset property dictionary.'})  # fmt: skip
    is_anonymous: Optional[bool] = field(default=None, metadata={'description': 'If the name version are system generated (anonymous registration).'})  # fmt: skip
    is_archived: Optional[bool] = field(default=None, metadata={"description": "Is the asset archived?"})
    data_type: Optional[str] = field(default=None, metadata={"description": "Enum to determine the type of data."})
    data_uri: Optional[str] = field(default=None, metadata={'description': '[Required] Uri of the data. Example: https://go.microsoft.com/fwlink/?linkid=2202330'})  # fmt: skip


@define(eq=False, slots=False)
class AzureMachineLearningDatastore(MicrosoftResource, AzureProxyResource):
    kind: ClassVar[str] = "azure_machine_learning_datastore"
    api_spec: ClassVar[AzureResourceSpec] = AzureResourceSpec(
        service="machinelearningservices",
        version="2024-04-01",
        path="/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.MachineLearningServices/workspaces/{workspaceName}/datastores",
        path_parameters=["subscriptionId", "resourceGroupName", "workspaceName"],
        query_parameters=["api-version"],
        access_path="value",
        expect_array=True,
    )
    mapping: ClassVar[Dict[str, Bender]] = AzureProxyResource.mapping | {
        "id": K(None),
        "tags": S("tags", default={}),
        "name": K(None),
        "ctime": K(None),
        "mtime": K(None),
        "atime": K(None),
        "credentials": S("properties", "credentials", "credentialsType"),
        "datastore_type": S("properties", "datastoreType"),
        "is_default": S("properties", "isDefault"),
        "description": S("properties", "description"),
        "properties": S("properties", "properties"),
    }
    description: Optional[str] = field(default=None, metadata={"description": "The asset description text."})
    properties: Optional[Dict[str, str]] = field(default=None, metadata={'description': 'The asset property dictionary.'})  # fmt: skip
    credentials: Optional[str] = field(default=None, metadata={'description': 'Base definition for datastore credentials.'})  # fmt: skip
    datastore_type: Optional[str] = field(default=None, metadata={'description': 'Enum to determine the datastore contents type.'})  # fmt: skip
    is_default: Optional[bool] = field(default=None, metadata={'description': 'Readonly property to indicate if datastore is the workspace default datastore'})  # fmt: skip


@define(eq=False, slots=False)
class AzureEndpointDeploymentResourceProperties:
    kind: ClassVar[str] = "azure_endpoint_deployment_resource_properties"
    mapping: ClassVar[Dict[str, Bender]] = {
        "failure_reason": S("failureReason"),
        "provisioning_state": S("provisioningState"),
        "type": S("type"),
    }
    failure_reason: Optional[str] = field(default=None, metadata={'description': 'The failure reason if the creation failed.'})  # fmt: skip
    provisioning_state: Optional[str] = field(default=None, metadata={"description": ""})
    type: Optional[str] = field(default=None, metadata={"description": "Kind of the deployment."})


@define(eq=False, slots=False)
class AzureEndpointDeploymentResourcePropertiesBasicResource:
    kind: ClassVar[str] = "azure_endpoint_deployment_resource_properties_basic_resource"
    mapping: ClassVar[Dict[str, Bender]] = {
        "failure_reason": S("properties", "failureReason"),
        "id": S("id"),
        "name": S("name"),
        "provisioning_state": S("properties", "provisioningState"),
        "system_data": S("systemData") >> Bend(AzureSystemData.mapping),
        "type": S("properties", "type"),
    }
    failure_reason: Optional[str] = field(default=None, metadata={'description': 'The failure reason if the creation failed.'})  # fmt: skip
    id: Optional[str] = field(default=None, metadata={'description': 'Fully qualified resource ID for the resource. Ex - /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}'})  # fmt: skip
    name: Optional[str] = field(default=None, metadata={"description": "The name of the resource"})
    provisioning_state: Optional[str] = field(default=None, metadata={"description": ""})
    system_data: Optional[AzureSystemData] = field(default=None, metadata={'description': 'Metadata pertaining to creation and last modification of the resource.'})  # fmt: skip
    type: Optional[str] = field(default=None, metadata={"description": "Kind of the deployment."})


@define(eq=False, slots=False)
class AzureMachineLearningEndpoint(MicrosoftResource):
    kind: ClassVar[str] = "azure_machine_learning_endpoint"
    api_spec: ClassVar[AzureResourceSpec] = AzureResourceSpec(
        service="machinelearningservices",
        version="2024-07-01-preview",
        path="/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.MachineLearningServices/workspaces/{workspaceName}/endpoints",
        path_parameters=["subscriptionId", "resourceGroupName", "workspaceName"],
        query_parameters=["api-version"],
        access_path="value",
        expect_array=True,
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "ctime": K(None),
        "mtime": K(None),
        "atime": K(None),
        "associated_resource_id": S("properties", "associatedResourceId"),
        "deployments": S("properties", "deployments")
        >> ForallBend(AzureEndpointDeploymentResourcePropertiesBasicResource.mapping),
        "endpoint_type": S("properties", "endpointType"),
        "endpoint_uri": S("properties", "endpointUri"),
        "failure_reason": S("properties", "failureReason"),
        "provisioning_state": S("properties", "provisioningState"),
        "should_create_ai_services_endpoint": S("properties", "shouldCreateAiServicesEndpoint"),
        "system_data": S("systemData") >> Bend(AzureSystemData.mapping),
    }
    associated_resource_id: Optional[str] = field(default=None, metadata={'description': 'Byo resource id for creating the built-in model service endpoints.'})  # fmt: skip
    deployments: Optional[List[AzureEndpointDeploymentResourcePropertiesBasicResource]] = field(default=None, metadata={'description': 'Deployments info.'})  # fmt: skip
    endpoint_type: Optional[str] = field(default=None, metadata={"description": "Type of the endpoint."})
    endpoint_uri: Optional[str] = field(default=None, metadata={"description": "Uri of the endpoint."})
    failure_reason: Optional[str] = field(default=None, metadata={'description': 'The failure reason if the creation failed.'})  # fmt: skip
    provisioning_state: Optional[str] = field(default=None, metadata={"description": ""})
    should_create_ai_services_endpoint: Optional[bool] = field(default=None, metadata={'description': 'Whether the proxy (non-byo) endpoint is a regular endpoint or a OneKeyV2 AI services account endpoint.'})  # fmt: skip
    system_data: Optional[AzureSystemData] = field(default=None, metadata={'description': 'Metadata pertaining to creation and last modification of the resource.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureBuildContext:
    kind: ClassVar[str] = "azure_build_context"
    mapping: ClassVar[Dict[str, Bender]] = {"context_uri": S("contextUri"), "dockerfile_path": S("dockerfilePath")}
    context_uri: Optional[str] = field(default=None, metadata={'description': '[Required] URI of the Docker build context used to build the image. Supports blob URIs on environment creation and may return blob or Git URIs. <seealso href= https://docs.docker.com/engine/reference/commandline/build/#extended-description />'})  # fmt: skip
    dockerfile_path: Optional[str] = field(default=None, metadata={'description': 'Path to the Dockerfile in the build context. <seealso href= https://docs.docker.com/engine/reference/builder/ />'})  # fmt: skip


@define(eq=False, slots=False)
class AzureRoute:
    kind: ClassVar[str] = "azure_route"
    mapping: ClassVar[Dict[str, Bender]] = {"path": S("path"), "port": S("port")}
    path: Optional[str] = field(default=None, metadata={"description": "[Required] The path for the route."})
    port: Optional[int] = field(default=None, metadata={"description": "[Required] The port for the route."})


@define(eq=False, slots=False)
class AzureInferenceContainerProperties:
    kind: ClassVar[str] = "azure_inference_container_properties"
    mapping: ClassVar[Dict[str, Bender]] = {
        "liveness_route": S("livenessRoute") >> Bend(AzureRoute.mapping),
        "readiness_route": S("readinessRoute") >> Bend(AzureRoute.mapping),
        "scoring_route": S("scoringRoute") >> Bend(AzureRoute.mapping),
    }
    liveness_route: Optional[AzureRoute] = field(default=None, metadata={"description": ""})
    readiness_route: Optional[AzureRoute] = field(default=None, metadata={"description": ""})
    scoring_route: Optional[AzureRoute] = field(default=None, metadata={"description": ""})


@define(eq=False, slots=False)
class AzureMachineLearningEnvironmentVersion(MicrosoftResource, AzureProxyResource):
    kind: ClassVar[str] = "azure_machine_learning_environment_version"
    api_spec: ClassVar[AzureResourceSpec] = AzureResourceSpec(
        service="machinelearningservices",
        version="2024-04-01",
        path="/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.MachineLearningServices/workspaces/{workspaceName}/environments/{name}/versions",
        path_parameters=["subscriptionId", "resourceGroupName", "workspaceName", "name"],
        query_parameters=["api-version"],
        access_path="value",
        expect_array=True,
    )
    mapping: ClassVar[Dict[str, Bender]] = AzureProxyResource.mapping | {
        "id": K(None),
        "name": K(None),
        "ctime": K(None),
        "mtime": K(None),
        "atime": K(None),
        "auto_rebuild": S("properties", "autoRebuild"),
        "build": S("properties", "build") >> Bend(AzureBuildContext.mapping),
        "conda_file": S("properties", "condaFile"),
        "environment_type": S("properties", "environmentType"),
        "image": S("properties", "image"),
        "inference_config": S("properties", "inferenceConfig") >> Bend(AzureInferenceContainerProperties.mapping),
        "os_type": S("properties", "osType"),
        "stage": S("properties", "stage"),
        "tags": S("properties", "tags", default={}),
        "code_uri": S("properties", "codeUri"),
        "provisioning_state": S("properties", "provisioningState"),
        "description": S("properties", "description"),
        "properties": S("properties", "properties"),
        "is_anonymous": S("properties", "isAnonymous"),
        "is_archived": S("properties", "isArchived"),
    }
    description: Optional[str] = field(default=None, metadata={"description": "The asset description text."})
    properties: Optional[Dict[str, str]] = field(default=None, metadata={'description': 'The asset property dictionary.'})  # fmt: skip
    is_anonymous: Optional[bool] = field(default=None, metadata={'description': 'If the name version are system generated (anonymous registration).'})  # fmt: skip
    is_archived: Optional[bool] = field(default=None, metadata={"description": "Is the asset archived?"})
    auto_rebuild: Optional[str] = field(default=None, metadata={'description': 'AutoRebuild setting for the derived image'})  # fmt: skip
    build: Optional[AzureBuildContext] = field(default=None, metadata={'description': 'Configuration settings for Docker build context'})  # fmt: skip
    conda_file: Optional[str] = field(default=None, metadata={'description': 'Standard configuration file used by Conda that lets you install any kind of package, including Python, R, and C/C++ packages. <see href= https://repo2docker.readthedocs.io/en/latest/config_files.html#environment-yml-install-a-conda-environment />'})  # fmt: skip
    environment_type: Optional[str] = field(default=None, metadata={'description': 'Environment type is either user created or curated by Azure ML service'})  # fmt: skip
    image: Optional[str] = field(default=None, metadata={'description': 'Name of the image that will be used for the environment. <seealso href= https://docs.microsoft.com/en-us/azure/machine-learning/how-to-deploy-custom-docker-image#use-a-custom-base-image />'})  # fmt: skip
    inference_config: Optional[AzureInferenceContainerProperties] = field(default=None, metadata={"description": ""})
    os_type: Optional[str] = field(default=None, metadata={"description": "The type of operating system."})
    provisioning_state: Optional[str] = field(default=None, metadata={'description': 'Provisioning state of registry asset.'})  # fmt: skip
    stage: Optional[str] = field(default=None, metadata={'description': 'Stage in the environment lifecycle assigned to this environment'})  # fmt: skip


@define(eq=False, slots=False)
class AzureTriggerBase:
    kind: ClassVar[str] = "azure_trigger_base"
    mapping: ClassVar[Dict[str, Bender]] = {
        "end_time": S("endTime"),
        "start_time": S("startTime"),
        "time_zone": S("timeZone"),
        "trigger_type": S("triggerType"),
    }
    end_time: Optional[str] = field(default=None, metadata={'description': 'Specifies end time of schedule in ISO 8601, but without a UTC offset. Refer https://en.wikipedia.org/wiki/ISO_8601. Recommented format would be 2022-06-01T00:00:01 If not present, the schedule will run indefinitely'})  # fmt: skip
    start_time: Optional[str] = field(default=None, metadata={'description': 'Specifies start time of schedule in ISO 8601 format, but without a UTC offset.'})  # fmt: skip
    time_zone: Optional[str] = field(default=None, metadata={'description': 'Specifies time zone in which the schedule runs. TimeZone should follow Windows time zone format. Refer: https://docs.microsoft.com/en-us/windows-hardware/manufacture/desktop/default-time-zones?view=windows-11'})  # fmt: skip
    trigger_type: Optional[str] = field(default=None, metadata={"description": ""})


@define(eq=False, slots=False)
class AzureRecurrenceSchedule:
    kind: ClassVar[str] = "azure_recurrence_schedule"
    mapping: ClassVar[Dict[str, Bender]] = {
        "hours": S("hours"),
        "minutes": S("minutes"),
        "month_days": S("monthDays"),
        "week_days": S("weekDays"),
    }
    hours: Optional[List[int]] = field(
        default=None, metadata={"description": "[Required] List of hours for the schedule."}
    )
    minutes: Optional[List[int]] = field(default=None, metadata={'description': '[Required] List of minutes for the schedule.'})  # fmt: skip
    month_days: Optional[List[int]] = field(
        default=None, metadata={"description": "List of month days for the schedule"}
    )
    week_days: Optional[List[str]] = field(default=None, metadata={"description": "List of days for the schedule."})


@define(eq=False, slots=False)
class AzureRecurrenceTrigger(AzureTriggerBase):
    kind: ClassVar[str] = "azure_recurrence_trigger"
    mapping: ClassVar[Dict[str, Bender]] = AzureTriggerBase.mapping | {
        "frequency": S("frequency"),
        "interval": S("interval"),
        "schedule": S("schedule") >> Bend(AzureRecurrenceSchedule.mapping),
    }
    frequency: Optional[str] = field(default=None, metadata={'description': 'Enum to describe the frequency of a recurrence schedule'})  # fmt: skip
    interval: Optional[int] = field(default=None, metadata={'description': '[Required] Specifies schedule interval in conjunction with frequency'})  # fmt: skip
    schedule: Optional[AzureRecurrenceSchedule] = field(default=None, metadata={"description": ""})


@define(eq=False, slots=False)
class AzureWebhook:
    kind: ClassVar[str] = "azure_webhook"
    mapping: ClassVar[Dict[str, Bender]] = {"event_type": S("eventType"), "webhook_type": S("webhookType")}
    event_type: Optional[str] = field(default=None, metadata={'description': 'Send callback on a specified notification event'})  # fmt: skip
    webhook_type: Optional[str] = field(default=None, metadata={'description': 'Enum to determine the webhook callback service type.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureNotificationSetting:
    kind: ClassVar[str] = "azure_notification_setting"
    mapping: ClassVar[Dict[str, Bender]] = {"email_on": S("emailOn"), "emails": S("emails"), "webhooks": S("webhooks")}
    email_on: Optional[List[str]] = field(default=None, metadata={'description': 'Send email notification to user on specified notification type'})  # fmt: skip
    emails: Optional[List[str]] = field(default=None, metadata={'description': 'This is the email recipient list which has a limitation of 499 characters in total concat with comma separator'})  # fmt: skip
    webhooks: Optional[Dict[str, AzureWebhook]] = field(default=None, metadata={'description': 'Send webhook callback to a service. Key is a user-provided name for the webhook.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureMaterializationSettings:
    kind: ClassVar[str] = "azure_materialization_settings"
    mapping: ClassVar[Dict[str, Bender]] = {
        "notification": S("notification") >> Bend(AzureNotificationSetting.mapping),
        "resource": S("resource", "instanceType"),
        "schedule": S("schedule") >> Bend(AzureRecurrenceTrigger.mapping),
        "spark_configuration": S("sparkConfiguration"),
        "store_type": S("storeType"),
    }
    notification: Optional[AzureNotificationSetting] = field(default=None, metadata={'description': 'Configuration for notification.'})  # fmt: skip
    resource: Optional[str] = field(default=None, metadata={"description": "DTO object representing compute resource"})
    schedule: Optional[AzureRecurrenceTrigger] = field(default=None, metadata={"description": ""})
    spark_configuration: Optional[Dict[str, str]] = field(default=None, metadata={'description': 'Specifies the spark compute settings'})  # fmt: skip
    store_type: Optional[str] = field(default=None, metadata={"description": ""})


@define(eq=False, slots=False)
class AzureMachineLearningFeaturesetVersion(MicrosoftResource, AzureProxyResource):
    kind: ClassVar[str] = "azure_machine_learning_featureset_version"
    api_spec: ClassVar[AzureResourceSpec] = AzureResourceSpec(
        service="machinelearningservices",
        version="2024-04-01",
        path="/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.MachineLearningServices/workspaces/{workspaceName}/featuresets/{name}/versions",
        path_parameters=["subscriptionId", "resourceGroupName", "workspaceName", "name"],
        query_parameters=["api-version"],
        access_path="value",
        expect_array=True,
    )
    mapping: ClassVar[Dict[str, Bender]] = AzureProxyResource.mapping | {
        "id": K(None),
        "name": K(None),
        "ctime": K(None),
        "mtime": K(None),
        "atime": K(None),
        "entities": S("properties", "entities"),
        "materialization_settings": S("properties", "materializationSettings")
        >> Bend(AzureMaterializationSettings.mapping),
        "specification": S("properties", "specification", "path"),
        "stage": S("properties", "stage"),
        "tags": S("properties", "tags", default={}),
        "code_uri": S("properties", "codeUri"),
        "provisioning_state": S("properties", "provisioningState"),
        "description": S("properties", "description"),
        "properties": S("properties", "properties"),
        "is_anonymous": S("properties", "isAnonymous"),
        "is_archived": S("properties", "isArchived"),
    }
    description: Optional[str] = field(default=None, metadata={"description": "The asset description text."})
    properties: Optional[Dict[str, str]] = field(default=None, metadata={'description': 'The asset property dictionary.'})  # fmt: skip
    is_anonymous: Optional[bool] = field(default=None, metadata={'description': 'If the name version are system generated (anonymous registration).'})  # fmt: skip
    is_archived: Optional[bool] = field(default=None, metadata={"description": "Is the asset archived?"})
    entities: Optional[List[str]] = field(default=None, metadata={"description": "Specifies list of entities"})
    materialization_settings: Optional[AzureMaterializationSettings] = field(default=None, metadata={'description': ''})  # fmt: skip
    provisioning_state: Optional[str] = field(default=None, metadata={'description': 'Provisioning state of registry asset.'})  # fmt: skip
    specification: Optional[str] = field(default=None, metadata={'description': 'DTO object representing specification'})  # fmt: skip
    stage: Optional[str] = field(default=None, metadata={"description": "Specifies the asset stage"})


@define(eq=False, slots=False)
class AzureIndexColumn:
    kind: ClassVar[str] = "azure_index_column"
    mapping: ClassVar[Dict[str, Bender]] = {"column_name": S("columnName"), "data_type": S("dataType")}
    column_name: Optional[str] = field(default=None, metadata={"description": "Specifies the column name"})
    data_type: Optional[str] = field(default=None, metadata={"description": ""})


@define(eq=False, slots=False)
class AzureMachineLearningFeaturestoreEntityVersion(MicrosoftResource, AzureProxyResource):
    kind: ClassVar[str] = "azure_machine_learning_featurestore_entity_version"
    api_spec: ClassVar[AzureResourceSpec] = AzureResourceSpec(
        service="machinelearningservices",
        version="2024-04-01",
        path="/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.MachineLearningServices/workspaces/{workspaceName}/featurestoreEntities/{name}/versions",
        path_parameters=["subscriptionId", "resourceGroupName", "workspaceName", "name"],
        query_parameters=["api-version"],
        access_path="value",
        expect_array=True,
    )
    mapping: ClassVar[Dict[str, Bender]] = AzureProxyResource.mapping | {
        "id": K(None),
        "name": K(None),
        "ctime": K(None),
        "mtime": K(None),
        "atime": K(None),
        "index_columns": S("properties", "indexColumns") >> ForallBend(AzureIndexColumn.mapping),
        "stage": S("properties", "stage"),
        "tags": S("properties", "tags", default={}),
        "code_uri": S("properties", "codeUri"),
        "provisioning_state": S("properties", "provisioningState"),
        "description": S("properties", "description"),
        "properties": S("properties", "properties"),
        "is_anonymous": S("properties", "isAnonymous"),
        "is_archived": S("properties", "isArchived"),
    }
    description: Optional[str] = field(default=None, metadata={"description": "The asset description text."})
    properties: Optional[Dict[str, str]] = field(default=None, metadata={'description': 'The asset property dictionary.'})  # fmt: skip
    is_anonymous: Optional[bool] = field(default=None, metadata={'description': 'If the name version are system generated (anonymous registration).'})  # fmt: skip
    is_archived: Optional[bool] = field(default=None, metadata={"description": "Is the asset archived?"})
    index_columns: Optional[List[AzureIndexColumn]] = field(default=None, metadata={'description': 'Specifies index columns'})  # fmt: skip
    provisioning_state: Optional[str] = field(default=None, metadata={'description': 'Provisioning state of registry asset.'})  # fmt: skip
    stage: Optional[str] = field(default=None, metadata={"description": "Specifies the asset stage"})


@define(eq=False, slots=False)
class AzureJobService:
    kind: ClassVar[str] = "azure_job_service"
    mapping: ClassVar[Dict[str, Bender]] = {
        "endpoint": S("endpoint"),
        "error_message": S("errorMessage"),
        "job_service_type": S("jobServiceType"),
        "nodes": S("nodes", "nodesValueType"),
        "port": S("port"),
        "properties": S("properties"),
        "status": S("status"),
    }
    endpoint: Optional[str] = field(default=None, metadata={"description": "Url for endpoint."})
    error_message: Optional[str] = field(default=None, metadata={"description": "Any error in the service."})
    job_service_type: Optional[str] = field(default=None, metadata={"description": "Endpoint type."})
    nodes: Optional[str] = field(default=None, metadata={"description": "Abstract Nodes definition"})
    port: Optional[int] = field(default=None, metadata={"description": "Port for endpoint."})
    properties: Optional[Dict[str, str]] = field(default=None, metadata={'description': 'Additional properties to set on the endpoint.'})  # fmt: skip
    status: Optional[str] = field(default=None, metadata={"description": "Status of endpoint."})


@define(eq=False, slots=False)
class AzureMachineLearningJob(MicrosoftResource, AzureProxyResource):
    kind: ClassVar[str] = "azure_machine_learning_job"
    api_spec: ClassVar[AzureResourceSpec] = AzureResourceSpec(
        service="machinelearningservices",
        version="2024-04-01",
        path="/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.MachineLearningServices/workspaces/{workspaceName}/jobs",
        path_parameters=["subscriptionId", "resourceGroupName", "workspaceName"],
        query_parameters=["api-version"],
        access_path="value",
        expect_array=True,
    )
    mapping: ClassVar[Dict[str, Bender]] = AzureProxyResource.mapping | {
        "id": K(None),
        "tags": S("tags", default={}),
        "name": K(None),
        "ctime": K(None),
        "mtime": K(None),
        "atime": K(None),
        "component_id": S("properties", "componentId"),
        "compute_id": S("properties", "computeId"),
        "display_name": S("properties", "displayName"),
        "experiment_name": S("properties", "experimentName"),
        "identity": S("properties", "identity", "identityType"),
        "is_archived": S("properties", "isArchived"),
        "job_type": S("properties", "jobType"),
        "notification_setting": S("properties", "notificationSetting") >> Bend(AzureNotificationSetting.mapping),
        "services": S("properties", "services"),
        "status": S("properties", "status"),
        "description": S("properties", "description"),
        "properties": S("properties", "properties"),
    }
    description: Optional[str] = field(default=None, metadata={"description": "The asset description text."})
    properties: Optional[Dict[str, str]] = field(default=None, metadata={'description': 'The asset property dictionary.'})  # fmt: skip
    component_id: Optional[str] = field(default=None, metadata={'description': 'ARM resource ID of the component resource.'})  # fmt: skip
    compute_id: Optional[str] = field(default=None, metadata={'description': 'ARM resource ID of the compute resource.'})  # fmt: skip
    display_name: Optional[str] = field(default=None, metadata={"description": "Display name of job."})
    experiment_name: Optional[str] = field(default=None, metadata={'description': 'The name of the experiment the job belongs to. If not set, the job is placed in the Default experiment.'})  # fmt: skip
    identity: Optional[str] = field(default=None, metadata={'description': 'Base definition for identity configuration.'})  # fmt: skip
    is_archived: Optional[bool] = field(default=None, metadata={"description": "Is the asset archived?"})
    job_type: Optional[str] = field(default=None, metadata={"description": "Enum to determine the type of job."})
    notification_setting: Optional[AzureNotificationSetting] = field(default=None, metadata={'description': 'Configuration for notification.'})  # fmt: skip
    services: Optional[Dict[str, AzureJobService]] = field(default=None, metadata={'description': 'List of JobEndpoints. For local jobs, a job endpoint will have an endpoint value of FileStreamObject.'})  # fmt: skip
    status: Optional[str] = field(default=None, metadata={"description": "The status of a job."})


@define(eq=False, slots=False)
class AzureLabelClass:
    kind: ClassVar[str] = "azure_label_class"
    mapping: ClassVar[Dict[str, Bender]] = {"display_name": S("displayName"), "subclasses": S("subclasses")}
    display_name: Optional[str] = field(default=None, metadata={"description": "Display name of the label class."})
    subclasses: Optional[Dict[str, Any]] = field(default=None, metadata={'description': 'Dictionary of subclasses of the label class.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureLabelCategory:
    kind: ClassVar[str] = "azure_label_category"
    mapping: ClassVar[Dict[str, Bender]] = {
        "allow_multi_select": S("allowMultiSelect"),
        "classes": S("classes"),
        "display_name": S("displayName"),
    }
    allow_multi_select: Optional[bool] = field(default=None, metadata={'description': 'Indicates whether it is allowed to select multiple classes in this category.'})  # fmt: skip
    classes: Optional[Dict[str, AzureLabelClass]] = field(default=None, metadata={'description': 'Dictionary of label classes in this category.'})  # fmt: skip
    display_name: Optional[str] = field(default=None, metadata={"description": "Display name of the label category."})


@define(eq=False, slots=False)
class AzureLabelingDatasetConfiguration:
    kind: ClassVar[str] = "azure_labeling_dataset_configuration"
    mapping: ClassVar[Dict[str, Bender]] = {
        "asset_name": S("assetName"),
        "dataset_version": S("datasetVersion"),
        "enable_incremental_dataset_refresh": S("enableIncrementalDatasetRefresh"),
    }
    asset_name: Optional[str] = field(default=None, metadata={'description': 'Name of the data asset to perform labeling.'})  # fmt: skip
    dataset_version: Optional[str] = field(default=None, metadata={"description": "AML dataset version."})
    enable_incremental_dataset_refresh: Optional[bool] = field(default=None, metadata={'description': 'Indicates whether to enable incremental dataset refresh.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureComputeBinding:
    kind: ClassVar[str] = "azure_compute_binding"
    mapping: ClassVar[Dict[str, Bender]] = {"compute_id": S("computeId"), "node_count": S("nodeCount")}
    compute_id: Optional[str] = field(default=None, metadata={"description": "ID of the compute resource."})
    node_count: Optional[int] = field(default=None, metadata={"description": "Number of nodes."})


@define(eq=False, slots=False)
class AzureMLAssistConfiguration:
    kind: ClassVar[str] = "azure_ml_assist_configuration"
    mapping: ClassVar[Dict[str, Bender]] = {
        "inferencing_compute_binding": S("inferencingComputeBinding") >> Bend(AzureComputeBinding.mapping),
        "ml_assist_enabled": S("mlAssistEnabled"),
        "model_name_prefix": S("modelNamePrefix"),
        "prelabel_accuracy_threshold": S("prelabelAccuracyThreshold"),
        "training_compute_binding": S("trainingComputeBinding") >> Bend(AzureComputeBinding.mapping),
    }
    inferencing_compute_binding: Optional[AzureComputeBinding] = field(default=None, metadata={'description': 'Compute binding definition.'})  # fmt: skip
    ml_assist_enabled: Optional[bool] = field(default=None, metadata={'description': 'Indicates whether MLAssist feature is enabled.'})  # fmt: skip
    model_name_prefix: Optional[str] = field(default=None, metadata={'description': 'Name prefix to use for machine learning model. For each iteration modelName will be appended with iteration e.g.{modelName}_{i}.'})  # fmt: skip
    prelabel_accuracy_threshold: Optional[float] = field(default=None, metadata={'description': 'Prelabel accuracy threshold used in MLAssist feature.'})  # fmt: skip
    training_compute_binding: Optional[AzureComputeBinding] = field(default=None, metadata={'description': 'Compute binding definition.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureLabelingJobMediaProperties:
    kind: ClassVar[str] = "azure_labeling_job_media_properties"
    mapping: ClassVar[Dict[str, Bender]] = {"media_type": S("mediaType")}
    media_type: Optional[str] = field(default=None, metadata={"description": "Media type of data asset."})


@define(eq=False, slots=False)
class AzureAnnotationType:
    kind: ClassVar[str] = "azure_annotation_type"
    mapping: ClassVar[Dict[str, Bender]] = {"annotation_type": S("annotationType")}
    annotation_type: Optional[str] = field(default=None, metadata={'description': 'Annotation type of image labeling tasks.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureLabelingJobImageProperties(AzureLabelingJobMediaProperties, AzureAnnotationType):
    kind: ClassVar[str] = "azure_labeling_job_image_properties"
    mapping: ClassVar[Dict[str, Bender]] = AzureLabelingJobMediaProperties.mapping | AzureAnnotationType.mapping | {}


@define(eq=False, slots=False)
class AzureProgressMetrics:
    kind: ClassVar[str] = "azure_progress_metrics"
    mapping: ClassVar[Dict[str, Bender]] = {
        "completed_datapoint_count": S("completedDatapointCount"),
        "incremental_dataset_last_refresh_time": S("incrementalDatasetLastRefreshTime"),
        "skipped_datapoint_count": S("skippedDatapointCount"),
        "total_datapoint_count": S("totalDatapointCount"),
    }
    completed_datapoint_count: Optional[int] = field(default=None, metadata={'description': 'The completed datapoint count.'})  # fmt: skip
    incremental_dataset_last_refresh_time: Optional[datetime] = field(default=None, metadata={'description': 'The time of last successful incremental dataset refresh in UTC.'})  # fmt: skip
    skipped_datapoint_count: Optional[int] = field(default=None, metadata={'description': 'The skipped datapoint count.'})  # fmt: skip
    total_datapoint_count: Optional[int] = field(default=None, metadata={"description": "The total datapoint count."})


@define(eq=False, slots=False)
class AzureStatusMessage:
    kind: ClassVar[str] = "azure_status_message"
    mapping: ClassVar[Dict[str, Bender]] = {
        "code": S("code"),
        "created_time_utc": S("createdTimeUtc"),
        "level": S("level"),
        "message": S("message"),
    }
    code: Optional[str] = field(default=None, metadata={"description": "Service-defined message code."})
    created_time_utc: Optional[datetime] = field(default=None, metadata={'description': 'Time in UTC at which the message was created.'})  # fmt: skip
    level: Optional[str] = field(default=None, metadata={"description": "Severity level of the status message."})
    message: Optional[str] = field(default=None, metadata={'description': 'A human-readable representation of the message code.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureMachineLearningLabelingJob(MicrosoftResource):
    kind: ClassVar[str] = "azure_machine_learning_labeling_job"
    api_spec: ClassVar[AzureResourceSpec] = AzureResourceSpec(
        service="machinelearningservices",
        version="2024-04-01-preview",
        path="/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.MachineLearningServices/workspaces/{workspaceName}/labelingJobs",
        path_parameters=["subscriptionId", "resourceGroupName", "workspaceName"],
        query_parameters=["api-version"],
        access_path="value",
        expect_array=True,
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "ctime": K(None),
        "mtime": K(None),
        "atime": K(None),
        "created_time_utc": S("properties", "createdTimeUtc"),
        "dataset_configuration": S("properties", "datasetConfiguration")
        >> Bend(AzureLabelingDatasetConfiguration.mapping),
        "job_instructions": S("properties", "jobInstructions", "uri"),
        "label_categories": S("properties", "labelCategories"),
        "labeling_job_media_properties": S("properties", "labelingJobMediaProperties")
        >> Bend(AzureLabelingJobImageProperties.mapping),
        "ml_assist_configuration": S("properties", "mlAssistConfiguration") >> Bend(AzureMLAssistConfiguration.mapping),
        "progress_metrics": S("properties", "progressMetrics") >> Bend(AzureProgressMetrics.mapping),
        "project_id": S("properties", "projectId"),
        "properties": S("properties", "properties"),
        "status": S("properties", "status"),
        "status_messages": S("properties", "statusMessages") >> ForallBend(AzureStatusMessage.mapping),
        "system_data": S("systemData") >> Bend(AzureSystemData.mapping),
    }
    created_time_utc: Optional[datetime] = field(default=None, metadata={'description': 'Created time of the job in UTC timezone.'})  # fmt: skip
    dataset_configuration: Optional[AzureLabelingDatasetConfiguration] = field(default=None, metadata={'description': 'Represents configuration of dataset used in a labeling job.'})  # fmt: skip
    job_instructions: Optional[str] = field(default=None, metadata={"description": "Instructions for a labeling job."})
    label_categories: Optional[Dict[str, AzureLabelCategory]] = field(default=None, metadata={'description': 'Label categories of the job.'})  # fmt: skip
    labeling_job_media_properties: Optional[AzureLabelingJobImageProperties] = field(default=None, metadata={'description': ''})  # fmt: skip
    ml_assist_configuration: Optional[AzureMLAssistConfiguration] = field(default=None, metadata={'description': 'Represents configuration for machine learning assisted features in a labeling job.'})  # fmt: skip
    progress_metrics: Optional[AzureProgressMetrics] = field(default=None, metadata={'description': 'Progress metrics for a labeling job.'})  # fmt: skip
    project_id: Optional[str] = field(default=None, metadata={'description': 'Internal id of the job(Previously called project).'})  # fmt: skip
    properties: Optional[Dict[str, str]] = field(default=None, metadata={'description': 'The job property dictionary. Properties can be added, but not removed or altered.'})  # fmt: skip
    status: Optional[str] = field(default=None, metadata={"description": "The status of a job."})
    status_messages: Optional[List[AzureStatusMessage]] = field(default=None, metadata={'description': 'Status messages of the job.'})  # fmt: skip
    system_data: Optional[AzureSystemData] = field(default=None, metadata={'description': 'Metadata pertaining to creation and last modification of the resource.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureFlavorData:
    kind: ClassVar[str] = "azure_flavor_data"
    mapping: ClassVar[Dict[str, Bender]] = {"data": S("data")}
    data: Optional[Dict[str, str]] = field(default=None, metadata={"description": "Model flavor-specific data."})


@define(eq=False, slots=False)
class AzureMachineLearningModelVersion(MicrosoftResource, AzureProxyResource):
    kind: ClassVar[str] = "azure_machine_learning_model_version"
    api_spec: ClassVar[AzureResourceSpec] = AzureResourceSpec(
        service="machinelearningservices",
        version="2024-04-01",
        path="/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.MachineLearningServices/workspaces/{workspaceName}/models/{name}/versions",
        path_parameters=["subscriptionId", "resourceGroupName", "workspaceName", "name"],
        query_parameters=["api-version"],
        access_path="value",
        expect_array=True,
    )
    mapping: ClassVar[Dict[str, Bender]] = AzureProxyResource.mapping | {
        "id": K(None),
        "name": K(None),
        "ctime": K(None),
        "mtime": K(None),
        "atime": K(None),
        "flavors": S("properties", "flavors"),
        "job_name": S("properties", "jobName"),
        "model_type": S("properties", "modelType"),
        "model_uri": S("properties", "modelUri"),
        "stage": S("properties", "stage"),
        "tags": S("properties", "tags", default={}),
        "code_uri": S("properties", "codeUri"),
        "provisioning_state": S("properties", "provisioningState"),
        "description": S("properties", "description"),
        "properties": S("properties", "properties"),
        "is_anonymous": S("properties", "isAnonymous"),
        "is_archived": S("properties", "isArchived"),
    }
    description: Optional[str] = field(default=None, metadata={"description": "The asset description text."})
    properties: Optional[Dict[str, str]] = field(default=None, metadata={'description': 'The asset property dictionary.'})  # fmt: skip
    is_anonymous: Optional[bool] = field(default=None, metadata={'description': 'If the name version are system generated (anonymous registration).'})  # fmt: skip
    is_archived: Optional[bool] = field(default=None, metadata={"description": "Is the asset archived?"})
    flavors: Optional[Dict[str, AzureFlavorData]] = field(default=None, metadata={'description': 'Mapping of model flavors to their properties.'})  # fmt: skip
    job_name: Optional[str] = field(default=None, metadata={'description': 'Name of the training job which produced this model'})  # fmt: skip
    model_type: Optional[str] = field(default=None, metadata={'description': 'The storage format for this entity. Used for NCD.'})  # fmt: skip
    model_uri: Optional[str] = field(default=None, metadata={"description": "The URI path to the model contents."})
    provisioning_state: Optional[str] = field(default=None, metadata={'description': 'Provisioning state of registry asset.'})  # fmt: skip
    stage: Optional[str] = field(default=None, metadata={'description': 'Stage in the model lifecycle assigned to this model'})  # fmt: skip


@define(eq=False, slots=False)
class AzureMachineLearningOnlineEndpoint(MicrosoftResource, AzureTrackedResource):
    kind: ClassVar[str] = "azure_machine_learning_online_endpoint"
    api_spec: ClassVar[AzureResourceSpec] = AzureResourceSpec(
        service="machinelearningservices",
        version="2024-04-01",
        path="/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.MachineLearningServices/workspaces/{workspaceName}/onlineEndpoints",
        path_parameters=["subscriptionId", "resourceGroupName", "workspaceName"],
        query_parameters=["api-version"],
        access_path="value",
        expect_array=True,
    )
    mapping: ClassVar[Dict[str, Bender]] = AzureTrackedResource.mapping | {
        "id": K(None),
        "tags": S("tags", default={}),
        "name": K(None),
        "ctime": K(None),
        "mtime": K(None),
        "atime": K(None),
        "compute": S("properties", "compute"),
        "identity": S("identity") >> Bend(AzureManagedServiceIdentity.mapping),
        "azure_kind": S("kind"),
        "mirror_traffic": S("properties", "mirrorTraffic"),
        "provisioning_state": S("properties", "provisioningState"),
        "public_network_access": S("properties", "publicNetworkAccess"),
        "sku": S("sku") >> Bend(AzureSku.mapping),
        "traffic": S("properties", "traffic"),
        "auth_mode": S("properties", "authMode"),
        "description": S("properties", "description"),
        "keys": S("keys") >> Bend(AzureEndpointAuthKeys.mapping),
        "properties": S("properties", "properties"),
        "scoring_uri": S("properties", "scoringUri"),
        "swagger_uri": S("properties", "swaggerUri"),
    }
    compute: Optional[str] = field(default=None, metadata={'description': 'ARM resource ID of the compute if it exists. optional'})  # fmt: skip
    identity: Optional[AzureManagedServiceIdentity] = field(default=None, metadata={'description': 'Managed service identity (system assigned and/or user assigned identities)'})  # fmt: skip
    azure_kind: Optional[str] = field(default=None, metadata={'description': 'Metadata used by portal/tooling/etc to render different UX experiences for resources of the same type.'})  # fmt: skip
    mirror_traffic: Optional[Dict[str, int]] = field(default=None, metadata={'description': 'Percentage of traffic to be mirrored to each deployment without using returned scoring. Traffic values need to sum to utmost 50.'})  # fmt: skip
    provisioning_state: Optional[str] = field(default=None, metadata={'description': 'State of endpoint provisioning.'})  # fmt: skip
    public_network_access: Optional[str] = field(default=None, metadata={'description': 'Enum to determine whether PublicNetworkAccess is Enabled or Disabled.'})  # fmt: skip
    sku: Optional[AzureSku] = field(default=None, metadata={'description': 'The resource model definition representing SKU'})  # fmt: skip
    traffic: Optional[Dict[str, int]] = field(default=None, metadata={'description': 'Percentage of traffic from endpoint to divert to each deployment. Traffic values need to sum to 100.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureMachineLearningPaginatedDataStore(MicrosoftResource):
    kind: ClassVar[str] = "azure_machine_learning_paginated_data_store"
    api_spec: ClassVar[AzureResourceSpec] = AzureResourceSpec(
        service="machinelearningservices",
        version="2019-09-30",
        path="/datastore/v1.0/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.MachineLearningServices/workspaces/{workspaceName}/datastores",
        path_parameters=["subscriptionId", "resourceGroupName", "workspaceName"],
        query_parameters=[],
        access_path=None,
        expect_array=False,
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": K(None),
        "tags": S("tags", default={}),
        "name": K(None),
        "ctime": K(None),
        "mtime": K(None),
        "atime": K(None),
        "continuation_token": S("continuationToken"),
        "next_link": S("nextLink"),
        "value": S("value") >> ForallBend(AzureDataStore.mapping),
    }
    continuation_token: Optional[str] = field(default=None, metadata={'description': 'The token used in retrieving the next page. If null, there are no additional pages.'})  # fmt: skip
    next_link: Optional[str] = field(default=None, metadata={'description': 'The link to the next page constructed using the continuationToken. If null, there are no additional pages.'})  # fmt: skip
    value: Optional[List[AzureDataStore]] = field(default=None, metadata={'description': 'An array of objects of type DataStore.'})  # fmt: skip


@define(eq=False, slots=False)
class AzurePrivateLinkServiceConnectionState:
    kind: ClassVar[str] = "azure_private_link_service_connection_state"
    mapping: ClassVar[Dict[str, Bender]] = {
        "actions_required": S("actionsRequired"),
        "description": S("description"),
        "status": S("status"),
    }
    actions_required: Optional[str] = field(default=None, metadata={'description': 'A message indicating if changes on the service provider require any updates on the consumer.'})  # fmt: skip
    description: Optional[str] = field(default=None, metadata={'description': 'The reason for approval/rejection of the connection.'})  # fmt: skip
    status: Optional[str] = field(default=None, metadata={"description": "The private endpoint connection status."})


@define(eq=False, slots=False)
class AzurePrivateEndpointConnectionProperties:
    kind: ClassVar[str] = "azure_private_endpoint_connection_properties"
    mapping: ClassVar[Dict[str, Bender]] = {
        "private_endpoint": S("privateEndpoint", "id"),
        "private_link_service_connection_state": S("privateLinkServiceConnectionState")
        >> Bend(AzurePrivateLinkServiceConnectionState.mapping),
        "provisioning_state": S("provisioningState"),
    }
    private_endpoint: Optional[str] = field(default=None, metadata={"description": "The Private Endpoint resource."})
    private_link_service_connection_state: Optional[AzurePrivateLinkServiceConnectionState] = field(default=None, metadata={'description': 'A collection of information about the state of the connection between service consumer and provider.'})  # fmt: skip
    provisioning_state: Optional[str] = field(default=None, metadata={'description': 'The current provisioning state.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureMachineLearningPrivateEndpointConnection(MicrosoftResource):
    kind: ClassVar[str] = "azure_machine_learning_private_endpoint_connection"
    api_spec: ClassVar[AzureResourceSpec] = AzureResourceSpec(
        service="machinelearningservices",
        version="2024-04-01",
        path="/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.MachineLearningServices/workspaces/{workspaceName}/privateEndpointConnections",
        path_parameters=["subscriptionId", "resourceGroupName", "workspaceName"],
        query_parameters=["api-version"],
        access_path="value",
        expect_array=True,
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "identity": S("identity") >> Bend(AzureManagedServiceIdentity.mapping),
        "location": S("location"),
        "name": S("name"),
        "private_endpoint": S("properties", "privateEndpoint", "id"),
        "private_link_service_connection_state": S("properties", "privateLinkServiceConnectionState")
        >> Bend(AzurePrivateLinkServiceConnectionState.mapping),
        "provisioning_state": S("properties", "provisioningState"),
        "sku": S("sku") >> Bend(AzureSku.mapping),
        "system_data": S("systemData") >> Bend(AzureSystemData.mapping),
        "tags": S("tags"),
        "type": S("type"),
    }
    identity: Optional[AzureManagedServiceIdentity] = field(default=None, metadata={'description': 'Managed service identity (system assigned and/or user assigned identities)'})  # fmt: skip
    location: Optional[str] = field(default=None, metadata={"description": "Specifies the location of the resource."})
    private_endpoint: Optional[str] = field(default=None, metadata={"description": "The Private Endpoint resource."})
    private_link_service_connection_state: Optional[AzurePrivateLinkServiceConnectionState] = field(default=None, metadata={'description': 'A collection of information about the state of the connection between service consumer and provider.'})  # fmt: skip
    provisioning_state: Optional[str] = field(default=None, metadata={'description': 'The current provisioning state.'})  # fmt: skip
    sku: Optional[AzureSku] = field(default=None, metadata={'description': 'The resource model definition representing SKU'})  # fmt: skip
    system_data: Optional[AzureSystemData] = field(default=None, metadata={'description': 'Metadata pertaining to creation and last modification of the resource.'})  # fmt: skip
    type: Optional[str] = field(default=None, metadata={'description': 'The type of the resource. E.g. Microsoft.Compute/virtualMachines or Microsoft.Storage/storageAccounts '})  # fmt: skip


@define(eq=False, slots=False)
class AzureMachineLearningPrivateLink(MicrosoftResource):
    kind: ClassVar[str] = "azure_machine_learning_private_link"
    api_spec: ClassVar[AzureResourceSpec] = AzureResourceSpec(
        service="machinelearningservices",
        version="2024-04-01",
        path="/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.MachineLearningServices/workspaces/{workspaceName}/privateLinkResources",
        path_parameters=["subscriptionId", "resourceGroupName", "workspaceName"],
        query_parameters=["api-version"],
        access_path="value",
        expect_array=True,
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "ctime": K(None),
        "mtime": K(None),
        "atime": K(None),
        "group_id": S("properties", "groupId"),
        "identity": S("identity") >> Bend(AzureManagedServiceIdentity.mapping),
        "required_members": S("properties", "requiredMembers"),
        "required_zone_names": S("properties", "requiredZoneNames"),
        "sku": S("sku") >> Bend(AzureSku.mapping),
        "system_data": S("systemData") >> Bend(AzureSystemData.mapping),
    }
    group_id: Optional[str] = field(default=None, metadata={"description": "The private link resource group id."})
    identity: Optional[AzureManagedServiceIdentity] = field(default=None, metadata={'description': 'Managed service identity (system assigned and/or user assigned identities)'})  # fmt: skip
    required_members: Optional[List[str]] = field(default=None, metadata={'description': 'The private link resource required member names.'})  # fmt: skip
    required_zone_names: Optional[List[str]] = field(default=None, metadata={'description': 'The private link resource Private link DNS zone name.'})  # fmt: skip
    sku: Optional[AzureSku] = field(default=None, metadata={'description': 'The resource model definition representing SKU'})  # fmt: skip
    system_data: Optional[AzureSystemData] = field(default=None, metadata={'description': 'Metadata pertaining to creation and last modification of the resource.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureRegistryPrivateLinkServiceConnectionState:
    kind: ClassVar[str] = "azure_registry_private_link_service_connection_state"
    mapping: ClassVar[Dict[str, Bender]] = {
        "actions_required": S("actionsRequired"),
        "description": S("description"),
        "status": S("status"),
    }
    actions_required: Optional[str] = field(default=None, metadata={'description': 'Some RP chose None . Other RPs use this for region expansion.'})  # fmt: skip
    description: Optional[str] = field(default=None, metadata={'description': 'User-defined message that, per NRP doc, may be used for approval-related message.'})  # fmt: skip
    status: Optional[str] = field(default=None, metadata={'description': 'Connection status of the service consumer with the service provider'})  # fmt: skip


@define(eq=False, slots=False)
class AzureRegistryPrivateEndpointConnectionProperties:
    kind: ClassVar[str] = "azure_registry_private_endpoint_connection_properties"
    mapping: ClassVar[Dict[str, Bender]] = {
        "group_ids": S("groupIds"),
        "private_endpoint": S("privateEndpoint", "subnetArmId"),
        "provisioning_state": S("provisioningState"),
        "registry_private_link_service_connection_state": S("registryPrivateLinkServiceConnectionState")
        >> Bend(AzureRegistryPrivateLinkServiceConnectionState.mapping),
    }
    group_ids: Optional[List[str]] = field(default=None, metadata={"description": "The group ids"})
    private_endpoint: Optional[str] = field(default=None, metadata={'description': 'The PE network resource that is linked to this PE connection.'})  # fmt: skip
    provisioning_state: Optional[str] = field(default=None, metadata={'description': 'One of null, Succeeded , Provisioning , Failed . While not approved, it s null.'})  # fmt: skip
    registry_private_link_service_connection_state: Optional[AzureRegistryPrivateLinkServiceConnectionState] = field(default=None, metadata={'description': 'The connection state.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureRegistryPrivateEndpointConnection:
    kind: ClassVar[str] = "azure_registry_private_endpoint_connection"
    mapping: ClassVar[Dict[str, Bender]] = {
        "group_ids": S("properties", "groupIds"),
        "id": S("id"),
        "location": S("location"),
        "private_endpoint": S("properties", "privateEndpoint", "subnetArmId"),
        "provisioning_state": S("properties", "provisioningState"),
        "registry_private_link_service_connection_state": S("properties", "registryPrivateLinkServiceConnectionState")
        >> Bend(AzureRegistryPrivateLinkServiceConnectionState.mapping),
    }
    group_ids: Optional[List[str]] = field(default=None, metadata={"description": "The group ids"})
    id: Optional[str] = field(default=None, metadata={'description': 'This is the private endpoint connection name created on SRP Full resource id: /subscriptions/{subId}/resourceGroups/{rgName}/providers/Microsoft.MachineLearningServices/{resourceType}/{resourceName}/registryPrivateEndpointConnections/{peConnectionName}'})  # fmt: skip
    location: Optional[str] = field(default=None, metadata={"description": "Same as workspace location."})
    private_endpoint: Optional[str] = field(default=None, metadata={'description': 'The PE network resource that is linked to this PE connection.'})  # fmt: skip
    provisioning_state: Optional[str] = field(default=None, metadata={'description': 'One of null, Succeeded , Provisioning , Failed . While not approved, it s null.'})  # fmt: skip
    registry_private_link_service_connection_state: Optional[AzureRegistryPrivateLinkServiceConnectionState] = field(default=None, metadata={'description': 'The connection state.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureSystemCreatedAcrAccount:
    kind: ClassVar[str] = "azure_system_created_acr_account"
    mapping: ClassVar[Dict[str, Bender]] = {
        "acr_account_name": S("acrAccountName"),
        "acr_account_sku": S("acrAccountSku"),
        "arm_resource_id": S("armResourceId", "resourceId"),
    }
    acr_account_name: Optional[str] = field(default=None, metadata={"description": "Name of the ACR account"})
    acr_account_sku: Optional[str] = field(default=None, metadata={"description": "SKU of the ACR account"})
    arm_resource_id: Optional[str] = field(default=None, metadata={"description": "ARM ResourceId of a resource"})


@define(eq=False, slots=False)
class AzureUserCreatedAcrAccount:
    kind: ClassVar[str] = "azure_user_created_acr_account"
    mapping: ClassVar[Dict[str, Bender]] = {"arm_resource_id": S("armResourceId", "resourceId")}
    arm_resource_id: Optional[str] = field(default=None, metadata={"description": "ARM ResourceId of a resource"})


@define(eq=False, slots=False)
class AzureAcrDetails:
    kind: ClassVar[str] = "azure_acr_details"
    mapping: ClassVar[Dict[str, Bender]] = {
        "system_created_acr_account": S("systemCreatedAcrAccount") >> Bend(AzureSystemCreatedAcrAccount.mapping),
        "user_created_acr_account": S("userCreatedAcrAccount") >> Bend(AzureUserCreatedAcrAccount.mapping),
    }
    system_created_acr_account: Optional[AzureSystemCreatedAcrAccount] = field(default=None, metadata={'description': ''})  # fmt: skip
    user_created_acr_account: Optional[AzureUserCreatedAcrAccount] = field(default=None, metadata={"description": ""})


@define(eq=False, slots=False)
class AzureSystemCreatedStorageAccount:
    kind: ClassVar[str] = "azure_system_created_storage_account"
    mapping: ClassVar[Dict[str, Bender]] = {
        "allow_blob_public_access": S("allowBlobPublicAccess"),
        "arm_resource_id": S("armResourceId", "resourceId"),
        "storage_account_hns_enabled": S("storageAccountHnsEnabled"),
        "storage_account_name": S("storageAccountName"),
        "storage_account_type": S("storageAccountType"),
    }
    allow_blob_public_access: Optional[bool] = field(default=None, metadata={'description': 'Public blob access allowed'})  # fmt: skip
    arm_resource_id: Optional[str] = field(default=None, metadata={"description": "ARM ResourceId of a resource"})
    storage_account_hns_enabled: Optional[bool] = field(default=None, metadata={'description': 'HNS enabled for storage account'})  # fmt: skip
    storage_account_name: Optional[str] = field(default=None, metadata={"description": "Name of the storage account"})
    storage_account_type: Optional[str] = field(default=None, metadata={'description': 'Allowed values: Standard_LRS , Standard_GRS , Standard_RAGRS , Standard_ZRS , Standard_GZRS , Standard_RAGZRS , Premium_LRS , Premium_ZRS '})  # fmt: skip


@define(eq=False, slots=False)
class AzureUserCreatedStorageAccount:
    kind: ClassVar[str] = "azure_user_created_storage_account"
    mapping: ClassVar[Dict[str, Bender]] = {"arm_resource_id": S("armResourceId", "resourceId")}
    arm_resource_id: Optional[str] = field(default=None, metadata={"description": "ARM ResourceId of a resource"})


@define(eq=False, slots=False)
class AzureStorageAccountDetails:
    kind: ClassVar[str] = "azure_storage_account_details"
    mapping: ClassVar[Dict[str, Bender]] = {
        "system_created_storage_account": S("systemCreatedStorageAccount")
        >> Bend(AzureSystemCreatedStorageAccount.mapping),
        "user_created_storage_account": S("userCreatedStorageAccount") >> Bend(AzureUserCreatedStorageAccount.mapping),
    }
    system_created_storage_account: Optional[AzureSystemCreatedStorageAccount] = field(default=None, metadata={'description': ''})  # fmt: skip
    user_created_storage_account: Optional[AzureUserCreatedStorageAccount] = field(default=None, metadata={'description': ''})  # fmt: skip


@define(eq=False, slots=False)
class AzureRegistryRegionArmDetails:
    kind: ClassVar[str] = "azure_registry_region_arm_details"
    mapping: ClassVar[Dict[str, Bender]] = {
        "acr_details": S("acrDetails") >> ForallBend(AzureAcrDetails.mapping),
        "location": S("location"),
        "storage_account_details": S("storageAccountDetails") >> ForallBend(AzureStorageAccountDetails.mapping),
    }
    acr_details: Optional[List[AzureAcrDetails]] = field(default=None, metadata={"description": "List of ACR accounts"})
    location: Optional[str] = field(default=None, metadata={"description": "The location where the registry exists"})
    storage_account_details: Optional[List[AzureStorageAccountDetails]] = field(default=None, metadata={'description': 'List of storage accounts'})  # fmt: skip


@define(eq=False, slots=False)
class AzureMachineLearningRegistry(MicrosoftResource, AzureTrackedResource):
    kind: ClassVar[str] = "azure_machine_learning_registry"
    api_spec: ClassVar[AzureResourceSpec] = AzureResourceSpec(
        service="machinelearningservices",
        version="2024-04-01",
        path="/subscriptions/{subscriptionId}/providers/Microsoft.MachineLearningServices/registries",
        path_parameters=["subscriptionId"],
        query_parameters=["api-version"],
        access_path="value",
        expect_array=True,
    )
    mapping: ClassVar[Dict[str, Bender]] = AzureTrackedResource.mapping | {
        "id": K(None),
        "tags": S("tags", default={}),
        "name": K(None),
        "ctime": K(None),
        "mtime": K(None),
        "atime": K(None),
        "discovery_url": S("properties", "discoveryUrl"),
        "identity": S("identity") >> Bend(AzureManagedServiceIdentity.mapping),
        "intellectual_property_publisher": S("properties", "intellectualPropertyPublisher"),
        "azure_kind": S("kind"),
        "managed_resource_group": S("properties", "managedResourceGroup", "resourceId"),
        "ml_flow_registry_uri": S("properties", "mlFlowRegistryUri"),
        "public_network_access": S("properties", "publicNetworkAccess"),
        "region_details": S("properties", "regionDetails") >> ForallBend(AzureRegistryRegionArmDetails.mapping),
        "registry_private_endpoint_connections": S("properties", "registryPrivateEndpointConnections")
        >> ForallBend(AzureRegistryPrivateEndpointConnection.mapping),
        "sku": S("sku") >> Bend(AzureSku.mapping),
    }
    discovery_url: Optional[str] = field(default=None, metadata={"description": "Discovery URL for the Registry"})
    identity: Optional[AzureManagedServiceIdentity] = field(default=None, metadata={'description': 'Managed service identity (system assigned and/or user assigned identities)'})  # fmt: skip
    intellectual_property_publisher: Optional[str] = field(default=None, metadata={'description': 'IntellectualPropertyPublisher for the registry'})  # fmt: skip
    azure_kind: Optional[str] = field(default=None, metadata={'description': 'Metadata used by portal/tooling/etc to render different UX experiences for resources of the same type.'})  # fmt: skip
    managed_resource_group: Optional[str] = field(default=None, metadata={'description': 'ARM ResourceId of a resource'})  # fmt: skip
    ml_flow_registry_uri: Optional[str] = field(default=None, metadata={'description': 'MLFlow Registry URI for the Registry'})  # fmt: skip
    public_network_access: Optional[str] = field(default=None, metadata={'description': 'Is the Registry accessible from the internet? Possible values: Enabled or Disabled '})  # fmt: skip
    region_details: Optional[List[AzureRegistryRegionArmDetails]] = field(default=None, metadata={'description': 'Details of each region the registry is in'})  # fmt: skip
    registry_private_endpoint_connections: Optional[List[AzureRegistryPrivateEndpointConnection]] = field(default=None, metadata={'description': 'Private endpoint connections info used for pending connections in private link portal'})  # fmt: skip
    sku: Optional[AzureSku] = field(default=None, metadata={'description': 'The resource model definition representing SKU'})  # fmt: skip


@define(eq=False, slots=False)
class AzureResourceName:
    kind: ClassVar[str] = "azure_resource_name"
    mapping: ClassVar[Dict[str, Bender]] = {"localized_value": S("localizedValue"), "value": S("value")}
    localized_value: Optional[str] = field(default=None, metadata={'description': 'The localized name of the resource.'})  # fmt: skip
    value: Optional[str] = field(default=None, metadata={"description": "The name of the resource."})


@define(eq=False, slots=False)
class AzureMachineLearningQuota(MicrosoftResource):
    kind: ClassVar[str] = "azure_machine_learning_quota"
    api_spec: ClassVar[AzureResourceSpec] = AzureResourceSpec(
        service="machinelearningservices",
        version="2024-04-01",
        path="/subscriptions/{subscriptionId}/providers/Microsoft.MachineLearningServices/locations/{location}/quotas",
        path_parameters=["subscriptionId", "location"],
        query_parameters=["api-version"],
        access_path="value",
        expect_array=True,
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "ctime": K(None),
        "mtime": K(None),
        "atime": K(None),
        "aml_workspace_location": S("amlWorkspaceLocation"),
        "limit": S("limit"),
        "unit": S("unit"),
    }
    aml_workspace_location: Optional[str] = field(default=None, metadata={'description': 'Region of the AML workspace in the id.'})  # fmt: skip
    limit: Optional[int] = field(default=None, metadata={'description': 'The maximum permitted quota of the resource.'})  # fmt: skip
    unit: Optional[str] = field(default=None, metadata={'description': 'An enum describing the unit of quota measurement.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureMachineLearningSchedule(MicrosoftResource, AzureProxyResource):
    kind: ClassVar[str] = "azure_machine_learning_schedule"
    api_spec: ClassVar[AzureResourceSpec] = AzureResourceSpec(
        service="machinelearningservices",
        version="2024-04-01",
        path="/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.MachineLearningServices/workspaces/{workspaceName}/schedules",
        path_parameters=["subscriptionId", "resourceGroupName", "workspaceName"],
        query_parameters=["api-version"],
        access_path="value",
        expect_array=True,
    )
    mapping: ClassVar[Dict[str, Bender]] = AzureProxyResource.mapping | {
        "id": K(None),
        "tags": S("tags", default={}),
        "name": K(None),
        "ctime": K(None),
        "mtime": K(None),
        "atime": K(None),
        "action": S("properties", "action", "actionType"),
        "display_name": S("properties", "displayName"),
        "is_enabled": S("properties", "isEnabled"),
        "provisioning_state": S("properties", "provisioningState"),
        "trigger": S("properties", "trigger") >> Bend(AzureTriggerBase.mapping),
        "description": S("properties", "description"),
        "properties": S("properties", "properties"),
    }
    description: Optional[str] = field(default=None, metadata={"description": "The asset description text."})
    properties: Optional[Dict[str, str]] = field(default=None, metadata={'description': 'The asset property dictionary.'})  # fmt: skip
    action: Optional[str] = field(default=None, metadata={"description": ""})
    display_name: Optional[str] = field(default=None, metadata={"description": "Display name of schedule."})
    is_enabled: Optional[bool] = field(default=None, metadata={"description": "Is the schedule enabled?"})
    provisioning_state: Optional[str] = field(default=None, metadata={"description": ""})
    trigger: Optional[AzureTriggerBase] = field(default=None, metadata={"description": ""})


@define(eq=False, slots=False)
class AzureServerlessInferenceEndpoint:
    kind: ClassVar[str] = "azure_serverless_inference_endpoint"
    mapping: ClassVar[Dict[str, Bender]] = {"headers": S("headers"), "uri": S("uri")}
    headers: Optional[Dict[str, str]] = field(default=None, metadata={'description': 'Specifies any required headers to target this serverless endpoint.'})  # fmt: skip
    uri: Optional[str] = field(default=None, metadata={'description': '[Required] The inference uri to target when making requests against the Serverless Endpoint.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureMachineLearningServerlessEndpoint(MicrosoftResource, AzureTrackedResource):
    kind: ClassVar[str] = "azure_machine_learning_serverless_endpoint"
    api_spec: ClassVar[AzureResourceSpec] = AzureResourceSpec(
        service="machinelearningservices",
        version="2024-04-01",
        path="/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.MachineLearningServices/workspaces/{workspaceName}/serverlessEndpoints",
        path_parameters=["subscriptionId", "resourceGroupName", "workspaceName"],
        query_parameters=["api-version"],
        access_path="value",
        expect_array=True,
    )
    mapping: ClassVar[Dict[str, Bender]] = AzureTrackedResource.mapping | {
        "id": K(None),
        "tags": S("tags", default={}),
        "name": K(None),
        "ctime": K(None),
        "mtime": K(None),
        "atime": K(None),
        "auth_mode": S("properties", "authMode"),
        "content_safety": S("properties", "contentSafety", "contentSafetyStatus"),
        "endpoint_state": S("properties", "endpointState"),
        "identity": S("identity") >> Bend(AzureManagedServiceIdentity.mapping),
        "inference_endpoint": S("properties", "inferenceEndpoint") >> Bend(AzureServerlessInferenceEndpoint.mapping),
        "azure_kind": S("kind"),
        "marketplace_subscription_id": S("properties", "marketplaceSubscriptionId"),
        "model_settings": S("properties", "modelSettings", "modelId"),
        "provisioning_state": S("properties", "provisioningState"),
        "sku": S("sku") >> Bend(AzureSku.mapping),
    }
    auth_mode: Optional[str] = field(default=None, metadata={"description": ""})
    content_safety: Optional[str] = field(default=None, metadata={"description": ""})
    endpoint_state: Optional[str] = field(default=None, metadata={"description": "State of the Serverless Endpoint."})
    identity: Optional[AzureManagedServiceIdentity] = field(default=None, metadata={'description': 'Managed service identity (system assigned and/or user assigned identities)'})  # fmt: skip
    inference_endpoint: Optional[AzureServerlessInferenceEndpoint] = field(default=None, metadata={"description": ""})
    azure_kind: Optional[str] = field(default=None, metadata={'description': 'Metadata used by portal/tooling/etc to render different UX experiences for resources of the same type.'})  # fmt: skip
    marketplace_subscription_id: Optional[str] = field(default=None, metadata={'description': 'The MarketplaceSubscription Azure ID associated to this ServerlessEndpoint.'})  # fmt: skip
    model_settings: Optional[str] = field(default=None, metadata={"description": ""})
    provisioning_state: Optional[str] = field(default=None, metadata={'description': 'State of endpoint provisioning.'})  # fmt: skip
    sku: Optional[AzureSku] = field(default=None, metadata={'description': 'The resource model definition representing SKU'})  # fmt: skip


@define(eq=False, slots=False)
class AzureUsageName:
    kind: ClassVar[str] = "azure_usage_name"
    mapping: ClassVar[Dict[str, Bender]] = {"localized_value": S("localizedValue"), "value": S("value")}
    localized_value: Optional[str] = field(default=None, metadata={'description': 'The localized name of the resource.'})  # fmt: skip
    value: Optional[str] = field(default=None, metadata={"description": "The name of the resource."})


@define(eq=False, slots=False)
class AzureMachineLearningUsage(MicrosoftResource, AzureBaseUsage):
    kind: ClassVar[str] = "azure_machine_learning_usage"
    api_spec: ClassVar[AzureResourceSpec] = AzureResourceSpec(
        service="machinelearningservices",
        version="2024-04-01",
        path="/subscriptions/{subscriptionId}/providers/Microsoft.MachineLearningServices/locations/{location}/usages",
        path_parameters=["subscriptionId", "location"],
        query_parameters=["api-version"],
        access_path="value",
        expect_array=True,
        expected_error_codes=AzureBaseUsage._expected_error_codes,
    )
    mapping: ClassVar[Dict[str, Bender]] = AzureBaseUsage.mapping | {
        "id": S("id"),
        "name": S("name", "value"),
        "aml_workspace_location": S("amlWorkspaceLocation"),
    }
    aml_workspace_location: Optional[str] = field(default=None, metadata={'description': 'Region of the AML workspace in the id.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureEstimatedVMPrice:
    kind: ClassVar[str] = "azure_estimated_vm_price"
    mapping: ClassVar[Dict[str, Bender]] = {
        "os_type": S("osType"),
        "retail_price": S("retailPrice"),
        "vm_tier": S("vmTier"),
    }
    os_type: Optional[str] = field(default=None, metadata={"description": "Operating system type used by the VM."})
    retail_price: Optional[float] = field(default=None, metadata={'description': 'The price charged for using the VM.'})  # fmt: skip
    vm_tier: Optional[str] = field(default=None, metadata={"description": "The type of the VM."})


@define(eq=False, slots=False)
class AzureEstimatedVMPrices:
    kind: ClassVar[str] = "azure_estimated_vm_prices"
    mapping: ClassVar[Dict[str, Bender]] = {
        "billing_currency": S("billingCurrency"),
        "unit_of_measure": S("unitOfMeasure"),
        "values": S("values") >> ForallBend(AzureEstimatedVMPrice.mapping),
    }
    billing_currency: Optional[str] = field(default=None, metadata={'description': 'Three lettered code specifying the currency of the VM price. Example: USD'})  # fmt: skip
    unit_of_measure: Optional[str] = field(default=None, metadata={'description': 'The unit of time measurement for the specified VM price. Example: OneHour'})  # fmt: skip
    values: Optional[List[AzureEstimatedVMPrice]] = field(default=None, metadata={'description': 'The list of estimated prices for using a VM of a particular OS type, tier, etc.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureMachineLearningVirtualMachineSize(MicrosoftResource):
    kind: ClassVar[str] = "azure_machine_learning_virtual_machine_size"
    api_spec: ClassVar[AzureResourceSpec] = AzureResourceSpec(
        service="machinelearningservices",
        version="2024-04-01",
        path="/subscriptions/{subscriptionId}/providers/Microsoft.MachineLearningServices/locations/{location}/vmSizes",
        path_parameters=["location", "subscriptionId"],
        query_parameters=["api-version"],
        access_path="value",
        expect_array=True,
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": K(None),
        "tags": S("tags", default={}),
        "name": S("name"),
        "ctime": K(None),
        "mtime": K(None),
        "atime": K(None),
        "estimated_vm_prices": S("estimatedVMPrices") >> Bend(AzureEstimatedVMPrices.mapping),
        "family": S("family"),
        "gpus": S("gpus"),
        "low_priority_capable": S("lowPriorityCapable"),
        "max_resource_volume_mb": S("maxResourceVolumeMB"),
        "memory_gb": S("memoryGB"),
        "os_vhd_size_mb": S("osVhdSizeMB"),
        "premium_io": S("premiumIO"),
        "supported_compute_types": S("supportedComputeTypes"),
        "v_cp_us": S("vCPUs"),
    }
    estimated_vm_prices: Optional[AzureEstimatedVMPrices] = field(default=None, metadata={'description': 'The estimated price info for using a VM.'})  # fmt: skip
    family: Optional[str] = field(default=None, metadata={'description': 'The family name of the virtual machine size.'})  # fmt: skip
    gpus: Optional[int] = field(default=None, metadata={'description': 'The number of gPUs supported by the virtual machine size.'})  # fmt: skip
    low_priority_capable: Optional[bool] = field(default=None, metadata={'description': 'Specifies if the virtual machine size supports low priority VMs.'})  # fmt: skip
    max_resource_volume_mb: Optional[int] = field(default=None, metadata={'description': 'The resource volume size, in MB, allowed by the virtual machine size.'})  # fmt: skip
    memory_gb: Optional[float] = field(default=None, metadata={'description': 'The amount of memory, in GB, supported by the virtual machine size.'})  # fmt: skip
    os_vhd_size_mb: Optional[int] = field(default=None, metadata={'description': 'The OS VHD disk size, in MB, allowed by the virtual machine size.'})  # fmt: skip
    premium_io: Optional[bool] = field(default=None, metadata={'description': 'Specifies if the virtual machine size supports premium IO.'})  # fmt: skip
    supported_compute_types: Optional[List[str]] = field(default=None, metadata={'description': 'Specifies the compute types supported by the virtual machine size.'})  # fmt: skip
    v_cp_us: Optional[int] = field(default=None, metadata={'description': 'The number of vCPUs supported by the virtual machine size.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureEncryptionKeyVaultProperties:
    kind: ClassVar[str] = "azure_encryption_key_vault_properties"
    mapping: ClassVar[Dict[str, Bender]] = {
        "identity_client_id": S("identityClientId"),
        "key_identifier": S("keyIdentifier"),
        "key_vault_arm_id": S("keyVaultArmId"),
    }
    identity_client_id: Optional[str] = field(default=None, metadata={'description': 'For future use - The client id of the identity which will be used to access key vault.'})  # fmt: skip
    key_identifier: Optional[str] = field(default=None, metadata={'description': 'Key vault uri to access the encryption key.'})  # fmt: skip
    key_vault_arm_id: Optional[str] = field(default=None, metadata={'description': 'The ArmId of the keyVault where the customer owned encryption key is present.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureEncryptionProperty:
    kind: ClassVar[str] = "azure_encryption_property"
    mapping: ClassVar[Dict[str, Bender]] = {
        "identity": S("identity", "userAssignedIdentity"),
        "key_vault_properties": S("keyVaultProperties") >> Bend(AzureEncryptionKeyVaultProperties.mapping),
        "status": S("status"),
    }
    identity: Optional[str] = field(default=None, metadata={'description': 'Identity that will be used to access key vault for encryption at rest'})  # fmt: skip
    key_vault_properties: Optional[AzureEncryptionKeyVaultProperties] = field(default=None, metadata={'description': ''})  # fmt: skip
    status: Optional[str] = field(default=None, metadata={'description': 'Indicates whether or not the encryption is enabled for the workspace.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureServerlessComputeSettings:
    kind: ClassVar[str] = "azure_serverless_compute_settings"
    mapping: ClassVar[Dict[str, Bender]] = {
        "serverless_compute_custom_subnet": S("serverlessComputeCustomSubnet"),
        "serverless_compute_no_public_ip": S("serverlessComputeNoPublicIP"),
    }
    serverless_compute_custom_subnet: Optional[str] = field(default=None, metadata={'description': 'The resource ID of an existing virtual network subnet in which serverless compute nodes should be deployed'})  # fmt: skip
    serverless_compute_no_public_ip: Optional[bool] = field(default=None, metadata={'description': 'The flag to signal if serverless compute nodes deployed in custom vNet would have no public IP addresses for a workspace with private endpoint'})  # fmt: skip


@define(eq=False, slots=False)
class AzureSharedPrivateLinkResourceProperty:
    kind: ClassVar[str] = "azure_shared_private_link_resource_property"
    mapping: ClassVar[Dict[str, Bender]] = {
        "group_id": S("groupId"),
        "private_link_resource_id": S("privateLinkResourceId"),
        "request_message": S("requestMessage"),
        "status": S("status"),
    }
    group_id: Optional[str] = field(default=None, metadata={"description": "The private link resource group id."})
    private_link_resource_id: Optional[str] = field(default=None, metadata={'description': 'The resource id that private link links to.'})  # fmt: skip
    request_message: Optional[str] = field(default=None, metadata={"description": "Request message."})
    status: Optional[str] = field(default=None, metadata={"description": "The private endpoint connection status."})


@define(eq=False, slots=False)
class AzureSharedPrivateLinkResource:
    kind: ClassVar[str] = "azure_shared_private_link_resource"
    mapping: ClassVar[Dict[str, Bender]] = {
        "group_id": S("properties", "groupId"),
        "name": S("name"),
        "private_link_resource_id": S("properties", "privateLinkResourceId"),
        "request_message": S("properties", "requestMessage"),
        "status": S("properties", "status"),
    }
    group_id: Optional[str] = field(default=None, metadata={"description": "The private link resource group id."})
    name: Optional[str] = field(default=None, metadata={"description": "Unique name of the private link."})
    private_link_resource_id: Optional[str] = field(default=None, metadata={'description': 'The resource id that private link links to.'})  # fmt: skip
    request_message: Optional[str] = field(default=None, metadata={"description": "Request message."})
    status: Optional[str] = field(default=None, metadata={"description": "The private endpoint connection status."})


@define(eq=False, slots=False)
class AzureNotebookPreparationError:
    kind: ClassVar[str] = "azure_notebook_preparation_error"
    mapping: ClassVar[Dict[str, Bender]] = {"error_message": S("errorMessage"), "status_code": S("statusCode")}
    error_message: Optional[str] = field(default=None, metadata={"description": ""})
    status_code: Optional[int] = field(default=None, metadata={"description": ""})


@define(eq=False, slots=False)
class AzureNotebookResourceInfo:
    kind: ClassVar[str] = "azure_notebook_resource_info"
    mapping: ClassVar[Dict[str, Bender]] = {
        "fqdn": S("fqdn"),
        "notebook_preparation_error": S("notebookPreparationError") >> Bend(AzureNotebookPreparationError.mapping),
        "resource_id": S("resourceId"),
    }
    fqdn: Optional[str] = field(default=None, metadata={"description": ""})
    notebook_preparation_error: Optional[AzureNotebookPreparationError] = field(default=None, metadata={'description': ''})  # fmt: skip
    resource_id: Optional[str] = field(default=None, metadata={'description': 'the data plane resourceId that used to initialize notebook component'})  # fmt: skip


@define(eq=False, slots=False)
class AzureServiceManagedResourcesSettings:
    kind: ClassVar[str] = "azure_service_managed_resources_settings"
    mapping: ClassVar[Dict[str, Bender]] = {"cosmos_db": S("cosmosDb", "collectionsThroughput")}
    cosmos_db: Optional[int] = field(default=None, metadata={"description": ""})


@define(eq=False, slots=False)
class AzureManagedNetworkProvisionStatus:
    kind: ClassVar[str] = "azure_managed_network_provision_status"
    mapping: ClassVar[Dict[str, Bender]] = {"spark_ready": S("sparkReady"), "status": S("status")}
    spark_ready: Optional[bool] = field(default=None, metadata={"description": ""})
    status: Optional[str] = field(default=None, metadata={'description': 'Status for the managed network of a machine learning workspace.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureOutboundRule:
    kind: ClassVar[str] = "azure_outbound_rule"
    mapping: ClassVar[Dict[str, Bender]] = {"category": S("category"), "status": S("status"), "type": S("type")}
    category: Optional[str] = field(default=None, metadata={'description': 'Category of a managed network Outbound Rule of a machine learning workspace.'})  # fmt: skip
    status: Optional[str] = field(default=None, metadata={'description': 'Type of a managed network Outbound Rule of a machine learning workspace.'})  # fmt: skip
    type: Optional[str] = field(default=None, metadata={'description': 'Type of a managed network Outbound Rule of a machine learning workspace.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureManagedNetworkSettings:
    kind: ClassVar[str] = "azure_managed_network_settings"
    mapping: ClassVar[Dict[str, Bender]] = {
        "isolation_mode": S("isolationMode"),
        "network_id": S("networkId"),
        "outbound_rules": S("outboundRules"),
        "status": S("status") >> Bend(AzureManagedNetworkProvisionStatus.mapping),
    }
    isolation_mode: Optional[str] = field(default=None, metadata={'description': 'Isolation mode for the managed network of a machine learning workspace.'})  # fmt: skip
    network_id: Optional[str] = field(default=None, metadata={"description": ""})
    outbound_rules: Optional[Dict[str, AzureOutboundRule]] = field(default=None, metadata={"description": ""})
    status: Optional[AzureManagedNetworkProvisionStatus] = field(default=None, metadata={'description': 'Status of the Provisioning for the managed network of a machine learning workspace.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureFeatureStoreSettings:
    kind: ClassVar[str] = "azure_feature_store_settings"
    mapping: ClassVar[Dict[str, Bender]] = {
        "compute_runtime": S("computeRuntime", "sparkRuntimeVersion"),
        "offline_store_connection_name": S("offlineStoreConnectionName"),
        "online_store_connection_name": S("onlineStoreConnectionName"),
    }
    compute_runtime: Optional[str] = field(default=None, metadata={'description': 'Compute runtime config for feature store type workspace.'})  # fmt: skip
    offline_store_connection_name: Optional[str] = field(default=None, metadata={"description": ""})
    online_store_connection_name: Optional[str] = field(default=None, metadata={"description": ""})


@define(eq=False, slots=False)
class AzureWorkspaceHubConfig:
    kind: ClassVar[str] = "azure_workspace_hub_config"
    mapping: ClassVar[Dict[str, Bender]] = {
        "additional_workspace_storage_accounts": S("additionalWorkspaceStorageAccounts"),
        "default_workspace_resource_group": S("defaultWorkspaceResourceGroup"),
    }
    additional_workspace_storage_accounts: Optional[List[str]] = field(default=None, metadata={"description": ""})
    default_workspace_resource_group: Optional[str] = field(default=None, metadata={"description": ""})


@define(eq=False, slots=False)
class AzureMachineLearningWorkspace(MicrosoftResource):
    kind: ClassVar[str] = "azure_machine_learning_workspace"
    api_spec: ClassVar[AzureResourceSpec] = AzureResourceSpec(
        service="machinelearningservices",
        version="2024-04-01",
        path="/subscriptions/{subscriptionId}/providers/Microsoft.MachineLearningServices/workspaces",
        path_parameters=["subscriptionId"],
        query_parameters=["api-version"],
        access_path="value",
        expect_array=True,
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "ctime": K(None),
        "mtime": K(None),
        "atime": K(None),
        "allow_public_access_when_behind_vnet": S("properties", "allowPublicAccessWhenBehindVnet"),
        "application_insights": S("properties", "applicationInsights"),
        "associated_workspaces": S("properties", "associatedWorkspaces"),
        "container_registry": S("properties", "containerRegistry"),
        "description": S("properties", "description"),
        "discovery_url": S("properties", "discoveryUrl"),
        "enable_data_isolation": S("properties", "enableDataIsolation"),
        "encryption": S("properties", "encryption") >> Bend(AzureEncryptionProperty.mapping),
        "feature_store_settings": S("properties", "featureStoreSettings") >> Bend(AzureFeatureStoreSettings.mapping),
        "friendly_name": S("properties", "friendlyName"),
        "hbi_workspace": S("properties", "hbiWorkspace"),
        "hub_resource_id": S("properties", "hubResourceId"),
        "identity": S("identity") >> Bend(AzureManagedServiceIdentity.mapping),
        "image_build_compute": S("properties", "imageBuildCompute"),
        "key_vault": S("properties", "keyVault"),
        "azure_kind": S("kind"),
        "managed_network": S("properties", "managedNetwork") >> Bend(AzureManagedNetworkSettings.mapping),
        "ml_flow_tracking_uri": S("properties", "mlFlowTrackingUri"),
        "notebook_info": S("properties", "notebookInfo") >> Bend(AzureNotebookResourceInfo.mapping),
        "primary_user_assigned_identity": S("properties", "primaryUserAssignedIdentity"),
        "private_endpoint_connections": S("properties", "privateEndpointConnections") >> ForallBend(S("id")),
        "private_link_count": S("properties", "privateLinkCount"),
        "provisioning_state": S("properties", "provisioningState"),
        "public_network_access": S("properties", "publicNetworkAccess"),
        "serverless_compute_settings": S("properties", "serverlessComputeSettings")
        >> Bend(AzureServerlessComputeSettings.mapping),
        "service_managed_resources_settings": S("properties", "serviceManagedResourcesSettings")
        >> Bend(AzureServiceManagedResourcesSettings.mapping),
        "service_provisioned_resource_group": S("properties", "serviceProvisionedResourceGroup"),
        "shared_private_link_resources": S("properties", "sharedPrivateLinkResources")
        >> ForallBend(AzureSharedPrivateLinkResource.mapping),
        "sku": S("sku") >> Bend(AzureSku.mapping),
        "storage_account": S("properties", "storageAccount"),
        "storage_hns_enabled": S("properties", "storageHnsEnabled"),
        "system_data": S("systemData") >> Bend(AzureSystemData.mapping),
        "tenant_id": S("properties", "tenantId"),
        "v1_legacy_mode": S("properties", "v1LegacyMode"),
        "workspace_hub_config": S("properties", "workspaceHubConfig") >> Bend(AzureWorkspaceHubConfig.mapping),
        "workspace_id": S("properties", "workspaceId"),
    }
    allow_public_access_when_behind_vnet: Optional[bool] = field(default=None, metadata={'description': 'The flag to indicate whether to allow public access when behind VNet.'})  # fmt: skip
    application_insights: Optional[str] = field(default=None, metadata={'description': 'ARM id of the application insights associated with this workspace.'})  # fmt: skip
    associated_workspaces: Optional[List[str]] = field(default=None, metadata={"description": ""})
    container_registry: Optional[str] = field(default=None, metadata={'description': 'ARM id of the container registry associated with this workspace.'})  # fmt: skip
    description: Optional[str] = field(default=None, metadata={"description": "The description of this workspace."})
    discovery_url: Optional[str] = field(default=None, metadata={'description': 'Url for the discovery service to identify regional endpoints for machine learning experimentation services'})  # fmt: skip
    enable_data_isolation: Optional[bool] = field(default=None, metadata={"description": ""})
    encryption: Optional[AzureEncryptionProperty] = field(default=None, metadata={"description": ""})
    feature_store_settings: Optional[AzureFeatureStoreSettings] = field(default=None, metadata={'description': 'Settings for feature store type workspace.'})  # fmt: skip
    friendly_name: Optional[str] = field(default=None, metadata={'description': 'The friendly name for this workspace. This name in mutable'})  # fmt: skip
    hbi_workspace: Optional[bool] = field(default=None, metadata={'description': 'The flag to signal HBI data in the workspace and reduce diagnostic data collected by the service'})  # fmt: skip
    hub_resource_id: Optional[str] = field(default=None, metadata={"description": ""})
    identity: Optional[AzureManagedServiceIdentity] = field(default=None, metadata={'description': 'Managed service identity (system assigned and/or user assigned identities)'})  # fmt: skip
    image_build_compute: Optional[str] = field(default=None, metadata={'description': 'The compute name for image build'})  # fmt: skip
    key_vault: Optional[str] = field(default=None, metadata={'description': 'ARM id of the key vault associated with this workspace. This cannot be changed once the workspace has been created'})  # fmt: skip
    azure_kind: Optional[str] = field(default=None, metadata={"description": ""})
    managed_network: Optional[AzureManagedNetworkSettings] = field(default=None, metadata={'description': 'Managed Network settings for a machine learning workspace.'})  # fmt: skip
    ml_flow_tracking_uri: Optional[str] = field(default=None, metadata={'description': 'The URI associated with this workspace that machine learning flow must point at to set up tracking.'})  # fmt: skip
    notebook_info: Optional[AzureNotebookResourceInfo] = field(default=None, metadata={"description": ""})
    primary_user_assigned_identity: Optional[str] = field(default=None, metadata={'description': 'The user assigned identity resource id that represents the workspace identity.'})  # fmt: skip
    private_endpoint_connections: Optional[List[str]] = field(default=None, metadata={'description': 'The list of private endpoint connections in the workspace.'})  # fmt: skip
    private_link_count: Optional[int] = field(default=None, metadata={'description': 'Count of private connections in the workspace'})  # fmt: skip
    provisioning_state: Optional[str] = field(default=None, metadata={'description': 'The current deployment state of workspace resource. The provisioningState is to indicate states for resource provisioning.'})  # fmt: skip
    public_network_access: Optional[str] = field(default=None, metadata={'description': 'Whether requests from Public Network are allowed.'})  # fmt: skip
    serverless_compute_settings: Optional[AzureServerlessComputeSettings] = field(default=None, metadata={'description': ''})  # fmt: skip
    service_managed_resources_settings: Optional[AzureServiceManagedResourcesSettings] = field(default=None, metadata={'description': ''})  # fmt: skip
    service_provisioned_resource_group: Optional[str] = field(default=None, metadata={'description': 'The name of the managed resource group created by workspace RP in customer subscription if the workspace is CMK workspace'})  # fmt: skip
    shared_private_link_resources: Optional[List[AzureSharedPrivateLinkResource]] = field(default=None, metadata={'description': 'The list of shared private link resources in this workspace.'})  # fmt: skip
    sku: Optional[AzureSku] = field(default=None, metadata={'description': 'The resource model definition representing SKU'})  # fmt: skip
    storage_account: Optional[str] = field(default=None, metadata={'description': 'ARM id of the storage account associated with this workspace. This cannot be changed once the workspace has been created'})  # fmt: skip
    storage_hns_enabled: Optional[bool] = field(default=None, metadata={'description': 'If the storage associated with the workspace has hierarchical namespace(HNS) enabled.'})  # fmt: skip
    system_data: Optional[AzureSystemData] = field(default=None, metadata={'description': 'Metadata pertaining to creation and last modification of the resource.'})  # fmt: skip
    tenant_id: Optional[str] = field(default=None, metadata={'description': 'The tenant id associated with this workspace.'})  # fmt: skip
    v1_legacy_mode: Optional[bool] = field(default=None, metadata={'description': 'Enabling v1_legacy_mode may prevent you from using features provided by the v2 API.'})  # fmt: skip
    workspace_hub_config: Optional[AzureWorkspaceHubConfig] = field(default=None, metadata={'description': 'WorkspaceHub s configuration object.'})  # fmt: skip
    workspace_id: Optional[str] = field(default=None, metadata={'description': 'The immutable id associated with this workspace.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureMachineLearningWorkspaceConnection(MicrosoftResource):
    kind: ClassVar[str] = "azure_machine_learning_workspace_connection"
    api_spec: ClassVar[AzureResourceSpec] = AzureResourceSpec(
        service="machinelearningservices",
        version="2024-04-01",
        path="/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.MachineLearningServices/workspaces/{workspaceName}/connections",
        path_parameters=["subscriptionId", "resourceGroupName", "workspaceName"],
        query_parameters=["api-version"],
        access_path="value",
        expect_array=True,
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "ctime": K(None),
        "mtime": K(None),
        "atime": K(None),
        "auth_type": S("properties", "authType"),
        "category": S("properties", "category"),
        "created_by_workspace_arm_id": S("properties", "createdByWorkspaceArmId"),
        "expiry_time": S("properties", "expiryTime"),
        "group": S("properties", "group"),
        "is_shared_to_all": S("properties", "isSharedToAll"),
        "workspace_connection_metadata": S("properties", "metadata"),
        "shared_user_list": S("properties", "sharedUserList"),
        "system_data": S("systemData") >> Bend(AzureSystemData.mapping),
        "target": S("properties", "target"),
        "value": S("properties", "value"),
        "value_format": S("properties", "valueFormat"),
    }
    auth_type: Optional[str] = field(default=None, metadata={'description': 'Authentication type of the connection target'})  # fmt: skip
    category: Optional[str] = field(default=None, metadata={"description": "Category of the connection"})
    created_by_workspace_arm_id: Optional[str] = field(default=None, metadata={"description": ""})
    expiry_time: Optional[datetime] = field(default=None, metadata={"description": ""})
    group: Optional[str] = field(default=None, metadata={"description": "Group based on connection category"})
    is_shared_to_all: Optional[bool] = field(default=None, metadata={"description": ""})
    workspace_connection_metadata: Optional[Dict[str, str]] = field(default=None, metadata={'description': 'Store user metadata for this connection'})  # fmt: skip
    shared_user_list: Optional[List[str]] = field(default=None, metadata={"description": ""})
    system_data: Optional[AzureSystemData] = field(default=None, metadata={'description': 'Metadata pertaining to creation and last modification of the resource.'})  # fmt: skip
    target: Optional[str] = field(default=None, metadata={"description": ""})
    value: Optional[str] = field(default=None, metadata={"description": "Value details of the workspace connection."})
    value_format: Optional[str] = field(default=None, metadata={'description': 'format for the workspace connection value'})  # fmt: skip


resources: List[Type[MicrosoftResource]] = [
    AzureMachineLearningBatchEndpoint,
    AzureMachineLearningCodeVersion,
    AzureMachineLearningComponentVersion,
    AzureMachineLearningCompute,
    AzureMachineLearningDataVersion,
    AzureMachineLearningDatastore,
    AzureMachineLearningEndpoint,
    AzureMachineLearningEnvironmentVersion,
    AzureMachineLearningFeaturesetVersion,
    AzureMachineLearningFeaturestoreEntityVersion,
    AzureMachineLearningJob,
    AzureMachineLearningLabelingJob,
    AzureMachineLearningModelVersion,
    AzureMachineLearningOnlineEndpoint,
    AzureMachineLearningPaginatedDataStore,
    AzureMachineLearningPrivateEndpointConnection,
    AzureMachineLearningPrivateLink,
    AzureMachineLearningRegistry,
    AzureMachineLearningQuota,
    AzureMachineLearningSchedule,
    AzureMachineLearningServerlessEndpoint,
    AzureMachineLearningUsage,
    AzureMachineLearningVirtualMachineSize,
    AzureMachineLearningWorkspace,
    AzureMachineLearningWorkspaceConnection,
]
