from datetime import datetime
from typing import Any, ClassVar, Optional, Dict, List, Type
from attr import define, field
from fix_plugin_azure.azure_client import AzureApiSpec
from fix_plugin_azure.resource.base import AzureBaseUsage, AzureResource, GraphBuilder

from fixlib.baseresources import EdgeType, ModelReference
from fixlib.json_bender import Bender, S, ForallBend, Bend
from fixlib.types import Json

service_name = "azure_storage"


@define(eq=False, slots=False)
class AzureUpdateHistoryProperty:
    kind: ClassVar[str] = "azure_update_history_property"
    mapping: ClassVar[Dict[str, Bender]] = {
        "allow_protected_append_writes": S("allowProtectedAppendWrites"),
        "allow_protected_append_writes_all": S("allowProtectedAppendWritesAll"),
        "immutability_period_since_creation_in_days": S("immutabilityPeriodSinceCreationInDays"),
        "object_identifier": S("objectIdentifier"),
        "tenant_id": S("tenantId"),
        "timestamp": S("timestamp"),
        "update": S("update"),
        "upn": S("upn"),
    }
    allow_protected_append_writes: Optional[bool] = field(default=None, metadata={'description': 'This property can only be changed for unlocked time-based retention policies. When enabled, new blocks can be written to an append blob while maintaining immutability protection and compliance. Only new blocks can be added and any existing blocks cannot be modified or deleted. This property cannot be changed with ExtendImmutabilityPolicy API.'})  # fmt: skip
    allow_protected_append_writes_all: Optional[bool] = field(default=None, metadata={'description': 'This property can only be changed for unlocked time-based retention policies. When enabled, new blocks can be written to both Append and Bock Blobs while maintaining immutability protection and compliance. Only new blocks can be added and any existing blocks cannot be modified or deleted. This property cannot be changed with ExtendImmutabilityPolicy API. The allowProtectedAppendWrites and allowProtectedAppendWritesAll properties are mutually exclusive.'})  # fmt: skip
    immutability_period_since_creation_in_days: Optional[int] = field(default=None, metadata={'description': 'The immutability period for the blobs in the container since the policy creation, in days.'})  # fmt: skip
    object_identifier: Optional[str] = field(default=None, metadata={'description': 'Returns the Object ID of the user who updated the ImmutabilityPolicy.'})  # fmt: skip
    tenant_id: Optional[str] = field(default=None, metadata={'description': 'Returns the Tenant ID that issued the token for the user who updated the ImmutabilityPolicy.'})  # fmt: skip
    timestamp: Optional[datetime] = field(default=None, metadata={'description': 'Returns the date and time the ImmutabilityPolicy was updated.'})  # fmt: skip
    update: Optional[str] = field(default=None, metadata={'description': 'The ImmutabilityPolicy update type of a blob container, possible values include: put, lock and extend.'})  # fmt: skip
    upn: Optional[str] = field(default=None, metadata={'description': 'Returns the User Principal Name of the user who updated the ImmutabilityPolicy.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureImmutabilityPolicyProperties:
    kind: ClassVar[str] = "azure_immutability_policy_properties"
    mapping: ClassVar[Dict[str, Bender]] = {
        "allow_protected_append_writes": S("properties", "allowProtectedAppendWrites"),
        "allow_protected_append_writes_all": S("properties", "allowProtectedAppendWritesAll"),
        "etag": S("etag"),
        "immutability_period_since_creation_in_days": S("properties", "immutabilityPeriodSinceCreationInDays"),
        "state": S("properties", "state"),
        "update_history": S("updateHistory") >> ForallBend(AzureUpdateHistoryProperty.mapping),
    }
    allow_protected_append_writes: Optional[bool] = field(default=None, metadata={'description': 'This property can only be changed for unlocked time-based retention policies. When enabled, new blocks can be written to an append blob while maintaining immutability protection and compliance. Only new blocks can be added and any existing blocks cannot be modified or deleted. This property cannot be changed with ExtendImmutabilityPolicy API.'})  # fmt: skip
    allow_protected_append_writes_all: Optional[bool] = field(default=None, metadata={'description': 'This property can only be changed for unlocked time-based retention policies. When enabled, new blocks can be written to both Append and Bock Blobs while maintaining immutability protection and compliance. Only new blocks can be added and any existing blocks cannot be modified or deleted. This property cannot be changed with ExtendImmutabilityPolicy API. The allowProtectedAppendWrites and allowProtectedAppendWritesAll properties are mutually exclusive.'})  # fmt: skip
    etag: Optional[str] = field(default=None, metadata={"description": "ImmutabilityPolicy Etag."})
    immutability_period_since_creation_in_days: Optional[int] = field(default=None, metadata={'description': 'The immutability period for the blobs in the container since the policy creation, in days.'})  # fmt: skip
    state: Optional[str] = field(default=None, metadata={'description': 'The ImmutabilityPolicy state of a blob container, possible values include: Locked and Unlocked.'})  # fmt: skip
    update_history: Optional[List[AzureUpdateHistoryProperty]] = field(default=None, metadata={'description': 'The ImmutabilityPolicy update history of the blob container.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureTagProperty:
    kind: ClassVar[str] = "azure_tag_property"
    mapping: ClassVar[Dict[str, Bender]] = {
        "object_identifier": S("objectIdentifier"),
        "tag": S("tag"),
        "tenant_id": S("tenantId"),
        "timestamp": S("timestamp"),
        "upn": S("upn"),
    }
    object_identifier: Optional[str] = field(default=None, metadata={'description': 'Returns the Object ID of the user who added the tag.'})  # fmt: skip
    tag: Optional[str] = field(default=None, metadata={"description": "The tag value."})
    tenant_id: Optional[str] = field(default=None, metadata={'description': 'Returns the Tenant ID that issued the token for the user who added the tag.'})  # fmt: skip
    timestamp: Optional[datetime] = field(default=None, metadata={'description': 'Returns the date and time the tag was added.'})  # fmt: skip
    upn: Optional[str] = field(default=None, metadata={'description': 'Returns the User Principal Name of the user who added the tag.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureProtectedAppendWritesHistory:
    kind: ClassVar[str] = "azure_protected_append_writes_history"
    mapping: ClassVar[Dict[str, Bender]] = {
        "allow_protected_append_writes_all": S("allowProtectedAppendWritesAll"),
        "timestamp": S("timestamp"),
    }
    allow_protected_append_writes_all: Optional[bool] = field(default=None, metadata={'description': 'When enabled, new blocks can be written to both Append and Bock Blobs while maintaining legal hold protection and compliance. Only new blocks can be added and any existing blocks cannot be modified or deleted.'})  # fmt: skip
    timestamp: Optional[datetime] = field(default=None, metadata={'description': 'Returns the date and time the tag was added.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureLegalHoldProperties:
    kind: ClassVar[str] = "azure_legal_hold_properties"
    mapping: ClassVar[Dict[str, Bender]] = {
        "has_legal_hold": S("hasLegalHold"),
        "protected_append_writes_history": S("protectedAppendWritesHistory")
        >> Bend(AzureProtectedAppendWritesHistory.mapping),
        "tags": S("tags") >> ForallBend(AzureTagProperty.mapping),
    }
    has_legal_hold: Optional[bool] = field(default=None, metadata={'description': 'The hasLegalHold public property is set to true by SRP if there are at least one existing tag. The hasLegalHold public property is set to false by SRP if all existing legal hold tags are cleared out. There can be a maximum of 1000 blob containers with hasLegalHold=true for a given account.'})  # fmt: skip
    protected_append_writes_history: Optional[AzureProtectedAppendWritesHistory] = field(default=None, metadata={'description': 'Protected append writes history setting for the blob container with Legal holds.'})  # fmt: skip
    tags: Optional[List[AzureTagProperty]] = field(default=None, metadata={'description': 'The list of LegalHold tags of a blob container.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureImmutableStorageWithVersioning:
    kind: ClassVar[str] = "azure_immutable_storage_with_versioning"
    mapping: ClassVar[Dict[str, Bender]] = {
        "enabled": S("enabled"),
        "migration_state": S("migrationState"),
        "time_stamp": S("timeStamp"),
    }
    enabled: Optional[bool] = field(default=None, metadata={'description': 'This is an immutable property, when set to true it enables object level immutability at the container level.'})  # fmt: skip
    migration_state: Optional[str] = field(default=None, metadata={'description': 'This property denotes the container level immutability to object level immutability migration state.'})  # fmt: skip
    time_stamp: Optional[datetime] = field(default=None, metadata={'description': 'Returns the date and time the object level immutability was enabled.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureBlobContainer(AzureResource):
    kind: ClassVar[str] = "azure_blob_container"
    # api_spec: ClassVar[AzureApiSpec] = AzureApiSpec(
    #     service="storage",
    #     version="2023-01-01",
    #     path="/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Storage/storageAccounts/{accountName}/blobServices/default/containers/{containerName}",
    #     path_parameters=["resourceGroupName", "accountName", "containerName", "subscriptionId"],
    #     query_parameters=["api-version"],
    #     access_path=None,
    #     expect_array=False,
    # )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "tags": S("tags", default={}),
        "etag": S("etag"),
        "name": S("name"),
        "mtime": S("properties", "lastModifiedTime"),
        "default_encryption_scope": S("properties", "defaultEncryptionScope"),
        "deleted": S("properties", "deleted"),
        "deleted_time": S("properties", "deletedTime"),
        "deny_encryption_scope_override": S("properties", "denyEncryptionScopeOverride"),
        "enable_nfs_v3_all_squash": S("properties", "enableNfsV3AllSquash"),
        "enable_nfs_v3_root_squash": S("properties", "enableNfsV3RootSquash"),
        "has_immutability_policy": S("properties", "hasImmutabilityPolicy"),
        "has_legal_hold": S("properties", "hasLegalHold"),
        "immutability_policy": S("properties", "immutabilityPolicy") >> Bend(AzureImmutabilityPolicyProperties.mapping),
        "blob_immutable_storage_with_versioning": S("properties", "immutableStorageWithVersioning")
        >> Bend(AzureImmutableStorageWithVersioning.mapping),
        "last_modified_time": S("properties", "lastModifiedTime"),
        "lease_duration": S("properties", "leaseDuration"),
        "lease_state": S("properties", "leaseState"),
        "lease_status": S("properties", "leaseStatus"),
        "legal_hold": S("properties", "legalHold") >> Bend(AzureLegalHoldProperties.mapping),
        "blob_metadata": S("properties", "metadata"),
        "public_access": S("properties", "publicAccess"),
        "remaining_retention_days": S("properties", "remainingRetentionDays"),
        "version": S("properties", "version"),
    }
    etag: Optional[str] = field(default=None, metadata={"description": "Resource Etag."})
    name: Optional[str] = field(default=None, metadata={"description": "The name of the resource"})
    type: Optional[str] = field(default=None, metadata={'description': 'The type of the resource. E.g. Microsoft.Compute/virtualMachines or Microsoft.Storage/storageAccounts '})  # fmt: skip
    default_encryption_scope: Optional[str] = field(default=None, metadata={'description': 'Default the container to use specified encryption scope for all writes.'})  # fmt: skip
    deleted: Optional[bool] = field(default=None, metadata={'description': 'Indicates whether the blob container was deleted.'})  # fmt: skip
    deleted_time: Optional[datetime] = field(default=None, metadata={"description": "Blob container deletion time."})
    deny_encryption_scope_override: Optional[bool] = field(default=None, metadata={'description': 'Block override of encryption scope from the container default.'})  # fmt: skip
    enable_nfs_v3_all_squash: Optional[bool] = field(default=None, metadata={'description': 'Enable NFSv3 all squash on blob container.'})  # fmt: skip
    enable_nfs_v3_root_squash: Optional[bool] = field(default=None, metadata={'description': 'Enable NFSv3 root squash on blob container.'})  # fmt: skip
    has_immutability_policy: Optional[bool] = field(default=None, metadata={'description': 'The hasImmutabilityPolicy public property is set to true by SRP if ImmutabilityPolicy has been created for this container. The hasImmutabilityPolicy public property is set to false by SRP if ImmutabilityPolicy has not been created for this container.'})  # fmt: skip
    has_legal_hold: Optional[bool] = field(default=None, metadata={'description': 'The hasLegalHold public property is set to true by SRP if there are at least one existing tag. The hasLegalHold public property is set to false by SRP if all existing legal hold tags are cleared out. There can be a maximum of 1000 blob containers with hasLegalHold=true for a given account.'})  # fmt: skip
    immutability_policy: Optional[AzureImmutabilityPolicyProperties] = field(default=None, metadata={'description': 'The properties of an ImmutabilityPolicy of a blob container.'})  # fmt: skip
    blob_immutable_storage_with_versioning: Optional[AzureImmutableStorageWithVersioning] = field(default=None, metadata={'description': 'Object level immutability properties of the container.'})  # fmt: skip
    last_modified_time: Optional[datetime] = field(default=None, metadata={'description': 'Returns the date and time the container was last modified.'})  # fmt: skip
    lease_duration: Optional[str] = field(default=None, metadata={'description': 'Specifies whether the lease on a container is of infinite or fixed duration, only when the container is leased.'})  # fmt: skip
    lease_state: Optional[str] = field(default=None, metadata={"description": "Lease state of the container."})
    lease_status: Optional[str] = field(default=None, metadata={"description": "The lease status of the container."})
    legal_hold: Optional[AzureLegalHoldProperties] = field(default=None, metadata={'description': 'The LegalHold property of a blob container.'})  # fmt: skip
    blob_metadata: Optional[Dict[str, str]] = field(default=None, metadata={'description': 'A name-value pair to associate with the container as metadata.'})  # fmt: skip
    public_access: Optional[str] = field(default=None, metadata={'description': 'Specifies whether data in the container may be accessed publicly and the level of access.'})  # fmt: skip
    remaining_retention_days: Optional[int] = field(default=None, metadata={'description': 'Remaining retention days for soft deleted blob container.'})  # fmt: skip
    version: Optional[str] = field(default=None, metadata={'description': 'The version of the deleted blob container.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureDeletedAccount(AzureResource):
    kind: ClassVar[str] = "azure_deleted_account"
    api_spec: ClassVar[AzureApiSpec] = AzureApiSpec(
        service="storage",
        version="2023-01-01",
        path="/subscriptions/{subscriptionId}/providers/Microsoft.Storage/deletedAccounts",
        path_parameters=["subscriptionId"],
        query_parameters=["api-version"],
        access_path="value",
        expect_array=True,
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "type": S("type"),
        "ctime": S("creationTime"),
        "atime": S("deletionTime"),
        "creation_time": S("properties", "creationTime"),
        "deletion_time": S("properties", "deletionTime"),
        "restore_reference": S("properties", "restoreReference"),
        "storage_account_resource_id": S("properties", "storageAccountResourceId"),
    }
    name: Optional[str] = field(default=None, metadata={"description": "The name of the resource"})
    type: Optional[str] = field(default=None, metadata={'description': 'The type of the resource. E.g. Microsoft.Compute/virtualMachines or Microsoft.Storage/storageAccounts '})  # fmt: skip
    creation_time: Optional[datetime] = field(default=None, metadata={'description': 'Creation time of the deleted account.'})  # fmt: skip
    deletion_time: Optional[datetime] = field(default=None, metadata={'description': 'Deletion time of the deleted account.'})  # fmt: skip
    restore_reference: Optional[str] = field(default=None, metadata={'description': 'Can be used to attempt recovering this deleted account via PutStorageAccount API.'})  # fmt: skip
    storage_account_resource_id: Optional[str] = field(default=None, metadata={'description': 'Full resource id of the original storage account.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureProviderResourceOperationDescription:
    kind: ClassVar[str] = "azure_provider_resource_operation_description"
    mapping: ClassVar[Dict[str, Bender]] = {
        "description": S("description"),
        "operation": S("operation"),
        "provider": S("provider"),
        "resource": S("resource"),
    }
    description: Optional[str] = field(default=None, metadata={"description": "Description of the operation."})
    operation: Optional[str] = field(default=None, metadata={'description': 'Type of operation: get, read, delete, etc.'})  # fmt: skip
    provider: Optional[str] = field(default=None, metadata={"description": "Service provider: Microsoft Storage."})
    resource: Optional[str] = field(default=None, metadata={'description': 'Resource on which the operation is performed etc.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureDimension:
    kind: ClassVar[str] = "azure_dimension"
    mapping: ClassVar[Dict[str, Bender]] = {"display_name": S("displayName"), "name": S("name")}
    display_name: Optional[str] = field(default=None, metadata={"description": "Display name of dimension."})
    name: Optional[str] = field(default=None, metadata={"description": "Display name of dimension."})


@define(eq=False, slots=False)
class AzureMetricSpecification:
    kind: ClassVar[str] = "azure_metric_specification"
    mapping: ClassVar[Dict[str, Bender]] = {
        "aggregation_type": S("aggregationType"),
        "category": S("category"),
        "dimensions": S("dimensions") >> ForallBend(AzureDimension.mapping),
        "display_description": S("displayDescription"),
        "display_name": S("displayName"),
        "fill_gap_with_zero": S("fillGapWithZero"),
        "name": S("name"),
        "resource_id_dimension_name_override": S("resourceIdDimensionNameOverride"),
        "unit": S("unit"),
    }
    aggregation_type: Optional[str] = field(default=None, metadata={'description': 'Aggregation type could be Average.'})  # fmt: skip
    category: Optional[str] = field(default=None, metadata={'description': 'The category this metric specification belong to, could be Capacity.'})  # fmt: skip
    dimensions: Optional[List[AzureDimension]] = field(default=None, metadata={'description': 'Dimensions of blobs, including blob type and access tier.'})  # fmt: skip
    display_description: Optional[str] = field(default=None, metadata={'description': 'Display description of metric specification.'})  # fmt: skip
    display_name: Optional[str] = field(default=None, metadata={'description': 'Display name of metric specification.'})  # fmt: skip
    fill_gap_with_zero: Optional[bool] = field(default=None, metadata={'description': 'The property to decide fill gap with zero or not.'})  # fmt: skip
    name: Optional[str] = field(default=None, metadata={"description": "Name of metric specification."})
    resource_id_dimension_name_override: Optional[str] = field(default=None, metadata={'description': 'Account Resource Id.'})  # fmt: skip
    unit: Optional[str] = field(default=None, metadata={"description": "Unit could be Bytes or Count."})


@define(eq=False, slots=False)
class AzureServiceSpecification:
    kind: ClassVar[str] = "azure_service_specification"
    mapping: ClassVar[Dict[str, Bender]] = {
        "metric_specifications": S("metricSpecifications") >> ForallBend(AzureMetricSpecification.mapping)
    }
    metric_specifications: Optional[List[AzureMetricSpecification]] = field(default=None, metadata={'description': 'Metric specifications of operation.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureSKUCapability:
    kind: ClassVar[str] = "azure_sku_capability"
    mapping: ClassVar[Dict[str, Bender]] = {"name": S("name"), "value": S("value")}
    name: Optional[str] = field(default=None, metadata={'description': 'The name of capability, The capability information in the specified SKU, including file encryption, network ACLs, change notification, etc.'})  # fmt: skip
    value: Optional[str] = field(default=None, metadata={'description': 'A string value to indicate states of given capability. Possibly true or false .'})  # fmt: skip


@define(eq=False, slots=False)
class AzureRestriction:
    kind: ClassVar[str] = "azure_restriction"
    mapping: ClassVar[Dict[str, Bender]] = {"reason_code": S("reasonCode"), "type": S("type"), "values": S("values")}
    reason_code: Optional[str] = field(default=None, metadata={'description': 'The reason for the restriction. As of now this can be QuotaId or NotAvailableForSubscription . Quota Id is set when the SKU has requiredQuotas parameter as the subscription does not belong to that quota. The NotAvailableForSubscription is related to capacity at DC.'})  # fmt: skip
    type: Optional[str] = field(default=None, metadata={'description': 'The type of restrictions. As of now only possible value for this is location.'})  # fmt: skip
    values: Optional[List[str]] = field(default=None, metadata={'description': 'The value of restrictions. If the restriction type is set to location. This would be different locations where the SKU is restricted.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureStorageSku(AzureResource):
    kind: ClassVar[str] = "azure_storage_sku"
    api_spec: ClassVar[AzureApiSpec] = AzureApiSpec(
        service="storage",
        version="2023-01-01",
        path="/subscriptions/{subscriptionId}/providers/Microsoft.Storage/skus",
        path_parameters=["subscriptionId"],
        query_parameters=["api-version"],
        access_path="value",
        expect_array=True,
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("name"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "sku_capabilities": S("capabilities") >> ForallBend(AzureSKUCapability.mapping),
        "resource_kind": S("kind"),
        "locations": S("locations"),
        "resource_type": S("resourceType"),
        "sku_restrictions": S("restrictions") >> ForallBend(AzureRestriction.mapping),
        "tier": S("tier"),
    }
    sku_capabilities: Optional[List[AzureSKUCapability]] = field(default=None, metadata={'description': 'The capability information in the specified SKU, including file encryption, network ACLs, change notification, etc.'})  # fmt: skip
    resource_kind: Optional[str] = field(
        default=None, metadata={"description": "Indicates the type of storage account."}
    )
    locations: Optional[List[str]] = field(default=None, metadata={'description': 'The set of locations that the SKU is available. This will be supported and registered Azure Geo Regions (e.g. West US, East US, Southeast Asia, etc.).'})  # fmt: skip
    resource_type: Optional[str] = field(default=None, metadata={'description': 'The type of the resource, usually it is storageAccounts .'})  # fmt: skip
    sku_restrictions: Optional[List[AzureRestriction]] = field(default=None, metadata={'description': 'The restrictions because of which SKU cannot be used. This is empty if there are no restrictions.'})  # fmt: skip
    tier: Optional[str] = field(default=None, metadata={"description": "The SKU tier. This is based on the SKU name."})

    def post_process(self, graph_builder: GraphBuilder, source: Json) -> None:
        # Encapsulating each location from the list for future connection to the storage account
        if locations := self.locations:
            for location in locations:
                # Dynamically setting a property for each location
                setattr(self, f"_{location}_location", location)


@define(eq=False, slots=False)
class AzureSku:
    kind: ClassVar[str] = "azure_sku"
    mapping: ClassVar[Dict[str, Bender]] = {"name": S("name"), "tier": S("tier")}
    name: Optional[str] = field(default=None, metadata={'description': 'The SKU name. Required for account creation; optional for update. Note that in older versions, SKU name was called accountType.'})  # fmt: skip
    tier: Optional[str] = field(default=None, metadata={"description": "The SKU tier. This is based on the SKU name."})


@define(eq=False, slots=False)
class AzureUserAssignedIdentity:
    kind: ClassVar[str] = "azure_user_assigned_identity"
    mapping: ClassVar[Dict[str, Bender]] = {"client_id": S("clientId"), "principal_id": S("principalId")}
    client_id: Optional[str] = field(default=None, metadata={"description": "The client ID of the identity."})
    principal_id: Optional[str] = field(default=None, metadata={"description": "The principal ID of the identity."})


@define(eq=False, slots=False)
class AzureIdentity:
    kind: ClassVar[str] = "azure_identity"
    mapping: ClassVar[Dict[str, Bender]] = {
        "principal_id": S("principalId"),
        "tenant_id": S("tenantId"),
        "type": S("type"),
        "user_assigned_identities": S("userAssignedIdentities"),
    }
    principal_id: Optional[str] = field(default=None, metadata={'description': 'The principal ID of resource identity.'})  # fmt: skip
    tenant_id: Optional[str] = field(default=None, metadata={"description": "The tenant ID of resource."})
    type: Optional[str] = field(default=None, metadata={"description": "The identity type."})
    user_assigned_identities: Optional[Dict[str, AzureUserAssignedIdentity]] = field(default=None, metadata={'description': 'Gets or sets a list of key value pairs that describe the set of User Assigned identities that will be used with this storage account. The key is the ARM resource identifier of the identity. Only 1 User Assigned identity is permitted here.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureExtendedLocation:
    kind: ClassVar[str] = "azure_extended_location"
    mapping: ClassVar[Dict[str, Bender]] = {"name": S("name"), "type": S("type")}
    name: Optional[str] = field(default=None, metadata={"description": "The name of the extended location."})
    type: Optional[str] = field(default=None, metadata={"description": "The type of extendedLocation."})


@define(eq=False, slots=False)
class AzureStorageAccountMicrosoftEndpoints:
    kind: ClassVar[str] = "azure_storage_account_microsoft_endpoints"
    mapping: ClassVar[Dict[str, Bender]] = {
        "blob": S("blob"),
        "dfs": S("dfs"),
        "file": S("file"),
        "queue": S("queue"),
        "table": S("table"),
        "web": S("web"),
    }
    blob: Optional[str] = field(default=None, metadata={"description": "Gets the blob endpoint."})
    dfs: Optional[str] = field(default=None, metadata={"description": "Gets the dfs endpoint."})
    file: Optional[str] = field(default=None, metadata={"description": "Gets the file endpoint."})
    queue: Optional[str] = field(default=None, metadata={"description": "Gets the queue endpoint."})
    table: Optional[str] = field(default=None, metadata={"description": "Gets the table endpoint."})
    web: Optional[str] = field(default=None, metadata={"description": "Gets the web endpoint."})


@define(eq=False, slots=False)
class AzureStorageAccountInternetEndpoints:
    kind: ClassVar[str] = "azure_storage_account_internet_endpoints"
    mapping: ClassVar[Dict[str, Bender]] = {"blob": S("blob"), "dfs": S("dfs"), "file": S("file"), "web": S("web")}
    blob: Optional[str] = field(default=None, metadata={"description": "Gets the blob endpoint."})
    dfs: Optional[str] = field(default=None, metadata={"description": "Gets the dfs endpoint."})
    file: Optional[str] = field(default=None, metadata={"description": "Gets the file endpoint."})
    web: Optional[str] = field(default=None, metadata={"description": "Gets the web endpoint."})


@define(eq=False, slots=False)
class AzureEndpoints:
    kind: ClassVar[str] = "azure_endpoints"
    mapping: ClassVar[Dict[str, Bender]] = {
        "blob": S("blob"),
        "dfs": S("dfs"),
        "file": S("file"),
        "internet_endpoints": S("internetEndpoints") >> Bend(AzureStorageAccountInternetEndpoints.mapping),
        "microsoft_endpoints": S("microsoftEndpoints") >> Bend(AzureStorageAccountMicrosoftEndpoints.mapping),
        "queue": S("queue"),
        "table": S("table"),
        "web": S("web"),
    }
    blob: Optional[str] = field(default=None, metadata={"description": "Gets the blob endpoint."})
    dfs: Optional[str] = field(default=None, metadata={"description": "Gets the dfs endpoint."})
    file: Optional[str] = field(default=None, metadata={"description": "Gets the file endpoint."})
    internet_endpoints: Optional[AzureStorageAccountInternetEndpoints] = field(default=None, metadata={'description': 'The URIs that are used to perform a retrieval of a public blob, file, web or dfs object via a internet routing endpoint.'})  # fmt: skip
    microsoft_endpoints: Optional[AzureStorageAccountMicrosoftEndpoints] = field(default=None, metadata={'description': 'The URIs that are used to perform a retrieval of a public blob, queue, table, web or dfs object via a microsoft routing endpoint.'})  # fmt: skip
    queue: Optional[str] = field(default=None, metadata={"description": "Gets the queue endpoint."})
    table: Optional[str] = field(default=None, metadata={"description": "Gets the table endpoint."})
    web: Optional[str] = field(default=None, metadata={"description": "Gets the web endpoint."})


@define(eq=False, slots=False)
class AzureCustomDomain:
    kind: ClassVar[str] = "azure_custom_domain"
    mapping: ClassVar[Dict[str, Bender]] = {"name": S("name"), "use_sub_domain_name": S("useSubDomainName")}
    name: Optional[str] = field(default=None, metadata={'description': 'Gets or sets the custom domain name assigned to the storage account. Name is the CNAME source.'})  # fmt: skip
    use_sub_domain_name: Optional[bool] = field(default=None, metadata={'description': 'Indicates whether indirect CName validation is enabled. Default value is false. This should only be set on updates.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureSasPolicy:
    kind: ClassVar[str] = "azure_sas_policy"
    mapping: ClassVar[Dict[str, Bender]] = {
        "expiration_action": S("expirationAction"),
        "sas_expiration_period": S("sasExpirationPeriod"),
    }
    expiration_action: Optional[str] = field(default=None, metadata={'description': 'The SAS expiration action. Can only be Log.'})  # fmt: skip
    sas_expiration_period: Optional[str] = field(default=None, metadata={'description': 'The SAS expiration period, DD.HH:MM:SS.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureKeyCreationTime:
    kind: ClassVar[str] = "azure_key_creation_time"
    mapping: ClassVar[Dict[str, Bender]] = {"key1": S("key1"), "key2": S("key2")}
    key1: Optional[datetime] = field(default=None, metadata={"description": ""})
    key2: Optional[datetime] = field(default=None, metadata={"description": ""})


@define(eq=False, slots=False)
class AzureEncryptionService:
    kind: ClassVar[str] = "azure_encryption_service"
    mapping: ClassVar[Dict[str, Bender]] = {
        "enabled": S("enabled"),
        "key_type": S("keyType"),
        "last_enabled_time": S("lastEnabledTime"),
    }
    enabled: Optional[bool] = field(default=None, metadata={'description': 'A boolean indicating whether or not the service encrypts the data as it is stored. Encryption at rest is enabled by default today and cannot be disabled.'})  # fmt: skip
    key_type: Optional[str] = field(default=None, metadata={'description': 'Encryption key type to be used for the encryption service. Account key type implies that an account-scoped encryption key will be used. Service key type implies that a default service key is used.'})  # fmt: skip
    last_enabled_time: Optional[datetime] = field(default=None, metadata={'description': 'Gets a rough estimate of the date/time when the encryption was last enabled by the user. Data is encrypted at rest by default today and cannot be disabled.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureEncryptionServices:
    kind: ClassVar[str] = "azure_encryption_services"
    mapping: ClassVar[Dict[str, Bender]] = {
        "blob": S("blob") >> Bend(AzureEncryptionService.mapping),
        "file": S("file") >> Bend(AzureEncryptionService.mapping),
        "queue": S("queue") >> Bend(AzureEncryptionService.mapping),
        "table": S("table") >> Bend(AzureEncryptionService.mapping),
    }
    blob: Optional[AzureEncryptionService] = field(default=None, metadata={'description': 'A service that allows server-side encryption to be used.'})  # fmt: skip
    file: Optional[AzureEncryptionService] = field(default=None, metadata={'description': 'A service that allows server-side encryption to be used.'})  # fmt: skip
    queue: Optional[AzureEncryptionService] = field(default=None, metadata={'description': 'A service that allows server-side encryption to be used.'})  # fmt: skip
    table: Optional[AzureEncryptionService] = field(default=None, metadata={'description': 'A service that allows server-side encryption to be used.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureKeyVaultProperties:
    kind: ClassVar[str] = "azure_key_vault_properties"
    mapping: ClassVar[Dict[str, Bender]] = {
        "current_versioned_key_expiration_timestamp": S("currentVersionedKeyExpirationTimestamp"),
        "current_versioned_key_identifier": S("currentVersionedKeyIdentifier"),
        "keyname": S("keyname"),
        "keyvaulturi": S("keyvaulturi"),
        "keyversion": S("keyversion"),
        "last_key_rotation_timestamp": S("lastKeyRotationTimestamp"),
    }
    current_versioned_key_expiration_timestamp: Optional[datetime] = field(default=None, metadata={'description': 'This is a read only property that represents the expiration time of the current version of the customer managed key used for encryption.'})  # fmt: skip
    current_versioned_key_identifier: Optional[str] = field(default=None, metadata={'description': 'The object identifier of the current versioned Key Vault Key in use.'})  # fmt: skip
    keyname: Optional[str] = field(default=None, metadata={"description": "The name of KeyVault key."})
    keyvaulturi: Optional[str] = field(default=None, metadata={"description": "The Uri of KeyVault."})
    keyversion: Optional[str] = field(default=None, metadata={"description": "The version of KeyVault key."})
    last_key_rotation_timestamp: Optional[datetime] = field(default=None, metadata={'description': 'Timestamp of last rotation of the Key Vault Key.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureEncryptionIdentity:
    kind: ClassVar[str] = "azure_encryption_identity"
    mapping: ClassVar[Dict[str, Bender]] = {
        "federated_identity_client_id": S("federatedIdentityClientId"),
        "user_assigned_identity": S("userAssignedIdentity"),
    }
    federated_identity_client_id: Optional[str] = field(default=None, metadata={'description': 'ClientId of the multi-tenant application to be used in conjunction with the user-assigned identity for cross-tenant customer-managed-keys server-side encryption on the storage account.'})  # fmt: skip
    user_assigned_identity: Optional[str] = field(default=None, metadata={'description': 'Resource identifier of the UserAssigned identity to be associated with server-side encryption on the storage account.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureStorageEncryption:
    kind: ClassVar[str] = "azure_storage_encryption"
    mapping: ClassVar[Dict[str, Bender]] = {
        "identity": S("identity") >> Bend(AzureEncryptionIdentity.mapping),
        "key_source": S("keySource"),
        "keyvaultproperties": S("keyvaultproperties") >> Bend(AzureKeyVaultProperties.mapping),
        "require_infrastructure_encryption": S("requireInfrastructureEncryption"),
        "services": S("services") >> Bend(AzureEncryptionServices.mapping),
    }
    identity: Optional[AzureEncryptionIdentity] = field(default=None, metadata={'description': 'Encryption identity for the storage account.'})  # fmt: skip
    key_source: Optional[str] = field(default=None, metadata={'description': 'The encryption keySource (provider). Possible values (case-insensitive): Microsoft.Storage, Microsoft.Keyvault'})  # fmt: skip
    keyvaultproperties: Optional[AzureKeyVaultProperties] = field(default=None, metadata={'description': 'Properties of key vault.'})  # fmt: skip
    require_infrastructure_encryption: Optional[bool] = field(default=None, metadata={'description': 'A boolean indicating whether or not the service applies a secondary layer of encryption with platform managed keys for data at rest.'})  # fmt: skip
    services: Optional[AzureEncryptionServices] = field(default=None, metadata={'description': 'A list of services that support encryption.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureActiveDirectoryProperties:
    kind: ClassVar[str] = "azure_active_directory_properties"
    mapping: ClassVar[Dict[str, Bender]] = {
        "account_type": S("accountType"),
        "azure_storage_sid": S("azureStorageSid"),
        "domain_guid": S("domainGuid"),
        "domain_name": S("domainName"),
        "domain_sid": S("domainSid"),
        "forest_name": S("forestName"),
        "net_bios_domain_name": S("netBiosDomainName"),
        "sam_account_name": S("samAccountName"),
    }
    account_type: Optional[str] = field(default=None, metadata={'description': 'Specifies the Active Directory account type for Azure Storage.'})  # fmt: skip
    azure_storage_sid: Optional[str] = field(default=None, metadata={'description': 'Specifies the security identifier (SID) for Azure Storage.'})  # fmt: skip
    domain_guid: Optional[str] = field(default=None, metadata={"description": "Specifies the domain GUID."})
    domain_name: Optional[str] = field(default=None, metadata={'description': 'Specifies the primary domain that the AD DNS server is authoritative for.'})  # fmt: skip
    domain_sid: Optional[str] = field(default=None, metadata={'description': 'Specifies the security identifier (SID).'})  # fmt: skip
    forest_name: Optional[str] = field(default=None, metadata={'description': 'Specifies the Active Directory forest to get.'})  # fmt: skip
    net_bios_domain_name: Optional[str] = field(default=None, metadata={'description': 'Specifies the NetBIOS domain name.'})  # fmt: skip
    sam_account_name: Optional[str] = field(default=None, metadata={'description': 'Specifies the Active Directory SAMAccountName for Azure Storage.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureAzureFilesIdentityBasedAuthentication:
    kind: ClassVar[str] = "azure_azure_files_identity_based_authentication"
    mapping: ClassVar[Dict[str, Bender]] = {
        "active_directory_properties": S("activeDirectoryProperties") >> Bend(AzureActiveDirectoryProperties.mapping),
        "default_share_permission": S("defaultSharePermission"),
        "directory_service_options": S("directoryServiceOptions"),
    }
    active_directory_properties: Optional[AzureActiveDirectoryProperties] = field(default=None, metadata={'description': 'Settings properties for Active Directory (AD).'})  # fmt: skip
    default_share_permission: Optional[str] = field(default=None, metadata={'description': 'Default share permission for users using Kerberos authentication if RBAC role is not assigned.'})  # fmt: skip
    directory_service_options: Optional[str] = field(default=None, metadata={'description': 'Indicates the directory service used. Note that this enum may be extended in the future.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureResourceAccessRule:
    kind: ClassVar[str] = "azure_resource_access_rule"
    mapping: ClassVar[Dict[str, Bender]] = {"resource_id": S("resourceId"), "tenant_id": S("tenantId")}
    resource_id: Optional[str] = field(default=None, metadata={"description": "Resource Id"})
    tenant_id: Optional[str] = field(default=None, metadata={"description": "Tenant Id"})


@define(eq=False, slots=False)
class AzureVirtualNetworkRule:
    kind: ClassVar[str] = "azure_virtual_network_rule"
    mapping: ClassVar[Dict[str, Bender]] = {"action": S("action"), "id": S("id"), "state": S("state")}
    action: Optional[str] = field(default=None, metadata={"description": "The action of virtual network rule."})
    id: Optional[str] = field(default=None, metadata={'description': 'Resource ID of a subnet, for example: /subscriptions/{subscriptionId}/resourceGroups/{groupName}/providers/Microsoft.Network/virtualNetworks/{vnetName}/subnets/{subnetName}.'})  # fmt: skip
    state: Optional[str] = field(default=None, metadata={"description": "Gets the state of virtual network rule."})


@define(eq=False, slots=False)
class AzureIPRule:
    kind: ClassVar[str] = "azure_ip_rule"
    mapping: ClassVar[Dict[str, Bender]] = {"action": S("action"), "value": S("value")}
    action: Optional[str] = field(default=None, metadata={"description": "The action of IP ACL rule."})
    value: Optional[str] = field(default=None, metadata={'description': 'Specifies the IP or IP range in CIDR format. Only IPV4 address is allowed.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureNetworkRuleSet:
    kind: ClassVar[str] = "azure_network_rule_set"
    mapping: ClassVar[Dict[str, Bender]] = {
        "bypass": S("bypass"),
        "default_action": S("defaultAction"),
        "ip_rules": S("ipRules") >> ForallBend(AzureIPRule.mapping),
        "resource_access_rules": S("resourceAccessRules") >> ForallBend(AzureResourceAccessRule.mapping),
        "virtual_network_rules": S("virtualNetworkRules") >> ForallBend(AzureVirtualNetworkRule.mapping),
    }
    bypass: Optional[str] = field(default=None, metadata={'description': 'Specifies whether traffic is bypassed for Logging/Metrics/AzureServices. Possible values are any combination of Logging|Metrics|AzureServices (For example, Logging, Metrics ), or None to bypass none of those traffics.'})  # fmt: skip
    default_action: Optional[str] = field(default=None, metadata={'description': 'Specifies the default action of allow or deny when no other rules match.'})  # fmt: skip
    ip_rules: Optional[List[AzureIPRule]] = field(default=None, metadata={"description": "Sets the IP ACL rules"})
    resource_access_rules: Optional[List[AzureResourceAccessRule]] = field(default=None, metadata={'description': 'Sets the resource access rules'})  # fmt: skip
    virtual_network_rules: Optional[List[AzureVirtualNetworkRule]] = field(default=None, metadata={'description': 'Sets the virtual network rules'})  # fmt: skip


@define(eq=False, slots=False)
class AzureGeoReplicationStats:
    kind: ClassVar[str] = "azure_geo_replication_stats"
    mapping: ClassVar[Dict[str, Bender]] = {
        "can_failover": S("canFailover"),
        "can_planned_failover": S("canPlannedFailover"),
        "last_sync_time": S("lastSyncTime"),
        "post_failover_redundancy": S("postFailoverRedundancy"),
        "post_planned_failover_redundancy": S("postPlannedFailoverRedundancy"),
        "status": S("status"),
    }
    can_failover: Optional[bool] = field(default=None, metadata={'description': 'A boolean flag which indicates whether or not account failover is supported for the account.'})  # fmt: skip
    can_planned_failover: Optional[bool] = field(default=None, metadata={'description': 'A boolean flag which indicates whether or not planned account failover is supported for the account.'})  # fmt: skip
    last_sync_time: Optional[datetime] = field(default=None, metadata={'description': 'All primary writes preceding this UTC date/time value are guaranteed to be available for read operations. Primary writes following this point in time may or may not be available for reads. Element may be default value if value of LastSyncTime is not available, this can happen if secondary is offline or we are in bootstrap.'})  # fmt: skip
    post_failover_redundancy: Optional[str] = field(default=None, metadata={'description': 'The redundancy type of the account after an account failover is performed.'})  # fmt: skip
    post_planned_failover_redundancy: Optional[str] = field(default=None, metadata={'description': 'The redundancy type of the account after a planned account failover is performed.'})  # fmt: skip
    status: Optional[str] = field(default=None, metadata={'description': 'The status of the secondary location. Possible values are: - Live: Indicates that the secondary location is active and operational. - Bootstrap: Indicates initial synchronization from the primary location to the secondary location is in progress.This typically occurs when replication is first enabled. - Unavailable: Indicates that the secondary location is temporarily unavailable.'})  # fmt: skip


@define(eq=False, slots=False)
class AzurePrivateLinkServiceConnectionState:
    kind: ClassVar[str] = "azure_private_link_service_connection_state"
    mapping: ClassVar[Dict[str, Bender]] = {
        "action_required": S("actionRequired"),
        "description": S("description"),
        "status": S("status"),
    }
    action_required: Optional[str] = field(default=None, metadata={'description': 'A message indicating if changes on the service provider require any updates on the consumer.'})  # fmt: skip
    description: Optional[str] = field(default=None, metadata={'description': 'The reason for approval/rejection of the connection.'})  # fmt: skip
    status: Optional[str] = field(default=None, metadata={"description": "The private endpoint connection status."})


@define(eq=False, slots=False)
class AzurePrivateEndpointConnection:
    kind: ClassVar[str] = "azure_private_endpoint_connection"
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "name": S("name"),
        "private_endpoint": S("properties", "privateEndpoint", "id"),
        "private_link_service_connection_state": S("properties", "privateLinkServiceConnectionState")
        >> Bend(AzurePrivateLinkServiceConnectionState.mapping),
        "provisioning_state": S("properties", "provisioningState"),
        "type": S("type"),
    }
    id: Optional[str] = field(default=None, metadata={'description': 'Fully qualified resource ID for the resource. Ex - /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}'})  # fmt: skip
    name: Optional[str] = field(default=None, metadata={"description": "The name of the resource"})
    private_endpoint: Optional[str] = field(default=None, metadata={"description": "The Private Endpoint resource."})
    private_link_service_connection_state: Optional[AzurePrivateLinkServiceConnectionState] = field(default=None, metadata={'description': 'A collection of information about the state of the connection between service consumer and provider.'})  # fmt: skip
    provisioning_state: Optional[str] = field(default=None, metadata={'description': 'The current provisioning state.'})  # fmt: skip
    type: Optional[str] = field(default=None, metadata={'description': 'The type of the resource. E.g. Microsoft.Compute/virtualMachines or Microsoft.Storage/storageAccounts '})  # fmt: skip


@define(eq=False, slots=False)
class AzureRoutingPreference:
    kind: ClassVar[str] = "azure_routing_preference"
    mapping: ClassVar[Dict[str, Bender]] = {
        "publish_internet_endpoints": S("publishInternetEndpoints"),
        "publish_microsoft_endpoints": S("publishMicrosoftEndpoints"),
        "routing_choice": S("routingChoice"),
    }
    publish_internet_endpoints: Optional[bool] = field(default=None, metadata={'description': 'A boolean flag which indicates whether internet routing storage endpoints are to be published'})  # fmt: skip
    publish_microsoft_endpoints: Optional[bool] = field(default=None, metadata={'description': 'A boolean flag which indicates whether microsoft routing storage endpoints are to be published'})  # fmt: skip
    routing_choice: Optional[str] = field(default=None, metadata={'description': 'Routing Choice defines the kind of network routing opted by the user.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureBlobRestoreRange:
    kind: ClassVar[str] = "azure_blob_restore_range"
    mapping: ClassVar[Dict[str, Bender]] = {"end_range": S("endRange"), "start_range": S("startRange")}
    end_range: Optional[str] = field(default=None, metadata={'description': 'Blob end range. This is exclusive. Empty means account end.'})  # fmt: skip
    start_range: Optional[str] = field(default=None, metadata={'description': 'Blob start range. This is inclusive. Empty means account start.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureBlobRestoreParameters:
    kind: ClassVar[str] = "azure_blob_restore_parameters"
    mapping: ClassVar[Dict[str, Bender]] = {
        "blob_ranges": S("blobRanges") >> ForallBend(AzureBlobRestoreRange.mapping),
        "time_to_restore": S("timeToRestore"),
    }
    blob_ranges: Optional[List[AzureBlobRestoreRange]] = field(default=None, metadata={'description': 'Blob ranges to restore.'})  # fmt: skip
    time_to_restore: Optional[datetime] = field(default=None, metadata={'description': 'Restore blob to the specified time.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureBlobRestoreStatus:
    kind: ClassVar[str] = "azure_blob_restore_status"
    mapping: ClassVar[Dict[str, Bender]] = {
        "failure_reason": S("failureReason"),
        "parameters": S("parameters") >> Bend(AzureBlobRestoreParameters.mapping),
        "restore_id": S("restoreId"),
        "status": S("status"),
    }
    failure_reason: Optional[str] = field(default=None, metadata={'description': 'Failure reason when blob restore is failed.'})  # fmt: skip
    parameters: Optional[AzureBlobRestoreParameters] = field(default=None, metadata={'description': 'Blob restore parameters'})  # fmt: skip
    restore_id: Optional[str] = field(default=None, metadata={"description": "Id for tracking blob restore request."})
    status: Optional[str] = field(default=None, metadata={'description': 'The status of blob restore progress. Possible values are: - InProgress: Indicates that blob restore is ongoing. - Complete: Indicates that blob restore has been completed successfully. - Failed: Indicates that blob restore is failed.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureAccountImmutabilityPolicyProperties:
    kind: ClassVar[str] = "azure_account_immutability_policy_properties"
    mapping: ClassVar[Dict[str, Bender]] = {
        "allow_protected_append_writes": S("allowProtectedAppendWrites"),
        "immutability_period_since_creation_in_days": S("immutabilityPeriodSinceCreationInDays"),
        "state": S("state"),
    }
    allow_protected_append_writes: Optional[bool] = field(default=None, metadata={'description': 'This property can only be changed for disabled and unlocked time-based retention policies. When enabled, new blocks can be written to an append blob while maintaining immutability protection and compliance. Only new blocks can be added and any existing blocks cannot be modified or deleted.'})  # fmt: skip
    immutability_period_since_creation_in_days: Optional[int] = field(default=None, metadata={'description': 'The immutability period for the blobs in the container since the policy creation, in days.'})  # fmt: skip
    state: Optional[str] = field(default=None, metadata={'description': 'The ImmutabilityPolicy state defines the mode of the policy. Disabled state disables the policy, Unlocked state allows increase and decrease of immutability retention time and also allows toggling allowProtectedAppendWrites property, Locked state only allows the increase of the immutability retention time. A policy can only be created in a Disabled or Unlocked state and can be toggled between the two states. Only a policy in an Unlocked state can transition to a Locked state which cannot be reverted.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureImmutableStorageAccount:
    kind: ClassVar[str] = "azure_immutable_storage_account"
    mapping: ClassVar[Dict[str, Bender]] = {
        "enabled": S("enabled"),
        "immutability_policy": S("immutabilityPolicy") >> Bend(AzureAccountImmutabilityPolicyProperties.mapping),
    }
    enabled: Optional[bool] = field(default=None, metadata={'description': 'A boolean flag which enables account-level immutability. All the containers under such an account have object-level immutability enabled by default.'})  # fmt: skip
    immutability_policy: Optional[AzureAccountImmutabilityPolicyProperties] = field(default=None, metadata={'description': 'This defines account-level immutability policy properties.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureStorageAccountSkuConversionStatus:
    kind: ClassVar[str] = "azure_storage_account_sku_conversion_status"
    mapping: ClassVar[Dict[str, Bender]] = {
        "end_time": S("endTime"),
        "sku_conversion_status": S("skuConversionStatus"),
        "start_time": S("startTime"),
        "target_sku_name": S("targetSkuName"),
    }
    end_time: Optional[str] = field(default=None, metadata={'description': 'This property represents the sku conversion end time.'})  # fmt: skip
    sku_conversion_status: Optional[str] = field(default=None, metadata={'description': 'This property indicates the current sku conversion status.'})  # fmt: skip
    start_time: Optional[str] = field(default=None, metadata={'description': 'This property represents the sku conversion start time.'})  # fmt: skip
    target_sku_name: Optional[str] = field(default=None, metadata={'description': 'The SKU name. Required for account creation; optional for update. Note that in older versions, SKU name was called accountType.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureStorageAccount(AzureResource):
    kind: ClassVar[str] = "azure_storage_account"
    api_spec: ClassVar[AzureApiSpec] = AzureApiSpec(
        service="storage",
        version="2023-01-01",
        path="/subscriptions/{subscriptionId}/providers/Microsoft.Storage/storageAccounts",
        path_parameters=["subscriptionId"],
        query_parameters=["api-version"],
        access_path="value",
        expect_array=True,
    )
    reference_kinds: ClassVar[ModelReference] = {
        "successors": {"default": ["azure_storage_sku"]},
    }
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "location": S("location"),
        "ctime": S("properties", "creationTime"),
        "access_tier": S("properties", "accessTier"),
        "account_migration_in_progress": S("properties", "accountMigrationInProgress"),
        "allow_blob_public_access": S("properties", "allowBlobPublicAccess"),
        "allow_cross_tenant_replication": S("properties", "allowCrossTenantReplication"),
        "allow_shared_key_access": S("properties", "allowSharedKeyAccess"),
        "allowed_copy_scope": S("properties", "allowedCopyScope"),
        "azure_files_identity_based_authentication": S("properties", "azureFilesIdentityBasedAuthentication")
        >> Bend(AzureAzureFilesIdentityBasedAuthentication.mapping),
        "blob_restore_status": S("properties", "blobRestoreStatus") >> Bend(AzureBlobRestoreStatus.mapping),
        "creation_time": S("properties", "creationTime"),
        "storage_custom_domain": S("properties", "customDomain") >> Bend(AzureCustomDomain.mapping),
        "default_to_o_auth_authentication": S("properties", "defaultToOAuthAuthentication"),
        "dns_endpoint_type": S("properties", "dnsEndpointType"),
        "storage_encryption": S("properties", "encryption") >> Bend(AzureStorageEncryption.mapping),
        "extended_location": S("extendedLocation") >> Bend(AzureExtendedLocation.mapping),
        "failover_in_progress": S("properties", "failoverInProgress"),
        "geo_replication_stats": S("properties", "geoReplicationStats") >> Bend(AzureGeoReplicationStats.mapping),
        "storage_identity": S("identity") >> Bend(AzureIdentity.mapping),
        "immutable_storage_with_versioning": S("properties", "immutableStorageWithVersioning")
        >> Bend(AzureImmutableStorageAccount.mapping),
        "is_hns_enabled": S("properties", "isHnsEnabled"),
        "is_local_user_enabled": S("properties", "isLocalUserEnabled"),
        "is_nfs_v3_enabled": S("properties", "isNfsV3Enabled"),
        "is_sftp_enabled": S("properties", "isSftpEnabled"),
        "is_sku_conversion_blocked": S("properties", "isSkuConversionBlocked"),
        "key_creation_time": S("properties", "keyCreationTime") >> Bend(AzureKeyCreationTime.mapping),
        "key_policy": S("properties", "keyPolicy", "keyExpirationPeriodInDays"),
        "resource_kind": S("kind"),
        "large_file_shares_state": S("properties", "largeFileSharesState"),
        "last_geo_failover_time": S("properties", "lastGeoFailoverTime"),
        "minimum_tls_version": S("properties", "minimumTlsVersion"),
        "storage_network_acls": S("properties", "networkAcls") >> Bend(AzureNetworkRuleSet.mapping),
        "primary_endpoints": S("properties", "primaryEndpoints") >> Bend(AzureEndpoints.mapping),
        "primary_location": S("properties", "primaryLocation"),
        "storage_private_endpoint_connections": S("properties", "privateEndpointConnections")
        >> ForallBend(AzurePrivateEndpointConnection.mapping),
        "provisioning_state": S("properties", "provisioningState"),
        "public_network_access": S("properties", "publicNetworkAccess"),
        "routing_preference": S("properties", "routingPreference") >> Bend(AzureRoutingPreference.mapping),
        "sas_policy": S("properties", "sasPolicy") >> Bend(AzureSasPolicy.mapping),
        "secondary_endpoints": S("properties", "secondaryEndpoints") >> Bend(AzureEndpoints.mapping),
        "secondary_location": S("properties", "secondaryLocation"),
        "azure_sku": S("sku") >> Bend(AzureSku.mapping),
        "storage_sku_name": S("sku", "name"),
        "storage_sku_tier": S("sku", "tier"),
        "status_of_primary": S("properties", "statusOfPrimary"),
        "status_of_secondary": S("properties", "statusOfSecondary"),
        "storage_account_sku_conversion_status": S("properties", "storageAccountSkuConversionStatus")
        >> Bend(AzureStorageAccountSkuConversionStatus.mapping),
        "supports_https_traffic_only": S("properties", "supportsHttpsTrafficOnly"),
    }
    storage_sku_name: Optional[str] = field(default=None, metadata={'description': 'The SKU name. Required for account creation; optional for update. Note that in older versions, SKU name was called accountType.'})  # fmt: skip
    storage_sku_tier: Optional[str] = field(
        default=None, metadata={"description": "The SKU tier. This is based on the SKU name."}
    )
    name: Optional[str] = field(default=None, metadata={"description": "The name of the resource"})
    type: Optional[str] = field(default=None, metadata={'description': 'The type of the resource. E.g. Microsoft.Compute/virtualMachines or Microsoft.Storage/storageAccounts '})  # fmt: skip
    location: Optional[str] = field(default=None, metadata={'description': 'The geo-location where the resource lives'})  # fmt: skip
    access_tier: Optional[str] = field(default=None, metadata={'description': 'Required for storage accounts where kind = BlobStorage. The access tier is used for billing. The Premium access tier is the default value for premium block blobs storage account type and it cannot be changed for the premium block blobs storage account type.'})  # fmt: skip
    account_migration_in_progress: Optional[bool] = field(default=None, metadata={'description': 'If customer initiated account migration is in progress, the value will be true else it will be null.'})  # fmt: skip
    allow_blob_public_access: Optional[bool] = field(default=None, metadata={'description': 'Allow or disallow public access to all blobs or containers in the storage account. The default interpretation is false for this property.'})  # fmt: skip
    allow_cross_tenant_replication: Optional[bool] = field(default=None, metadata={'description': 'Allow or disallow cross AAD tenant object replication. Set this property to true for new or existing accounts only if object replication policies will involve storage accounts in different AAD tenants. The default interpretation is false for new accounts to follow best security practices by default.'})  # fmt: skip
    allow_shared_key_access: Optional[bool] = field(default=None, metadata={'description': 'Indicates whether the storage account permits requests to be authorized with the account access key via Shared Key. If false, then all requests, including shared access signatures, must be authorized with Azure Active Directory (Azure AD). The default value is null, which is equivalent to true.'})  # fmt: skip
    allowed_copy_scope: Optional[str] = field(default=None, metadata={'description': 'Restrict copy to and from Storage Accounts within an AAD tenant or with Private Links to the same VNet.'})  # fmt: skip
    azure_files_identity_based_authentication: Optional[AzureAzureFilesIdentityBasedAuthentication] = field(default=None, metadata={'description': 'Settings for Azure Files identity based authentication.'})  # fmt: skip
    blob_restore_status: Optional[AzureBlobRestoreStatus] = field(default=None, metadata={'description': 'Blob restore status.'})  # fmt: skip
    creation_time: Optional[datetime] = field(default=None, metadata={'description': 'Gets the creation date and time of the storage account in UTC.'})  # fmt: skip
    storage_custom_domain: Optional[AzureCustomDomain] = field(default=None, metadata={'description': 'The custom domain assigned to this storage account. This can be set via Update.'})  # fmt: skip
    default_to_o_auth_authentication: Optional[bool] = field(default=None, metadata={'description': 'A boolean flag which indicates whether the default authentication is OAuth or not. The default interpretation is false for this property.'})  # fmt: skip
    dns_endpoint_type: Optional[str] = field(default=None, metadata={'description': 'Allows you to specify the type of endpoint. Set this to AzureDNSZone to create a large number of accounts in a single subscription, which creates accounts in an Azure DNS Zone and the endpoint URL will have an alphanumeric DNS Zone identifier.'})  # fmt: skip
    storage_encryption: Optional[AzureStorageEncryption] = field(default=None, metadata={'description': 'The encryption settings on the storage account.'})  # fmt: skip
    extended_location: Optional[AzureExtendedLocation] = field(default=None, metadata={'description': 'The complex type of the extended location.'})  # fmt: skip
    failover_in_progress: Optional[bool] = field(default=None, metadata={'description': 'If the failover is in progress, the value will be true, otherwise, it will be null.'})  # fmt: skip
    geo_replication_stats: Optional[AzureGeoReplicationStats] = field(default=None, metadata={'description': 'Statistics related to replication for storage account s Blob, Table, Queue and File services. It is only available when geo-redundant replication is enabled for the storage account.'})  # fmt: skip
    storage_identity: Optional[AzureIdentity] = field(
        default=None, metadata={"description": "Identity for the resource."}
    )
    immutable_storage_with_versioning: Optional[AzureImmutableStorageAccount] = field(default=None, metadata={'description': 'This property enables and defines account-level immutability. Enabling the feature auto-enables Blob Versioning.'})  # fmt: skip
    is_hns_enabled: Optional[bool] = field(default=None, metadata={'description': 'Account HierarchicalNamespace enabled if sets to true.'})  # fmt: skip
    is_local_user_enabled: Optional[bool] = field(default=None, metadata={'description': 'Enables local users feature, if set to true'})  # fmt: skip
    is_nfs_v3_enabled: Optional[bool] = field(default=None, metadata={'description': 'NFS 3.0 protocol support enabled if set to true.'})  # fmt: skip
    is_sftp_enabled: Optional[bool] = field(default=None, metadata={'description': 'Enables Secure File Transfer Protocol, if set to true'})  # fmt: skip
    is_sku_conversion_blocked: Optional[bool] = field(default=None, metadata={'description': 'This property will be set to true or false on an event of ongoing migration. Default value is null.'})  # fmt: skip
    key_creation_time: Optional[AzureKeyCreationTime] = field(default=None, metadata={'description': 'Storage account keys creation time.'})  # fmt: skip
    key_policy: Optional[int] = field(default=None, metadata={'description': 'KeyPolicy assigned to the storage account.'})  # fmt: skip
    resource_kind: Optional[str] = field(default=None, metadata={"description": "Gets the Kind."})
    large_file_shares_state: Optional[str] = field(default=None, metadata={'description': 'Allow large file shares if sets to Enabled. It cannot be disabled once it is enabled.'})  # fmt: skip
    last_geo_failover_time: Optional[datetime] = field(default=None, metadata={'description': 'Gets the timestamp of the most recent instance of a failover to the secondary location. Only the most recent timestamp is retained. This element is not returned if there has never been a failover instance. Only available if the accountType is Standard_GRS or Standard_RAGRS.'})  # fmt: skip
    minimum_tls_version: Optional[str] = field(default=None, metadata={'description': 'Set the minimum TLS version to be permitted on requests to storage. The default interpretation is TLS 1.0 for this property.'})  # fmt: skip
    storage_network_acls: Optional[AzureNetworkRuleSet] = field(
        default=None, metadata={"description": "Network rule set"}
    )
    primary_endpoints: Optional[AzureEndpoints] = field(default=None, metadata={'description': 'The URIs that are used to perform a retrieval of a public blob, queue, table, web or dfs object.'})  # fmt: skip
    primary_location: Optional[str] = field(default=None, metadata={'description': 'Gets the location of the primary data center for the storage account.'})  # fmt: skip
    storage_private_endpoint_connections: Optional[List[AzurePrivateEndpointConnection]] = field(default=None, metadata={'description': 'List of private endpoint connection associated with the specified storage account'})  # fmt: skip
    provisioning_state: Optional[str] = field(default=None, metadata={'description': 'Gets the status of the storage account at the time the operation was called.'})  # fmt: skip
    public_network_access: Optional[str] = field(default=None, metadata={'description': 'Allow or disallow public network access to Storage Account. Value is optional but if passed in, must be Enabled or Disabled .'})  # fmt: skip
    routing_preference: Optional[AzureRoutingPreference] = field(default=None, metadata={'description': 'Routing preference defines the type of network, either microsoft or internet routing to be used to deliver the user data, the default option is microsoft routing'})  # fmt: skip
    sas_policy: Optional[AzureSasPolicy] = field(default=None, metadata={'description': 'SasPolicy assigned to the storage account.'})  # fmt: skip
    secondary_endpoints: Optional[AzureEndpoints] = field(default=None, metadata={'description': 'The URIs that are used to perform a retrieval of a public blob, queue, table, web or dfs object.'})  # fmt: skip
    secondary_location: Optional[str] = field(default=None, metadata={'description': 'Gets the location of the geo-replicated secondary for the storage account. Only available if the accountType is Standard_GRS or Standard_RAGRS.'})  # fmt: skip
    azure_sku: Optional[AzureSku] = field(default=None, metadata={"description": "The SKU of the storage account."})
    status_of_primary: Optional[str] = field(default=None, metadata={'description': 'Gets the status indicating whether the primary location of the storage account is available or unavailable.'})  # fmt: skip
    status_of_secondary: Optional[str] = field(default=None, metadata={'description': 'Gets the status indicating whether the secondary location of the storage account is available or unavailable. Only available if the SKU name is Standard_GRS or Standard_RAGRS.'})  # fmt: skip
    storage_account_sku_conversion_status: Optional[AzureStorageAccountSkuConversionStatus] = field(default=None, metadata={'description': 'This defines the sku conversion status object for asynchronous sku conversions.'})  # fmt: skip
    supports_https_traffic_only: Optional[bool] = field(default=None, metadata={'description': 'Allows https traffic only to storage service if sets to true.'})  # fmt: skip

    def post_process(self, graph_builder: GraphBuilder, source: Json) -> None:
        def collect_blobs() -> None:
            if (
                (sub_id := self.resource_subscription_id())
                and (rg := self.resource_group())
                and (account_name := self.name)
            ):
                path = f"/subscriptions/{sub_id}/resourceGroups/{rg}/providers/Microsoft.Storage/storageAccounts/{account_name}/blobServices/default/containers"
                api_spec = AzureApiSpec(
                    service="storage",
                    version="2023-01-01",
                    path=path,
                    path_parameters=[],
                    query_parameters=["api-version"],
                    access_path="value",
                    expect_array=True,
                )
                items = graph_builder.client.list(api_spec)
                AzureBlobContainer.collect(items, graph_builder)

        graph_builder.submit_work(service_name, collect_blobs)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if (
            (sku := self.azure_sku)
            and (sku_name := sku.name)
            and (sku_tier := sku.tier)
            and (location := self.location)
        ):
            maybe_sku_location = f"_{location}_location"
            property_dict: Dict[str, Any] = {
                maybe_sku_location: location,
                "name": sku_name,
                "tier": sku_tier,
                "clazz": AzureStorageSku,
            }

            builder.add_edge(
                self,
                edge_type=EdgeType.default,
                **property_dict,
            )


@define(eq=False, slots=False)
class AzureStorageUsage(AzureResource, AzureBaseUsage):
    kind: ClassVar[str] = "azure_storage_usage"
    api_spec: ClassVar[AzureApiSpec] = AzureApiSpec(
        service="storage",
        version="2023-01-01",
        path="/subscriptions/{subscriptionId}/providers/Microsoft.Storage/locations/{location}/usages",
        path_parameters=["subscriptionId", "location"],
        query_parameters=["api-version"],
        access_path="value",
        expect_array=True,
        expected_error_codes=AzureBaseUsage._expected_error_codes,
    )
    mapping: ClassVar[Dict[str, Bender]] = AzureBaseUsage.mapping | {
        "id": S("name", "value"),
    }


resources: List[Type[AzureResource]] = [
    AzureBlobContainer,
    AzureDeletedAccount,
    AzureStorageSku,
    AzureStorageAccount,
    AzureStorageUsage,
]
