from datetime import datetime
from typing import ClassVar, Dict, Optional, List, Tuple, Type

from attr import define, field

from fix_plugin_azure.azure_client import AzureApiSpec
from fix_plugin_azure.resource.base import AzureResource, AzureSystemData, GraphBuilder
from fixlib.baseresources import EdgeType, ModelReference
from fixlib.json_bender import Bender, S, Bend, ForallBend
from fixlib.types import Json


@define(eq=False, slots=False)
class AzureTrackedResource:
    kind: ClassVar[str] = "azure_tracked_resource"
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "location": S("location"),
        "name": S("name"),
        "system_data": S("systemData") >> Bend(AzureSystemData.mapping),
        "tags": S("tags"),
        "type": S("type"),
    }
    id: Optional[str] = field(default=None, metadata={'description': 'Fully qualified resource ID for the resource. Ex - /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}'})  # fmt: skip
    location: Optional[str] = field(default=None, metadata={'description': 'The geo-location where the resource lives'})  # fmt: skip
    name: Optional[str] = field(default=None, metadata={"description": "The name of the resource"})
    system_data: Optional[AzureSystemData] = field(default=None, metadata={'description': 'Metadata pertaining to creation and last modification of the resource.'})  # fmt: skip
    tags: Optional[Dict[str, str]] = field(default=None, metadata={"description": "Resource tags."})
    type: Optional[str] = field(default=None, metadata={'description': 'The type of the resource. E.g. Microsoft.Compute/virtualMachines or Microsoft.Storage/storageAccounts '})  # fmt: skip


@define(eq=False, slots=False)
class AzureAPIServerAccessProfile:
    kind: ClassVar[str] = "azure_api_server_access_profile"
    mapping: ClassVar[Dict[str, Bender]] = {
        "enable_private_cluster": S("enablePrivateCluster"),
        "enable_vnet_integration": S("enableVnetIntegration"),
        "subnet_id": S("subnetId"),
    }
    enable_private_cluster: Optional[bool] = field(default=None, metadata={'description': 'Whether to create the Fleet hub as a private cluster or not.'})  # fmt: skip
    enable_vnet_integration: Optional[bool] = field(default=None, metadata={'description': 'Whether to enable apiserver vnet integration for the Fleet hub or not.'})  # fmt: skip
    subnet_id: Optional[str] = field(default=None, metadata={'description': 'A type definition that refers the id to an ARM resource.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureAgentProfile:
    kind: ClassVar[str] = "azure_agent_profile"
    mapping: ClassVar[Dict[str, Bender]] = {"subnet_id": S("subnetId"), "vm_size": S("vmSize")}
    subnet_id: Optional[str] = field(default=None, metadata={'description': 'A type definition that refers the id to an ARM resource.'})  # fmt: skip
    vm_size: Optional[str] = field(default=None, metadata={'description': 'The virtual machine size of the Fleet hub.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureFleetHubProfile:
    kind: ClassVar[str] = "azure_fleet_hub_profile"
    mapping: ClassVar[Dict[str, Bender]] = {
        "agent_profile": S("agentProfile") >> Bend(AzureAgentProfile.mapping),
        "api_server_access_profile": S("apiServerAccessProfile") >> Bend(AzureAPIServerAccessProfile.mapping),
        "dns_prefix": S("dnsPrefix"),
        "fqdn": S("fqdn"),
        "kubernetes_version": S("kubernetesVersion"),
        "portal_fqdn": S("portalFqdn"),
    }
    agent_profile: Optional[AzureAgentProfile] = field(default=None, metadata={'description': 'Agent profile for the Fleet hub.'})  # fmt: skip
    api_server_access_profile: Optional[AzureAPIServerAccessProfile] = field(default=None, metadata={'description': 'Access profile for the Fleet hub API server.'})  # fmt: skip
    dns_prefix: Optional[str] = field(default=None, metadata={'description': 'DNS prefix used to create the FQDN for the Fleet hub.'})  # fmt: skip
    fqdn: Optional[str] = field(default=None, metadata={"description": "The FQDN of the Fleet hub."})
    kubernetes_version: Optional[str] = field(default=None, metadata={'description': 'The Kubernetes version of the Fleet hub.'})  # fmt: skip
    portal_fqdn: Optional[str] = field(default=None, metadata={'description': 'The Azure Portal FQDN of the Fleet hub.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureUserAssignedIdentity:
    kind: ClassVar[str] = "azure_user_assigned_identity"
    mapping: ClassVar[Dict[str, Bender]] = {
        "client_id": S("clientId"),
        "object_id": S("objectId"),
        "resource_id": S("resourceId"),
    }
    client_id: Optional[str] = field(default=None, metadata={'description': 'The client ID of the user assigned identity.'})  # fmt: skip
    object_id: Optional[str] = field(default=None, metadata={'description': 'The object ID of the user assigned identity.'})  # fmt: skip
    resource_id: Optional[str] = field(default=None, metadata={'description': 'The resource ID of the user assigned identity.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureManagedServiceIdentity:
    kind: ClassVar[str] = "azure_managed_service_identity"
    mapping: ClassVar[Dict[str, Bender]] = {
        "principal_id": S("principalId"),
        "tenant_id": S("tenantId"),
        "type": S("type"),
        "user_assigned_identities": S("userAssignedIdentities"),
    }
    principal_id: Optional[str] = field(default=None, metadata={'description': 'The service principal ID of the system assigned identity. This property will only be provided for a system assigned identity.'})  # fmt: skip
    tenant_id: Optional[str] = field(default=None, metadata={'description': 'The tenant ID of the system assigned identity. This property will only be provided for a system assigned identity.'})  # fmt: skip
    type: Optional[str] = field(default=None, metadata={'description': 'Type of managed service identity (where both SystemAssigned and UserAssigned types are allowed).'})  # fmt: skip
    user_assigned_identities: Optional[Dict[str, AzureUserAssignedIdentity]] = field(default=None, metadata={'description': 'The set of user assigned identities associated with the resource. The userAssignedIdentities dictionary keys will be ARM resource ids in the form: /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ManagedIdentity/userAssignedIdentities/{identityName}. The dictionary values can be empty objects ({}) in requests.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureFleet(AzureResource):
    kind: ClassVar[str] = "azure_fleet"
    api_spec: ClassVar[AzureApiSpec] = AzureApiSpec(
        service="containerservice",
        version="2023-08-15-preview",
        path="/subscriptions/{subscriptionId}/providers/Microsoft.ContainerService/fleets",
        path_parameters=["subscriptionId"],
        query_parameters=["api-version"],
        access_path="value",
        expect_array=True,
    )
    reference_kinds: ClassVar[ModelReference] = {
        "successors": {"default": ["azure_managed_cluster"]},
    }
    mapping: ClassVar[Dict[str, Bender]] = AzureTrackedResource.mapping | {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "ctime": S("systemData", "createdAt"),
        "mtime": S("systemData", "lastModifiedAt"),
        "e_tag": S("eTag"),
        "resource_group": S("resourceGroup"),
        "hub_profile": S("properties", "hubProfile") >> Bend(AzureFleetHubProfile.mapping),
        "azure_fleet_identity": S("identity") >> Bend(AzureManagedServiceIdentity.mapping),
        "provisioning_state": S("properties", "provisioningState"),
    }
    e_tag: Optional[str] = field(default=None, metadata={'description': 'If eTag is provided in the response body, it may also be provided as a header per the normal etag convention. Entity tags are used for comparing two or more entities from the same requested resource. HTTP/1.1 uses entity tags in the etag (section 14.19), If-Match (section 14.24), If-None-Match (section 14.26), and If-Range (section 14.27) header fields.'})  # fmt: skip
    hub_profile: Optional[AzureFleetHubProfile] = field(default=None, metadata={'description': 'The FleetHubProfile configures the fleet hub.'})  # fmt: skip
    azure_fleet_identity: Optional[AzureManagedServiceIdentity] = field(default=None, metadata={'description': 'Managed service identity (system assigned and/or user assigned identities)'})  # fmt: skip
    provisioning_state: Optional[str] = field(default=None, metadata={'description': 'The provisioning state of the last accepted operation.'})  # fmt: skip
    resource_group: Optional[str] = field(default=None, metadata={"description": "Resource group name"})
    cluster_resource_id: Optional[str] = field(default=None, metadata={"description": "Reference to the cluster ID"})

    def post_process(self, graph_builder: GraphBuilder, source: Json) -> None:
        api_spec = AzureApiSpec(
            service="containerservice",
            version="2023-10-15",
            path=f"{self.id}/members",
            path_parameters=[],
            query_parameters=["api-version"],
            access_path="value",
            expect_array=True,
        )
        items: List[Json] = graph_builder.client.list(api_spec)

        item: Json = next(iter(items), {})

        try:
            self.cluster_resource_id = item["properties"]["clusterResourceId"]
        except KeyError:
            pass

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if cluster_id := self.cluster_resource_id:
            builder.add_edge(self, edge_type=EdgeType.default, clazz=AzureManagedCluster, id=cluster_id)


@define(eq=False, slots=False)
class AzureKubernetesVersionCapabilities:
    kind: ClassVar[str] = "azure_kubernetes_version_capabilities"
    mapping: ClassVar[Dict[str, Bender]] = {"support_plan": S("supportPlan")}
    support_plan: Optional[List[str]] = field(default=None, metadata={"description": ""})


@define(eq=False, slots=False)
class AzureKubernetesPatchVersion:
    kind: ClassVar[str] = "azure_kubernetes_patch_version"
    mapping: ClassVar[Dict[str, Bender]] = {"upgrades": S("upgrades")}
    upgrades: Optional[List[str]] = field(default=None, metadata={'description': 'Possible upgrade path for given patch version'})  # fmt: skip


@define(eq=False, slots=False)
class AzureManagedClusterSKU:
    kind: ClassVar[str] = "azure_managed_cluster_sku"
    mapping: ClassVar[Dict[str, Bender]] = {"name": S("name"), "tier": S("tier")}
    name: Optional[str] = field(default=None, metadata={"description": "The name of a managed cluster SKU."})
    tier: Optional[str] = field(default=None, metadata={'description': 'If not specified, the default is Free . See [AKS Pricing Tier](https://learn.microsoft.com/azure/aks/free-standard-pricing-tiers) for more details.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureExtendedLocation:
    kind: ClassVar[str] = "azure_extended_location"
    mapping: ClassVar[Dict[str, Bender]] = {"name": S("name"), "type": S("type")}
    name: Optional[str] = field(default=None, metadata={"description": "The name of the extended location."})
    type: Optional[str] = field(default=None, metadata={"description": "The type of extendedLocation."})


@define(eq=False, slots=False)
class AzureDelegatedResource:
    kind: ClassVar[str] = "azure_delegated_resource"
    mapping: ClassVar[Dict[str, Bender]] = {
        "location": S("location"),
        "referral_resource": S("referralResource"),
        "resource_id": S("resourceId"),
        "tenant_id": S("tenantId"),
    }
    location: Optional[str] = field(default=None, metadata={'description': 'The source resource location - internal use only.'})  # fmt: skip
    referral_resource: Optional[str] = field(default=None, metadata={'description': 'The delegation id of the referral delegation (optional) - internal use only.'})  # fmt: skip
    resource_id: Optional[str] = field(default=None, metadata={'description': 'The ARM resource id of the delegated resource - internal use only.'})  # fmt: skip
    tenant_id: Optional[str] = field(default=None, metadata={'description': 'The tenant id of the delegated resource - internal use only.'})  # fmt: skip


@define(eq=False, slots=False)
class AzurePrincipalidClientid:
    kind: ClassVar[str] = "azure_principalid_clientid"
    mapping: ClassVar[Dict[str, Bender]] = {"client_id": S("clientId"), "principal_id": S("principalId")}
    client_id: Optional[str] = field(default=None, metadata={'description': 'The client id of user assigned identity.'})  # fmt: skip
    principal_id: Optional[str] = field(default=None, metadata={'description': 'The principal id of user assigned identity.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureManagedClusterIdentity:
    kind: ClassVar[str] = "azure_managed_cluster_identity"
    mapping: ClassVar[Dict[str, Bender]] = {
        "delegated_resources": S("delegatedResources"),
        "principal_id": S("principalId"),
        "tenant_id": S("tenantId"),
        "type": S("type"),
        "user_assigned_identities": S("userAssignedIdentities"),
    }
    delegated_resources: Optional[Dict[str, AzureDelegatedResource]] = field(default=None, metadata={'description': 'The set of delegated resources. The delegated resources dictionary keys will be source resource internal ids - internal use only.'})  # fmt: skip
    principal_id: Optional[str] = field(default=None, metadata={'description': 'The principal id of the system assigned identity which is used by master components.'})  # fmt: skip
    tenant_id: Optional[str] = field(default=None, metadata={'description': 'The tenant id of the system assigned identity which is used by master components.'})  # fmt: skip
    type: Optional[str] = field(default=None, metadata={'description': 'For more information see [use managed identities in AKS](https://docs.microsoft.com/azure/aks/use-managed-identity).'})  # fmt: skip
    user_assigned_identities: Optional[Dict[str, AzurePrincipalidClientid]] = field(default=None, metadata={'description': 'The keys must be ARM resource IDs in the form: /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ManagedIdentity/userAssignedIdentities/{identityName} .'})  # fmt: skip


@define(eq=False, slots=False)
class AzureContainerServiceSshConfiguration:
    kind: ClassVar[str] = "azure_container_service_ssh_configuration"
    mapping: ClassVar[Dict[str, Bender]] = {"public_keys": S("publicKeys", default=[]) >> ForallBend(S("keyData"))}
    public_keys: Optional[List[str]] = field(default=None, metadata={'description': 'The list of SSH public keys used to authenticate with Linux-based VMs. A maximum of 1 key may be specified.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureContainerServiceLinuxProfile:
    kind: ClassVar[str] = "azure_container_service_linux_profile"
    mapping: ClassVar[Dict[str, Bender]] = {
        "admin_username": S("adminUsername"),
        "ssh": S("ssh") >> Bend(AzureContainerServiceSshConfiguration.mapping),
    }
    admin_username: Optional[str] = field(default=None, metadata={'description': 'The administrator username to use for Linux VMs.'})  # fmt: skip
    ssh: Optional[AzureContainerServiceSshConfiguration] = field(default=None, metadata={'description': 'SSH configuration for Linux-based VMs running on Azure.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureWindowsGmsaProfile:
    kind: ClassVar[str] = "azure_windows_gmsa_profile"
    mapping: ClassVar[Dict[str, Bender]] = {
        "dns_server": S("dnsServer"),
        "enabled": S("enabled"),
        "root_domain_name": S("rootDomainName"),
    }
    dns_server: Optional[str] = field(default=None, metadata={'description': 'Specifies the DNS server for Windows gMSA. Set it to empty if you have configured the DNS server in the vnet which is used to create the managed cluster.'})  # fmt: skip
    enabled: Optional[bool] = field(default=None, metadata={'description': 'Specifies whether to enable Windows gMSA in the managed cluster.'})  # fmt: skip
    root_domain_name: Optional[str] = field(default=None, metadata={'description': 'Specifies the root domain name for Windows gMSA. Set it to empty if you have configured the DNS server in the vnet which is used to create the managed cluster.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureManagedClusterWindowsProfile:
    kind: ClassVar[str] = "azure_managed_cluster_windows_profile"
    mapping: ClassVar[Dict[str, Bender]] = {
        "admin_password": S("adminPassword"),
        "admin_username": S("adminUsername"),
        "enable_csi_proxy": S("enableCSIProxy"),
        "gmsa_profile": S("gmsaProfile") >> Bend(AzureWindowsGmsaProfile.mapping),
        "license_type": S("licenseType"),
    }
    admin_password: Optional[str] = field(default=None, metadata={'description': 'Specifies the password of the administrator account. **Minimum-length:** 8 characters **Max-length:** 123 characters **Complexity requirements:** 3 out of 4 conditions below need to be fulfilled Has lower characters Has upper characters Has a digit Has a special character (Regex match [\\W_]) **Disallowed values:** abc@123 , P@$$w0rd , P@ssw0rd , P@ssword123 , Pa$$word , pass@word1 , Password! , Password1 , Password22 , iloveyou! '})  # fmt: skip
    admin_username: Optional[str] = field(default=None, metadata={'description': 'Specifies the name of the administrator account. **Restriction:** Cannot end in . **Disallowed values:** administrator , admin , user , user1 , test , user2 , test1 , user3 , admin1 , 1 , 123 , a , actuser , adm , admin2 , aspnet , backup , console , david , guest , john , owner , root , server , sql , support , support_388945a0 , sys , test2 , test3 , user4 , user5 . **Minimum-length:** 1 character **Max-length:** 20 characters'})  # fmt: skip
    enable_csi_proxy: Optional[bool] = field(default=None, metadata={'description': 'For more details on CSI proxy, see the [CSI proxy GitHub repo](https://github.com/kubernetes-csi/csi-proxy).'})  # fmt: skip
    gmsa_profile: Optional[AzureWindowsGmsaProfile] = field(default=None, metadata={'description': 'Windows gMSA Profile in the managed cluster.'})  # fmt: skip
    license_type: Optional[str] = field(default=None, metadata={'description': 'The license type to use for Windows VMs. See [Azure Hybrid User Benefits](https://azure.microsoft.com/pricing/hybrid-benefit/faq/) for more details.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureManagedClusterServicePrincipalProfile:
    kind: ClassVar[str] = "azure_managed_cluster_service_principal_profile"
    mapping: ClassVar[Dict[str, Bender]] = {"client_id": S("clientId"), "secret": S("secret")}
    client_id: Optional[str] = field(default=None, metadata={"description": "The ID for the service principal."})
    secret: Optional[str] = field(default=None, metadata={'description': 'The secret password associated with the service principal in plain text.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureManagedClusterAddonProfile:
    kind: ClassVar[str] = "azure_managed_cluster_addon_profile"
    mapping: ClassVar[Dict[str, Bender]] = {
        "config": S("config"),
        "enabled": S("enabled"),
        "identity": S("identity") >> Bend(AzureUserAssignedIdentity.mapping),
    }
    config: Optional[Dict[str, str]] = field(default=None, metadata={'description': 'Key-value pairs for configuring an add-on.'})  # fmt: skip
    enabled: Optional[bool] = field(default=None, metadata={"description": "Whether the add-on is enabled or not."})
    identity: Optional[AzureUserAssignedIdentity] = field(default=None, metadata={'description': 'Information of user assigned identity used by this add-on.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureManagedClusterPodIdentityProvisioningErrorBody:
    kind: ClassVar[str] = "azure_managed_cluster_pod_identity_provisioning_error_body"
    mapping: ClassVar[Dict[str, Bender]] = {
        "code": S("code"),
        "details": S("details"),
        "message": S("message"),
        "target": S("target"),
    }
    code: Optional[str] = field(default=None, metadata={'description': 'An identifier for the error. Codes are invariant and are intended to be consumed programmatically.'})  # fmt: skip
    details: Optional[List[Json]] = field(default=None, metadata={'description': 'A list of additional details about the error.'})  # fmt: skip
    message: Optional[str] = field(default=None, metadata={'description': 'A message describing the error, intended to be suitable for display in a user interface.'})  # fmt: skip
    target: Optional[str] = field(default=None, metadata={'description': 'The target of the particular error. For example, the name of the property in error.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureManagedClusterPodIdentityProvisioningError:
    kind: ClassVar[str] = "azure_managed_cluster_pod_identity_provisioning_error"
    mapping: ClassVar[Dict[str, Bender]] = {
        "error": S("error") >> Bend(AzureManagedClusterPodIdentityProvisioningErrorBody.mapping)
    }
    error: Optional[AzureManagedClusterPodIdentityProvisioningErrorBody] = field(default=None, metadata={'description': 'An error response from the pod identity provisioning.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureError:
    kind: ClassVar[str] = "azure_error"
    mapping: ClassVar[Dict[str, Bender]] = {
        "error": S("error") >> Bend(AzureManagedClusterPodIdentityProvisioningError.mapping)
    }
    error: Optional[AzureManagedClusterPodIdentityProvisioningError] = field(default=None, metadata={'description': 'An error response from the pod identity provisioning.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureManagedClusterPodIdentity:
    kind: ClassVar[str] = "azure_managed_cluster_pod_identity"
    mapping: ClassVar[Dict[str, Bender]] = {
        "binding_selector": S("bindingSelector"),
        "identity": S("identity") >> Bend(AzureUserAssignedIdentity.mapping),
        "name": S("name"),
        "namespace": S("namespace"),
        "provisioning_info": S("provisioningInfo") >> Bend(AzureError.mapping),
        "provisioning_state": S("provisioningState"),
    }
    binding_selector: Optional[str] = field(default=None, metadata={'description': 'The binding selector to use for the AzureIdentityBinding resource.'})  # fmt: skip
    identity: Optional[AzureUserAssignedIdentity] = field(default=None, metadata={'description': 'Details about a user assigned identity.'})  # fmt: skip
    name: Optional[str] = field(default=None, metadata={"description": "The name of the pod identity."})
    namespace: Optional[str] = field(default=None, metadata={"description": "The namespace of the pod identity."})
    provisioning_info: Optional[AzureError] = field(default=None, metadata={"description": ""})
    provisioning_state: Optional[str] = field(default=None, metadata={'description': 'The current provisioning state of the pod identity.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureManagedClusterPodIdentityException:
    kind: ClassVar[str] = "azure_managed_cluster_pod_identity_exception"
    mapping: ClassVar[Dict[str, Bender]] = {
        "name": S("name"),
        "namespace": S("namespace"),
        "pod_labels": S("podLabels"),
    }
    name: Optional[str] = field(default=None, metadata={"description": "The name of the pod identity exception."})
    namespace: Optional[str] = field(default=None, metadata={'description': 'The namespace of the pod identity exception.'})  # fmt: skip
    pod_labels: Optional[Dict[str, str]] = field(default=None, metadata={"description": "The pod labels to match."})


@define(eq=False, slots=False)
class AzureManagedClusterPodIdentityProfile:
    kind: ClassVar[str] = "azure_managed_cluster_pod_identity_profile"
    mapping: ClassVar[Dict[str, Bender]] = {
        "allow_network_plugin_kubenet": S("allowNetworkPluginKubenet"),
        "enabled": S("enabled"),
        "user_assigned_identities": S("userAssignedIdentities") >> ForallBend(AzureManagedClusterPodIdentity.mapping),
        "user_assigned_identity_exceptions": S("userAssignedIdentityExceptions")
        >> ForallBend(AzureManagedClusterPodIdentityException.mapping),
    }
    allow_network_plugin_kubenet: Optional[bool] = field(default=None, metadata={'description': 'Running in Kubenet is disabled by default due to the security related nature of AAD Pod Identity and the risks of IP spoofing. See [using Kubenet network plugin with AAD Pod Identity](https://docs.microsoft.com/azure/aks/use-azure-ad-pod-identity#using-kubenet-network-plugin-with-azure-active-directory-pod-managed-identities) for more information.'})  # fmt: skip
    enabled: Optional[bool] = field(default=None, metadata={'description': 'Whether the pod identity addon is enabled.'})  # fmt: skip
    user_assigned_identities: Optional[List[AzureManagedClusterPodIdentity]] = field(default=None, metadata={'description': 'The pod identities to use in the cluster.'})  # fmt: skip
    user_assigned_identity_exceptions: Optional[List[AzureManagedClusterPodIdentityException]] = field(default=None, metadata={'description': 'The pod identity exceptions to allow.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureManagedClusterOIDCIssuerProfile:
    kind: ClassVar[str] = "azure_managed_cluster_oidc_issuer_profile"
    mapping: ClassVar[Dict[str, Bender]] = {"enabled": S("enabled"), "issuer_url": S("issuerURL")}
    enabled: Optional[bool] = field(default=None, metadata={"description": "Whether the OIDC issuer is enabled."})
    issuer_url: Optional[str] = field(default=None, metadata={'description': 'The OIDC issuer url of the Managed Cluster.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureCountCountipv6:
    kind: ClassVar[str] = "azure_count_countipv6"
    mapping: ClassVar[Dict[str, Bender]] = {"count": S("count"), "count_i_pv6": S("countIPv6")}
    count: Optional[int] = field(default=None, metadata={'description': 'The desired number of IPv4 outbound IPs created/managed by Azure for the cluster load balancer. Allowed values must be in the range of 1 to 100 (inclusive). The default value is 1. '})  # fmt: skip
    count_i_pv6: Optional[int] = field(default=None, metadata={'description': 'The desired number of IPv6 outbound IPs created/managed by Azure for the cluster load balancer. Allowed values must be in the range of 1 to 100 (inclusive). The default value is 0 for single-stack and 1 for dual-stack. '})  # fmt: skip


@define(eq=False, slots=False)
class AzurePublicIPPrefixes:
    kind: ClassVar[str] = "azure_public_ip_prefixes"
    mapping: ClassVar[Dict[str, Bender]] = {
        "public_ip_prefixes": S("publicIPPrefixes", default=[]) >> ForallBend(S("id"))
    }
    public_ip_prefixes: Optional[List[str]] = field(default=None, metadata={'description': 'A list of public IP prefix resources.'})  # fmt: skip


@define(eq=False, slots=False)
class AzurePublicIPs:
    kind: ClassVar[str] = "azure_public_i_ps"
    mapping: ClassVar[Dict[str, Bender]] = {"public_i_ps": S("publicIPs", default=[]) >> ForallBend(S("id"))}
    public_i_ps: Optional[List[str]] = field(default=None, metadata={"description": "A list of public IP resources."})


@define(eq=False, slots=False)
class AzureManagedClusterLoadBalancerProfile:
    kind: ClassVar[str] = "azure_managed_cluster_load_balancer_profile"
    mapping: ClassVar[Dict[str, Bender]] = {
        "allocated_outbound_ports": S("allocatedOutboundPorts"),
        "effective_outbound_i_ps": S("effectiveOutboundIPs", default=[]) >> ForallBend(S("id")),
        "enable_multiple_standard_load_balancers": S("enableMultipleStandardLoadBalancers"),
        "idle_timeout_in_minutes": S("idleTimeoutInMinutes"),
        "managed_outbound_i_ps": S("managedOutboundIPs") >> Bend(AzureCountCountipv6.mapping),
        "outbound_i_ps": S("outboundIPs") >> Bend(AzurePublicIPs.mapping),
        "outbound_ip_prefixes": S("outboundIPPrefixes") >> Bend(AzurePublicIPPrefixes.mapping),
    }
    allocated_outbound_ports: Optional[int] = field(default=None, metadata={'description': 'The desired number of allocated SNAT ports per VM. Allowed values are in the range of 0 to 64000 (inclusive). The default value is 0 which results in Azure dynamically allocating ports.'})  # fmt: skip
    effective_outbound_i_ps: Optional[List[str]] = field(default=None, metadata={'description': 'The effective outbound IP resources of the cluster load balancer.'})  # fmt: skip
    enable_multiple_standard_load_balancers: Optional[bool] = field(default=None, metadata={'description': 'Enable multiple standard load balancers per AKS cluster or not.'})  # fmt: skip
    idle_timeout_in_minutes: Optional[int] = field(default=None, metadata={'description': 'Desired outbound flow idle timeout in minutes. Allowed values are in the range of 4 to 120 (inclusive). The default value is 30 minutes.'})  # fmt: skip
    managed_outbound_i_ps: Optional[AzureCountCountipv6] = field(default=None, metadata={'description': 'Desired managed outbound IPs for the cluster load balancer.'})  # fmt: skip
    outbound_i_ps: Optional[AzurePublicIPs] = field(default=None, metadata={'description': 'Desired outbound IP resources for the cluster load balancer.'})  # fmt: skip
    outbound_ip_prefixes: Optional[AzurePublicIPPrefixes] = field(default=None, metadata={'description': 'Desired outbound IP Prefix resources for the cluster load balancer.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureManagedClusterNATGatewayProfile:
    kind: ClassVar[str] = "azure_managed_cluster_nat_gateway_profile"
    mapping: ClassVar[Dict[str, Bender]] = {
        "effective_outbound_i_ps": S("effectiveOutboundIPs", default=[]) >> ForallBend(S("id")),
        "idle_timeout_in_minutes": S("idleTimeoutInMinutes"),
        "managed_outbound_ip_profile": S("managedOutboundIPProfile", "count"),
    }
    effective_outbound_i_ps: Optional[List[str]] = field(default=None, metadata={'description': 'The effective outbound IP resources of the cluster NAT gateway.'})  # fmt: skip
    idle_timeout_in_minutes: Optional[int] = field(default=None, metadata={'description': 'Desired outbound flow idle timeout in minutes. Allowed values are in the range of 4 to 120 (inclusive). The default value is 4 minutes.'})  # fmt: skip
    managed_outbound_ip_profile: Optional[int] = field(default=None, metadata={'description': 'Profile of the managed outbound IP resources of the managed cluster.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureContainerServiceNetworkProfile:
    kind: ClassVar[str] = "azure_container_service_network_profile"
    mapping: ClassVar[Dict[str, Bender]] = {
        "dns_service_ip": S("dnsServiceIP"),
        "ip_families": S("ipFamilies"),
        "load_balancer_profile": S("loadBalancerProfile") >> Bend(AzureManagedClusterLoadBalancerProfile.mapping),
        "load_balancer_sku": S("loadBalancerSku"),
        "nat_gateway_profile": S("natGatewayProfile") >> Bend(AzureManagedClusterNATGatewayProfile.mapping),
        "network_dataplane": S("networkDataplane"),
        "network_mode": S("networkMode"),
        "network_plugin": S("networkPlugin"),
        "network_plugin_mode": S("networkPluginMode"),
        "network_policy": S("networkPolicy"),
        "outbound_type": S("outboundType"),
        "pod_cidr": S("podCidr"),
        "pod_cidrs": S("podCidrs"),
        "service_cidr": S("serviceCidr"),
        "service_cidrs": S("serviceCidrs"),
    }
    dns_service_ip: Optional[str] = field(default=None, metadata={'description': 'An IP address assigned to the Kubernetes DNS service. It must be within the Kubernetes service address range specified in serviceCidr.'})  # fmt: skip
    ip_families: Optional[List[str]] = field(default=None, metadata={'description': 'IP families are used to determine single-stack or dual-stack clusters. For single-stack, the expected value is IPv4. For dual-stack, the expected values are IPv4 and IPv6.'})  # fmt: skip
    load_balancer_profile: Optional[AzureManagedClusterLoadBalancerProfile] = field(default=None, metadata={'description': 'Profile of the managed cluster load balancer.'})  # fmt: skip
    load_balancer_sku: Optional[str] = field(default=None, metadata={'description': 'The default is standard . See [Azure Load Balancer SKUs](https://docs.microsoft.com/azure/load-balancer/skus) for more information about the differences between load balancer SKUs.'})  # fmt: skip
    nat_gateway_profile: Optional[AzureManagedClusterNATGatewayProfile] = field(default=None, metadata={'description': 'Profile of the managed cluster NAT gateway.'})  # fmt: skip
    network_dataplane: Optional[str] = field(default=None, metadata={'description': 'Network dataplane used in the Kubernetes cluster.'})  # fmt: skip
    network_mode: Optional[str] = field(default=None, metadata={'description': 'This cannot be specified if networkPlugin is anything other than azure .'})  # fmt: skip
    network_plugin: Optional[str] = field(default=None, metadata={'description': 'Network plugin used for building the Kubernetes network.'})  # fmt: skip
    network_plugin_mode: Optional[str] = field(default=None, metadata={'description': 'The mode the network plugin should use.'})  # fmt: skip
    network_policy: Optional[str] = field(default=None, metadata={'description': 'Network policy used for building the Kubernetes network.'})  # fmt: skip
    outbound_type: Optional[str] = field(default=None, metadata={'description': 'This can only be set at cluster creation time and cannot be changed later. For more information see [egress outbound type](https://docs.microsoft.com/azure/aks/egress-outboundtype).'})  # fmt: skip
    pod_cidr: Optional[str] = field(default=None, metadata={'description': 'A CIDR notation IP range from which to assign pod IPs when kubenet is used.'})  # fmt: skip
    pod_cidrs: Optional[List[str]] = field(default=None, metadata={'description': 'One IPv4 CIDR is expected for single-stack networking. Two CIDRs, one for each IP family (IPv4/IPv6), is expected for dual-stack networking.'})  # fmt: skip
    service_cidr: Optional[str] = field(default=None, metadata={'description': 'A CIDR notation IP range from which to assign service cluster IPs. It must not overlap with any Subnet IP ranges.'})  # fmt: skip
    service_cidrs: Optional[List[str]] = field(default=None, metadata={'description': 'One IPv4 CIDR is expected for single-stack networking. Two CIDRs, one for each IP family (IPv4/IPv6), is expected for dual-stack networking. They must not overlap with any Subnet IP ranges.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureManagedClusterAADProfile:
    kind: ClassVar[str] = "azure_managed_cluster_aad_profile"
    mapping: ClassVar[Dict[str, Bender]] = {
        "admin_group_object_i_ds": S("adminGroupObjectIDs"),
        "client_app_id": S("clientAppID"),
        "enable_azure_rbac": S("enableAzureRBAC"),
        "managed": S("managed"),
        "server_app_id": S("serverAppID"),
        "server_app_secret": S("serverAppSecret"),
        "tenant_id": S("tenantID"),
    }
    admin_group_object_i_ds: Optional[List[str]] = field(default=None, metadata={'description': 'The list of AAD group object IDs that will have admin role of the cluster.'})  # fmt: skip
    client_app_id: Optional[str] = field(default=None, metadata={'description': '(DEPRECATED) The client AAD application ID. Learn more at https://aka.ms/aks/aad-legacy.'})  # fmt: skip
    enable_azure_rbac: Optional[bool] = field(default=None, metadata={'description': 'Whether to enable Azure RBAC for Kubernetes authorization.'})  # fmt: skip
    managed: Optional[bool] = field(default=None, metadata={"description": "Whether to enable managed AAD."})
    server_app_id: Optional[str] = field(default=None, metadata={'description': '(DEPRECATED) The server AAD application ID. Learn more at https://aka.ms/aks/aad-legacy.'})  # fmt: skip
    server_app_secret: Optional[str] = field(default=None, metadata={'description': '(DEPRECATED) The server AAD application secret. Learn more at https://aka.ms/aks/aad-legacy.'})  # fmt: skip
    tenant_id: Optional[str] = field(default=None, metadata={'description': 'The AAD tenant ID to use for authentication. If not specified, will use the tenant of the deployment subscription.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureManagedClusterAutoUpgradeProfile:
    kind: ClassVar[str] = "azure_managed_cluster_auto_upgrade_profile"
    mapping: ClassVar[Dict[str, Bender]] = {
        "node_os_upgrade_channel": S("nodeOSUpgradeChannel"),
        "upgrade_channel": S("upgradeChannel"),
    }
    node_os_upgrade_channel: Optional[str] = field(default=None, metadata={'description': 'Manner in which the OS on your nodes is updated. The default is NodeImage.'})  # fmt: skip
    upgrade_channel: Optional[str] = field(default=None, metadata={'description': 'For more information see [setting the AKS cluster auto-upgrade channel](https://docs.microsoft.com/azure/aks/upgrade-cluster#set-auto-upgrade-channel).'})  # fmt: skip


@define(eq=False, slots=False)
class AzureUpgradeOverrideSettings:
    kind: ClassVar[str] = "azure_upgrade_override_settings"
    mapping: ClassVar[Dict[str, Bender]] = {"force_upgrade": S("forceUpgrade"), "until": S("until")}
    force_upgrade: Optional[bool] = field(default=None, metadata={'description': 'Whether to force upgrade the cluster. Note that this option instructs upgrade operation to bypass upgrade protections such as checking for deprecated API usage. Enable this option only with caution.'})  # fmt: skip
    until: Optional[datetime] = field(default=None, metadata={'description': 'Until when the overrides are effective. Note that this only matches the start time of an upgrade, and the effectiveness won t change once an upgrade starts even if the `until` expires as upgrade proceeds. This field is not set by default. It must be set for the overrides to take effect.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureClusterUpgradeSettings:
    kind: ClassVar[str] = "azure_cluster_upgrade_settings"
    mapping: ClassVar[Dict[str, Bender]] = {
        "override_settings": S("overrideSettings") >> Bend(AzureUpgradeOverrideSettings.mapping)
    }
    override_settings: Optional[AzureUpgradeOverrideSettings] = field(default=None, metadata={'description': 'Settings for overrides when upgrading a cluster.'})  # fmt: skip


@define(eq=False, slots=False)
class AutoScalerProfile:
    kind: ClassVar[str] = "azure_auto_scaler_profile"
    mapping: ClassVar[Dict[str, Bender]] = {
        "balance_similar_node_groups": S("balance-similar-node-groups"),
        "expander": S("expander"),
        "max_empty_bulk_delete": S("max-empty-bulk-delete"),
        "max_graceful_termination_sec": S("max-graceful-termination-sec"),
        "max_node_provision_time": S("max-node-provision-time"),
        "max_total_unready_percentage": S("max-total-unready-percentage"),
        "new_pod_scale_up_delay": S("new-pod-scale-up-delay"),
        "ok_total_unready_count": S("ok-total-unready-count"),
        "scale_down_delay_after_add": S("scale-down-delay-after-add"),
        "scale_down_delay_after_delete": S("scale-down-delay-after-delete"),
        "scale_down_delay_after_failure": S("scale-down-delay-after-failure"),
        "scale_down_unneeded_time": S("scale-down-unneeded-time"),
        "scale_down_unready_time": S("scale-down-unready-time"),
        "scale_down_utilization_threshold": S("scale-down-utilization-threshold"),
        "scan_interval": S("scan-interval"),
        "skip_nodes_with_local_storage": S("skip-nodes-with-local-storage"),
        "skip_nodes_with_system_pods": S("skip-nodes-with-system-pods"),
    }
    balance_similar_node_groups: Optional[str] = field(default=None, metadata={'description': 'Valid values are true and false '})  # fmt: skip
    expander: Optional[str] = field(default=None, metadata={'description': 'If not specified, the default is random . See [expanders](https://github.com/kubernetes/autoscaler/blob/master/cluster-autoscaler/FAQ.md#what-are-expanders) for more information.'})  # fmt: skip
    max_empty_bulk_delete: Optional[str] = field(default=None, metadata={"description": "The default is 10."})
    max_graceful_termination_sec: Optional[str] = field(default=None, metadata={"description": "The default is 600."})
    max_node_provision_time: Optional[str] = field(default=None, metadata={'description': 'The default is 15m . Values must be an integer followed by an m . No unit of time other than minutes (m) is supported.'})  # fmt: skip
    max_total_unready_percentage: Optional[str] = field(default=None, metadata={'description': 'The default is 45. The maximum is 100 and the minimum is 0.'})  # fmt: skip
    new_pod_scale_up_delay: Optional[str] = field(default=None, metadata={'description': 'For scenarios like burst/batch scale where you don t want CA to act before the kubernetes scheduler could schedule all the pods, you can tell CA to ignore unscheduled pods before they re a certain age. The default is 0s . Values must be an integer followed by a unit ( s for seconds, m for minutes, h for hours, etc).'})  # fmt: skip
    ok_total_unready_count: Optional[str] = field(default=None, metadata={'description': 'This must be an integer. The default is 3.'})  # fmt: skip
    scale_down_delay_after_add: Optional[str] = field(default=None, metadata={'description': 'The default is 10m . Values must be an integer followed by an m . No unit of time other than minutes (m) is supported.'})  # fmt: skip
    scale_down_delay_after_delete: Optional[str] = field(default=None, metadata={'description': 'The default is the scan_interval. Values must be an integer followed by an m . No unit of time other than minutes (m) is supported.'})  # fmt: skip
    scale_down_delay_after_failure: Optional[str] = field(default=None, metadata={'description': 'The default is 3m . Values must be an integer followed by an m . No unit of time other than minutes (m) is supported.'})  # fmt: skip
    scale_down_unneeded_time: Optional[str] = field(default=None, metadata={'description': 'The default is 10m . Values must be an integer followed by an m . No unit of time other than minutes (m) is supported.'})  # fmt: skip
    scale_down_unready_time: Optional[str] = field(default=None, metadata={'description': 'The default is 20m . Values must be an integer followed by an m . No unit of time other than minutes (m) is supported.'})  # fmt: skip
    scale_down_utilization_threshold: Optional[str] = field(default=None, metadata={'description': 'The default is 0.5 .'})  # fmt: skip
    scan_interval: Optional[str] = field(default=None, metadata={'description': 'The default is 10 . Values must be an integer number of seconds.'})  # fmt: skip
    skip_nodes_with_local_storage: Optional[str] = field(default=None, metadata={'description': 'The default is true.'})  # fmt: skip
    skip_nodes_with_system_pods: Optional[str] = field(default=None, metadata={"description": "The default is true."})


@define(eq=False, slots=False)
class AzureManagedClusterAPIServerAccessProfile:
    kind: ClassVar[str] = "azure_managed_cluster_api_server_access_profile"
    mapping: ClassVar[Dict[str, Bender]] = {
        "authorized_ip_ranges": S("authorizedIPRanges"),
        "disable_run_command": S("disableRunCommand"),
        "enable_private_cluster": S("enablePrivateCluster"),
        "enable_private_cluster_public_fqdn": S("enablePrivateClusterPublicFQDN"),
        "private_dns_zone": S("privateDNSZone"),
    }
    authorized_ip_ranges: Optional[List[str]] = field(default=None, metadata={'description': 'IP ranges are specified in CIDR format, e.g. 137.117.106.88/29. This feature is not compatible with clusters that use Public IP Per Node, or clusters that are using a Basic Load Balancer. For more information see [API server authorized IP ranges](https://docs.microsoft.com/azure/aks/api-server-authorized-ip-ranges).'})  # fmt: skip
    disable_run_command: Optional[bool] = field(default=None, metadata={'description': 'Whether to disable run command for the cluster or not.'})  # fmt: skip
    enable_private_cluster: Optional[bool] = field(default=None, metadata={'description': 'For more details, see [Creating a private AKS cluster](https://docs.microsoft.com/azure/aks/private-clusters).'})  # fmt: skip
    enable_private_cluster_public_fqdn: Optional[bool] = field(default=None, metadata={'description': 'Whether to create additional public FQDN for private cluster or not.'})  # fmt: skip
    private_dns_zone: Optional[str] = field(default=None, metadata={'description': 'The default is System. For more details see [configure private DNS zone](https://docs.microsoft.com/azure/aks/private-clusters#configure-private-dns-zone). Allowed values are system and none .'})  # fmt: skip


@define(eq=False, slots=False)
class AzurePrivateLinkResource:
    kind: ClassVar[str] = "azure_private_link_resource"
    mapping: ClassVar[Dict[str, Bender]] = {
        "group_id": S("groupId"),
        "id": S("id"),
        "name": S("name"),
        "private_link_service_id": S("privateLinkServiceID"),
        "required_members": S("requiredMembers"),
        "type": S("type"),
    }
    group_id: Optional[str] = field(default=None, metadata={"description": "The group ID of the resource."})
    id: Optional[str] = field(default=None, metadata={"description": "The ID of the private link resource."})
    name: Optional[str] = field(default=None, metadata={"description": "The name of the private link resource."})
    private_link_service_id: Optional[str] = field(default=None, metadata={'description': 'The private link service ID of the resource, this field is exposed only to NRP internally.'})  # fmt: skip
    required_members: Optional[List[str]] = field(default=None, metadata={'description': 'The RequiredMembers of the resource'})  # fmt: skip
    type: Optional[str] = field(default=None, metadata={"description": "The resource type."})


@define(eq=False, slots=False)
class AzureManagedClusterHTTPProxyConfig:
    kind: ClassVar[str] = "azure_managed_cluster_http_proxy_config"
    mapping: ClassVar[Dict[str, Bender]] = {
        "http_proxy": S("httpProxy"),
        "https_proxy": S("httpsProxy"),
        "no_proxy": S("noProxy"),
        "trusted_ca": S("trustedCa"),
    }
    http_proxy: Optional[str] = field(default=None, metadata={"description": "The HTTP proxy server endpoint to use."})
    https_proxy: Optional[str] = field(default=None, metadata={'description': 'The HTTPS proxy server endpoint to use.'})  # fmt: skip
    no_proxy: Optional[List[str]] = field(default=None, metadata={'description': 'The endpoints that should not go through proxy.'})  # fmt: skip
    trusted_ca: Optional[str] = field(default=None, metadata={'description': 'Alternative CA cert to use for connecting to proxy servers.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureManagedClusterSecurityProfileDefender:
    kind: ClassVar[str] = "azure_managed_cluster_security_profile_defender"
    mapping: ClassVar[Dict[str, Bender]] = {
        "log_analytics_workspace_resource_id": S("logAnalyticsWorkspaceResourceId"),
        "security_monitoring": S("securityMonitoring", "enabled"),
    }
    log_analytics_workspace_resource_id: Optional[str] = field(default=None, metadata={'description': 'Resource ID of the Log Analytics workspace to be associated with Microsoft Defender. When Microsoft Defender is enabled, this field is required and must be a valid workspace resource ID. When Microsoft Defender is disabled, leave the field empty.'})  # fmt: skip
    security_monitoring: Optional[bool] = field(default=None, metadata={'description': 'Microsoft Defender settings for the security profile threat detection.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureAzureKeyVaultKms:
    kind: ClassVar[str] = "azure_azure_key_vault_kms"
    mapping: ClassVar[Dict[str, Bender]] = {
        "enabled": S("enabled"),
        "key_id": S("keyId"),
        "key_vault_network_access": S("keyVaultNetworkAccess"),
        "key_vault_resource_id": S("keyVaultResourceId"),
    }
    enabled: Optional[bool] = field(default=None, metadata={'description': 'Whether to enable Azure Key Vault key management service. The default is false.'})  # fmt: skip
    key_id: Optional[str] = field(default=None, metadata={'description': 'Identifier of Azure Key Vault key. See [key identifier format](https://docs.microsoft.com/en-us/azure/key-vault/general/about-keys-secrets-certificates#vault-name-and-object-name) for more details. When Azure Key Vault key management service is enabled, this field is required and must be a valid key identifier. When Azure Key Vault key management service is disabled, leave the field empty.'})  # fmt: skip
    key_vault_network_access: Optional[str] = field(default=None, metadata={'description': 'Network access of key vault. The possible values are `Public` and `Private`. `Public` means the key vault allows public access from all networks. `Private` means the key vault disables public access and enables private link. The default value is `Public`.'})  # fmt: skip
    key_vault_resource_id: Optional[str] = field(default=None, metadata={'description': 'Resource ID of key vault. When keyVaultNetworkAccess is `Private`, this field is required and must be a valid resource ID. When keyVaultNetworkAccess is `Public`, leave the field empty.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureManagedClusterSecurityProfileImageCleaner:
    kind: ClassVar[str] = "azure_managed_cluster_security_profile_image_cleaner"
    mapping: ClassVar[Dict[str, Bender]] = {"enabled": S("enabled"), "interval_hours": S("intervalHours")}
    enabled: Optional[bool] = field(default=None, metadata={'description': 'Whether to enable Image Cleaner on AKS cluster.'})  # fmt: skip
    interval_hours: Optional[int] = field(default=None, metadata={'description': 'Image Cleaner scanning interval in hours.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureManagedClusterSecurityProfile:
    kind: ClassVar[str] = "azure_managed_cluster_security_profile"
    mapping: ClassVar[Dict[str, Bender]] = {
        "azure_key_vault_kms": S("azureKeyVaultKms") >> Bend(AzureAzureKeyVaultKms.mapping),
        "defender": S("defender") >> Bend(AzureManagedClusterSecurityProfileDefender.mapping),
        "image_cleaner": S("imageCleaner") >> Bend(AzureManagedClusterSecurityProfileImageCleaner.mapping),
        "workload_identity": S("workloadIdentity", "enabled"),
    }
    azure_key_vault_kms: Optional[AzureAzureKeyVaultKms] = field(default=None, metadata={'description': 'Azure Key Vault key management service settings for the security profile.'})  # fmt: skip
    defender: Optional[AzureManagedClusterSecurityProfileDefender] = field(default=None, metadata={'description': 'Microsoft Defender settings for the security profile.'})  # fmt: skip
    image_cleaner: Optional[AzureManagedClusterSecurityProfileImageCleaner] = field(default=None, metadata={'description': 'Image Cleaner removes unused images from nodes, freeing up disk space and helping to reduce attack surface area. Here are settings for the security profile.'})  # fmt: skip
    workload_identity: Optional[bool] = field(default=None, metadata={'description': 'Workload identity settings for the security profile.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureManagedClusterStorageProfile:
    kind: ClassVar[str] = "azure_managed_cluster_storage_profile"
    mapping: ClassVar[Dict[str, Bender]] = {
        "blob_csi_driver": S("blobCSIDriver", "enabled"),
        "disk_csi_driver": S("diskCSIDriver", "enabled"),
        "file_csi_driver": S("fileCSIDriver", "enabled"),
        "snapshot_controller": S("snapshotController", "enabled"),
    }
    blob_csi_driver: Optional[bool] = field(default=None, metadata={'description': 'AzureBlob CSI Driver settings for the storage profile.'})  # fmt: skip
    disk_csi_driver: Optional[bool] = field(default=None, metadata={'description': 'AzureDisk CSI Driver settings for the storage profile.'})  # fmt: skip
    file_csi_driver: Optional[bool] = field(default=None, metadata={'description': 'AzureFile CSI Driver settings for the storage profile.'})  # fmt: skip
    snapshot_controller: Optional[bool] = field(default=None, metadata={'description': 'Snapshot Controller settings for the storage profile.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureManagedClusterWorkloadAutoScalerProfile:
    kind: ClassVar[str] = "azure_managed_cluster_workload_auto_scaler_profile"
    mapping: ClassVar[Dict[str, Bender]] = {
        "keda": S("keda", "enabled"),
        "vertical_pod_autoscaler": S("verticalPodAutoscaler", "enabled"),
    }
    keda: Optional[bool] = field(default=None, metadata={'description': 'KEDA (Kubernetes Event-driven Autoscaling) settings for the workload auto-scaler profile.'})  # fmt: skip
    vertical_pod_autoscaler: Optional[bool] = field(default=None, metadata={'description': 'VPA (Vertical Pod Autoscaler) settings for the workload auto-scaler profile.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureManagedClusterAzureMonitorProfileKubeStateMetrics:
    kind: ClassVar[str] = "azure_managed_cluster_azure_monitor_profile_kube_state_metrics"
    mapping: ClassVar[Dict[str, Bender]] = {
        "metric_annotations_allow_list": S("metricAnnotationsAllowList"),
        "metric_labels_allowlist": S("metricLabelsAllowlist"),
    }
    metric_annotations_allow_list: Optional[str] = field(default=None, metadata={'description': 'Comma-separated list of Kubernetes annotation keys that will be used in the resource s labels metric (Example: namespaces=[kubernetes.io/team,...],pods=[kubernetes.io/team],... ). By default the metric contains only resource name and namespace labels.'})  # fmt: skip
    metric_labels_allowlist: Optional[str] = field(default=None, metadata={'description': 'Comma-separated list of additional Kubernetes label keys that will be used in the resource s labels metric (Example: namespaces=[k8s-label-1,k8s-label-n,...],pods=[app],... ). By default the metric contains only resource name and namespace labels.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureManagedClusterAzureMonitorProfileMetrics:
    kind: ClassVar[str] = "azure_managed_cluster_azure_monitor_profile_metrics"
    mapping: ClassVar[Dict[str, Bender]] = {
        "enabled": S("enabled"),
        "kube_state_metrics": S("kubeStateMetrics")
        >> Bend(AzureManagedClusterAzureMonitorProfileKubeStateMetrics.mapping),
    }
    enabled: Optional[bool] = field(default=None, metadata={'description': 'Whether to enable or disable the Azure Managed Prometheus addon for Prometheus monitoring. See aka.ms/AzureManagedPrometheus-aks-enable for details on enabling and disabling.'})  # fmt: skip
    kube_state_metrics: Optional[AzureManagedClusterAzureMonitorProfileKubeStateMetrics] = field(default=None, metadata={'description': 'Kube State Metrics profile for the Azure Managed Prometheus addon. These optional settings are for the kube-state-metrics pod that is deployed with the addon. See aka.ms/AzureManagedPrometheus-optional-parameters for details.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureManagedClusterAzureMonitorProfile:
    kind: ClassVar[str] = "azure_managed_cluster_azure_monitor_profile"
    mapping: ClassVar[Dict[str, Bender]] = {
        "metrics": S("metrics") >> Bend(AzureManagedClusterAzureMonitorProfileMetrics.mapping)
    }
    metrics: Optional[AzureManagedClusterAzureMonitorProfileMetrics] = field(default=None, metadata={'description': 'Metrics profile for the Azure Monitor managed service for Prometheus addon. Collect out-of-the-box Kubernetes infrastructure metrics to send to an Azure Monitor Workspace and configure additional scraping for custom targets. See aka.ms/AzureManagedPrometheus for an overview.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureIstioIngressGateway:
    kind: ClassVar[str] = "azure_istio_ingress_gateway"
    mapping: ClassVar[Dict[str, Bender]] = {"enabled": S("enabled"), "mode": S("mode")}
    enabled: Optional[bool] = field(default=None, metadata={"description": "Whether to enable the ingress gateway."})
    mode: Optional[str] = field(default=None, metadata={"description": "Mode of an ingress gateway."})


@define(eq=False, slots=False)
class AzureIstioEgressGateway:
    kind: ClassVar[str] = "azure_istio_egress_gateway"
    mapping: ClassVar[Dict[str, Bender]] = {"enabled": S("enabled"), "node_selector": S("nodeSelector")}
    enabled: Optional[bool] = field(default=None, metadata={"description": "Whether to enable the egress gateway."})
    node_selector: Optional[Dict[str, str]] = field(default=None, metadata={'description': 'NodeSelector for scheduling the egress gateway.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureIstioComponents:
    kind: ClassVar[str] = "azure_istio_components"
    mapping: ClassVar[Dict[str, Bender]] = {
        "egress_gateways": S("egressGateways") >> ForallBend(AzureIstioEgressGateway.mapping),
        "ingress_gateways": S("ingressGateways") >> ForallBend(AzureIstioIngressGateway.mapping),
    }
    egress_gateways: Optional[List[AzureIstioEgressGateway]] = field(default=None, metadata={'description': 'Istio egress gateways.'})  # fmt: skip
    ingress_gateways: Optional[List[AzureIstioIngressGateway]] = field(default=None, metadata={'description': 'Istio ingress gateways.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureIstioPluginCertificateAuthority:
    kind: ClassVar[str] = "azure_istio_plugin_certificate_authority"
    mapping: ClassVar[Dict[str, Bender]] = {
        "cert_chain_object_name": S("certChainObjectName"),
        "cert_object_name": S("certObjectName"),
        "key_object_name": S("keyObjectName"),
        "key_vault_id": S("keyVaultId"),
        "root_cert_object_name": S("rootCertObjectName"),
    }
    cert_chain_object_name: Optional[str] = field(default=None, metadata={'description': 'Certificate chain object name in Azure Key Vault.'})  # fmt: skip
    cert_object_name: Optional[str] = field(default=None, metadata={'description': 'Intermediate certificate object name in Azure Key Vault.'})  # fmt: skip
    key_object_name: Optional[str] = field(default=None, metadata={'description': 'Intermediate certificate private key object name in Azure Key Vault.'})  # fmt: skip
    key_vault_id: Optional[str] = field(default=None, metadata={"description": "The resource ID of the Key Vault."})
    root_cert_object_name: Optional[str] = field(default=None, metadata={'description': 'Root certificate object name in Azure Key Vault.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureIstioCertificateAuthority:
    kind: ClassVar[str] = "azure_istio_certificate_authority"
    mapping: ClassVar[Dict[str, Bender]] = {"plugin": S("plugin") >> Bend(AzureIstioPluginCertificateAuthority.mapping)}
    plugin: Optional[AzureIstioPluginCertificateAuthority] = field(default=None, metadata={'description': 'Plugin certificates information for Service Mesh.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureIstioServiceMesh:
    kind: ClassVar[str] = "azure_istio_service_mesh"
    mapping: ClassVar[Dict[str, Bender]] = {
        "certificate_authority": S("certificateAuthority") >> Bend(AzureIstioCertificateAuthority.mapping),
        "components": S("components") >> Bend(AzureIstioComponents.mapping),
        "revisions": S("revisions"),
    }
    certificate_authority: Optional[AzureIstioCertificateAuthority] = field(default=None, metadata={'description': 'Istio Service Mesh Certificate Authority (CA) configuration. For now, we only support plugin certificates as described here https://aka.ms/asm-plugin-ca'})  # fmt: skip
    components: Optional[AzureIstioComponents] = field(default=None, metadata={'description': 'Istio components configuration.'})  # fmt: skip
    revisions: Optional[List[str]] = field(default=None, metadata={'description': 'The list of revisions of the Istio control plane. When an upgrade is not in progress, this holds one value. When canary upgrade is in progress, this can only hold two consecutive values. For more information, see: https://learn.microsoft.com/en-us/azure/aks/istio-upgrade'})  # fmt: skip


@define(eq=False, slots=False)
class AzureServiceMeshProfile:
    kind: ClassVar[str] = "azure_service_mesh_profile"
    mapping: ClassVar[Dict[str, Bender]] = {
        "istio": S("istio") >> Bend(AzureIstioServiceMesh.mapping),
        "mode": S("mode"),
    }
    istio: Optional[AzureIstioServiceMesh] = field(default=None, metadata={'description': 'Istio service mesh configuration.'})  # fmt: skip
    mode: Optional[str] = field(default=None, metadata={"description": "Mode of the service mesh."})


@define(eq=False, slots=False)
class AzureManagedCluster(AzureResource):
    kind: ClassVar[str] = "azure_managed_cluster"
    api_spec: ClassVar[AzureApiSpec] = AzureApiSpec(
        service="containerservice",
        version="2023-08-01",
        path="/subscriptions/{subscriptionId}/providers/Microsoft.ContainerService/managedClusters",
        path_parameters=["subscriptionId"],
        query_parameters=["api-version"],
        access_path="value",
        expect_array=True,
    )
    reference_kinds: ClassVar[ModelReference] = {
        "successors": {"default": ["azure_disk_encryption_set", "azure_virtual_machine_scale_set"]},
    }
    mapping: ClassVar[Dict[str, Bender]] = AzureTrackedResource.mapping | {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "aad_profile": S("properties", "aadProfile") >> Bend(AzureManagedClusterAADProfile.mapping),
        "addon_profiles": S("properties", "addonProfiles"),
        "agent_pool_profiles": S("properties") >> S("agentPoolProfiles", default=[]) >> ForallBend(S("name")),
        "api_server_access_profile": S("properties", "apiServerAccessProfile")
        >> Bend(AzureManagedClusterAPIServerAccessProfile.mapping),
        "auto_scaler_profile": S("properties", "autoScalerProfile") >> Bend(AutoScalerProfile.mapping),
        "auto_upgrade_profile": S("properties", "autoUpgradeProfile")
        >> Bend(AzureManagedClusterAutoUpgradeProfile.mapping),
        "azure_monitor_profile": S("properties", "azureMonitorProfile")
        >> Bend(AzureManagedClusterAzureMonitorProfile.mapping),
        "azure_portal_fqdn": S("properties", "azurePortalFQDN"),
        "current_kubernetes_version": S("properties", "currentKubernetesVersion"),
        "disable_local_accounts": S("properties", "disableLocalAccounts"),
        "disk_encryption_set_id": S("properties", "diskEncryptionSetID"),
        "dns_prefix": S("properties", "dnsPrefix"),
        "enable_pod_security_policy": S("properties", "enablePodSecurityPolicy"),
        "enable_rbac": S("properties", "enableRBAC"),
        "extended_location": S("extendedLocation") >> Bend(AzureExtendedLocation.mapping),
        "fqdn": S("properties", "fqdn"),
        "fqdn_subdomain": S("properties", "fqdnSubdomain"),
        "http_proxy_config": S("properties", "httpProxyConfig") >> Bend(AzureManagedClusterHTTPProxyConfig.mapping),
        "managed_cluster_identity": S("identity") >> Bend(AzureManagedClusterIdentity.mapping),
        "identity_profile": S("properties", "identityProfile"),
        "kubernetes_version": S("properties", "kubernetesVersion"),
        "linux_profile": S("properties", "linuxProfile") >> Bend(AzureContainerServiceLinuxProfile.mapping),
        "max_agent_pools": S("properties", "maxAgentPools"),
        "container_service_network_profile": S("properties", "networkProfile")
        >> Bend(AzureContainerServiceNetworkProfile.mapping),
        "node_resource_group": S("properties", "nodeResourceGroup"),
        "oidc_issuer_profile": S("properties", "oidcIssuerProfile")
        >> Bend(AzureManagedClusterOIDCIssuerProfile.mapping),
        "pod_identity_profile": S("properties", "podIdentityProfile")
        >> Bend(AzureManagedClusterPodIdentityProfile.mapping),
        "power_state": S("properties", "powerState", "code"),
        "private_fqdn": S("properties", "privateFQDN"),
        "private_link_resources": S("properties", "privateLinkResources")
        >> ForallBend(AzurePrivateLinkResource.mapping),
        "provisioning_state": S("properties", "provisioningState"),
        "public_network_access": S("properties", "publicNetworkAccess"),
        "resource_uid": S("properties", "resourceUID"),
        "security_profile": S("properties", "securityProfile") >> Bend(AzureManagedClusterSecurityProfile.mapping),
        "service_mesh_profile": S("properties", "serviceMeshProfile") >> Bend(AzureServiceMeshProfile.mapping),
        "service_principal_profile": S("properties", "servicePrincipalProfile")
        >> Bend(AzureManagedClusterServicePrincipalProfile.mapping),
        "managed_cluster_sku": S("sku") >> Bend(AzureManagedClusterSKU.mapping),
        "managed_cluster_storage_profile": S("properties", "storageProfile")
        >> Bend(AzureManagedClusterStorageProfile.mapping),
        "support_plan": S("properties", "supportPlan"),
        "upgrade_settings": S("properties", "upgradeSettings") >> Bend(AzureClusterUpgradeSettings.mapping),
        "windows_profile": S("properties", "windowsProfile") >> Bend(AzureManagedClusterWindowsProfile.mapping),
        "workload_auto_scaler_profile": S("properties", "workloadAutoScalerProfile")
        >> Bend(AzureManagedClusterWorkloadAutoScalerProfile.mapping),
    }
    aad_profile: Optional[AzureManagedClusterAADProfile] = field(default=None, metadata={'description': 'For more details see [managed AAD on AKS](https://docs.microsoft.com/azure/aks/managed-aad).'})  # fmt: skip
    addon_profiles: Optional[Dict[str, AzureManagedClusterAddonProfile]] = field(default=None, metadata={'description': 'The profile of managed cluster add-on.'})  # fmt: skip
    agent_pool_profiles: Optional[List[str]] = field(default=None, metadata={"description": "The agent pool properties."})  # fmt: skip
    api_server_access_profile: Optional[AzureManagedClusterAPIServerAccessProfile] = field(default=None, metadata={'description': 'Access profile for managed cluster API server.'})  # fmt: skip
    auto_scaler_profile: Optional[AutoScalerProfile] = field(default=None, metadata={'description': 'Parameters to be applied to the cluster-autoscaler when enabled'})  # fmt: skip
    auto_upgrade_profile: Optional[AzureManagedClusterAutoUpgradeProfile] = field(default=None, metadata={'description': 'Auto upgrade profile for a managed cluster.'})  # fmt: skip
    azure_monitor_profile: Optional[AzureManagedClusterAzureMonitorProfile] = field(default=None, metadata={'description': 'Azure Monitor addon profiles for monitoring the managed cluster.'})  # fmt: skip
    azure_portal_fqdn: Optional[str] = field(default=None, metadata={'description': 'The Azure Portal requires certain Cross-Origin Resource Sharing (CORS) headers to be sent in some responses, which Kubernetes APIServer doesn t handle by default. This special FQDN supports CORS, allowing the Azure Portal to function properly.'})  # fmt: skip
    current_kubernetes_version: Optional[str] = field(default=None, metadata={'description': 'If kubernetesVersion was a fully specified version <major.minor.patch>, this field will be exactly equal to it. If kubernetesVersion was <major.minor>, this field will contain the full <major.minor.patch> version being used.'})  # fmt: skip
    disable_local_accounts: Optional[bool] = field(default=None, metadata={'description': 'If set to true, getting static credentials will be disabled for this cluster. This must only be used on Managed Clusters that are AAD enabled. For more details see [disable local accounts](https://docs.microsoft.com/azure/aks/managed-aad#disable-local-accounts-preview).'})  # fmt: skip
    disk_encryption_set_id: Optional[str] = field(default=None, metadata={'description': 'This is of the form: /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Compute/diskEncryptionSets/{encryptionSetName} '})  # fmt: skip
    dns_prefix: Optional[str] = field(default=None, metadata={'description': 'This cannot be updated once the Managed Cluster has been created.'})  # fmt: skip
    enable_pod_security_policy: Optional[bool] = field(default=None, metadata={'description': '(DEPRECATED) Whether to enable Kubernetes pod security policy (preview). PodSecurityPolicy was deprecated in Kubernetes v1.21, and removed from Kubernetes in v1.25. Learn more at https://aka.ms/k8s/psp and https://aka.ms/aks/psp.'})  # fmt: skip
    enable_rbac: Optional[bool] = field(default=None, metadata={'description': 'Whether to enable Kubernetes Role-Based Access Control.'})  # fmt: skip
    extended_location: Optional[AzureExtendedLocation] = field(default=None, metadata={'description': 'The complex type of the extended location.'})  # fmt: skip
    fqdn: Optional[str] = field(default=None, metadata={"description": "The FQDN of the master pool."})
    fqdn_subdomain: Optional[str] = field(default=None, metadata={'description': 'This cannot be updated once the Managed Cluster has been created.'})  # fmt: skip
    http_proxy_config: Optional[AzureManagedClusterHTTPProxyConfig] = field(default=None, metadata={'description': 'Cluster HTTP proxy configuration.'})  # fmt: skip
    managed_cluster_identity: Optional[AzureManagedClusterIdentity] = field(default=None, metadata={'description': 'Identity for the managed cluster.'})  # fmt: skip
    identity_profile: Optional[Dict[str, AzureUserAssignedIdentity]] = field(default=None, metadata={"description": "Identities associated with the cluster."})  # fmt: skip
    kubernetes_version: Optional[str] = field(default=None, metadata={'description': 'Both patch version <major.minor.patch> (e.g. 1.20.13) and <major.minor> (e.g. 1.20) are supported. When <major.minor> is specified, the latest supported GA patch version is chosen automatically. Updating the cluster with the same <major.minor> once it has been created (e.g. 1.14.x -> 1.14) will not trigger an upgrade, even if a newer patch version is available. When you upgrade a supported AKS cluster, Kubernetes minor versions cannot be skipped. All upgrades must be performed sequentially by major version number. For example, upgrades between 1.14.x -> 1.15.x or 1.15.x -> 1.16.x are allowed, however 1.14.x -> 1.16.x is not allowed. See [upgrading an AKS cluster](https://docs.microsoft.com/azure/aks/upgrade-cluster) for more details.'})  # fmt: skip
    linux_profile: Optional[AzureContainerServiceLinuxProfile] = field(default=None, metadata={'description': 'Profile for Linux VMs in the container service cluster.'})  # fmt: skip
    max_agent_pools: Optional[int] = field(default=None, metadata={'description': 'The max number of agent pools for the managed cluster.'})  # fmt: skip
    container_service_network_profile: Optional[AzureContainerServiceNetworkProfile] = field(default=None, metadata={'description': 'Profile of network configuration.'})  # fmt: skip
    node_resource_group: Optional[str] = field(default=None, metadata={'description': 'The name of the resource group containing agent pool nodes.'})  # fmt: skip
    oidc_issuer_profile: Optional[AzureManagedClusterOIDCIssuerProfile] = field(default=None, metadata={'description': 'The OIDC issuer profile of the Managed Cluster.'})  # fmt: skip
    pod_identity_profile: Optional[AzureManagedClusterPodIdentityProfile] = field(default=None, metadata={'description': 'See [use AAD pod identity](https://docs.microsoft.com/azure/aks/use-azure-ad-pod-identity) for more details on pod identity integration.'})  # fmt: skip
    power_state: Optional[str] = field(default=None, metadata={'description': 'Describes the Power State of the cluster'})  # fmt: skip
    private_fqdn: Optional[str] = field(default=None, metadata={"description": "The FQDN of private cluster."})
    private_link_resources: Optional[List[AzurePrivateLinkResource]] = field(default=None, metadata={'description': 'Private link resources associated with the cluster.'})  # fmt: skip
    provisioning_state: Optional[str] = field(default=None, metadata={'description': 'The current provisioning state.'})  # fmt: skip
    public_network_access: Optional[str] = field(default=None, metadata={'description': 'Allow or deny public network access for AKS'})  # fmt: skip
    resource_uid: Optional[str] = field(default=None, metadata={'description': 'The resourceUID uniquely identifies ManagedClusters that reuse ARM ResourceIds (i.e: create, delete, create sequence)'})  # fmt: skip
    security_profile: Optional[AzureManagedClusterSecurityProfile] = field(default=None, metadata={'description': 'Security profile for the container service cluster.'})  # fmt: skip
    service_mesh_profile: Optional[AzureServiceMeshProfile] = field(default=None, metadata={'description': 'Service mesh profile for a managed cluster.'})  # fmt: skip
    service_principal_profile: Optional[AzureManagedClusterServicePrincipalProfile] = field(default=None, metadata={'description': 'Information about a service principal identity for the cluster to use for manipulating Azure APIs.'})  # fmt: skip
    managed_cluster_sku: Optional[AzureManagedClusterSKU] = field(default=None, metadata={'description': 'The SKU of a Managed Cluster.'})  # fmt: skip
    managed_cluster_storage_profile: Optional[AzureManagedClusterStorageProfile] = field(default=None, metadata={'description': 'Storage profile for the container service cluster.'})  # fmt: skip
    support_plan: Optional[str] = field(default=None, metadata={'description': 'Different support tiers for AKS managed clusters'})  # fmt: skip
    upgrade_settings: Optional[AzureClusterUpgradeSettings] = field(default=None, metadata={'description': 'Settings for upgrading a cluster.'})  # fmt: skip
    windows_profile: Optional[AzureManagedClusterWindowsProfile] = field(default=None, metadata={'description': 'Profile for Windows VMs in the managed cluster.'})  # fmt: skip
    workload_auto_scaler_profile: Optional[AzureManagedClusterWorkloadAutoScalerProfile] = field(default=None, metadata={'description': 'Workload Auto-scaler profile for the managed cluster.'})  # fmt: skip

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        from fix_plugin_azure.resource.compute import AzureDiskEncryptionSet, AzureVirtualMachineScaleSet

        if disk_id := self.disk_encryption_set_id:
            builder.add_edge(self, edge_type=EdgeType.default, clazz=AzureDiskEncryptionSet, id=disk_id)

        if agent_pool_profiles := self.agent_pool_profiles:
            vmss_agent_pool_names_and_ids = self._get_poolnames_and_vmss_ids(builder)
            for agent_pool_profile_name in agent_pool_profiles:
                for info in vmss_agent_pool_names_and_ids:
                    pool_name, vmss_id = info
                    if agent_pool_profile_name == pool_name:
                        builder.add_edge(
                            self, edge_type=EdgeType.default, clazz=AzureVirtualMachineScaleSet, id=vmss_id
                        )

    def _get_poolnames_and_vmss_ids(self, builder: GraphBuilder) -> List[Tuple[str, str]]:
        from fix_plugin_azure.resource.compute import AzureVirtualMachineScaleSet

        return [
            (poolname, vmss_id)
            for vmss in builder.nodes(clazz=AzureVirtualMachineScaleSet)
            if (poolname := vmss.tags.get("aks-managed-poolName")) and (vmss_id := vmss.id)
        ]


@define(eq=False, slots=False)
class AzureProxyResource:
    kind: ClassVar[str] = "azure_proxy_resource"
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "name": S("name"),
        "system_data": S("systemData") >> Bend(AzureSystemData.mapping),
        "type": S("type"),
    }
    id: Optional[str] = field(default=None, metadata={'description': 'Fully qualified resource ID for the resource. Ex - /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}'})  # fmt: skip
    name: Optional[str] = field(default=None, metadata={"description": "The name of the resource"})
    system_data: Optional[AzureSystemData] = field(default=None, metadata={'description': 'Metadata pertaining to creation and last modification of the resource.'})  # fmt: skip
    type: Optional[str] = field(default=None, metadata={'description': 'The type of the resource. E.g. Microsoft.Compute/virtualMachines or Microsoft.Storage/storageAccounts '})  # fmt: skip


@define(eq=False, slots=False)
class AzureCompatibleVersions:
    kind: ClassVar[str] = "azure_compatible_versions"
    mapping: ClassVar[Dict[str, Bender]] = {"name": S("name"), "versions": S("versions")}
    name: Optional[str] = field(default=None, metadata={"description": "The product/service name."})
    versions: Optional[List[str]] = field(default=None, metadata={'description': 'Product/service versions compatible with a service mesh add-on revision.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureMeshRevision:
    kind: ClassVar[str] = "azure_mesh_revision"
    mapping: ClassVar[Dict[str, Bender]] = {
        "compatible_with": S("compatibleWith") >> ForallBend(AzureCompatibleVersions.mapping),
        "revision": S("revision"),
        "upgrades": S("upgrades"),
    }
    compatible_with: Optional[List[AzureCompatibleVersions]] = field(default=None, metadata={'description': 'List of items this revision of service mesh is compatible with, and their associated versions.'})  # fmt: skip
    revision: Optional[str] = field(default=None, metadata={"description": "The revision of the mesh release."})
    upgrades: Optional[List[str]] = field(default=None, metadata={'description': 'List of revisions available for upgrade of a specific mesh revision'})  # fmt: skip


@define(eq=False, slots=False)
class AzureOSOptionProperty:
    kind: ClassVar[str] = "azure_os_option_property"
    mapping: ClassVar[Dict[str, Bender]] = {"enable_fips_image": S("enable-fips-image"), "os_type": S("os-type")}
    enable_fips_image: Optional[bool] = field(default=None, metadata={'description': 'Whether the image is FIPS-enabled.'})  # fmt: skip
    os_type: Optional[str] = field(default=None, metadata={"description": "The OS type."})


@define(eq=False, slots=False)
class AzureKubernetesSnapshot(AzureResource):
    kind: ClassVar[str] = "azure_kubernetes_snapshot"
    api_spec: ClassVar[AzureApiSpec] = AzureApiSpec(
        service="containerservice",
        version="2023-08-01",
        path="/subscriptions/{subscriptionId}/providers/Microsoft.ContainerService/snapshots",
        path_parameters=["subscriptionId"],
        query_parameters=["api-version"],
        access_path="value",
        expect_array=True,
    )
    reference_kinds: ClassVar[ModelReference] = {
        "predecessors": {"default": ["azure_managed_cluster"]},
    }
    mapping: ClassVar[Dict[str, Bender]] = AzureTrackedResource.mapping | {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "ctime": S("systemData", "createdAt"),
        "creation_data_source_id": S("properties", "creationData", "sourceResourceId"),
        "enable_fips": S("properties", "enableFIPS"),
        "kubernetes_version": S("properties", "kubernetesVersion"),
        "node_image_version": S("properties", "nodeImageVersion"),
        "os_sku": S("properties", "osSku"),
        "os_type": S("properties", "osType"),
        "snapshot_type": S("properties", "snapshotType"),
        "vm_size": S("properties", "vmSize"),
    }
    creation_data_source_id: Optional[str] = field(default=None, metadata={'description': 'Data used when creating a target resource from a source resource.'})  # fmt: skip
    enable_fips: Optional[bool] = field(default=None, metadata={"description": "Whether to use a FIPS-enabled OS."})
    kubernetes_version: Optional[str] = field(default=None, metadata={"description": "The version of Kubernetes."})
    node_image_version: Optional[str] = field(default=None, metadata={"description": "The version of node image."})
    os_sku: Optional[str] = field(default=None, metadata={'description': 'Specifies the OS SKU used by the agent pool. The default is Ubuntu if OSType is Linux. The default is Windows2019 when Kubernetes <= 1.24 or Windows2022 when Kubernetes >= 1.25 if OSType is Windows.'})  # fmt: skip
    os_type: Optional[str] = field(default=None, metadata={'description': 'The operating system type. The default is Linux.'})  # fmt: skip
    snapshot_type: Optional[str] = field(default=None, metadata={'description': 'The type of a snapshot. The default is NodePool.'})  # fmt: skip
    vm_size: Optional[str] = field(default=None, metadata={"description": "The size of the VM."})

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if agent_pool_id := self.creation_data_source_id:
            cluster_id = "/".join((agent_pool_id.split("/")[:-2]))
            builder.add_edge(self, edge_type=EdgeType.default, reverse=True, clazz=AzureManagedCluster, id=cluster_id)


resources: List[Type[AzureResource]] = [AzureManagedCluster, AzureFleet, AzureKubernetesSnapshot]
