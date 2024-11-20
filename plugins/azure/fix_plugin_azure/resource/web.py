import logging
from datetime import datetime
from typing import ClassVar, Optional, Dict, List, Type, Any

from attr import define, field

from fix_plugin_azure.azure_client import AzureResourceSpec
from fix_plugin_azure.resource.base import (
    MicrosoftResource,
    AzureSku,
    AzurePrivateEndpointConnection,
    AzureManagedServiceIdentity,
    AzureExtendedLocation,
    GraphBuilder,
    parse_json,
)
from fix_plugin_azure.resource.keyvault import AzureKeyVault
from fix_plugin_azure.utils import NoneIfEmpty
from fixlib.baseresources import BaseServerlessFunction, ModelReference
from fixlib.json_bender import Bender, S, ForallBend, Bend, MapDict
from fixlib.types import Json

log = logging.getLogger("fix.plugins.azure")
service_name = "app-service"


@define(eq=False, slots=False)
class AzureVirtualNetworkProfile:
    kind: ClassVar[str] = "azure_virtual_network_profile"
    mapping: ClassVar[Dict[str, Bender]] = {"id": S("id"), "name": S("name"), "subnet": S("subnet"), "type": S("type")}
    id: Optional[str] = field(default=None, metadata={"description": "Resource id of the virtual network"})
    name: Optional[str] = field(default=None, metadata={"description": "Name of the virtual network (read-only)"})
    subnet: Optional[str] = field(default=None, metadata={"description": "Subnet within the virtual network"})
    type: Optional[str] = field(default=None, metadata={'description': 'Resource type of the virtual network (read-only)'})  # fmt: skip


@define(eq=False, slots=False)
class AzureProxyOnlyResource:
    kind: ClassVar[str] = "azure_proxy_only_resource"
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "azure_kind": S("kind"),
        "name": S("name"),
        "type": S("type"),
    }
    id: Optional[str] = field(default=None, metadata={"description": "Resource Id."})
    azure_kind: Optional[str] = field(default=None, metadata={"description": "Kind of resource."})
    name: Optional[str] = field(default=None, metadata={"description": "Resource Name."})
    type: Optional[str] = field(default=None, metadata={"description": "Resource type."})


@define(eq=False, slots=False)
class AzureHostingEnvironmentProfile:
    kind: ClassVar[str] = "azure_hosting_environment_profile"
    mapping: ClassVar[Dict[str, Bender]] = {"id": S("id"), "name": S("name"), "type": S("type")}
    id: Optional[str] = field(default=None, metadata={"description": "Resource ID of the App Service Environment."})
    name: Optional[str] = field(default=None, metadata={"description": "Name of the App Service Environment."})
    type: Optional[str] = field(default=None, metadata={'description': 'Resource type of the App Service Environment.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureKubeEnvironmentProfile:
    kind: ClassVar[str] = "azure_kube_environment_profile"
    mapping: ClassVar[Dict[str, Bender]] = {"id": S("id"), "name": S("name"), "type": S("type")}
    id: Optional[str] = field(default=None, metadata={"description": "Resource ID of the Kubernetes Environment."})
    name: Optional[str] = field(default=None, metadata={"description": "Name of the Kubernetes Environment."})
    type: Optional[str] = field(default=None, metadata={"description": "Resource type of the Kubernetes Environment."})


@define(eq=False, slots=False)
class AzureWebAppServicePlan(MicrosoftResource):
    kind: ClassVar[str] = "azure_web_app_service_plan"
    _kind_display: ClassVar[str] = "Azure Web App Service Plan"
    _kind_service: ClassVar[Optional[str]] = service_name
    _kind_description: ClassVar[str] = "Azure Web App Service Plan is a resource that defines the compute capacity for running web apps in Azure. It specifies the number of virtual machines, their size, and features available to the hosted applications. Users can choose from various tiers, each offering different performance levels, storage options, and additional capabilities to match their application requirements."  # fmt: skip
    _docs_url: ClassVar[str] = "https://learn.microsoft.com/en-us/azure/app-service/overview-hosting-plans"
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "config", "group": "misc"}
    api_spec: ClassVar[AzureResourceSpec] = AzureResourceSpec(
        service="web",
        version="2023-12-01",
        path="/subscriptions/{subscriptionId}/providers/Microsoft.Web/serverfarms",
        path_parameters=["subscriptionId"],
        query_parameters=["api-version"],
        access_path="value",
        expect_array=True,
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "elastic_scale_enabled": S("properties", "elasticScaleEnabled"),
        "extended_location": S("extendedLocation") >> Bend(AzureExtendedLocation.mapping),
        "free_offer_expiration_time": S("properties", "freeOfferExpirationTime"),
        "geo_region": S("properties", "geoRegion"),
        "hosting_environment_profile": S("properties", "hostingEnvironmentProfile")
        >> Bend(AzureHostingEnvironmentProfile.mapping),
        "hyper_v": S("properties", "hyperV"),
        "is_spot": S("properties", "isSpot"),
        "is_xenon": S("properties", "isXenon"),
        "azure_kind": S("kind"),
        "kube_environment_profile": S("properties", "kubeEnvironmentProfile")
        >> Bend(AzureKubeEnvironmentProfile.mapping),
        "maximum_elastic_worker_count": S("properties", "maximumElasticWorkerCount"),
        "maximum_number_of_workers": S("properties", "maximumNumberOfWorkers"),
        "number_of_sites": S("properties", "numberOfSites"),
        "number_of_workers": S("properties", "numberOfWorkers"),
        "per_site_scaling": S("properties", "perSiteScaling"),
        "provisioning_state": S("properties", "provisioningState"),
        "reserved": S("properties", "reserved"),
        "resource_group": S("properties", "resourceGroup"),
        "azure_sku": S("sku") >> Bend(AzureSku.mapping),
        "spot_expiration_time": S("properties", "spotExpirationTime"),
        "status": S("properties", "status"),
        "subscription": S("properties", "subscription"),
        "target_worker_count": S("properties", "targetWorkerCount"),
        "target_worker_size_id": S("properties", "targetWorkerSizeId"),
        "worker_tier_name": S("properties", "workerTierName"),
        "zone_redundant": S("properties", "zoneRedundant"),
    }
    elastic_scale_enabled: Optional[bool] = field(default=None, metadata={'description': 'ServerFarm supports ElasticScale. Apps in this plan will scale as if the ServerFarm was ElasticPremium sku'})  # fmt: skip
    extended_location: Optional[AzureExtendedLocation] = field(default=None, metadata={'description': 'Extended Location.'})  # fmt: skip
    free_offer_expiration_time: Optional[datetime] = field(default=None, metadata={'description': 'The time when the server farm free offer expires.'})  # fmt: skip
    geo_region: Optional[str] = field(default=None, metadata={'description': 'Geographical location for the App Service plan.'})  # fmt: skip
    hosting_environment_profile: Optional[AzureHostingEnvironmentProfile] = field(default=None, metadata={'description': 'Specification for an App Service Environment to use for this resource.'})  # fmt: skip
    hyper_v: Optional[bool] = field(default=None, metadata={'description': 'If Hyper-V container app service plan <code>true</code>, <code>false</code> otherwise.'})  # fmt: skip
    is_spot: Optional[bool] = field(default=None, metadata={'description': 'If <code>true</code>, this App Service Plan owns spot instances.'})  # fmt: skip
    is_xenon: Optional[bool] = field(default=None, metadata={'description': 'Obsolete: If Hyper-V container app service plan <code>true</code>, <code>false</code> otherwise.'})  # fmt: skip
    azure_kind: Optional[str] = field(default=None, metadata={"description": "Kind of resource."})
    kube_environment_profile: Optional[AzureKubeEnvironmentProfile] = field(default=None, metadata={'description': 'Specification for a Kubernetes Environment to use for this resource.'})  # fmt: skip
    maximum_elastic_worker_count: Optional[int] = field(default=None, metadata={'description': 'Maximum number of total workers allowed for this ElasticScaleEnabled App Service Plan'})  # fmt: skip
    maximum_number_of_workers: Optional[int] = field(default=None, metadata={'description': 'Maximum number of instances that can be assigned to this App Service plan.'})  # fmt: skip
    number_of_sites: Optional[int] = field(default=None, metadata={'description': 'Number of apps assigned to this App Service plan.'})  # fmt: skip
    number_of_workers: Optional[int] = field(default=None, metadata={'description': 'The number of instances that are assigned to this App Service plan.'})  # fmt: skip
    per_site_scaling: Optional[bool] = field(default=None, metadata={'description': 'If <code>true</code>, apps assigned to this App Service plan can be scaled independently. If <code>false</code>, apps assigned to this App Service plan will scale to all instances of the plan.'})  # fmt: skip
    reserved: Optional[bool] = field(default=None, metadata={'description': 'If Linux app service plan <code>true</code>, <code>false</code> otherwise.'})  # fmt: skip
    resource_group: Optional[str] = field(default=None, metadata={'description': 'Resource group of the App Service plan.'})  # fmt: skip
    azure_sku: Optional[AzureSku] = field(default=None, metadata={'description': 'Description of a SKU for a scalable resource.'})  # fmt: skip
    spot_expiration_time: Optional[datetime] = field(default=None, metadata={'description': 'The time when the server farm expires. Valid only if it is a spot server farm.'})  # fmt: skip
    status: Optional[str] = field(default=None, metadata={"description": "App Service plan status."})
    subscription: Optional[str] = field(default=None, metadata={"description": "App Service plan subscription."})
    target_worker_count: Optional[int] = field(default=None, metadata={"description": "Scaling worker count."})
    target_worker_size_id: Optional[int] = field(default=None, metadata={"description": "Scaling worker size ID."})
    worker_tier_name: Optional[str] = field(default=None, metadata={'description': 'Target worker tier assigned to the App Service plan.'})  # fmt: skip
    zone_redundant: Optional[bool] = field(default=None, metadata={'description': 'If <code>true</code>, this App Service Plan will perform availability zone balancing. If <code>false</code>, this App Service Plan will not perform availability zone balancing.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureWebCertificate(MicrosoftResource):
    kind: ClassVar[str] = "azure_web_certificate"
    _kind_display: ClassVar[str] = "Azure Web Certificate"
    _kind_service: ClassVar[Optional[str]] = service_name
    _kind_description: ClassVar[str] = "Azure Web Certificate is a digital credential issued by Microsoft Azure for websites hosted on its platform. It verifies the identity and security of web applications, ensuring encrypted connections between users and servers. This certificate helps protect data in transit, prevents unauthorized access, and enhances trust in Azure-hosted websites for both site owners and visitors."  # fmt: skip
    _docs_url: ClassVar[str] = "https://learn.microsoft.com/en-us/azure/app-service/configure-ssl-certificate"
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "certificate", "group": "compute"}
    api_spec: ClassVar[AzureResourceSpec] = AzureResourceSpec(
        service="web",
        version="2023-12-01",
        path="/subscriptions/{subscriptionId}/providers/Microsoft.Web/certificates",
        path_parameters=["subscriptionId"],
        query_parameters=["api-version"],
        access_path="value",
        expect_array=True,
    )
    _reference_kinds: ClassVar[ModelReference] = {
        "predecessors": {
            "default": [
                "azure_web_app_service_plan",
                AzureKeyVault.kind,
            ]
        },
    }
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "ctime": S("properties", "issueDate"),
        "canonical_name": S("properties", "canonicalName"),
        "cer_blob": S("properties", "cerBlob"),
        "domain_validation_method": S("properties", "domainValidationMethod"),
        "expiration_date": S("properties", "expirationDate"),
        "friendly_name": S("properties", "friendlyName"),
        "host_names": S("properties", "hostNames"),
        "hosting_environment_profile": S("properties", "hostingEnvironmentProfile")
        >> Bend(AzureHostingEnvironmentProfile.mapping),
        "issue_date": S("properties", "issueDate"),
        "issuer": S("properties", "issuer"),
        "key_vault_id": S("properties", "keyVaultId"),
        "key_vault_secret_name": S("properties", "keyVaultSecretName"),
        "key_vault_secret_status": S("properties", "keyVaultSecretStatus"),
        "azure_kind": S("kind"),
        "password": S("properties", "password"),
        "pfx_blob": S("properties", "pfxBlob"),
        "public_key_hash": S("properties", "publicKeyHash"),
        "self_link": S("properties", "selfLink"),
        "server_farm_id": S("properties", "serverFarmId"),
        "site_name": S("properties", "siteName"),
        "subject_name": S("properties", "subjectName"),
        "thumbprint": S("properties", "thumbprint"),
        "valid": S("properties", "valid"),
    }
    canonical_name: Optional[str] = field(default=None, metadata={'description': 'CNAME of the certificate to be issued via free certificate'})  # fmt: skip
    cer_blob: Optional[str] = field(default=None, metadata={"description": "Raw bytes of .cer file"})
    domain_validation_method: Optional[str] = field(default=None, metadata={'description': 'Method of domain validation for free cert'})  # fmt: skip
    expiration_date: Optional[datetime] = field(default=None, metadata={"description": "Certificate expiration date."})
    friendly_name: Optional[str] = field(default=None, metadata={"description": "Friendly name of the certificate."})
    host_names: Optional[List[str]] = field(
        default=None, metadata={"description": "Host names the certificate applies to."}
    )
    hosting_environment_profile: Optional[AzureHostingEnvironmentProfile] = field(default=None, metadata={'description': 'Specification for an App Service Environment to use for this resource.'})  # fmt: skip
    issue_date: Optional[datetime] = field(default=None, metadata={"description": "Certificate issue Date."})
    issuer: Optional[str] = field(default=None, metadata={"description": "Certificate issuer."})
    key_vault_id: Optional[str] = field(default=None, metadata={"description": "Key Vault Csm resource Id."})
    key_vault_secret_name: Optional[str] = field(default=None, metadata={"description": "Key Vault secret name."})
    key_vault_secret_status: Optional[str] = field(default=None, metadata={'description': 'Status of the Key Vault secret.'})  # fmt: skip
    azure_kind: Optional[str] = field(default=None, metadata={"description": "Kind of resource."})
    password: Optional[str] = field(default=None, metadata={"description": "Certificate password."})
    pfx_blob: Optional[str] = field(default=None, metadata={"description": "Pfx blob."})
    public_key_hash: Optional[str] = field(default=None, metadata={"description": "Public key hash."})
    self_link: Optional[str] = field(default=None, metadata={"description": "Self link."})
    server_farm_id: Optional[str] = field(default=None, metadata={'description': 'Resource ID of the associated App Service plan, formatted as: /subscriptions/{subscriptionID}/resourceGroups/{groupName}/providers/Microsoft.Web/serverfarms/{appServicePlanName} .'})  # fmt: skip
    site_name: Optional[str] = field(default=None, metadata={"description": "App name."})
    subject_name: Optional[str] = field(default=None, metadata={"description": "Subject name of the certificate."})
    thumbprint: Optional[str] = field(default=None, metadata={"description": "Certificate thumbprint."})
    valid: Optional[bool] = field(default=None, metadata={"description": "Is the certificate valid?."})

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if server_farm_id := self.server_farm_id:
            builder.add_edge(self, clazz=AzureWebAppServicePlan, reverse=True, id=server_farm_id)
        if key_vault_id := self.key_vault_id:
            builder.add_edge(self, clazz=AzureKeyVault, reverse=True, id=key_vault_id)


@define(eq=False, slots=False)
class AzureTrafficWeight:
    kind: ClassVar[str] = "azure_traffic_weight"
    mapping: ClassVar[Dict[str, Bender]] = {
        "latest_revision": S("latestRevision"),
        "revision_name": S("revisionName"),
        "weight": S("weight"),
    }
    latest_revision: Optional[bool] = field(default=None, metadata={'description': 'Indicates that the traffic weight belongs to a latest stable revision'})  # fmt: skip
    revision_name: Optional[str] = field(default=None, metadata={"description": "Name of a revision"})
    weight: Optional[int] = field(default=None, metadata={"description": "Traffic weight assigned to a revision"})


@define(eq=False, slots=False)
class AzureIngress:
    kind: ClassVar[str] = "azure_ingress"
    mapping: ClassVar[Dict[str, Bender]] = {
        "allow_insecure": S("allowInsecure"),
        "external": S("external"),
        "fqdn": S("fqdn"),
        "target_port": S("targetPort"),
        "traffic": S("traffic") >> ForallBend(AzureTrafficWeight.mapping),
        "transport": S("transport"),
    }
    allow_insecure: Optional[bool] = field(default=None, metadata={'description': 'Bool indicating if HTTP connections to is allowed. If set to false HTTP connections are automatically redirected to HTTPS connections'})  # fmt: skip
    external: Optional[bool] = field(default=None, metadata={'description': 'Bool indicating if app exposes an external http endpoint'})  # fmt: skip
    fqdn: Optional[str] = field(default=None, metadata={"description": "Hostname."})
    target_port: Optional[int] = field(default=None, metadata={'description': 'Target Port in containers for traffic from ingress'})  # fmt: skip
    traffic: Optional[List[AzureTrafficWeight]] = field(default=None, metadata={"description": ""})
    transport: Optional[str] = field(default=None, metadata={"description": "Ingress transport protocol"})


@define(eq=False, slots=False)
class AzureRegistryCredentials:
    kind: ClassVar[str] = "azure_registry_credentials"
    mapping: ClassVar[Dict[str, Bender]] = {
        "password_secret_ref": S("passwordSecretRef"),
        "server": S("server"),
        "username": S("username"),
    }
    password_secret_ref: Optional[str] = field(default=None, metadata={'description': 'The name of the Secret that contains the registry login password'})  # fmt: skip
    server: Optional[str] = field(default=None, metadata={"description": "Container Registry Server"})
    username: Optional[str] = field(default=None, metadata={"description": "Container Registry Username"})


@define(eq=False, slots=False)
class AzureConfiguration:
    kind: ClassVar[str] = "azure_configuration"
    mapping: ClassVar[Dict[str, Bender]] = {
        "active_revisions_mode": S("activeRevisionsMode"),
        "ingress": S("ingress") >> Bend(AzureIngress.mapping),
        "registries": S("registries") >> ForallBend(AzureRegistryCredentials.mapping),
        "secrets": S("secrets") >> MapDict(S("name"), S("value")),
    }
    active_revisions_mode: Optional[str] = field(default=None, metadata={'description': 'ActiveRevisionsMode controls how active revisions are handled for the Container app: <list><item>Multiple: multiple revisions can be active. If no value if provided, this is the default</item><item>Single: Only one revision can be active at a time. Revision weights can not be used in this mode</item></list>'})  # fmt: skip
    ingress: Optional[AzureIngress] = field(default=None, metadata={'description': 'Container App Ingress configuration.'})  # fmt: skip
    registries: Optional[List[AzureRegistryCredentials]] = field(default=None, metadata={'description': 'Collection of private container registry credentials for containers used by the Container app'})  # fmt: skip
    secrets: Optional[Dict[str, str]] = field(default=None, metadata={'description': 'Collection of secrets used by a Container app'})  # fmt: skip


@define(eq=False, slots=False)
class AzureEnvironmentVar:
    kind: ClassVar[str] = "azure_environment_var"
    mapping: ClassVar[Dict[str, Bender]] = {"name": S("name"), "secret_ref": S("secretRef"), "value": S("value")}
    name: Optional[str] = field(default=None, metadata={"description": "Environment variable name."})
    secret_ref: Optional[str] = field(default=None, metadata={'description': 'Name of the Container App secret from which to pull the environment variable value.'})  # fmt: skip
    value: Optional[str] = field(default=None, metadata={"description": "Non-secret environment variable value."})


@define(eq=False, slots=False)
class AzureContainerResources:
    kind: ClassVar[str] = "azure_container_resources"
    mapping: ClassVar[Dict[str, Bender]] = {"cpu": S("cpu"), "memory": S("memory")}
    cpu: Optional[float] = field(default=None, metadata={"description": "Required CPU in cores, e.g. 0.5"})
    memory: Optional[str] = field(default=None, metadata={"description": "Required memory, e.g. 250Mb "})


@define(eq=False, slots=False)
class AzureContainer:
    kind: ClassVar[str] = "azure_container"
    mapping: ClassVar[Dict[str, Bender]] = {
        "args": S("args"),
        "command": S("command"),
        "env": S("env") >> ForallBend(AzureEnvironmentVar.mapping),
        "image": S("image"),
        "name": S("name"),
        "resources": S("resources") >> Bend(AzureContainerResources.mapping),
    }
    args: Optional[List[str]] = field(default=None, metadata={"description": "Container start command arguments."})
    command: Optional[List[str]] = field(default=None, metadata={"description": "Container start command."})
    env: Optional[List[AzureEnvironmentVar]] = field(default=None, metadata={'description': 'Container environment variables.'})  # fmt: skip
    image: Optional[str] = field(default=None, metadata={"description": "Container image tag."})
    name: Optional[str] = field(default=None, metadata={"description": "Custom container name."})
    resources: Optional[AzureContainerResources] = field(default=None, metadata={'description': 'Container App container resource requirements.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureScale:
    kind: ClassVar[str] = "azure_scale"
    mapping: ClassVar[Dict[str, Bender]] = {
        "max_replicas": S("maxReplicas"),
        "min_replicas": S("minReplicas"),
    }
    max_replicas: Optional[int] = field(default=None, metadata={'description': 'Optional. Maximum number of container replicas. Defaults to 10 if not set.'})  # fmt: skip
    min_replicas: Optional[int] = field(default=None, metadata={'description': 'Optional. Minimum number of container replicas.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureDaprMetadata:
    kind: ClassVar[str] = "azure_dapr_metadata"
    mapping: ClassVar[Dict[str, Bender]] = {"name": S("name"), "secret_ref": S("secretRef"), "value": S("value")}
    name: Optional[str] = field(default=None, metadata={"description": "Metadata property name."})
    secret_ref: Optional[str] = field(default=None, metadata={'description': 'Name of the Container App secret from which to pull the metadata property value.'})  # fmt: skip
    value: Optional[str] = field(default=None, metadata={"description": "Metadata property value."})


@define(eq=False, slots=False)
class AzureDaprComponent:
    kind: ClassVar[str] = "azure_dapr_component"
    mapping: ClassVar[Dict[str, Bender]] = {
        "metadata": S("metadata") >> ForallBend(AzureDaprMetadata.mapping),
        "name": S("name"),
        "type": S("type"),
        "version": S("version"),
    }
    metadata: Optional[List[AzureDaprMetadata]] = field(default=None, metadata={"description": "Component metadata"})
    name: Optional[str] = field(default=None, metadata={"description": "Component name"})
    type: Optional[str] = field(default=None, metadata={"description": "Component type"})
    version: Optional[str] = field(default=None, metadata={"description": "Component version"})


@define(eq=False, slots=False)
class AzureDapr:
    kind: ClassVar[str] = "azure_dapr"
    mapping: ClassVar[Dict[str, Bender]] = {
        "app_id": S("appId"),
        "app_port": S("appPort"),
        "components": S("components") >> ForallBend(AzureDaprComponent.mapping),
        "enabled": S("enabled"),
    }
    app_id: Optional[str] = field(default=None, metadata={"description": "Dapr application identifier"})
    app_port: Optional[int] = field(default=None, metadata={"description": "Port on which the Dapr side car"})
    components: Optional[List[AzureDaprComponent]] = field(default=None, metadata={'description': 'Collection of Dapr components'})  # fmt: skip
    enabled: Optional[bool] = field(default=None, metadata={'description': 'Boolean indicating if the Dapr side car is enabled'})  # fmt: skip


@define(eq=False, slots=False)
class AzureTemplate:
    kind: ClassVar[str] = "azure_template"
    mapping: ClassVar[Dict[str, Bender]] = {
        "containers": S("containers") >> ForallBend(AzureContainer.mapping),
        "dapr": S("dapr") >> Bend(AzureDapr.mapping),
        "revision_suffix": S("revisionSuffix"),
        "scale": S("scale") >> Bend(AzureScale.mapping),
    }
    containers: Optional[List[AzureContainer]] = field(default=None, metadata={'description': 'List of container definitions for the Container App.'})  # fmt: skip
    dapr: Optional[AzureDapr] = field(default=None, metadata={"description": "Container App Dapr configuration."})
    revision_suffix: Optional[str] = field(default=None, metadata={'description': 'User friendly suffix that is appended to the revision name'})  # fmt: skip
    scale: Optional[AzureScale] = field(default=None, metadata={'description': 'Container App scaling configurations.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureWebContainerApp(MicrosoftResource):
    kind: ClassVar[str] = "azure_web_container_app"
    _kind_display: ClassVar[str] = "Azure Web Container App"
    _kind_service: ClassVar[Optional[str]] = service_name
    _kind_description: ClassVar[str] = "Azure Web Container App is a cloud service for deploying containerized web applications. It runs and manages containers in a serverless environment, handling infrastructure tasks like scaling and load balancing. The service supports various programming languages and frameworks, integrates with Azure services, and offers features for monitoring, security, and continuous deployment of containerized applications."  # fmt: skip
    _docs_url: ClassVar[str] = "https://learn.microsoft.com/en-us/azure/container-apps/"
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "application", "group": "compute"}
    api_spec: ClassVar[AzureResourceSpec] = AzureResourceSpec(
        service="web",
        version="2021-03-01",
        path="/subscriptions/{subscriptionId}/providers/Microsoft.Web/containerApps",
        path_parameters=["subscriptionId"],
        query_parameters=["api-version"],
        access_path="value",
        expect_array=True,
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "container_configuration": S("properties", "configuration") >> Bend(AzureConfiguration.mapping),
        "azure_kind": S("kind"),
        "kube_environment_id": S("properties", "kubeEnvironmentId"),
        "latest_revision_fqdn": S("properties", "latestRevisionFqdn"),
        "latest_revision_name": S("properties", "latestRevisionName"),
        "provisioning_state": S("properties", "provisioningState"),
        "template": S("properties", "template") >> Bend(AzureTemplate.mapping),
    }
    container_configuration: Optional[AzureConfiguration] = field(default=None, metadata={'description': 'Non versioned Container App configuration properties that define the mutable settings of a Container app'})  # fmt: skip
    azure_kind: Optional[str] = field(default=None, metadata={"description": "Kind of resource."})
    kube_environment_id: Optional[str] = field(default=None, metadata={'description': 'Resource ID of the Container App s KubeEnvironment.'})  # fmt: skip
    latest_revision_fqdn: Optional[str] = field(default=None, metadata={'description': 'Fully Qualified Domain Name of the latest revision of the Container App.'})  # fmt: skip
    latest_revision_name: Optional[str] = field(default=None, metadata={'description': 'Name of the latest revision of the Container App.'})  # fmt: skip
    template: Optional[AzureTemplate] = field(default=None, metadata={'description': 'Container App versioned application definition. Defines the desired state of an immutable revision. Any changes to this section Will result in a new revision being created'})  # fmt: skip


@define(eq=False, slots=False)
class AzureAddress:
    kind: ClassVar[str] = "azure_address"
    mapping: ClassVar[Dict[str, Bender]] = {
        "address1": S("address1"),
        "address2": S("address2"),
        "city": S("city"),
        "country": S("country"),
        "postal_code": S("postalCode"),
        "state": S("state"),
    }
    address1: Optional[str] = field(default=None, metadata={"description": "Address 1"})
    address2: Optional[str] = field(default=None, metadata={"description": "Address 2"})
    city: Optional[str] = field(default=None, metadata={"description": "City"})
    country: Optional[str] = field(default=None, metadata={"description": "Country"})
    postal_code: Optional[str] = field(default=None, metadata={"description": "Postal code"})
    state: Optional[str] = field(default=None, metadata={"description": "State"})


@define(eq=False, slots=False)
class AzureContact:
    kind: ClassVar[str] = "azure_contact"
    mapping: ClassVar[Dict[str, Bender]] = {
        "address_mailing": S("addressMailing") >> Bend(AzureAddress.mapping),
        "email": S("email"),
        "fax": S("fax"),
        "job_title": S("jobTitle"),
        "name_first": S("nameFirst"),
        "name_last": S("nameLast"),
        "name_middle": S("nameMiddle"),
        "organization": S("organization"),
        "phone": S("phone"),
    }
    address_mailing: Optional[AzureAddress] = field(default=None, metadata={'description': 'Address information for domain registration'})  # fmt: skip
    email: Optional[str] = field(default=None, metadata={"description": "Email address"})
    fax: Optional[str] = field(default=None, metadata={"description": "Fax number"})
    job_title: Optional[str] = field(default=None, metadata={"description": "Job title"})
    name_first: Optional[str] = field(default=None, metadata={"description": "First name"})
    name_last: Optional[str] = field(default=None, metadata={"description": "Last name"})
    name_middle: Optional[str] = field(default=None, metadata={"description": "Middle name"})
    organization: Optional[str] = field(default=None, metadata={"description": "Organization"})
    phone: Optional[str] = field(default=None, metadata={"description": "Phone number"})


@define(eq=False, slots=False)
class AzureHostName:
    kind: ClassVar[str] = "azure_host_name"
    mapping: ClassVar[Dict[str, Bender]] = {
        "azure_resource_name": S("azureResourceName"),
        "azure_resource_type": S("azureResourceType"),
        "custom_host_name_dns_record_type": S("customHostNameDnsRecordType"),
        "host_name_type": S("hostNameType"),
        "name": S("name"),
        "site_names": S("siteNames"),
    }
    azure_resource_name: Optional[str] = field(default=None, metadata={'description': 'Name of the Azure resource the hostname is assigned to. If it is assigned to a traffic manager then it will be the traffic manager name otherwise it will be the website name'})  # fmt: skip
    azure_resource_type: Optional[str] = field(default=None, metadata={'description': 'Type of the Azure resource the hostname is assigned to'})  # fmt: skip
    custom_host_name_dns_record_type: Optional[str] = field(default=None, metadata={'description': 'Type of the Dns record'})  # fmt: skip
    host_name_type: Optional[str] = field(default=None, metadata={"description": "Type of the hostname"})
    name: Optional[str] = field(default=None, metadata={"description": "Name of the hostname"})
    site_names: Optional[List[str]] = field(default=None, metadata={'description': 'List of sites the hostname is assigned to. This list will have more than one site only if the hostname is pointing to a Traffic Manager'})  # fmt: skip


@define(eq=False, slots=False)
class AzureDomainPurchaseConsent:
    kind: ClassVar[str] = "azure_domain_purchase_consent"
    mapping: ClassVar[Dict[str, Bender]] = {
        "agreed_at": S("agreedAt"),
        "agreed_by": S("agreedBy"),
        "agreement_keys": S("agreementKeys"),
    }
    agreed_at: Optional[datetime] = field(default=None, metadata={'description': 'Timestamp when the agreements were accepted'})  # fmt: skip
    agreed_by: Optional[str] = field(default=None, metadata={"description": "Client IP address"})
    agreement_keys: Optional[List[str]] = field(default=None, metadata={'description': 'List of applicable legal agreement keys. This list can be retrieved using ListLegalAgreements Api under TopLevelDomain resource'})  # fmt: skip


@define(eq=False, slots=False)
class AzureWebDomain(MicrosoftResource):
    kind: ClassVar[str] = "azure_web_domain"
    _kind_display: ClassVar[str] = "Azure Web Domain"
    _kind_service: ClassVar[Optional[str]] = service_name
    _kind_description: ClassVar[str] = "Azure Web Domain is a service provided by Microsoft Azure that manages domain names for web applications. It offers domain registration, DNS configuration, and integration with other Azure services. Users can purchase domains, set up DNS records, and connect their domains to Azure-hosted websites or applications, simplifying web hosting and domain management within the Azure ecosystem."  # fmt: skip
    _docs_url: ClassVar[str] = "https://learn.microsoft.com/en-us/azure/app-service/manage-custom-dns-buy-domain"
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "dns", "group": "networking"}
    api_spec: ClassVar[AzureResourceSpec] = AzureResourceSpec(
        service="web",
        version="2023-12-01",
        path="/subscriptions/{subscriptionId}/providers/Microsoft.DomainRegistration/domains",
        path_parameters=["subscriptionId"],
        query_parameters=["api-version"],
        access_path="value",
        expect_array=True,
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "auto_renew": S("properties", "autoRenew"),
        "consent": S("properties", "consent") >> Bend(AzureDomainPurchaseConsent.mapping),
        "contact_admin": S("properties", "contactAdmin") >> Bend(AzureContact.mapping),
        "contact_billing": S("properties", "contactBilling") >> Bend(AzureContact.mapping),
        "contact_registrant": S("properties", "contactRegistrant") >> Bend(AzureContact.mapping),
        "contact_tech": S("properties", "contactTech") >> Bend(AzureContact.mapping),
        "created_time": S("properties", "createdTime"),
        "domain_not_renewable_reasons": S("properties", "domainNotRenewableReasons"),
        "expiration_time": S("properties", "expirationTime"),
        "azure_kind": S("kind"),
        "last_renewed_time": S("properties", "lastRenewedTime"),
        "managed_host_names": S("properties", "managedHostNames") >> ForallBend(AzureHostName.mapping),
        "name_servers": S("properties", "nameServers"),
        "privacy": S("properties", "privacy"),
        "provisioning_state": S("properties", "provisioningState"),
        "ready_for_dns_record_management": S("properties", "readyForDnsRecordManagement"),
        "registration_status": S("properties", "registrationStatus"),
    }
    auto_renew: Optional[bool] = field(default=None, metadata={'description': 'If true then domain will renewed automatically'})  # fmt: skip
    consent: Optional[AzureDomainPurchaseConsent] = field(default=None, metadata={'description': 'Domain purchase consent object representing acceptance of applicable legal agreements'})  # fmt: skip
    contact_admin: Optional[AzureContact] = field(default=None, metadata={'description': 'Contact information for domain registration. If Domain Privacy option is not selected then the contact information will be made publicly available through the Whois directories as per ICANN requirements.'})  # fmt: skip
    contact_billing: Optional[AzureContact] = field(default=None, metadata={'description': 'Contact information for domain registration. If Domain Privacy option is not selected then the contact information will be made publicly available through the Whois directories as per ICANN requirements.'})  # fmt: skip
    contact_registrant: Optional[AzureContact] = field(default=None, metadata={'description': 'Contact information for domain registration. If Domain Privacy option is not selected then the contact information will be made publicly available through the Whois directories as per ICANN requirements.'})  # fmt: skip
    contact_tech: Optional[AzureContact] = field(default=None, metadata={'description': 'Contact information for domain registration. If Domain Privacy option is not selected then the contact information will be made publicly available through the Whois directories as per ICANN requirements.'})  # fmt: skip
    created_time: Optional[datetime] = field(default=None, metadata={"description": "Domain creation timestamp"})
    domain_not_renewable_reasons: Optional[List[str]] = field(default=None, metadata={'description': 'Reasons why domain is not renewable'})  # fmt: skip
    expiration_time: Optional[datetime] = field(default=None, metadata={"description": "Domain expiration timestamp"})
    azure_kind: Optional[str] = field(default=None, metadata={"description": "Kind of resource"})
    last_renewed_time: Optional[datetime] = field(default=None, metadata={'description': 'Timestamp when the domain was renewed last time'})  # fmt: skip
    managed_host_names: Optional[List[AzureHostName]] = field(default=None, metadata={'description': 'All hostnames derived from the domain and assigned to Azure resources'})  # fmt: skip
    name_servers: Optional[List[str]] = field(default=None, metadata={"description": "Name servers"})
    privacy: Optional[bool] = field(default=None, metadata={'description': 'If true then domain privacy is enabled for this domain'})  # fmt: skip
    ready_for_dns_record_management: Optional[bool] = field(default=None, metadata={'description': 'If true then Azure can assign this domain to Web Apps. This value will be true if domain registration status is active and it is hosted on name servers Azure has programmatic access to'})  # fmt: skip
    registration_status: Optional[str] = field(default=None, metadata={"description": "Domain registration status"})


@define(eq=False, slots=False)
class AzureWorkerPool:
    kind: ClassVar[str] = "azure_worker_pool"
    mapping: ClassVar[Dict[str, Bender]] = {
        "compute_mode": S("properties", "computeMode"),
        "id": S("id"),
        "instance_names": S("properties", "instanceNames"),
        "azure_kind": S("kind"),
        "location": S("location"),
        "name": S("name"),
        "azure_sku": S("sku") >> Bend(AzureSku.mapping),
        "tags": S("tags"),
        "type": S("type"),
        "worker_count": S("properties", "workerCount"),
        "worker_size": S("properties", "workerSize"),
        "worker_size_id": S("properties", "workerSizeId"),
    }
    compute_mode: Optional[str] = field(default=None, metadata={"description": "Shared or dedicated web app hosting"})
    id: Optional[str] = field(default=None, metadata={"description": "Resource Id"})
    instance_names: Optional[List[str]] = field(default=None, metadata={'description': 'Names of all instances in the worker pool (read only)'})  # fmt: skip
    azure_kind: Optional[str] = field(default=None, metadata={"description": "Kind of resource"})
    location: Optional[str] = field(default=None, metadata={"description": "Resource Location"})
    name: Optional[str] = field(default=None, metadata={"description": "Resource Name"})
    azure_sku: Optional[AzureSku] = field(default=None, metadata={'description': 'Describes a sku for a scalable resource'})  # fmt: skip
    tags: Optional[Dict[str, str]] = field(default=None, metadata={"description": "Resource tags"})
    type: Optional[str] = field(default=None, metadata={"description": "Resource type"})
    worker_count: Optional[int] = field(default=None, metadata={'description': 'Number of instances in the worker pool'})  # fmt: skip
    worker_size: Optional[str] = field(default=None, metadata={"description": "VM size of the worker pool instances"})
    worker_size_id: Optional[int] = field(default=None, metadata={'description': 'Worker size id for referencing this worker pool'})  # fmt: skip


@define(eq=False, slots=False)
class AzureVirtualIPMapping:
    kind: ClassVar[str] = "azure_virtual_ip_mapping"
    mapping: ClassVar[Dict[str, Bender]] = {
        "in_use": S("inUse"),
        "internal_http_port": S("internalHttpPort"),
        "internal_https_port": S("internalHttpsPort"),
        "virtual_ip": S("virtualIP"),
    }
    in_use: Optional[bool] = field(default=None, metadata={"description": "Is VIP mapping in use"})
    internal_http_port: Optional[int] = field(default=None, metadata={"description": "Internal HTTP port"})
    internal_https_port: Optional[int] = field(default=None, metadata={"description": "Internal HTTPS port"})
    virtual_ip: Optional[str] = field(default=None, metadata={"description": "Virtual IP address"})


@define(eq=False, slots=False)
class AzureStampCapacity:
    kind: ClassVar[str] = "azure_stamp_capacity"
    mapping: ClassVar[Dict[str, Bender]] = {
        "available_capacity": S("availableCapacity"),
        "compute_mode": S("computeMode"),
        "exclude_from_capacity_allocation": S("excludeFromCapacityAllocation"),
        "is_applicable_for_all_compute_modes": S("isApplicableForAllComputeModes"),
        "name": S("name"),
        "site_mode": S("siteMode"),
        "total_capacity": S("totalCapacity"),
        "unit": S("unit"),
        "worker_size": S("workerSize"),
        "worker_size_id": S("workerSizeId"),
    }
    available_capacity: Optional[int] = field(default=None, metadata={'description': 'Available capacity (# of machines, bytes of storage etc...)'})  # fmt: skip
    compute_mode: Optional[str] = field(default=None, metadata={"description": "Shared/Dedicated workers"})
    exclude_from_capacity_allocation: Optional[bool] = field(default=None, metadata={'description': 'If true it includes basic sites Basic sites are not used for capacity allocation.'})  # fmt: skip
    is_applicable_for_all_compute_modes: Optional[bool] = field(default=None, metadata={'description': 'Is capacity applicable for all sites?'})  # fmt: skip
    name: Optional[str] = field(default=None, metadata={"description": "Name of the stamp"})
    site_mode: Optional[str] = field(default=None, metadata={"description": "Shared or Dedicated"})
    total_capacity: Optional[int] = field(default=None, metadata={'description': 'Total capacity (# of machines, bytes of storage etc...)'})  # fmt: skip
    unit: Optional[str] = field(default=None, metadata={"description": "Name of the unit"})
    worker_size: Optional[str] = field(default=None, metadata={"description": "Size of the machines"})
    worker_size_id: Optional[int] = field(default=None, metadata={'description': 'Size Id of machines: 0 - Small 1 - Medium 2 - Large'})  # fmt: skip


@define(eq=False, slots=False)
class AzureNetworkAccessControlEntry:
    kind: ClassVar[str] = "azure_network_access_control_entry"
    mapping: ClassVar[Dict[str, Bender]] = {
        "action": S("action"),
        "description": S("description"),
        "order": S("order"),
        "remote_subnet": S("remoteSubnet"),
    }
    action: Optional[str] = field(default=None, metadata={"description": ""})
    description: Optional[str] = field(default=None, metadata={"description": ""})
    order: Optional[int] = field(default=None, metadata={"description": ""})
    remote_subnet: Optional[str] = field(default=None, metadata={"description": ""})


@define(eq=False, slots=False)
class AzureWebHostingEnvironment(MicrosoftResource):
    kind: ClassVar[str] = "azure_web_hosting_environment"
    _kind_display: ClassVar[str] = "Azure Web Hosting Environment"
    _kind_service: ClassVar[Optional[str]] = service_name
    _kind_description: ClassVar[str] = "Azure Web Hosting Environment is a cloud-based service for deploying and running web applications. It provides infrastructure, tools, and resources for hosting websites and web apps on Microsoft's Azure platform. Users can deploy applications, manage domains, configure security settings, and scale resources as needed. The service supports multiple programming languages and frameworks."  # fmt: skip
    _docs_url: ClassVar[str] = "https://learn.microsoft.com/en-us/azure/app-service/environment/intro"
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "environment", "group": "compute"}
    api_spec: ClassVar[AzureResourceSpec] = AzureResourceSpec(
        service="web",
        version="2015-08-01",
        path="/subscriptions/{subscriptionId}/providers/Microsoft.Web/hostingEnvironments",
        path_parameters=["subscriptionId"],
        query_parameters=["api-version"],
        access_path="value",
        expect_array=True,
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "allowed_multi_sizes": S("properties", "allowedMultiSizes"),
        "allowed_worker_sizes": S("properties", "allowedWorkerSizes"),
        "api_management_account_id": S("properties", "apiManagementAccountId"),
        "hosting_environment_cluster_settings": S("properties", "clusterSettings") >> MapDict(S("name"), S("value")),
        "database_edition": S("properties", "databaseEdition"),
        "database_service_objective": S("properties", "databaseServiceObjective"),
        "dns_suffix": S("properties", "dnsSuffix"),
        "environment_capacities": S("properties", "environmentCapacities") >> ForallBend(AzureStampCapacity.mapping),
        "environment_is_healthy": S("properties", "environmentIsHealthy"),
        "environment_status": S("properties", "environmentStatus"),
        "internal_load_balancing_mode": S("properties", "internalLoadBalancingMode"),
        "ipssl_address_count": S("properties", "ipsslAddressCount"),
        "azure_kind": S("kind"),
        "last_action": S("properties", "lastAction"),
        "last_action_result": S("properties", "lastActionResult"),
        "maximum_number_of_machines": S("properties", "maximumNumberOfMachines"),
        "multi_role_count": S("properties", "multiRoleCount"),
        "multi_size": S("properties", "multiSize"),
        "network_access_control_list": S("properties", "networkAccessControlList")
        >> ForallBend(AzureNetworkAccessControlEntry.mapping),
        "provisioning_state": S("properties", "provisioningState"),
        "resource_group": S("properties", "resourceGroup"),
        "status": S("properties", "status"),
        "subscription_id": S("properties", "subscriptionId"),
        "suspended": S("properties", "suspended"),
        "upgrade_domains": S("properties", "upgradeDomains"),
        "vip_mappings": S("properties", "vipMappings") >> ForallBend(AzureVirtualIPMapping.mapping),
        "hosting_environment_virtual_network": S("properties", "virtualNetwork")
        >> Bend(AzureVirtualNetworkProfile.mapping),
        "vnet_name": S("properties", "vnetName"),
        "vnet_resource_group_name": S("properties", "vnetResourceGroupName"),
        "vnet_subnet_name": S("properties", "vnetSubnetName"),
        "worker_pools": S("properties", "workerPools") >> ForallBend(AzureWorkerPool.mapping),
    }
    allowed_multi_sizes: Optional[str] = field(default=None, metadata={'description': 'List of comma separated strings describing which VM sizes are allowed for front-ends'})  # fmt: skip
    allowed_worker_sizes: Optional[str] = field(default=None, metadata={'description': 'List of comma separated strings describing which VM sizes are allowed for workers'})  # fmt: skip
    api_management_account_id: Optional[str] = field(default=None, metadata={'description': 'Api Management Account associated with this Hosting Environment'})  # fmt: skip
    hosting_environment_cluster_settings: Optional[Json] = field(default=None, metadata={'description': 'Custom settings for changing the behavior of the hosting environment'})  # fmt: skip
    database_edition: Optional[str] = field(default=None, metadata={'description': 'Edition of the metadata database for the hostingEnvironment (App Service Environment) e.g. Standard '})  # fmt: skip
    database_service_objective: Optional[str] = field(default=None, metadata={'description': 'Service objective of the metadata database for the hostingEnvironment (App Service Environment) e.g. S0 '})  # fmt: skip
    dns_suffix: Optional[str] = field(default=None, metadata={'description': 'DNS suffix of the hostingEnvironment (App Service Environment)'})  # fmt: skip
    environment_capacities: Optional[List[AzureStampCapacity]] = field(default=None, metadata={'description': 'Current total, used, and available worker capacities'})  # fmt: skip
    environment_is_healthy: Optional[bool] = field(default=None, metadata={'description': 'True/false indicating whether the hostingEnvironment (App Service Environment) is healthy'})  # fmt: skip
    environment_status: Optional[str] = field(default=None, metadata={'description': 'Detailed message about with results of the last check of the hostingEnvironment (App Service Environment)'})  # fmt: skip
    internal_load_balancing_mode: Optional[str] = field(default=None, metadata={'description': 'Specifies which endpoints to serve internally in the hostingEnvironment s (App Service Environment) VNET'})  # fmt: skip
    ipssl_address_count: Optional[int] = field(default=None, metadata={'description': 'Number of IP SSL addresses reserved for this hostingEnvironment (App Service Environment)'})  # fmt: skip
    azure_kind: Optional[str] = field(default=None, metadata={"description": "Kind of resource"})
    last_action: Optional[str] = field(default=None, metadata={'description': 'Last deployment action on this hostingEnvironment (App Service Environment)'})  # fmt: skip
    last_action_result: Optional[str] = field(default=None, metadata={'description': 'Result of the last deployment action on this hostingEnvironment (App Service Environment)'})  # fmt: skip
    maximum_number_of_machines: Optional[int] = field(default=None, metadata={'description': 'Maximum number of VMs in this hostingEnvironment (App Service Environment)'})  # fmt: skip
    multi_role_count: Optional[int] = field(default=None, metadata={"description": "Number of front-end instances"})
    multi_size: Optional[str] = field(default=None, metadata={'description': 'Front-end VM size, e.g. Medium , Large '})  # fmt: skip
    network_access_control_list: Optional[List[AzureNetworkAccessControlEntry]] = field(default=None, metadata={'description': 'Access control list for controlling traffic to the hostingEnvironment (App Service Environment)'})  # fmt: skip
    resource_group: Optional[str] = field(default=None, metadata={'description': 'Resource group of the hostingEnvironment (App Service Environment)'})  # fmt: skip
    status: Optional[str] = field(default=None, metadata={'description': 'Current status of the hostingEnvironment (App Service Environment)'})  # fmt: skip
    subscription_id: Optional[str] = field(default=None, metadata={'description': 'Subscription of the hostingEnvironment (App Service Environment)'})  # fmt: skip
    suspended: Optional[bool] = field(default=None, metadata={'description': 'True/false indicating whether the hostingEnvironment is suspended. The environment can be suspended e.g. when the management endpoint is no longer available (most likely because NSG blocked the incoming traffic)'})  # fmt: skip
    upgrade_domains: Optional[int] = field(default=None, metadata={'description': 'Number of upgrade domains of this hostingEnvironment (App Service Environment)'})  # fmt: skip
    vip_mappings: Optional[List[AzureVirtualIPMapping]] = field(default=None, metadata={'description': 'Description of IP SSL mapping for this hostingEnvironment (App Service Environment)'})  # fmt: skip
    hosting_environment_virtual_network: Optional[AzureVirtualNetworkProfile] = field(default=None, metadata={'description': 'Specification for using a virtual network'})  # fmt: skip
    vnet_name: Optional[str] = field(default=None, metadata={'description': 'Name of the hostingEnvironment s (App Service Environment) virtual network'})  # fmt: skip
    vnet_resource_group_name: Optional[str] = field(default=None, metadata={'description': 'Resource group of the hostingEnvironment s (App Service Environment) virtual network'})  # fmt: skip
    vnet_subnet_name: Optional[str] = field(default=None, metadata={'description': 'Subnet of the hostingEnvironment s (App Service Environment) virtual network'})  # fmt: skip
    worker_pools: Optional[List[AzureWorkerPool]] = field(default=None, metadata={'description': 'Description of worker pools with worker size ids, VM sizes, and number of workers in each pool'})  # fmt: skip


@define(eq=False, slots=False)
class AzureArcConfiguration:
    kind: ClassVar[str] = "azure_arc_configuration"
    mapping: ClassVar[Dict[str, Bender]] = {
        "artifact_storage_access_mode": S("artifactStorageAccessMode"),
        "artifact_storage_class_name": S("artifactStorageClassName"),
        "artifact_storage_mount_path": S("artifactStorageMountPath"),
        "artifact_storage_node_name": S("artifactStorageNodeName"),
        "artifacts_storage_type": S("artifactsStorageType"),
        "front_end_service_configuration": S("frontEndServiceConfiguration", "kind"),
        "kube_config": S("kubeConfig"),
    }
    artifact_storage_access_mode: Optional[str] = field(default=None, metadata={"description": ""})
    artifact_storage_class_name: Optional[str] = field(default=None, metadata={"description": ""})
    artifact_storage_mount_path: Optional[str] = field(default=None, metadata={"description": ""})
    artifact_storage_node_name: Optional[str] = field(default=None, metadata={"description": ""})
    artifacts_storage_type: Optional[str] = field(default=None, metadata={"description": ""})
    front_end_service_configuration: Optional[str] = field(default=None, metadata={"description": ""})
    kube_config: Optional[str] = field(default=None, metadata={"description": ""})


@define(eq=False, slots=False)
class AzureLogAnalyticsConfiguration:
    kind: ClassVar[str] = "azure_log_analytics_configuration"
    mapping: ClassVar[Dict[str, Bender]] = {"customer_id": S("customerId"), "shared_key": S("sharedKey")}
    customer_id: Optional[str] = field(default=None, metadata={"description": ""})
    shared_key: Optional[str] = field(default=None, metadata={"description": ""})


@define(eq=False, slots=False)
class AzureAppLogsConfiguration:
    kind: ClassVar[str] = "azure_app_logs_configuration"
    mapping: ClassVar[Dict[str, Bender]] = {
        "destination": S("destination"),
        "log_analytics_configuration": S("logAnalyticsConfiguration") >> Bend(AzureLogAnalyticsConfiguration.mapping),
    }
    destination: Optional[str] = field(default=None, metadata={"description": ""})
    log_analytics_configuration: Optional[AzureLogAnalyticsConfiguration] = field(default=None, metadata={'description': ''})  # fmt: skip


@define(eq=False, slots=False)
class AzureContainerAppsConfiguration:
    kind: ClassVar[str] = "azure_container_apps_configuration"
    mapping: ClassVar[Dict[str, Bender]] = {
        "app_subnet_resource_id": S("appSubnetResourceId"),
        "control_plane_subnet_resource_id": S("controlPlaneSubnetResourceId"),
        "dapr_ai_instrumentation_key": S("daprAIInstrumentationKey"),
        "docker_bridge_cidr": S("dockerBridgeCidr"),
        "platform_reserved_cidr": S("platformReservedCidr"),
        "platform_reserved_dns_ip": S("platformReservedDnsIP"),
    }
    app_subnet_resource_id: Optional[str] = field(default=None, metadata={'description': 'Resource ID of a subnet for control plane infrastructure components. This subnet must be in the same VNET as the subnet defined in appSubnetResourceId. Must not overlap with the IP range defined in platformReservedCidr, if defined.'})  # fmt: skip
    control_plane_subnet_resource_id: Optional[str] = field(default=None, metadata={'description': 'Resource ID of a subnet for control plane infrastructure components. This subnet must be in the same VNET as the subnet defined in appSubnetResourceId. Must not overlap with the IP range defined in platformReservedCidr, if defined.'})  # fmt: skip
    dapr_ai_instrumentation_key: Optional[str] = field(default=None, metadata={'description': 'Azure Monitor instrumentation key used by Dapr to export Service to Service communication telemetry'})  # fmt: skip
    docker_bridge_cidr: Optional[str] = field(default=None, metadata={'description': 'CIDR notation IP range assigned to the Docker bridge network. It must not overlap with any Subnet IP ranges or the IP range defined in platformReservedCidr, if defined.'})  # fmt: skip
    platform_reserved_cidr: Optional[str] = field(default=None, metadata={'description': 'IP range in CIDR notation that can be reserved for environment infrastructure IP addresses. It must not overlap with any other Subnet IP ranges.'})  # fmt: skip
    platform_reserved_dns_ip: Optional[str] = field(default=None, metadata={'description': 'An IP address from the IP range defined by platformReservedCidr that will be reserved for the internal DNS server'})  # fmt: skip


@define(eq=False, slots=False)
class AzureWebKubeEnvironment(MicrosoftResource):
    kind: ClassVar[str] = "azure_web_kube_environment"
    _kind_display: ClassVar[str] = "Azure Web Kube Environment"
    _kind_service: ClassVar[Optional[str]] = service_name
    _kind_description: ClassVar[str] = "Azure Web Kube Environment is a service for deploying and managing containerized web applications on Azure Kubernetes Service. It provides tools for configuring, monitoring, and scaling applications in Kubernetes clusters. Users can deploy applications, set up networking, manage container registries, and handle application updates through this integrated platform."  # fmt: skip
    _docs_url: ClassVar[str] = "https://learn.microsoft.com/en-us/azure/app-service/environment/overview"
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "environment", "group": "managed_kubernetes"}
    api_spec: ClassVar[AzureResourceSpec] = AzureResourceSpec(
        service="web",
        version="2023-12-01",
        path="/subscriptions/{subscriptionId}/providers/Microsoft.Web/kubeEnvironments",
        path_parameters=["subscriptionId"],
        query_parameters=["api-version"],
        access_path="value",
        expect_array=True,
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "aks_resource_id": S("properties", "aksResourceID"),
        "app_logs_configuration": S("properties", "appLogsConfiguration") >> Bend(AzureAppLogsConfiguration.mapping),
        "arc_configuration": S("properties", "arcConfiguration") >> Bend(AzureArcConfiguration.mapping),
        "container_apps_configuration": S("properties", "containerAppsConfiguration")
        >> Bend(AzureContainerAppsConfiguration.mapping),
        "default_domain": S("properties", "defaultDomain"),
        "deployment_errors": S("properties", "deploymentErrors"),
        "environment_type": S("properties", "environmentType"),
        "extended_location": S("extendedLocation") >> Bend(AzureExtendedLocation.mapping),
        "internal_load_balancer_enabled": S("properties", "internalLoadBalancerEnabled"),
        "azure_kind": S("kind"),
        "provisioning_state": S("properties", "provisioningState"),
        "static_ip": S("properties", "staticIp"),
    }
    aks_resource_id: Optional[str] = field(default=None, metadata={"description": ""})
    app_logs_configuration: Optional[AzureAppLogsConfiguration] = field(default=None, metadata={"description": ""})
    arc_configuration: Optional[AzureArcConfiguration] = field(default=None, metadata={"description": ""})
    container_apps_configuration: Optional[AzureContainerAppsConfiguration] = field(default=None, metadata={'description': ''})  # fmt: skip
    default_domain: Optional[str] = field(default=None, metadata={'description': 'Default Domain Name for the cluster'})  # fmt: skip
    deployment_errors: Optional[str] = field(default=None, metadata={'description': 'Any errors that occurred during deployment or deployment validation'})  # fmt: skip
    environment_type: Optional[str] = field(default=None, metadata={'description': 'Type of Kubernetes Environment. Only supported for Container App Environments with value as Managed'})  # fmt: skip
    extended_location: Optional[AzureExtendedLocation] = field(default=None, metadata={'description': 'Extended Location.'})  # fmt: skip
    internal_load_balancer_enabled: Optional[bool] = field(default=None, metadata={'description': 'Only visible within Vnet/Subnet'})  # fmt: skip
    azure_kind: Optional[str] = field(default=None, metadata={"description": "Kind of resource."})
    static_ip: Optional[str] = field(default=None, metadata={"description": "Static IP of the KubeEnvironment"})


@define(eq=False, slots=False)
class AzureHostNameSslState:
    kind: ClassVar[str] = "azure_host_name_ssl_state"
    mapping: ClassVar[Dict[str, Bender]] = {
        "host_type": S("hostType"),
        "name": S("name"),
        "ssl_state": S("sslState"),
        "thumbprint": S("thumbprint"),
        "to_update": S("toUpdate"),
        "virtual_ip": S("virtualIP"),
    }
    host_type: Optional[str] = field(default=None, metadata={'description': 'Indicates whether the hostname is a standard or repository hostname.'})  # fmt: skip
    name: Optional[str] = field(default=None, metadata={"description": "Hostname."})
    ssl_state: Optional[str] = field(default=None, metadata={"description": "SSL type."})
    thumbprint: Optional[str] = field(default=None, metadata={"description": "SSL certificate thumbprint."})
    to_update: Optional[bool] = field(default=None, metadata={'description': 'Set to <code>true</code> to update existing hostname.'})  # fmt: skip
    virtual_ip: Optional[str] = field(default=None, metadata={'description': 'Virtual IP address assigned to the hostname if IP based SSL is enabled.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureSiteDnsConfig:
    kind: ClassVar[str] = "azure_site_dns_config"
    mapping: ClassVar[Dict[str, Bender]] = {
        "dns_alt_server": S("dnsAltServer"),
        "dns_legacy_sort_order": S("dnsLegacySortOrder"),
        "dns_max_cache_timeout": S("dnsMaxCacheTimeout"),
        "dns_retry_attempt_count": S("dnsRetryAttemptCount"),
        "dns_retry_attempt_timeout": S("dnsRetryAttemptTimeout"),
        "dns_servers": S("dnsServers"),
    }
    dns_alt_server: Optional[str] = field(default=None, metadata={'description': 'Alternate DNS server to be used by apps. This property replicates the WEBSITE_DNS_ALT_SERVER app setting.'})  # fmt: skip
    dns_legacy_sort_order: Optional[bool] = field(default=None, metadata={'description': 'Indicates that sites using Virtual network custom DNS servers are still sorting the list of DNS servers. Read-Only.'})  # fmt: skip
    dns_max_cache_timeout: Optional[int] = field(default=None, metadata={'description': 'Custom time for DNS to be cached in seconds. Allowed range: 0-60. Default is 30 seconds. 0 means caching disabled.'})  # fmt: skip
    dns_retry_attempt_count: Optional[int] = field(default=None, metadata={'description': 'Total number of retries for dns lookup. Allowed range: 1-5. Default is 3.'})  # fmt: skip
    dns_retry_attempt_timeout: Optional[int] = field(default=None, metadata={'description': 'Timeout for a single dns lookup in seconds. Allowed range: 1-30. Default is 3.'})  # fmt: skip
    dns_servers: Optional[List[str]] = field(default=None, metadata={'description': 'List of custom DNS servers to be used by an app for lookups. Maximum 5 dns servers can be set.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureConnStringInfo:
    kind: ClassVar[str] = "azure_conn_string_info"
    mapping: ClassVar[Dict[str, Bender]] = {
        "connection_string": S("connectionString"),
        "name": S("name"),
        "type": S("type"),
    }
    connection_string: Optional[str] = field(default=None, metadata={"description": "Connection string value."})
    name: Optional[str] = field(default=None, metadata={"description": "Name of connection string."})
    type: Optional[str] = field(default=None, metadata={"description": "Type of database."})


@define(eq=False, slots=False)
class AzureSiteMachineKey:
    kind: ClassVar[str] = "azure_site_machine_key"
    mapping: ClassVar[Dict[str, Bender]] = {
        "decryption": S("decryption"),
        "decryption_key": S("decryptionKey"),
        "validation": S("validation"),
        "validation_key": S("validationKey"),
    }
    decryption: Optional[str] = field(default=None, metadata={"description": "Algorithm used for decryption."})
    decryption_key: Optional[str] = field(default=None, metadata={"description": "Decryption key."})
    validation: Optional[str] = field(default=None, metadata={"description": "MachineKey validation."})
    validation_key: Optional[str] = field(default=None, metadata={"description": "Validation key."})


@define(eq=False, slots=False)
class AzureHandlerMapping:
    kind: ClassVar[str] = "azure_handler_mapping"
    mapping: ClassVar[Dict[str, Bender]] = {
        "arguments": S("arguments"),
        "extension": S("extension"),
        "script_processor": S("scriptProcessor"),
    }
    arguments: Optional[str] = field(default=None, metadata={'description': 'Command-line arguments to be passed to the script processor.'})  # fmt: skip
    extension: Optional[str] = field(default=None, metadata={'description': 'Requests with this extension will be handled using the specified FastCGI application.'})  # fmt: skip
    script_processor: Optional[str] = field(default=None, metadata={'description': 'The absolute path to the FastCGI application.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureVirtualDirectory:
    kind: ClassVar[str] = "azure_virtual_directory"
    mapping: ClassVar[Dict[str, Bender]] = {"physical_path": S("physicalPath"), "virtual_path": S("virtualPath")}
    physical_path: Optional[str] = field(default=None, metadata={"description": "Physical path."})
    virtual_path: Optional[str] = field(default=None, metadata={"description": "Path to virtual application."})


@define(eq=False, slots=False)
class AzureVirtualApplication:
    kind: ClassVar[str] = "azure_virtual_application"
    mapping: ClassVar[Dict[str, Bender]] = {
        "physical_path": S("physicalPath"),
        "preload_enabled": S("preloadEnabled"),
        "virtual_directories": S("virtualDirectories") >> ForallBend(AzureVirtualDirectory.mapping),
        "virtual_path": S("virtualPath"),
    }
    physical_path: Optional[str] = field(default=None, metadata={"description": "Physical path."})
    preload_enabled: Optional[bool] = field(default=None, metadata={'description': '<code>true</code> if preloading is enabled; otherwise, <code>false</code>.'})  # fmt: skip
    virtual_directories: Optional[List[AzureVirtualDirectory]] = field(default=None, metadata={'description': 'Virtual directories for virtual application.'})  # fmt: skip
    virtual_path: Optional[str] = field(default=None, metadata={"description": "Virtual path."})


@define(eq=False, slots=False)
class AzureRampUpRule:
    kind: ClassVar[str] = "azure_ramp_up_rule"
    mapping: ClassVar[Dict[str, Bender]] = {
        "action_host_name": S("actionHostName"),
        "change_decision_callback_url": S("changeDecisionCallbackUrl"),
        "change_interval_in_minutes": S("changeIntervalInMinutes"),
        "change_step": S("changeStep"),
        "max_reroute_percentage": S("maxReroutePercentage"),
        "min_reroute_percentage": S("minReroutePercentage"),
        "name": S("name"),
        "reroute_percentage": S("reroutePercentage"),
    }
    action_host_name: Optional[str] = field(default=None, metadata={'description': 'Hostname of a slot to which the traffic will be redirected if decided to. E.g. myapp-stage.azurewebsites.net.'})  # fmt: skip
    change_decision_callback_url: Optional[str] = field(default=None, metadata={'description': 'Custom decision algorithm can be provided in TiPCallback site extension which URL can be specified. See TiPCallback site extension for the scaffold and contracts. https://www.siteextensions.net/packages/TiPCallback/'})  # fmt: skip
    change_interval_in_minutes: Optional[int] = field(default=None, metadata={'description': 'Specifies interval in minutes to reevaluate ReroutePercentage.'})  # fmt: skip
    change_step: Optional[float] = field(default=None, metadata={'description': 'In auto ramp up scenario this is the step to add/remove from <code>ReroutePercentage</code> until it reaches \n<code>MinReroutePercentage</code> or <code>MaxReroutePercentage</code>. Site metrics are checked every N minutes specified in <code>ChangeIntervalInMinutes</code>.\nCustom decision algorithm can be provided in TiPCallback site extension which URL can be specified in <code>ChangeDecisionCallbackUrl</code>.'})  # fmt: skip
    max_reroute_percentage: Optional[float] = field(default=None, metadata={'description': 'Specifies upper boundary below which ReroutePercentage will stay.'})  # fmt: skip
    min_reroute_percentage: Optional[float] = field(default=None, metadata={'description': 'Specifies lower boundary above which ReroutePercentage will stay.'})  # fmt: skip
    name: Optional[str] = field(default=None, metadata={'description': 'Name of the routing rule. The recommended name would be to point to the slot which will receive the traffic in the experiment.'})  # fmt: skip
    reroute_percentage: Optional[float] = field(default=None, metadata={'description': 'Percentage of the traffic which will be redirected to <code>ActionHostName</code>.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureExperiments:
    kind: ClassVar[str] = "azure_experiments"
    mapping: ClassVar[Dict[str, Bender]] = {"ramp_up_rules": S("rampUpRules") >> ForallBend(AzureRampUpRule.mapping)}
    ramp_up_rules: Optional[List[AzureRampUpRule]] = field(
        default=None, metadata={"description": "List of ramp-up rules."}
    )


@define(eq=False, slots=False)
class AzureSiteLimits:
    kind: ClassVar[str] = "azure_site_limits"
    mapping: ClassVar[Dict[str, Bender]] = {
        "max_disk_size_in_mb": S("maxDiskSizeInMb"),
        "max_memory_in_mb": S("maxMemoryInMb"),
        "max_percentage_cpu": S("maxPercentageCpu"),
    }
    max_disk_size_in_mb: Optional[int] = field(default=None, metadata={'description': 'Maximum allowed disk size usage in MB.'})  # fmt: skip
    max_memory_in_mb: Optional[int] = field(default=None, metadata={'description': 'Maximum allowed memory usage in MB.'})  # fmt: skip
    max_percentage_cpu: Optional[float] = field(default=None, metadata={'description': 'Maximum allowed CPU usage percentage.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureCorsSettings:
    kind: ClassVar[str] = "azure_cors_settings"
    mapping: ClassVar[Dict[str, Bender]] = {
        "allowed_origins": S("allowedOrigins"),
        "support_credentials": S("supportCredentials"),
    }
    allowed_origins: Optional[List[str]] = field(default=None, metadata={'description': 'Gets or sets the list of origins that should be allowed to make cross-origin calls (for example: https://example.com:12345). Use * to allow all.'})  # fmt: skip
    support_credentials: Optional[bool] = field(default=None, metadata={'description': 'Gets or sets whether CORS requests with credentials are allowed. See https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS#Requests_with_credentials for more details.'})  # fmt: skip


@define(eq=False, slots=False)
class AzurePushSettings(AzureProxyOnlyResource):
    kind: ClassVar[str] = "azure_push_settings"
    mapping: ClassVar[Dict[str, Bender]] = AzureProxyOnlyResource.mapping | {
        "dynamic_tags_json": S("properties", "dynamicTagsJson"),
        "is_push_enabled": S("properties", "isPushEnabled"),
        "tag_whitelist_json": S("properties", "tagWhitelistJson"),
        "tags_requiring_auth": S("properties", "tagsRequiringAuth"),
    }
    dynamic_tags_json: Optional[str] = field(default=None, metadata={'description': 'Gets or sets a JSON string containing a list of dynamic tags that will be evaluated from user claims in the push registration endpoint.'})  # fmt: skip
    is_push_enabled: Optional[bool] = field(default=None, metadata={'description': 'Gets or sets a flag indicating whether the Push endpoint is enabled.'})  # fmt: skip
    tag_whitelist_json: Optional[str] = field(default=None, metadata={'description': 'Gets or sets a JSON string containing a list of tags that are whitelisted for use by the push registration endpoint.'})  # fmt: skip
    tags_requiring_auth: Optional[str] = field(default=None, metadata={'description': 'Gets or sets a JSON string containing a list of tags that require user authentication to be used in the push registration endpoint. Tags can consist of alphanumeric characters and the following: _ , @ , # , . , : , - . Validation should be performed at the PushRequestHandler.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureIpSecurityRestriction:
    kind: ClassVar[str] = "azure_ip_security_restriction"
    mapping: ClassVar[Dict[str, Bender]] = {
        "action": S("action"),
        "description": S("description"),
        "headers": S("headers"),
        "ip_address": S("ipAddress"),
        "name": S("name"),
        "priority": S("priority"),
        "subnet_mask": S("subnetMask"),
        "subnet_traffic_tag": S("subnetTrafficTag"),
        "tag": S("tag"),
        "vnet_subnet_resource_id": S("vnetSubnetResourceId"),
        "vnet_traffic_tag": S("vnetTrafficTag"),
    }
    action: Optional[str] = field(default=None, metadata={"description": "Allow or Deny access for this IP range."})
    description: Optional[str] = field(default=None, metadata={"description": "IP restriction rule description."})
    headers: Optional[Json] = field(default=None, metadata={'description': 'IP restriction rule headers. X-Forwarded-Host (https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Forwarded-Host#Examples). The matching logic is .. - If the property is null or empty (default), all hosts(or lack of) are allowed. - A value is compared using ordinal-ignore-case (excluding port number). - Subdomain wildcards are permitted but don t match the root domain. For example, *.contoso.com matches the subdomain foo.contoso.com but not the root domain contoso.com or multi-level foo.bar.contoso.com - Unicode host names are allowed but are converted to Punycode for matching. X-Forwarded-For (https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Forwarded-For#Examples). The matching logic is .. - If the property is null or empty (default), any forwarded-for chains (or lack of) are allowed. - If any address (excluding port number) in the chain (comma separated) matches the CIDR defined by the property. X-Azure-FDID and X-FD-HealthProbe. The matching logic is exact match.'})  # fmt: skip
    ip_address: Optional[str] = field(default=None, metadata={'description': 'IP address the security restriction is valid for. It can be in form of pure ipv4 address (required SubnetMask property) or CIDR notation such as ipv4/mask (leading bit match). For CIDR, SubnetMask property must not be specified.'})  # fmt: skip
    name: Optional[str] = field(default=None, metadata={"description": "IP restriction rule name."})
    priority: Optional[int] = field(default=None, metadata={"description": "Priority of IP restriction rule."})
    subnet_mask: Optional[str] = field(default=None, metadata={'description': 'Subnet mask for the range of IP addresses the restriction is valid for.'})  # fmt: skip
    subnet_traffic_tag: Optional[int] = field(default=None, metadata={"description": "(internal) Subnet traffic tag"})
    tag: Optional[str] = field(default=None, metadata={'description': 'Defines what this IP filter will be used for. This is to support IP filtering on proxies.'})  # fmt: skip
    vnet_subnet_resource_id: Optional[str] = field(default=None, metadata={'description': 'Virtual network resource id'})  # fmt: skip
    vnet_traffic_tag: Optional[int] = field(default=None, metadata={"description": "(internal) Vnet traffic tag"})


@define(eq=False, slots=False)
class AzureStorageInfoValue:
    kind: ClassVar[str] = "azure_storage_info_value"
    mapping: ClassVar[Dict[str, Bender]] = {
        "access_key": S("accessKey"),
        "account_name": S("accountName"),
        "mount_path": S("mountPath"),
        "protocol": S("protocol"),
        "share_name": S("shareName"),
        "state": S("state"),
        "type": S("type"),
    }
    access_key: Optional[str] = field(default=None, metadata={"description": "Access key for the storage account."})
    account_name: Optional[str] = field(default=None, metadata={"description": "Name of the storage account."})
    mount_path: Optional[str] = field(default=None, metadata={'description': 'Path to mount the storage within the site s runtime environment.'})  # fmt: skip
    protocol: Optional[str] = field(default=None, metadata={'description': 'Mounting protocol to use for the storage account.'})  # fmt: skip
    share_name: Optional[str] = field(default=None, metadata={'description': 'Name of the file share (container name, for Blob storage).'})  # fmt: skip
    state: Optional[str] = field(default=None, metadata={"description": "State of the storage account."})
    type: Optional[str] = field(default=None, metadata={"description": "Type of storage."})


@define(eq=False, slots=False)
class AzureSiteConfig:
    kind: ClassVar[str] = "azure_site_config"
    mapping: ClassVar[Dict[str, Bender]] = {
        "acr_use_managed_identity_creds": S("acrUseManagedIdentityCreds"),
        "acr_user_managed_identity_id": S("acrUserManagedIdentityID"),
        "always_on": S("alwaysOn"),
        "api_definition": S("apiDefinition", "url"),
        "api_management_config": S("apiManagementConfig", "id"),
        "app_command_line": S("appCommandLine"),
        "app_settings": S("appSettings") >> MapDict(S("name"), S("value")),
        "auto_heal_enabled": S("autoHealEnabled"),
        "auto_swap_slot_name": S("autoSwapSlotName"),
        "azure_storage_accounts": S("azureStorageAccounts"),
        "connection_strings": S("connectionStrings") >> ForallBend(AzureConnStringInfo.mapping),
        "cors": S("cors") >> Bend(AzureCorsSettings.mapping),
        "default_documents": S("defaultDocuments"),
        "detailed_error_logging_enabled": S("detailedErrorLoggingEnabled"),
        "document_root": S("documentRoot"),
        "elastic_web_app_scale_limit": S("elasticWebAppScaleLimit"),
        "experiments": S("experiments") >> Bend(AzureExperiments.mapping),
        "ftps_state": S("ftpsState"),
        "function_app_scale_limit": S("functionAppScaleLimit"),
        "functions_runtime_scale_monitoring_enabled": S("functionsRuntimeScaleMonitoringEnabled"),
        "handler_mappings": S("handlerMappings") >> ForallBend(AzureHandlerMapping.mapping),
        "health_check_path": S("healthCheckPath"),
        "http20_enabled": S("http20Enabled"),
        "http_logging_enabled": S("httpLoggingEnabled"),
        "ip_security_restrictions": S("ipSecurityRestrictions") >> ForallBend(AzureIpSecurityRestriction.mapping),
        "ip_security_restrictions_default_action": S("ipSecurityRestrictionsDefaultAction"),
        "java_container": S("javaContainer"),
        "java_container_version": S("javaContainerVersion"),
        "java_version": S("javaVersion"),
        "key_vault_reference_identity": S("keyVaultReferenceIdentity"),
        "limits": S("limits") >> Bend(AzureSiteLimits.mapping),
        "linux_fx_version": S("linuxFxVersion"),
        "load_balancing": S("loadBalancing"),
        "local_my_sql_enabled": S("localMySqlEnabled"),
        "logs_directory_size_limit": S("logsDirectorySizeLimit"),
        "machine_key": S("machineKey") >> Bend(AzureSiteMachineKey.mapping),
        "managed_pipeline_mode": S("managedPipelineMode"),
        "managed_service_identity_id": S("managedServiceIdentityId"),
        "metadata": S("metadata") >> MapDict(S("name"), S("value")),
        "min_tls_cipher_suite": S("minTlsCipherSuite"),
        "min_tls_version": S("minTlsVersion"),
        "minimum_elastic_instance_count": S("minimumElasticInstanceCount"),
        "net_framework_version": S("netFrameworkVersion"),
        "node_version": S("nodeVersion"),
        "number_of_workers": S("numberOfWorkers"),
        "php_version": S("phpVersion"),
        "power_shell_version": S("powerShellVersion"),
        "pre_warmed_instance_count": S("preWarmedInstanceCount"),
        "public_network_access": S("publicNetworkAccess"),
        "publishing_username": S("publishingUsername"),
        "push": S("push") >> Bend(AzurePushSettings.mapping),
        "python_version": S("pythonVersion"),
        "remote_debugging_enabled": S("remoteDebuggingEnabled"),
        "remote_debugging_version": S("remoteDebuggingVersion"),
        "request_tracing_enabled": S("requestTracingEnabled"),
        "request_tracing_expiration_time": S("requestTracingExpirationTime"),
        "scm_ip_security_restrictions": S("scmIpSecurityRestrictions")
        >> ForallBend(AzureIpSecurityRestriction.mapping),
        "scm_ip_security_restrictions_default_action": S("scmIpSecurityRestrictionsDefaultAction"),
        "scm_ip_security_restrictions_use_main": S("scmIpSecurityRestrictionsUseMain"),
        "scm_min_tls_version": S("scmMinTlsVersion"),
        "scm_type": S("scmType"),
        "tracing_options": S("tracingOptions"),
        "use32_bit_worker_process": S("use32BitWorkerProcess"),
        "virtual_applications": S("virtualApplications") >> ForallBend(AzureVirtualApplication.mapping),
        "vnet_name": S("vnetName"),
        "vnet_private_ports_count": S("vnetPrivatePortsCount"),
        "vnet_route_all_enabled": S("vnetRouteAllEnabled"),
        "web_sockets_enabled": S("webSocketsEnabled"),
        "website_time_zone": S("websiteTimeZone"),
        "windows_fx_version": S("windowsFxVersion"),
        "x_managed_service_identity_id": S("xManagedServiceIdentityId"),
    }
    acr_use_managed_identity_creds: Optional[bool] = field(default=None, metadata={'description': 'Flag to use Managed Identity Creds for ACR pull'})  # fmt: skip
    acr_user_managed_identity_id: Optional[str] = field(default=None, metadata={'description': 'If using user managed identity, the user managed identity ClientId'})  # fmt: skip
    always_on: Optional[bool] = field(default=None, metadata={'description': '<code>true</code> if Always On is enabled; otherwise, <code>false</code>.'})  # fmt: skip
    api_definition: Optional[str] = field(default=None, metadata={'description': 'Information about the formal API definition for the app.'})  # fmt: skip
    api_management_config: Optional[str] = field(default=None, metadata={'description': 'Azure API management (APIM) configuration linked to the app.'})  # fmt: skip
    app_command_line: Optional[str] = field(default=None, metadata={"description": "App command line to launch."})
    app_settings: Optional[Json] = field(default=None, metadata={"description": "Application settings."})
    auto_heal_enabled: Optional[bool] = field(default=None, metadata={'description': '<code>true</code> if Auto Heal is enabled; otherwise, <code>false</code>.'})  # fmt: skip
    auto_swap_slot_name: Optional[str] = field(default=None, metadata={"description": "Auto-swap slot name."})
    azure_storage_accounts: Optional[Dict[str, AzureStorageInfoValue]] = field(default=None, metadata={'description': 'List of Azure Storage Accounts.'})  # fmt: skip
    connection_strings: Optional[List[AzureConnStringInfo]] = field(default=None, metadata={'description': 'Connection strings.'})  # fmt: skip
    cors: Optional[AzureCorsSettings] = field(default=None, metadata={'description': 'Cross-Origin Resource Sharing (CORS) settings for the app.'})  # fmt: skip
    default_documents: Optional[List[str]] = field(default=None, metadata={"description": "Default documents."})
    detailed_error_logging_enabled: Optional[bool] = field(default=None, metadata={'description': '<code>true</code> if detailed error logging is enabled; otherwise, <code>false</code>.'})  # fmt: skip
    document_root: Optional[str] = field(default=None, metadata={"description": "Document root."})
    elastic_web_app_scale_limit: Optional[int] = field(default=None, metadata={'description': 'Maximum number of workers that a site can scale out to. This setting only applies to apps in plans where ElasticScaleEnabled is <code>true</code>'})  # fmt: skip
    experiments: Optional[AzureExperiments] = field(default=None, metadata={'description': 'Routing rules in production experiments.'})  # fmt: skip
    ftps_state: Optional[str] = field(default=None, metadata={"description": "State of FTP / FTPS service"})
    function_app_scale_limit: Optional[int] = field(default=None, metadata={'description': 'Maximum number of workers that a site can scale out to. This setting only applies to the Consumption and Elastic Premium Plans'})  # fmt: skip
    functions_runtime_scale_monitoring_enabled: Optional[bool] = field(default=None, metadata={'description': 'Gets or sets a value indicating whether functions runtime scale monitoring is enabled. When enabled, the ScaleController will not monitor event sources directly, but will instead call to the runtime to get scale status.'})  # fmt: skip
    handler_mappings: Optional[List[AzureHandlerMapping]] = field(default=None, metadata={'description': 'Handler mappings.'})  # fmt: skip
    health_check_path: Optional[str] = field(default=None, metadata={"description": "Health check path"})
    http20_enabled: Optional[bool] = field(default=None, metadata={'description': 'Http20Enabled: configures a web site to allow clients to connect over http2.0'})  # fmt: skip
    http_logging_enabled: Optional[bool] = field(default=None, metadata={'description': '<code>true</code> if HTTP logging is enabled; otherwise, <code>false</code>.'})  # fmt: skip
    ip_security_restrictions: Optional[List[AzureIpSecurityRestriction]] = field(default=None, metadata={'description': 'IP security restrictions for main.'})  # fmt: skip
    ip_security_restrictions_default_action: Optional[str] = field(default=None, metadata={'description': 'Default action for main access restriction if no rules are matched.'})  # fmt: skip
    java_container: Optional[str] = field(default=None, metadata={"description": "Java container."})
    java_container_version: Optional[str] = field(default=None, metadata={"description": "Java container version."})
    java_version: Optional[str] = field(default=None, metadata={"description": "Java version."})
    key_vault_reference_identity: Optional[str] = field(default=None, metadata={'description': 'Identity to use for Key Vault Reference authentication.'})  # fmt: skip
    limits: Optional[AzureSiteLimits] = field(default=None, metadata={"description": "Metric limits set on an app."})
    linux_fx_version: Optional[str] = field(default=None, metadata={"description": "Linux App Framework and version"})
    load_balancing: Optional[str] = field(default=None, metadata={"description": "Site load balancing."})
    local_my_sql_enabled: Optional[bool] = field(default=None, metadata={'description': '<code>true</code> to enable local MySQL; otherwise, <code>false</code>.'})  # fmt: skip
    logs_directory_size_limit: Optional[int] = field(default=None, metadata={'description': 'HTTP logs directory size limit.'})  # fmt: skip
    machine_key: Optional[AzureSiteMachineKey] = field(default=None, metadata={"description": "MachineKey of an app."})
    managed_pipeline_mode: Optional[str] = field(default=None, metadata={"description": "Managed pipeline mode."})
    managed_service_identity_id: Optional[int] = field(default=None, metadata={'description': 'Managed Service Identity Id'})  # fmt: skip
    metadata: Optional[Json] = field(default=None, metadata={'description': 'Application metadata. This property cannot be retrieved, since it may contain secrets.'})  # fmt: skip
    min_tls_cipher_suite: Optional[str] = field(default=None, metadata={'description': 'The minimum strength TLS cipher suite allowed for an application'})  # fmt: skip
    min_tls_version: Optional[str] = field(default=None, metadata={'description': 'MinTlsVersion: configures the minimum version of TLS required for SSL requests'})  # fmt: skip
    minimum_elastic_instance_count: Optional[int] = field(default=None, metadata={'description': 'Number of minimum instance count for a site This setting only applies to the Elastic Plans'})  # fmt: skip
    net_framework_version: Optional[str] = field(default=None, metadata={"description": ".NET Framework version."})
    node_version: Optional[str] = field(default=None, metadata={"description": "Version of Node.js."})
    number_of_workers: Optional[int] = field(default=None, metadata={"description": "Number of workers."})
    php_version: Optional[str] = field(default=None, metadata={"description": "Version of PHP."})
    power_shell_version: Optional[str] = field(default=None, metadata={"description": "Version of PowerShell."})
    pre_warmed_instance_count: Optional[int] = field(default=None, metadata={'description': 'Number of preWarmed instances. This setting only applies to the Consumption and Elastic Plans'})  # fmt: skip
    public_network_access: Optional[str] = field(default=None, metadata={'description': 'Property to allow or block all public traffic.'})  # fmt: skip
    publishing_username: Optional[str] = field(default=None, metadata={"description": "Publishing user name."})
    push: Optional[AzurePushSettings] = field(default=None, metadata={"description": "Push settings for the App."})
    python_version: Optional[str] = field(default=None, metadata={"description": "Version of Python."})
    remote_debugging_enabled: Optional[bool] = field(default=None, metadata={'description': '<code>true</code> if remote debugging is enabled; otherwise, <code>false</code>.'})  # fmt: skip
    remote_debugging_version: Optional[str] = field(default=None, metadata={'description': 'Remote debugging version.'})  # fmt: skip
    request_tracing_enabled: Optional[bool] = field(default=None, metadata={'description': '<code>true</code> if request tracing is enabled; otherwise, <code>false</code>.'})  # fmt: skip
    request_tracing_expiration_time: Optional[datetime] = field(default=None, metadata={'description': 'Request tracing expiration time.'})  # fmt: skip
    scm_ip_security_restrictions: Optional[List[AzureIpSecurityRestriction]] = field(default=None, metadata={'description': 'IP security restrictions for scm.'})  # fmt: skip
    scm_ip_security_restrictions_default_action: Optional[str] = field(default=None, metadata={'description': 'Default action for scm access restriction if no rules are matched.'})  # fmt: skip
    scm_ip_security_restrictions_use_main: Optional[bool] = field(default=None, metadata={'description': 'IP security restrictions for scm to use main.'})  # fmt: skip
    scm_min_tls_version: Optional[str] = field(default=None, metadata={'description': 'ScmMinTlsVersion: configures the minimum version of TLS required for SSL requests for SCM site'})  # fmt: skip
    scm_type: Optional[str] = field(default=None, metadata={"description": "SCM type."})
    tracing_options: Optional[str] = field(default=None, metadata={"description": "Tracing options."})
    use32_bit_worker_process: Optional[bool] = field(default=None, metadata={'description': '<code>true</code> to use 32-bit worker process; otherwise, <code>false</code>.'})  # fmt: skip
    virtual_applications: Optional[List[AzureVirtualApplication]] = field(default=None, metadata={'description': 'Virtual applications.'})  # fmt: skip
    vnet_name: Optional[str] = field(default=None, metadata={"description": "Virtual Network name."})
    vnet_private_ports_count: Optional[int] = field(default=None, metadata={'description': 'The number of private ports assigned to this app. These will be assigned dynamically on runtime.'})  # fmt: skip
    vnet_route_all_enabled: Optional[bool] = field(default=None, metadata={'description': 'Virtual Network Route All enabled. This causes all outbound traffic to have Virtual Network Security Groups and User Defined Routes applied.'})  # fmt: skip
    web_sockets_enabled: Optional[bool] = field(default=None, metadata={'description': '<code>true</code> if WebSocket is enabled; otherwise, <code>false</code>.'})  # fmt: skip
    website_time_zone: Optional[str] = field(default=None, metadata={'description': 'Sets the time zone a site uses for generating timestamps. Compatible with Linux and Windows App Service. Setting the WEBSITE_TIME_ZONE app setting takes precedence over this config. For Linux, expects tz database values https://www.iana.org/time-zones (for a quick reference see https://en.wikipedia.org/wiki/List_of_tz_database_time_zones). For Windows, expects one of the time zones listed under HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Time Zones'})  # fmt: skip
    windows_fx_version: Optional[str] = field(default=None, metadata={'description': 'Xenon App Framework and version'})  # fmt: skip
    x_managed_service_identity_id: Optional[int] = field(default=None, metadata={'description': 'Explicit Managed Service Identity Id'})  # fmt: skip


@define(eq=False, slots=False)
class AzureTypeAuthentication:
    kind: ClassVar[str] = "azure_type_authentication"
    mapping: ClassVar[Dict[str, Bender]] = {
        "storage_account_connection_string_name": S("storageAccountConnectionStringName"),
        "type": S("type"),
        "user_assigned_identity_resource_id": S("userAssignedIdentityResourceId"),
    }
    storage_account_connection_string_name: Optional[str] = field(default=None, metadata={'description': 'Use this property for StorageAccountConnectionString. Set the name of the app setting that has the storage account connection string. Do not set a value for this property when using other authentication type.'})  # fmt: skip
    type: Optional[str] = field(default=None, metadata={'description': 'Property to select authentication type to access the selected storage account. Available options: SystemAssignedIdentity, UserAssignedIdentity, StorageAccountConnectionString.'})  # fmt: skip
    user_assigned_identity_resource_id: Optional[str] = field(default=None, metadata={'description': 'Use this property for UserAssignedIdentity. Set the resource ID of the identity. Do not set a value for this property when using other authentication type.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureTypeValueAuthentication:
    kind: ClassVar[str] = "azure_type_value_authentication"
    mapping: ClassVar[Dict[str, Bender]] = {
        "authentication": S("authentication") >> Bend(AzureTypeAuthentication.mapping),
        "type": S("type"),
        "value": S("value"),
    }
    authentication: Optional[AzureTypeAuthentication] = field(default=None, metadata={'description': 'Authentication method to access the storage account for deployment.'})  # fmt: skip
    type: Optional[str] = field(default=None, metadata={'description': 'Property to select Azure Storage type. Available options: blobContainer.'})  # fmt: skip
    value: Optional[str] = field(default=None, metadata={'description': 'Property to set the URL for the selected Azure Storage type. Example: For blobContainer, the value could be https://<storageAccountName>.blob.core.windows.net/<containerName>.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureFunctionsDeployment:
    kind: ClassVar[str] = "azure_functions_deployment"
    mapping: ClassVar[Dict[str, Bender]] = {"storage": S("storage") >> Bend(AzureTypeValueAuthentication.mapping)}
    storage: Optional[AzureTypeValueAuthentication] = field(default=None, metadata={'description': 'Storage for deployed package used by the function app.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureFunctionsRuntime:
    kind: ClassVar[str] = "azure_functions_runtime"
    mapping: ClassVar[Dict[str, Bender]] = {"name": S("name"), "version": S("version")}
    name: Optional[str] = field(default=None, metadata={'description': 'Function app runtime name. Available options: dotnet-isolated, node, java, powershell, python, custom'})  # fmt: skip
    version: Optional[str] = field(default=None, metadata={'description': 'Function app runtime version. Example: 8 (for dotnet-isolated)'})  # fmt: skip


@define(eq=False, slots=False)
class AzureFunctionsAlwaysReadyConfig:
    kind: ClassVar[str] = "azure_functions_always_ready_config"
    mapping: ClassVar[Dict[str, Bender]] = {"instance_count": S("instanceCount"), "name": S("name")}
    instance_count: Optional[float] = field(default=None, metadata={'description': 'Sets the number of Always Ready instances for a given function group or a specific function. For additional information see https://aka.ms/flexconsumption/alwaysready.'})  # fmt: skip
    name: Optional[str] = field(default=None, metadata={'description': 'Either a function group or a function name is required. For additional information see https://aka.ms/flexconsumption/alwaysready.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureFunctionsScaleAndConcurrency:
    kind: ClassVar[str] = "azure_functions_scale_and_concurrency"
    mapping: ClassVar[Dict[str, Bender]] = {
        "always_ready": S("alwaysReady") >> ForallBend(AzureFunctionsAlwaysReadyConfig.mapping),
        "instance_memory_mb": S("instanceMemoryMB"),
        "maximum_instance_count": S("maximumInstanceCount"),
        "http_trigger_instance_concurrency": S("triggers", "http", "perInstanceConcurrency"),
    }
    always_ready: Optional[List[AzureFunctionsAlwaysReadyConfig]] = field(default=None, metadata={'description': ' Always Ready configuration for the function app.'})  # fmt: skip
    instance_memory_mb: Optional[float] = field(default=None, metadata={'description': 'Set the amount of memory allocated to each instance of the function app in MB. CPU and network bandwidth are allocated proportionally.'})  # fmt: skip
    maximum_instance_count: Optional[float] = field(default=None, metadata={'description': 'The maximum number of instances for the function app.'})  # fmt: skip
    http_trigger_instance_concurrency: Optional[float] = field(default=None, metadata={'description': 'Scale and concurrency settings for the HTTP trigger.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureFunctionAppConfig:
    kind: ClassVar[str] = "azure_function_app_config"
    mapping: ClassVar[Dict[str, Bender]] = {
        "deployment": S("deployment") >> Bend(AzureFunctionsDeployment.mapping),
        "runtime": S("runtime") >> Bend(AzureFunctionsRuntime.mapping),
        "scale_and_concurrency": S("scaleAndConcurrency") >> Bend(AzureFunctionsScaleAndConcurrency.mapping),
    }
    deployment: Optional[AzureFunctionsDeployment] = field(default=None, metadata={'description': 'Configuration section for the function app deployment.'})  # fmt: skip
    runtime: Optional[AzureFunctionsRuntime] = field(default=None, metadata={'description': 'Function app runtime name and version.'})  # fmt: skip
    scale_and_concurrency: Optional[AzureFunctionsScaleAndConcurrency] = field(default=None, metadata={'description': 'Scale and concurrency settings for the function app.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureDaprConfig:
    kind: ClassVar[str] = "azure_dapr_config"
    mapping: ClassVar[Dict[str, Bender]] = {
        "app_id": S("appId"),
        "app_port": S("appPort"),
        "enable_api_logging": S("enableApiLogging"),
        "enabled": S("enabled"),
        "http_max_request_size": S("httpMaxRequestSize"),
        "http_read_buffer_size": S("httpReadBufferSize"),
        "log_level": S("logLevel"),
    }
    app_id: Optional[str] = field(default=None, metadata={"description": "Dapr application identifier"})
    app_port: Optional[int] = field(default=None, metadata={'description': 'Tells Dapr which port your application is listening on'})  # fmt: skip
    enable_api_logging: Optional[bool] = field(default=None, metadata={'description': 'Enables API logging for the Dapr sidecar'})  # fmt: skip
    enabled: Optional[bool] = field(default=None, metadata={'description': 'Boolean indicating if the Dapr side car is enabled'})  # fmt: skip
    http_max_request_size: Optional[int] = field(default=None, metadata={'description': 'Increasing max size of request body http servers parameter in MB to handle uploading of big files. Default is 4 MB.'})  # fmt: skip
    http_read_buffer_size: Optional[int] = field(default=None, metadata={'description': 'Dapr max size of http header read buffer in KB to handle when sending multi-KB headers. Default is 65KB.'})  # fmt: skip
    log_level: Optional[str] = field(default=None, metadata={'description': 'Sets the log level for the Dapr sidecar. Allowed values are debug, info, warn, error. Default is info.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureResourceConfig:
    kind: ClassVar[str] = "azure_resource_config"
    mapping: ClassVar[Dict[str, Bender]] = {"cpu": S("cpu"), "memory": S("memory")}
    cpu: Optional[float] = field(default=None, metadata={"description": "Required CPU in cores, e.g. 0.5"})
    memory: Optional[str] = field(default=None, metadata={"description": "Required memory, e.g. 1Gi "})


@define(eq=False, slots=False)
class AzureCloningInfo:
    kind: ClassVar[str] = "azure_cloning_info"
    mapping: ClassVar[Dict[str, Bender]] = {
        "app_settings_overrides": S("appSettingsOverrides"),
        "clone_custom_host_names": S("cloneCustomHostNames"),
        "clone_source_control": S("cloneSourceControl"),
        "configure_load_balancing": S("configureLoadBalancing"),
        "correlation_id": S("correlationId"),
        "hosting_environment": S("hostingEnvironment"),
        "overwrite": S("overwrite"),
        "source_web_app_id": S("sourceWebAppId"),
        "source_web_app_location": S("sourceWebAppLocation"),
        "traffic_manager_profile_id": S("trafficManagerProfileId"),
        "traffic_manager_profile_name": S("trafficManagerProfileName"),
    }
    app_settings_overrides: Optional[Dict[str, str]] = field(default=None, metadata={'description': 'Application setting overrides for cloned app. If specified, these settings override the settings cloned from source app. Otherwise, application settings from source app are retained.'})  # fmt: skip
    clone_custom_host_names: Optional[bool] = field(default=None, metadata={'description': '<code>true</code> to clone custom hostnames from source app; otherwise, <code>false</code>.'})  # fmt: skip
    clone_source_control: Optional[bool] = field(default=None, metadata={'description': '<code>true</code> to clone source control from source app; otherwise, <code>false</code>.'})  # fmt: skip
    configure_load_balancing: Optional[bool] = field(default=None, metadata={'description': '<code>true</code> to configure load balancing for source and destination app.'})  # fmt: skip
    correlation_id: Optional[str] = field(default=None, metadata={'description': 'Correlation ID of cloning operation. This ID ties multiple cloning operations together to use the same snapshot.'})  # fmt: skip
    hosting_environment: Optional[str] = field(default=None, metadata={"description": "App Service Environment."})
    overwrite: Optional[bool] = field(default=None, metadata={'description': '<code>true</code> to overwrite destination app; otherwise, <code>false</code>.'})  # fmt: skip
    source_web_app_id: Optional[str] = field(default=None, metadata={'description': 'ARM resource ID of the source app. App resource ID is of the form /subscriptions/{subId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Web/sites/{siteName} for production slots and /subscriptions/{subId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Web/sites/{siteName}/slots/{slotName} for other slots.'})  # fmt: skip
    source_web_app_location: Optional[str] = field(default=None, metadata={'description': 'Location of source app ex: West US or North Europe'})  # fmt: skip
    traffic_manager_profile_id: Optional[str] = field(default=None, metadata={'description': 'ARM resource ID of the Traffic Manager profile to use, if it exists. Traffic Manager resource ID is of the form /subscriptions/{subId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Network/trafficManagerProfiles/{profileName}.'})  # fmt: skip
    traffic_manager_profile_name: Optional[str] = field(default=None, metadata={'description': 'Name of Traffic Manager profile to create. This is only needed if Traffic Manager profile does not already exist.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureSlotSwapStatus:
    kind: ClassVar[str] = "azure_slot_swap_status"
    mapping: ClassVar[Dict[str, Bender]] = {
        "destination_slot_name": S("destinationSlotName"),
        "source_slot_name": S("sourceSlotName"),
        "timestamp_utc": S("timestampUtc"),
    }
    destination_slot_name: Optional[str] = field(default=None, metadata={'description': 'The destination slot of the last swap operation.'})  # fmt: skip
    source_slot_name: Optional[str] = field(default=None, metadata={'description': 'The source slot of the last swap operation.'})  # fmt: skip
    timestamp_utc: Optional[datetime] = field(default=None, metadata={'description': 'The time the last successful slot swap completed.'})  # fmt: skip


@define(eq=False, slots=True)
class AzureWebAppAuthIdentityProvider:
    kind: ClassVar[str] = "azure_web_app_auth_identity_provider"
    mapping: ClassVar[Dict[str, Bender]] = {
        "enabled": S("enabled"),
        "login": S("login") >> NoneIfEmpty,
        "registration": S("registration") >> NoneIfEmpty,
        "validation": S("validation") >> NoneIfEmpty,
    }
    enabled: Optional[bool] = field(default=None, metadata={'description': 'Flag to enable or disable authentication for the app.'})  # fmt: skip
    login: Optional[Json] = field(default=None, metadata={'description': 'Login settings for the app.'})  # fmt: skip
    registration: Optional[Json] = field(default=None, metadata={'description': 'Registration settings for the app.'})  # fmt: skip
    validation: Optional[Json] = field(default=None, metadata={'description': 'Validation settings for the app.'})  # fmt: skip


@define(eq=False, slots=True)
class AzureWebAppAuthSettings:
    kind: ClassVar[str] = "azure_web_app_auth_settings"
    mapping: ClassVar[Dict[str, Bender]] = {
        "enabled": S("properties", "platform", "enabled"),
        "runtime_version": S("properties", "platform", "runtimeVersion"),
        "require_https": S("properties", "httpSettings", "requireHttps"),
        "require_authentication": S("properties", "globalValidation", "requireAuthentication"),
        "identity_provider": S("properties", "identityProviders")
        >> MapDict(value_bender=Bend(AzureWebAppAuthIdentityProvider.mapping)),
    }
    enabled: Optional[bool] = field(default=None, metadata={'description': 'Flag to enable or disable authentication for the app.'})  # fmt: skip
    runtime_version: Optional[str] = field(default=None, metadata={'description': 'Runtime version of the authentication provider.'})  # fmt: skip
    require_https: Optional[bool] = field(default=None, metadata={'description': 'Flag to require HTTPS for the app.'})  # fmt: skip
    require_authentication: Optional[bool] = field(default=None, metadata={'description': 'Flag to require authentication for the app.'})  # fmt: skip
    identity_provider: Optional[Dict[str, AzureWebAppAuthIdentityProvider]] = field(default=None, metadata={'description': 'Identity providers for the app.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureWebApp(MicrosoftResource, BaseServerlessFunction):
    kind: ClassVar[str] = "azure_web_app"
    _kind_display: ClassVar[str] = "Azure Web App"
    _kind_service: ClassVar[Optional[str]] = service_name
    _kind_description: ClassVar[str] = "Azure Web App is a cloud-based platform for hosting web applications. It supports multiple programming languages and frameworks, offering automatic scaling and load balancing. Users can deploy code directly from version control systems, configure custom domains, and implement SSL certificates. The service integrates with other Azure products for monitoring, security, and database connectivity."  # fmt: skip
    _docs_url: ClassVar[str] = "https://learn.microsoft.com/en-us/azure/app-service/"
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "function", "group": "compute"}
    api_spec: ClassVar[AzureResourceSpec] = AzureResourceSpec(
        service="web",
        version="2023-12-01",
        path="/subscriptions/{subscriptionId}/providers/Microsoft.Web/sites",
        path_parameters=["subscriptionId"],
        query_parameters=["api-version"],
        access_path="value",
        expect_array=True,
    )
    _reference_kinds: ClassVar[ModelReference] = {
        "successors": {
            "default": [
                "azure_web_app_service_plan",
            ]
        },
    }
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "availability_state": S("properties", "availabilityState"),
        "client_affinity_enabled": S("properties", "clientAffinityEnabled"),
        "client_cert_enabled": S("properties", "clientCertEnabled"),
        "client_cert_exclusion_paths": S("properties", "clientCertExclusionPaths"),
        "client_cert_mode": S("properties", "clientCertMode"),
        "cloning_info": S("properties", "cloningInfo") >> Bend(AzureCloningInfo.mapping),
        "container_size": S("properties", "containerSize"),
        "custom_domain_verification_id": S("properties", "customDomainVerificationId"),
        "daily_memory_time_quota": S("properties", "dailyMemoryTimeQuota"),
        "dapr_config": S("properties", "daprConfig") >> Bend(AzureDaprConfig.mapping),
        "default_host_name": S("properties", "defaultHostName"),
        "dns_configuration": S("properties", "dnsConfiguration") >> Bend(AzureSiteDnsConfig.mapping),
        "enabled": S("properties", "enabled"),
        "enabled_host_names": S("properties", "enabledHostNames"),
        "extended_location": S("extendedLocation") >> Bend(AzureExtendedLocation.mapping),
        "function_app_config": S("properties", "functionAppConfig") >> Bend(AzureFunctionAppConfig.mapping),
        "host_name_ssl_states": S("properties", "hostNameSslStates") >> ForallBend(AzureHostNameSslState.mapping),
        "host_names": S("properties", "hostNames"),
        "host_names_disabled": S("properties", "hostNamesDisabled"),
        "hosting_environment_profile": S("properties", "hostingEnvironmentProfile")
        >> Bend(AzureHostingEnvironmentProfile.mapping),
        "https_only": S("properties", "httpsOnly"),
        "hyper_v": S("properties", "hyperV"),
        "identity": S("identity") >> Bend(AzureManagedServiceIdentity.mapping),
        "in_progress_operation_id": S("properties", "inProgressOperationId"),
        "is_default_container": S("properties", "isDefaultContainer"),
        "is_xenon": S("properties", "isXenon"),
        "key_vault_reference_identity": S("properties", "keyVaultReferenceIdentity"),
        "azure_kind": S("kind"),
        "last_modified_time_utc": S("properties", "lastModifiedTimeUtc"),
        "managed_environment_id": S("properties", "managedEnvironmentId"),
        "max_number_of_workers": S("properties", "maxNumberOfWorkers"),
        "outbound_ip_addresses": S("properties", "outboundIpAddresses"),
        "possible_outbound_ip_addresses": S("properties", "possibleOutboundIpAddresses"),
        "public_network_access": S("properties", "publicNetworkAccess"),
        "redundancy_mode": S("properties", "redundancyMode"),
        "repository_site_name": S("properties", "repositorySiteName"),
        "reserved": S("properties", "reserved"),
        "resource_config": S("properties", "resourceConfig") >> Bend(AzureResourceConfig.mapping),
        "resource_group": S("properties", "resourceGroup"),
        "scm_site_also_stopped": S("properties", "scmSiteAlsoStopped"),
        "server_farm_id": S("properties", "serverFarmId"),
        "site_config": S("properties", "siteConfig") >> Bend(AzureSiteConfig.mapping),
        "slot_swap_status": S("properties", "slotSwapStatus") >> Bend(AzureSlotSwapStatus.mapping),
        "state": S("properties", "state"),
        "storage_account_required": S("properties", "storageAccountRequired"),
        "suspended_till": S("properties", "suspendedTill"),
        "target_swap_slot": S("properties", "targetSwapSlot"),
        "traffic_manager_host_names": S("properties", "trafficManagerHostNames"),
        "usage_state": S("properties", "usageState"),
        "site_virtual_network_subnet_id": S("properties", "virtualNetworkSubnetId"),
        "vnet_backup_restore_enabled": S("properties", "vnetBackupRestoreEnabled"),
        "vnet_content_share_enabled": S("properties", "vnetContentShareEnabled"),
        "vnet_image_pull_enabled": S("properties", "vnetImagePullEnabled"),
        "vnet_route_all_enabled": S("properties", "vnetRouteAllEnabled"),
        "workload_profile_name": S("properties", "workloadProfileName"),
        "memory_size": S("properties", "siteConfig", "limits", "maxMemoryInMb"),
    }
    availability_state: Optional[str] = field(default=None, metadata={'description': 'Management information availability state for the app.'})  # fmt: skip
    client_affinity_enabled: Optional[bool] = field(default=None, metadata={'description': '<code>true</code> to enable client affinity; <code>false</code> to stop sending session affinity cookies, which route client requests in the same session to the same instance. Default is <code>true</code>.'})  # fmt: skip
    client_cert_enabled: Optional[bool] = field(default=None, metadata={'description': '<code>true</code> to enable client certificate authentication (TLS mutual authentication); otherwise, <code>false</code>. Default is <code>false</code>.'})  # fmt: skip
    client_cert_exclusion_paths: Optional[str] = field(default=None, metadata={'description': 'client certificate authentication comma-separated exclusion paths'})  # fmt: skip
    client_cert_mode: Optional[str] = field(default=None, metadata={'description': 'This composes with ClientCertEnabled setting. - ClientCertEnabled: false means ClientCert is ignored. - ClientCertEnabled: true and ClientCertMode: Required means ClientCert is required. - ClientCertEnabled: true and ClientCertMode: Optional means ClientCert is optional or accepted.'})  # fmt: skip
    cloning_info: Optional[AzureCloningInfo] = field(default=None, metadata={'description': 'Information needed for cloning operation.'})  # fmt: skip
    container_size: Optional[int] = field(default=None, metadata={"description": "Size of the function container."})
    custom_domain_verification_id: Optional[str] = field(default=None, metadata={'description': 'Unique identifier that verifies the custom domains assigned to the app. Customer will add this id to a txt record for verification.'})  # fmt: skip
    daily_memory_time_quota: Optional[int] = field(default=None, metadata={'description': 'Maximum allowed daily memory-time quota (applicable on dynamic apps only).'})  # fmt: skip
    dapr_config: Optional[AzureDaprConfig] = field(default=None, metadata={"description": "App Dapr configuration."})
    default_host_name: Optional[str] = field(default=None, metadata={'description': 'Default hostname of the app. Read-only.'})  # fmt: skip
    dns_configuration: Optional[AzureSiteDnsConfig] = field(default=None, metadata={"description": ""})
    enabled: Optional[bool] = field(default=None, metadata={'description': '<code>true</code> if the app is enabled; otherwise, <code>false</code>. Setting this value to false disables the app (takes the app offline).'})  # fmt: skip
    enabled_host_names: Optional[List[str]] = field(default=None, metadata={'description': 'Enabled hostnames for the app.Hostnames need to be assigned (see HostNames) AND enabled. Otherwise, the app is not served on those hostnames.'})  # fmt: skip
    extended_location: Optional[AzureExtendedLocation] = field(default=None, metadata={'description': 'Extended Location.'})  # fmt: skip
    function_app_config: Optional[AzureFunctionAppConfig] = field(default=None, metadata={'description': 'Function app configuration.'})  # fmt: skip
    host_name_ssl_states: Optional[List[AzureHostNameSslState]] = field(default=None, metadata={'description': 'Hostname SSL states are used to manage the SSL bindings for app s hostnames.'})  # fmt: skip
    host_names: Optional[List[str]] = field(
        default=None, metadata={"description": "Hostnames associated with the app."}
    )
    host_names_disabled: Optional[bool] = field(default=None, metadata={'description': '<code>true</code> to disable the public hostnames of the app; otherwise, <code>false</code>. If <code>true</code>, the app is only accessible via API management process.'})  # fmt: skip
    hosting_environment_profile: Optional[AzureHostingEnvironmentProfile] = field(default=None, metadata={'description': 'Specification for an App Service Environment to use for this resource.'})  # fmt: skip
    https_only: Optional[bool] = field(default=None, metadata={'description': 'HttpsOnly: configures a web site to accept only https requests. Issues redirect for http requests'})  # fmt: skip
    hyper_v: Optional[bool] = field(default=None, metadata={"description": "Hyper-V sandbox."})
    identity: Optional[AzureManagedServiceIdentity] = field(default=None, metadata={'description': 'Managed service identity.'})  # fmt: skip
    in_progress_operation_id: Optional[str] = field(default=None, metadata={'description': 'Specifies an operation id if this site has a pending operation.'})  # fmt: skip
    is_default_container: Optional[bool] = field(default=None, metadata={'description': '<code>true</code> if the app is a default container; otherwise, <code>false</code>.'})  # fmt: skip
    is_xenon: Optional[bool] = field(default=None, metadata={"description": "Obsolete: Hyper-V sandbox."})
    key_vault_reference_identity: Optional[str] = field(default=None, metadata={'description': 'Identity to use for Key Vault Reference authentication.'})  # fmt: skip
    azure_kind: Optional[str] = field(default=None, metadata={"description": "Kind of resource."})
    last_modified_time_utc: Optional[datetime] = field(default=None, metadata={'description': 'Last time the app was modified, in UTC. Read-only.'})  # fmt: skip
    managed_environment_id: Optional[str] = field(default=None, metadata={'description': 'Azure Resource Manager ID of the customer s selected Managed Environment on which to host this app. This must be of the form /subscriptions/{subscriptionId}/resourceGroups/{resourceGroup}/providers/Microsoft.App/managedEnvironments/{managedEnvironmentName}'})  # fmt: skip
    max_number_of_workers: Optional[int] = field(default=None, metadata={'description': 'Maximum number of workers. This only applies to Functions container.'})  # fmt: skip
    outbound_ip_addresses: Optional[str] = field(default=None, metadata={'description': 'List of IP addresses that the app uses for outbound connections (e.g. database access). Includes VIPs from tenants that site can be hosted with current settings. Read-only.'})  # fmt: skip
    possible_outbound_ip_addresses: Optional[str] = field(default=None, metadata={'description': 'List of IP addresses that the app uses for outbound connections (e.g. database access). Includes VIPs from all tenants except dataComponent. Read-only.'})  # fmt: skip
    public_network_access: Optional[str] = field(default=None, metadata={'description': 'Property to allow or block all public traffic. Allowed Values: Enabled , Disabled or an empty string.'})  # fmt: skip
    redundancy_mode: Optional[str] = field(default=None, metadata={"description": "Site redundancy mode"})
    repository_site_name: Optional[str] = field(default=None, metadata={"description": "Name of the repository site."})
    reserved: Optional[bool] = field(default=None, metadata={'description': '<code>true</code> if reserved; otherwise, <code>false</code>.'})  # fmt: skip
    resource_config: Optional[AzureResourceConfig] = field(default=None, metadata={'description': 'Function app resource requirements.'})  # fmt: skip
    resource_group: Optional[str] = field(default=None, metadata={'description': 'Name of the resource group the app belongs to. Read-only.'})  # fmt: skip
    scm_site_also_stopped: Optional[bool] = field(default=None, metadata={'description': '<code>true</code> to stop SCM (KUDU) site when the app is stopped; otherwise, <code>false</code>. The default is <code>false</code>.'})  # fmt: skip
    server_farm_id: Optional[str] = field(default=None, metadata={'description': 'Resource ID of the associated App Service plan, formatted as: /subscriptions/{subscriptionID}/resourceGroups/{groupName}/providers/Microsoft.Web/serverfarms/{appServicePlanName} .'})  # fmt: skip
    site_config: Optional[AzureSiteConfig] = field(default=None, metadata={'description': 'Configuration of an App Service app.'})  # fmt: skip
    slot_swap_status: Optional[AzureSlotSwapStatus] = field(default=None, metadata={'description': 'The status of the last successful slot swap operation.'})  # fmt: skip
    state: Optional[str] = field(default=None, metadata={"description": "Current state of the app."})
    storage_account_required: Optional[bool] = field(default=None, metadata={'description': 'Checks if Customer provided storage account is required'})  # fmt: skip
    suspended_till: Optional[datetime] = field(default=None, metadata={'description': 'App suspended till in case memory-time quota is exceeded.'})  # fmt: skip
    target_swap_slot: Optional[str] = field(default=None, metadata={'description': 'Specifies which deployment slot this app will swap into. Read-only.'})  # fmt: skip
    traffic_manager_host_names: Optional[List[str]] = field(default=None, metadata={'description': 'Azure Traffic Manager hostnames associated with the app. Read-only.'})  # fmt: skip
    usage_state: Optional[str] = field(default=None, metadata={'description': 'State indicating whether the app has exceeded its quota usage. Read-only.'})  # fmt: skip
    site_virtual_network_subnet_id: Optional[str] = field(default=None, metadata={'description': 'Azure Resource Manager ID of the Virtual network and subnet to be joined by Regional VNET Integration. This must be of the form /subscriptions/{subscriptionName}/resourceGroups/{resourceGroupName}/providers/Microsoft.Network/virtualNetworks/{vnetName}/subnets/{subnetName}'})  # fmt: skip
    vnet_backup_restore_enabled: Optional[bool] = field(default=None, metadata={'description': 'To enable Backup and Restore operations over virtual network'})  # fmt: skip
    vnet_content_share_enabled: Optional[bool] = field(default=None, metadata={'description': 'To enable accessing content over virtual network'})  # fmt: skip
    vnet_image_pull_enabled: Optional[bool] = field(default=None, metadata={'description': 'To enable pulling image over Virtual Network'})  # fmt: skip
    vnet_route_all_enabled: Optional[bool] = field(default=None, metadata={'description': 'Virtual Network Route All enabled. This causes all outbound traffic to have Virtual Network Security Groups and User Defined Routes applied.'})  # fmt: skip
    workload_profile_name: Optional[str] = field(default=None, metadata={'description': 'Workload profile name for function app to execute on.'})  # fmt: skip
    app_authentication_settings: Optional[AzureWebAppAuthSettings] = field(default=None, metadata={'description': 'Authentication settings for the app.'})  # fmt: skip

    def post_process(self, graph_builder: GraphBuilder, source: Json) -> None:
        def auth_settings() -> None:
            for dep_json in graph_builder.client.list(
                AzureResourceSpec(
                    service=self.api_spec.service,
                    version=self.api_spec.version,
                    path=f"{self.id}/config/authsettingsV2/list",
                    query_parameters=["api-version"],
                    expect_array=True,
                )
            ):
                self.app_authentication_settings = parse_json(
                    dep_json, AzureWebAppAuthSettings, graph_builder, AzureWebAppAuthSettings.mapping
                )

        graph_builder.submit_work(service_name, auth_settings)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if server_farm_id := self.server_farm_id:
            builder.add_edge(self, clazz=AzureWebAppServicePlan, id=server_farm_id)


@define(eq=False, slots=False)
class AzureStaticSiteBuildProperties:
    kind: ClassVar[str] = "azure_static_site_build_properties"
    mapping: ClassVar[Dict[str, Bender]] = {
        "api_build_command": S("apiBuildCommand"),
        "api_location": S("apiLocation"),
        "app_artifact_location": S("appArtifactLocation"),
        "app_build_command": S("appBuildCommand"),
        "app_location": S("appLocation"),
        "github_action_secret_name_override": S("githubActionSecretNameOverride"),
        "output_location": S("outputLocation"),
        "skip_github_action_workflow_generation": S("skipGithubActionWorkflowGeneration"),
    }
    api_build_command: Optional[str] = field(default=None, metadata={'description': 'A custom command to run during deployment of the Azure Functions API application.'})  # fmt: skip
    api_location: Optional[str] = field(default=None, metadata={'description': 'The path to the api code within the repository.'})  # fmt: skip
    app_artifact_location: Optional[str] = field(default=None, metadata={'description': 'Deprecated: The path of the app artifacts after building (deprecated in favor of OutputLocation)'})  # fmt: skip
    app_build_command: Optional[str] = field(default=None, metadata={'description': 'A custom command to run during deployment of the static content application.'})  # fmt: skip
    app_location: Optional[str] = field(default=None, metadata={'description': 'The path to the app code within the repository.'})  # fmt: skip
    github_action_secret_name_override: Optional[str] = field(default=None, metadata={'description': 'Github Action secret name override.'})  # fmt: skip
    output_location: Optional[str] = field(default=None, metadata={'description': 'The output path of the app after building.'})  # fmt: skip
    skip_github_action_workflow_generation: Optional[bool] = field(default=None, metadata={'description': 'Skip Github Action workflow generation.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureStaticSiteTemplateOptions:
    kind: ClassVar[str] = "azure_static_site_template_options"
    mapping: ClassVar[Dict[str, Bender]] = {
        "description": S("description"),
        "is_private": S("isPrivate"),
        "owner": S("owner"),
        "repository_name": S("repositoryName"),
        "template_repository_url": S("templateRepositoryUrl"),
    }
    description: Optional[str] = field(default=None, metadata={'description': 'Description of the newly generated repository.'})  # fmt: skip
    is_private: Optional[bool] = field(default=None, metadata={'description': 'Whether or not the newly generated repository is a private repository. Defaults to false (i.e. public).'})  # fmt: skip
    owner: Optional[str] = field(default=None, metadata={"description": "Owner of the newly generated repository."})
    repository_name: Optional[str] = field(default=None, metadata={'description': 'Name of the newly generated repository.'})  # fmt: skip
    template_repository_url: Optional[str] = field(default=None, metadata={'description': 'URL of the template repository. The newly generated repository will be based on this one.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureStaticSiteUserProvidedFunctionApp(AzureProxyOnlyResource):
    kind: ClassVar[str] = "azure_static_site_user_provided_function_app"
    mapping: ClassVar[Dict[str, Bender]] = AzureProxyOnlyResource.mapping | {
        "created_on": S("properties", "createdOn"),
        "function_app_region": S("properties", "functionAppRegion"),
        "function_app_resource_id": S("properties", "functionAppResourceId"),
    }
    created_on: Optional[datetime] = field(default=None, metadata={'description': 'The date and time on which the function app was registered with the static site.'})  # fmt: skip
    function_app_region: Optional[str] = field(default=None, metadata={'description': 'The region of the function app registered with the static site'})  # fmt: skip
    function_app_resource_id: Optional[str] = field(default=None, metadata={'description': 'The resource id of the function app registered with the static site'})  # fmt: skip


@define(eq=False, slots=False)
class AzureStaticSiteLinkedBackend:
    kind: ClassVar[str] = "azure_static_site_linked_backend"
    mapping: ClassVar[Dict[str, Bender]] = {
        "backend_resource_id": S("backendResourceId"),
        "created_on": S("createdOn"),
        "provisioning_state": S("provisioningState"),
        "region": S("region"),
    }
    backend_resource_id: Optional[str] = field(default=None, metadata={'description': 'The resource id of the backend linked to the static site'})  # fmt: skip
    created_on: Optional[datetime] = field(default=None, metadata={'description': 'The date and time on which the backend was linked to the static site.'})  # fmt: skip
    provisioning_state: Optional[str] = field(default=None, metadata={'description': 'The provisioning state of the linking process.'})  # fmt: skip
    region: Optional[str] = field(default=None, metadata={'description': 'The region of the backend linked to the static site'})  # fmt: skip


@define(eq=False, slots=False)
class AzureStaticSiteDatabaseConnectionConfigurationFileOverview:
    kind: ClassVar[str] = "azure_static_site_database_connection_configuration_file_overview"
    mapping: ClassVar[Dict[str, Bender]] = {"contents": S("contents"), "file_name": S("fileName"), "type": S("type")}
    contents: Optional[str] = field(default=None, metadata={'description': 'The Base64 encoding of the file contents.'})  # fmt: skip
    file_name: Optional[str] = field(default=None, metadata={"description": "The name of the configuration file."})
    type: Optional[str] = field(default=None, metadata={"description": "The type of configuration file."})


@define(eq=False, slots=False)
class AzureDatabaseConnectionOverview:
    kind: ClassVar[str] = "azure_database_connection_overview"
    mapping: ClassVar[Dict[str, Bender]] = {
        "configuration_files": S("configurationFiles")
        >> ForallBend(AzureStaticSiteDatabaseConnectionConfigurationFileOverview.mapping),
        "connection_identity": S("connectionIdentity"),
        "name": S("name"),
        "region": S("region"),
        "resource_id": S("resourceId"),
    }
    configuration_files: Optional[List[AzureStaticSiteDatabaseConnectionConfigurationFileOverview]] = field(default=None, metadata={'description': 'A list of configuration files associated with this database connection.'})  # fmt: skip
    connection_identity: Optional[str] = field(default=None, metadata={'description': 'If present, the identity is used in conjunction with connection string to connect to the database. Use of the system-assigned managed identity is indicated with the string SystemAssigned , while use of a user-assigned managed identity is indicated with the resource id of the managed identity resource.'})  # fmt: skip
    name: Optional[str] = field(default=None, metadata={'description': 'If present, the name of this database connection resource.'})  # fmt: skip
    region: Optional[str] = field(default=None, metadata={"description": "The region of the database resource."})
    resource_id: Optional[str] = field(default=None, metadata={"description": "The resource id of the database."})


@define(eq=False, slots=False)
class AzureWebAppStaticSite(MicrosoftResource):
    kind: ClassVar[str] = "azure_web_app_static_site"
    _kind_display: ClassVar[str] = "Azure Web App Static Site"
    _kind_service: ClassVar[Optional[str]] = service_name
    _kind_description: ClassVar[str] = "Azure Web App Static Site is a service for hosting static web content. It offers global content distribution, automated builds and deployments from code repositories, and integration with Azure services. Users can deploy HTML, CSS, JavaScript, and image files directly from their repositories, with support for custom domains and free SSL certificates."  # fmt: skip
    _docs_url: ClassVar[str] = "https://learn.microsoft.com/en-us/azure/static-web-apps/"
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "service", "group": "compute"}
    api_spec: ClassVar[AzureResourceSpec] = AzureResourceSpec(
        service="web",
        version="2023-12-01",
        path="/subscriptions/{subscriptionId}/providers/Microsoft.Web/staticSites",
        path_parameters=["subscriptionId"],
        query_parameters=["api-version"],
        access_path="value",
        expect_array=True,
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "allow_config_file_updates": S("properties", "allowConfigFileUpdates"),
        "branch": S("properties", "branch"),
        "build_properties": S("properties", "buildProperties") >> Bend(AzureStaticSiteBuildProperties.mapping),
        "content_distribution_endpoint": S("properties", "contentDistributionEndpoint"),
        "custom_domains": S("properties", "customDomains"),
        "database_connections": S("properties", "databaseConnections")
        >> ForallBend(AzureDatabaseConnectionOverview.mapping),
        "default_hostname": S("properties", "defaultHostname"),
        "enterprise_grade_cdn_status": S("properties", "enterpriseGradeCdnStatus"),
        "identity": S("identity") >> Bend(AzureManagedServiceIdentity.mapping),
        "key_vault_reference_identity": S("properties", "keyVaultReferenceIdentity"),
        "azure_kind": S("kind"),
        "linked_backends": S("properties", "linkedBackends") >> ForallBend(AzureStaticSiteLinkedBackend.mapping),
        "private_endpoint_connections": S("properties", "privateEndpointConnections")
        >> ForallBend(AzurePrivateEndpointConnection.mapping),
        "provider": S("properties", "provider"),
        "public_network_access": S("properties", "publicNetworkAccess"),
        "repository_token": S("properties", "repositoryToken"),
        "repository_url": S("properties", "repositoryUrl"),
        "azure_sku": S("sku") >> Bend(AzureSku.mapping),
        "staging_environment_policy": S("properties", "stagingEnvironmentPolicy"),
        "site_template_properties": S("properties", "templateProperties")
        >> Bend(AzureStaticSiteTemplateOptions.mapping),
        "user_provided_function_apps": S("properties", "userProvidedFunctionApps")
        >> ForallBend(AzureStaticSiteUserProvidedFunctionApp.mapping),
    }
    allow_config_file_updates: Optional[bool] = field(default=None, metadata={'description': '<code>false</code> if config file is locked for this static web app; otherwise, <code>true</code>.'})  # fmt: skip
    branch: Optional[str] = field(default=None, metadata={"description": "The target branch in the repository."})
    build_properties: Optional[AzureStaticSiteBuildProperties] = field(default=None, metadata={'description': 'Build properties for the static site.'})  # fmt: skip
    content_distribution_endpoint: Optional[str] = field(default=None, metadata={'description': 'The content distribution endpoint for the static site.'})  # fmt: skip
    custom_domains: Optional[List[str]] = field(default=None, metadata={'description': 'The custom domains associated with this static site.'})  # fmt: skip
    database_connections: Optional[List[AzureDatabaseConnectionOverview]] = field(default=None, metadata={'description': 'Database connections for the static site'})  # fmt: skip
    default_hostname: Optional[str] = field(default=None, metadata={'description': 'The default autogenerated hostname for the static site.'})  # fmt: skip
    enterprise_grade_cdn_status: Optional[str] = field(default=None, metadata={'description': 'State indicating the status of the enterprise grade CDN serving traffic to the static web app.'})  # fmt: skip
    identity: Optional[AzureManagedServiceIdentity] = field(default=None, metadata={'description': 'Managed service identity.'})  # fmt: skip
    key_vault_reference_identity: Optional[str] = field(default=None, metadata={'description': 'Identity to use for Key Vault Reference authentication.'})  # fmt: skip
    azure_kind: Optional[str] = field(default=None, metadata={"description": "Kind of resource."})
    linked_backends: Optional[List[AzureStaticSiteLinkedBackend]] = field(default=None, metadata={'description': 'Backends linked to the static side'})  # fmt: skip
    private_endpoint_connections: Optional[List[AzurePrivateEndpointConnection]] = field(default=None, metadata={'description': 'Private endpoint connections'})  # fmt: skip
    provider: Optional[str] = field(default=None, metadata={'description': 'The provider that submitted the last deployment to the primary environment of the static site.'})  # fmt: skip
    public_network_access: Optional[str] = field(default=None, metadata={'description': 'State indicating whether public traffic are allowed or not for a static web app. Allowed Values: Enabled , Disabled or an empty string.'})  # fmt: skip
    repository_token: Optional[str] = field(default=None, metadata={'description': 'A user s github repository token. This is used to setup the Github Actions workflow file and API secrets.'})  # fmt: skip
    repository_url: Optional[str] = field(default=None, metadata={'description': 'URL for the repository of the static site.'})  # fmt: skip
    azure_sku: Optional[AzureSku] = field(default=None, metadata={'description': 'Description of a SKU for a scalable resource.'})  # fmt: skip
    staging_environment_policy: Optional[str] = field(default=None, metadata={'description': 'State indicating whether staging environments are allowed or not allowed for a static web app.'})  # fmt: skip
    site_template_properties: Optional[AzureStaticSiteTemplateOptions] = field(default=None, metadata={'description': 'Template Options for the static site.'})  # fmt: skip
    user_provided_function_apps: Optional[List[AzureStaticSiteUserProvidedFunctionApp]] = field(default=None, metadata={'description': 'User provided function apps registered with the static site'})  # fmt: skip


resources: List[Type[MicrosoftResource]] = [
    AzureWebAppServicePlan,
    AzureWebApp,
    AzureWebAppStaticSite,
    AzureWebCertificate,
    AzureWebContainerApp,
    AzureWebDomain,
    AzureWebHostingEnvironment,
    AzureWebKubeEnvironment,
]
