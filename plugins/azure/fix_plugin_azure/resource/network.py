from typing import Callable, ClassVar, Dict, Optional, List, Type, Tuple

from attr import define, field

from fix_plugin_azure.azure_client import AzureApiSpec
from fix_plugin_azure.resource.base import (
    AzureResource,
    GraphBuilder,
    AzureSubResource,
    AzureSku,
    AzureExtendedLocation,
    AzurePrincipalidClientid,
    AzurePrivateLinkServiceConnectionState,
)
from fix_plugin_azure.resource.containerservice import AzureManagedCluster
from fix_plugin_azure.utils import rgetattr
from fixlib.baseresources import (
    BaseGateway,
    BaseFirewall,
    BasePolicy,
    BaseLoadBalancer,
    BaseNetwork,
    BaseNetworkQuota,
    BasePeeringConnection,
    ModelReference,
    EdgeType,
)
from fixlib.json_bender import Bender, S, Bend, ForallBend, AsInt, StringToUnitNumber
from fixlib.types import Json


@define(eq=False, slots=False)
class AzureApplicationGatewaySku:
    kind: ClassVar[str] = "azure_application_gateway_sku"
    mapping: ClassVar[Dict[str, Bender]] = {"capacity": S("capacity"), "name": S("name"), "tier": S("tier")}
    capacity: Optional[int] = field(default=None, metadata={'description': 'Capacity (instance count) of an application gateway.'})  # fmt: skip
    name: Optional[str] = field(default=None, metadata={"description": "Name of an application gateway SKU."})
    tier: Optional[str] = field(default=None, metadata={"description": "Tier of an application gateway."})


@define(eq=False, slots=False)
class AzureApplicationGatewaySslPolicy:
    kind: ClassVar[str] = "azure_application_gateway_ssl_policy"
    mapping: ClassVar[Dict[str, Bender]] = {
        "cipher_suites": S("cipherSuites"),
        "disabled_ssl_protocols": S("disabledSslProtocols"),
        "min_protocol_version": S("minProtocolVersion"),
        "policy_name": S("policyName"),
        "policy_type": S("policyType"),
    }
    cipher_suites: Optional[List[str]] = field(default=None, metadata={'description': 'Ssl cipher suites to be enabled in the specified order to application gateway.'})  # fmt: skip
    disabled_ssl_protocols: Optional[List[str]] = field(default=None, metadata={'description': 'Ssl protocols to be disabled on application gateway.'})  # fmt: skip
    min_protocol_version: Optional[str] = field(default=None, metadata={"description": "Ssl protocol enums."})
    policy_name: Optional[str] = field(default=None, metadata={"description": "Ssl predefined policy name enums."})
    policy_type: Optional[str] = field(default=None, metadata={"description": "Type of Ssl Policy."})


@define(eq=False, slots=False)
class AzureApplicationGatewayIPConfiguration(AzureSubResource):
    kind: ClassVar[str] = "azure_application_gateway_ip_configuration"
    mapping: ClassVar[Dict[str, Bender]] = AzureSubResource.mapping | {
        "etag": S("etag"),
        "name": S("name"),
        "provisioning_state": S("properties", "provisioningState"),
        "subnet": S("properties", "subnet", "id"),
        "type": S("type"),
    }
    etag: Optional[str] = field(default=None, metadata={'description': 'A unique read-only string that changes whenever the resource is updated.'})  # fmt: skip
    name: Optional[str] = field(default=None, metadata={'description': 'Name of the IP configuration that is unique within an Application Gateway.'})  # fmt: skip
    provisioning_state: Optional[str] = field(default=None, metadata={'description': 'The current provisioning state.'})  # fmt: skip
    subnet: Optional[str] = field(default=None, metadata={"description": "Reference to another subresource."})
    type: Optional[str] = field(default=None, metadata={"description": "Type of the resource."})


@define(eq=False, slots=False)
class AzureApplicationGatewayAuthenticationCertificate(AzureSubResource):
    kind: ClassVar[str] = "azure_application_gateway_authentication_certificate"
    mapping: ClassVar[Dict[str, Bender]] = AzureSubResource.mapping | {
        "data": S("properties", "data"),
        "etag": S("etag"),
        "name": S("name"),
        "provisioning_state": S("properties", "provisioningState"),
        "type": S("type"),
    }
    data: Optional[str] = field(default=None, metadata={"description": "Certificate public data."})
    etag: Optional[str] = field(default=None, metadata={'description': 'A unique read-only string that changes whenever the resource is updated.'})  # fmt: skip
    name: Optional[str] = field(default=None, metadata={'description': 'Name of the authentication certificate that is unique within an Application Gateway.'})  # fmt: skip
    provisioning_state: Optional[str] = field(default=None, metadata={'description': 'The current provisioning state.'})  # fmt: skip
    type: Optional[str] = field(default=None, metadata={"description": "Type of the resource."})


@define(eq=False, slots=False)
class AzureApplicationGatewayTrustedRootCertificate(AzureSubResource):
    kind: ClassVar[str] = "azure_application_gateway_trusted_root_certificate"
    mapping: ClassVar[Dict[str, Bender]] = AzureSubResource.mapping | {
        "data": S("properties", "data"),
        "etag": S("etag"),
        "key_vault_secret_id": S("properties", "keyVaultSecretId"),
        "name": S("name"),
        "provisioning_state": S("properties", "provisioningState"),
        "type": S("type"),
    }
    data: Optional[str] = field(default=None, metadata={"description": "Certificate public data."})
    etag: Optional[str] = field(default=None, metadata={'description': 'A unique read-only string that changes whenever the resource is updated.'})  # fmt: skip
    key_vault_secret_id: Optional[str] = field(default=None, metadata={'description': 'Secret Id of (base-64 encoded unencrypted pfx) Secret or Certificate object stored in KeyVault.'})  # fmt: skip
    name: Optional[str] = field(default=None, metadata={'description': 'Name of the trusted root certificate that is unique within an Application Gateway.'})  # fmt: skip
    provisioning_state: Optional[str] = field(default=None, metadata={'description': 'The current provisioning state.'})  # fmt: skip
    type: Optional[str] = field(default=None, metadata={"description": "Type of the resource."})


@define(eq=False, slots=False)
class AzureApplicationGatewayTrustedClientCertificate(AzureSubResource):
    kind: ClassVar[str] = "azure_application_gateway_trusted_client_certificate"
    mapping: ClassVar[Dict[str, Bender]] = AzureSubResource.mapping | {
        "client_cert_issuer_dn": S("properties", "clientCertIssuerDN"),
        "data": S("properties", "data"),
        "etag": S("etag"),
        "name": S("name"),
        "provisioning_state": S("properties", "provisioningState"),
        "type": S("type"),
        "validated_cert_data": S("properties", "validatedCertData"),
    }
    client_cert_issuer_dn: Optional[str] = field(default=None, metadata={'description': 'Distinguished name of client certificate issuer.'})  # fmt: skip
    data: Optional[str] = field(default=None, metadata={"description": "Certificate public data."})
    etag: Optional[str] = field(default=None, metadata={'description': 'A unique read-only string that changes whenever the resource is updated.'})  # fmt: skip
    name: Optional[str] = field(default=None, metadata={'description': 'Name of the trusted client certificate that is unique within an Application Gateway.'})  # fmt: skip
    provisioning_state: Optional[str] = field(default=None, metadata={'description': 'The current provisioning state.'})  # fmt: skip
    type: Optional[str] = field(default=None, metadata={"description": "Type of the resource."})
    validated_cert_data: Optional[str] = field(default=None, metadata={"description": "Validated certificate data."})


@define(eq=False, slots=False)
class AzureApplicationGatewaySslCertificate(AzureSubResource):
    kind: ClassVar[str] = "azure_application_gateway_ssl_certificate"
    mapping: ClassVar[Dict[str, Bender]] = AzureSubResource.mapping | {
        "data": S("properties", "data"),
        "etag": S("etag"),
        "key_vault_secret_id": S("properties", "keyVaultSecretId"),
        "name": S("name"),
        "password": S("properties", "password"),
        "provisioning_state": S("properties", "provisioningState"),
        "public_cert_data": S("properties", "publicCertData"),
        "type": S("type"),
    }
    data: Optional[str] = field(default=None, metadata={'description': 'Base-64 encoded pfx certificate. Only applicable in PUT Request.'})  # fmt: skip
    etag: Optional[str] = field(default=None, metadata={'description': 'A unique read-only string that changes whenever the resource is updated.'})  # fmt: skip
    key_vault_secret_id: Optional[str] = field(default=None, metadata={'description': 'Secret Id of (base-64 encoded unencrypted pfx) Secret or Certificate object stored in KeyVault.'})  # fmt: skip
    name: Optional[str] = field(default=None, metadata={'description': 'Name of the SSL certificate that is unique within an Application Gateway.'})  # fmt: skip
    password: Optional[str] = field(default=None, metadata={'description': 'Password for the pfx file specified in data. Only applicable in PUT request.'})  # fmt: skip
    provisioning_state: Optional[str] = field(default=None, metadata={'description': 'The current provisioning state.'})  # fmt: skip
    public_cert_data: Optional[str] = field(default=None, metadata={'description': 'Base-64 encoded Public cert data corresponding to pfx specified in data. Only applicable in GET request.'})  # fmt: skip
    type: Optional[str] = field(default=None, metadata={"description": "Type of the resource."})


@define(eq=False, slots=False)
class AzureApplicationGatewayFrontendIPConfiguration(AzureSubResource):
    kind: ClassVar[str] = "azure_application_gateway_frontend_ip_configuration"
    mapping: ClassVar[Dict[str, Bender]] = AzureSubResource.mapping | {
        "etag": S("etag"),
        "name": S("name"),
        "private_ip_address": S("properties", "privateIPAddress"),
        "private_ip_allocation_method": S("properties", "privateIPAllocationMethod"),
        "private_link_configuration": S("properties", "privateLinkConfiguration", "id"),
        "provisioning_state": S("properties", "provisioningState"),
        "public_ip_address": S("properties", "publicIPAddress", "id"),
        "subnet": S("properties", "subnet", "id"),
        "type": S("type"),
    }
    etag: Optional[str] = field(default=None, metadata={'description': 'A unique read-only string that changes whenever the resource is updated.'})  # fmt: skip
    name: Optional[str] = field(default=None, metadata={'description': 'Name of the frontend IP configuration that is unique within an Application Gateway.'})  # fmt: skip
    private_ip_address: Optional[str] = field(default=None, metadata={'description': 'PrivateIPAddress of the network interface IP Configuration.'})  # fmt: skip
    private_ip_allocation_method: Optional[str] = field(default=None, metadata={'description': 'IP address allocation method.'})  # fmt: skip
    private_link_configuration: Optional[str] = field(default=None, metadata={'description': 'Reference to another subresource.'})  # fmt: skip
    provisioning_state: Optional[str] = field(default=None, metadata={'description': 'The current provisioning state.'})  # fmt: skip
    public_ip_address: Optional[str] = field(default=None, metadata={'description': 'Reference to another subresource.'})  # fmt: skip
    subnet: Optional[str] = field(default=None, metadata={"description": "Reference to another subresource."})
    type: Optional[str] = field(default=None, metadata={"description": "Type of the resource."})


@define(eq=False, slots=False)
class AzureApplicationGatewayFrontendPort(AzureSubResource):
    kind: ClassVar[str] = "azure_application_gateway_frontend_port"
    mapping: ClassVar[Dict[str, Bender]] = AzureSubResource.mapping | {
        "etag": S("etag"),
        "name": S("name"),
        "port": S("properties", "port"),
        "provisioning_state": S("properties", "provisioningState"),
        "type": S("type"),
    }
    etag: Optional[str] = field(default=None, metadata={'description': 'A unique read-only string that changes whenever the resource is updated.'})  # fmt: skip
    name: Optional[str] = field(default=None, metadata={'description': 'Name of the frontend port that is unique within an Application Gateway.'})  # fmt: skip
    port: Optional[int] = field(default=None, metadata={"description": "Frontend port."})
    provisioning_state: Optional[str] = field(default=None, metadata={'description': 'The current provisioning state.'})  # fmt: skip
    type: Optional[str] = field(default=None, metadata={"description": "Type of the resource."})


@define(eq=False, slots=False)
class AzureApplicationGatewayProbeHealthResponseMatch:
    kind: ClassVar[str] = "azure_application_gateway_probe_health_response_match"
    mapping: ClassVar[Dict[str, Bender]] = {"body": S("body"), "status_codes": S("statusCodes")}
    body: Optional[str] = field(default=None, metadata={'description': 'Body that must be contained in the health response. Default value is empty.'})  # fmt: skip
    status_codes: Optional[List[str]] = field(default=None, metadata={'description': 'Allowed ranges of healthy status codes. Default range of healthy status codes is 200-399.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureApplicationGatewayProbe(AzureSubResource):
    kind: ClassVar[str] = "azure_application_gateway_probe"
    mapping: ClassVar[Dict[str, Bender]] = AzureSubResource.mapping | {
        "etag": S("etag"),
        "host": S("properties", "host"),
        "interval": S("properties", "interval"),
        "match": S("properties", "match") >> Bend(AzureApplicationGatewayProbeHealthResponseMatch.mapping),
        "min_servers": S("properties", "minServers"),
        "name": S("name"),
        "path": S("properties", "path"),
        "pick_host_name_from_backend_http_settings": S("properties", "pickHostNameFromBackendHttpSettings"),
        "pick_host_name_from_backend_settings": S("properties", "pickHostNameFromBackendSettings"),
        "port": S("properties", "port"),
        "protocol": S("properties", "protocol"),
        "provisioning_state": S("properties", "provisioningState"),
        "timeout": S("properties", "timeout"),
        "type": S("type"),
        "unhealthy_threshold": S("properties", "unhealthyThreshold"),
    }
    etag: Optional[str] = field(default=None, metadata={'description': 'A unique read-only string that changes whenever the resource is updated.'})  # fmt: skip
    host: Optional[str] = field(default=None, metadata={"description": "Host name to send the probe to."})
    interval: Optional[int] = field(default=None, metadata={'description': 'The probing interval in seconds. This is the time interval between two consecutive probes. Acceptable values are from 1 second to 86400 seconds.'})  # fmt: skip
    match: Optional[AzureApplicationGatewayProbeHealthResponseMatch] = field(default=None, metadata={'description': 'Application gateway probe health response match.'})  # fmt: skip
    min_servers: Optional[int] = field(default=None, metadata={'description': 'Minimum number of servers that are always marked healthy. Default value is 0.'})  # fmt: skip
    name: Optional[str] = field(default=None, metadata={'description': 'Name of the probe that is unique within an Application Gateway.'})  # fmt: skip
    path: Optional[str] = field(default=None, metadata={'description': 'Relative path of probe. Valid path starts from / . Probe is sent to <Protocol>://<host>:<port><path>.'})  # fmt: skip
    pick_host_name_from_backend_http_settings: Optional[bool] = field(default=None, metadata={'description': 'Whether the host header should be picked from the backend http settings. Default value is false.'})  # fmt: skip
    pick_host_name_from_backend_settings: Optional[bool] = field(default=None, metadata={'description': 'Whether the server name indication should be picked from the backend settings for Tls protocol. Default value is false.'})  # fmt: skip
    port: Optional[int] = field(default=None, metadata={'description': 'Custom port which will be used for probing the backend servers. The valid value ranges from 1 to 65535. In case not set, port from http settings will be used. This property is valid for Basic, Standard_v2 and WAF_v2 only.'})  # fmt: skip
    protocol: Optional[str] = field(default=None, metadata={"description": "Application Gateway protocol."})
    provisioning_state: Optional[str] = field(default=None, metadata={'description': 'The current provisioning state.'})  # fmt: skip
    timeout: Optional[int] = field(default=None, metadata={'description': 'The probe timeout in seconds. Probe marked as failed if valid response is not received with this timeout period. Acceptable values are from 1 second to 86400 seconds.'})  # fmt: skip
    type: Optional[str] = field(default=None, metadata={"description": "Type of the resource."})
    unhealthy_threshold: Optional[int] = field(default=None, metadata={'description': 'The probe retry count. Backend server is marked down after consecutive probe failure count reaches UnhealthyThreshold. Acceptable values are from 1 second to 20.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureApplicationGatewayBackendAddress:
    kind: ClassVar[str] = "azure_application_gateway_backend_address"
    mapping: ClassVar[Dict[str, Bender]] = {"fqdn": S("fqdn"), "ip_address": S("ipAddress")}
    fqdn: Optional[str] = field(default=None, metadata={"description": "Fully qualified domain name (FQDN)."})
    ip_address: Optional[str] = field(default=None, metadata={"description": "IP address."})


@define(eq=False, slots=False)
class AzureApplicationGatewayBackendAddressPool(AzureSubResource):
    kind: ClassVar[str] = "azure_application_gateway_backend_address_pool"
    mapping: ClassVar[Dict[str, Bender]] = AzureSubResource.mapping | {
        "backend_addresses": S("properties", "backendAddresses")
        >> ForallBend(AzureApplicationGatewayBackendAddress.mapping),
        "etag": S("etag"),
        "name": S("name"),
        "provisioning_state": S("properties", "provisioningState"),
        "type": S("type"),
    }
    backend_addresses: Optional[List[AzureApplicationGatewayBackendAddress]] = field(default=None, metadata={'description': 'Backend addresses.'})  # fmt: skip
    etag: Optional[str] = field(default=None, metadata={'description': 'A unique read-only string that changes whenever the resource is updated.'})  # fmt: skip
    name: Optional[str] = field(default=None, metadata={'description': 'Name of the backend address pool that is unique within an Application Gateway.'})  # fmt: skip
    provisioning_state: Optional[str] = field(default=None, metadata={'description': 'The current provisioning state.'})  # fmt: skip
    type: Optional[str] = field(default=None, metadata={"description": "Type of the resource."})


@define(eq=False, slots=False)
class AzureApplicationGatewayConnectionDraining:
    kind: ClassVar[str] = "azure_application_gateway_connection_draining"
    mapping: ClassVar[Dict[str, Bender]] = {"drain_timeout_in_sec": S("drainTimeoutInSec"), "enabled": S("enabled")}
    drain_timeout_in_sec: Optional[int] = field(default=None, metadata={'description': 'The number of seconds connection draining is active. Acceptable values are from 1 second to 3600 seconds.'})  # fmt: skip
    enabled: Optional[bool] = field(default=None, metadata={'description': 'Whether connection draining is enabled or not.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureApplicationGatewayBackendHttpSettings(AzureSubResource):
    kind: ClassVar[str] = "azure_application_gateway_backend_http_settings"
    mapping: ClassVar[Dict[str, Bender]] = AzureSubResource.mapping | {
        "affinity_cookie_name": S("properties", "affinityCookieName"),
        "authentication_certificates": S("properties")
        >> S("authenticationCertificates", default=[])
        >> ForallBend(S("id")),
        "connection_draining": S("properties", "connectionDraining")
        >> Bend(AzureApplicationGatewayConnectionDraining.mapping),
        "cookie_based_affinity": S("properties", "cookieBasedAffinity"),
        "etag": S("etag"),
        "host_name": S("properties", "hostName"),
        "name": S("name"),
        "path": S("properties", "path"),
        "pick_host_name_from_backend_address": S("properties", "pickHostNameFromBackendAddress"),
        "port": S("properties", "port"),
        "probe": S("properties", "probe", "id"),
        "probe_enabled": S("properties", "probeEnabled"),
        "protocol": S("properties", "protocol"),
        "provisioning_state": S("properties", "provisioningState"),
        "request_timeout": S("properties", "requestTimeout"),
        "trusted_root_certificates": S("properties") >> S("trustedRootCertificates", default=[]) >> ForallBend(S("id")),
        "type": S("type"),
    }
    affinity_cookie_name: Optional[str] = field(default=None, metadata={'description': 'Cookie name to use for the affinity cookie.'})  # fmt: skip
    authentication_certificates: Optional[List[str]] = field(default=None, metadata={'description': 'Array of references to application gateway authentication certificates.'})  # fmt: skip
    connection_draining: Optional[AzureApplicationGatewayConnectionDraining] = field(default=None, metadata={'description': 'Connection draining allows open connections to a backend server to be active for a specified time after the backend server got removed from the configuration.'})  # fmt: skip
    cookie_based_affinity: Optional[str] = field(default=None, metadata={"description": "Cookie based affinity."})
    etag: Optional[str] = field(default=None, metadata={'description': 'A unique read-only string that changes whenever the resource is updated.'})  # fmt: skip
    host_name: Optional[str] = field(default=None, metadata={'description': 'Host header to be sent to the backend servers.'})  # fmt: skip
    name: Optional[str] = field(default=None, metadata={'description': 'Name of the backend http settings that is unique within an Application Gateway.'})  # fmt: skip
    path: Optional[str] = field(default=None, metadata={'description': 'Path which should be used as a prefix for all HTTP requests. Null means no path will be prefixed. Default value is null.'})  # fmt: skip
    pick_host_name_from_backend_address: Optional[bool] = field(default=None, metadata={'description': 'Whether to pick host header should be picked from the host name of the backend server. Default value is false.'})  # fmt: skip
    port: Optional[int] = field(default=None, metadata={"description": "The destination port on the backend."})
    probe: Optional[str] = field(default=None, metadata={"description": "Reference to another subresource."})
    probe_enabled: Optional[bool] = field(default=None, metadata={'description': 'Whether the probe is enabled. Default value is false.'})  # fmt: skip
    protocol: Optional[str] = field(default=None, metadata={"description": "Application Gateway protocol."})
    provisioning_state: Optional[str] = field(default=None, metadata={'description': 'The current provisioning state.'})  # fmt: skip
    request_timeout: Optional[int] = field(default=None, metadata={'description': 'Request timeout in seconds. Application Gateway will fail the request if response is not received within RequestTimeout. Acceptable values are from 1 second to 86400 seconds.'})  # fmt: skip
    trusted_root_certificates: Optional[List[str]] = field(default=None, metadata={'description': 'Array of references to application gateway trusted root certificates.'})  # fmt: skip
    type: Optional[str] = field(default=None, metadata={"description": "Type of the resource."})


@define(eq=False, slots=False)
class AzureApplicationGatewayBackendSettings(AzureSubResource):
    kind: ClassVar[str] = "azure_application_gateway_backend_settings"
    mapping: ClassVar[Dict[str, Bender]] = AzureSubResource.mapping | {
        "etag": S("etag"),
        "host_name": S("properties", "hostName"),
        "name": S("name"),
        "pick_host_name_from_backend_address": S("properties", "pickHostNameFromBackendAddress"),
        "port": S("properties", "port"),
        "probe": S("properties", "probe", "id"),
        "protocol": S("properties", "protocol"),
        "provisioning_state": S("properties", "provisioningState"),
        "timeout": S("properties", "timeout"),
        "trusted_root_certificates": S("properties") >> S("trustedRootCertificates", default=[]) >> ForallBend(S("id")),
        "type": S("type"),
    }
    etag: Optional[str] = field(default=None, metadata={'description': 'A unique read-only string that changes whenever the resource is updated.'})  # fmt: skip
    host_name: Optional[str] = field(default=None, metadata={'description': 'Server name indication to be sent to the backend servers for Tls protocol.'})  # fmt: skip
    name: Optional[str] = field(default=None, metadata={'description': 'Name of the backend settings that is unique within an Application Gateway.'})  # fmt: skip
    pick_host_name_from_backend_address: Optional[bool] = field(default=None, metadata={'description': 'Whether to pick server name indication from the host name of the backend server for Tls protocol. Default value is false.'})  # fmt: skip
    port: Optional[int] = field(default=None, metadata={"description": "The destination port on the backend."})
    probe: Optional[str] = field(default=None, metadata={"description": "Reference to another subresource."})
    protocol: Optional[str] = field(default=None, metadata={"description": "Application Gateway protocol."})
    provisioning_state: Optional[str] = field(default=None, metadata={'description': 'The current provisioning state.'})  # fmt: skip
    timeout: Optional[int] = field(default=None, metadata={'description': 'Connection timeout in seconds. Application Gateway will fail the request if response is not received within ConnectionTimeout. Acceptable values are from 1 second to 86400 seconds.'})  # fmt: skip
    trusted_root_certificates: Optional[List[str]] = field(default=None, metadata={'description': 'Array of references to application gateway trusted root certificates.'})  # fmt: skip
    type: Optional[str] = field(default=None, metadata={"description": "Type of the resource."})


@define(eq=False, slots=False)
class AzureApplicationGatewayCustomError:
    kind: ClassVar[str] = "azure_application_gateway_custom_error"
    mapping: ClassVar[Dict[str, Bender]] = {
        "custom_error_page_url": S("customErrorPageUrl"),
        "status_code": S("statusCode"),
    }
    custom_error_page_url: Optional[str] = field(default=None, metadata={'description': 'Error page URL of the application gateway custom error.'})  # fmt: skip
    status_code: Optional[str] = field(default=None, metadata={'description': 'Status code of the application gateway custom error.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureApplicationGatewayHttpListener(AzureSubResource):
    kind: ClassVar[str] = "azure_application_gateway_http_listener"
    mapping: ClassVar[Dict[str, Bender]] = AzureSubResource.mapping | {
        "custom_error_configurations": S("properties", "customErrorConfigurations")
        >> ForallBend(AzureApplicationGatewayCustomError.mapping),
        "etag": S("etag"),
        "firewall_policy": S("properties", "firewallPolicy", "id"),
        "frontend_ip_configuration": S("properties", "frontendIPConfiguration", "id"),
        "frontend_port": S("properties", "frontendPort", "id"),
        "host_name": S("properties", "hostName"),
        "host_names": S("properties", "hostNames"),
        "name": S("name"),
        "protocol": S("properties", "protocol"),
        "provisioning_state": S("properties", "provisioningState"),
        "require_server_name_indication": S("properties", "requireServerNameIndication"),
        "ssl_certificate": S("properties", "sslCertificate", "id"),
        "ssl_profile": S("properties", "sslProfile", "id"),
        "type": S("type"),
    }
    custom_error_configurations: Optional[List[AzureApplicationGatewayCustomError]] = field(default=None, metadata={'description': 'Custom error configurations of the HTTP listener.'})  # fmt: skip
    etag: Optional[str] = field(default=None, metadata={'description': 'A unique read-only string that changes whenever the resource is updated.'})  # fmt: skip
    firewall_policy: Optional[str] = field(default=None, metadata={"description": "Reference to another subresource."})
    frontend_ip_configuration: Optional[str] = field(default=None, metadata={'description': 'Reference to another subresource.'})  # fmt: skip
    frontend_port: Optional[str] = field(default=None, metadata={"description": "Reference to another subresource."})
    host_name: Optional[str] = field(default=None, metadata={"description": "Host name of HTTP listener."})
    host_names: Optional[List[str]] = field(default=None, metadata={'description': 'List of Host names for HTTP Listener that allows special wildcard characters as well.'})  # fmt: skip
    name: Optional[str] = field(default=None, metadata={'description': 'Name of the HTTP listener that is unique within an Application Gateway.'})  # fmt: skip
    protocol: Optional[str] = field(default=None, metadata={"description": "Application Gateway protocol."})
    provisioning_state: Optional[str] = field(default=None, metadata={'description': 'The current provisioning state.'})  # fmt: skip
    require_server_name_indication: Optional[bool] = field(default=None, metadata={'description': 'Applicable only if protocol is https. Enables SNI for multi-hosting.'})  # fmt: skip
    ssl_certificate: Optional[str] = field(default=None, metadata={"description": "Reference to another subresource."})
    ssl_profile: Optional[str] = field(default=None, metadata={"description": "Reference to another subresource."})
    type: Optional[str] = field(default=None, metadata={"description": "Type of the resource."})


@define(eq=False, slots=False)
class AzureApplicationGatewayListener(AzureSubResource):
    kind: ClassVar[str] = "azure_application_gateway_listener"
    mapping: ClassVar[Dict[str, Bender]] = AzureSubResource.mapping | {
        "etag": S("etag"),
        "frontend_ip_configuration": S("properties", "frontendIPConfiguration", "id"),
        "frontend_port": S("properties", "frontendPort", "id"),
        "name": S("name"),
        "protocol": S("properties", "protocol"),
        "provisioning_state": S("properties", "provisioningState"),
        "ssl_certificate": S("properties", "sslCertificate", "id"),
        "ssl_profile": S("properties", "sslProfile", "id"),
        "type": S("type"),
    }
    etag: Optional[str] = field(default=None, metadata={'description': 'A unique read-only string that changes whenever the resource is updated.'})  # fmt: skip
    frontend_ip_configuration: Optional[str] = field(default=None, metadata={'description': 'Reference to another subresource.'})  # fmt: skip
    frontend_port: Optional[str] = field(default=None, metadata={"description": "Reference to another subresource."})
    name: Optional[str] = field(default=None, metadata={'description': 'Name of the listener that is unique within an Application Gateway.'})  # fmt: skip
    protocol: Optional[str] = field(default=None, metadata={"description": "Application Gateway protocol."})
    provisioning_state: Optional[str] = field(default=None, metadata={'description': 'The current provisioning state.'})  # fmt: skip
    ssl_certificate: Optional[str] = field(default=None, metadata={"description": "Reference to another subresource."})
    ssl_profile: Optional[str] = field(default=None, metadata={"description": "Reference to another subresource."})
    type: Optional[str] = field(default=None, metadata={"description": "Type of the resource."})


@define(eq=False, slots=False)
class AzureApplicationGatewayClientAuthConfiguration:
    kind: ClassVar[str] = "azure_application_gateway_client_auth_configuration"
    mapping: ClassVar[Dict[str, Bender]] = {
        "verify_client_cert_issuer_dn": S("verifyClientCertIssuerDN"),
        "verify_client_revocation": S("verifyClientRevocation"),
    }
    verify_client_cert_issuer_dn: Optional[bool] = field(default=None, metadata={'description': 'Verify client certificate issuer name on the application gateway.'})  # fmt: skip
    verify_client_revocation: Optional[str] = field(default=None, metadata={'description': 'Verify client certificate revocation status.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureApplicationGatewaySslProfile(AzureSubResource):
    kind: ClassVar[str] = "azure_application_gateway_ssl_profile"
    mapping: ClassVar[Dict[str, Bender]] = AzureSubResource.mapping | {
        "client_auth_configuration": S("properties", "clientAuthConfiguration")
        >> Bend(AzureApplicationGatewayClientAuthConfiguration.mapping),
        "etag": S("etag"),
        "name": S("name"),
        "provisioning_state": S("properties", "provisioningState"),
        "ssl_policy": S("properties", "sslPolicy") >> Bend(AzureApplicationGatewaySslPolicy.mapping),
        "trusted_client_certificates": S("properties")
        >> S("trustedClientCertificates", default=[])
        >> ForallBend(S("id")),
        "type": S("type"),
    }
    client_auth_configuration: Optional[AzureApplicationGatewayClientAuthConfiguration] = field(default=None, metadata={'description': 'Application gateway client authentication configuration.'})  # fmt: skip
    etag: Optional[str] = field(default=None, metadata={'description': 'A unique read-only string that changes whenever the resource is updated.'})  # fmt: skip
    name: Optional[str] = field(default=None, metadata={'description': 'Name of the SSL profile that is unique within an Application Gateway.'})  # fmt: skip
    provisioning_state: Optional[str] = field(default=None, metadata={'description': 'The current provisioning state.'})  # fmt: skip
    ssl_policy: Optional[AzureApplicationGatewaySslPolicy] = field(default=None, metadata={'description': 'Application Gateway Ssl policy.'})  # fmt: skip
    trusted_client_certificates: Optional[List[str]] = field(default=None, metadata={'description': 'Array of references to application gateway trusted client certificates.'})  # fmt: skip
    type: Optional[str] = field(default=None, metadata={"description": "Type of the resource."})


@define(eq=False, slots=False)
class AzureApplicationGatewayPathRule(AzureSubResource):
    kind: ClassVar[str] = "azure_application_gateway_path_rule"
    mapping: ClassVar[Dict[str, Bender]] = AzureSubResource.mapping | {
        "backend_address_pool": S("properties", "backendAddressPool", "id"),
        "backend_http_settings": S("properties", "backendHttpSettings", "id"),
        "etag": S("etag"),
        "firewall_policy": S("properties", "firewallPolicy", "id"),
        "load_distribution_policy": S("properties", "loadDistributionPolicy", "id"),
        "name": S("name"),
        "paths": S("properties", "paths"),
        "provisioning_state": S("properties", "provisioningState"),
        "redirect_configuration": S("properties", "redirectConfiguration", "id"),
        "rewrite_rule_set": S("properties", "rewriteRuleSet", "id"),
        "type": S("type"),
    }
    backend_address_pool: Optional[str] = field(default=None, metadata={'description': 'Reference to another subresource.'})  # fmt: skip
    backend_http_settings: Optional[str] = field(default=None, metadata={'description': 'Reference to another subresource.'})  # fmt: skip
    etag: Optional[str] = field(default=None, metadata={'description': 'A unique read-only string that changes whenever the resource is updated.'})  # fmt: skip
    firewall_policy: Optional[str] = field(default=None, metadata={"description": "Reference to another subresource."})
    load_distribution_policy: Optional[str] = field(default=None, metadata={'description': 'Reference to another subresource.'})  # fmt: skip
    name: Optional[str] = field(default=None, metadata={'description': 'Name of the path rule that is unique within an Application Gateway.'})  # fmt: skip
    paths: Optional[List[str]] = field(default=None, metadata={"description": "Path rules of URL path map."})
    provisioning_state: Optional[str] = field(default=None, metadata={'description': 'The current provisioning state.'})  # fmt: skip
    redirect_configuration: Optional[str] = field(default=None, metadata={'description': 'Reference to another subresource.'})  # fmt: skip
    rewrite_rule_set: Optional[str] = field(default=None, metadata={'description': 'Reference to another subresource.'})  # fmt: skip
    type: Optional[str] = field(default=None, metadata={"description": "Type of the resource."})


@define(eq=False, slots=False)
class AzureApplicationGatewayUrlPathMap(AzureSubResource):
    kind: ClassVar[str] = "azure_application_gateway_url_path_map"
    mapping: ClassVar[Dict[str, Bender]] = AzureSubResource.mapping | {
        "default_backend_address_pool": S("properties", "defaultBackendAddressPool", "id"),
        "default_backend_http_settings": S("properties", "defaultBackendHttpSettings", "id"),
        "default_load_distribution_policy": S("properties", "defaultLoadDistributionPolicy", "id"),
        "default_redirect_configuration": S("properties", "defaultRedirectConfiguration", "id"),
        "default_rewrite_rule_set": S("properties", "defaultRewriteRuleSet", "id"),
        "etag": S("etag"),
        "name": S("name"),
        "path_rules": S("properties", "pathRules") >> ForallBend(AzureApplicationGatewayPathRule.mapping),
        "provisioning_state": S("properties", "provisioningState"),
        "type": S("type"),
    }
    default_backend_address_pool: Optional[str] = field(default=None, metadata={'description': 'Reference to another subresource.'})  # fmt: skip
    default_backend_http_settings: Optional[str] = field(default=None, metadata={'description': 'Reference to another subresource.'})  # fmt: skip
    default_load_distribution_policy: Optional[str] = field(default=None, metadata={'description': 'Reference to another subresource.'})  # fmt: skip
    default_redirect_configuration: Optional[str] = field(default=None, metadata={'description': 'Reference to another subresource.'})  # fmt: skip
    default_rewrite_rule_set: Optional[str] = field(default=None, metadata={'description': 'Reference to another subresource.'})  # fmt: skip
    etag: Optional[str] = field(default=None, metadata={'description': 'A unique read-only string that changes whenever the resource is updated.'})  # fmt: skip
    name: Optional[str] = field(default=None, metadata={'description': 'Name of the URL path map that is unique within an Application Gateway.'})  # fmt: skip
    path_rules: Optional[List[AzureApplicationGatewayPathRule]] = field(default=None, metadata={'description': 'Path rule of URL path map resource.'})  # fmt: skip
    provisioning_state: Optional[str] = field(default=None, metadata={'description': 'The current provisioning state.'})  # fmt: skip
    type: Optional[str] = field(default=None, metadata={"description": "Type of the resource."})


@define(eq=False, slots=False)
class AzureApplicationGatewayRequestRoutingRule(AzureSubResource):
    kind: ClassVar[str] = "azure_application_gateway_request_routing_rule"
    mapping: ClassVar[Dict[str, Bender]] = AzureSubResource.mapping | {
        "backend_address_pool": S("properties", "backendAddressPool", "id"),
        "backend_http_settings": S("properties", "backendHttpSettings", "id"),
        "etag": S("etag"),
        "http_listener": S("properties", "httpListener", "id"),
        "load_distribution_policy": S("properties", "loadDistributionPolicy", "id"),
        "name": S("name"),
        "priority": S("properties", "priority"),
        "provisioning_state": S("properties", "provisioningState"),
        "redirect_configuration": S("properties", "redirectConfiguration", "id"),
        "rewrite_rule_set": S("properties", "rewriteRuleSet", "id"),
        "rule_type": S("properties", "ruleType"),
        "type": S("type"),
        "url_path_map": S("properties", "urlPathMap", "id"),
    }
    backend_address_pool: Optional[str] = field(default=None, metadata={'description': 'Reference to another subresource.'})  # fmt: skip
    backend_http_settings: Optional[str] = field(default=None, metadata={'description': 'Reference to another subresource.'})  # fmt: skip
    etag: Optional[str] = field(default=None, metadata={'description': 'A unique read-only string that changes whenever the resource is updated.'})  # fmt: skip
    http_listener: Optional[str] = field(default=None, metadata={"description": "Reference to another subresource."})
    load_distribution_policy: Optional[str] = field(default=None, metadata={'description': 'Reference to another subresource.'})  # fmt: skip
    name: Optional[str] = field(default=None, metadata={'description': 'Name of the request routing rule that is unique within an Application Gateway.'})  # fmt: skip
    priority: Optional[int] = field(default=None, metadata={"description": "Priority of the request routing rule."})
    provisioning_state: Optional[str] = field(default=None, metadata={'description': 'The current provisioning state.'})  # fmt: skip
    redirect_configuration: Optional[str] = field(default=None, metadata={'description': 'Reference to another subresource.'})  # fmt: skip
    rewrite_rule_set: Optional[str] = field(default=None, metadata={'description': 'Reference to another subresource.'})  # fmt: skip
    rule_type: Optional[str] = field(default=None, metadata={"description": "Rule type."})
    type: Optional[str] = field(default=None, metadata={"description": "Type of the resource."})
    url_path_map: Optional[str] = field(default=None, metadata={"description": "Reference to another subresource."})


@define(eq=False, slots=False)
class AzureApplicationGatewayRoutingRule(AzureSubResource):
    kind: ClassVar[str] = "azure_application_gateway_routing_rule"
    mapping: ClassVar[Dict[str, Bender]] = AzureSubResource.mapping | {
        "backend_address_pool": S("properties", "backendAddressPool", "id"),
        "backend_settings": S("properties", "backendSettings", "id"),
        "etag": S("etag"),
        "listener": S("properties", "listener", "id"),
        "name": S("name"),
        "priority": S("properties", "priority"),
        "provisioning_state": S("properties", "provisioningState"),
        "rule_type": S("properties", "ruleType"),
        "type": S("type"),
    }
    backend_address_pool: Optional[str] = field(default=None, metadata={'description': 'Reference to another subresource.'})  # fmt: skip
    backend_settings: Optional[str] = field(default=None, metadata={'description': 'Reference to another subresource.'})  # fmt: skip
    etag: Optional[str] = field(default=None, metadata={'description': 'A unique read-only string that changes whenever the resource is updated.'})  # fmt: skip
    listener: Optional[str] = field(default=None, metadata={"description": "Reference to another subresource."})
    name: Optional[str] = field(default=None, metadata={'description': 'Name of the routing rule that is unique within an Application Gateway.'})  # fmt: skip
    priority: Optional[int] = field(default=None, metadata={"description": "Priority of the routing rule."})
    provisioning_state: Optional[str] = field(default=None, metadata={'description': 'The current provisioning state.'})  # fmt: skip
    rule_type: Optional[str] = field(default=None, metadata={"description": "Rule type."})
    type: Optional[str] = field(default=None, metadata={"description": "Type of the resource."})


@define(eq=False, slots=False)
class AzureApplicationGatewayRewriteRuleCondition:
    kind: ClassVar[str] = "azure_application_gateway_rewrite_rule_condition"
    mapping: ClassVar[Dict[str, Bender]] = {
        "ignore_case": S("ignoreCase"),
        "negate": S("negate"),
        "pattern": S("pattern"),
        "variable": S("variable"),
    }
    ignore_case: Optional[bool] = field(default=None, metadata={'description': 'Setting this parameter to truth value with force the pattern to do a case in-sensitive comparison.'})  # fmt: skip
    negate: Optional[bool] = field(default=None, metadata={'description': 'Setting this value as truth will force to check the negation of the condition given by the user.'})  # fmt: skip
    pattern: Optional[str] = field(default=None, metadata={'description': 'The pattern, either fixed string or regular expression, that evaluates the truthfulness of the condition.'})  # fmt: skip
    variable: Optional[str] = field(default=None, metadata={'description': 'The condition parameter of the RewriteRuleCondition.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureApplicationGatewayHeaderConfiguration:
    kind: ClassVar[str] = "azure_application_gateway_header_configuration"
    mapping: ClassVar[Dict[str, Bender]] = {"header_name": S("headerName"), "header_value": S("headerValue")}
    header_name: Optional[str] = field(default=None, metadata={'description': 'Header name of the header configuration.'})  # fmt: skip
    header_value: Optional[str] = field(default=None, metadata={'description': 'Header value of the header configuration.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureApplicationGatewayUrlConfiguration:
    kind: ClassVar[str] = "azure_application_gateway_url_configuration"
    mapping: ClassVar[Dict[str, Bender]] = {
        "modified_path": S("modifiedPath"),
        "modified_query_string": S("modifiedQueryString"),
        "reroute": S("reroute"),
    }
    modified_path: Optional[str] = field(default=None, metadata={'description': 'Url path which user has provided for url rewrite. Null means no path will be updated. Default value is null.'})  # fmt: skip
    modified_query_string: Optional[str] = field(default=None, metadata={'description': 'Query string which user has provided for url rewrite. Null means no query string will be updated. Default value is null.'})  # fmt: skip
    reroute: Optional[bool] = field(default=None, metadata={'description': 'If set as true, it will re-evaluate the url path map provided in path based request routing rules using modified path. Default value is false.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureApplicationGatewayRewriteRuleActionSet:
    kind: ClassVar[str] = "azure_application_gateway_rewrite_rule_action_set"
    mapping: ClassVar[Dict[str, Bender]] = {
        "request_header_configurations": S("requestHeaderConfigurations")
        >> ForallBend(AzureApplicationGatewayHeaderConfiguration.mapping),
        "response_header_configurations": S("responseHeaderConfigurations")
        >> ForallBend(AzureApplicationGatewayHeaderConfiguration.mapping),
        "url_configuration": S("urlConfiguration") >> Bend(AzureApplicationGatewayUrlConfiguration.mapping),
    }
    request_header_configurations: Optional[List[AzureApplicationGatewayHeaderConfiguration]] = field(default=None, metadata={'description': 'Request Header Actions in the Action Set.'})  # fmt: skip
    response_header_configurations: Optional[List[AzureApplicationGatewayHeaderConfiguration]] = field(default=None, metadata={'description': 'Response Header Actions in the Action Set.'})  # fmt: skip
    url_configuration: Optional[AzureApplicationGatewayUrlConfiguration] = field(default=None, metadata={'description': 'Url configuration of the Actions set in Application Gateway.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureApplicationGatewayRewriteRule:
    kind: ClassVar[str] = "azure_application_gateway_rewrite_rule"
    mapping: ClassVar[Dict[str, Bender]] = {
        "action_set": S("actionSet") >> Bend(AzureApplicationGatewayRewriteRuleActionSet.mapping),
        "conditions": S("conditions") >> ForallBend(AzureApplicationGatewayRewriteRuleCondition.mapping),
        "name": S("name"),
        "rule_sequence": S("ruleSequence"),
    }
    action_set: Optional[AzureApplicationGatewayRewriteRuleActionSet] = field(default=None, metadata={'description': 'Set of actions in the Rewrite Rule in Application Gateway.'})  # fmt: skip
    conditions: Optional[List[AzureApplicationGatewayRewriteRuleCondition]] = field(default=None, metadata={'description': 'Conditions based on which the action set execution will be evaluated.'})  # fmt: skip
    name: Optional[str] = field(default=None, metadata={'description': 'Name of the rewrite rule that is unique within an Application Gateway.'})  # fmt: skip
    rule_sequence: Optional[int] = field(default=None, metadata={'description': 'Rule Sequence of the rewrite rule that determines the order of execution of a particular rule in a RewriteRuleSet.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureApplicationGatewayRewriteRuleSet(AzureSubResource):
    kind: ClassVar[str] = "azure_application_gateway_rewrite_rule_set"
    mapping: ClassVar[Dict[str, Bender]] = AzureSubResource.mapping | {
        "etag": S("etag"),
        "name": S("name"),
        "provisioning_state": S("properties", "provisioningState"),
        "rewrite_rules": S("properties", "rewriteRules") >> ForallBend(AzureApplicationGatewayRewriteRule.mapping),
    }
    etag: Optional[str] = field(default=None, metadata={'description': 'A unique read-only string that changes whenever the resource is updated.'})  # fmt: skip
    name: Optional[str] = field(default=None, metadata={'description': 'Name of the rewrite rule set that is unique within an Application Gateway.'})  # fmt: skip
    provisioning_state: Optional[str] = field(default=None, metadata={'description': 'The current provisioning state.'})  # fmt: skip
    rewrite_rules: Optional[List[AzureApplicationGatewayRewriteRule]] = field(default=None, metadata={'description': 'Rewrite rules in the rewrite rule set.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureApplicationGatewayRedirectConfiguration(AzureSubResource):
    kind: ClassVar[str] = "azure_application_gateway_redirect_configuration"
    mapping: ClassVar[Dict[str, Bender]] = AzureSubResource.mapping | {
        "etag": S("etag"),
        "include_path": S("properties", "includePath"),
        "include_query_string": S("properties", "includeQueryString"),
        "name": S("name"),
        "path_rules": S("properties") >> S("pathRules", default=[]) >> ForallBend(S("id")),
        "redirect_type": S("properties", "redirectType"),
        "request_routing_rules": S("properties") >> S("requestRoutingRules", default=[]) >> ForallBend(S("id")),
        "target_listener": S("properties", "targetListener", "id"),
        "target_url": S("properties", "targetUrl"),
        "type": S("type"),
        "url_path_maps": S("properties") >> S("urlPathMaps", default=[]) >> ForallBend(S("id")),
    }
    etag: Optional[str] = field(default=None, metadata={'description': 'A unique read-only string that changes whenever the resource is updated.'})  # fmt: skip
    include_path: Optional[bool] = field(default=None, metadata={"description": "Include path in the redirected url."})
    include_query_string: Optional[bool] = field(default=None, metadata={'description': 'Include query string in the redirected url.'})  # fmt: skip
    name: Optional[str] = field(default=None, metadata={'description': 'Name of the redirect configuration that is unique within an Application Gateway.'})  # fmt: skip
    path_rules: Optional[List[str]] = field(default=None, metadata={'description': 'Path rules specifying redirect configuration.'})  # fmt: skip
    redirect_type: Optional[str] = field(default=None, metadata={"description": "Redirect type enum."})
    request_routing_rules: Optional[List[str]] = field(default=None, metadata={'description': 'Request routing specifying redirect configuration.'})  # fmt: skip
    target_listener: Optional[str] = field(default=None, metadata={"description": "Reference to another subresource."})
    target_url: Optional[str] = field(default=None, metadata={"description": "Url to redirect the request to."})
    type: Optional[str] = field(default=None, metadata={"description": "Type of the resource."})
    url_path_maps: Optional[List[str]] = field(default=None, metadata={'description': 'Url path maps specifying default redirect configuration.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureApplicationGatewayFirewallDisabledRuleGroup:
    kind: ClassVar[str] = "azure_application_gateway_firewall_disabled_rule_group"
    mapping: ClassVar[Dict[str, Bender]] = {"rule_group_name": S("ruleGroupName"), "rules": S("rules")}
    rule_group_name: Optional[str] = field(default=None, metadata={'description': 'The name of the rule group that will be disabled.'})  # fmt: skip
    rules: Optional[List[int]] = field(default=None, metadata={'description': 'The list of rules that will be disabled. If null, all rules of the rule group will be disabled.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureApplicationGatewayFirewallExclusion:
    kind: ClassVar[str] = "azure_application_gateway_firewall_exclusion"
    mapping: ClassVar[Dict[str, Bender]] = {
        "match_variable": S("matchVariable"),
        "selector": S("selector"),
        "selector_match_operator": S("selectorMatchOperator"),
    }
    match_variable: Optional[str] = field(default=None, metadata={"description": "The variable to be excluded."})
    selector: Optional[str] = field(default=None, metadata={'description': 'When matchVariable is a collection, operator used to specify which elements in the collection this exclusion applies to.'})  # fmt: skip
    selector_match_operator: Optional[str] = field(default=None, metadata={'description': 'When matchVariable is a collection, operate on the selector to specify which elements in the collection this exclusion applies to.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureApplicationGatewayWebApplicationFirewallConfiguration:
    kind: ClassVar[str] = "azure_application_gateway_web_application_firewall_configuration"
    mapping: ClassVar[Dict[str, Bender]] = {
        "disabled_rule_groups": S("disabledRuleGroups")
        >> ForallBend(AzureApplicationGatewayFirewallDisabledRuleGroup.mapping),
        "enabled": S("enabled"),
        "exclusions": S("exclusions") >> ForallBend(AzureApplicationGatewayFirewallExclusion.mapping),
        "file_upload_limit_in_mb": S("fileUploadLimitInMb"),
        "firewall_mode": S("firewallMode"),
        "max_request_body_size": S("maxRequestBodySize"),
        "max_request_body_size_in_kb": S("maxRequestBodySizeInKb"),
        "request_body_check": S("requestBodyCheck"),
        "rule_set_type": S("ruleSetType"),
        "rule_set_version": S("ruleSetVersion"),
    }
    disabled_rule_groups: Optional[List[AzureApplicationGatewayFirewallDisabledRuleGroup]] = field(default=None, metadata={'description': 'The disabled rule groups.'})  # fmt: skip
    enabled: Optional[bool] = field(default=None, metadata={'description': 'Whether the web application firewall is enabled or not.'})  # fmt: skip
    exclusions: Optional[List[AzureApplicationGatewayFirewallExclusion]] = field(default=None, metadata={'description': 'The exclusion list.'})  # fmt: skip
    file_upload_limit_in_mb: Optional[int] = field(default=None, metadata={'description': 'Maximum file upload size in Mb for WAF.'})  # fmt: skip
    firewall_mode: Optional[str] = field(default=None, metadata={"description": "Web application firewall mode."})
    max_request_body_size: Optional[int] = field(default=None, metadata={'description': 'Maximum request body size for WAF.'})  # fmt: skip
    max_request_body_size_in_kb: Optional[int] = field(default=None, metadata={'description': 'Maximum request body size in Kb for WAF.'})  # fmt: skip
    request_body_check: Optional[bool] = field(default=None, metadata={'description': 'Whether allow WAF to check request Body.'})  # fmt: skip
    rule_set_type: Optional[str] = field(default=None, metadata={'description': 'The type of the web application firewall rule set. Possible values are: OWASP .'})  # fmt: skip
    rule_set_version: Optional[str] = field(default=None, metadata={'description': 'The version of the rule set type.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureApplicationGatewayAutoscaleConfiguration:
    kind: ClassVar[str] = "azure_application_gateway_autoscale_configuration"
    mapping: ClassVar[Dict[str, Bender]] = {"max_capacity": S("maxCapacity"), "min_capacity": S("minCapacity")}
    max_capacity: Optional[int] = field(default=None, metadata={'description': 'Upper bound on number of Application Gateway capacity.'})  # fmt: skip
    min_capacity: Optional[int] = field(default=None, metadata={'description': 'Lower bound on number of Application Gateway capacity.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureApplicationGatewayPrivateLinkIpConfiguration(AzureSubResource):
    kind: ClassVar[str] = "azure_application_gateway_private_link_ip_configuration"
    mapping: ClassVar[Dict[str, Bender]] = AzureSubResource.mapping | {
        "etag": S("etag"),
        "name": S("name"),
        "primary": S("properties", "primary"),
        "private_ip_address": S("properties", "privateIPAddress"),
        "private_ip_allocation_method": S("properties", "privateIPAllocationMethod"),
        "provisioning_state": S("properties", "provisioningState"),
        "subnet": S("properties", "subnet", "id"),
        "type": S("type"),
    }
    etag: Optional[str] = field(default=None, metadata={'description': 'A unique read-only string that changes whenever the resource is updated.'})  # fmt: skip
    name: Optional[str] = field(default=None, metadata={'description': 'The name of application gateway private link ip configuration.'})  # fmt: skip
    primary: Optional[bool] = field(default=None, metadata={'description': 'Whether the ip configuration is primary or not.'})  # fmt: skip
    private_ip_address: Optional[str] = field(default=None, metadata={'description': 'The private IP address of the IP configuration.'})  # fmt: skip
    private_ip_allocation_method: Optional[str] = field(default=None, metadata={'description': 'IP address allocation method.'})  # fmt: skip
    provisioning_state: Optional[str] = field(default=None, metadata={'description': 'The current provisioning state.'})  # fmt: skip
    subnet: Optional[str] = field(default=None, metadata={"description": "Reference to another subresource."})
    type: Optional[str] = field(default=None, metadata={"description": "The resource type."})


@define(eq=False, slots=False)
class AzureApplicationGatewayPrivateLinkConfiguration(AzureSubResource):
    kind: ClassVar[str] = "azure_application_gateway_private_link_configuration"
    mapping: ClassVar[Dict[str, Bender]] = AzureSubResource.mapping | {
        "etag": S("etag"),
        "link_ip_configurations": S("properties", "ipConfigurations")
        >> ForallBend(AzureApplicationGatewayPrivateLinkIpConfiguration.mapping),
        "name": S("name"),
        "provisioning_state": S("properties", "provisioningState"),
        "type": S("type"),
    }
    etag: Optional[str] = field(default=None, metadata={'description': 'A unique read-only string that changes whenever the resource is updated.'})  # fmt: skip
    link_ip_configurations: Optional[List[AzureApplicationGatewayPrivateLinkIpConfiguration]] = field(default=None, metadata={'description': 'An array of application gateway private link ip configurations.'})  # fmt: skip
    name: Optional[str] = field(default=None, metadata={'description': 'Name of the private link configuration that is unique within an Application Gateway.'})  # fmt: skip
    provisioning_state: Optional[str] = field(default=None, metadata={'description': 'The current provisioning state.'})  # fmt: skip
    type: Optional[str] = field(default=None, metadata={"description": "Type of the resource."})


@define(eq=False, slots=False)
class AzurePrivateLinkServiceConnection(AzureSubResource):
    kind: ClassVar[str] = "azure_private_link_service_connection"
    mapping: ClassVar[Dict[str, Bender]] = AzureSubResource.mapping | {
        "etag": S("etag"),
        "group_ids": S("properties", "groupIds"),
        "name": S("name"),
        "private_link_service_connection_state": S("properties", "privateLinkServiceConnectionState")
        >> Bend(AzurePrivateLinkServiceConnectionState.mapping),
        "private_link_service_id": S("properties", "privateLinkServiceId"),
        "provisioning_state": S("properties", "provisioningState"),
        "request_message": S("properties", "requestMessage"),
        "type": S("type"),
    }
    etag: Optional[str] = field(default=None, metadata={'description': 'A unique read-only string that changes whenever the resource is updated.'})  # fmt: skip
    group_ids: Optional[List[str]] = field(default=None, metadata={'description': 'The ID(s) of the group(s) obtained from the remote resource that this private endpoint should connect to.'})  # fmt: skip
    name: Optional[str] = field(default=None, metadata={'description': 'The name of the resource that is unique within a resource group. This name can be used to access the resource.'})  # fmt: skip
    private_link_service_connection_state: Optional[AzurePrivateLinkServiceConnectionState] = field(default=None, metadata={'description': 'A collection of information about the state of the connection between service consumer and provider.'})  # fmt: skip
    private_link_service_id: Optional[str] = field(default=None, metadata={'description': 'The resource id of private link service.'})  # fmt: skip
    provisioning_state: Optional[str] = field(default=None, metadata={'description': 'The current provisioning state.'})  # fmt: skip
    request_message: Optional[str] = field(default=None, metadata={'description': 'A message passed to the owner of the remote resource with this connection request. Restricted to 140 chars.'})  # fmt: skip
    type: Optional[str] = field(default=None, metadata={"description": "The resource type."})


@define(eq=False, slots=False)
class AzureCustomDnsConfigPropertiesFormat:
    kind: ClassVar[str] = "azure_custom_dns_config_properties_format"
    mapping: ClassVar[Dict[str, Bender]] = {"fqdn": S("fqdn"), "ip_addresses": S("ipAddresses")}
    fqdn: Optional[str] = field(default=None, metadata={'description': 'Fqdn that resolves to private endpoint ip address.'})  # fmt: skip
    ip_addresses: Optional[List[str]] = field(default=None, metadata={'description': 'A list of private ip addresses of the private endpoint.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureApplicationSecurityGroup:
    kind: ClassVar[str] = "azure_application_security_group"
    mapping: ClassVar[Dict[str, Bender]] = {
        "etag": S("etag"),
        "id": S("id"),
        "location": S("location"),
        "name": S("name"),
        "provisioning_state": S("properties", "provisioningState"),
        "resource_guid": S("properties", "resourceGuid"),
        "tags": S("tags", default={}),
        "type": S("type"),
    }
    etag: Optional[str] = field(default=None, metadata={'description': 'A unique read-only string that changes whenever the resource is updated.'})  # fmt: skip
    id: Optional[str] = field(default=None, metadata={"description": "Resource ID."})
    location: Optional[str] = field(default=None, metadata={"description": "Resource location."})
    name: Optional[str] = field(default=None, metadata={"description": "Resource name."})
    provisioning_state: Optional[str] = field(default=None, metadata={'description': 'The current provisioning state.'})  # fmt: skip
    resource_guid: Optional[str] = field(default=None, metadata={'description': 'The resource GUID property of the application security group resource. It uniquely identifies a resource, even if the user changes its name or migrate the resource across subscriptions or resource groups.'})  # fmt: skip
    tags: Optional[Dict[str, str]] = field(default=None, metadata={"description": "Resource tags."})
    type: Optional[str] = field(default=None, metadata={"description": "Resource type."})


@define(eq=False, slots=False)
class AzurePrivateEndpointIPConfiguration:
    kind: ClassVar[str] = "azure_private_endpoint_ip_configuration"
    mapping: ClassVar[Dict[str, Bender]] = {
        "etag": S("etag"),
        "group_id": S("properties", "groupId"),
        "member_name": S("properties", "memberName"),
        "name": S("name"),
        "private_ip_address": S("properties", "privateIPAddress"),
        "type": S("type"),
    }
    etag: Optional[str] = field(default=None, metadata={'description': 'A unique read-only string that changes whenever the resource is updated.'})  # fmt: skip
    group_id: Optional[str] = field(default=None, metadata={'description': 'The ID of a group obtained from the remote resource that this private endpoint should connect to.'})  # fmt: skip
    member_name: Optional[str] = field(default=None, metadata={'description': 'The member name of a group obtained from the remote resource that this private endpoint should connect to.'})  # fmt: skip
    name: Optional[str] = field(default=None, metadata={'description': 'The name of the resource that is unique within a resource group.'})  # fmt: skip
    private_ip_address: Optional[str] = field(default=None, metadata={'description': 'A private ip address obtained from the private endpoint s subnet.'})  # fmt: skip
    type: Optional[str] = field(default=None, metadata={"description": "The resource type."})


@define(eq=False, slots=False)
class AzurePrivateEndpoint:
    kind: ClassVar[str] = "azure_private_endpoint"
    mapping: ClassVar[Dict[str, Bender]] = {
        "application_security_groups": S("properties", "applicationSecurityGroups")
        >> ForallBend(AzureApplicationSecurityGroup.mapping),
        "custom_dns_configs": S("properties", "customDnsConfigs")
        >> ForallBend(AzureCustomDnsConfigPropertiesFormat.mapping),
        "custom_network_interface_name": S("properties", "customNetworkInterfaceName"),
        "etag": S("etag"),
        "extended_location": S("extendedLocation") >> Bend(AzureExtendedLocation.mapping),
        "id": S("id"),
        "ip_configurations": S("properties", "ipConfigurations")
        >> ForallBend(AzurePrivateEndpointIPConfiguration.mapping),
        "location": S("location"),
        "manual_private_link_service_connections": S("properties", "manualPrivateLinkServiceConnections")
        >> ForallBend(AzurePrivateLinkServiceConnection.mapping),
        "name": S("name"),
        "private_link_service_connections": S("properties", "privateLinkServiceConnections")
        >> ForallBend(AzurePrivateLinkServiceConnection.mapping),
        "provisioning_state": S("properties", "provisioningState"),
        "tags": S("tags", default={}),
        "type": S("type"),
    }
    application_security_groups: Optional[List[AzureApplicationSecurityGroup]] = field(default=None, metadata={'description': 'Application security groups in which the private endpoint IP configuration is included.'})  # fmt: skip
    custom_dns_configs: Optional[List[AzureCustomDnsConfigPropertiesFormat]] = field(default=None, metadata={'description': 'An array of custom dns configurations.'})  # fmt: skip
    custom_network_interface_name: Optional[str] = field(default=None, metadata={'description': 'The custom name of the network interface attached to the private endpoint.'})  # fmt: skip
    etag: Optional[str] = field(default=None, metadata={'description': 'A unique read-only string that changes whenever the resource is updated.'})  # fmt: skip
    extended_location: Optional[AzureExtendedLocation] = field(default=None, metadata={'description': 'ExtendedLocation complex type.'})  # fmt: skip
    id: Optional[str] = field(default=None, metadata={"description": "Resource ID."})
    ip_configurations: Optional[List[AzurePrivateEndpointIPConfiguration]] = field(default=None, metadata={'description': 'A list of IP configurations of the private endpoint. This will be used to map to the First Party Service s endpoints.'})  # fmt: skip
    location: Optional[str] = field(default=None, metadata={"description": "Resource location."})
    manual_private_link_service_connections: Optional[List[AzurePrivateLinkServiceConnection]] = field(default=None, metadata={'description': 'A grouping of information about the connection to the remote resource. Used when the network admin does not have access to approve connections to the remote resource.'})  # fmt: skip
    name: Optional[str] = field(default=None, metadata={"description": "Resource name."})
    private_link_service_connections: Optional[List[AzurePrivateLinkServiceConnection]] = field(default=None, metadata={'description': 'A grouping of information about the connection to the remote resource.'})  # fmt: skip
    provisioning_state: Optional[str] = field(default=None, metadata={'description': 'The current provisioning state.'})  # fmt: skip
    tags: Optional[Dict[str, str]] = field(default=None, metadata={"description": "Resource tags."})
    type: Optional[str] = field(default=None, metadata={"description": "Resource type."})


@define(eq=False, slots=False)
class AzureApplicationGatewayPrivateEndpointConnection(AzureSubResource):
    kind: ClassVar[str] = "azure_application_gateway_private_endpoint_connection"
    mapping: ClassVar[Dict[str, Bender]] = AzureSubResource.mapping | {
        "etag": S("etag"),
        "link_identifier": S("properties", "linkIdentifier"),
        "name": S("name"),
        "private_endpoint": S("properties", "privateEndpoint") >> Bend(AzurePrivateEndpoint.mapping),
        "private_link_service_connection_state": S("properties", "privateLinkServiceConnectionState")
        >> Bend(AzurePrivateLinkServiceConnectionState.mapping),
        "provisioning_state": S("properties", "provisioningState"),
        "type": S("type"),
    }
    etag: Optional[str] = field(default=None, metadata={'description': 'A unique read-only string that changes whenever the resource is updated.'})  # fmt: skip
    link_identifier: Optional[str] = field(default=None, metadata={"description": "The consumer link id."})
    name: Optional[str] = field(default=None, metadata={'description': 'Name of the private endpoint connection on an application gateway.'})  # fmt: skip
    private_endpoint: Optional[AzurePrivateEndpoint] = field(default=None, metadata={'description': 'Private endpoint resource.'})  # fmt: skip
    private_link_service_connection_state: Optional[AzurePrivateLinkServiceConnectionState] = field(default=None, metadata={'description': 'A collection of information about the state of the connection between service consumer and provider.'})  # fmt: skip
    provisioning_state: Optional[str] = field(default=None, metadata={'description': 'The current provisioning state.'})  # fmt: skip
    type: Optional[str] = field(default=None, metadata={"description": "Type of the resource."})


@define(eq=False, slots=False)
class AzureApplicationGatewayLoadDistributionTarget(AzureSubResource):
    kind: ClassVar[str] = "azure_application_gateway_load_distribution_target"
    mapping: ClassVar[Dict[str, Bender]] = AzureSubResource.mapping | {
        "backend_address_pool": S("properties", "backendAddressPool", "id"),
        "etag": S("etag"),
        "name": S("name"),
        "type": S("type"),
        "weight_per_server": S("properties", "weightPerServer"),
    }
    backend_address_pool: Optional[str] = field(default=None, metadata={'description': 'Reference to another subresource.'})  # fmt: skip
    etag: Optional[str] = field(default=None, metadata={'description': 'A unique read-only string that changes whenever the resource is updated.'})  # fmt: skip
    name: Optional[str] = field(default=None, metadata={'description': 'Name of the load distribution policy that is unique within an Application Gateway.'})  # fmt: skip
    type: Optional[str] = field(default=None, metadata={"description": "Type of the resource."})
    weight_per_server: Optional[int] = field(default=None, metadata={'description': 'Weight per server. Range between 1 and 100.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureApplicationGatewayLoadDistributionPolicy(AzureSubResource):
    kind: ClassVar[str] = "azure_application_gateway_load_distribution_policy"
    mapping: ClassVar[Dict[str, Bender]] = AzureSubResource.mapping | {
        "etag": S("etag"),
        "load_distribution_algorithm": S("properties", "loadDistributionAlgorithm"),
        "load_distribution_targets": S("properties", "loadDistributionTargets")
        >> ForallBend(AzureApplicationGatewayLoadDistributionTarget.mapping),
        "name": S("name"),
        "provisioning_state": S("properties", "provisioningState"),
        "type": S("type"),
    }
    etag: Optional[str] = field(default=None, metadata={'description': 'A unique read-only string that changes whenever the resource is updated.'})  # fmt: skip
    load_distribution_algorithm: Optional[str] = field(default=None, metadata={'description': 'Load Distribution Algorithm enums.'})  # fmt: skip
    load_distribution_targets: Optional[List[AzureApplicationGatewayLoadDistributionTarget]] = field(default=None, metadata={'description': 'Load Distribution Targets resource of an application gateway.'})  # fmt: skip
    name: Optional[str] = field(default=None, metadata={'description': 'Name of the load distribution policy that is unique within an Application Gateway.'})  # fmt: skip
    provisioning_state: Optional[str] = field(default=None, metadata={'description': 'The current provisioning state.'})  # fmt: skip
    type: Optional[str] = field(default=None, metadata={"description": "Type of the resource."})


@define(eq=False, slots=False)
class AzureApplicationGatewayGlobalConfiguration:
    kind: ClassVar[str] = "azure_application_gateway_global_configuration"
    mapping: ClassVar[Dict[str, Bender]] = {
        "enable_request_buffering": S("enableRequestBuffering"),
        "enable_response_buffering": S("enableResponseBuffering"),
    }
    enable_request_buffering: Optional[bool] = field(default=None, metadata={'description': 'Enable request buffering.'})  # fmt: skip
    enable_response_buffering: Optional[bool] = field(default=None, metadata={'description': 'Enable response buffering.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureManagedServiceIdentity:
    kind: ClassVar[str] = "azure_managed_service_identity"
    mapping: ClassVar[Dict[str, Bender]] = {
        "principal_id": S("principalId"),
        "tenant_id": S("tenantId"),
        "type": S("type"),
        "user_assigned_identities": S("userAssignedIdentities"),
    }
    principal_id: Optional[str] = field(default=None, metadata={'description': 'The principal id of the system assigned identity. This property will only be provided for a system assigned identity.'})  # fmt: skip
    tenant_id: Optional[str] = field(default=None, metadata={'description': 'The tenant id of the system assigned identity. This property will only be provided for a system assigned identity.'})  # fmt: skip
    type: Optional[str] = field(default=None, metadata={'description': 'The type of identity used for the resource. The type SystemAssigned, UserAssigned includes both an implicitly created identity and a set of user assigned identities. The type None will remove any identities from the virtual machine.'})  # fmt: skip
    user_assigned_identities: Optional[Dict[str, AzurePrincipalidClientid]] = field(default=None, metadata={'description': 'The list of user identities associated with resource. The user identity dictionary key references will be ARM resource ids in the form: /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ManagedIdentity/userAssignedIdentities/{identityName} .'})  # fmt: skip


@define(eq=False, slots=False)
class AzureApplicationGateway(AzureResource, BaseGateway):
    kind: ClassVar[str] = "azure_application_gateway"
    api_spec: ClassVar[AzureApiSpec] = AzureApiSpec(
        service="network",
        version="2023-05-01",
        path="/subscriptions/{subscriptionId}/providers/Microsoft.Network/applicationGateways",
        path_parameters=["subscriptionId"],
        query_parameters=["api-version"],
        access_path="value",
        expect_array=True,
    )
    reference_kinds: ClassVar[ModelReference] = {
        "predecessors": {"default": ["azure_subnet"]},
        "successors": {"default": ["azure_web_application_firewall_policy"]},
    }
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "authentication_certificates": S("properties", "authenticationCertificates")
        >> ForallBend(AzureApplicationGatewayAuthenticationCertificate.mapping),
        "autoscale_configuration": S("properties", "autoscaleConfiguration")
        >> Bend(AzureApplicationGatewayAutoscaleConfiguration.mapping),
        "gateway_backend_address_pools": S("properties", "backendAddressPools")
        >> ForallBend(AzureApplicationGatewayBackendAddressPool.mapping),
        "backend_http_settings_collection": S("properties", "backendHttpSettingsCollection")
        >> ForallBend(AzureApplicationGatewayBackendHttpSettings.mapping),
        "backend_settings_collection": S("properties", "backendSettingsCollection")
        >> ForallBend(AzureApplicationGatewayBackendSettings.mapping),
        "custom_error_configurations": S("properties", "customErrorConfigurations")
        >> ForallBend(AzureApplicationGatewayCustomError.mapping),
        "default_predefined_ssl_policy": S("properties", "defaultPredefinedSslPolicy"),
        "enable_fips": S("properties", "enableFips"),
        "enable_http2": S("properties", "enableHttp2"),
        "etag": S("etag"),
        "firewall_policy": S("properties", "firewallPolicy", "id"),
        "force_firewall_policy_association": S("properties", "forceFirewallPolicyAssociation"),
        "frontend_ip_configurations": S("properties", "frontendIPConfigurations")
        >> ForallBend(AzureApplicationGatewayFrontendIPConfiguration.mapping),
        "frontend_ports": S("properties", "frontendPorts") >> ForallBend(AzureApplicationGatewayFrontendPort.mapping),
        "application_gateway_ip_configurations": S("properties", "gatewayIPConfigurations")
        >> ForallBend(AzureApplicationGatewayIPConfiguration.mapping),
        "global_configuration": S("properties", "globalConfiguration")
        >> Bend(AzureApplicationGatewayGlobalConfiguration.mapping),
        "http_listeners": S("properties", "httpListeners") >> ForallBend(AzureApplicationGatewayHttpListener.mapping),
        "identity": S("identity") >> Bend(AzureManagedServiceIdentity.mapping),
        "listeners": S("properties", "listeners") >> ForallBend(AzureApplicationGatewayListener.mapping),
        "load_distribution_policies": S("properties", "loadDistributionPolicies")
        >> ForallBend(AzureApplicationGatewayLoadDistributionPolicy.mapping),
        "operational_state": S("properties", "operationalState"),
        "gateway_private_endpoint_connections": S("properties", "privateEndpointConnections")
        >> ForallBend(AzureApplicationGatewayPrivateEndpointConnection.mapping),
        "private_link_configurations": S("properties", "privateLinkConfigurations")
        >> ForallBend(AzureApplicationGatewayPrivateLinkConfiguration.mapping),
        "gateway_probes": S("properties", "probes") >> ForallBend(AzureApplicationGatewayProbe.mapping),
        "provisioning_state": S("properties", "provisioningState"),
        "redirect_configurations": S("properties", "redirectConfigurations")
        >> ForallBend(AzureApplicationGatewayRedirectConfiguration.mapping),
        "request_routing_rules": S("properties", "requestRoutingRules")
        >> ForallBend(AzureApplicationGatewayRequestRoutingRule.mapping),
        "resource_guid": S("properties", "resourceGuid"),
        "rewrite_rule_sets": S("properties", "rewriteRuleSets")
        >> ForallBend(AzureApplicationGatewayRewriteRuleSet.mapping),
        "routing_rules": S("properties", "routingRules") >> ForallBend(AzureApplicationGatewayRoutingRule.mapping),
        "gateway_sku": S("properties", "sku") >> Bend(AzureApplicationGatewaySku.mapping),
        "gateway_ssl_certificates": S("properties", "sslCertificates")
        >> ForallBend(AzureApplicationGatewaySslCertificate.mapping),
        "gateway_ssl_policy": S("properties", "sslPolicy") >> Bend(AzureApplicationGatewaySslPolicy.mapping),
        "ssl_profiles": S("properties", "sslProfiles") >> ForallBend(AzureApplicationGatewaySslProfile.mapping),
        "trusted_client_certificates": S("properties", "trustedClientCertificates")
        >> ForallBend(AzureApplicationGatewayTrustedClientCertificate.mapping),
        "trusted_root_certificates": S("properties", "trustedRootCertificates")
        >> ForallBend(AzureApplicationGatewayTrustedRootCertificate.mapping),
        "url_path_maps": S("properties", "urlPathMaps") >> ForallBend(AzureApplicationGatewayUrlPathMap.mapping),
        "web_application_firewall_configuration": S("properties", "webApplicationFirewallConfiguration")
        >> Bend(AzureApplicationGatewayWebApplicationFirewallConfiguration.mapping),
    }
    authentication_certificates: Optional[List[AzureApplicationGatewayAuthenticationCertificate]] = field(default=None, metadata={'description': 'Authentication certificates of the application gateway resource. For default limits, see [Application Gateway limits](https://docs.microsoft.com/azure/azure-subscription-service-limits#application-gateway-limits).'})  # fmt: skip
    autoscale_configuration: Optional[AzureApplicationGatewayAutoscaleConfiguration] = field(default=None, metadata={'description': 'Application Gateway autoscale configuration.'})  # fmt: skip
    gateway_backend_address_pools: Optional[List[AzureApplicationGatewayBackendAddressPool]] = field(default=None, metadata={'description': 'Backend address pool of the application gateway resource. For default limits, see [Application Gateway limits](https://docs.microsoft.com/azure/azure-subscription-service-limits#application-gateway-limits).'})  # fmt: skip
    backend_http_settings_collection: Optional[List[AzureApplicationGatewayBackendHttpSettings]] = field(default=None, metadata={'description': 'Backend http settings of the application gateway resource. For default limits, see [Application Gateway limits](https://docs.microsoft.com/azure/azure-subscription-service-limits#application-gateway-limits).'})  # fmt: skip
    backend_settings_collection: Optional[List[AzureApplicationGatewayBackendSettings]] = field(default=None, metadata={'description': 'Backend settings of the application gateway resource. For default limits, see [Application Gateway limits](https://docs.microsoft.com/azure/azure-subscription-service-limits#application-gateway-limits).'})  # fmt: skip
    custom_error_configurations: Optional[List[AzureApplicationGatewayCustomError]] = field(default=None, metadata={'description': 'Custom error configurations of the application gateway resource.'})  # fmt: skip
    default_predefined_ssl_policy: Optional[str] = field(default=None, metadata={'description': 'Ssl predefined policy name enums.'})  # fmt: skip
    enable_fips: Optional[bool] = field(default=None, metadata={'description': 'Whether FIPS is enabled on the application gateway resource.'})  # fmt: skip
    enable_http2: Optional[bool] = field(default=None, metadata={'description': 'Whether HTTP2 is enabled on the application gateway resource.'})  # fmt: skip
    etag: Optional[str] = field(default=None, metadata={'description': 'A unique read-only string that changes whenever the resource is updated.'})  # fmt: skip
    firewall_policy: Optional[str] = field(default=None, metadata={"description": "Reference to another subresource."})
    force_firewall_policy_association: Optional[bool] = field(default=None, metadata={'description': 'If true, associates a firewall policy with an application gateway regardless whether the policy differs from the WAF Config.'})  # fmt: skip
    frontend_ip_configurations: Optional[List[AzureApplicationGatewayFrontendIPConfiguration]] = field(default=None, metadata={'description': 'Frontend IP addresses of the application gateway resource. For default limits, see [Application Gateway limits](https://docs.microsoft.com/azure/azure-subscription-service-limits#application-gateway-limits).'})  # fmt: skip
    frontend_ports: Optional[List[AzureApplicationGatewayFrontendPort]] = field(default=None, metadata={'description': 'Frontend ports of the application gateway resource. For default limits, see [Application Gateway limits](https://docs.microsoft.com/azure/azure-subscription-service-limits#application-gateway-limits).'})  # fmt: skip
    application_gateway_ip_configurations: Optional[List[AzureApplicationGatewayIPConfiguration]] = field(default=None, metadata={'description': 'Subnets of the application gateway resource. For default limits, see [Application Gateway limits](https://docs.microsoft.com/azure/azure-subscription-service-limits#application-gateway-limits).'})  # fmt: skip
    global_configuration: Optional[AzureApplicationGatewayGlobalConfiguration] = field(default=None, metadata={'description': 'Application Gateway global configuration.'})  # fmt: skip
    http_listeners: Optional[List[AzureApplicationGatewayHttpListener]] = field(default=None, metadata={'description': 'Http listeners of the application gateway resource. For default limits, see [Application Gateway limits](https://docs.microsoft.com/azure/azure-subscription-service-limits#application-gateway-limits).'})  # fmt: skip
    identity: Optional[AzureManagedServiceIdentity] = field(default=None, metadata={'description': 'Identity for the resource.'})  # fmt: skip
    listeners: Optional[List[AzureApplicationGatewayListener]] = field(default=None, metadata={'description': 'Listeners of the application gateway resource. For default limits, see [Application Gateway limits](https://docs.microsoft.com/azure/azure-subscription-service-limits#application-gateway-limits).'})  # fmt: skip
    load_distribution_policies: Optional[List[AzureApplicationGatewayLoadDistributionPolicy]] = field(default=None, metadata={'description': 'Load distribution policies of the application gateway resource.'})  # fmt: skip
    operational_state: Optional[str] = field(default=None, metadata={'description': 'Operational state of the application gateway resource.'})  # fmt: skip
    gateway_private_endpoint_connections: Optional[List[AzureApplicationGatewayPrivateEndpointConnection]] = field(default=None, metadata={'description': 'Private Endpoint connections on application gateway.'})  # fmt: skip
    private_link_configurations: Optional[List[AzureApplicationGatewayPrivateLinkConfiguration]] = field(default=None, metadata={'description': 'PrivateLink configurations on application gateway.'})  # fmt: skip
    gateway_probes: Optional[List[AzureApplicationGatewayProbe]] = field(default=None, metadata={'description': 'Probes of the application gateway resource.'})  # fmt: skip
    provisioning_state: Optional[str] = field(default=None, metadata={'description': 'The current provisioning state.'})  # fmt: skip
    redirect_configurations: Optional[List[AzureApplicationGatewayRedirectConfiguration]] = field(default=None, metadata={'description': 'Redirect configurations of the application gateway resource. For default limits, see [Application Gateway limits](https://docs.microsoft.com/azure/azure-subscription-service-limits#application-gateway-limits).'})  # fmt: skip
    request_routing_rules: Optional[List[AzureApplicationGatewayRequestRoutingRule]] = field(default=None, metadata={'description': 'Request routing rules of the application gateway resource.'})  # fmt: skip
    resource_guid: Optional[str] = field(default=None, metadata={'description': 'The resource GUID property of the application gateway resource.'})  # fmt: skip
    rewrite_rule_sets: Optional[List[AzureApplicationGatewayRewriteRuleSet]] = field(default=None, metadata={'description': 'Rewrite rules for the application gateway resource.'})  # fmt: skip
    routing_rules: Optional[List[AzureApplicationGatewayRoutingRule]] = field(default=None, metadata={'description': 'Routing rules of the application gateway resource.'})  # fmt: skip
    gateway_sku: Optional[AzureApplicationGatewaySku] = field(default=None, metadata={'description': 'SKU of an application gateway.'})  # fmt: skip
    gateway_ssl_certificates: Optional[List[AzureApplicationGatewaySslCertificate]] = field(default=None, metadata={'description': 'SSL certificates of the application gateway resource. For default limits, see [Application Gateway limits](https://docs.microsoft.com/azure/azure-subscription-service-limits#application-gateway-limits).'})  # fmt: skip
    gateway_ssl_policy: Optional[AzureApplicationGatewaySslPolicy] = field(default=None, metadata={'description': 'Application Gateway Ssl policy.'})  # fmt: skip
    ssl_profiles: Optional[List[AzureApplicationGatewaySslProfile]] = field(default=None, metadata={'description': 'SSL profiles of the application gateway resource. For default limits, see [Application Gateway limits](https://docs.microsoft.com/azure/azure-subscription-service-limits#application-gateway-limits).'})  # fmt: skip
    trusted_client_certificates: Optional[List[AzureApplicationGatewayTrustedClientCertificate]] = field(default=None, metadata={'description': 'Trusted client certificates of the application gateway resource. For default limits, see [Application Gateway limits](https://docs.microsoft.com/azure/azure-subscription-service-limits#application-gateway-limits).'})  # fmt: skip
    trusted_root_certificates: Optional[List[AzureApplicationGatewayTrustedRootCertificate]] = field(default=None, metadata={'description': 'Trusted Root certificates of the application gateway resource. For default limits, see [Application Gateway limits](https://docs.microsoft.com/azure/azure-subscription-service-limits#application-gateway-limits).'})  # fmt: skip
    url_path_maps: Optional[List[AzureApplicationGatewayUrlPathMap]] = field(default=None, metadata={'description': 'URL path map of the application gateway resource. For default limits, see [Application Gateway limits](https://docs.microsoft.com/azure/azure-subscription-service-limits#application-gateway-limits).'})  # fmt: skip
    web_application_firewall_configuration: Optional[AzureApplicationGatewayWebApplicationFirewallConfiguration] = field(default=None, metadata={'description': 'Application gateway web application firewall configuration.'})  # fmt: skip

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if firewall_policy := self.firewall_policy:
            builder.add_edge(
                self, edge_type=EdgeType.default, clazz=AzureWebApplicationFirewallPolicy, id=firewall_policy
            )
        if pl_configurations := self.private_link_configurations:
            for pl_configuration in pl_configurations:
                if ip_configurations := pl_configuration.link_ip_configurations:
                    for ip_configuration in ip_configurations:
                        if subnet_id := ip_configuration.subnet:
                            builder.add_edge(
                                self, edge_type=EdgeType.default, reverse=True, clazz=AzureSubnet, id=subnet_id
                            )


@define(eq=False, slots=False)
class AzureApplicationGatewayFirewallRule:
    kind: ClassVar[str] = "azure_application_gateway_firewall_rule"
    mapping: ClassVar[Dict[str, Bender]] = {
        "action": S("action"),
        "description": S("description"),
        "rule_id": S("ruleId"),
        "rule_id_string": S("ruleIdString"),
        "state": S("state"),
    }
    action: Optional[str] = field(default=None, metadata={'description': 'The string representation of the web application firewall rule action.'})  # fmt: skip
    description: Optional[str] = field(default=None, metadata={'description': 'The description of the web application firewall rule.'})  # fmt: skip
    rule_id: Optional[int] = field(default=None, metadata={'description': 'The identifier of the web application firewall rule.'})  # fmt: skip
    rule_id_string: Optional[str] = field(default=None, metadata={'description': 'The string representation of the web application firewall rule identifier.'})  # fmt: skip
    state: Optional[str] = field(default=None, metadata={'description': 'The string representation of the web application firewall rule state.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureApplicationGatewayFirewallRuleGroup:
    kind: ClassVar[str] = "azure_application_gateway_firewall_rule_group"
    mapping: ClassVar[Dict[str, Bender]] = {
        "description": S("description"),
        "rule_group_name": S("ruleGroupName"),
        "rules": S("rules") >> ForallBend(AzureApplicationGatewayFirewallRule.mapping),
    }
    description: Optional[str] = field(default=None, metadata={'description': 'The description of the web application firewall rule group.'})  # fmt: skip
    rule_group_name: Optional[str] = field(default=None, metadata={'description': 'The name of the web application firewall rule group.'})  # fmt: skip
    rules: Optional[List[AzureApplicationGatewayFirewallRule]] = field(default=None, metadata={'description': 'The rules of the web application firewall rule group.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureApplicationGatewayFirewallRuleSet(AzureResource):
    kind: ClassVar[str] = "azure_application_gateway_firewall_rule_set"
    api_spec: ClassVar[AzureApiSpec] = AzureApiSpec(
        service="network",
        version="2023-05-01",
        path="/subscriptions/{subscriptionId}/providers/Microsoft.Network/applicationGatewayAvailableWafRuleSets",
        path_parameters=["subscriptionId"],
        query_parameters=["api-version"],
        access_path="value",
        expect_array=True,
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("name"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "provisioning_state": S("properties", "provisioningState"),
        "rule_groups": S("properties", "ruleGroups") >> ForallBend(AzureApplicationGatewayFirewallRuleGroup.mapping),
        "rule_set_type": S("properties", "ruleSetType"),
        "rule_set_version": S("properties", "ruleSetVersion"),
        "tiers": S("properties", "tiers"),
    }
    provisioning_state: Optional[str] = field(default=None, metadata={'description': 'The current provisioning state.'})  # fmt: skip
    rule_groups: Optional[List[AzureApplicationGatewayFirewallRuleGroup]] = field(default=None, metadata={'description': 'The rule groups of the web application firewall rule set.'})  # fmt: skip
    rule_set_type: Optional[str] = field(default=None, metadata={'description': 'The type of the web application firewall rule set.'})  # fmt: skip
    rule_set_version: Optional[str] = field(default=None, metadata={'description': 'The version of the web application firewall rule set type.'})  # fmt: skip
    tiers: Optional[List[str]] = field(default=None, metadata={'description': 'Tier of an application gateway that support the rule set.'})  # fmt: skip
    _is_provider_link: bool = False


@define(eq=False, slots=False)
class AzureFirewallApplicationRuleProtocol:
    kind: ClassVar[str] = "azure_firewall_application_rule_protocol"
    mapping: ClassVar[Dict[str, Bender]] = {"port": S("port"), "protocol_type": S("protocolType")}
    port: Optional[int] = field(default=None, metadata={'description': 'Port number for the protocol, cannot be greater than 64000. This field is optional.'})  # fmt: skip
    protocol_type: Optional[str] = field(default=None, metadata={'description': 'The protocol type of a Application Rule resource.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureFirewallApplicationRule:
    kind: ClassVar[str] = "azure_firewall_application_rule"
    mapping: ClassVar[Dict[str, Bender]] = {
        "description": S("description"),
        "fqdn_tags": S("fqdnTags"),
        "name": S("name"),
        "protocols": S("protocols") >> ForallBend(AzureFirewallApplicationRuleProtocol.mapping),
        "source_addresses": S("sourceAddresses"),
        "source_ip_groups": S("sourceIpGroups"),
        "target_fqdns": S("targetFqdns"),
    }
    description: Optional[str] = field(default=None, metadata={"description": "Description of the rule."})
    fqdn_tags: Optional[List[str]] = field(default=None, metadata={"description": "List of FQDN Tags for this rule."})
    name: Optional[str] = field(default=None, metadata={"description": "Name of the application rule."})
    protocols: Optional[List[AzureFirewallApplicationRuleProtocol]] = field(default=None, metadata={'description': 'Array of ApplicationRuleProtocols.'})  # fmt: skip
    source_addresses: Optional[List[str]] = field(default=None, metadata={'description': 'List of source IP addresses for this rule.'})  # fmt: skip
    source_ip_groups: Optional[List[str]] = field(default=None, metadata={'description': 'List of source IpGroups for this rule.'})  # fmt: skip
    target_fqdns: Optional[List[str]] = field(default=None, metadata={"description": "List of FQDNs for this rule."})


@define(eq=False, slots=False)
class AzureFirewallApplicationRuleCollection(AzureSubResource):
    kind: ClassVar[str] = "azure_firewall_application_rule_collection"
    mapping: ClassVar[Dict[str, Bender]] = AzureSubResource.mapping | {
        "action": S("properties", "action", "type"),
        "etag": S("etag"),
        "name": S("name"),
        "priority": S("properties", "priority"),
        "provisioning_state": S("properties", "provisioningState"),
        "rules": S("properties", "rules") >> ForallBend(AzureFirewallApplicationRule.mapping),
    }
    action: Optional[str] = field(default=None, metadata={"description": "Properties of the AzureFirewallRCAction."})
    etag: Optional[str] = field(default=None, metadata={'description': 'A unique read-only string that changes whenever the resource is updated.'})  # fmt: skip
    name: Optional[str] = field(default=None, metadata={'description': 'The name of the resource that is unique within the Azure firewall. This name can be used to access the resource.'})  # fmt: skip
    priority: Optional[int] = field(default=None, metadata={'description': 'Priority of the application rule collection resource.'})  # fmt: skip
    provisioning_state: Optional[str] = field(default=None, metadata={'description': 'The current provisioning state.'})  # fmt: skip
    rules: Optional[List[AzureFirewallApplicationRule]] = field(default=None, metadata={'description': 'Collection of rules used by a application rule collection.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureFirewallNatRule:
    kind: ClassVar[str] = "azure_firewall_nat_rule"
    mapping: ClassVar[Dict[str, Bender]] = {
        "description": S("description"),
        "destination_addresses": S("destinationAddresses"),
        "destination_ports": S("destinationPorts"),
        "name": S("name"),
        "protocols": S("protocols"),
        "source_addresses": S("sourceAddresses"),
        "source_ip_groups": S("sourceIpGroups"),
        "translated_address": S("translatedAddress"),
        "translated_fqdn": S("translatedFqdn"),
        "translated_port": S("translatedPort"),
    }
    description: Optional[str] = field(default=None, metadata={"description": "Description of the rule."})
    destination_addresses: Optional[List[str]] = field(default=None, metadata={'description': 'List of destination IP addresses for this rule. Supports IP ranges, prefixes, and service tags.'})  # fmt: skip
    destination_ports: Optional[List[str]] = field(default=None, metadata={"description": "List of destination ports."})
    name: Optional[str] = field(default=None, metadata={"description": "Name of the NAT rule."})
    protocols: Optional[List[str]] = field(default=None, metadata={'description': 'Array of AzureFirewallNetworkRuleProtocols applicable to this NAT rule.'})  # fmt: skip
    source_addresses: Optional[List[str]] = field(default=None, metadata={'description': 'List of source IP addresses for this rule.'})  # fmt: skip
    source_ip_groups: Optional[List[str]] = field(default=None, metadata={'description': 'List of source IpGroups for this rule.'})  # fmt: skip
    translated_address: Optional[str] = field(default=None, metadata={'description': 'The translated address for this NAT rule.'})  # fmt: skip
    translated_fqdn: Optional[str] = field(default=None, metadata={'description': 'The translated FQDN for this NAT rule.'})  # fmt: skip
    translated_port: Optional[str] = field(default=None, metadata={'description': 'The translated port for this NAT rule.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureFirewallNatRuleCollection(AzureSubResource):
    kind: ClassVar[str] = "azure_firewall_nat_rule_collection"
    mapping: ClassVar[Dict[str, Bender]] = AzureSubResource.mapping | {
        "action": S("properties", "action", "type"),
        "etag": S("etag"),
        "name": S("name"),
        "priority": S("properties", "priority"),
        "provisioning_state": S("properties", "provisioningState"),
        "rules": S("properties", "rules") >> ForallBend(AzureFirewallNatRule.mapping),
    }
    action: Optional[str] = field(default=None, metadata={"description": "AzureFirewall NAT Rule Collection Action."})
    etag: Optional[str] = field(default=None, metadata={'description': 'A unique read-only string that changes whenever the resource is updated.'})  # fmt: skip
    name: Optional[str] = field(default=None, metadata={'description': 'The name of the resource that is unique within the Azure firewall. This name can be used to access the resource.'})  # fmt: skip
    priority: Optional[int] = field(default=None, metadata={'description': 'Priority of the NAT rule collection resource.'})  # fmt: skip
    provisioning_state: Optional[str] = field(default=None, metadata={'description': 'The current provisioning state.'})  # fmt: skip
    rules: Optional[List[AzureFirewallNatRule]] = field(default=None, metadata={'description': 'Collection of rules used by a NAT rule collection.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureFirewallNetworkRule:
    kind: ClassVar[str] = "azure_firewall_network_rule"
    mapping: ClassVar[Dict[str, Bender]] = {
        "description": S("description"),
        "destination_addresses": S("destinationAddresses"),
        "destination_fqdns": S("destinationFqdns"),
        "destination_ip_groups": S("destinationIpGroups"),
        "destination_ports": S("destinationPorts"),
        "name": S("name"),
        "protocols": S("protocols"),
        "source_addresses": S("sourceAddresses"),
        "source_ip_groups": S("sourceIpGroups"),
    }
    description: Optional[str] = field(default=None, metadata={"description": "Description of the rule."})
    destination_addresses: Optional[List[str]] = field(default=None, metadata={'description': 'List of destination IP addresses.'})  # fmt: skip
    destination_fqdns: Optional[List[str]] = field(default=None, metadata={"description": "List of destination FQDNs."})
    destination_ip_groups: Optional[List[str]] = field(default=None, metadata={'description': 'List of destination IpGroups for this rule.'})  # fmt: skip
    destination_ports: Optional[List[str]] = field(default=None, metadata={"description": "List of destination ports."})
    name: Optional[str] = field(default=None, metadata={"description": "Name of the network rule."})
    protocols: Optional[List[str]] = field(default=None, metadata={'description': 'Array of AzureFirewallNetworkRuleProtocols.'})  # fmt: skip
    source_addresses: Optional[List[str]] = field(default=None, metadata={'description': 'List of source IP addresses for this rule.'})  # fmt: skip
    source_ip_groups: Optional[List[str]] = field(default=None, metadata={'description': 'List of source IpGroups for this rule.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureFirewallNetworkRuleCollection(AzureSubResource):
    kind: ClassVar[str] = "azure_firewall_network_rule_collection"
    mapping: ClassVar[Dict[str, Bender]] = AzureSubResource.mapping | {
        "action": S("properties", "action", "type"),
        "etag": S("etag"),
        "name": S("name"),
        "priority": S("properties", "priority"),
        "provisioning_state": S("properties", "provisioningState"),
        "rules": S("properties", "rules") >> ForallBend(AzureFirewallNetworkRule.mapping),
    }
    action: Optional[str] = field(default=None, metadata={"description": "Properties of the AzureFirewallRCAction."})
    etag: Optional[str] = field(default=None, metadata={'description': 'A unique read-only string that changes whenever the resource is updated.'})  # fmt: skip
    name: Optional[str] = field(default=None, metadata={'description': 'The name of the resource that is unique within the Azure firewall. This name can be used to access the resource.'})  # fmt: skip
    priority: Optional[int] = field(default=None, metadata={'description': 'Priority of the network rule collection resource.'})  # fmt: skip
    provisioning_state: Optional[str] = field(default=None, metadata={'description': 'The current provisioning state.'})  # fmt: skip
    rules: Optional[List[AzureFirewallNetworkRule]] = field(default=None, metadata={'description': 'Collection of rules used by a network rule collection.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureFirewallIPConfiguration(AzureSubResource):
    kind: ClassVar[str] = "azure_firewall_ip_configuration"
    mapping: ClassVar[Dict[str, Bender]] = AzureSubResource.mapping | {
        "etag": S("etag"),
        "name": S("name"),
        "private_ip_address": S("properties", "privateIPAddress"),
        "provisioning_state": S("properties", "provisioningState"),
        "public_ip_address": S("properties", "publicIPAddress", "id"),
        "subnet": S("properties", "subnet", "id"),
        "type": S("type"),
    }
    etag: Optional[str] = field(default=None, metadata={'description': 'A unique read-only string that changes whenever the resource is updated.'})  # fmt: skip
    name: Optional[str] = field(default=None, metadata={'description': 'Name of the resource that is unique within a resource group. This name can be used to access the resource.'})  # fmt: skip
    private_ip_address: Optional[str] = field(default=None, metadata={'description': 'The Firewall Internal Load Balancer IP to be used as the next hop in User Defined Routes.'})  # fmt: skip
    provisioning_state: Optional[str] = field(default=None, metadata={'description': 'The current provisioning state.'})  # fmt: skip
    public_ip_address: Optional[str] = field(default=None, metadata={'description': 'Reference to another subresource.'})  # fmt: skip
    subnet: Optional[str] = field(default=None, metadata={"description": "Reference to another subresource."})
    type: Optional[str] = field(default=None, metadata={"description": "Type of the resource."})


@define(eq=False, slots=False)
class AzureHubPublicIPAddresses:
    kind: ClassVar[str] = "azure_hub_public_ip_addresses"
    mapping: ClassVar[Dict[str, Bender]] = {
        "addresses": S("addresses", default=[]) >> ForallBend(S("address")),
        "count": S("count"),
    }
    addresses: Optional[List[str]] = field(default=None, metadata={'description': 'The list of Public IP addresses associated with azure firewall or IP addresses to be retained.'})  # fmt: skip
    count: Optional[int] = field(default=None, metadata={'description': 'The number of Public IP addresses associated with azure firewall.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureHubIPAddresses:
    kind: ClassVar[str] = "azure_hub_ip_addresses"
    mapping: ClassVar[Dict[str, Bender]] = {
        "private_ip_address": S("privateIPAddress"),
        "public_i_ps": S("publicIPs") >> Bend(AzureHubPublicIPAddresses.mapping),
    }
    private_ip_address: Optional[str] = field(default=None, metadata={'description': 'Private IP Address associated with azure firewall.'})  # fmt: skip
    public_i_ps: Optional[AzureHubPublicIPAddresses] = field(default=None, metadata={'description': 'Public IP addresses associated with azure firewall.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureFirewallIpGroups:
    kind: ClassVar[str] = "azure_firewall_ip_groups"
    mapping: ClassVar[Dict[str, Bender]] = {"change_number": S("changeNumber"), "id": S("id")}
    change_number: Optional[str] = field(default=None, metadata={"description": "The iteration number."})
    id: Optional[str] = field(default=None, metadata={"description": "Resource ID."})


@define(eq=False, slots=False)
class AzureFirewallSku:
    kind: ClassVar[str] = "azure_firewall_sku"
    mapping: ClassVar[Dict[str, Bender]] = {"name": S("name"), "tier": S("tier")}
    name: Optional[str] = field(default=None, metadata={"description": "Name of an Azure Firewall SKU."})
    tier: Optional[str] = field(default=None, metadata={"description": "Tier of an Azure Firewall."})


@define(eq=False, slots=False)
class AzureFirewall(AzureResource, BaseFirewall):
    kind: ClassVar[str] = "azure_firewall"
    api_spec: ClassVar[AzureApiSpec] = AzureApiSpec(
        service="network",
        version="2023-05-01",
        path="/subscriptions/{subscriptionId}/providers/Microsoft.Network/azureFirewalls",
        path_parameters=["subscriptionId"],
        query_parameters=["api-version"],
        access_path="value",
        expect_array=True,
    )
    reference_kinds: ClassVar[ModelReference] = {
        "predecessors": {"default": ["azure_subnet"]},
        "successors": {"default": ["azure_firewall_policy", "azure_virtual_hub"]},
    }
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "additional_properties": S("properties", "additionalProperties"),
        "application_rule_collections": S("properties", "applicationRuleCollections")
        >> ForallBend(AzureFirewallApplicationRuleCollection.mapping),
        "etag": S("etag"),
        "firewall_policy": S("properties", "firewallPolicy", "id"),
        "hub_ip_addresses": S("properties", "hubIPAddresses") >> Bend(AzureHubIPAddresses.mapping),
        "firewall_ip_configurations": S("properties", "ipConfigurations")
        >> ForallBend(AzureFirewallIPConfiguration.mapping),
        "ip_groups": S("properties", "ipGroups") >> ForallBend(AzureFirewallIpGroups.mapping),
        "management_ip_configuration": S("properties", "managementIpConfiguration")
        >> Bend(AzureFirewallIPConfiguration.mapping),
        "nat_rule_collections": S("properties", "natRuleCollections")
        >> ForallBend(AzureFirewallNatRuleCollection.mapping),
        "network_rule_collections": S("properties", "networkRuleCollections")
        >> ForallBend(AzureFirewallNetworkRuleCollection.mapping),
        "provisioning_state": S("properties", "provisioningState"),
        "firewall_sku": S("properties", "sku") >> Bend(AzureFirewallSku.mapping),
        "threat_intel_mode": S("properties", "threatIntelMode"),
        "virtual_hub": S("properties", "virtualHub", "id"),
    }
    additional_properties: Optional[Dict[str, str]] = field(default=None, metadata={'description': 'The additional properties of azure firewall.'})  # fmt: skip
    application_rule_collections: Optional[List[AzureFirewallApplicationRuleCollection]] = field(default=None, metadata={'description': 'Collection of application rule collections used by Azure Firewall.'})  # fmt: skip
    etag: Optional[str] = field(default=None, metadata={'description': 'A unique read-only string that changes whenever the resource is updated.'})  # fmt: skip
    firewall_policy: Optional[str] = field(default=None, metadata={"description": "Reference to another subresource."})
    hub_ip_addresses: Optional[AzureHubIPAddresses] = field(default=None, metadata={'description': 'IP addresses associated with azure firewall.'})  # fmt: skip
    firewall_ip_configurations: Optional[List[AzureFirewallIPConfiguration]] = field(default=None, metadata={'description': 'IP configuration of the Azure Firewall resource.'})  # fmt: skip
    ip_groups: Optional[List[AzureFirewallIpGroups]] = field(default=None, metadata={'description': 'List of IpGroups associated with azure firewall.'})  # fmt: skip
    management_ip_configuration: Optional[AzureFirewallIPConfiguration] = field(default=None, metadata={'description': 'IP configuration of an Azure Firewall.'})  # fmt: skip
    nat_rule_collections: Optional[List[AzureFirewallNatRuleCollection]] = field(default=None, metadata={'description': 'Collection of NAT rule collections used by Azure Firewall.'})  # fmt: skip
    network_rule_collections: Optional[List[AzureFirewallNetworkRuleCollection]] = field(default=None, metadata={'description': 'Collection of network rule collections used by Azure Firewall.'})  # fmt: skip
    provisioning_state: Optional[str] = field(default=None, metadata={'description': 'The current provisioning state.'})  # fmt: skip
    firewall_sku: Optional[AzureFirewallSku] = field(
        default=None, metadata={"description": "SKU of an Azure Firewall."}
    )
    threat_intel_mode: Optional[str] = field(default=None, metadata={'description': 'The operation mode for Threat Intel.'})  # fmt: skip
    virtual_hub: Optional[str] = field(default=None, metadata={"description": "Reference to another subresource."})

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if policy_id := self.firewall_policy:
            builder.add_edge(self, edge_type=EdgeType.default, clazz=AzureFirewallPolicy, id=policy_id)
        if ip_confs := self.firewall_ip_configurations:
            for ip_conf in ip_confs:
                if subnet_id := ip_conf.subnet:
                    builder.add_edge(self, edge_type=EdgeType.default, reverse=True, clazz=AzureSubnet, id=subnet_id)
        if vh_id := self.virtual_hub:
            builder.add_edge(self, edge_type=EdgeType.default, clazz=AzureVirtualHub, id=vh_id)


@define(eq=False, slots=False)
class AzureBastionHostIPConfiguration(AzureSubResource):
    kind: ClassVar[str] = "azure_bastion_host_ip_configuration"
    mapping: ClassVar[Dict[str, Bender]] = AzureSubResource.mapping | {
        "etag": S("etag"),
        "name": S("name"),
        "private_ip_allocation_method": S("properties", "privateIPAllocationMethod"),
        "provisioning_state": S("properties", "provisioningState"),
        "public_ip_address": S("properties", "publicIPAddress", "id"),
        "subnet": S("properties", "subnet", "id"),
        "type": S("type"),
    }
    etag: Optional[str] = field(default=None, metadata={'description': 'A unique read-only string that changes whenever the resource is updated.'})  # fmt: skip
    name: Optional[str] = field(default=None, metadata={'description': 'Name of the resource that is unique within a resource group. This name can be used to access the resource.'})  # fmt: skip
    private_ip_allocation_method: Optional[str] = field(default=None, metadata={'description': 'IP address allocation method.'})  # fmt: skip
    provisioning_state: Optional[str] = field(default=None, metadata={'description': 'The current provisioning state.'})  # fmt: skip
    public_ip_address: Optional[str] = field(default=None, metadata={'description': 'Reference to another subresource.'})  # fmt: skip
    subnet: Optional[str] = field(default=None, metadata={"description": "Reference to another subresource."})
    type: Optional[str] = field(default=None, metadata={"description": "Ip configuration type."})


@define(eq=False, slots=False)
class AzureIpRules:
    kind: ClassVar[str] = "azure_ip_rules"
    mapping: ClassVar[Dict[str, Bender]] = {"ip_rules": S("ipRules", default=[]) >> ForallBend(S("addressPrefix"))}
    ip_rules: Optional[List[str]] = field(default=None, metadata={'description': 'Sets the IP ACL rules for Developer Bastion Host.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureBastionHost(AzureResource):
    kind: ClassVar[str] = "azure_bastion_host"
    api_spec: ClassVar[AzureApiSpec] = AzureApiSpec(
        service="network",
        version="2023-05-01",
        path="/subscriptions/{subscriptionId}/providers/Microsoft.Network/bastionHosts",
        path_parameters=["subscriptionId"],
        query_parameters=["api-version"],
        access_path="value",
        expect_array=True,
    )
    reference_kinds: ClassVar[ModelReference] = {
        "predecessors": {"default": ["azure_virtual_network", "azure_subnet"]},
        "successors": {"default": ["azure_public_ip_address"]},
    }
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "disable_copy_paste": S("properties", "disableCopyPaste"),
        "dns_name": S("properties", "dnsName"),
        "enable_file_copy": S("properties", "enableFileCopy"),
        "enable_ip_connect": S("properties", "enableIpConnect"),
        "enable_kerberos": S("properties", "enableKerberos"),
        "enable_shareable_link": S("properties", "enableShareableLink"),
        "enable_tunneling": S("properties", "enableTunneling"),
        "etag": S("etag"),
        "bastion_host_ip_configurations": S("properties", "ipConfigurations")
        >> ForallBend(AzureBastionHostIPConfiguration.mapping),
        "network_acls": S("properties", "networkAcls") >> Bend(AzureIpRules.mapping),
        "provisioning_state": S("properties", "provisioningState"),
        "scale_units": S("properties", "scaleUnits"),
        "sku": S("sku", "name"),
        "virtual_network": S("properties", "virtualNetwork", "id"),
    }
    disable_copy_paste: Optional[bool] = field(default=None, metadata={'description': 'Enable/Disable Copy/Paste feature of the Bastion Host resource.'})  # fmt: skip
    dns_name: Optional[str] = field(default=None, metadata={'description': 'FQDN for the endpoint on which bastion host is accessible.'})  # fmt: skip
    enable_file_copy: Optional[bool] = field(default=None, metadata={'description': 'Enable/Disable File Copy feature of the Bastion Host resource.'})  # fmt: skip
    enable_ip_connect: Optional[bool] = field(default=None, metadata={'description': 'Enable/Disable IP Connect feature of the Bastion Host resource.'})  # fmt: skip
    enable_kerberos: Optional[bool] = field(default=None, metadata={'description': 'Enable/Disable Kerberos feature of the Bastion Host resource.'})  # fmt: skip
    enable_shareable_link: Optional[bool] = field(default=None, metadata={'description': 'Enable/Disable Shareable Link of the Bastion Host resource.'})  # fmt: skip
    enable_tunneling: Optional[bool] = field(default=None, metadata={'description': 'Enable/Disable Tunneling feature of the Bastion Host resource.'})  # fmt: skip
    etag: Optional[str] = field(default=None, metadata={'description': 'A unique read-only string that changes whenever the resource is updated.'})  # fmt: skip
    bastion_host_ip_configurations: Optional[List[AzureBastionHostIPConfiguration]] = field(default=None, metadata={'description': 'IP configuration of the Bastion Host resource.'})  # fmt: skip
    network_acls: Optional[AzureIpRules] = field(default=None, metadata={"description": ""})
    provisioning_state: Optional[str] = field(default=None, metadata={'description': 'The current provisioning state.'})  # fmt: skip
    scale_units: Optional[int] = field(default=None, metadata={'description': 'The scale units for the Bastion Host resource.'})  # fmt: skip
    sku: Optional[str] = field(default=None, metadata={"description": "The sku of this Bastion Host."})
    virtual_network: Optional[str] = field(default=None, metadata={"description": "Reference to another subresource."})

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if vn_id := self.virtual_network:
            builder.add_edge(self, edge_type=EdgeType.default, reverse=True, clazz=AzureVirtualNetwork, id=vn_id)
        if ip_configurations := self.bastion_host_ip_configurations:
            for ip_configuration in ip_configurations:
                if subnet_id := ip_configuration.subnet:
                    builder.add_edge(self, edge_type=EdgeType.default, reverse=True, clazz=AzureSubnet, id=subnet_id)
                if p_ip_address_id := ip_configuration.public_ip_address:
                    builder.add_edge(self, edge_type=EdgeType.default, clazz=AzurePublicIPAddress, id=p_ip_address_id)


@define(eq=False, slots=False)
class AzureCustomIpPrefix(AzureResource):
    kind: ClassVar[str] = "azure_custom_ip_prefix"
    api_spec: ClassVar[AzureApiSpec] = AzureApiSpec(
        service="network",
        version="2023-05-01",
        path="/subscriptions/{subscriptionId}/providers/Microsoft.Network/customIpPrefixes",
        path_parameters=["subscriptionId"],
        query_parameters=["api-version"],
        access_path="value",
        expect_array=True,
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "asn": S("properties", "asn"),
        "authorization_message": S("properties", "authorizationMessage"),
        "child_custom_ip_prefixes": S("properties") >> S("childCustomIpPrefixes", default=[]) >> ForallBend(S("id")),
        "cidr": S("properties", "cidr"),
        "commissioned_state": S("properties", "commissionedState"),
        "custom_ip_prefix_parent": S("properties", "customIpPrefixParent", "id"),
        "etag": S("etag"),
        "express_route_advertise": S("properties", "expressRouteAdvertise"),
        "extended_location": S("extendedLocation") >> Bend(AzureExtendedLocation.mapping),
        "failed_reason": S("properties", "failedReason"),
        "geo": S("properties", "geo"),
        "no_internet_advertise": S("properties", "noInternetAdvertise"),
        "prefix_type": S("properties", "prefixType"),
        "provisioning_state": S("properties", "provisioningState"),
        "public_ip_prefixes": S("properties") >> S("publicIpPrefixes", default=[]) >> ForallBend(S("id")),
        "resource_guid": S("properties", "resourceGuid"),
        "signed_message": S("properties", "signedMessage"),
    }
    asn: Optional[str] = field(default=None, metadata={'description': 'The ASN for CIDR advertising. Should be an integer as string.'})  # fmt: skip
    authorization_message: Optional[str] = field(default=None, metadata={'description': 'Authorization message for WAN validation.'})  # fmt: skip
    child_custom_ip_prefixes: Optional[List[str]] = field(default=None, metadata={'description': 'The list of all Children for IPv6 /48 CustomIpPrefix.'})  # fmt: skip
    cidr: Optional[str] = field(default=None, metadata={'description': 'The prefix range in CIDR notation. Should include the start address and the prefix length.'})  # fmt: skip
    commissioned_state: Optional[str] = field(default=None, metadata={'description': 'The commissioned state of the Custom IP Prefix.'})  # fmt: skip
    custom_ip_prefix_parent: Optional[str] = field(default=None, metadata={'description': 'Reference to another subresource.'})  # fmt: skip
    etag: Optional[str] = field(default=None, metadata={'description': 'A unique read-only string that changes whenever the resource is updated.'})  # fmt: skip
    express_route_advertise: Optional[bool] = field(default=None, metadata={'description': 'Whether to do express route advertise.'})  # fmt: skip
    extended_location: Optional[AzureExtendedLocation] = field(default=None, metadata={'description': 'ExtendedLocation complex type.'})  # fmt: skip
    failed_reason: Optional[str] = field(default=None, metadata={'description': 'The reason why resource is in failed state.'})  # fmt: skip
    geo: Optional[str] = field(default=None, metadata={'description': 'The Geo for CIDR advertising. Should be an Geo code.'})  # fmt: skip
    no_internet_advertise: Optional[bool] = field(default=None, metadata={'description': 'Whether to Advertise the range to Internet.'})  # fmt: skip
    prefix_type: Optional[str] = field(default=None, metadata={'description': 'Type of custom IP prefix. Should be Singular, Parent, or Child.'})  # fmt: skip
    provisioning_state: Optional[str] = field(default=None, metadata={'description': 'The current provisioning state.'})  # fmt: skip
    public_ip_prefixes: Optional[List[str]] = field(default=None, metadata={'description': 'The list of all referenced PublicIpPrefixes.'})  # fmt: skip
    resource_guid: Optional[str] = field(default=None, metadata={'description': 'The resource GUID property of the custom IP prefix resource.'})  # fmt: skip
    signed_message: Optional[str] = field(default=None, metadata={"description": "Signed message for WAN validation."})


@define(eq=False, slots=False)
class AzureDdosProtectionPlan(AzureResource):
    kind: ClassVar[str] = "azure_ddos_protection_plan"
    api_spec: ClassVar[AzureApiSpec] = AzureApiSpec(
        service="network",
        version="2023-05-01",
        path="/subscriptions/{subscriptionId}/providers/Microsoft.Network/ddosProtectionPlans",
        path_parameters=["subscriptionId"],
        query_parameters=["api-version"],
        access_path="value",
        expect_array=True,
    )
    reference_kinds: ClassVar[ModelReference] = {
        "successors": {"default": ["azure_public_ip_address", "azure_virtual_network"]},
    }
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "etag": S("etag"),
        "provisioning_state": S("properties", "provisioningState"),
        "public_ip_addresses": S("properties") >> S("publicIPAddresses", default=[]) >> ForallBend(S("id")),
        "resource_guid": S("properties", "resourceGuid"),
        "virtual_networks": S("properties") >> S("virtualNetworks", default=[]) >> ForallBend(S("id")),
    }
    etag: Optional[str] = field(default=None, metadata={'description': 'A unique read-only string that changes whenever the resource is updated.'})  # fmt: skip
    provisioning_state: Optional[str] = field(default=None, metadata={'description': 'The current provisioning state.'})  # fmt: skip
    public_ip_addresses: Optional[List[str]] = field(default=None, metadata={'description': 'The list of public IPs associated with the DDoS protection plan resource. This list is read-only.'})  # fmt: skip
    resource_guid: Optional[str] = field(default=None, metadata={'description': 'The resource GUID property of the DDoS protection plan resource. It uniquely identifies the resource, even if the user changes its name or migrate the resource across subscriptions or resource groups.'})  # fmt: skip
    virtual_networks: Optional[List[str]] = field(default=None, metadata={'description': 'The list of virtual networks associated with the DDoS protection plan resource. This list is read-only.'})  # fmt: skip

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if vns := self.virtual_networks:
            for vn_id in vns:
                builder.add_edge(self, edge_type=EdgeType.default, clazz=AzureVirtualNetwork, id=vn_id)
        if p_ip_addresses := self.public_ip_addresses:
            for p_ip_address_id in p_ip_addresses:
                builder.add_edge(self, edge_type=EdgeType.default, clazz=AzurePublicIPAddress, id=p_ip_address_id)


@define(eq=False, slots=False)
class AzureQosIpRange:
    kind: ClassVar[str] = "azure_qos_ip_range"
    mapping: ClassVar[Dict[str, Bender]] = {"end_ip": S("endIP"), "start_ip": S("startIP")}
    end_ip: Optional[str] = field(default=None, metadata={"description": "End IP Address."})
    start_ip: Optional[str] = field(default=None, metadata={"description": "Start IP Address."})


@define(eq=False, slots=False)
class AzureQosPortRange:
    kind: ClassVar[str] = "azure_qos_port_range"
    mapping: ClassVar[Dict[str, Bender]] = {"end": S("end"), "start": S("start")}
    end: Optional[int] = field(default=None, metadata={"description": "Qos Port Range end."})
    start: Optional[int] = field(default=None, metadata={"description": "Qos Port Range start."})


@define(eq=False, slots=False)
class AzureQosDefinition:
    kind: ClassVar[str] = "azure_qos_definition"
    mapping: ClassVar[Dict[str, Bender]] = {
        "destination_ip_ranges": S("destinationIpRanges") >> ForallBend(AzureQosIpRange.mapping),
        "destination_port_ranges": S("destinationPortRanges") >> ForallBend(AzureQosPortRange.mapping),
        "markings": S("markings"),
        "protocol": S("protocol"),
        "source_ip_ranges": S("sourceIpRanges") >> ForallBend(AzureQosIpRange.mapping),
        "source_port_ranges": S("sourcePortRanges") >> ForallBend(AzureQosPortRange.mapping),
    }
    destination_ip_ranges: Optional[List[AzureQosIpRange]] = field(default=None, metadata={'description': 'Destination IP ranges.'})  # fmt: skip
    destination_port_ranges: Optional[List[AzureQosPortRange]] = field(default=None, metadata={'description': 'Destination port ranges.'})  # fmt: skip
    markings: Optional[List[int]] = field(default=None, metadata={'description': 'List of markings to be used in the configuration.'})  # fmt: skip
    protocol: Optional[str] = field(default=None, metadata={"description": "RNM supported protocol types."})
    source_ip_ranges: Optional[List[AzureQosIpRange]] = field(
        default=None, metadata={"description": "Source IP ranges."}
    )
    source_port_ranges: Optional[List[AzureQosPortRange]] = field(default=None, metadata={'description': 'Sources port ranges.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureSecurityRule(AzureSubResource):
    kind: ClassVar[str] = "azure_security_rule"
    mapping: ClassVar[Dict[str, Bender]] = AzureSubResource.mapping | {
        "access": S("properties", "access"),
        "description": S("properties", "description"),
        "destination_address_prefix": S("properties", "destinationAddressPrefix"),
        "destination_address_prefixes": S("properties", "destinationAddressPrefixes"),
        "destination_application_security_groups": S("properties", "destinationApplicationSecurityGroups")
        >> ForallBend(AzureApplicationSecurityGroup.mapping),
        "destination_port_range": S("properties", "destinationPortRange"),
        "destination_port_ranges": S("properties", "destinationPortRanges"),
        "direction": S("properties", "direction"),
        "etag": S("etag"),
        "name": S("name"),
        "priority": S("properties", "priority"),
        "protocol": S("properties", "protocol"),
        "provisioning_state": S("properties", "provisioningState"),
        "source_address_prefix": S("properties", "sourceAddressPrefix"),
        "source_address_prefixes": S("properties", "sourceAddressPrefixes"),
        "source_application_security_groups": S("properties", "sourceApplicationSecurityGroups")
        >> ForallBend(AzureApplicationSecurityGroup.mapping),
        "source_port_range": S("properties", "sourcePortRange"),
        "source_port_ranges": S("properties", "sourcePortRanges"),
        "type": S("type"),
    }
    access: Optional[str] = field(default=None, metadata={'description': 'Whether network traffic is allowed or denied.'})  # fmt: skip
    description: Optional[str] = field(default=None, metadata={'description': 'A description for this rule. Restricted to 140 chars.'})  # fmt: skip
    destination_address_prefix: Optional[str] = field(default=None, metadata={'description': 'The destination address prefix. CIDR or destination IP range. Asterisk * can also be used to match all source IPs. Default tags such as VirtualNetwork , AzureLoadBalancer and Internet can also be used.'})  # fmt: skip
    destination_address_prefixes: Optional[List[str]] = field(default=None, metadata={'description': 'The destination address prefixes. CIDR or destination IP ranges.'})  # fmt: skip
    destination_application_security_groups: Optional[List[AzureApplicationSecurityGroup]] = field(default=None, metadata={'description': 'The application security group specified as destination.'})  # fmt: skip
    destination_port_range: Optional[str] = field(default=None, metadata={'description': 'The destination port or range. Integer or range between 0 and 65535. Asterisk * can also be used to match all ports.'})  # fmt: skip
    destination_port_ranges: Optional[List[str]] = field(default=None, metadata={'description': 'The destination port ranges.'})  # fmt: skip
    direction: Optional[str] = field(default=None, metadata={'description': 'The direction of the rule. The direction specifies if rule will be evaluated on incoming or outgoing traffic.'})  # fmt: skip
    etag: Optional[str] = field(default=None, metadata={'description': 'A unique read-only string that changes whenever the resource is updated.'})  # fmt: skip
    name: Optional[str] = field(default=None, metadata={'description': 'The name of the resource that is unique within a resource group. This name can be used to access the resource.'})  # fmt: skip
    priority: Optional[int] = field(default=None, metadata={'description': 'The priority of the rule. The value can be between 100 and 4096. The priority number must be unique for each rule in the collection. The lower the priority number, the higher the priority of the rule.'})  # fmt: skip
    protocol: Optional[str] = field(default=None, metadata={"description": "Network protocol this rule applies to."})
    provisioning_state: Optional[str] = field(default=None, metadata={'description': 'The current provisioning state.'})  # fmt: skip
    source_address_prefix: Optional[str] = field(default=None, metadata={'description': 'The CIDR or source IP range. Asterisk * can also be used to match all source IPs. Default tags such as VirtualNetwork , AzureLoadBalancer and Internet can also be used. If this is an ingress rule, specifies where network traffic originates from.'})  # fmt: skip
    source_address_prefixes: Optional[List[str]] = field(default=None, metadata={'description': 'The CIDR or source IP ranges.'})  # fmt: skip
    source_application_security_groups: Optional[List[AzureApplicationSecurityGroup]] = field(default=None, metadata={'description': 'The application security group specified as source.'})  # fmt: skip
    source_port_range: Optional[str] = field(default=None, metadata={'description': 'The source port or range. Integer or range between 0 and 65535. Asterisk * can also be used to match all ports.'})  # fmt: skip
    source_port_ranges: Optional[List[str]] = field(default=None, metadata={"description": "The source port ranges."})
    type: Optional[str] = field(default=None, metadata={"description": "The type of the resource."})


@define(eq=False, slots=False)
class AzureRetentionPolicyParameters:
    kind: ClassVar[str] = "azure_retention_policy_parameters"
    mapping: ClassVar[Dict[str, Bender]] = {"days": S("days"), "enabled": S("enabled")}
    days: Optional[int] = field(default=None, metadata={"description": "Number of days to retain flow log records."})
    enabled: Optional[bool] = field(default=None, metadata={"description": "Flag to enable/disable retention."})


@define(eq=False, slots=False)
class AzureFlowLogFormatParameters:
    kind: ClassVar[str] = "azure_flow_log_format_parameters"
    mapping: ClassVar[Dict[str, Bender]] = {"type": S("type"), "version": S("version")}
    type: Optional[str] = field(default=None, metadata={"description": "The file type of flow log."})
    version: Optional[int] = field(default=None, metadata={"description": "The version (revision) of the flow log."})


@define(eq=False, slots=False)
class AzureTrafficAnalyticsConfigurationProperties:
    kind: ClassVar[str] = "azure_traffic_analytics_configuration_properties"
    mapping: ClassVar[Dict[str, Bender]] = {
        "enabled": S("enabled"),
        "traffic_analytics_interval": S("trafficAnalyticsInterval"),
        "workspace_id": S("workspaceId"),
        "workspace_region": S("workspaceRegion"),
        "workspace_resource_id": S("workspaceResourceId"),
    }
    enabled: Optional[bool] = field(default=None, metadata={'description': 'Flag to enable/disable traffic analytics.'})  # fmt: skip
    traffic_analytics_interval: Optional[int] = field(default=None, metadata={'description': 'The interval in minutes which would decide how frequently TA service should do flow analytics.'})  # fmt: skip
    workspace_id: Optional[str] = field(default=None, metadata={'description': 'The resource guid of the attached workspace.'})  # fmt: skip
    workspace_region: Optional[str] = field(default=None, metadata={'description': 'The location of the attached workspace.'})  # fmt: skip
    workspace_resource_id: Optional[str] = field(default=None, metadata={'description': 'Resource Id of the attached workspace.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureTrafficAnalyticsProperties:
    kind: ClassVar[str] = "azure_traffic_analytics_properties"
    mapping: ClassVar[Dict[str, Bender]] = {
        "network_watcher_flow_analytics_configuration": S("networkWatcherFlowAnalyticsConfiguration")
        >> Bend(AzureTrafficAnalyticsConfigurationProperties.mapping)
    }
    network_watcher_flow_analytics_configuration: Optional[AzureTrafficAnalyticsConfigurationProperties] = field(default=None, metadata={'description': 'Parameters that define the configuration of traffic analytics.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureFlowLog:
    kind: ClassVar[str] = "azure_flow_log"
    mapping: ClassVar[Dict[str, Bender]] = {
        "enabled": S("properties", "enabled"),
        "etag": S("etag"),
        "flow_analytics_configuration": S("properties", "flowAnalyticsConfiguration")
        >> Bend(AzureTrafficAnalyticsProperties.mapping),
        "format": S("properties", "format") >> Bend(AzureFlowLogFormatParameters.mapping),
        "id": S("id"),
        "location": S("location"),
        "name": S("name"),
        "provisioning_state": S("properties", "provisioningState"),
        "retention_policy": S("properties", "retentionPolicy") >> Bend(AzureRetentionPolicyParameters.mapping),
        "storage_id": S("properties", "storageId"),
        "tags": S("tags", default={}),
        "target_resource_guid": S("properties", "targetResourceGuid"),
        "target_resource_id": S("properties", "targetResourceId"),
        "type": S("type"),
    }
    enabled: Optional[bool] = field(default=None, metadata={"description": "Flag to enable/disable flow logging."})
    etag: Optional[str] = field(default=None, metadata={'description': 'A unique read-only string that changes whenever the resource is updated.'})  # fmt: skip
    flow_analytics_configuration: Optional[AzureTrafficAnalyticsProperties] = field(default=None, metadata={'description': 'Parameters that define the configuration of traffic analytics.'})  # fmt: skip
    format: Optional[AzureFlowLogFormatParameters] = field(default=None, metadata={'description': 'Parameters that define the flow log format.'})  # fmt: skip
    id: Optional[str] = field(default=None, metadata={"description": "Resource ID."})
    location: Optional[str] = field(default=None, metadata={"description": "Resource location."})
    name: Optional[str] = field(default=None, metadata={"description": "Resource name."})
    provisioning_state: Optional[str] = field(default=None, metadata={'description': 'The current provisioning state.'})  # fmt: skip
    retention_policy: Optional[AzureRetentionPolicyParameters] = field(default=None, metadata={'description': 'Parameters that define the retention policy for flow log.'})  # fmt: skip
    storage_id: Optional[str] = field(default=None, metadata={'description': 'ID of the storage account which is used to store the flow log.'})  # fmt: skip
    tags: Optional[Dict[str, str]] = field(default=None, metadata={"description": "Resource tags."})
    target_resource_guid: Optional[str] = field(default=None, metadata={'description': 'Guid of network security group to which flow log will be applied.'})  # fmt: skip
    target_resource_id: Optional[str] = field(default=None, metadata={'description': 'ID of network security group to which flow log will be applied.'})  # fmt: skip
    type: Optional[str] = field(default=None, metadata={"description": "Resource type."})


@define(eq=False, slots=False)
class AzureNetworkSecurityGroup(AzureResource):
    kind: ClassVar[str] = "azure_network_security_group"
    api_spec: ClassVar[AzureApiSpec] = AzureApiSpec(
        service="network",
        version="2023-05-01",
        path="/subscriptions/{subscriptionId}/providers/Microsoft.Network/networkSecurityGroups",
        path_parameters=["subscriptionId"],
        query_parameters=["api-version"],
        access_path="value",
        expect_array=True,
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "default_security_rules": S("properties", "defaultSecurityRules") >> ForallBend(AzureSecurityRule.mapping),
        "etag": S("etag"),
        "flow_logs": S("properties", "flowLogs") >> ForallBend(AzureFlowLog.mapping),
        "flush_connection": S("properties", "flushConnection"),
        "provisioning_state": S("properties", "provisioningState"),
        "resource_guid": S("properties", "resourceGuid"),
        "security_rules": S("properties", "securityRules") >> ForallBend(AzureSecurityRule.mapping),
    }
    default_security_rules: Optional[List[AzureSecurityRule]] = field(default=None, metadata={'description': 'The default security rules of network security group.'})  # fmt: skip
    etag: Optional[str] = field(default=None, metadata={'description': 'A unique read-only string that changes whenever the resource is updated.'})  # fmt: skip
    flow_logs: Optional[List[AzureFlowLog]] = field(default=None, metadata={'description': 'A collection of references to flow log resources.'})  # fmt: skip
    flush_connection: Optional[bool] = field(default=None, metadata={'description': 'When enabled, flows created from Network Security Group connections will be re-evaluated when rules are updates. Initial enablement will trigger re-evaluation.'})  # fmt: skip
    provisioning_state: Optional[str] = field(default=None, metadata={'description': 'The current provisioning state.'})  # fmt: skip
    resource_guid: Optional[str] = field(default=None, metadata={'description': 'The resource GUID property of the network security group resource.'})  # fmt: skip
    security_rules: Optional[List[AzureSecurityRule]] = field(default=None, metadata={'description': 'A collection of security rules of the network security group.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureNetworkInterfaceTapConfiguration(AzureSubResource):
    kind: ClassVar[str] = "azure_network_interface_tap_configuration"
    mapping: ClassVar[Dict[str, Bender]] = AzureSubResource.mapping | {
        "etag": S("etag"),
        "name": S("name"),
        "properties": S("properties", "provisioningState"),
        "type": S("type"),
    }
    etag: Optional[str] = field(default=None, metadata={'description': 'A unique read-only string that changes whenever the resource is updated.'})  # fmt: skip
    name: Optional[str] = field(default=None, metadata={'description': 'The name of the resource that is unique within a resource group. This name can be used to access the resource.'})  # fmt: skip
    properties: Optional[str] = field(default=None, metadata={'description': 'Properties of Virtual Network Tap configuration.'})  # fmt: skip
    type: Optional[str] = field(default=None, metadata={"description": "Sub Resource type."})


@define(eq=False, slots=False)
class AzureRoute(AzureSubResource):
    kind: ClassVar[str] = "azure_route"
    mapping: ClassVar[Dict[str, Bender]] = AzureSubResource.mapping | {
        "address_prefix": S("properties", "addressPrefix"),
        "etag": S("etag"),
        "has_bgp_override": S("properties", "hasBgpOverride"),
        "name": S("name"),
        "next_hop_ip_address": S("properties", "nextHopIpAddress"),
        "next_hop_type": S("properties", "nextHopType"),
        "provisioning_state": S("properties", "provisioningState"),
        "type": S("type"),
    }
    address_prefix: Optional[str] = field(default=None, metadata={'description': 'The destination CIDR to which the route applies.'})  # fmt: skip
    etag: Optional[str] = field(default=None, metadata={'description': 'A unique read-only string that changes whenever the resource is updated.'})  # fmt: skip
    has_bgp_override: Optional[bool] = field(default=None, metadata={'description': 'A value indicating whether this route overrides overlapping BGP routes regardless of LPM.'})  # fmt: skip
    name: Optional[str] = field(default=None, metadata={'description': 'The name of the resource that is unique within a resource group. This name can be used to access the resource.'})  # fmt: skip
    next_hop_ip_address: Optional[str] = field(default=None, metadata={'description': 'The IP address packets should be forwarded to. Next hop values are only allowed in routes where the next hop type is VirtualAppliance.'})  # fmt: skip
    next_hop_type: Optional[str] = field(default=None, metadata={'description': 'The type of Azure hop the packet should be sent to.'})  # fmt: skip
    provisioning_state: Optional[str] = field(default=None, metadata={'description': 'The current provisioning state.'})  # fmt: skip
    type: Optional[str] = field(default=None, metadata={"description": "The type of the resource."})


@define(eq=False, slots=False)
class AzureRouteTable:
    kind: ClassVar[str] = "azure_route_table"
    mapping: ClassVar[Dict[str, Bender]] = {
        "disable_bgp_route_propagation": S("properties", "disableBgpRoutePropagation"),
        "etag": S("etag"),
        "id": S("id"),
        "location": S("location"),
        "name": S("name"),
        "provisioning_state": S("properties", "provisioningState"),
        "resource_guid": S("properties", "resourceGuid"),
        "routes": S("properties", "routes") >> ForallBend(AzureRoute.mapping),
        "tags": S("tags", default={}),
        "type": S("type"),
    }
    disable_bgp_route_propagation: Optional[bool] = field(default=None, metadata={'description': 'Whether to disable the routes learned by BGP on that route table. True means disable.'})  # fmt: skip
    etag: Optional[str] = field(default=None, metadata={'description': 'A unique read-only string that changes whenever the resource is updated.'})  # fmt: skip
    id: Optional[str] = field(default=None, metadata={"description": "Resource ID."})
    location: Optional[str] = field(default=None, metadata={"description": "Resource location."})
    name: Optional[str] = field(default=None, metadata={"description": "Resource name."})
    provisioning_state: Optional[str] = field(default=None, metadata={'description': 'The current provisioning state.'})  # fmt: skip
    resource_guid: Optional[str] = field(default=None, metadata={'description': 'The resource GUID property of the route table.'})  # fmt: skip
    routes: Optional[List[AzureRoute]] = field(default=None, metadata={'description': 'Collection of routes contained within a route table.'})  # fmt: skip
    tags: Optional[Dict[str, str]] = field(default=None, metadata={"description": "Resource tags."})
    type: Optional[str] = field(default=None, metadata={"description": "Resource type."})


@define(eq=False, slots=False)
class AzureServiceEndpointPropertiesFormat:
    kind: ClassVar[str] = "azure_service_endpoint_properties_format"
    mapping: ClassVar[Dict[str, Bender]] = {
        "locations": S("locations"),
        "provisioning_state": S("provisioningState"),
        "service": S("service"),
    }
    locations: Optional[List[str]] = field(default=None, metadata={"description": "A list of locations."})
    provisioning_state: Optional[str] = field(default=None, metadata={'description': 'The current provisioning state.'})  # fmt: skip
    service: Optional[str] = field(default=None, metadata={"description": "The type of the endpoint service."})


@define(eq=False, slots=False)
class AzureServiceEndpointPolicyDefinition(AzureSubResource):
    kind: ClassVar[str] = "azure_service_endpoint_policy_definition"
    mapping: ClassVar[Dict[str, Bender]] = AzureSubResource.mapping | {
        "description": S("properties", "description"),
        "etag": S("etag"),
        "name": S("name"),
        "provisioning_state": S("properties", "provisioningState"),
        "service": S("properties", "service"),
        "service_resources": S("properties", "serviceResources"),
        "type": S("type"),
    }
    description: Optional[str] = field(default=None, metadata={'description': 'A description for this rule. Restricted to 140 chars.'})  # fmt: skip
    etag: Optional[str] = field(default=None, metadata={'description': 'A unique read-only string that changes whenever the resource is updated.'})  # fmt: skip
    name: Optional[str] = field(default=None, metadata={'description': 'The name of the resource that is unique within a resource group. This name can be used to access the resource.'})  # fmt: skip
    provisioning_state: Optional[str] = field(default=None, metadata={'description': 'The current provisioning state.'})  # fmt: skip
    service: Optional[str] = field(default=None, metadata={"description": "Service endpoint name."})
    service_resources: Optional[List[str]] = field(
        default=None, metadata={"description": "A list of service resources."}
    )
    type: Optional[str] = field(default=None, metadata={"description": "The type of the resource."})


@define(eq=False, slots=False)
class AzureServiceEndpointPolicy:
    kind: ClassVar[str] = "azure_service_endpoint_policy"
    mapping: ClassVar[Dict[str, Bender]] = {
        "contextual_service_endpoint_policies": S("properties", "contextualServiceEndpointPolicies"),
        "etag": S("etag"),
        "id": S("id"),
        "policy_kind": S("kind"),
        "location": S("location"),
        "name": S("name"),
        "provisioning_state": S("properties", "provisioningState"),
        "resource_guid": S("properties", "resourceGuid"),
        "service_alias": S("properties", "serviceAlias"),
        "service_endpoint_policy_definitions": S("properties", "serviceEndpointPolicyDefinitions")
        >> ForallBend(AzureServiceEndpointPolicyDefinition.mapping),
        "tags": S("tags", default={}),
        "type": S("type"),
    }
    contextual_service_endpoint_policies: Optional[List[str]] = field(default=None, metadata={'description': 'A collection of contextual service endpoint policy.'})  # fmt: skip
    etag: Optional[str] = field(default=None, metadata={'description': 'A unique read-only string that changes whenever the resource is updated.'})  # fmt: skip
    id: Optional[str] = field(default=None, metadata={"description": "Resource ID."})
    policy_kind: Optional[str] = field(default=None, metadata={'description': 'Kind of service endpoint policy. This is metadata used for the Azure portal experience.'})  # fmt: skip
    location: Optional[str] = field(default=None, metadata={"description": "Resource location."})
    name: Optional[str] = field(default=None, metadata={"description": "Resource name."})
    provisioning_state: Optional[str] = field(default=None, metadata={'description': 'The current provisioning state.'})  # fmt: skip
    resource_guid: Optional[str] = field(default=None, metadata={'description': 'The resource GUID property of the service endpoint policy resource.'})  # fmt: skip
    service_alias: Optional[str] = field(default=None, metadata={'description': 'The alias indicating if the policy belongs to a service'})  # fmt: skip
    service_endpoint_policy_definitions: Optional[List[AzureServiceEndpointPolicyDefinition]] = field(default=None, metadata={'description': 'A collection of service endpoint policy definitions of the service endpoint policy.'})  # fmt: skip
    tags: Optional[Dict[str, str]] = field(default=None, metadata={"description": "Resource tags."})
    type: Optional[str] = field(default=None, metadata={"description": "Resource type."})


@define(eq=False, slots=False)
class AzurePublicIPAddressDnsSettings:
    kind: ClassVar[str] = "azure_public_ip_address_dns_settings"
    mapping: ClassVar[Dict[str, Bender]] = {
        "domain_name_label": S("domainNameLabel"),
        "domain_name_label_scope": S("domainNameLabelScope"),
        "fqdn": S("fqdn"),
        "reverse_fqdn": S("reverseFqdn"),
    }
    domain_name_label: Optional[str] = field(default=None, metadata={'description': 'The domain name label. The concatenation of the domain name label and the regionalized DNS zone make up the fully qualified domain name associated with the public IP address. If a domain name label is specified, an A DNS record is created for the public IP in the Microsoft Azure DNS system.'})  # fmt: skip
    domain_name_label_scope: Optional[str] = field(default=None, metadata={'description': 'The domain name label scope. If a domain name label and a domain name label scope are specified, an A DNS record is created for the public IP in the Microsoft Azure DNS system with a hashed value includes in FQDN.'})  # fmt: skip
    fqdn: Optional[str] = field(default=None, metadata={'description': 'The Fully Qualified Domain Name of the A DNS record associated with the public IP. This is the concatenation of the domainNameLabel and the regionalized DNS zone.'})  # fmt: skip
    reverse_fqdn: Optional[str] = field(default=None, metadata={'description': 'The reverse FQDN. A user-visible, fully qualified domain name that resolves to this public IP address. If the reverseFqdn is specified, then a PTR DNS record is created pointing from the IP address in the in-addr.arpa domain to the reverse FQDN.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureDdosSettings:
    kind: ClassVar[str] = "azure_ddos_settings"
    mapping: ClassVar[Dict[str, Bender]] = {
        "ddos_protection_plan": S("ddosProtectionPlan", "id"),
        "protection_mode": S("protectionMode"),
    }
    ddos_protection_plan: Optional[str] = field(default=None, metadata={'description': 'Reference to another subresource.'})  # fmt: skip
    protection_mode: Optional[str] = field(default=None, metadata={'description': 'The DDoS protection mode of the public IP'})  # fmt: skip


@define(eq=False, slots=False)
class AzureIpTag:
    kind: ClassVar[str] = "azure_ip_tag"
    mapping: ClassVar[Dict[str, Bender]] = {"ip_tag_type": S("ipTagType"), "tag": S("tag")}
    ip_tag_type: Optional[str] = field(default=None, metadata={'description': 'The IP tag type. Example: FirstPartyUsage.'})  # fmt: skip
    tag: Optional[str] = field(default=None, metadata={'description': 'The value of the IP tag associated with the public IP. Example: SQL.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureNatGateway(AzureResource):
    kind: ClassVar[str] = "azure_nat_gateway"
    api_spec: ClassVar[AzureApiSpec] = AzureApiSpec(
        service="network",
        version="2023-05-01",
        path="/subscriptions/{subscriptionId}/providers/Microsoft.Network/natGateways",
        path_parameters=["subscriptionId"],
        query_parameters=["api-version"],
        access_path="value",
        expect_array=True,
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "etag": S("etag"),
        "idle_timeout_in_minutes": S("properties", "idleTimeoutInMinutes"),
        "location": S("location"),
        "provisioning_state": S("properties", "provisioningState"),
        "public_ip_addresses": S("properties") >> S("publicIpAddresses", default=[]) >> ForallBend(S("id")),
        "public_ip_prefixes": S("properties") >> S("publicIpPrefixes", default=[]) >> ForallBend(S("id")),
        "resource_guid": S("properties", "resourceGuid"),
        "sku": S("sku", "name"),
        "subnet_ids": S("properties") >> S("subnets", default=[]) >> ForallBend(S("id")),
        "type": S("type"),
        "zones": S("zones"),
    }
    etag: Optional[str] = field(default=None, metadata={'description': 'A unique read-only string that changes whenever the resource is updated.'})  # fmt: skip
    idle_timeout_in_minutes: Optional[int] = field(default=None, metadata={'description': 'The idle timeout of the nat gateway.'})  # fmt: skip
    location: Optional[str] = field(default=None, metadata={"description": "Resource location."})
    provisioning_state: Optional[str] = field(default=None, metadata={'description': 'The current provisioning state.'})  # fmt: skip
    public_ip_addresses: Optional[List[str]] = field(default=None, metadata={'description': 'An array of public ip addresses associated with the nat gateway resource.'})  # fmt: skip
    public_ip_prefixes: Optional[List[str]] = field(default=None, metadata={'description': 'An array of public ip prefixes associated with the nat gateway resource.'})  # fmt: skip
    resource_guid: Optional[str] = field(default=None, metadata={'description': 'The resource GUID property of the NAT gateway resource.'})  # fmt: skip
    sku: Optional[str] = field(default=None, metadata={"description": "SKU of nat gateway."})
    subnet_ids: Optional[List[str]] = field(default=None, metadata={'description': 'An array of references to the subnets using this nat gateway resource.'})  # fmt: skip
    type: Optional[str] = field(default=None, metadata={"description": "Resource type."})
    zones: Optional[List[str]] = field(default=None, metadata={'description': 'A list of availability zones denoting the zone in which Nat Gateway should be deployed.'})  # fmt: skip


@define(eq=False, slots=False)
class AzurePublicIPAddress(AzureResource):
    kind: ClassVar[str] = "azure_public_ip_address"
    api_spec: ClassVar[AzureApiSpec] = AzureApiSpec(
        service="network",
        version="2023-05-01",
        path="/subscriptions/{subscriptionId}/providers/Microsoft.Network/publicIPAddresses",
        path_parameters=["subscriptionId"],
        query_parameters=["api-version"],
        access_path="value",
        expect_array=True,
    )
    reference_kinds: ClassVar[ModelReference] = {
        "predecessors": {"default": ["azure_nat_gateway", "azure_public_ip_prefix"]},
    }
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "ddos_settings": S("properties", "ddosSettings") >> Bend(AzureDdosSettings.mapping),
        "delete_option": S("properties", "deleteOption"),
        "ip_dns_settings": S("properties", "dnsSettings") >> Bend(AzurePublicIPAddressDnsSettings.mapping),
        "etag": S("etag"),
        "extended_location": S("extendedLocation") >> Bend(AzureExtendedLocation.mapping),
        "idle_timeout_in_minutes": S("properties", "idleTimeoutInMinutes"),
        "ip_address": S("properties", "ipAddress"),
        "ip_tags": S("properties", "ipTags") >> ForallBend(AzureIpTag.mapping),
        "location": S("location"),
        "migration_phase": S("properties", "migrationPhase"),
        "_nat_gateway_id": S("properties", "natGateway", "id"),
        "provisioning_state": S("properties", "provisioningState"),
        "public_ip_address_version": S("properties", "publicIPAddressVersion"),
        "public_ip_allocation_method": S("properties", "publicIPAllocationMethod"),
        "public_ip_prefix": S("properties", "publicIPPrefix", "id"),
        "resource_guid": S("properties", "resourceGuid"),
        "azure_sku": S("sku") >> Bend(AzureSku.mapping),
        "type": S("type"),
        "zones": S("zones"),
    }
    ddos_settings: Optional[AzureDdosSettings] = field(default=None, metadata={'description': 'Contains the DDoS protection settings of the public IP.'})  # fmt: skip
    delete_option: Optional[str] = field(default=None, metadata={'description': 'Specify what happens to the public IP address when the VM using it is deleted'})  # fmt: skip
    ip_dns_settings: Optional[AzurePublicIPAddressDnsSettings] = field(default=None, metadata={'description': 'Contains FQDN of the DNS record associated with the public IP address.'})  # fmt: skip
    etag: Optional[str] = field(default=None, metadata={'description': 'A unique read-only string that changes whenever the resource is updated.'})  # fmt: skip
    extended_location: Optional[AzureExtendedLocation] = field(default=None, metadata={'description': 'ExtendedLocation complex type.'})  # fmt: skip
    idle_timeout_in_minutes: Optional[int] = field(default=None, metadata={'description': 'The idle timeout of the public IP address.'})  # fmt: skip
    ip_address: Optional[str] = field(default=None, metadata={'description': 'The IP address associated with the public IP address resource.'})  # fmt: skip
    ip_tags: Optional[List[AzureIpTag]] = field(default=None, metadata={'description': 'The list of tags associated with the public IP address.'})  # fmt: skip
    location: Optional[str] = field(default=None, metadata={"description": "Resource location."})
    migration_phase: Optional[str] = field(default=None, metadata={'description': 'Migration phase of Public IP Address.'})  # fmt: skip
    _nat_gateway_id: Optional[str] = field(default=None, metadata={"description": "Nat Gateway resource."})
    provisioning_state: Optional[str] = field(default=None, metadata={'description': 'The current provisioning state.'})  # fmt: skip
    public_ip_address_version: Optional[str] = field(default=None, metadata={"description": "IP address version."})
    public_ip_allocation_method: Optional[str] = field(default=None, metadata={'description': 'IP address allocation method.'})  # fmt: skip
    public_ip_prefix: Optional[str] = field(default=None, metadata={'description': 'Reference to another subresource.'})  # fmt: skip
    resource_guid: Optional[str] = field(default=None, metadata={'description': 'The resource GUID property of the public IP address resource.'})  # fmt: skip
    azure_sku: Optional[AzureSku] = field(default=None, metadata={'description': 'SKU of a public IP address.'})  # fmt: skip
    type: Optional[str] = field(default=None, metadata={"description": "Resource type."})
    zones: Optional[List[str]] = field(default=None, metadata={'description': 'A list of availability zones denoting the IP allocated for the resource needs to come from.'})  # fmt: skip

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if p_ip_prefix_id := self.public_ip_prefix:
            builder.add_edge(
                self, edge_type=EdgeType.default, reverse=True, clazz=AzurePublicIPPrefix, id=p_ip_prefix_id
            )
        if nat_gateway_id := self._nat_gateway_id:
            builder.add_edge(self, edge_type=EdgeType.default, reverse=True, clazz=AzureNatGateway, id=nat_gateway_id)


@define(eq=False, slots=False)
class AzureIPConfiguration(AzureSubResource):
    kind: ClassVar[str] = "azure_ip_configuration"
    mapping: ClassVar[Dict[str, Bender]] = AzureSubResource.mapping | {
        "etag": S("etag"),
        "name": S("name"),
        "private_ip_address": S("properties", "privateIPAddress"),
        "private_ip_allocation_method": S("properties", "privateIPAllocationMethod"),
        "provisioning_state": S("properties", "provisioningState"),
        "_public_ip_address_id": S("properties", "publicIPAddress", "id"),
    }
    etag: Optional[str] = field(default=None, metadata={'description': 'A unique read-only string that changes whenever the resource is updated.'})  # fmt: skip
    name: Optional[str] = field(default=None, metadata={'description': 'The name of the resource that is unique within a resource group. This name can be used to access the resource.'})  # fmt: skip
    private_ip_address: Optional[str] = field(default=None, metadata={'description': 'The private IP address of the IP configuration.'})  # fmt: skip
    private_ip_allocation_method: Optional[str] = field(default=None, metadata={'description': 'IP address allocation method.'})  # fmt: skip
    provisioning_state: Optional[str] = field(default=None, metadata={'description': 'The current provisioning state.'})  # fmt: skip
    _public_ip_address_id: Optional[str] = field(default=None, metadata={'description': 'Public IP address resource.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureIPConfigurationProfile(AzureSubResource):
    kind: ClassVar[str] = "azure_ip_configuration_profile"
    mapping: ClassVar[Dict[str, Bender]] = AzureSubResource.mapping | {
        "etag": S("etag"),
        "name": S("name"),
        "properties": S("properties", "provisioningState"),
        "type": S("type"),
        "_subnet_id": S("properties", "subnet", "id"),
    }
    etag: Optional[str] = field(default=None, metadata={'description': 'A unique read-only string that changes whenever the resource is updated.'})  # fmt: skip
    name: Optional[str] = field(default=None, metadata={'description': 'The name of the resource. This name can be used to access the resource.'})  # fmt: skip
    properties: Optional[str] = field(default=None, metadata={"description": "IP configuration profile properties."})
    type: Optional[str] = field(default=None, metadata={"description": "Sub Resource type."})
    _subnet_id: Optional[str] = field(
        default=None,
        metadata={
            "description": "The reference to the subnet resource to create a container network interface ip configuration."
        },
    )


@define(eq=False, slots=False)
class AzureResourceNavigationLink(AzureSubResource):
    kind: ClassVar[str] = "azure_resource_navigation_link"
    mapping: ClassVar[Dict[str, Bender]] = AzureSubResource.mapping | {
        "etag": S("etag"),
        "id": S("id"),
        "link": S("properties", "link"),
        "linked_resource_type": S("properties", "linkedResourceType"),
        "name": S("name"),
        "provisioning_state": S("properties", "provisioningState"),
        "type": S("type"),
    }
    etag: Optional[str] = field(default=None, metadata={'description': 'A unique read-only string that changes whenever the resource is updated.'})  # fmt: skip
    id: Optional[str] = field(default=None, metadata={"description": "Resource navigation link identifier."})
    link: Optional[str] = field(default=None, metadata={"description": "Link to the external resource."})
    linked_resource_type: Optional[str] = field(default=None, metadata={'description': 'Resource type of the linked resource.'})  # fmt: skip
    name: Optional[str] = field(default=None, metadata={'description': 'Name of the resource that is unique within a resource group. This name can be used to access the resource.'})  # fmt: skip
    provisioning_state: Optional[str] = field(default=None, metadata={'description': 'The current provisioning state.'})  # fmt: skip
    type: Optional[str] = field(default=None, metadata={"description": "Resource type."})


@define(eq=False, slots=False)
class AzureServiceAssociationLink(AzureSubResource):
    kind: ClassVar[str] = "azure_service_association_link"
    mapping: ClassVar[Dict[str, Bender]] = AzureSubResource.mapping | {
        "allow_delete": S("properties", "allowDelete"),
        "etag": S("etag"),
        "link": S("properties", "link"),
        "linked_resource_type": S("properties", "linkedResourceType"),
        "locations": S("properties", "locations"),
        "name": S("name"),
        "provisioning_state": S("properties", "provisioningState"),
        "type": S("type"),
    }
    allow_delete: Optional[bool] = field(default=None, metadata={'description': 'If true, the resource can be deleted.'})  # fmt: skip
    etag: Optional[str] = field(default=None, metadata={'description': 'A unique read-only string that changes whenever the resource is updated.'})  # fmt: skip
    link: Optional[str] = field(default=None, metadata={"description": "Link to the external resource."})
    linked_resource_type: Optional[str] = field(default=None, metadata={'description': 'Resource type of the linked resource.'})  # fmt: skip
    locations: Optional[List[str]] = field(default=None, metadata={"description": "A list of locations."})
    name: Optional[str] = field(default=None, metadata={'description': 'Name of the resource that is unique within a resource group. This name can be used to access the resource.'})  # fmt: skip
    provisioning_state: Optional[str] = field(default=None, metadata={'description': 'The current provisioning state.'})  # fmt: skip
    type: Optional[str] = field(default=None, metadata={"description": "Resource type."})


@define(eq=False, slots=False)
class AzureDelegation(AzureSubResource):
    kind: ClassVar[str] = "azure_delegation"
    mapping: ClassVar[Dict[str, Bender]] = AzureSubResource.mapping | {
        "actions": S("properties", "actions"),
        "etag": S("etag"),
        "name": S("name"),
        "provisioning_state": S("properties", "provisioningState"),
        "service_name": S("properties", "serviceName"),
        "type": S("type"),
    }
    actions: Optional[List[str]] = field(default=None, metadata={'description': 'The actions permitted to the service upon delegation.'})  # fmt: skip
    etag: Optional[str] = field(default=None, metadata={'description': 'A unique read-only string that changes whenever the resource is updated.'})  # fmt: skip
    name: Optional[str] = field(default=None, metadata={'description': 'The name of the resource that is unique within a subnet. This name can be used to access the resource.'})  # fmt: skip
    provisioning_state: Optional[str] = field(default=None, metadata={'description': 'The current provisioning state.'})  # fmt: skip
    service_name: Optional[str] = field(default=None, metadata={'description': 'The name of the service to whom the subnet should be delegated (e.g. Microsoft.Sql/servers).'})  # fmt: skip
    type: Optional[str] = field(default=None, metadata={"description": "Resource type."})


@define(eq=False, slots=False)
class AzureSubnet(AzureResource):
    kind: ClassVar[str] = "azure_subnet"
    reference_kinds: ClassVar[ModelReference] = {
        "successors": {
            "default": [
                "azure_nat_gateway",
                "azure_network_security_group",
            ]
        },
    }
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "address_prefix": S("properties", "addressPrefix"),
        "address_prefixes": S("properties", "addressPrefixes"),
        "application_gateway_ip_configurations": S("properties", "applicationGatewayIPConfigurations")
        >> ForallBend(AzureApplicationGatewayIPConfiguration.mapping),
        "default_outbound_access": S("properties", "defaultOutboundAccess"),
        "delegations": S("properties", "delegations") >> ForallBend(AzureDelegation.mapping),
        "etag": S("etag"),
        "ip_allocations": S("properties") >> S("ipAllocations", default=[]) >> ForallBend(S("id")),
        "ip_configuration_profiles": S("properties", "ipConfigurationProfiles")
        >> ForallBend(AzureIPConfigurationProfile.mapping),
        "_ip_configuration_ids": S("properties", "ipConfigurations", default=[]) >> ForallBend(S("id")),
        "_nat_gateway_id": S("properties", "natGateway", "id"),
        "_network_security_group_id": S("properties", "networkSecurityGroup", "id"),
        "private_endpoint_network_policies": S("properties", "privateEndpointNetworkPolicies"),
        "private_endpoints": S("properties", "privateEndpoints") >> ForallBend(AzurePrivateEndpoint.mapping),
        "private_link_service_network_policies": S("properties", "privateLinkServiceNetworkPolicies"),
        "provisioning_state": S("properties", "provisioningState"),
        "purpose": S("properties", "purpose"),
        "resource_navigation_links": S("properties", "resourceNavigationLinks")
        >> ForallBend(AzureResourceNavigationLink.mapping),
        "route_table": S("properties", "routeTable") >> Bend(AzureRouteTable.mapping),
        "service_association_links": S("properties", "serviceAssociationLinks")
        >> ForallBend(AzureServiceAssociationLink.mapping),
        "service_endpoint_policies": S("properties", "serviceEndpointPolicies")
        >> ForallBend(AzureServiceEndpointPolicy.mapping),
        "service_endpoints": S("properties", "serviceEndpoints")
        >> ForallBend(AzureServiceEndpointPropertiesFormat.mapping),
        "type": S("type"),
    }
    address_prefix: Optional[str] = field(default=None, metadata={"description": "The address prefix for the subnet."})
    address_prefixes: Optional[List[str]] = field(default=None, metadata={'description': 'List of address prefixes for the subnet.'})  # fmt: skip
    application_gateway_ip_configurations: Optional[List[AzureApplicationGatewayIPConfiguration]] = field(default=None, metadata={'description': 'Application gateway IP configurations of virtual network resource.'})  # fmt: skip
    default_outbound_access: Optional[bool] = field(default=None, metadata={'description': 'Set this property to false to disable default outbound connectivity for all VMs in the subnet. This property can only be set at the time of subnet creation and cannot be updated for an existing subnet.'})  # fmt: skip
    delegations: Optional[List[AzureDelegation]] = field(default=None, metadata={'description': 'An array of references to the delegations on the subnet.'})  # fmt: skip
    etag: Optional[str] = field(default=None, metadata={'description': 'A unique read-only string that changes whenever the resource is updated.'})  # fmt: skip
    ip_allocations: Optional[List[str]] = field(default=None, metadata={'description': 'Array of IpAllocation which reference this subnet.'})  # fmt: skip
    ip_configuration_profiles: Optional[List[AzureIPConfigurationProfile]] = field(default=None, metadata={'description': 'Array of IP configuration profiles which reference this subnet.'})  # fmt: skip
    _ip_configuration_ids: Optional[List[str]] = field(default=None, metadata={'description': 'An array of references to the network interface IP configurations using subnet.'})  # fmt: skip
    name: Optional[str] = field(default=None, metadata={'description': 'The name of the resource that is unique within a resource group. This name can be used to access the resource.'})  # fmt: skip
    _nat_gateway_id: Optional[str] = field(default=None, metadata={"description": "Reference to another subresource."})
    _network_security_group_id: Optional[str] = field(default=None, metadata={'description': 'NetworkSecurityGroup resource.'})  # fmt: skip
    private_endpoint_network_policies: Optional[str] = field(default=None, metadata={'description': 'Enable or Disable apply network policies on private end point in the subnet.'})  # fmt: skip
    private_endpoints: Optional[List[AzurePrivateEndpoint]] = field(default=None, metadata={'description': 'An array of references to private endpoints.'})  # fmt: skip
    private_link_service_network_policies: Optional[str] = field(default=None, metadata={'description': 'Enable or Disable apply network policies on private link service in the subnet.'})  # fmt: skip
    provisioning_state: Optional[str] = field(default=None, metadata={'description': 'The current provisioning state.'})  # fmt: skip
    purpose: Optional[str] = field(default=None, metadata={'description': 'A read-only string identifying the intention of use for this subnet based on delegations and other user-defined properties.'})  # fmt: skip
    resource_navigation_links: Optional[List[AzureResourceNavigationLink]] = field(default=None, metadata={'description': 'An array of references to the external resources using subnet.'})  # fmt: skip
    route_table: Optional[AzureRouteTable] = field(default=None, metadata={"description": "Route table resource."})
    service_association_links: Optional[List[AzureServiceAssociationLink]] = field(default=None, metadata={'description': 'An array of references to services injecting into this subnet.'})  # fmt: skip
    service_endpoint_policies: Optional[List[AzureServiceEndpointPolicy]] = field(default=None, metadata={'description': 'An array of service endpoint policies.'})  # fmt: skip
    service_endpoints: Optional[List[AzureServiceEndpointPropertiesFormat]] = field(default=None, metadata={'description': 'An array of service endpoints.'})  # fmt: skip
    type: Optional[str] = field(default=None, metadata={"description": "Resource type."})

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if nat_gateway_id := self._nat_gateway_id:
            builder.add_edge(self, edge_type=EdgeType.default, clazz=AzureNatGateway, id=nat_gateway_id)
        if nsg_id := self._network_security_group_id:
            builder.add_edge(self, edge_type=EdgeType.default, clazz=AzureNetworkSecurityGroup, id=nsg_id)


@define(eq=False, slots=False)
class AzureFrontendIPConfiguration(AzureSubResource):
    kind: ClassVar[str] = "azure_frontend_ip_configuration"
    mapping: ClassVar[Dict[str, Bender]] = AzureSubResource.mapping | {
        "etag": S("etag"),
        "gateway_load_balancer": S("properties", "gatewayLoadBalancer", "id"),
        "inbound_nat_pools": S("properties") >> S("inboundNatPools", default=[]) >> ForallBend(S("id")),
        "inbound_nat_rules": S("properties") >> S("inboundNatRules", default=[]) >> ForallBend(S("id")),
        "load_balancing_rules": S("properties") >> S("loadBalancingRules", default=[]) >> ForallBend(S("id")),
        "name": S("name"),
        "outbound_rules": S("properties") >> S("outboundRules", default=[]) >> ForallBend(S("id")),
        "private_ip_address": S("properties", "privateIPAddress"),
        "private_ip_address_version": S("properties", "privateIPAddressVersion"),
        "private_ip_allocation_method": S("properties", "privateIPAllocationMethod"),
        "provisioning_state": S("properties", "provisioningState"),
        "_public_ip_address_id": S("properties", "publicIPAddress", "id"),
        "public_ip_prefix": S("properties", "publicIPPrefix", "id"),
        "_subnet_id": S("properties", "subnet", "id"),
        "type": S("type"),
        "zones": S("zones"),
    }
    etag: Optional[str] = field(default=None, metadata={'description': 'A unique read-only string that changes whenever the resource is updated.'})  # fmt: skip
    gateway_load_balancer: Optional[str] = field(default=None, metadata={'description': 'Reference to another subresource.'})  # fmt: skip
    inbound_nat_pools: Optional[List[str]] = field(default=None, metadata={'description': 'An array of references to inbound pools that use this frontend IP.'})  # fmt: skip
    inbound_nat_rules: Optional[List[str]] = field(default=None, metadata={'description': 'An array of references to inbound rules that use this frontend IP.'})  # fmt: skip
    load_balancing_rules: Optional[List[str]] = field(default=None, metadata={'description': 'An array of references to load balancing rules that use this frontend IP.'})  # fmt: skip
    name: Optional[str] = field(default=None, metadata={'description': 'The name of the resource that is unique within the set of frontend IP configurations used by the load balancer. This name can be used to access the resource.'})  # fmt: skip
    outbound_rules: Optional[List[str]] = field(default=None, metadata={'description': 'An array of references to outbound rules that use this frontend IP.'})  # fmt: skip
    private_ip_address: Optional[str] = field(default=None, metadata={'description': 'The private IP address of the IP configuration.'})  # fmt: skip
    private_ip_address_version: Optional[str] = field(default=None, metadata={"description": "IP address version."})
    private_ip_allocation_method: Optional[str] = field(default=None, metadata={'description': 'IP address allocation method.'})  # fmt: skip
    provisioning_state: Optional[str] = field(default=None, metadata={'description': 'The current provisioning state.'})  # fmt: skip
    _public_ip_address_id: Optional[str] = field(default=None, metadata={'description': 'Public IP address resource.'})  # fmt: skip
    public_ip_prefix: Optional[str] = field(default=None, metadata={'description': 'Reference to another subresource.'})  # fmt: skip
    _subnet_id: Optional[str] = field(default=None, metadata={'description': 'Subnet in a virtual network resource.'})  # fmt: skip
    type: Optional[str] = field(default=None, metadata={"description": "Type of the resource."})
    zones: Optional[List[str]] = field(default=None, metadata={'description': 'A list of availability zones denoting the IP allocated for the resource needs to come from.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureVirtualNetworkTap(AzureResource):
    kind: ClassVar[str] = "azure_virtual_network_tap"
    api_spec: ClassVar[AzureApiSpec] = AzureApiSpec(
        service="network",
        version="2023-05-01",
        path="/subscriptions/{subscriptionId}/providers/Microsoft.Network/virtualNetworkTaps",
        path_parameters=["subscriptionId"],
        query_parameters=["api-version"],
        access_path="value",
        expect_array=True,
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "destination_load_balancer_front_end_ip_configuration": S(
            "properties", "destinationLoadBalancerFrontEndIPConfiguration"
        )
        >> Bend(AzureFrontendIPConfiguration.mapping),
        "destination_port": S("properties", "destinationPort"),
        "etag": S("etag"),
        "location": S("location"),
        "network_interface_tap_configurations": S("properties", "networkInterfaceTapConfigurations")
        >> ForallBend(AzureNetworkInterfaceTapConfiguration.mapping),
        "provisioning_state": S("properties", "provisioningState"),
        "resource_guid": S("properties", "resourceGuid"),
        "type": S("type"),
    }
    destination_load_balancer_front_end_ip_configuration: Optional[AzureFrontendIPConfiguration] = field(default=None, metadata={'description': 'Frontend IP address of the load balancer.'})  # fmt: skip
    destination_port: Optional[int] = field(default=None, metadata={'description': 'The VXLAN destination port that will receive the tapped traffic.'})  # fmt: skip
    etag: Optional[str] = field(default=None, metadata={'description': 'A unique read-only string that changes whenever the resource is updated.'})  # fmt: skip
    location: Optional[str] = field(default=None, metadata={"description": "Resource location."})
    network_interface_tap_configurations: Optional[List[AzureNetworkInterfaceTapConfiguration]] = field(default=None, metadata={'description': 'Specifies the list of resource IDs for the network interface IP configuration that needs to be tapped.'})  # fmt: skip
    provisioning_state: Optional[str] = field(default=None, metadata={'description': 'The current provisioning state.'})  # fmt: skip
    resource_guid: Optional[str] = field(default=None, metadata={'description': 'The resource GUID property of the virtual network tap resource.'})  # fmt: skip
    type: Optional[str] = field(default=None, metadata={"description": "Resource type."})


@define(eq=False, slots=False)
class AzureInboundNatRule(AzureSubResource):
    kind: ClassVar[str] = "azure_inbound_nat_rule"
    mapping: ClassVar[Dict[str, Bender]] = AzureSubResource.mapping | {
        "backend_address_pool": S("properties", "backendAddressPool", "id"),
        "backend_port": S("properties", "backendPort"),
        "enable_floating_ip": S("properties", "enableFloatingIP"),
        "enable_tcp_reset": S("properties", "enableTcpReset"),
        "etag": S("etag"),
        "frontend_ip_configuration": S("properties", "frontendIPConfiguration", "id"),
        "frontend_port": S("properties", "frontendPort"),
        "frontend_port_range_end": S("properties", "frontendPortRangeEnd"),
        "frontend_port_range_start": S("properties", "frontendPortRangeStart"),
        "idle_timeout_in_minutes": S("properties", "idleTimeoutInMinutes"),
        "name": S("name"),
        "protocol": S("properties", "protocol"),
        "provisioning_state": S("properties", "provisioningState"),
        "type": S("type"),
    }
    backend_address_pool: Optional[str] = field(default=None, metadata={'description': 'Reference to another subresource.'})  # fmt: skip
    backend_port: Optional[int] = field(default=None, metadata={'description': 'The port used for the internal endpoint. Acceptable values range from 1 to 65535.'})  # fmt: skip
    enable_floating_ip: Optional[bool] = field(default=None, metadata={'description': 'Configures a virtual machine s endpoint for the floating IP capability required to configure a SQL AlwaysOn Availability Group. This setting is required when using the SQL AlwaysOn Availability Groups in SQL server. This setting can t be changed after you create the endpoint.'})  # fmt: skip
    enable_tcp_reset: Optional[bool] = field(default=None, metadata={'description': 'Receive bidirectional TCP Reset on TCP flow idle timeout or unexpected connection termination. This element is only used when the protocol is set to TCP.'})  # fmt: skip
    etag: Optional[str] = field(default=None, metadata={'description': 'A unique read-only string that changes whenever the resource is updated.'})  # fmt: skip
    frontend_ip_configuration: Optional[str] = field(default=None, metadata={'description': 'Reference to another subresource.'})  # fmt: skip
    frontend_port: Optional[int] = field(default=None, metadata={'description': 'The port for the external endpoint. Port numbers for each rule must be unique within the Load Balancer. Acceptable values range from 1 to 65534.'})  # fmt: skip
    frontend_port_range_end: Optional[int] = field(default=None, metadata={'description': 'The port range end for the external endpoint. This property is used together with BackendAddressPool and FrontendPortRangeStart. Individual inbound NAT rule port mappings will be created for each backend address from BackendAddressPool. Acceptable values range from 1 to 65534.'})  # fmt: skip
    frontend_port_range_start: Optional[int] = field(default=None, metadata={'description': 'The port range start for the external endpoint. This property is used together with BackendAddressPool and FrontendPortRangeEnd. Individual inbound NAT rule port mappings will be created for each backend address from BackendAddressPool. Acceptable values range from 1 to 65534.'})  # fmt: skip
    idle_timeout_in_minutes: Optional[int] = field(default=None, metadata={'description': 'The timeout for the TCP idle connection. The value can be set between 4 and 30 minutes. The default value is 4 minutes. This element is only used when the protocol is set to TCP.'})  # fmt: skip
    name: Optional[str] = field(default=None, metadata={'description': 'The name of the resource that is unique within the set of inbound NAT rules used by the load balancer. This name can be used to access the resource.'})  # fmt: skip
    protocol: Optional[str] = field(default=None, metadata={"description": "The transport protocol for the endpoint."})
    provisioning_state: Optional[str] = field(default=None, metadata={'description': 'The current provisioning state.'})  # fmt: skip
    type: Optional[str] = field(default=None, metadata={"description": "Type of the resource."})


@define(eq=False, slots=False)
class AzureNetworkInterfaceIPConfigurationPrivateLinkConnectionProperties:
    kind: ClassVar[str] = "azure_network_interface_ip_configuration_private_link_connection_properties"
    mapping: ClassVar[Dict[str, Bender]] = {
        "fqdns": S("fqdns"),
        "group_id": S("groupId"),
        "required_member_name": S("requiredMemberName"),
    }
    fqdns: Optional[List[str]] = field(default=None, metadata={'description': 'List of FQDNs for current private link connection.'})  # fmt: skip
    group_id: Optional[str] = field(default=None, metadata={'description': 'The group ID for current private link connection.'})  # fmt: skip
    required_member_name: Optional[str] = field(default=None, metadata={'description': 'The required member name for current private link connection.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureNetworkInterfaceIPConfiguration(AzureSubResource):
    kind: ClassVar[str] = "azure_network_interface_ip_configuration"
    mapping: ClassVar[Dict[str, Bender]] = AzureSubResource.mapping | {
        "application_gateway_backend_address_pools": S("properties", "applicationGatewayBackendAddressPools")
        >> ForallBend(AzureApplicationGatewayBackendAddressPool.mapping),
        "application_security_groups": S("properties", "applicationSecurityGroups")
        >> ForallBend(AzureApplicationSecurityGroup.mapping),
        "etag": S("etag"),
        "gateway_load_balancer": S("properties", "gatewayLoadBalancer", "id"),
        "load_balancer_inbound_nat_rules": S("properties", "loadBalancerInboundNatRules")
        >> ForallBend(AzureInboundNatRule.mapping),
        "name": S("name"),
        "primary": S("properties", "primary"),
        "private_ip_address": S("properties", "privateIPAddress"),
        "private_ip_address_version": S("properties", "privateIPAddressVersion"),
        "private_ip_allocation_method": S("properties", "privateIPAllocationMethod"),
        "private_link_connection_properties": S("properties", "privateLinkConnectionProperties")
        >> Bend(AzureNetworkInterfaceIPConfigurationPrivateLinkConnectionProperties.mapping),
        "provisioning_state": S("properties", "provisioningState"),
        "_public_ip_id": S("properties", "publicIPAddress", "id"),
        "type": S("type"),
        "_virtual_network_tap_ids": S("properties", "virtualNetworkTaps", default=[]) >> ForallBend(S("id")),
        "_subnet_id": S("properties", "subnet", "id"),
    }
    application_gateway_backend_address_pools: Optional[List[AzureApplicationGatewayBackendAddressPool]] = field(default=None, metadata={'description': 'The reference to ApplicationGatewayBackendAddressPool resource.'})  # fmt: skip
    application_security_groups: Optional[List[AzureApplicationSecurityGroup]] = field(default=None, metadata={'description': 'Application security groups in which the IP configuration is included.'})  # fmt: skip
    etag: Optional[str] = field(default=None, metadata={'description': 'A unique read-only string that changes whenever the resource is updated.'})  # fmt: skip
    gateway_load_balancer: Optional[str] = field(default=None, metadata={'description': 'Reference to another subresource.'})  # fmt: skip
    load_balancer_inbound_nat_rules: Optional[List[AzureInboundNatRule]] = field(default=None, metadata={'description': 'A list of references of LoadBalancerInboundNatRules.'})  # fmt: skip
    name: Optional[str] = field(default=None, metadata={'description': 'The name of the resource that is unique within a resource group. This name can be used to access the resource.'})  # fmt: skip
    primary: Optional[bool] = field(default=None, metadata={'description': 'Whether this is a primary customer address on the network interface.'})  # fmt: skip
    private_ip_address: Optional[str] = field(default=None, metadata={'description': 'Private IP address of the IP configuration.'})  # fmt: skip
    private_ip_address_version: Optional[str] = field(default=None, metadata={"description": "IP address version."})
    private_ip_allocation_method: Optional[str] = field(default=None, metadata={'description': 'IP address allocation method.'})  # fmt: skip
    private_link_connection_properties: Optional[AzureNetworkInterfaceIPConfigurationPrivateLinkConnectionProperties] = field(default=None, metadata={'description': 'PrivateLinkConnection properties for the network interface.'})  # fmt: skip
    provisioning_state: Optional[str] = field(default=None, metadata={'description': 'The current provisioning state.'})  # fmt: skip
    _public_ip_id: Optional[str] = field(default=None, metadata={'description': 'Public IP address resource.'})  # fmt: skip
    type: Optional[str] = field(default=None, metadata={"description": "Resource type."})
    _virtual_network_tap_ids: Optional[List[str]] = field(default=None, metadata={'description': 'The reference to Virtual Network Taps.'})  # fmt: skip
    _subnet_id: Optional[str] = field(default=None, metadata={'description': 'Subnet in a virtual network resource.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureNetworkInterfaceDnsSettings:
    kind: ClassVar[str] = "azure_network_interface_dns_settings"
    mapping: ClassVar[Dict[str, Bender]] = {
        "applied_dns_servers": S("appliedDnsServers"),
        "dns_servers": S("dnsServers"),
        "internal_dns_name_label": S("internalDnsNameLabel"),
        "internal_domain_name_suffix": S("internalDomainNameSuffix"),
        "internal_fqdn": S("internalFqdn"),
    }
    applied_dns_servers: Optional[List[str]] = field(default=None, metadata={'description': 'If the VM that uses this NIC is part of an Availability Set, then this list will have the union of all DNS servers from all NICs that are part of the Availability Set. This property is what is configured on each of those VMs.'})  # fmt: skip
    dns_servers: Optional[List[str]] = field(default=None, metadata={'description': 'List of DNS servers IP addresses. Use AzureProvidedDNS to switch to azure provided DNS resolution. AzureProvidedDNS value cannot be combined with other IPs, it must be the only value in dnsServers collection.'})  # fmt: skip
    internal_dns_name_label: Optional[str] = field(default=None, metadata={'description': 'Relative DNS name for this NIC used for internal communications between VMs in the same virtual network.'})  # fmt: skip
    internal_domain_name_suffix: Optional[str] = field(default=None, metadata={'description': 'Even if internalDnsNameLabel is not specified, a DNS entry is created for the primary NIC of the VM. This DNS name can be constructed by concatenating the VM name with the value of internalDomainNameSuffix.'})  # fmt: skip
    internal_fqdn: Optional[str] = field(default=None, metadata={'description': 'Fully qualified DNS name supporting internal communications between VMs in the same virtual network.'})  # fmt: skip


@define(eq=False, slots=False)
class AzurePrivateLinkServiceIpConfiguration(AzureSubResource):
    kind: ClassVar[str] = "azure_private_link_service_ip_configuration"
    mapping: ClassVar[Dict[str, Bender]] = AzureSubResource.mapping | {
        "etag": S("etag"),
        "name": S("name"),
        "primary": S("properties", "primary"),
        "private_ip_address": S("properties", "privateIPAddress"),
        "private_ip_address_version": S("properties", "privateIPAddressVersion"),
        "private_ip_allocation_method": S("properties", "privateIPAllocationMethod"),
        "provisioning_state": S("properties", "provisioningState"),
        "_subnet_id": S("properties", "subnet", "id"),
        "type": S("type"),
    }
    etag: Optional[str] = field(default=None, metadata={'description': 'A unique read-only string that changes whenever the resource is updated.'})  # fmt: skip
    name: Optional[str] = field(default=None, metadata={'description': 'The name of private link service ip configuration.'})  # fmt: skip
    primary: Optional[bool] = field(default=None, metadata={'description': 'Whether the ip configuration is primary or not.'})  # fmt: skip
    private_ip_address: Optional[str] = field(default=None, metadata={'description': 'The private IP address of the IP configuration.'})  # fmt: skip
    private_ip_address_version: Optional[str] = field(default=None, metadata={"description": "IP address version."})
    private_ip_allocation_method: Optional[str] = field(default=None, metadata={'description': 'IP address allocation method.'})  # fmt: skip
    provisioning_state: Optional[str] = field(default=None, metadata={'description': 'The current provisioning state.'})  # fmt: skip
    _subnet_id: Optional[str] = field(default=None, metadata={'description': 'Subnet in a virtual network resource.'})  # fmt: skip
    type: Optional[str] = field(default=None, metadata={"description": "The resource type."})


@define(eq=False, slots=False)
class AzureLinkServicePrivateEndpointConnection(AzureSubResource):
    kind: ClassVar[str] = "azure_link_service_private_endpoint_connection"
    mapping: ClassVar[Dict[str, Bender]] = AzureSubResource.mapping | {
        "etag": S("etag"),
        "link_identifier": S("properties", "linkIdentifier"),
        "name": S("name"),
        "private_endpoint": S("properties", "privateEndpoint") >> Bend(AzurePrivateEndpoint.mapping),
        "private_endpoint_location": S("properties", "privateEndpointLocation"),
        "private_link_service_connection_state": S("properties", "privateLinkServiceConnectionState")
        >> Bend(AzurePrivateLinkServiceConnectionState.mapping),
        "provisioning_state": S("properties", "provisioningState"),
        "type": S("type"),
    }
    etag: Optional[str] = field(default=None, metadata={'description': 'A unique read-only string that changes whenever the resource is updated.'})  # fmt: skip
    link_identifier: Optional[str] = field(default=None, metadata={"description": "The consumer link id."})
    name: Optional[str] = field(default=None, metadata={'description': 'The name of the resource that is unique within a resource group. This name can be used to access the resource.'})  # fmt: skip
    private_endpoint: Optional[AzurePrivateEndpoint] = field(default=None, metadata={'description': 'Private endpoint resource.'})  # fmt: skip
    private_endpoint_location: Optional[str] = field(default=None, metadata={'description': 'The location of the private endpoint.'})  # fmt: skip
    private_link_service_connection_state: Optional[AzurePrivateLinkServiceConnectionState] = field(default=None, metadata={'description': 'A collection of information about the state of the connection between service consumer and provider.'})  # fmt: skip
    provisioning_state: Optional[str] = field(default=None, metadata={'description': 'The current provisioning state.'})  # fmt: skip
    type: Optional[str] = field(default=None, metadata={"description": "The resource type."})


@define(eq=False, slots=False)
class AzureResourceSet:
    kind: ClassVar[str] = "azure_resource_set"
    mapping: ClassVar[Dict[str, Bender]] = {"subscriptions": S("subscriptions")}
    subscriptions: Optional[List[str]] = field(default=None, metadata={"description": "The list of subscriptions."})


@define(eq=False, slots=False)
class AzurePrivateLinkService(AzureResource):
    kind: ClassVar[str] = "azure_private_link_service"
    api_spec: ClassVar[AzureApiSpec] = AzureApiSpec(
        service="network",
        version="2023-05-01",
        path="/subscriptions/{subscriptionId}/providers/Microsoft.Network/privateLinkServices",
        path_parameters=["subscriptionId"],
        query_parameters=["api-version"],
        access_path="value",
        expect_array=True,
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "alias": S("properties", "alias"),
        "auto_approval": S("properties", "autoApproval") >> Bend(AzureResourceSet.mapping),
        "enable_proxy_protocol": S("properties", "enableProxyProtocol"),
        "etag": S("etag"),
        "extended_location": S("extendedLocation") >> Bend(AzureExtendedLocation.mapping),
        "fqdns": S("properties", "fqdns"),
        "link_service_ip_configurations": S("properties", "ipConfigurations")
        >> ForallBend(AzurePrivateLinkServiceIpConfiguration.mapping),
        "_load_balancer_frontend_ip_configuration_ids": S(
            "properties", "loadBalancerFrontendIpConfigurations", default=[]
        )
        >> ForallBend(S("id")),
        "location": S("location"),
        "link_service_private_endpoint_connections": S("properties", "privateEndpointConnections")
        >> ForallBend(AzureLinkServicePrivateEndpointConnection.mapping),
        "provisioning_state": S("properties", "provisioningState"),
        "type": S("type"),
        "visibility": S("properties", "visibility") >> Bend(AzureResourceSet.mapping),
    }
    alias: Optional[str] = field(default=None, metadata={"description": "The alias of the private link service."})
    auto_approval: Optional[AzureResourceSet] = field(default=None, metadata={'description': 'The auto-approval list of the private link service.'})  # fmt: skip
    enable_proxy_protocol: Optional[bool] = field(default=None, metadata={'description': 'Whether the private link service is enabled for proxy protocol or not.'})  # fmt: skip
    etag: Optional[str] = field(default=None, metadata={'description': 'A unique read-only string that changes whenever the resource is updated.'})  # fmt: skip
    extended_location: Optional[AzureExtendedLocation] = field(default=None, metadata={'description': 'ExtendedLocation complex type.'})  # fmt: skip
    fqdns: Optional[List[str]] = field(default=None, metadata={"description": "The list of Fqdn."})
    link_service_ip_configurations: Optional[List[AzurePrivateLinkServiceIpConfiguration]] = field(default=None, metadata={'description': 'An array of private link service IP configurations.'})  # fmt: skip
    _load_balancer_frontend_ip_configuration_ids: Optional[List[str]] = field(default=None, metadata={'description': 'An array of references to the load balancer IP configurations.'})  # fmt: skip
    location: Optional[str] = field(default=None, metadata={"description": "Resource location."})
    link_service_private_endpoint_connections: Optional[List[AzureLinkServicePrivateEndpointConnection]] = field(default=None, metadata={'description': 'An array of list about connections to the private endpoint.'})  # fmt: skip
    provisioning_state: Optional[str] = field(default=None, metadata={'description': 'The current provisioning state.'})  # fmt: skip
    type: Optional[str] = field(default=None, metadata={"description": "Resource type."})
    visibility: Optional[AzureResourceSet] = field(default=None, metadata={'description': 'The visibility list of the private link service.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureNetworkInterface(AzureResource):
    kind: ClassVar[str] = "azure_network_interface"
    api_spec: ClassVar[AzureApiSpec] = AzureApiSpec(
        service="network",
        version="2023-05-01",
        path="/subscriptions/{subscriptionId}/providers/Microsoft.Network/networkInterfaces",
        path_parameters=["subscriptionId"],
        query_parameters=["api-version"],
        access_path="value",
        expect_array=True,
    )
    reference_kinds: ClassVar[ModelReference] = {
        "predecessors": {
            "default": [
                "azure_virtual_network_tap",
                "azure_network_security_group",
                "azure_private_link_service",
            ]
        },
        "successors": {"default": ["azure_dscp_configuration"]},
    }
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "auxiliary_mode": S("properties", "auxiliaryMode"),
        "auxiliary_sku": S("properties", "auxiliarySku"),
        "disable_tcp_state_tracking": S("properties", "disableTcpStateTracking"),
        "interface_dns_settings": S("properties", "dnsSettings") >> Bend(AzureNetworkInterfaceDnsSettings.mapping),
        "dscp_configuration": S("properties", "dscpConfiguration", "id"),
        "enable_accelerated_networking": S("properties", "enableAcceleratedNetworking"),
        "enable_ip_forwarding": S("properties", "enableIPForwarding"),
        "etag": S("etag"),
        "extended_location": S("extendedLocation") >> Bend(AzureExtendedLocation.mapping),
        "hosted_workloads": S("properties", "hostedWorkloads"),
        "interface_ip_configurations": S("properties", "ipConfigurations")
        >> ForallBend(AzureNetworkInterfaceIPConfiguration.mapping),
        "location": S("location"),
        "mac_address": S("properties", "macAddress"),
        "migration_phase": S("properties", "migrationPhase"),
        "_network_security_group_id": S("properties", "networkSecurityGroup", "id"),
        "nic_type": S("properties", "nicType"),
        "primary": S("properties", "primary"),
        "private_endpoint": S("properties", "privateEndpoint") >> Bend(AzurePrivateEndpoint.mapping),
        "_private_link_service_id": S("properties", "privateLinkService", "id"),
        "provisioning_state": S("properties", "provisioningState"),
        "resource_guid": S("properties", "resourceGuid"),
        "tap_configurations": S("properties", "tapConfigurations")
        >> ForallBend(AzureNetworkInterfaceTapConfiguration.mapping),
        "type": S("type"),
        "virtual_machine": S("properties", "virtualMachine", "id"),
        "vnet_encryption_supported": S("properties", "vnetEncryptionSupported"),
        "workload_type": S("properties", "workloadType"),
    }
    auxiliary_mode: Optional[str] = field(default=None, metadata={'description': 'Auxiliary mode of Network Interface resource.'})  # fmt: skip
    auxiliary_sku: Optional[str] = field(default=None, metadata={'description': 'Auxiliary sku of Network Interface resource.'})  # fmt: skip
    disable_tcp_state_tracking: Optional[bool] = field(default=None, metadata={'description': 'Indicates whether to disable tcp state tracking.'})  # fmt: skip
    interface_dns_settings_settings: Optional[AzureNetworkInterfaceDnsSettings] = field(default=None, metadata={'description': 'DNS settings of a network interface.'})  # fmt: skip
    dscp_configuration: Optional[str] = field(default=None, metadata={'description': 'Reference to another subresource.'})  # fmt: skip
    enable_accelerated_networking: Optional[bool] = field(default=None, metadata={'description': 'If the network interface is configured for accelerated networking. Not applicable to VM sizes which require accelerated networking.'})  # fmt: skip
    enable_ip_forwarding: Optional[bool] = field(default=None, metadata={'description': 'Indicates whether IP forwarding is enabled on this network interface.'})  # fmt: skip
    etag: Optional[str] = field(default=None, metadata={'description': 'A unique read-only string that changes whenever the resource is updated.'})  # fmt: skip
    extended_location: Optional[AzureExtendedLocation] = field(default=None, metadata={'description': 'ExtendedLocation complex type.'})  # fmt: skip
    hosted_workloads: Optional[List[str]] = field(default=None, metadata={'description': 'A list of references to linked BareMetal resources.'})  # fmt: skip
    interface_ip_configurations: Optional[List[AzureNetworkInterfaceIPConfiguration]] = field(default=None, metadata={'description': 'A list of IPConfigurations of the network interface.'})  # fmt: skip
    location: Optional[str] = field(default=None, metadata={"description": "Resource location."})
    mac_address: Optional[str] = field(default=None, metadata={'description': 'The MAC address of the network interface.'})  # fmt: skip
    migration_phase: Optional[str] = field(default=None, metadata={'description': 'Migration phase of Network Interface resource.'})  # fmt: skip
    _network_security_group_id: Optional[str] = field(default=None, metadata={'description': 'NetworkSecurityGroup resource.'})  # fmt: skip
    nic_type: Optional[str] = field(default=None, metadata={"description": "Type of Network Interface resource."})
    primary: Optional[bool] = field(default=None, metadata={'description': 'Whether this is a primary network interface on a virtual machine.'})  # fmt: skip
    private_endpoint: Optional[AzurePrivateEndpoint] = field(default=None, metadata={'description': 'Private endpoint resource.'})  # fmt: skip
    _private_link_service_id: Optional[str] = field(default=None, metadata={'description': 'Private link service resource.'})  # fmt: skip
    provisioning_state: Optional[str] = field(default=None, metadata={'description': 'The current provisioning state.'})  # fmt: skip
    resource_guid: Optional[str] = field(default=None, metadata={'description': 'The resource GUID property of the network interface resource.'})  # fmt: skip
    tap_configurations: Optional[List[AzureNetworkInterfaceTapConfiguration]] = field(default=None, metadata={'description': 'A list of TapConfigurations of the network interface.'})  # fmt: skip
    type: Optional[str] = field(default=None, metadata={"description": "Resource type."})
    virtual_machine: Optional[str] = field(default=None, metadata={"description": "Reference to another subresource."})
    vnet_encryption_supported: Optional[bool] = field(default=None, metadata={'description': 'Whether the virtual machine this nic is attached to supports encryption.'})  # fmt: skip
    workload_type: Optional[str] = field(default=None, metadata={'description': 'WorkloadType of the NetworkInterface for BareMetal resources'})  # fmt: skip

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if dscp_config_id := self.dscp_configuration:
            builder.add_edge(self, edge_type=EdgeType.default, clazz=AzureDscpConfiguration, id=dscp_config_id)
        if tap_configs := self.tap_configurations:
            for tap_config in tap_configs:
                if vn_tap_id := tap_config.id:
                    builder.add_edge(
                        self, edge_type=EdgeType.default, reverse=True, clazz=AzureVirtualNetworkTap, id=vn_tap_id
                    )
        if nsg_id := self._network_security_group_id:
            builder.add_edge(self, edge_type=EdgeType.default, reverse=True, clazz=AzureNetworkSecurityGroup, id=nsg_id)
        if p_l_service_id := self._private_link_service_id:
            builder.add_edge(
                self, edge_type=EdgeType.default, reverse=True, clazz=AzurePrivateLinkService, id=p_l_service_id
            )


@define(eq=False, slots=False)
class AzureDscpConfiguration(AzureResource):
    kind: ClassVar[str] = "azure_dscp_configuration"
    api_spec: ClassVar[AzureApiSpec] = AzureApiSpec(
        service="network",
        version="2023-05-01",
        path="/subscriptions/{subscriptionId}/providers/Microsoft.Network/dscpConfigurations",
        path_parameters=["subscriptionId"],
        query_parameters=["api-version"],
        access_path="value",
        expect_array=True,
    )
    reference_kinds: ClassVar[ModelReference] = {
        "predecessors": {"default": ["azure_subnet"]},
    }
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "_associated_network_interface_ids": S("properties", "associatedNetworkInterfaces", default=[])
        >> ForallBend(S("id")),
        "destination_ip_ranges": S("properties", "destinationIpRanges") >> ForallBend(AzureQosIpRange.mapping),
        "destination_port_ranges": S("properties", "destinationPortRanges") >> ForallBend(AzureQosPortRange.mapping),
        "etag": S("etag"),
        "markings": S("properties", "markings"),
        "protocol": S("properties", "protocol"),
        "provisioning_state": S("properties", "provisioningState"),
        "qos_collection_id": S("properties", "qosCollectionId"),
        "qos_definition_collection": S("properties", "qosDefinitionCollection")
        >> ForallBend(AzureQosDefinition.mapping),
        "resource_guid": S("properties", "resourceGuid"),
        "source_ip_ranges": S("properties", "sourceIpRanges") >> ForallBend(AzureQosIpRange.mapping),
        "source_port_ranges": S("properties", "sourcePortRanges") >> ForallBend(AzureQosPortRange.mapping),
    }
    _associated_network_interface_ids: Optional[List[str]] = field(default=None, metadata={'description': 'Associated Network Interfaces to the DSCP Configuration.'})  # fmt: skip
    destination_ip_ranges: Optional[List[AzureQosIpRange]] = field(default=None, metadata={'description': 'Destination IP ranges.'})  # fmt: skip
    destination_port_ranges: Optional[List[AzureQosPortRange]] = field(default=None, metadata={'description': 'Destination port ranges.'})  # fmt: skip
    etag: Optional[str] = field(default=None, metadata={'description': 'A unique read-only string that changes whenever the resource is updated.'})  # fmt: skip
    markings: Optional[List[int]] = field(default=None, metadata={'description': 'List of markings to be used in the configuration.'})  # fmt: skip
    protocol: Optional[str] = field(default=None, metadata={"description": "RNM supported protocol types."})
    provisioning_state: Optional[str] = field(default=None, metadata={'description': 'The current provisioning state.'})  # fmt: skip
    qos_collection_id: Optional[str] = field(default=None, metadata={'description': 'Qos Collection ID generated by RNM.'})  # fmt: skip
    qos_definition_collection: Optional[List[AzureQosDefinition]] = field(default=None, metadata={'description': 'QoS object definitions'})  # fmt: skip
    resource_guid: Optional[str] = field(default=None, metadata={'description': 'The resource GUID property of the DSCP Configuration resource.'})  # fmt: skip
    source_ip_ranges: Optional[List[AzureQosIpRange]] = field(
        default=None, metadata={"description": "Source IP ranges."}
    )
    source_port_ranges: Optional[List[AzureQosPortRange]] = field(default=None, metadata={'description': 'Sources port ranges.'})  # fmt: skip

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if network_interfaces := self._associated_network_interface_ids:
            nis_and_subnet_id = self._get_nic_id_and_subnet_ids(builder)

            if ni_ids_and_s_id := nis_and_subnet_id:
                for network_interface_id in network_interfaces:
                    for info in ni_ids_and_s_id:
                        ni_id, subnet_ids = info
                        for subnet_id in subnet_ids:
                            if network_interface_id == ni_id:
                                builder.add_edge(
                                    self, edge_type=EdgeType.default, reverse=True, clazz=AzureSubnet, id=subnet_id
                                )

    def _get_nic_id_and_subnet_ids(self, builder: GraphBuilder) -> List[Tuple[str, List[str]]]:
        get_ip_conf_subnet_ids: Callable[[AzureNetworkInterface], List[str]] = lambda interface: [
            ip_config._subnet_id
            for ip_config in interface.interface_ip_configurations or []
            if ip_config._subnet_id is not None
        ]

        return [
            (nic_id, get_ip_conf_subnet_ids(interface))
            for interface in builder.nodes(clazz=AzureNetworkInterface)
            if (nic_id := interface.id)
        ]


@define(eq=False, slots=False)
class AzureExpressRouteCircuitAuthorization(AzureSubResource):
    kind: ClassVar[str] = "azure_express_route_circuit_authorization"
    mapping: ClassVar[Dict[str, Bender]] = AzureSubResource.mapping | {
        "authorization_key": S("properties", "authorizationKey"),
        "authorization_use_status": S("properties", "authorizationUseStatus"),
        "etag": S("etag"),
        "name": S("name"),
        "provisioning_state": S("properties", "provisioningState"),
        "type": S("type"),
    }
    authorization_key: Optional[str] = field(default=None, metadata={"description": "The authorization key."})
    authorization_use_status: Optional[str] = field(default=None, metadata={'description': 'The authorization use status.'})  # fmt: skip
    etag: Optional[str] = field(default=None, metadata={'description': 'A unique read-only string that changes whenever the resource is updated.'})  # fmt: skip
    name: Optional[str] = field(default=None, metadata={'description': 'The name of the resource that is unique within a resource group. This name can be used to access the resource.'})  # fmt: skip
    provisioning_state: Optional[str] = field(default=None, metadata={'description': 'The current provisioning state.'})  # fmt: skip
    type: Optional[str] = field(default=None, metadata={"description": "Type of the resource."})


@define(eq=False, slots=False)
class AzureExpressRouteCircuitPeeringConfig:
    kind: ClassVar[str] = "azure_express_route_circuit_peering_config"
    mapping: ClassVar[Dict[str, Bender]] = {
        "advertised_communities": S("advertisedCommunities"),
        "advertised_public_prefixes": S("advertisedPublicPrefixes"),
        "advertised_public_prefixes_state": S("advertisedPublicPrefixesState"),
        "customer_asn": S("customerASN"),
        "legacy_mode": S("legacyMode"),
        "routing_registry_name": S("routingRegistryName"),
    }
    advertised_communities: Optional[List[str]] = field(default=None, metadata={'description': 'The communities of bgp peering. Specified for microsoft peering.'})  # fmt: skip
    advertised_public_prefixes: Optional[List[str]] = field(default=None, metadata={'description': 'The reference to AdvertisedPublicPrefixes.'})  # fmt: skip
    advertised_public_prefixes_state: Optional[str] = field(default=None, metadata={'description': 'The advertised public prefix state of the Peering resource.'})  # fmt: skip
    customer_asn: Optional[int] = field(default=None, metadata={"description": "The CustomerASN of the peering."})
    legacy_mode: Optional[int] = field(default=None, metadata={"description": "The legacy mode of the peering."})
    routing_registry_name: Optional[str] = field(default=None, metadata={'description': 'The RoutingRegistryName of the configuration.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureExpressRouteCircuitStats:
    kind: ClassVar[str] = "azure_express_route_circuit_stats"
    mapping: ClassVar[Dict[str, Bender]] = {
        "primarybytes_in": S("primarybytesIn"),
        "primarybytes_out": S("primarybytesOut"),
        "secondarybytes_in": S("secondarybytesIn"),
        "secondarybytes_out": S("secondarybytesOut"),
    }
    primarybytes_in: Optional[int] = field(default=None, metadata={'description': 'The Primary BytesIn of the peering.'})  # fmt: skip
    primarybytes_out: Optional[int] = field(default=None, metadata={'description': 'The primary BytesOut of the peering.'})  # fmt: skip
    secondarybytes_in: Optional[int] = field(default=None, metadata={'description': 'The secondary BytesIn of the peering.'})  # fmt: skip
    secondarybytes_out: Optional[int] = field(default=None, metadata={'description': 'The secondary BytesOut of the peering.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureIpv6ExpressRouteCircuitPeeringConfig:
    kind: ClassVar[str] = "azure_ipv6_express_route_circuit_peering_config"
    mapping: ClassVar[Dict[str, Bender]] = {
        "microsoft_peering_config": S("microsoftPeeringConfig") >> Bend(AzureExpressRouteCircuitPeeringConfig.mapping),
        "primary_peer_address_prefix": S("primaryPeerAddressPrefix"),
        "route_filter": S("routeFilter", "id"),
        "secondary_peer_address_prefix": S("secondaryPeerAddressPrefix"),
        "state": S("state"),
    }
    microsoft_peering_config: Optional[AzureExpressRouteCircuitPeeringConfig] = field(default=None, metadata={'description': 'Specifies the peering configuration.'})  # fmt: skip
    primary_peer_address_prefix: Optional[str] = field(default=None, metadata={'description': 'The primary address prefix.'})  # fmt: skip
    route_filter: Optional[str] = field(default=None, metadata={"description": "Reference to another subresource."})
    secondary_peer_address_prefix: Optional[str] = field(default=None, metadata={'description': 'The secondary address prefix.'})  # fmt: skip
    state: Optional[str] = field(default=None, metadata={"description": "The state of peering."})


@define(eq=False, slots=False)
class AzureIpv6CircuitConnectionConfig:
    kind: ClassVar[str] = "azure_ipv6_circuit_connection_config"
    mapping: ClassVar[Dict[str, Bender]] = {
        "address_prefix": S("addressPrefix"),
        "circuit_connection_status": S("circuitConnectionStatus"),
    }
    address_prefix: Optional[str] = field(default=None, metadata={'description': '/125 IP address space to carve out customer addresses for global reach.'})  # fmt: skip
    circuit_connection_status: Optional[str] = field(default=None, metadata={'description': 'Express Route Circuit connection state.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureExpressRouteCircuitConnection(AzureSubResource):
    kind: ClassVar[str] = "azure_express_route_circuit_connection"
    mapping: ClassVar[Dict[str, Bender]] = AzureSubResource.mapping | {
        "address_prefix": S("properties", "addressPrefix"),
        "authorization_key": S("properties", "authorizationKey"),
        "circuit_connection_status": S("properties", "circuitConnectionStatus"),
        "etag": S("etag"),
        "express_route_circuit_peering": S("properties", "expressRouteCircuitPeering", "id"),
        "ipv6_circuit_connection_config": S("properties", "ipv6CircuitConnectionConfig")
        >> Bend(AzureIpv6CircuitConnectionConfig.mapping),
        "name": S("name"),
        "peer_express_route_circuit_peering": S("properties", "peerExpressRouteCircuitPeering", "id"),
        "provisioning_state": S("properties", "provisioningState"),
        "type": S("type"),
    }
    address_prefix: Optional[str] = field(default=None, metadata={'description': '/29 IP address space to carve out Customer addresses for tunnels.'})  # fmt: skip
    authorization_key: Optional[str] = field(default=None, metadata={"description": "The authorization key."})
    circuit_connection_status: Optional[str] = field(default=None, metadata={'description': 'Express Route Circuit connection state.'})  # fmt: skip
    etag: Optional[str] = field(default=None, metadata={'description': 'A unique read-only string that changes whenever the resource is updated.'})  # fmt: skip
    express_route_circuit_peering: Optional[str] = field(default=None, metadata={'description': 'Reference to another subresource.'})  # fmt: skip
    ipv6_circuit_connection_config: Optional[AzureIpv6CircuitConnectionConfig] = field(default=None, metadata={'description': 'IPv6 Circuit Connection properties for global reach.'})  # fmt: skip
    name: Optional[str] = field(default=None, metadata={'description': 'The name of the resource that is unique within a resource group. This name can be used to access the resource.'})  # fmt: skip
    peer_express_route_circuit_peering: Optional[str] = field(default=None, metadata={'description': 'Reference to another subresource.'})  # fmt: skip
    provisioning_state: Optional[str] = field(default=None, metadata={'description': 'The current provisioning state.'})  # fmt: skip
    type: Optional[str] = field(default=None, metadata={"description": "Type of the resource."})


@define(eq=False, slots=False)
class AzurePeerExpressRouteCircuitConnection(AzureSubResource):
    kind: ClassVar[str] = "azure_peer_express_route_circuit_connection"
    mapping: ClassVar[Dict[str, Bender]] = AzureSubResource.mapping | {
        "address_prefix": S("properties", "addressPrefix"),
        "auth_resource_guid": S("properties", "authResourceGuid"),
        "circuit_connection_status": S("properties", "circuitConnectionStatus"),
        "connection_name": S("properties", "connectionName"),
        "etag": S("etag"),
        "express_route_circuit_peering": S("properties", "expressRouteCircuitPeering", "id"),
        "name": S("name"),
        "peer_express_route_circuit_peering": S("properties", "peerExpressRouteCircuitPeering", "id"),
        "provisioning_state": S("properties", "provisioningState"),
        "type": S("type"),
    }
    address_prefix: Optional[str] = field(default=None, metadata={'description': '/29 IP address space to carve out Customer addresses for tunnels.'})  # fmt: skip
    auth_resource_guid: Optional[str] = field(default=None, metadata={'description': 'The resource guid of the authorization used for the express route circuit connection.'})  # fmt: skip
    circuit_connection_status: Optional[str] = field(default=None, metadata={'description': 'Express Route Circuit connection state.'})  # fmt: skip
    connection_name: Optional[str] = field(default=None, metadata={'description': 'The name of the express route circuit connection resource.'})  # fmt: skip
    etag: Optional[str] = field(default=None, metadata={'description': 'A unique read-only string that changes whenever the resource is updated.'})  # fmt: skip
    express_route_circuit_peering: Optional[str] = field(default=None, metadata={'description': 'Reference to another subresource.'})  # fmt: skip
    name: Optional[str] = field(default=None, metadata={'description': 'The name of the resource that is unique within a resource group. This name can be used to access the resource.'})  # fmt: skip
    peer_express_route_circuit_peering: Optional[str] = field(default=None, metadata={'description': 'Reference to another subresource.'})  # fmt: skip
    provisioning_state: Optional[str] = field(default=None, metadata={'description': 'The current provisioning state.'})  # fmt: skip
    type: Optional[str] = field(default=None, metadata={"description": "Type of the resource."})


@define(eq=False, slots=False)
class AzureExpressRouteCircuitPeering(AzureSubResource):
    kind: ClassVar[str] = "azure_express_route_circuit_peering"
    mapping: ClassVar[Dict[str, Bender]] = AzureSubResource.mapping | {
        "azure_asn": S("properties", "azureASN"),
        "connections": S("properties", "connections") >> ForallBend(AzureExpressRouteCircuitConnection.mapping),
        "etag": S("etag"),
        "express_route_connection": S("properties", "expressRouteConnection", "id"),
        "gateway_manager_etag": S("properties", "gatewayManagerEtag"),
        "ipv6_peering_config": S("properties", "ipv6PeeringConfig")
        >> Bend(AzureIpv6ExpressRouteCircuitPeeringConfig.mapping),
        "last_modified_by": S("properties", "lastModifiedBy"),
        "microsoft_peering_config": S("properties", "microsoftPeeringConfig")
        >> Bend(AzureExpressRouteCircuitPeeringConfig.mapping),
        "name": S("name"),
        "peer_asn": S("properties", "peerASN"),
        "peered_connections": S("properties", "peeredConnections")
        >> ForallBend(AzurePeerExpressRouteCircuitConnection.mapping),
        "peering_type": S("properties", "peeringType"),
        "primary_azure_port": S("properties", "primaryAzurePort"),
        "primary_peer_address_prefix": S("properties", "primaryPeerAddressPrefix"),
        "provisioning_state": S("properties", "provisioningState"),
        "route_filter": S("properties", "routeFilter", "id"),
        "secondary_azure_port": S("properties", "secondaryAzurePort"),
        "secondary_peer_address_prefix": S("properties", "secondaryPeerAddressPrefix"),
        "shared_key": S("properties", "sharedKey"),
        "state": S("properties", "state"),
        "stats": S("properties", "stats") >> Bend(AzureExpressRouteCircuitStats.mapping),
        "type": S("type"),
        "vlan_id": S("properties", "vlanId"),
    }
    azure_asn: Optional[int] = field(default=None, metadata={"description": "The Azure ASN."})
    connections: Optional[List[AzureExpressRouteCircuitConnection]] = field(default=None, metadata={'description': 'The list of circuit connections associated with Azure Private Peering for this circuit.'})  # fmt: skip
    etag: Optional[str] = field(default=None, metadata={'description': 'A unique read-only string that changes whenever the resource is updated.'})  # fmt: skip
    express_route_connection: Optional[str] = field(default=None, metadata={'description': 'The ID of the ExpressRouteConnection.'})  # fmt: skip
    gateway_manager_etag: Optional[str] = field(default=None, metadata={"description": "The GatewayManager Etag."})
    ipv6_peering_config: Optional[AzureIpv6ExpressRouteCircuitPeeringConfig] = field(default=None, metadata={'description': 'Contains IPv6 peering config.'})  # fmt: skip
    last_modified_by: Optional[str] = field(default=None, metadata={'description': 'Who was the last to modify the peering.'})  # fmt: skip
    microsoft_peering_config: Optional[AzureExpressRouteCircuitPeeringConfig] = field(default=None, metadata={'description': 'Specifies the peering configuration.'})  # fmt: skip
    name: Optional[str] = field(default=None, metadata={'description': 'The name of the resource that is unique within a resource group. This name can be used to access the resource.'})  # fmt: skip
    peer_asn: Optional[int] = field(default=None, metadata={"description": "The peer ASN."})
    peered_connections: Optional[List[AzurePeerExpressRouteCircuitConnection]] = field(default=None, metadata={'description': 'The list of peered circuit connections associated with Azure Private Peering for this circuit.'})  # fmt: skip
    peering_type: Optional[str] = field(default=None, metadata={"description": "The peering type."})
    primary_azure_port: Optional[str] = field(default=None, metadata={"description": "The primary port."})
    primary_peer_address_prefix: Optional[str] = field(default=None, metadata={'description': 'The primary address prefix.'})  # fmt: skip
    provisioning_state: Optional[str] = field(default=None, metadata={'description': 'The current provisioning state.'})  # fmt: skip
    route_filter: Optional[str] = field(default=None, metadata={"description": "Reference to another subresource."})
    secondary_azure_port: Optional[str] = field(default=None, metadata={"description": "The secondary port."})
    secondary_peer_address_prefix: Optional[str] = field(default=None, metadata={'description': 'The secondary address prefix.'})  # fmt: skip
    shared_key: Optional[str] = field(default=None, metadata={"description": "The shared key."})
    state: Optional[str] = field(default=None, metadata={"description": "The state of peering."})
    stats: Optional[AzureExpressRouteCircuitStats] = field(default=None, metadata={'description': 'Contains stats associated with the peering.'})  # fmt: skip
    type: Optional[str] = field(default=None, metadata={"description": "Type of the resource."})
    vlan_id: Optional[int] = field(default=None, metadata={"description": "The VLAN ID."})


@define(eq=False, slots=False)
class AzureExpressRouteCircuitServiceProviderProperties:
    kind: ClassVar[str] = "azure_express_route_circuit_service_provider_properties"
    mapping: ClassVar[Dict[str, Bender]] = {
        "bandwidth_in_mbps": S("bandwidthInMbps"),
        "peering_location": S("peeringLocation"),
        "service_provider_name": S("serviceProviderName"),
    }
    bandwidth_in_mbps: Optional[int] = field(default=None, metadata={"description": "The BandwidthInMbps."})
    peering_location: Optional[str] = field(default=None, metadata={"description": "The peering location."})
    service_provider_name: Optional[str] = field(default=None, metadata={"description": "The serviceProviderName."})


@define(eq=False, slots=False)
class AzureExpressRouteCircuit(AzureResource):
    kind: ClassVar[str] = "azure_express_route_circuit"
    api_spec: ClassVar[AzureApiSpec] = AzureApiSpec(
        service="network",
        version="2023-05-01",
        path="/subscriptions/{subscriptionId}/providers/Microsoft.Network/expressRouteCircuits",
        path_parameters=["subscriptionId"],
        query_parameters=["api-version"],
        access_path="value",
        expect_array=True,
    )
    reference_kinds: ClassVar[ModelReference] = {
        "successors": {"default": ["azure_express_route_port", "azure_express_route_ports_location"]},
    }
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "allow_classic_operations": S("properties", "allowClassicOperations"),
        "authorization_key": S("properties", "authorizationKey"),
        "authorization_status": S("properties", "authorizationStatus"),
        "authorizations": S("properties", "authorizations")
        >> ForallBend(AzureExpressRouteCircuitAuthorization.mapping),
        "bandwidth_in_gbps": S("properties", "bandwidthInGbps"),
        "circuit_provisioning_state": S("properties", "circuitProvisioningState"),
        "etag": S("etag"),
        "express_route_port": S("properties", "expressRoutePort", "id"),
        "gateway_manager_etag": S("properties", "gatewayManagerEtag"),
        "global_reach_enabled": S("properties", "globalReachEnabled"),
        "circuit_peerings": S("properties", "peerings") >> ForallBend(AzureExpressRouteCircuitPeering.mapping),
        "provisioning_state": S("properties", "provisioningState"),
        "service_key": S("properties", "serviceKey"),
        "service_provider_notes": S("properties", "serviceProviderNotes"),
        "service_provider_properties": S("properties", "serviceProviderProperties")
        >> Bend(AzureExpressRouteCircuitServiceProviderProperties.mapping),
        "service_provider_provisioning_state": S("properties", "serviceProviderProvisioningState"),
        "azure_sku": S("sku") >> Bend(AzureSku.mapping),
        "stag": S("properties", "stag"),
    }
    allow_classic_operations: Optional[bool] = field(default=None, metadata={'description': 'Allow classic operations.'})  # fmt: skip
    authorization_key: Optional[str] = field(default=None, metadata={"description": "The authorizationKey."})
    authorization_status: Optional[str] = field(default=None, metadata={'description': 'The authorization status of the Circuit.'})  # fmt: skip
    authorizations: Optional[List[AzureExpressRouteCircuitAuthorization]] = field(default=None, metadata={'description': 'The list of authorizations.'})  # fmt: skip
    bandwidth_in_gbps: Optional[float] = field(default=None, metadata={'description': 'The bandwidth of the circuit when the circuit is provisioned on an ExpressRoutePort resource.'})  # fmt: skip
    circuit_provisioning_state: Optional[str] = field(default=None, metadata={'description': 'The CircuitProvisioningState state of the resource.'})  # fmt: skip
    etag: Optional[str] = field(default=None, metadata={'description': 'A unique read-only string that changes whenever the resource is updated.'})  # fmt: skip
    express_route_port: Optional[str] = field(default=None, metadata={'description': 'Reference to another subresource.'})  # fmt: skip
    gateway_manager_etag: Optional[str] = field(default=None, metadata={"description": "The GatewayManager Etag."})
    global_reach_enabled: Optional[bool] = field(default=None, metadata={'description': 'Flag denoting global reach status.'})  # fmt: skip
    circuit_peerings: Optional[List[AzureExpressRouteCircuitPeering]] = field(default=None, metadata={'description': 'The list of peerings.'})  # fmt: skip
    provisioning_state: Optional[str] = field(default=None, metadata={'description': 'The current provisioning state.'})  # fmt: skip
    service_key: Optional[str] = field(default=None, metadata={"description": "The ServiceKey."})
    service_provider_notes: Optional[str] = field(default=None, metadata={"description": "The ServiceProviderNotes."})
    service_provider_properties: Optional[AzureExpressRouteCircuitServiceProviderProperties] = field(default=None, metadata={'description': 'Contains ServiceProviderProperties in an ExpressRouteCircuit.'})  # fmt: skip
    service_provider_provisioning_state: Optional[str] = field(default=None, metadata={'description': 'The ServiceProviderProvisioningState state of the resource.'})  # fmt: skip
    azure_sku: Optional[AzureSku] = field(default=None, metadata={'description': 'Contains SKU in an ExpressRouteCircuit.'})  # fmt: skip
    stag: Optional[int] = field(default=None, metadata={'description': 'The identifier of the circuit traffic. Outer tag for QinQ encapsulation.'})  # fmt: skip

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if route_port_id := self.express_route_port:
            builder.add_edge(self, edge_type=EdgeType.default, clazz=AzureExpressRoutePort, id=route_port_id)
        if (provider_properties := self.service_provider_properties) and (
            location_name := provider_properties.peering_location
        ):
            ids_and_names_in_resource = self._get_aerpl_name_and_id(builder)

            if names_and_ids := ids_and_names_in_resource:
                for info in names_and_ids:
                    erplocation, erplocation_id = info
                    if erplocation == location_name:
                        builder.add_edge(
                            self, edge_type=EdgeType.default, clazz=AzureExpressRoutePortsLocation, id=erplocation_id
                        )

    def _get_aerpl_name_and_id(self, builder: GraphBuilder) -> List[Tuple[str, str]]:
        return [
            (aerpl_name, aerpl_id)
            for location in builder.nodes(clazz=AzureExpressRoutePortsLocation)
            if (aerpl_name := location.name) and (aerpl_id := location.id)
        ]


@define(eq=False, slots=False)
class AzureExpressRouteCrossConnectionPeering(AzureSubResource):
    kind: ClassVar[str] = "azure_express_route_cross_connection_peering"
    mapping: ClassVar[Dict[str, Bender]] = AzureSubResource.mapping | {
        "azure_asn": S("properties", "azureASN"),
        "etag": S("etag"),
        "gateway_manager_etag": S("properties", "gatewayManagerEtag"),
        "ipv6_peering_config": S("properties", "ipv6PeeringConfig")
        >> Bend(AzureIpv6ExpressRouteCircuitPeeringConfig.mapping),
        "last_modified_by": S("properties", "lastModifiedBy"),
        "microsoft_peering_config": S("properties", "microsoftPeeringConfig")
        >> Bend(AzureExpressRouteCircuitPeeringConfig.mapping),
        "name": S("name"),
        "peer_asn": S("properties", "peerASN"),
        "peering_type": S("properties", "peeringType"),
        "primary_azure_port": S("properties", "primaryAzurePort"),
        "primary_peer_address_prefix": S("properties", "primaryPeerAddressPrefix"),
        "provisioning_state": S("properties", "provisioningState"),
        "secondary_azure_port": S("properties", "secondaryAzurePort"),
        "secondary_peer_address_prefix": S("properties", "secondaryPeerAddressPrefix"),
        "shared_key": S("properties", "sharedKey"),
        "state": S("properties", "state"),
        "vlan_id": S("properties", "vlanId"),
    }
    azure_asn: Optional[int] = field(default=None, metadata={"description": "The Azure ASN."})
    etag: Optional[str] = field(default=None, metadata={'description': 'A unique read-only string that changes whenever the resource is updated.'})  # fmt: skip
    gateway_manager_etag: Optional[str] = field(default=None, metadata={"description": "The GatewayManager Etag."})
    ipv6_peering_config: Optional[AzureIpv6ExpressRouteCircuitPeeringConfig] = field(default=None, metadata={'description': 'Contains IPv6 peering config.'})  # fmt: skip
    last_modified_by: Optional[str] = field(default=None, metadata={'description': 'Who was the last to modify the peering.'})  # fmt: skip
    microsoft_peering_config: Optional[AzureExpressRouteCircuitPeeringConfig] = field(default=None, metadata={'description': 'Specifies the peering configuration.'})  # fmt: skip
    name: Optional[str] = field(default=None, metadata={'description': 'The name of the resource that is unique within a resource group. This name can be used to access the resource.'})  # fmt: skip
    peer_asn: Optional[int] = field(default=None, metadata={"description": "The peer ASN."})
    peering_type: Optional[str] = field(default=None, metadata={"description": "The peering type."})
    primary_azure_port: Optional[str] = field(default=None, metadata={"description": "The primary port."})
    primary_peer_address_prefix: Optional[str] = field(default=None, metadata={'description': 'The primary address prefix.'})  # fmt: skip
    provisioning_state: Optional[str] = field(default=None, metadata={'description': 'The current provisioning state.'})  # fmt: skip
    secondary_azure_port: Optional[str] = field(default=None, metadata={"description": "The secondary port."})
    secondary_peer_address_prefix: Optional[str] = field(default=None, metadata={'description': 'The secondary address prefix.'})  # fmt: skip
    shared_key: Optional[str] = field(default=None, metadata={"description": "The shared key."})
    state: Optional[str] = field(default=None, metadata={"description": "The state of peering."})
    vlan_id: Optional[int] = field(default=None, metadata={"description": "The VLAN ID."})


@define(eq=False, slots=False)
class AzureExpressRouteCrossConnection(AzureResource):
    kind: ClassVar[str] = "azure_express_route_cross_connection"
    api_spec: ClassVar[AzureApiSpec] = AzureApiSpec(
        service="network",
        version="2023-05-01",
        path="/subscriptions/{subscriptionId}/providers/Microsoft.Network/expressRouteCrossConnections",
        path_parameters=["subscriptionId"],
        query_parameters=["api-version"],
        access_path="value",
        expect_array=True,
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "bandwidth_in_mbps": S("properties", "bandwidthInMbps"),
        "etag": S("etag"),
        "express_route_circuit": S("properties", "expressRouteCircuit", "id"),
        "peering_location": S("properties", "peeringLocation"),
        "cross_connection_peerings": S("properties", "peerings")
        >> ForallBend(AzureExpressRouteCrossConnectionPeering.mapping),
        "primary_azure_port": S("properties", "primaryAzurePort"),
        "provisioning_state": S("properties", "provisioningState"),
        "s_tag": S("properties", "sTag"),
        "secondary_azure_port": S("properties", "secondaryAzurePort"),
        "service_provider_notes": S("properties", "serviceProviderNotes"),
        "service_provider_provisioning_state": S("properties", "serviceProviderProvisioningState"),
    }
    bandwidth_in_mbps: Optional[int] = field(default=None, metadata={"description": "The circuit bandwidth In Mbps."})
    etag: Optional[str] = field(default=None, metadata={'description': 'A unique read-only string that changes whenever the resource is updated.'})  # fmt: skip
    express_route_circuit: Optional[str] = field(default=None, metadata={'description': 'Reference to an express route circuit.'})  # fmt: skip
    peering_location: Optional[str] = field(default=None, metadata={'description': 'The peering location of the ExpressRoute circuit.'})  # fmt: skip
    cross_connection_peerings: Optional[List[AzureExpressRouteCrossConnectionPeering]] = field(default=None, metadata={'description': 'The list of peerings.'})  # fmt: skip
    primary_azure_port: Optional[str] = field(default=None, metadata={"description": "The name of the primary port."})
    provisioning_state: Optional[str] = field(default=None, metadata={'description': 'The current provisioning state.'})  # fmt: skip
    s_tag: Optional[int] = field(default=None, metadata={"description": "The identifier of the circuit traffic."})
    secondary_azure_port: Optional[str] = field(default=None, metadata={'description': 'The name of the secondary port.'})  # fmt: skip
    service_provider_notes: Optional[str] = field(default=None, metadata={'description': 'Additional read only notes set by the connectivity provider.'})  # fmt: skip
    service_provider_provisioning_state: Optional[str] = field(default=None, metadata={'description': 'The ServiceProviderProvisioningState state of the resource.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureMinMax:
    kind: ClassVar[str] = "azure_min_max"
    mapping: ClassVar[Dict[str, Bender]] = {"max": S("max"), "min": S("min")}
    max: Optional[int] = field(default=None, metadata={'description': 'Maximum number of scale units deployed for ExpressRoute gateway.'})  # fmt: skip
    min: Optional[int] = field(default=None, metadata={'description': 'Minimum number of scale units deployed for ExpressRoute gateway.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureBounds:
    kind: ClassVar[str] = "azure_bounds"
    mapping: ClassVar[Dict[str, Bender]] = {"bounds": S("bounds") >> Bend(AzureMinMax.mapping)}
    bounds: Optional[AzureMinMax] = field(default=None, metadata={'description': 'Minimum and maximum number of scale units to deploy.'})  # fmt: skip


@define(eq=False, slots=False)
class AzurePropagatedRouteTable:
    kind: ClassVar[str] = "azure_propagated_route_table"
    mapping: ClassVar[Dict[str, Bender]] = {"ids": S("ids", default=[]) >> ForallBend(S("id")), "labels": S("labels")}
    ids: Optional[List[str]] = field(default=None, metadata={'description': 'The list of resource ids of all the RouteTables.'})  # fmt: skip
    labels: Optional[List[str]] = field(default=None, metadata={"description": "The list of labels."})


@define(eq=False, slots=False)
class AzureStaticRoutesConfig:
    kind: ClassVar[str] = "azure_static_routes_config"
    mapping: ClassVar[Dict[str, Bender]] = {
        "propagate_static_routes": S("propagateStaticRoutes"),
        "vnet_local_route_override_criteria": S("vnetLocalRouteOverrideCriteria"),
    }
    propagate_static_routes: Optional[bool] = field(default=None, metadata={'description': 'Boolean indicating whether static routes on this connection are automatically propagate to route tables which this connection propagates to.'})  # fmt: skip
    vnet_local_route_override_criteria: Optional[str] = field(default=None, metadata={'description': 'Parameter determining whether NVA in spoke vnet is bypassed for traffic with destination in spoke vnet.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureStaticRoute:
    kind: ClassVar[str] = "azure_static_route"
    mapping: ClassVar[Dict[str, Bender]] = {
        "address_prefixes": S("addressPrefixes"),
        "name": S("name"),
        "next_hop_ip_address": S("nextHopIpAddress"),
    }
    address_prefixes: Optional[List[str]] = field(
        default=None, metadata={"description": "List of all address prefixes."}
    )
    name: Optional[str] = field(default=None, metadata={'description': 'The name of the StaticRoute that is unique within a VnetRoute.'})  # fmt: skip
    next_hop_ip_address: Optional[str] = field(default=None, metadata={'description': 'The ip address of the next hop.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureVnetRoute:
    kind: ClassVar[str] = "azure_vnet_route"
    mapping: ClassVar[Dict[str, Bender]] = {
        "bgp_connections": S("bgpConnections", default=[]) >> ForallBend(S("id")),
        "static_routes": S("staticRoutes") >> ForallBend(AzureStaticRoute.mapping),
        "static_routes_config": S("staticRoutesConfig") >> Bend(AzureStaticRoutesConfig.mapping),
    }
    bgp_connections: Optional[List[str]] = field(default=None, metadata={'description': 'The list of references to HubBgpConnection objects.'})  # fmt: skip
    static_routes: Optional[List[AzureStaticRoute]] = field(default=None, metadata={'description': 'List of all Static Routes.'})  # fmt: skip
    static_routes_config: Optional[AzureStaticRoutesConfig] = field(default=None, metadata={'description': 'Configuration for static routes on this HubVnetConnectionConfiguration for static routes on this HubVnetConnection.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureRoutingConfiguration:
    kind: ClassVar[str] = "azure_routing_configuration"
    mapping: ClassVar[Dict[str, Bender]] = {
        "associated_route_table": S("associatedRouteTable", "id"),
        "inbound_route_map": S("inboundRouteMap", "id"),
        "outbound_route_map": S("outboundRouteMap", "id"),
        "propagated_route_tables": S("propagatedRouteTables") >> Bend(AzurePropagatedRouteTable.mapping),
        "vnet_routes": S("vnetRoutes") >> Bend(AzureVnetRoute.mapping),
    }
    associated_route_table: Optional[str] = field(default=None, metadata={'description': 'Reference to another subresource.'})  # fmt: skip
    inbound_route_map: Optional[str] = field(default=None, metadata={'description': 'Reference to another subresource.'})  # fmt: skip
    outbound_route_map: Optional[str] = field(default=None, metadata={'description': 'Reference to another subresource.'})  # fmt: skip
    propagated_route_tables: Optional[AzurePropagatedRouteTable] = field(default=None, metadata={'description': 'The list of RouteTables to advertise the routes to.'})  # fmt: skip
    vnet_routes: Optional[AzureVnetRoute] = field(default=None, metadata={'description': 'List of routes that control routing from VirtualHub into a virtual network connection.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureExpressRouteConnection(AzureSubResource):
    kind: ClassVar[str] = "azure_express_route_connection"
    mapping: ClassVar[Dict[str, Bender]] = AzureSubResource.mapping | {
        "authorization_key": S("properties", "authorizationKey"),
        "enable_internet_security": S("properties", "enableInternetSecurity"),
        "enable_private_link_fast_path": S("properties", "enablePrivateLinkFastPath"),
        "express_route_circuit_peering": S("properties", "expressRouteCircuitPeering", "id"),
        "express_route_gateway_bypass": S("properties", "expressRouteGatewayBypass"),
        "name": S("name"),
        "provisioning_state": S("properties", "provisioningState"),
        "routing_configuration": S("properties", "routingConfiguration") >> Bend(AzureRoutingConfiguration.mapping),
        "routing_weight": S("properties", "routingWeight"),
    }
    authorization_key: Optional[str] = field(default=None, metadata={'description': 'Authorization key to establish the connection.'})  # fmt: skip
    enable_internet_security: Optional[bool] = field(default=None, metadata={'description': 'Enable internet security.'})  # fmt: skip
    enable_private_link_fast_path: Optional[bool] = field(default=None, metadata={'description': 'Bypass the ExpressRoute gateway when accessing private-links. ExpressRoute FastPath (expressRouteGatewayBypass) must be enabled.'})  # fmt: skip
    express_route_circuit_peering: Optional[str] = field(default=None, metadata={'description': 'ExpressRoute circuit peering identifier.'})  # fmt: skip
    express_route_gateway_bypass: Optional[bool] = field(default=None, metadata={'description': 'Enable FastPath to vWan Firewall hub.'})  # fmt: skip
    name: Optional[str] = field(default=None, metadata={"description": "The name of the resource."})
    provisioning_state: Optional[str] = field(default=None, metadata={'description': 'The current provisioning state.'})  # fmt: skip
    routing_configuration: Optional[AzureRoutingConfiguration] = field(default=None, metadata={'description': 'Routing Configuration indicating the associated and propagated route tables for this connection.'})  # fmt: skip
    routing_weight: Optional[int] = field(default=None, metadata={'description': 'The routing weight associated to the connection.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureExpressRouteGateway(AzureResource, BaseGateway):
    kind: ClassVar[str] = "azure_express_route_gateway"
    api_spec: ClassVar[AzureApiSpec] = AzureApiSpec(
        service="network",
        version="2023-05-01",
        path="/subscriptions/{subscriptionId}/providers/Microsoft.Network/expressRouteGateways",
        path_parameters=["subscriptionId"],
        query_parameters=["api-version"],
        access_path="value",
        expect_array=True,
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "allow_non_virtual_wan_traffic": S("properties", "allowNonVirtualWanTraffic"),
        "auto_scale_configuration": S("properties", "autoScaleConfiguration") >> Bend(AzureBounds.mapping),
        "etag": S("etag"),
        "express_route_connections": S("properties", "expressRouteConnections")
        >> ForallBend(AzureExpressRouteConnection.mapping),
        "provisioning_state": S("properties", "provisioningState"),
        "virtual_hub": S("properties", "virtualHub", "id"),
    }
    allow_non_virtual_wan_traffic: Optional[bool] = field(default=None, metadata={'description': 'Configures this gateway to accept traffic from non Virtual WAN networks.'})  # fmt: skip
    auto_scale_configuration: Optional[AzureBounds] = field(default=None, metadata={'description': 'Configuration for auto scaling.'})  # fmt: skip
    etag: Optional[str] = field(default=None, metadata={'description': 'A unique read-only string that changes whenever the resource is updated.'})  # fmt: skip
    express_route_connections: Optional[List[AzureExpressRouteConnection]] = field(default=None, metadata={'description': 'List of ExpressRoute connections to the ExpressRoute gateway.'})  # fmt: skip
    provisioning_state: Optional[str] = field(default=None, metadata={'description': 'The current provisioning state.'})  # fmt: skip
    virtual_hub: Optional[str] = field(default=None, metadata={"description": "Virtual Hub identifier."})


@define(eq=False, slots=False)
class AzureExpressRouteLinkMacSecConfig:
    kind: ClassVar[str] = "azure_express_route_link_mac_sec_config"
    mapping: ClassVar[Dict[str, Bender]] = {
        "cak_secret_identifier": S("cakSecretIdentifier"),
        "cipher": S("cipher"),
        "ckn_secret_identifier": S("cknSecretIdentifier"),
        "sci_state": S("sciState"),
    }
    cak_secret_identifier: Optional[str] = field(default=None, metadata={'description': 'Keyvault Secret Identifier URL containing Mac security CAK key.'})  # fmt: skip
    cipher: Optional[str] = field(default=None, metadata={"description": "Mac security cipher."})
    ckn_secret_identifier: Optional[str] = field(default=None, metadata={'description': 'Keyvault Secret Identifier URL containing Mac security CKN key.'})  # fmt: skip
    sci_state: Optional[str] = field(default=None, metadata={"description": "Sci mode enabled/disabled."})


@define(eq=False, slots=False)
class AzureExpressRouteLink(AzureSubResource):
    kind: ClassVar[str] = "azure_express_route_link"
    mapping: ClassVar[Dict[str, Bender]] = AzureSubResource.mapping | {
        "admin_state": S("properties", "adminState"),
        "colo_location": S("properties", "coloLocation"),
        "connector_type": S("properties", "connectorType"),
        "etag": S("etag"),
        "interface_name": S("properties", "interfaceName"),
        "mac_sec_config": S("properties", "macSecConfig") >> Bend(AzureExpressRouteLinkMacSecConfig.mapping),
        "name": S("name"),
        "patch_panel_id": S("properties", "patchPanelId"),
        "provisioning_state": S("properties", "provisioningState"),
        "rack_id": S("properties", "rackId"),
        "router_name": S("properties", "routerName"),
    }
    admin_state: Optional[str] = field(default=None, metadata={'description': 'Administrative state of the physical port.'})  # fmt: skip
    colo_location: Optional[str] = field(default=None, metadata={'description': 'Cololocation for ExpressRoute Hybrid Direct.'})  # fmt: skip
    connector_type: Optional[str] = field(default=None, metadata={"description": "Physical fiber port type."})
    etag: Optional[str] = field(default=None, metadata={'description': 'A unique read-only string that changes whenever the resource is updated.'})  # fmt: skip
    interface_name: Optional[str] = field(default=None, metadata={"description": "Name of Azure router interface."})
    mac_sec_config: Optional[AzureExpressRouteLinkMacSecConfig] = field(default=None, metadata={'description': 'ExpressRouteLink Mac Security Configuration.'})  # fmt: skip
    name: Optional[str] = field(default=None, metadata={'description': 'Name of child port resource that is unique among child port resources of the parent.'})  # fmt: skip
    patch_panel_id: Optional[str] = field(default=None, metadata={'description': 'Mapping between physical port to patch panel port.'})  # fmt: skip
    provisioning_state: Optional[str] = field(default=None, metadata={'description': 'The current provisioning state.'})  # fmt: skip
    rack_id: Optional[str] = field(default=None, metadata={"description": "Mapping of physical patch panel to rack."})
    router_name: Optional[str] = field(default=None, metadata={'description': 'Name of Azure router associated with physical port.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureExpressRoutePort(AzureResource):
    kind: ClassVar[str] = "azure_express_route_port"
    api_spec: ClassVar[AzureApiSpec] = AzureApiSpec(
        service="network",
        version="2023-05-01",
        path="/subscriptions/{subscriptionId}/providers/Microsoft.Network/ExpressRoutePorts",
        path_parameters=["subscriptionId"],
        query_parameters=["api-version"],
        access_path="value",
        expect_array=True,
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "allocation_date": S("properties", "allocationDate"),
        "bandwidth_in_gbps": S("properties", "bandwidthInGbps"),
        "billing_type": S("properties", "billingType"),
        "circuits": S("properties") >> S("circuits", default=[]) >> ForallBend(S("id")),
        "encapsulation": S("properties", "encapsulation"),
        "etag": S("etag"),
        "ether_type": S("properties", "etherType"),
        "identity": S("identity") >> Bend(AzureManagedServiceIdentity.mapping),
        "links": S("properties", "links") >> ForallBend(AzureExpressRouteLink.mapping),
        "mtu": S("properties", "mtu") >> AsInt(),
        "peering_location": S("properties", "peeringLocation"),
        "provisioned_bandwidth_in_gbps": S("properties", "provisionedBandwidthInGbps"),
        "provisioning_state": S("properties", "provisioningState"),
        "resource_guid": S("properties", "resourceGuid"),
    }
    allocation_date: Optional[str] = field(default=None, metadata={'description': 'Date of the physical port allocation to be used in Letter of Authorization.'})  # fmt: skip
    bandwidth_in_gbps: Optional[float] = field(default=None, metadata={'description': 'Bandwidth of procured ports in Gbps.'})  # fmt: skip
    billing_type: Optional[str] = field(default=None, metadata={'description': 'The billing type of the ExpressRoutePort resource.'})  # fmt: skip
    circuits: Optional[List[str]] = field(default=None, metadata={'description': 'Reference the ExpressRoute circuit(s) that are provisioned on this ExpressRoutePort resource.'})  # fmt: skip
    encapsulation: Optional[str] = field(default=None, metadata={'description': 'Encapsulation method on physical ports.'})  # fmt: skip
    etag: Optional[str] = field(default=None, metadata={'description': 'A unique read-only string that changes whenever the resource is updated.'})  # fmt: skip
    ether_type: Optional[str] = field(default=None, metadata={"description": "Ether type of the physical port."})
    identity: Optional[AzureManagedServiceIdentity] = field(default=None, metadata={'description': 'Identity for the resource.'})  # fmt: skip
    links: Optional[List[AzureExpressRouteLink]] = field(default=None, metadata={'description': 'The set of physical links of the ExpressRoutePort resource.'})  # fmt: skip
    mtu: Optional[int] = field(default=None, metadata={'description': 'Maximum transmission unit of the physical port pair(s).'})  # fmt: skip
    peering_location: Optional[str] = field(default=None, metadata={'description': 'The name of the peering location that the ExpressRoutePort is mapped to physically.'})  # fmt: skip
    provisioned_bandwidth_in_gbps: Optional[float] = field(default=None, metadata={'description': 'Aggregate Gbps of associated circuit bandwidths.'})  # fmt: skip
    provisioning_state: Optional[str] = field(default=None, metadata={'description': 'The current provisioning state.'})  # fmt: skip
    resource_guid: Optional[str] = field(default=None, metadata={'description': 'The resource GUID property of the express route port resource.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureExpressRoutePortsLocationBandwidths:
    kind: ClassVar[str] = "azure_express_route_ports_location_bandwidths"
    mapping: ClassVar[Dict[str, Bender]] = {"offer_name": S("offerName"), "value_in_gbps": S("valueInGbps")}
    offer_name: Optional[str] = field(default=None, metadata={"description": "Bandwidth descriptive name."})
    value_in_gbps: Optional[int] = field(default=None, metadata={"description": "Bandwidth value in Gbps."})


@define(eq=False, slots=False)
class AzureExpressRoutePortsLocation(AzureResource):
    kind: ClassVar[str] = "azure_express_route_ports_location"
    api_spec: ClassVar[AzureApiSpec] = AzureApiSpec(
        service="network",
        version="2023-05-01",
        path="/subscriptions/{subscriptionId}/providers/Microsoft.Network/ExpressRoutePortsLocations",
        path_parameters=["subscriptionId"],
        query_parameters=["api-version"],
        access_path="value",
        expect_array=True,
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "address": S("properties", "address"),
        "available_bandwidths": S("properties", "availableBandwidths")
        >> ForallBend(AzureExpressRoutePortsLocationBandwidths.mapping),
        "contact": S("properties", "contact"),
        "provisioning_state": S("properties", "provisioningState"),
    }
    address: Optional[str] = field(default=None, metadata={"description": "Address of peering location."})
    available_bandwidths: Optional[List[AzureExpressRoutePortsLocationBandwidths]] = field(default=None, metadata={'description': 'The inventory of available ExpressRoutePort bandwidths.'})  # fmt: skip
    contact: Optional[str] = field(default=None, metadata={"description": "Contact details of peering locations."})
    provisioning_state: Optional[str] = field(default=None, metadata={'description': 'The current provisioning state.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureFirewallPolicyThreatIntelWhitelist:
    kind: ClassVar[str] = "azure_firewall_policy_threat_intel_whitelist"
    mapping: ClassVar[Dict[str, Bender]] = {"fqdns": S("fqdns"), "ip_addresses": S("ipAddresses")}
    fqdns: Optional[List[str]] = field(default=None, metadata={'description': 'List of FQDNs for the ThreatIntel Whitelist.'})  # fmt: skip
    ip_addresses: Optional[List[str]] = field(default=None, metadata={'description': 'List of IP addresses for the ThreatIntel Whitelist.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureFirewallPolicyLogAnalyticsWorkspace:
    kind: ClassVar[str] = "azure_firewall_policy_log_analytics_workspace"
    mapping: ClassVar[Dict[str, Bender]] = {"region": S("region"), "workspace_id": S("workspaceId", "id")}
    region: Optional[str] = field(default=None, metadata={"description": "Region to configure the Workspace."})
    workspace_id: Optional[str] = field(default=None, metadata={"description": "Reference to another subresource."})


@define(eq=False, slots=False)
class AzureFirewallPolicyLogAnalyticsResources:
    kind: ClassVar[str] = "azure_firewall_policy_log_analytics_resources"
    mapping: ClassVar[Dict[str, Bender]] = {
        "default_workspace_id": S("defaultWorkspaceId", "id"),
        "workspaces": S("workspaces") >> ForallBend(AzureFirewallPolicyLogAnalyticsWorkspace.mapping),
    }
    default_workspace_id: Optional[str] = field(default=None, metadata={'description': 'Reference to another subresource.'})  # fmt: skip
    workspaces: Optional[List[AzureFirewallPolicyLogAnalyticsWorkspace]] = field(default=None, metadata={'description': 'List of workspaces for Firewall Policy Insights.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureFirewallPolicyInsights:
    kind: ClassVar[str] = "azure_firewall_policy_insights"
    mapping: ClassVar[Dict[str, Bender]] = {
        "is_enabled": S("isEnabled"),
        "log_analytics_resources": S("logAnalyticsResources") >> Bend(AzureFirewallPolicyLogAnalyticsResources.mapping),
        "retention_days": S("retentionDays"),
    }
    is_enabled: Optional[bool] = field(default=None, metadata={'description': 'A flag to indicate if the insights are enabled on the policy.'})  # fmt: skip
    log_analytics_resources: Optional[AzureFirewallPolicyLogAnalyticsResources] = field(default=None, metadata={'description': 'Log Analytics Resources for Firewall Policy Insights.'})  # fmt: skip
    retention_days: Optional[int] = field(default=None, metadata={'description': 'Number of days the insights should be enabled on the policy.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureFirewallPolicySNAT:
    kind: ClassVar[str] = "azure_firewall_policy_snat"
    mapping: ClassVar[Dict[str, Bender]] = {
        "auto_learn_private_ranges": S("autoLearnPrivateRanges"),
        "private_ranges": S("privateRanges"),
    }
    auto_learn_private_ranges: Optional[str] = field(default=None, metadata={'description': 'The operation mode for automatically learning private ranges to not be SNAT'})  # fmt: skip
    private_ranges: Optional[List[str]] = field(default=None, metadata={'description': 'List of private IP addresses/IP address ranges to not be SNAT.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureDnsSettings:
    kind: ClassVar[str] = "azure_dns_settings"
    mapping: ClassVar[Dict[str, Bender]] = {
        "enable_proxy": S("enableProxy"),
        "require_proxy_for_network_rules": S("requireProxyForNetworkRules"),
        "servers": S("servers"),
    }
    enable_proxy: Optional[bool] = field(default=None, metadata={'description': 'Enable DNS Proxy on Firewalls attached to the Firewall Policy.'})  # fmt: skip
    require_proxy_for_network_rules: Optional[bool] = field(default=None, metadata={'description': 'FQDNs in Network Rules are supported when set to true.'})  # fmt: skip
    servers: Optional[List[str]] = field(default=None, metadata={"description": "List of Custom DNS Servers."})


@define(eq=False, slots=False)
class AzureExplicitProxy:
    kind: ClassVar[str] = "azure_explicit_proxy"
    mapping: ClassVar[Dict[str, Bender]] = {
        "enable_explicit_proxy": S("enableExplicitProxy"),
        "enable_pac_file": S("enablePacFile"),
        "http_port": S("httpPort"),
        "https_port": S("httpsPort"),
        "pac_file": S("pacFile"),
        "pac_file_port": S("pacFilePort"),
    }
    enable_explicit_proxy: Optional[bool] = field(default=None, metadata={'description': 'When set to true, explicit proxy mode is enabled.'})  # fmt: skip
    enable_pac_file: Optional[bool] = field(default=None, metadata={'description': 'When set to true, pac file port and url needs to be provided.'})  # fmt: skip
    http_port: Optional[int] = field(default=None, metadata={'description': 'Port number for explicit proxy http protocol, cannot be greater than 64000.'})  # fmt: skip
    https_port: Optional[int] = field(default=None, metadata={'description': 'Port number for explicit proxy https protocol, cannot be greater than 64000.'})  # fmt: skip
    pac_file: Optional[str] = field(default=None, metadata={"description": "SAS URL for PAC file."})
    pac_file_port: Optional[int] = field(default=None, metadata={'description': 'Port number for firewall to serve PAC file.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureFirewallPolicyIntrusionDetectionSignatureSpecification:
    kind: ClassVar[str] = "azure_firewall_policy_intrusion_detection_signature_specification"
    mapping: ClassVar[Dict[str, Bender]] = {"id": S("id"), "mode": S("mode")}
    id: Optional[str] = field(default=None, metadata={"description": "Signature id."})
    mode: Optional[str] = field(default=None, metadata={"description": "Possible state values."})


@define(eq=False, slots=False)
class AzureFirewallPolicyIntrusionDetectionBypassTrafficSpecifications:
    kind: ClassVar[str] = "azure_firewall_policy_intrusion_detection_bypass_traffic_specifications"
    mapping: ClassVar[Dict[str, Bender]] = {
        "description": S("description"),
        "destination_addresses": S("destinationAddresses"),
        "destination_ip_groups": S("destinationIpGroups"),
        "destination_ports": S("destinationPorts"),
        "name": S("name"),
        "protocol": S("protocol"),
        "source_addresses": S("sourceAddresses"),
        "source_ip_groups": S("sourceIpGroups"),
    }
    description: Optional[str] = field(default=None, metadata={'description': 'Description of the bypass traffic rule.'})  # fmt: skip
    destination_addresses: Optional[List[str]] = field(default=None, metadata={'description': 'List of destination IP addresses or ranges for this rule.'})  # fmt: skip
    destination_ip_groups: Optional[List[str]] = field(default=None, metadata={'description': 'List of destination IpGroups for this rule.'})  # fmt: skip
    destination_ports: Optional[List[str]] = field(default=None, metadata={'description': 'List of destination ports or ranges.'})  # fmt: skip
    name: Optional[str] = field(default=None, metadata={"description": "Name of the bypass traffic rule."})
    protocol: Optional[str] = field(default=None, metadata={'description': 'Possible intrusion detection bypass traffic protocols.'})  # fmt: skip
    source_addresses: Optional[List[str]] = field(default=None, metadata={'description': 'List of source IP addresses or ranges for this rule.'})  # fmt: skip
    source_ip_groups: Optional[List[str]] = field(default=None, metadata={'description': 'List of source IpGroups for this rule.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureFirewallPolicyIntrusionDetectionConfiguration:
    kind: ClassVar[str] = "azure_firewall_policy_intrusion_detection_configuration"
    mapping: ClassVar[Dict[str, Bender]] = {
        "bypass_traffic_settings": S("bypassTrafficSettings")
        >> ForallBend(AzureFirewallPolicyIntrusionDetectionBypassTrafficSpecifications.mapping),
        "private_ranges": S("privateRanges"),
        "signature_overrides": S("signatureOverrides")
        >> ForallBend(AzureFirewallPolicyIntrusionDetectionSignatureSpecification.mapping),
    }
    bypass_traffic_settings: Optional[List[AzureFirewallPolicyIntrusionDetectionBypassTrafficSpecifications]] = field(default=None, metadata={'description': 'List of rules for traffic to bypass.'})  # fmt: skip
    private_ranges: Optional[List[str]] = field(default=None, metadata={'description': 'IDPS Private IP address ranges are used to identify traffic direction (i.e. inbound, outbound, etc.). By default, only ranges defined by IANA RFC 1918 are considered private IP addresses. To modify default ranges, specify your Private IP address ranges with this property'})  # fmt: skip
    signature_overrides: Optional[List[AzureFirewallPolicyIntrusionDetectionSignatureSpecification]] = field(default=None, metadata={'description': 'List of specific signatures states.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureFirewallPolicyIntrusionDetection:
    kind: ClassVar[str] = "azure_firewall_policy_intrusion_detection"
    mapping: ClassVar[Dict[str, Bender]] = {
        "configuration": S("configuration") >> Bend(AzureFirewallPolicyIntrusionDetectionConfiguration.mapping),
        "mode": S("mode"),
    }
    configuration: Optional[AzureFirewallPolicyIntrusionDetectionConfiguration] = field(default=None, metadata={'description': 'The operation for configuring intrusion detection.'})  # fmt: skip
    mode: Optional[str] = field(default=None, metadata={"description": "Possible state values."})


@define(eq=False, slots=False)
class AzureFirewallPolicyCertificateAuthority:
    kind: ClassVar[str] = "azure_firewall_policy_certificate_authority"
    mapping: ClassVar[Dict[str, Bender]] = {"key_vault_secret_id": S("keyVaultSecretId"), "name": S("name")}
    key_vault_secret_id: Optional[str] = field(default=None, metadata={'description': 'Secret Id of (base-64 encoded unencrypted pfx) Secret or Certificate object stored in KeyVault.'})  # fmt: skip
    name: Optional[str] = field(default=None, metadata={"description": "Name of the CA certificate."})


@define(eq=False, slots=False)
class AzureFirewallPolicyTransportSecurity:
    kind: ClassVar[str] = "azure_firewall_policy_transport_security"
    mapping: ClassVar[Dict[str, Bender]] = {
        "certificate_authority": S("certificateAuthority") >> Bend(AzureFirewallPolicyCertificateAuthority.mapping)
    }
    certificate_authority: Optional[AzureFirewallPolicyCertificateAuthority] = field(default=None, metadata={'description': 'Trusted Root certificates properties for tls.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureFirewallPolicy(AzureResource, BasePolicy):
    kind: ClassVar[str] = "azure_firewall_policy"
    api_spec: ClassVar[AzureApiSpec] = AzureApiSpec(
        service="network",
        version="2023-05-01",
        path="/subscriptions/{subscriptionId}/providers/Microsoft.Network/firewallPolicies",
        path_parameters=["subscriptionId"],
        query_parameters=["api-version"],
        access_path="value",
        expect_array=True,
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "base_policy": S("properties", "basePolicy", "id"),
        "child_policies": S("properties") >> S("childPolicies", default=[]) >> ForallBend(S("id")),
        "firewall_policy_dns_settings": S("properties", "dnsSettings") >> Bend(AzureDnsSettings.mapping),
        "etag": S("etag"),
        "explicit_proxy": S("properties", "explicitProxy") >> Bend(AzureExplicitProxy.mapping),
        "firewalls": S("properties") >> S("firewalls", default=[]) >> ForallBend(S("id")),
        "identity": S("identity") >> Bend(AzureManagedServiceIdentity.mapping),
        "insights": S("properties", "insights") >> Bend(AzureFirewallPolicyInsights.mapping),
        "intrusion_detection": S("properties", "intrusionDetection")
        >> Bend(AzureFirewallPolicyIntrusionDetection.mapping),
        "provisioning_state": S("properties", "provisioningState"),
        "rule_collection_groups": S("properties") >> S("ruleCollectionGroups", default=[]) >> ForallBend(S("id")),
        "size": S("properties", "size") >> StringToUnitNumber("B", expected=int),
        "sku": S("properties", "sku", "tier"),
        "snat": S("properties", "snat") >> Bend(AzureFirewallPolicySNAT.mapping),
        "sql": S("properties", "sql", "allowSqlRedirect"),
        "threat_intel_mode": S("properties", "threatIntelMode"),
        "threat_intel_whitelist": S("properties", "threatIntelWhitelist")
        >> Bend(AzureFirewallPolicyThreatIntelWhitelist.mapping),
        "transport_security": S("properties", "transportSecurity")
        >> Bend(AzureFirewallPolicyTransportSecurity.mapping),
    }
    base_policy: Optional[str] = field(default=None, metadata={"description": "Reference to another subresource."})
    child_policies: Optional[List[str]] = field(default=None, metadata={'description': 'List of references to Child Firewall Policies.'})  # fmt: skip
    firewall_policy_dns_settings_settings: Optional[AzureDnsSettings] = field(default=None, metadata={'description': 'DNS Proxy Settings in Firewall Policy.'})  # fmt: skip
    etag: Optional[str] = field(default=None, metadata={'description': 'A unique read-only string that changes whenever the resource is updated.'})  # fmt: skip
    explicit_proxy: Optional[AzureExplicitProxy] = field(default=None, metadata={'description': 'Explicit Proxy Settings in Firewall Policy.'})  # fmt: skip
    firewalls: Optional[List[str]] = field(default=None, metadata={'description': 'List of references to Azure Firewalls that this Firewall Policy is associated with.'})  # fmt: skip
    identity: Optional[AzureManagedServiceIdentity] = field(default=None, metadata={'description': 'Identity for the resource.'})  # fmt: skip
    insights: Optional[AzureFirewallPolicyInsights] = field(default=None, metadata={'description': 'Firewall Policy Insights.'})  # fmt: skip
    intrusion_detection: Optional[AzureFirewallPolicyIntrusionDetection] = field(default=None, metadata={'description': 'Configuration for intrusion detection mode and rules.'})  # fmt: skip
    provisioning_state: Optional[str] = field(default=None, metadata={'description': 'The current provisioning state.'})  # fmt: skip
    rule_collection_groups: Optional[List[str]] = field(default=None, metadata={'description': 'List of references to FirewallPolicyRuleCollectionGroups.'})  # fmt: skip
    size: Optional[int] = field(default=None, metadata={'description': 'A read-only string that represents the size of the FirewallPolicyPropertiesFormat in MB. (ex 0.5MB)'})  # fmt: skip
    sku: Optional[str] = field(default=None, metadata={"description": "SKU of Firewall policy."})
    snat: Optional[AzureFirewallPolicySNAT] = field(default=None, metadata={'description': 'The private IP addresses/IP ranges to which traffic will not be SNAT.'})  # fmt: skip
    sql: Optional[bool] = field(default=None, metadata={"description": "SQL Settings in Firewall Policy."})
    threat_intel_mode: Optional[str] = field(default=None, metadata={'description': 'The operation mode for Threat Intel.'})  # fmt: skip
    threat_intel_whitelist: Optional[AzureFirewallPolicyThreatIntelWhitelist] = field(default=None, metadata={'description': 'ThreatIntel Whitelist for Firewall Policy.'})  # fmt: skip
    transport_security: Optional[AzureFirewallPolicyTransportSecurity] = field(default=None, metadata={'description': 'Configuration needed to perform TLS termination & initiation.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureIpAllocation(AzureResource):
    kind: ClassVar[str] = "azure_ip_allocation"
    api_spec: ClassVar[AzureApiSpec] = AzureApiSpec(
        service="network",
        version="2023-05-01",
        path="/subscriptions/{subscriptionId}/providers/Microsoft.Network/IpAllocations",
        path_parameters=["subscriptionId"],
        query_parameters=["api-version"],
        access_path="value",
        expect_array=True,
    )
    reference_kinds: ClassVar[ModelReference] = {
        "predecessors": {"default": ["azure_virtual_network", "azure_subnet"]},
    }
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "allocation_tags": S("properties", "allocationTags"),
        "etag": S("etag"),
        "ipam_allocation_id": S("properties", "ipamAllocationId"),
        "prefix": S("properties", "prefix"),
        "prefix_length": S("properties", "prefixLength"),
        "prefix_type": S("properties", "prefixType"),
        "subnet": S("properties", "subnet", "id"),
        "virtual_network": S("properties", "virtualNetwork", "id"),
    }
    allocation_tags: Optional[Dict[str, str]] = field(default=None, metadata={"description": "IpAllocation tags."})
    etag: Optional[str] = field(default=None, metadata={'description': 'A unique read-only string that changes whenever the resource is updated.'})  # fmt: skip
    ipam_allocation_id: Optional[str] = field(default=None, metadata={"description": "The IPAM allocation ID."})
    prefix: Optional[str] = field(default=None, metadata={"description": "The address prefix for the IpAllocation."})
    prefix_length: Optional[int] = field(default=None, metadata={'description': 'The address prefix length for the IpAllocation.'})  # fmt: skip
    prefix_type: Optional[str] = field(default=None, metadata={"description": "IP address version."})
    subnet: Optional[str] = field(default=None, metadata={"description": "Reference to another subresource."})
    virtual_network: Optional[str] = field(default=None, metadata={"description": "Reference to another subresource."})

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if vn_id := self.virtual_network:
            builder.add_edge(self, edge_type=EdgeType.default, reverse=True, clazz=AzureVirtualNetwork, id=vn_id)
        if subnet_id := self.subnet:
            builder.add_edge(self, edge_type=EdgeType.default, reverse=True, clazz=AzureSubnet, id=subnet_id)


@define(eq=False, slots=False)
class AzureIpGroup(AzureResource):
    kind: ClassVar[str] = "azure_ip_group"
    api_spec: ClassVar[AzureApiSpec] = AzureApiSpec(
        service="network",
        version="2023-05-01",
        path="/subscriptions/{subscriptionId}/providers/Microsoft.Network/ipGroups",
        path_parameters=["subscriptionId"],
        query_parameters=["api-version"],
        access_path="value",
        expect_array=True,
    )
    reference_kinds: ClassVar[ModelReference] = {
        "predecessors": {"default": ["azure_virtual_network"]},
    }
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "etag": S("etag"),
        "firewall_policies": S("properties") >> S("firewallPolicies", default=[]) >> ForallBend(S("id")),
        "firewalls": S("properties") >> S("firewalls", default=[]) >> ForallBend(S("id")),
        "ip_addresses": S("properties", "ipAddresses"),
        "provisioning_state": S("properties", "provisioningState"),
    }
    etag: Optional[str] = field(default=None, metadata={'description': 'A unique read-only string that changes whenever the resource is updated.'})  # fmt: skip
    firewall_policies: Optional[List[str]] = field(default=None, metadata={'description': 'List of references to Firewall Policies resources that this IpGroups is associated with.'})  # fmt: skip
    firewalls: Optional[List[str]] = field(default=None, metadata={'description': 'List of references to Firewall resources that this IpGroups is associated with.'})  # fmt: skip
    ip_addresses: Optional[List[str]] = field(default=None, metadata={'description': 'IpAddresses/IpAddressPrefixes in the IpGroups resource.'})  # fmt: skip
    provisioning_state: Optional[str] = field(default=None, metadata={'description': 'The current provisioning state.'})  # fmt: skip

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if ip_addresses := self.ip_addresses:
            virtual_networks = self._get_virtual_network_ips_and_ids(builder)

            if vns := virtual_networks:
                for ip_address in ip_addresses:
                    for info in vns:
                        vn_ips, vn_id = info
                        for vn_address in vn_ips:
                            if ip_address == vn_address:
                                builder.add_edge(
                                    self, edge_type=EdgeType.default, reverse=True, clazz=AzureVirtualNetwork, id=vn_id
                                )

    def _get_virtual_network_ips_and_ids(self, builder: GraphBuilder) -> List[Tuple[List[str], str]]:
        get_virtual_network_ips: Callable[[AzureVirtualNetwork], List[str]] = lambda vn: (
            rgetattr(vn, "address_space.address_prefixes", None) or []
        )

        return [
            (get_virtual_network_ips(vn), vn_id) for vn in builder.nodes(clazz=AzureVirtualNetwork) if (vn_id := vn.id)
        ]


@define(eq=False, slots=False)
class AzureGatewayLoadBalancerTunnelInterface:
    kind: ClassVar[str] = "azure_gateway_load_balancer_tunnel_interface"
    mapping: ClassVar[Dict[str, Bender]] = {
        "identifier": S("identifier"),
        "port": S("port"),
        "protocol": S("protocol"),
        "type": S("type"),
    }
    identifier: Optional[int] = field(default=None, metadata={'description': 'Identifier of gateway load balancer tunnel interface.'})  # fmt: skip
    port: Optional[int] = field(default=None, metadata={'description': 'Port of gateway load balancer tunnel interface.'})  # fmt: skip
    protocol: Optional[str] = field(default=None, metadata={'description': 'Protocol of gateway load balancer tunnel interface.'})  # fmt: skip
    type: Optional[str] = field(default=None, metadata={'description': 'Traffic type of gateway load balancer tunnel interface.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureNatRulePortMapping:
    kind: ClassVar[str] = "azure_nat_rule_port_mapping"
    mapping: ClassVar[Dict[str, Bender]] = {
        "backend_port": S("backendPort"),
        "frontend_port": S("frontendPort"),
        "inbound_nat_rule_name": S("inboundNatRuleName"),
    }
    backend_port: Optional[int] = field(default=None, metadata={"description": "Backend port."})
    frontend_port: Optional[int] = field(default=None, metadata={"description": "Frontend port."})
    inbound_nat_rule_name: Optional[str] = field(default=None, metadata={"description": "Name of inbound NAT rule."})


@define(eq=False, slots=False)
class AzureLoadBalancerBackendAddress:
    kind: ClassVar[str] = "azure_load_balancer_backend_address"
    mapping: ClassVar[Dict[str, Bender]] = {
        "admin_state": S("properties", "adminState"),
        "inbound_nat_rules_port_mapping": S("properties", "inboundNatRulesPortMapping")
        >> ForallBend(AzureNatRulePortMapping.mapping),
        "ip_address": S("properties", "ipAddress"),
        "load_balancer_frontend_ip_configuration": S("properties", "loadBalancerFrontendIPConfiguration", "id"),
        "name": S("name"),
        "network_interface_ip_configuration": S("properties", "networkInterfaceIPConfiguration", "id"),
        "subnet": S("properties", "subnet", "id"),
        "virtual_network": S("properties", "virtualNetwork", "id"),
    }
    admin_state: Optional[str] = field(default=None, metadata={'description': 'A list of administrative states which once set can override health probe so that Load Balancer will always forward new connections to backend, or deny new connections and reset existing connections.'})  # fmt: skip
    inbound_nat_rules_port_mapping: Optional[List[AzureNatRulePortMapping]] = field(default=None, metadata={'description': 'Collection of inbound NAT rule port mappings.'})  # fmt: skip
    ip_address: Optional[str] = field(default=None, metadata={'description': 'IP Address belonging to the referenced virtual network.'})  # fmt: skip
    load_balancer_frontend_ip_configuration: Optional[str] = field(default=None, metadata={'description': 'Reference to another subresource.'})  # fmt: skip
    name: Optional[str] = field(default=None, metadata={"description": "Name of the backend address."})
    network_interface_ip_configuration: Optional[str] = field(default=None, metadata={'description': 'Reference to another subresource.'})  # fmt: skip
    subnet: Optional[str] = field(default=None, metadata={"description": "Reference to another subresource."})
    virtual_network: Optional[str] = field(default=None, metadata={"description": "Reference to another subresource."})


@define(eq=False, slots=False)
class AzureBackendAddressPool(AzureSubResource):
    kind: ClassVar[str] = "azure_backend_address_pool"
    mapping: ClassVar[Dict[str, Bender]] = AzureSubResource.mapping | {
        "drain_period_in_seconds": S("properties", "drainPeriodInSeconds"),
        "etag": S("etag"),
        "inbound_nat_rules": S("properties") >> S("inboundNatRules", default=[]) >> ForallBend(S("id")),
        "load_balancer_backend_addresses": S("properties", "loadBalancerBackendAddresses")
        >> ForallBend(AzureLoadBalancerBackendAddress.mapping),
        "load_balancing_rules": S("properties") >> S("loadBalancingRules", default=[]) >> ForallBend(S("id")),
        "location": S("properties", "location"),
        "name": S("name"),
        "outbound_rule": S("properties", "outboundRule", "id"),
        "outbound_rules": S("properties") >> S("outboundRules", default=[]) >> ForallBend(S("id")),
        "provisioning_state": S("properties", "provisioningState"),
        "sync_mode": S("properties", "syncMode"),
        "tunnel_interfaces": S("properties", "tunnelInterfaces")
        >> ForallBend(AzureGatewayLoadBalancerTunnelInterface.mapping),
        "type": S("type"),
        "virtual_network": S("properties", "virtualNetwork", "id"),
        "_backend_ip_configuration_ids": S("properties", "backendIPConfigurations", default=[]) >> ForallBend(S("id")),
    }
    drain_period_in_seconds: Optional[int] = field(default=None, metadata={'description': 'Amount of seconds Load Balancer waits for before sending RESET to client and backend address.'})  # fmt: skip
    etag: Optional[str] = field(default=None, metadata={'description': 'A unique read-only string that changes whenever the resource is updated.'})  # fmt: skip
    inbound_nat_rules: Optional[List[str]] = field(default=None, metadata={'description': 'An array of references to inbound NAT rules that use this backend address pool.'})  # fmt: skip
    load_balancer_backend_addresses: Optional[List[AzureLoadBalancerBackendAddress]] = field(default=None, metadata={'description': 'An array of backend addresses.'})  # fmt: skip
    load_balancing_rules: Optional[List[str]] = field(default=None, metadata={'description': 'An array of references to load balancing rules that use this backend address pool.'})  # fmt: skip
    location: Optional[str] = field(default=None, metadata={'description': 'The location of the backend address pool.'})  # fmt: skip
    name: Optional[str] = field(default=None, metadata={'description': 'The name of the resource that is unique within the set of backend address pools used by the load balancer. This name can be used to access the resource.'})  # fmt: skip
    outbound_rule: Optional[str] = field(default=None, metadata={"description": "Reference to another subresource."})
    outbound_rules: Optional[List[str]] = field(default=None, metadata={'description': 'An array of references to outbound rules that use this backend address pool.'})  # fmt: skip
    provisioning_state: Optional[str] = field(default=None, metadata={'description': 'The current provisioning state.'})  # fmt: skip
    sync_mode: Optional[str] = field(default=None, metadata={'description': 'Backend address synchronous mode for the backend pool'})  # fmt: skip
    tunnel_interfaces: Optional[List[AzureGatewayLoadBalancerTunnelInterface]] = field(default=None, metadata={'description': 'An array of gateway load balancer tunnel interfaces.'})  # fmt: skip
    type: Optional[str] = field(default=None, metadata={"description": "Type of the resource."})
    virtual_network: Optional[str] = field(default=None, metadata={"description": "Reference to another subresource."})
    _backend_ip_configuration_ids: Optional[List[str]] = field(
        default=None, metadata={"description": "An array of references to IP addresses defined in network interfaces."}
    )


@define(eq=False, slots=False)
class AzureLoadBalancingRule(AzureSubResource):
    kind: ClassVar[str] = "azure_load_balancing_rule"
    mapping: ClassVar[Dict[str, Bender]] = AzureSubResource.mapping | {
        "backend_address_pool": S("properties", "backendAddressPool", "id"),
        "backend_address_pools": S("properties") >> S("backendAddressPools", default=[]) >> ForallBend(S("id")),
        "backend_port": S("properties", "backendPort"),
        "disable_outbound_snat": S("properties", "disableOutboundSnat"),
        "enable_floating_ip": S("properties", "enableFloatingIP"),
        "enable_tcp_reset": S("properties", "enableTcpReset"),
        "etag": S("etag"),
        "frontend_ip_configuration": S("properties", "frontendIPConfiguration", "id"),
        "frontend_port": S("properties", "frontendPort"),
        "idle_timeout_in_minutes": S("properties", "idleTimeoutInMinutes"),
        "load_distribution": S("properties", "loadDistribution"),
        "name": S("name"),
        "probe": S("properties", "probe", "id"),
        "protocol": S("properties", "protocol"),
        "provisioning_state": S("properties", "provisioningState"),
        "type": S("type"),
    }
    backend_address_pool: Optional[str] = field(default=None, metadata={'description': 'Reference to another subresource.'})  # fmt: skip
    backend_address_pools: Optional[List[str]] = field(default=None, metadata={'description': 'An array of references to pool of DIPs.'})  # fmt: skip
    backend_port: Optional[int] = field(default=None, metadata={'description': 'The port used for internal connections on the endpoint. Acceptable values are between 0 and 65535. Note that value 0 enables Any Port .'})  # fmt: skip
    disable_outbound_snat: Optional[bool] = field(default=None, metadata={'description': 'Configures SNAT for the VMs in the backend pool to use the publicIP address specified in the frontend of the load balancing rule.'})  # fmt: skip
    enable_floating_ip: Optional[bool] = field(default=None, metadata={'description': 'Configures a virtual machine s endpoint for the floating IP capability required to configure a SQL AlwaysOn Availability Group. This setting is required when using the SQL AlwaysOn Availability Groups in SQL server. This setting can t be changed after you create the endpoint.'})  # fmt: skip
    enable_tcp_reset: Optional[bool] = field(default=None, metadata={'description': 'Receive bidirectional TCP Reset on TCP flow idle timeout or unexpected connection termination. This element is only used when the protocol is set to TCP.'})  # fmt: skip
    etag: Optional[str] = field(default=None, metadata={'description': 'A unique read-only string that changes whenever the resource is updated.'})  # fmt: skip
    frontend_ip_configuration: Optional[str] = field(default=None, metadata={'description': 'Reference to another subresource.'})  # fmt: skip
    frontend_port: Optional[int] = field(default=None, metadata={'description': 'The port for the external endpoint. Port numbers for each rule must be unique within the Load Balancer. Acceptable values are between 0 and 65534. Note that value 0 enables Any Port .'})  # fmt: skip
    idle_timeout_in_minutes: Optional[int] = field(default=None, metadata={'description': 'The timeout for the TCP idle connection. The value can be set between 4 and 30 minutes. The default value is 4 minutes. This element is only used when the protocol is set to TCP.'})  # fmt: skip
    load_distribution: Optional[str] = field(default=None, metadata={'description': 'The load distribution policy for this rule.'})  # fmt: skip
    name: Optional[str] = field(default=None, metadata={'description': 'The name of the resource that is unique within the set of load balancing rules used by the load balancer. This name can be used to access the resource.'})  # fmt: skip
    probe: Optional[str] = field(default=None, metadata={"description": "Reference to another subresource."})
    protocol: Optional[str] = field(default=None, metadata={"description": "The transport protocol for the endpoint."})
    provisioning_state: Optional[str] = field(default=None, metadata={'description': 'The current provisioning state.'})  # fmt: skip
    type: Optional[str] = field(default=None, metadata={"description": "Type of the resource."})


@define(eq=False, slots=False)
class AzureProbe(AzureSubResource):
    kind: ClassVar[str] = "azure_probe"
    mapping: ClassVar[Dict[str, Bender]] = AzureSubResource.mapping | {
        "etag": S("etag"),
        "interval_in_seconds": S("properties", "intervalInSeconds"),
        "load_balancing_rules": S("properties") >> S("loadBalancingRules", default=[]) >> ForallBend(S("id")),
        "name": S("name"),
        "number_of_probes": S("properties", "numberOfProbes"),
        "port": S("properties", "port"),
        "probe_threshold": S("properties", "probeThreshold"),
        "protocol": S("properties", "protocol"),
        "provisioning_state": S("properties", "provisioningState"),
        "request_path": S("properties", "requestPath"),
        "type": S("type"),
    }
    etag: Optional[str] = field(default=None, metadata={'description': 'A unique read-only string that changes whenever the resource is updated.'})  # fmt: skip
    interval_in_seconds: Optional[int] = field(default=None, metadata={'description': 'The interval, in seconds, for how frequently to probe the endpoint for health status. Typically, the interval is slightly less than half the allocated timeout period (in seconds) which allows two full probes before taking the instance out of rotation. The default value is 15, the minimum value is 5.'})  # fmt: skip
    load_balancing_rules: Optional[List[str]] = field(default=None, metadata={'description': 'The load balancer rules that use this probe.'})  # fmt: skip
    name: Optional[str] = field(default=None, metadata={'description': 'The name of the resource that is unique within the set of probes used by the load balancer. This name can be used to access the resource.'})  # fmt: skip
    number_of_probes: Optional[int] = field(default=None, metadata={'description': 'The number of probes where if no response, will result in stopping further traffic from being delivered to the endpoint. This values allows endpoints to be taken out of rotation faster or slower than the typical times used in Azure.'})  # fmt: skip
    port: Optional[int] = field(default=None, metadata={'description': 'The port for communicating the probe. Possible values range from 1 to 65535, inclusive.'})  # fmt: skip
    probe_threshold: Optional[int] = field(default=None, metadata={'description': 'The number of consecutive successful or failed probes in order to allow or deny traffic from being delivered to this endpoint. After failing the number of consecutive probes equal to this value, the endpoint will be taken out of rotation and require the same number of successful consecutive probes to be placed back in rotation.'})  # fmt: skip
    protocol: Optional[str] = field(default=None, metadata={'description': 'The protocol of the end point. If Tcp is specified, a received ACK is required for the probe to be successful. If Http or Https is specified, a 200 OK response from the specifies URI is required for the probe to be successful.'})  # fmt: skip
    provisioning_state: Optional[str] = field(default=None, metadata={'description': 'The current provisioning state.'})  # fmt: skip
    request_path: Optional[str] = field(default=None, metadata={'description': 'The URI used for requesting health status from the VM. Path is required if a protocol is set to http. Otherwise, it is not allowed. There is no default value.'})  # fmt: skip
    type: Optional[str] = field(default=None, metadata={"description": "Type of the resource."})


@define(eq=False, slots=False)
class AzureInboundNatPool(AzureSubResource):
    kind: ClassVar[str] = "azure_inbound_nat_pool"
    mapping: ClassVar[Dict[str, Bender]] = AzureSubResource.mapping | {
        "backend_port": S("properties", "backendPort"),
        "enable_floating_ip": S("properties", "enableFloatingIP"),
        "enable_tcp_reset": S("properties", "enableTcpReset"),
        "etag": S("etag"),
        "frontend_ip_configuration": S("properties", "frontendIPConfiguration", "id"),
        "frontend_port_range_end": S("properties", "frontendPortRangeEnd"),
        "frontend_port_range_start": S("properties", "frontendPortRangeStart"),
        "idle_timeout_in_minutes": S("properties", "idleTimeoutInMinutes"),
        "name": S("name"),
        "protocol": S("properties", "protocol"),
        "provisioning_state": S("properties", "provisioningState"),
        "type": S("type"),
    }
    backend_port: Optional[int] = field(default=None, metadata={'description': 'The port used for internal connections on the endpoint. Acceptable values are between 1 and 65535.'})  # fmt: skip
    enable_floating_ip: Optional[bool] = field(default=None, metadata={'description': 'Configures a virtual machine s endpoint for the floating IP capability required to configure a SQL AlwaysOn Availability Group. This setting is required when using the SQL AlwaysOn Availability Groups in SQL server. This setting can t be changed after you create the endpoint.'})  # fmt: skip
    enable_tcp_reset: Optional[bool] = field(default=None, metadata={'description': 'Receive bidirectional TCP Reset on TCP flow idle timeout or unexpected connection termination. This element is only used when the protocol is set to TCP.'})  # fmt: skip
    etag: Optional[str] = field(default=None, metadata={'description': 'A unique read-only string that changes whenever the resource is updated.'})  # fmt: skip
    frontend_ip_configuration: Optional[str] = field(default=None, metadata={'description': 'Reference to another subresource.'})  # fmt: skip
    frontend_port_range_end: Optional[int] = field(default=None, metadata={'description': 'The last port number in the range of external ports that will be used to provide Inbound Nat to NICs associated with a load balancer. Acceptable values range between 1 and 65535.'})  # fmt: skip
    frontend_port_range_start: Optional[int] = field(default=None, metadata={'description': 'The first port number in the range of external ports that will be used to provide Inbound Nat to NICs associated with a load balancer. Acceptable values range between 1 and 65534.'})  # fmt: skip
    idle_timeout_in_minutes: Optional[int] = field(default=None, metadata={'description': 'The timeout for the TCP idle connection. The value can be set between 4 and 30 minutes. The default value is 4 minutes. This element is only used when the protocol is set to TCP.'})  # fmt: skip
    name: Optional[str] = field(default=None, metadata={'description': 'The name of the resource that is unique within the set of inbound NAT pools used by the load balancer. This name can be used to access the resource.'})  # fmt: skip
    protocol: Optional[str] = field(default=None, metadata={"description": "The transport protocol for the endpoint."})
    provisioning_state: Optional[str] = field(default=None, metadata={'description': 'The current provisioning state.'})  # fmt: skip
    type: Optional[str] = field(default=None, metadata={"description": "Type of the resource."})


@define(eq=False, slots=False)
class AzureOutboundRule(AzureSubResource):
    kind: ClassVar[str] = "azure_outbound_rule"
    mapping: ClassVar[Dict[str, Bender]] = AzureSubResource.mapping | {
        "allocated_outbound_ports": S("properties", "allocatedOutboundPorts"),
        "backend_address_pool": S("properties", "backendAddressPool", "id"),
        "enable_tcp_reset": S("properties", "enableTcpReset"),
        "etag": S("etag"),
        "frontend_ip_configurations": S("properties")
        >> S("frontendIPConfigurations", default=[])
        >> ForallBend(S("id")),
        "idle_timeout_in_minutes": S("properties", "idleTimeoutInMinutes"),
        "name": S("name"),
        "protocol": S("properties", "protocol"),
        "provisioning_state": S("properties", "provisioningState"),
        "type": S("type"),
    }
    allocated_outbound_ports: Optional[int] = field(default=None, metadata={'description': 'The number of outbound ports to be used for NAT.'})  # fmt: skip
    backend_address_pool: Optional[str] = field(default=None, metadata={'description': 'Reference to another subresource.'})  # fmt: skip
    enable_tcp_reset: Optional[bool] = field(default=None, metadata={'description': 'Receive bidirectional TCP Reset on TCP flow idle timeout or unexpected connection termination. This element is only used when the protocol is set to TCP.'})  # fmt: skip
    etag: Optional[str] = field(default=None, metadata={'description': 'A unique read-only string that changes whenever the resource is updated.'})  # fmt: skip
    frontend_ip_configurations: Optional[List[str]] = field(default=None, metadata={'description': 'The Frontend IP addresses of the load balancer.'})  # fmt: skip
    idle_timeout_in_minutes: Optional[int] = field(default=None, metadata={'description': 'The timeout for the TCP idle connection.'})  # fmt: skip
    name: Optional[str] = field(default=None, metadata={'description': 'The name of the resource that is unique within the set of outbound rules used by the load balancer. This name can be used to access the resource.'})  # fmt: skip
    protocol: Optional[str] = field(default=None, metadata={'description': 'The protocol for the outbound rule in load balancer.'})  # fmt: skip
    provisioning_state: Optional[str] = field(default=None, metadata={'description': 'The current provisioning state.'})  # fmt: skip
    type: Optional[str] = field(default=None, metadata={"description": "Type of the resource."})


@define(eq=False, slots=False)
class AzureLoadBalancer(AzureResource, BaseLoadBalancer):
    kind: ClassVar[str] = "azure_load_balancer"
    api_spec: ClassVar[AzureApiSpec] = AzureApiSpec(
        service="network",
        version="2023-05-01",
        path="/subscriptions/{subscriptionId}/providers/Microsoft.Network/loadBalancers",
        path_parameters=["subscriptionId"],
        query_parameters=["api-version"],
        access_path="value",
        expect_array=True,
    )
    reference_kinds: ClassVar[ModelReference] = {
        "predecessors": {"default": ["azure_virtual_network", "azure_subnet", "azure_managed_cluster"]},
    }
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "backend_address_pools": S("properties", "backendAddressPools") >> ForallBend(AzureBackendAddressPool.mapping),
        "etag": S("etag"),
        "extended_location": S("extendedLocation") >> Bend(AzureExtendedLocation.mapping),
        "lb_frontend_ip_configurations": S("properties", "frontendIPConfigurations")
        >> ForallBend(AzureFrontendIPConfiguration.mapping),
        "inbound_nat_pools": S("properties", "inboundNatPools") >> ForallBend(AzureInboundNatPool.mapping),
        "inbound_nat_rules": S("properties", "inboundNatRules") >> ForallBend(AzureInboundNatRule.mapping),
        "load_balancing_rules": S("properties", "loadBalancingRules") >> ForallBend(AzureLoadBalancingRule.mapping),
        "outbound_rules": S("properties", "outboundRules") >> ForallBend(AzureOutboundRule.mapping),
        "lb_probes": S("properties", "probes") >> ForallBend(AzureProbe.mapping),
        "provisioning_state": S("properties", "provisioningState"),
        "resource_guid": S("properties", "resourceGuid"),
        "azure_sku": S("sku") >> Bend(AzureSku.mapping),
        "lb_type": S("type"),
        "backends": S("properties", "backendAddressPools")
        >> ForallBend(AzureBackendAddressPool.mapping)
        >> ForallBend(S("virtual_network"), default=[]),
    }
    backend_address_pools: Optional[List[AzureBackendAddressPool]] = field(default=None, metadata={'description': 'Collection of backend address pools used by a load balancer.'})  # fmt: skip
    etag: Optional[str] = field(default=None, metadata={'description': 'A unique read-only string that changes whenever the resource is updated.'})  # fmt: skip
    extended_location: Optional[AzureExtendedLocation] = field(default=None, metadata={'description': 'ExtendedLocation complex type.'})  # fmt: skip
    lb_frontend_ip_configurations: Optional[List[AzureFrontendIPConfiguration]] = field(default=None, metadata={'description': 'Object representing the frontend IPs to be used for the load balancer.'})  # fmt: skip
    inbound_nat_pools: Optional[List[AzureInboundNatPool]] = field(default=None, metadata={'description': 'Defines an external port range for inbound NAT to a single backend port on NICs associated with a load balancer. Inbound NAT rules are created automatically for each NIC associated with the Load Balancer using an external port from this range. Defining an Inbound NAT pool on your Load Balancer is mutually exclusive with defining inbound NAT rules. Inbound NAT pools are referenced from virtual machine scale sets. NICs that are associated with individual virtual machines cannot reference an inbound NAT pool. They have to reference individual inbound NAT rules.'})  # fmt: skip
    inbound_nat_rules: Optional[List[AzureInboundNatRule]] = field(default=None, metadata={'description': 'Collection of inbound NAT Rules used by a load balancer. Defining inbound NAT rules on your load balancer is mutually exclusive with defining an inbound NAT pool. Inbound NAT pools are referenced from virtual machine scale sets. NICs that are associated with individual virtual machines cannot reference an Inbound NAT pool. They have to reference individual inbound NAT rules.'})  # fmt: skip
    load_balancing_rules: Optional[List[AzureLoadBalancingRule]] = field(default=None, metadata={'description': 'Object collection representing the load balancing rules Gets the provisioning.'})  # fmt: skip
    outbound_rules: Optional[List[AzureOutboundRule]] = field(
        default=None, metadata={"description": "The outbound rules."}
    )
    lb_probes: Optional[List[AzureProbe]] = field(default=None, metadata={'description': 'Collection of probe objects used in the load balancer.'})  # fmt: skip
    provisioning_state: Optional[str] = field(default=None, metadata={'description': 'The current provisioning state.'})  # fmt: skip
    resource_guid: Optional[str] = field(default=None, metadata={'description': 'The resource GUID property of the load balancer resource.'})  # fmt: skip
    azure_sku: Optional[AzureSku] = field(default=None, metadata={"description": "SKU of a load balancer."})
    aks_public_ip_address: Optional[str] = field(default=None, metadata={"description": "AKS Load Balancer public IP address."})  # fmt: skip

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if vns := self.backends:
            for vn_id in vns:
                builder.add_edge(self, edge_type=EdgeType.default, reverse=True, clazz=AzureVirtualNetwork, id=vn_id)
        if baps := self.backend_address_pools:
            for bap in baps:
                if lbbas := bap.load_balancer_backend_addresses:
                    for lbba in lbbas:
                        if subnet_id := lbba.subnet:
                            builder.add_edge(
                                self, edge_type=EdgeType.default, reverse=True, clazz=AzureSubnet, id=subnet_id
                            )
        if ip_confs := self.lb_frontend_ip_configurations:
            p_ip_ids_and_cluster_ids = self._get_p_ip_ids_and_cluster_ids(builder)

            publ_ip_id_and_p_ip_address = self._get_publ_ip_id_and_p_ip_address(builder)

            for ip_conf in ip_confs:
                if p_ip_address_id := ip_conf._public_ip_address_id:
                    for info in p_ip_ids_and_cluster_ids:
                        ip_ids, clust_id = info
                        for ip_id in ip_ids:
                            if ip_id == p_ip_address_id:
                                builder.add_edge(
                                    self,
                                    edge_type=EdgeType.default,
                                    reverse=True,
                                    clazz=AzureManagedCluster,
                                    id=clust_id,
                                )
                    for ip_info in publ_ip_id_and_p_ip_address:
                        pub_ip_id, ip_address = ip_info
                        if pub_ip_id == p_ip_address_id:
                            self.aks_public_ip_address = ip_address

    def _get_publ_ip_id_and_p_ip_address(self, builder: GraphBuilder) -> List[Tuple[str, str]]:
        return [
            (pub_ip_id, pub_ip_addr)
            for ip in builder.nodes(clazz=AzurePublicIPAddress)
            if (ip.tags.get("k8s-azure-cluster-name") is not None)
            and (pub_ip_id := ip.id)
            and (pub_ip_addr := ip.ip_address)
        ]

    def _get_p_ip_ids_and_cluster_ids(self, builder: GraphBuilder) -> List[Tuple[List[str], str]]:
        get_p_ip_ids: Callable[[AzureManagedCluster], List[str]] = lambda cluster: (
            rgetattr(cluster, "container_service_network_profile.load_balancer_profile.effective_outbound_i_ps", None)
            or []
        )

        return [
            (get_p_ip_ids(cluster), cluster_id)
            for cluster in builder.nodes(clazz=AzureManagedCluster)
            if (cluster_id := cluster.id)
        ]


@define(eq=False, slots=False)
class AzureContainerNetworkInterfaceConfiguration(AzureSubResource):
    kind: ClassVar[str] = "azure_container_network_interface_configuration"
    mapping: ClassVar[Dict[str, Bender]] = AzureSubResource.mapping | {
        "container_network_interfaces": S("properties")
        >> S("containerNetworkInterfaces", default=[])
        >> ForallBend(S("id")),
        "etag": S("etag"),
        "ip_configurations": S("properties", "ipConfigurations") >> ForallBend(AzureIPConfigurationProfile.mapping),
        "name": S("name"),
        "provisioning_state": S("properties", "provisioningState"),
        "type": S("type"),
    }
    container_network_interfaces: Optional[List[str]] = field(default=None, metadata={'description': 'A list of container network interfaces created from this container network interface configuration.'})  # fmt: skip
    etag: Optional[str] = field(default=None, metadata={'description': 'A unique read-only string that changes whenever the resource is updated.'})  # fmt: skip
    ip_configurations: Optional[List[AzureIPConfigurationProfile]] = field(default=None, metadata={'description': 'A list of ip configurations of the container network interface configuration.'})  # fmt: skip
    name: Optional[str] = field(default=None, metadata={'description': 'The name of the resource. This name can be used to access the resource.'})  # fmt: skip
    provisioning_state: Optional[str] = field(default=None, metadata={'description': 'The current provisioning state.'})  # fmt: skip
    type: Optional[str] = field(default=None, metadata={"description": "Sub Resource type."})


@define(eq=False, slots=False)
class AzureContainer(AzureSubResource):
    kind: ClassVar[str] = "azure_container"
    mapping: ClassVar[Dict[str, Bender]] = AzureSubResource.mapping | {}


@define(eq=False, slots=False)
class AzureContainerNetworkInterfaceIpConfiguration:
    kind: ClassVar[str] = "azure_container_network_interface_ip_configuration"
    mapping: ClassVar[Dict[str, Bender]] = {
        "etag": S("etag"),
        "name": S("name"),
        "properties": S("properties", "provisioningState"),
        "type": S("type"),
    }
    etag: Optional[str] = field(default=None, metadata={'description': 'A unique read-only string that changes whenever the resource is updated.'})  # fmt: skip
    name: Optional[str] = field(default=None, metadata={'description': 'The name of the resource. This name can be used to access the resource.'})  # fmt: skip
    properties: Optional[str] = field(default=None, metadata={'description': 'Properties of the container network interface IP configuration.'})  # fmt: skip
    type: Optional[str] = field(default=None, metadata={"description": "Sub Resource type."})


@define(eq=False, slots=False)
class AzureContainerNetworkInterface(AzureSubResource):
    kind: ClassVar[str] = "azure_container_network_interface"
    mapping: ClassVar[Dict[str, Bender]] = AzureSubResource.mapping | {
        "container": S("properties", "container") >> Bend(AzureContainer.mapping),
        "container_network_interface_configuration": S("properties", "containerNetworkInterfaceConfiguration")
        >> Bend(AzureContainerNetworkInterfaceConfiguration.mapping),
        "etag": S("etag"),
        "ip_configurations": S("properties", "ipConfigurations")
        >> ForallBend(AzureContainerNetworkInterfaceIpConfiguration.mapping),
        "name": S("name"),
        "provisioning_state": S("properties", "provisioningState"),
        "type": S("type"),
    }
    container: Optional[AzureContainer] = field(default=None, metadata={'description': 'Reference to container resource in remote resource provider.'})  # fmt: skip
    container_network_interface_configuration: Optional[AzureContainerNetworkInterfaceConfiguration] = field(default=None, metadata={'description': 'Container network interface configuration child resource.'})  # fmt: skip
    etag: Optional[str] = field(default=None, metadata={'description': 'A unique read-only string that changes whenever the resource is updated.'})  # fmt: skip
    ip_configurations: Optional[List[AzureContainerNetworkInterfaceIpConfiguration]] = field(default=None, metadata={'description': 'Reference to the ip configuration on this container nic.'})  # fmt: skip
    name: Optional[str] = field(default=None, metadata={'description': 'The name of the resource. This name can be used to access the resource.'})  # fmt: skip
    provisioning_state: Optional[str] = field(default=None, metadata={'description': 'The current provisioning state.'})  # fmt: skip
    type: Optional[str] = field(default=None, metadata={"description": "Sub Resource type."})


@define(eq=False, slots=False)
class AzureNetworkProfile(AzureResource):
    kind: ClassVar[str] = "azure_network_profile"
    api_spec: ClassVar[AzureApiSpec] = AzureApiSpec(
        service="network",
        version="2023-05-01",
        path="/subscriptions/{subscriptionId}/providers/Microsoft.Network/networkProfiles",
        path_parameters=["subscriptionId"],
        query_parameters=["api-version"],
        access_path="value",
        expect_array=True,
    )
    reference_kinds: ClassVar[ModelReference] = {
        "predecessors": {"default": ["azure_subnet"]},
        "successors": {"default": ["azure_virtual_machine_base"]},
    }
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "container_network_interface_configurations": S("properties", "containerNetworkInterfaceConfigurations")
        >> ForallBend(AzureContainerNetworkInterfaceConfiguration.mapping),
        "container_network_interfaces": S("properties", "containerNetworkInterfaces")
        >> ForallBend(AzureContainerNetworkInterface.mapping),
        "etag": S("etag"),
        "provisioning_state": S("properties", "provisioningState"),
        "resource_guid": S("properties", "resourceGuid"),
    }
    container_network_interface_configurations: Optional[List[AzureContainerNetworkInterfaceConfiguration]] = field(default=None, metadata={'description': 'List of chid container network interface configurations.'})  # fmt: skip
    container_network_interfaces: Optional[List[AzureContainerNetworkInterface]] = field(default=None, metadata={'description': 'List of child container network interfaces.'})  # fmt: skip
    etag: Optional[str] = field(default=None, metadata={'description': 'A unique read-only string that changes whenever the resource is updated.'})  # fmt: skip
    provisioning_state: Optional[str] = field(default=None, metadata={'description': 'The current provisioning state.'})  # fmt: skip
    resource_guid: Optional[str] = field(default=None, metadata={'description': 'The resource GUID property of the network profile resource.'})  # fmt: skip

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        # Import placed inside the method due to circular import error resolution
        from fix_plugin_azure.resource.compute import (
            AzureVirtualMachineBase,
        )  # pylint: disable=import-outside-toplevel

        if container_nic := self.container_network_interface_configurations:
            ip_confs_and_vm_ids = self._get_ip_config_ids_and_vm_ids(builder)

            for container in container_nic:
                if ip_configurations := container.ip_configurations:
                    for ip_configuration in ip_configurations:
                        if subnet_id := ip_configuration._subnet_id:
                            builder.add_edge(
                                self, edge_type=EdgeType.default, reverse=True, clazz=AzureSubnet, id=subnet_id
                            )
                        if (ni_ids_and_vm_ids := ip_confs_and_vm_ids) and (c_ip_conf_id := ip_configuration.id):
                            for info in ni_ids_and_vm_ids:
                                ip_conf_ids, vm_id = info
                                for ip_conf_id in ip_conf_ids:
                                    if ip_conf_id == c_ip_conf_id:
                                        builder.add_edge(
                                            self, edge_type=EdgeType.default, clazz=AzureVirtualMachineBase, id=vm_id
                                        )

    def _get_ip_config_ids_and_vm_ids(self, builder: GraphBuilder) -> List[Tuple[List[str], str]]:
        get_ip_config_ids: Callable[[AzureNetworkInterface], List[str]] = lambda interface: [
            ip_config.id for ip_config in interface.interface_ip_configurations or [] if ip_config.id is not None
        ]

        return [
            (get_ip_config_ids(interface), vm_id)
            for interface in builder.nodes(clazz=AzureNetworkInterface)
            if (vm_id := interface.virtual_machine)
        ]


@define(eq=False, slots=False)
class AzureVirtualApplianceSkuProperties:
    kind: ClassVar[str] = "azure_virtual_appliance_sku_properties"
    mapping: ClassVar[Dict[str, Bender]] = {
        "bundled_scale_unit": S("bundledScaleUnit"),
        "market_place_version": S("marketPlaceVersion"),
        "vendor": S("vendor"),
    }
    bundled_scale_unit: Optional[str] = field(default=None, metadata={"description": "Virtual Appliance Scale Unit."})
    market_place_version: Optional[str] = field(default=None, metadata={"description": "Virtual Appliance Version."})
    vendor: Optional[str] = field(default=None, metadata={"description": "Virtual Appliance Vendor."})


@define(eq=False, slots=False)
class AzureVirtualApplianceNicProperties:
    kind: ClassVar[str] = "azure_virtual_appliance_nic_properties"
    mapping: ClassVar[Dict[str, Bender]] = {
        "instance_name": S("instanceName"),
        "name": S("name"),
        "private_ip_address": S("privateIpAddress"),
        "public_ip_address": S("publicIpAddress"),
    }
    instance_name: Optional[str] = field(default=None, metadata={"description": "Instance on which nic is attached."})
    name: Optional[str] = field(default=None, metadata={"description": "NIC name."})
    private_ip_address: Optional[str] = field(default=None, metadata={"description": "Private IP address."})
    public_ip_address: Optional[str] = field(default=None, metadata={"description": "Public IP address."})


@define(eq=False, slots=False)
class AzureVirtualApplianceAdditionalNicProperties:
    kind: ClassVar[str] = "azure_virtual_appliance_additional_nic_properties"
    mapping: ClassVar[Dict[str, Bender]] = {"has_public_ip": S("hasPublicIp"), "name": S("name")}
    has_public_ip: Optional[bool] = field(default=None, metadata={'description': 'Flag (true or false) for Intent for Public Ip on additional nic'})  # fmt: skip
    name: Optional[str] = field(default=None, metadata={"description": "Name of additional nic"})


@define(eq=False, slots=False)
class AzureDelegationProperties:
    kind: ClassVar[str] = "azure_delegation_properties"
    mapping: ClassVar[Dict[str, Bender]] = {
        "provisioning_state": S("provisioningState"),
        "service_name": S("serviceName"),
    }
    provisioning_state: Optional[str] = field(default=None, metadata={'description': 'The current provisioning state.'})  # fmt: skip
    service_name: Optional[str] = field(default=None, metadata={'description': 'The service name to which the NVA is delegated.'})  # fmt: skip


@define(eq=False, slots=False)
class AzurePartnerManagedResourceProperties:
    kind: ClassVar[str] = "azure_partner_managed_resource_properties"
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "internal_load_balancer_id": S("internalLoadBalancerId"),
        "standard_load_balancer_id": S("standardLoadBalancerId"),
    }
    id: Optional[str] = field(default=None, metadata={"description": "The partner managed resource id."})
    internal_load_balancer_id: Optional[str] = field(default=None, metadata={'description': 'The partner managed ILB resource id'})  # fmt: skip
    standard_load_balancer_id: Optional[str] = field(default=None, metadata={'description': 'The partner managed SLB resource id'})  # fmt: skip


@define(eq=False, slots=False)
class AzureNetworkVirtualAppliance(AzureResource):
    kind: ClassVar[str] = "azure_network_virtual_appliance"
    api_spec: ClassVar[AzureApiSpec] = AzureApiSpec(
        service="network",
        version="2023-05-01",
        path="/subscriptions/{subscriptionId}/providers/Microsoft.Network/networkVirtualAppliances",
        path_parameters=["subscriptionId"],
        query_parameters=["api-version"],
        access_path="value",
        expect_array=True,
    )
    reference_kinds: ClassVar[ModelReference] = {
        "predecessors": {"default": ["azure_subnet"]},
        "successors": {"default": ["azure_network_virtual_appliance_sku"]},
    }
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "additional_nics": S("properties", "additionalNics")
        >> ForallBend(AzureVirtualApplianceAdditionalNicProperties.mapping),
        "address_prefix": S("properties", "addressPrefix"),
        "boot_strap_configuration_blobs": S("properties", "bootStrapConfigurationBlobs"),
        "cloud_init_configuration": S("properties", "cloudInitConfiguration"),
        "cloud_init_configuration_blobs": S("properties", "cloudInitConfigurationBlobs"),
        "delegation": S("properties", "delegation") >> Bend(AzureDelegationProperties.mapping),
        "deployment_type": S("properties", "deploymentType"),
        "etag": S("etag"),
        "identity": S("identity") >> Bend(AzureManagedServiceIdentity.mapping),
        "inbound_security_rules": S("properties") >> S("inboundSecurityRules", default=[]) >> ForallBend(S("id")),
        "nva_sku": S("properties", "nvaSku") >> Bend(AzureVirtualApplianceSkuProperties.mapping),
        "partner_managed_resource": S("properties", "partnerManagedResource")
        >> Bend(AzurePartnerManagedResourceProperties.mapping),
        "provisioning_state": S("properties", "provisioningState"),
        "ssh_public_key": S("properties", "sshPublicKey"),
        "virtual_appliance_asn": S("properties", "virtualApplianceAsn"),
        "virtual_appliance_connections": S("properties")
        >> S("virtualApplianceConnections", default=[])
        >> ForallBend(S("id")),
        "virtual_appliance_nics": S("properties", "virtualApplianceNics")
        >> ForallBend(AzureVirtualApplianceNicProperties.mapping),
        "virtual_appliance_sites": S("properties") >> S("virtualApplianceSites", default=[]) >> ForallBend(S("id")),
        "virtual_hub": S("properties", "virtualHub", "id"),
    }
    additional_nics: Optional[List[AzureVirtualApplianceAdditionalNicProperties]] = field(default=None, metadata={'description': 'Details required for Additional Network Interface.'})  # fmt: skip
    address_prefix: Optional[str] = field(default=None, metadata={"description": "Address Prefix."})
    boot_strap_configuration_blobs: Optional[List[str]] = field(default=None, metadata={'description': 'BootStrapConfigurationBlobs storage URLs.'})  # fmt: skip
    cloud_init_configuration: Optional[str] = field(default=None, metadata={'description': 'CloudInitConfiguration string in plain text.'})  # fmt: skip
    cloud_init_configuration_blobs: Optional[List[str]] = field(default=None, metadata={'description': 'CloudInitConfigurationBlob storage URLs.'})  # fmt: skip
    delegation: Optional[AzureDelegationProperties] = field(default=None, metadata={'description': 'Properties of the delegation.'})  # fmt: skip
    deployment_type: Optional[str] = field(default=None, metadata={'description': 'The deployment type. PartnerManaged for the SaaS NVA'})  # fmt: skip
    etag: Optional[str] = field(default=None, metadata={'description': 'A unique read-only string that changes whenever the resource is updated.'})  # fmt: skip
    identity: Optional[AzureManagedServiceIdentity] = field(default=None, metadata={'description': 'Identity for the resource.'})  # fmt: skip
    inbound_security_rules: Optional[List[str]] = field(default=None, metadata={'description': 'List of references to InboundSecurityRules.'})  # fmt: skip
    nva_sku: Optional[AzureVirtualApplianceSkuProperties] = field(default=None, metadata={'description': 'Network Virtual Appliance Sku Properties.'})  # fmt: skip
    partner_managed_resource: Optional[AzurePartnerManagedResourceProperties] = field(default=None, metadata={'description': 'Properties of the partner managed resource.'})  # fmt: skip
    provisioning_state: Optional[str] = field(default=None, metadata={'description': 'The current provisioning state.'})  # fmt: skip
    ssh_public_key: Optional[str] = field(default=None, metadata={"description": "Public key for SSH login."})
    virtual_appliance_asn: Optional[int] = field(default=None, metadata={'description': 'VirtualAppliance ASN. Microsoft private, public and IANA reserved ASN are not supported.'})  # fmt: skip
    virtual_appliance_connections: Optional[List[str]] = field(default=None, metadata={'description': 'List of references to VirtualApplianceConnections.'})  # fmt: skip
    virtual_appliance_nics: Optional[List[AzureVirtualApplianceNicProperties]] = field(default=None, metadata={'description': 'List of Virtual Appliance Network Interfaces.'})  # fmt: skip
    virtual_appliance_sites: Optional[List[str]] = field(default=None, metadata={'description': 'List of references to VirtualApplianceSite.'})  # fmt: skip
    virtual_hub: Optional[str] = field(default=None, metadata={"description": "Reference to another subresource."})

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if (nva := self.nva_sku) and (nva_vendor := nva.vendor):
            vendors_in_resource = self._get_va_sku_vendor_and_name(builder)

            if vendors := vendors_in_resource:
                for vendors_info in vendors:
                    vendor_name, nvasku_name = vendors_info
                    if vendor_name == nva_vendor:
                        builder.add_edge(
                            self, edge_type=EdgeType.default, clazz=AzureNetworkVirtualApplianceSku, name=nvasku_name
                        )
                    if virtual_appliances := self.virtual_appliance_nics:
                        nic_name_and_subnet_ids = self._get_nic_name_and_subnet_ids(builder)

                        if nic_name_and_s_ids := nic_name_and_subnet_ids:
                            for va in virtual_appliances:
                                if va_nic_name := va.instance_name:
                                    for nics_and_subnets_info in nic_name_and_s_ids:
                                        nic_name, subnet_ids = nics_and_subnets_info
                                        if va_nic_name == nic_name:
                                            for subnet_id in subnet_ids:
                                                builder.add_edge(
                                                    self,
                                                    edge_type=EdgeType.default,
                                                    reverse=True,
                                                    clazz=AzureSubnet,
                                                    id=subnet_id,
                                                )

    def _get_va_sku_vendor_and_name(self, builder: GraphBuilder) -> List[Tuple[str, str]]:
        return [
            (sku_vendor, sku_name)
            for sku in builder.nodes(clazz=AzureNetworkVirtualApplianceSku)
            if (sku_vendor := sku.vendor) and (sku_name := sku.name)
        ]

    def _get_nic_name_and_subnet_ids(self, builder: GraphBuilder) -> List[Tuple[str, List[str]]]:
        get_ip_conf_subnet_ids: Callable[[AzureNetworkInterface], List[str]] = lambda interface: [
            ip_config._subnet_id
            for ip_config in interface.interface_ip_configurations or []
            if ip_config._subnet_id is not None
        ]

        return [
            (ni_name, get_ip_conf_subnet_ids(interface))
            for interface in builder.nodes(clazz=AzureNetworkInterface)
            if (ni_name := interface.name)
        ]


@define(eq=False, slots=False)
class AzureNetworkVirtualApplianceSkuInstances:
    kind: ClassVar[str] = "azure_network_virtual_appliance_sku_instances"
    mapping: ClassVar[Dict[str, Bender]] = {"instance_count": S("instanceCount"), "scale_unit": S("scaleUnit")}
    instance_count: Optional[int] = field(default=None, metadata={"description": "Instance Count."})
    scale_unit: Optional[str] = field(default=None, metadata={"description": "Scale Unit."})


@define(eq=False, slots=False)
class AzureNetworkVirtualApplianceSku(AzureResource):
    kind: ClassVar[str] = "azure_network_virtual_appliance_sku"
    api_spec: ClassVar[AzureApiSpec] = AzureApiSpec(
        service="network",
        version="2023-04-01",
        path="/subscriptions/{subscriptionId}/providers/Microsoft.Network/networkVirtualApplianceSkus",
        path_parameters=["subscriptionId"],
        query_parameters=["api-version"],
        access_path="value",
        expect_array=True,
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("name"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "available_scale_units": S("properties", "availableScaleUnits")
        >> ForallBend(AzureNetworkVirtualApplianceSkuInstances.mapping),
        "available_versions": S("properties", "availableVersions"),
        "etag": S("etag"),
        "vendor": S("properties", "vendor"),
    }
    available_scale_units: Optional[List[AzureNetworkVirtualApplianceSkuInstances]] = field(default=None, metadata={'description': 'The list of scale units available.'})  # fmt: skip
    available_versions: Optional[List[str]] = field(default=None, metadata={'description': 'Available Network Virtual Appliance versions.'})  # fmt: skip
    etag: Optional[str] = field(default=None, metadata={'description': 'A unique read-only string that changes whenever the resource is updated.'})  # fmt: skip
    vendor: Optional[str] = field(default=None, metadata={"description": "Network Virtual Appliance Sku vendor."})
    _is_provider_link: bool = False


@define(eq=False, slots=False)
class AzureNetworkWatcher(AzureResource):
    kind: ClassVar[str] = "azure_network_watcher"
    api_spec: ClassVar[AzureApiSpec] = AzureApiSpec(
        service="network",
        version="2023-05-01",
        path="/subscriptions/{subscriptionId}/providers/Microsoft.Network/networkWatchers",
        path_parameters=["subscriptionId"],
        query_parameters=["api-version"],
        access_path="value",
        expect_array=True,
    )
    reference_kinds: ClassVar[ModelReference] = {
        "predecessors": {"default": ["azure_virtual_network"]},
    }
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "etag": S("etag"),
        "properties": S("properties", "provisioningState"),
        "location": S("location"),
    }
    etag: Optional[str] = field(default=None, metadata={'description': 'A unique read-only string that changes whenever the resource is updated.'})  # fmt: skip
    properties: Optional[str] = field(default=None, metadata={"description": "The network watcher properties."})
    location: Optional[str] = field(default=None, metadata={"description": "Resource location."})

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if nw_location := self.location:
            virtual_network_locations_and_ids = self._get_virtual_network_locations_and_ids(builder)
            if vns_info := virtual_network_locations_and_ids:
                for info in vns_info:
                    vn_location, vn_id = info
                    if vn_location == nw_location:
                        builder.add_edge(
                            self, edge_type=EdgeType.default, reverse=True, clazz=AzureVirtualNetwork, id=vn_id
                        )

    def _get_virtual_network_locations_and_ids(self, builder: GraphBuilder) -> List[Tuple[str, str]]:
        return [
            (vn_location, vn_id)
            for network in builder.nodes(clazz=AzureVirtualNetwork)
            if (vn_location := network.location) and (vn_id := network.id)
        ]


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
    operation: Optional[str] = field(default=None, metadata={'description': 'Type of the operation: get, read, delete, etc.'})  # fmt: skip
    provider: Optional[str] = field(default=None, metadata={"description": "Service provider: Microsoft Network."})
    resource: Optional[str] = field(default=None, metadata={'description': 'Resource on which the operation is performed.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureAddressSpace:
    kind: ClassVar[str] = "azure_address_space"
    mapping: ClassVar[Dict[str, Bender]] = {"address_prefixes": S("addressPrefixes")}
    address_prefixes: Optional[List[str]] = field(default=None, metadata={'description': 'A list of address blocks reserved for this virtual network in CIDR notation.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureVpnServerConfigurationPolicyGroupMember:
    kind: ClassVar[str] = "azure_vpn_server_configuration_policy_group_member"
    mapping: ClassVar[Dict[str, Bender]] = {
        "attribute_type": S("attributeType"),
        "attribute_value": S("attributeValue"),
        "name": S("name"),
    }
    attribute_type: Optional[str] = field(default=None, metadata={'description': 'The Vpn Policy member attribute type.'})  # fmt: skip
    attribute_value: Optional[str] = field(default=None, metadata={'description': 'The value of Attribute used for this VpnServerConfigurationPolicyGroupMember.'})  # fmt: skip
    name: Optional[str] = field(default=None, metadata={'description': 'Name of the VpnServerConfigurationPolicyGroupMember.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureVpnServerConfigurationPolicyGroup(AzureSubResource):
    kind: ClassVar[str] = "azure_vpn_server_configuration_policy_group"
    mapping: ClassVar[Dict[str, Bender]] = AzureSubResource.mapping | {
        "etag": S("etag"),
        "is_default": S("properties", "isDefault"),
        "name": S("name"),
        "p2_s_connection_configurations": S("properties")
        >> S("p2SConnectionConfigurations", default=[])
        >> ForallBend(S("id")),
        "policy_members": S("properties", "policyMembers")
        >> ForallBend(AzureVpnServerConfigurationPolicyGroupMember.mapping),
        "priority": S("properties", "priority"),
        "provisioning_state": S("properties", "provisioningState"),
        "type": S("type"),
    }
    etag: Optional[str] = field(default=None, metadata={'description': 'A unique read-only string that changes whenever the resource is updated.'})  # fmt: skip
    is_default: Optional[bool] = field(default=None, metadata={'description': 'Shows if this is a Default VpnServerConfigurationPolicyGroup or not.'})  # fmt: skip
    name: Optional[str] = field(default=None, metadata={'description': 'The name of the resource that is unique within a resource group. This name can be used to access the resource.'})  # fmt: skip
    p2_s_connection_configurations: Optional[List[str]] = field(default=None, metadata={'description': 'List of references to P2SConnectionConfigurations.'})  # fmt: skip
    policy_members: Optional[List[AzureVpnServerConfigurationPolicyGroupMember]] = field(default=None, metadata={'description': 'Multiple PolicyMembers for VpnServerConfigurationPolicyGroup.'})  # fmt: skip
    priority: Optional[int] = field(default=None, metadata={'description': 'Priority for VpnServerConfigurationPolicyGroup.'})  # fmt: skip
    provisioning_state: Optional[str] = field(default=None, metadata={'description': 'The current provisioning state.'})  # fmt: skip
    type: Optional[str] = field(default=None, metadata={"description": "Resource type."})


@define(eq=False, slots=False)
class AzureP2SConnectionConfiguration(AzureSubResource):
    kind: ClassVar[str] = "azure_p2_s_connection_configuration"
    mapping: ClassVar[Dict[str, Bender]] = AzureSubResource.mapping | {
        "configuration_policy_group_associations": S("properties")
        >> S("configurationPolicyGroupAssociations", default=[])
        >> ForallBend(S("id")),
        "enable_internet_security": S("properties", "enableInternetSecurity"),
        "etag": S("etag"),
        "name": S("name"),
        "previous_configuration_policy_group_associations": S(
            "properties", "previousConfigurationPolicyGroupAssociations"
        )
        >> ForallBend(AzureVpnServerConfigurationPolicyGroup.mapping),
        "provisioning_state": S("properties", "provisioningState"),
        "routing_configuration": S("properties", "routingConfiguration") >> Bend(AzureRoutingConfiguration.mapping),
        "vpn_client_address_pool": S("properties", "vpnClientAddressPool") >> Bend(AzureAddressSpace.mapping),
    }
    configuration_policy_group_associations: Optional[List[str]] = field(default=None, metadata={'description': 'List of Configuration Policy Groups that this P2SConnectionConfiguration is attached to.'})  # fmt: skip
    enable_internet_security: Optional[bool] = field(default=None, metadata={'description': 'Flag indicating whether the enable internet security flag is turned on for the P2S Connections or not.'})  # fmt: skip
    etag: Optional[str] = field(default=None, metadata={'description': 'A unique read-only string that changes whenever the resource is updated.'})  # fmt: skip
    name: Optional[str] = field(default=None, metadata={'description': 'The name of the resource that is unique within a resource group. This name can be used to access the resource.'})  # fmt: skip
    previous_configuration_policy_group_associations: Optional[List[AzureVpnServerConfigurationPolicyGroup]] = field(default=None, metadata={'description': 'List of previous Configuration Policy Groups that this P2SConnectionConfiguration was attached to.'})  # fmt: skip
    provisioning_state: Optional[str] = field(default=None, metadata={'description': 'The current provisioning state.'})  # fmt: skip
    routing_configuration: Optional[AzureRoutingConfiguration] = field(default=None, metadata={'description': 'Routing Configuration indicating the associated and propagated route tables for this connection.'})  # fmt: skip
    vpn_client_address_pool: Optional[AzureAddressSpace] = field(default=None, metadata={'description': 'AddressSpace contains an array of IP address ranges that can be used by subnets of the virtual network.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureVpnClientConnectionHealth:
    kind: ClassVar[str] = "azure_vpn_client_connection_health"
    mapping: ClassVar[Dict[str, Bender]] = {
        "allocated_ip_addresses": S("allocatedIpAddresses"),
        "total_egress_bytes_transferred": S("totalEgressBytesTransferred"),
        "total_ingress_bytes_transferred": S("totalIngressBytesTransferred"),
        "vpn_client_connections_count": S("vpnClientConnectionsCount"),
    }
    allocated_ip_addresses: Optional[List[str]] = field(default=None, metadata={'description': 'List of allocated ip addresses to the connected p2s vpn clients.'})  # fmt: skip
    total_egress_bytes_transferred: Optional[int] = field(default=None, metadata={'description': 'Total of the Egress Bytes Transferred in this connection.'})  # fmt: skip
    total_ingress_bytes_transferred: Optional[int] = field(default=None, metadata={'description': 'Total of the Ingress Bytes Transferred in this P2S Vpn connection.'})  # fmt: skip
    vpn_client_connections_count: Optional[int] = field(default=None, metadata={'description': 'The total of p2s vpn clients connected at this time to this P2SVpnGateway.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureP2SVpnGateway(AzureResource):
    kind: ClassVar[str] = "azure_p2_s_vpn_gateway"
    api_spec: ClassVar[AzureApiSpec] = AzureApiSpec(
        service="network",
        version="2023-05-01",
        path="/subscriptions/{subscriptionId}/providers/Microsoft.Network/p2svpnGateways",
        path_parameters=["subscriptionId"],
        query_parameters=["api-version"],
        access_path="value",
        expect_array=True,
    )
    reference_kinds: ClassVar[ModelReference] = {
        "successors": {"default": ["azure_virtual_hub"]},
    }
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "custom_dns_servers": S("properties", "customDnsServers"),
        "etag": S("etag"),
        "is_routing_preference_internet": S("properties", "isRoutingPreferenceInternet"),
        "p2_s_connection_configurations": S("properties", "p2SConnectionConfigurations")
        >> ForallBend(AzureP2SConnectionConfiguration.mapping),
        "provisioning_state": S("properties", "provisioningState"),
        "virtual_hub": S("properties", "virtualHub", "id"),
        "vpn_client_connection_health": S("properties", "vpnClientConnectionHealth")
        >> Bend(AzureVpnClientConnectionHealth.mapping),
        "vpn_gateway_scale_unit": S("properties", "vpnGatewayScaleUnit"),
        "vpn_server_configuration": S("properties", "vpnServerConfiguration", "id"),
    }
    custom_dns_servers: Optional[List[str]] = field(default=None, metadata={'description': 'List of all customer specified DNS servers IP addresses.'})  # fmt: skip
    etag: Optional[str] = field(default=None, metadata={'description': 'A unique read-only string that changes whenever the resource is updated.'})  # fmt: skip
    is_routing_preference_internet: Optional[bool] = field(default=None, metadata={'description': 'Enable Routing Preference property for the Public IP Interface of the P2SVpnGateway.'})  # fmt: skip
    p2_s_connection_configurations: Optional[List[AzureP2SConnectionConfiguration]] = field(default=None, metadata={'description': 'List of all p2s connection configurations of the gateway.'})  # fmt: skip
    provisioning_state: Optional[str] = field(default=None, metadata={'description': 'The current provisioning state.'})  # fmt: skip
    virtual_hub: Optional[str] = field(default=None, metadata={"description": "Reference to another subresource."})
    vpn_client_connection_health: Optional[AzureVpnClientConnectionHealth] = field(default=None, metadata={'description': 'VpnClientConnectionHealth properties.'})  # fmt: skip
    vpn_gateway_scale_unit: Optional[int] = field(default=None, metadata={'description': 'The scale unit for this p2s vpn gateway.'})  # fmt: skip
    vpn_server_configuration: Optional[str] = field(default=None, metadata={'description': 'Reference to another subresource.'})  # fmt: skip

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if vh_id := self.virtual_hub:
            builder.add_edge(self, edge_type=EdgeType.default, clazz=AzureVirtualHub, id=vh_id)


@define(eq=False, slots=False)
class AzurePublicIPPrefix(AzureResource):
    kind: ClassVar[str] = "azure_public_ip_prefix"
    api_spec: ClassVar[AzureApiSpec] = AzureApiSpec(
        service="network",
        version="2023-05-01",
        path="/subscriptions/{subscriptionId}/providers/Microsoft.Network/publicIPPrefixes",
        path_parameters=["subscriptionId"],
        query_parameters=["api-version"],
        access_path="value",
        expect_array=True,
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "custom_ip_prefix": S("properties", "customIPPrefix", "id"),
        "etag": S("etag"),
        "extended_location": S("extendedLocation") >> Bend(AzureExtendedLocation.mapping),
        "ip_prefix": S("properties", "ipPrefix"),
        "ip_tags": S("properties", "ipTags") >> ForallBend(AzureIpTag.mapping),
        "load_balancer_frontend_ip_configuration": S("properties", "loadBalancerFrontendIpConfiguration", "id"),
        "_nat_gateway_id": S("properties", "natGateway", "id"),
        "prefix_length": S("properties", "prefixLength"),
        "provisioning_state": S("properties", "provisioningState"),
        "public_ip_address_version": S("properties", "publicIPAddressVersion"),
        "public_ip_addresses": S("properties") >> S("publicIPAddresses", default=[]) >> ForallBend(S("id")),
        "resource_guid": S("properties", "resourceGuid"),
        "azure_sku": S("sku") >> Bend(AzureSku.mapping),
    }
    custom_ip_prefix: Optional[str] = field(default=None, metadata={'description': 'Reference to another subresource.'})  # fmt: skip
    etag: Optional[str] = field(default=None, metadata={'description': 'A unique read-only string that changes whenever the resource is updated.'})  # fmt: skip
    extended_location: Optional[AzureExtendedLocation] = field(default=None, metadata={'description': 'ExtendedLocation complex type.'})  # fmt: skip
    ip_prefix: Optional[str] = field(default=None, metadata={"description": "The allocated Prefix."})
    ip_tags: Optional[List[AzureIpTag]] = field(default=None, metadata={'description': 'The list of tags associated with the public IP prefix.'})  # fmt: skip
    load_balancer_frontend_ip_configuration: Optional[str] = field(default=None, metadata={'description': 'Reference to another subresource.'})  # fmt: skip
    _nat_gateway_id: Optional[str] = field(default=None, metadata={"description": "Nat Gateway resource."})
    prefix_length: Optional[int] = field(default=None, metadata={"description": "The Length of the Public IP Prefix."})
    provisioning_state: Optional[str] = field(default=None, metadata={'description': 'The current provisioning state.'})  # fmt: skip
    public_ip_address_version: Optional[str] = field(default=None, metadata={"description": "IP address version."})
    public_ip_addresses: Optional[List[str]] = field(default=None, metadata={'description': 'The list of all referenced PublicIPAddresses.'})  # fmt: skip
    resource_guid: Optional[str] = field(default=None, metadata={'description': 'The resource GUID property of the public IP prefix resource.'})  # fmt: skip
    azure_sku: Optional[AzureSku] = field(default=None, metadata={"description": "SKU of a public IP prefix."})


@define(eq=False, slots=False)
class AzureRouteFilterRule(AzureSubResource):
    kind: ClassVar[str] = "azure_route_filter_rule"
    mapping: ClassVar[Dict[str, Bender]] = AzureSubResource.mapping | {
        "access": S("properties", "access"),
        "communities": S("properties", "communities"),
        "etag": S("etag"),
        "location": S("location"),
        "name": S("name"),
        "provisioning_state": S("properties", "provisioningState"),
        "route_filter_rule_type": S("properties", "routeFilterRuleType"),
    }
    access: Optional[str] = field(default=None, metadata={"description": "Access to be allowed or denied."})
    communities: Optional[List[str]] = field(default=None, metadata={'description': 'The collection for bgp community values to filter on. e.g. [ 12076:5010 , 12076:5020 ].'})  # fmt: skip
    etag: Optional[str] = field(default=None, metadata={'description': 'A unique read-only string that changes whenever the resource is updated.'})  # fmt: skip
    location: Optional[str] = field(default=None, metadata={"description": "Resource location."})
    name: Optional[str] = field(default=None, metadata={'description': 'The name of the resource that is unique within a resource group. This name can be used to access the resource.'})  # fmt: skip
    provisioning_state: Optional[str] = field(default=None, metadata={'description': 'The current provisioning state.'})  # fmt: skip
    route_filter_rule_type: Optional[str] = field(default=None, metadata={"description": "The rule type of the rule."})


@define(eq=False, slots=False)
class AzureRouteFilter(AzureResource):
    kind: ClassVar[str] = "azure_route_filter"
    api_spec: ClassVar[AzureApiSpec] = AzureApiSpec(
        service="network",
        version="2023-05-01",
        path="/subscriptions/{subscriptionId}/providers/Microsoft.Network/routeFilters",
        path_parameters=["subscriptionId"],
        query_parameters=["api-version"],
        access_path="value",
        expect_array=True,
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "etag": S("etag"),
        "ipv6_peerings": S("properties", "ipv6Peerings") >> ForallBend(AzureExpressRouteCircuitPeering.mapping),
        "filter_peerings": S("properties", "peerings") >> ForallBend(AzureExpressRouteCircuitPeering.mapping),
        "provisioning_state": S("properties", "provisioningState"),
        "filter_rules": S("properties", "rules") >> ForallBend(AzureRouteFilterRule.mapping),
    }
    etag: Optional[str] = field(default=None, metadata={'description': 'A unique read-only string that changes whenever the resource is updated.'})  # fmt: skip
    ipv6_peerings: Optional[List[AzureExpressRouteCircuitPeering]] = field(default=None, metadata={'description': 'A collection of references to express route circuit ipv6 peerings.'})  # fmt: skip
    filter_peerings: Optional[List[AzureExpressRouteCircuitPeering]] = field(default=None, metadata={'description': 'A collection of references to express route circuit peerings.'})  # fmt: skip
    provisioning_state: Optional[str] = field(default=None, metadata={'description': 'The current provisioning state.'})  # fmt: skip
    filter_rules: Optional[List[AzureRouteFilterRule]] = field(default=None, metadata={'description': 'Collection of RouteFilterRules contained within a route filter.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureSecurityPartnerProvider(AzureResource):
    kind: ClassVar[str] = "azure_security_partner_provider"
    api_spec: ClassVar[AzureApiSpec] = AzureApiSpec(
        service="network",
        version="2023-05-01",
        path="/subscriptions/{subscriptionId}/providers/Microsoft.Network/securityPartnerProviders",
        path_parameters=["subscriptionId"],
        query_parameters=["api-version"],
        access_path="value",
        expect_array=True,
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "connection_status": S("properties", "connectionStatus"),
        "etag": S("etag"),
        "provisioning_state": S("properties", "provisioningState"),
        "security_provider_name": S("properties", "securityProviderName"),
        "virtual_hub": S("properties", "virtualHub", "id"),
    }
    connection_status: Optional[str] = field(default=None, metadata={'description': 'The current state of the connection with Security Partner Provider.'})  # fmt: skip
    etag: Optional[str] = field(default=None, metadata={'description': 'A unique read-only string that changes whenever the resource is updated.'})  # fmt: skip
    provisioning_state: Optional[str] = field(default=None, metadata={'description': 'The current provisioning state.'})  # fmt: skip
    security_provider_name: Optional[str] = field(default=None, metadata={"description": "The Security Providers."})
    virtual_hub: Optional[str] = field(default=None, metadata={"description": "Reference to another subresource."})


@define(eq=False, slots=False)
class AzureUsageName:
    kind: ClassVar[str] = "azure_usage_name"
    mapping: ClassVar[Dict[str, Bender]] = {"localized_value": S("localizedValue"), "value": S("value")}
    localized_value: Optional[str] = field(default=None, metadata={'description': 'A localized string describing the resource name.'})  # fmt: skip
    value: Optional[str] = field(default=None, metadata={"description": "A string describing the resource name."})


@define(eq=False, slots=False)
class AzureUsage(AzureResource, BaseNetworkQuota):
    kind: ClassVar[str] = "azure_usage"
    api_spec: ClassVar[AzureApiSpec] = AzureApiSpec(
        service="network",
        version="2023-05-01",
        path="/subscriptions/{subscriptionId}/providers/Microsoft.Network/locations/{location}/usages",
        path_parameters=["location", "subscriptionId"],
        query_parameters=["api-version"],
        access_path="value",
        expect_array=True,
        expected_error_codes=["SubscriptionHasNoUsages"],
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name", "value"),
        "usage_name": S("name") >> Bend(AzureUsageName.mapping),
        "current_value": S("currentValue"),
        "limit": S("limit"),
        "unit": S("unit"),
        "quota_type": S("unit"),
        "quota": S("limit"),
    }
    usage_name: Optional[AzureUsageName] = field(
        default=None, metadata={"description": "The name of the type of usage."}
    )
    current_value: Optional[int] = field(default=None, metadata={"description": "The current value of the usage."})
    limit: Optional[int] = field(default=None, metadata={"description": "The limit of usage."})
    unit: Optional[str] = field(default=None, metadata={"description": "An enum describing the unit of measurement."})


@define(eq=False, slots=False)
class AzureVirtualHubRoute:
    kind: ClassVar[str] = "azure_virtual_hub_route"
    mapping: ClassVar[Dict[str, Bender]] = {
        "address_prefixes": S("addressPrefixes"),
        "next_hop_ip_address": S("nextHopIpAddress"),
    }
    address_prefixes: Optional[List[str]] = field(
        default=None, metadata={"description": "List of all addressPrefixes."}
    )
    next_hop_ip_address: Optional[str] = field(default=None, metadata={"description": "NextHop ip address."})


@define(eq=False, slots=False)
class AzureVirtualHubRouteTable:
    kind: ClassVar[str] = "azure_virtual_hub_route_table"
    mapping: ClassVar[Dict[str, Bender]] = {"routes": S("routes") >> ForallBend(AzureVirtualHubRoute.mapping)}
    routes: Optional[List[AzureVirtualHubRoute]] = field(default=None, metadata={"description": "List of all routes."})


@define(eq=False, slots=False)
class AzureVirtualHubRouteV2:
    kind: ClassVar[str] = "azure_virtual_hub_route_v2"
    mapping: ClassVar[Dict[str, Bender]] = {
        "destination_type": S("destinationType"),
        "destinations": S("destinations"),
        "next_hop_type": S("nextHopType"),
        "next_hops": S("nextHops"),
    }
    destination_type: Optional[str] = field(default=None, metadata={"description": "The type of destinations."})
    destinations: Optional[List[str]] = field(default=None, metadata={"description": "List of all destinations."})
    next_hop_type: Optional[str] = field(default=None, metadata={"description": "The type of next hops."})
    next_hops: Optional[List[str]] = field(default=None, metadata={"description": "NextHops ip address."})


@define(eq=False, slots=False)
class AzureVirtualHubRouteTableV2(AzureSubResource):
    kind: ClassVar[str] = "azure_virtual_hub_route_table_v2"
    mapping: ClassVar[Dict[str, Bender]] = AzureSubResource.mapping | {
        "attached_connections": S("properties", "attachedConnections"),
        "etag": S("etag"),
        "name": S("name"),
        "provisioning_state": S("properties", "provisioningState"),
        "routes": S("properties", "routes") >> ForallBend(AzureVirtualHubRouteV2.mapping),
    }
    attached_connections: Optional[List[str]] = field(default=None, metadata={'description': 'List of all connections attached to this route table v2.'})  # fmt: skip
    etag: Optional[str] = field(default=None, metadata={'description': 'A unique read-only string that changes whenever the resource is updated.'})  # fmt: skip
    name: Optional[str] = field(default=None, metadata={'description': 'The name of the resource that is unique within a resource group. This name can be used to access the resource.'})  # fmt: skip
    provisioning_state: Optional[str] = field(default=None, metadata={'description': 'The current provisioning state.'})  # fmt: skip
    routes: Optional[List[AzureVirtualHubRouteV2]] = field(
        default=None, metadata={"description": "List of all routes."}
    )


@define(eq=False, slots=False)
class AzureVirtualHub(AzureResource):
    kind: ClassVar[str] = "azure_virtual_hub"
    api_spec: ClassVar[AzureApiSpec] = AzureApiSpec(
        service="network",
        version="2023-05-01",
        path="/subscriptions/{subscriptionId}/providers/Microsoft.Network/virtualHubs",
        path_parameters=["subscriptionId"],
        query_parameters=["api-version"],
        access_path="value",
        expect_array=True,
    )
    reference_kinds: ClassVar[ModelReference] = {
        "predecessors": {"default": ["azure_express_route_gateway", "azure_vpn_gateway", "azure_virtual_wan"]},
        "successors": {"default": ["azure_public_ip_address"]},
    }
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "address_prefix": S("properties", "addressPrefix"),
        "allow_branch_to_branch_traffic": S("properties", "allowBranchToBranchTraffic"),
        "azure_firewall": S("properties", "azureFirewall", "id"),
        "bgp_connections": S("properties") >> S("bgpConnections", default=[]) >> ForallBend(S("id")),
        "etag": S("etag"),
        "express_route_gateway": S("properties", "expressRouteGateway", "id"),
        "hub_routing_preference": S("properties", "hubRoutingPreference"),
        "ip_configuration_ids": S("properties") >> S("ipConfigurations", default=[]) >> ForallBend(S("id")),
        "hub_kind": S("kind"),
        "p2s_vpn_gateway": S("properties", "p2SVpnGateway", "id"),
        "preferred_routing_gateway": S("properties", "preferredRoutingGateway"),
        "provisioning_state": S("properties", "provisioningState"),
        "route_maps": S("properties") >> S("routeMaps", default=[]) >> ForallBend(S("id")),
        "virtual_hub_route_table": S("properties", "routeTable") >> Bend(AzureVirtualHubRouteTable.mapping),
        "routing_state": S("properties", "routingState"),
        "security_partner_provider": S("properties", "securityPartnerProvider", "id"),
        "security_provider_name": S("properties", "securityProviderName"),
        "sku": S("properties", "sku"),
        "virtual_hub_route_table_v2s": S("properties", "virtualHubRouteTableV2s")
        >> ForallBend(AzureVirtualHubRouteTableV2.mapping),
        "virtual_router_asn": S("properties", "virtualRouterAsn"),
        "virtual_router_auto_scale_configuration": S(
            "properties", "virtualRouterAutoScaleConfiguration", "minCapacity"
        ),
        "virtual_router_ips": S("properties", "virtualRouterIps"),
        "virtual_wan": S("properties", "virtualWan", "id"),
        "vpn_gateway": S("properties", "vpnGateway", "id"),
    }
    address_prefix: Optional[str] = field(default=None, metadata={'description': 'Address-prefix for this VirtualHub.'})  # fmt: skip
    allow_branch_to_branch_traffic: Optional[bool] = field(default=None, metadata={'description': 'Flag to control transit for VirtualRouter hub.'})  # fmt: skip
    azure_firewall: Optional[str] = field(default=None, metadata={"description": "Reference to another subresource."})
    bgp_connections: Optional[List[str]] = field(default=None, metadata={'description': 'List of references to Bgp Connections.'})  # fmt: skip
    etag: Optional[str] = field(default=None, metadata={'description': 'A unique read-only string that changes whenever the resource is updated.'})  # fmt: skip
    express_route_gateway: Optional[str] = field(default=None, metadata={'description': 'Reference to another subresource.'})  # fmt: skip
    hub_routing_preference: Optional[str] = field(default=None, metadata={'description': 'The hub routing preference gateway types'})  # fmt: skip
    ip_configuration_ids: Optional[List[str]] = field(default=None, metadata={'description': 'List of references to IpConfigurations.'})  # fmt: skip
    hub_kind: Optional[str] = field(default=None, metadata={'description': 'Kind of service virtual hub. This is metadata used for the Azure portal experience for Route Server.'})  # fmt: skip
    p2s_vpn_gateway: Optional[str] = field(default=None, metadata={'description': 'Reference to another subresource.'})  # fmt: skip
    preferred_routing_gateway: Optional[str] = field(default=None, metadata={'description': 'The preferred routing gateway types'})  # fmt: skip
    provisioning_state: Optional[str] = field(default=None, metadata={'description': 'The current provisioning state.'})  # fmt: skip
    route_maps: Optional[List[str]] = field(default=None, metadata={"description": "List of references to RouteMaps."})
    virtual_hub_route_table: Optional[AzureVirtualHubRouteTable] = field(default=None, metadata={'description': 'VirtualHub route table.'})  # fmt: skip
    routing_state: Optional[str] = field(default=None, metadata={'description': 'The current routing state of the VirtualHub.'})  # fmt: skip
    security_partner_provider: Optional[str] = field(default=None, metadata={'description': 'Reference to another subresource.'})  # fmt: skip
    security_provider_name: Optional[str] = field(default=None, metadata={'description': 'The Security Provider name.'})  # fmt: skip
    sku: Optional[str] = field(default=None, metadata={"description": "The sku of this VirtualHub."})
    virtual_hub_route_table_v2s: Optional[List[AzureVirtualHubRouteTableV2]] = field(default=None, metadata={'description': 'List of all virtual hub route table v2s associated with this VirtualHub.'})  # fmt: skip
    virtual_router_asn: Optional[int] = field(default=None, metadata={"description": "VirtualRouter ASN."})
    virtual_router_auto_scale_configuration: Optional[int] = field(default=None, metadata={'description': 'The VirtualHub Router autoscale configuration.'})  # fmt: skip
    virtual_router_ips: Optional[List[str]] = field(default=None, metadata={"description": "VirtualRouter IPs."})
    virtual_wan: Optional[str] = field(default=None, metadata={"description": "Reference to another subresource."})
    vpn_gateway: Optional[str] = field(default=None, metadata={"description": "Reference to another subresource."})

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if er_gateway_id := self.express_route_gateway:
            builder.add_edge(
                self, edge_type=EdgeType.default, reverse=True, clazz=AzureExpressRouteGateway, id=er_gateway_id
            )
        if vpn_gateway_id := self.vpn_gateway:
            builder.add_edge(self, edge_type=EdgeType.default, reverse=True, clazz=AzureVpnGateway, id=vpn_gateway_id)
        if vw_id := self.virtual_wan:
            builder.add_edge(self, edge_type=EdgeType.default, reverse=True, clazz=AzureVirtualWAN, id=vw_id)
        if ip_config_ids := self.ip_configuration_ids:
            ip_conf_ids_and_public_ip_ids = self._get_ip_conf_ids_and_public_ip_ids(builder)

            if p_ip_a_and_ip_conf_ids := ip_conf_ids_and_public_ip_ids:
                for ip_config_id in ip_config_ids:
                    for info in p_ip_a_and_ip_conf_ids:
                        collected_ip_conf_ids, p_ip_address_ids = info
                        for collected_ip_conf_id in collected_ip_conf_ids:
                            if ip_config_id == collected_ip_conf_id:
                                for p_ip_address_id in p_ip_address_ids:
                                    builder.add_edge(
                                        self, edge_type=EdgeType.default, clazz=AzurePublicIPAddress, id=p_ip_address_id
                                    )

    def _get_ip_conf_ids_and_public_ip_ids(self, builder: GraphBuilder) -> List[Tuple[List[str], List[str]]]:
        get_ip_conf_ids: Callable[[AzureNetworkInterface], List[str]] = lambda interface: [
            ip_config.id for ip_config in interface.interface_ip_configurations or [] if ip_config.id is not None
        ]
        get_public_ip_ids: Callable[[AzureNetworkInterface], List[str]] = lambda interface: [
            ip_config._public_ip_id
            for ip_config in interface.interface_ip_configurations or []
            if ip_config._public_ip_id is not None
        ]

        return [
            (get_ip_conf_ids(interface), get_public_ip_ids(interface))
            for interface in builder.nodes(clazz=AzureNetworkInterface)
        ]


@define(eq=False, slots=False)
class AzureDhcpOptions:
    kind: ClassVar[str] = "azure_dhcp_options"
    mapping: ClassVar[Dict[str, Bender]] = {"dns_servers": S("dnsServers")}
    dns_servers: Optional[List[str]] = field(
        default=None, metadata={"description": "The list of DNS servers IP addresses."}
    )


@define(eq=False, slots=False)
class AzureVirtualNetworkBgpCommunities:
    kind: ClassVar[str] = "azure_virtual_network_bgp_communities"
    mapping: ClassVar[Dict[str, Bender]] = {
        "regional_community": S("regionalCommunity"),
        "virtual_network_community": S("virtualNetworkCommunity"),
    }
    regional_community: Optional[str] = field(default=None, metadata={'description': 'The BGP community associated with the region of the virtual network.'})  # fmt: skip
    virtual_network_community: Optional[str] = field(default=None, metadata={'description': 'The BGP community associated with the virtual network.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureVirtualNetworkEncryption:
    kind: ClassVar[str] = "azure_virtual_network_encryption"
    mapping: ClassVar[Dict[str, Bender]] = {"enabled": S("enabled"), "enforcement": S("enforcement")}
    enabled: Optional[bool] = field(default=None, metadata={'description': 'Indicates if encryption is enabled on the virtual network.'})  # fmt: skip
    enforcement: Optional[str] = field(default=None, metadata={'description': 'If the encrypted VNet allows VM that does not support encryption'})  # fmt: skip


@define(eq=False, slots=False)
class AzureVirtualNetworkPeering(AzureSubResource):
    kind: ClassVar[str] = "azure_virtual_network_peering"
    mapping: ClassVar[Dict[str, Bender]] = AzureSubResource.mapping | {
        "allow_forwarded_traffic": S("properties", "allowForwardedTraffic"),
        "allow_gateway_transit": S("properties", "allowGatewayTransit"),
        "allow_virtual_network_access": S("properties", "allowVirtualNetworkAccess"),
        "do_not_verify_remote_gateways": S("properties", "doNotVerifyRemoteGateways"),
        "etag": S("etag"),
        "name": S("name"),
        "peering_state": S("properties", "peeringState"),
        "peering_sync_level": S("properties", "peeringSyncLevel"),
        "provisioning_state": S("properties", "provisioningState"),
        "remote_address_space": S("properties", "remoteAddressSpace") >> Bend(AzureAddressSpace.mapping),
        "remote_bgp_communities": S("properties", "remoteBgpCommunities")
        >> Bend(AzureVirtualNetworkBgpCommunities.mapping),
        "remote_virtual_network": S("properties", "remoteVirtualNetwork", "id"),
        "remote_virtual_network_address_space": S("properties", "remoteVirtualNetworkAddressSpace")
        >> Bend(AzureAddressSpace.mapping),
        "remote_virtual_network_encryption": S("properties", "remoteVirtualNetworkEncryption")
        >> Bend(AzureVirtualNetworkEncryption.mapping),
        "resource_guid": S("properties", "resourceGuid"),
        "type": S("type"),
        "use_remote_gateways": S("properties", "useRemoteGateways"),
    }
    allow_forwarded_traffic: Optional[bool] = field(default=None, metadata={'description': 'Whether the forwarded traffic from the VMs in the local virtual network will be allowed/disallowed in remote virtual network.'})  # fmt: skip
    allow_gateway_transit: Optional[bool] = field(default=None, metadata={'description': 'If gateway links can be used in remote virtual networking to link to this virtual network.'})  # fmt: skip
    allow_virtual_network_access: Optional[bool] = field(default=None, metadata={'description': 'Whether the VMs in the local virtual network space would be able to access the VMs in remote virtual network space.'})  # fmt: skip
    do_not_verify_remote_gateways: Optional[bool] = field(default=None, metadata={'description': 'If we need to verify the provisioning state of the remote gateway.'})  # fmt: skip
    etag: Optional[str] = field(default=None, metadata={'description': 'A unique read-only string that changes whenever the resource is updated.'})  # fmt: skip
    name: Optional[str] = field(default=None, metadata={'description': 'The name of the resource that is unique within a resource group. This name can be used to access the resource.'})  # fmt: skip
    peering_state: Optional[str] = field(default=None, metadata={'description': 'The status of the virtual network peering.'})  # fmt: skip
    peering_sync_level: Optional[str] = field(default=None, metadata={'description': 'The peering sync status of the virtual network peering.'})  # fmt: skip
    provisioning_state: Optional[str] = field(default=None, metadata={'description': 'The current provisioning state.'})  # fmt: skip
    remote_address_space: Optional[AzureAddressSpace] = field(default=None, metadata={'description': 'AddressSpace contains an array of IP address ranges that can be used by subnets of the virtual network.'})  # fmt: skip
    remote_bgp_communities: Optional[AzureVirtualNetworkBgpCommunities] = field(default=None, metadata={'description': 'Bgp Communities sent over ExpressRoute with each route corresponding to a prefix in this VNET.'})  # fmt: skip
    remote_virtual_network: Optional[str] = field(default=None, metadata={'description': 'Reference to another subresource.'})  # fmt: skip
    remote_virtual_network_address_space: Optional[AzureAddressSpace] = field(default=None, metadata={'description': 'AddressSpace contains an array of IP address ranges that can be used by subnets of the virtual network.'})  # fmt: skip
    remote_virtual_network_encryption: Optional[AzureVirtualNetworkEncryption] = field(default=None, metadata={'description': 'Indicates if encryption is enabled on virtual network and if VM without encryption is allowed in encrypted VNet.'})  # fmt: skip
    resource_guid: Optional[str] = field(default=None, metadata={'description': 'The resourceGuid property of the Virtual Network peering resource.'})  # fmt: skip
    type: Optional[str] = field(default=None, metadata={"description": "Resource type."})
    use_remote_gateways: Optional[bool] = field(default=None, metadata={'description': 'If remote gateways can be used on this virtual network. If the flag is set to true, and allowGatewayTransit on remote peering is also true, virtual network will use gateways of remote virtual network for transit. Only one peering can have this flag set to true. This flag cannot be set if virtual network already has a gateway.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureVirtualNetwork(AzureResource, BaseNetwork):
    kind: ClassVar[str] = "azure_virtual_network"
    api_spec: ClassVar[AzureApiSpec] = AzureApiSpec(
        service="network",
        version="2023-05-01",
        path="/subscriptions/{subscriptionId}/providers/Microsoft.Network/virtualNetworks",
        path_parameters=["subscriptionId"],
        query_parameters=["api-version"],
        access_path="value",
        expect_array=True,
    )
    reference_kinds: ClassVar[ModelReference] = {
        "successors": {"default": ["azure_subnet"]},
    }
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "address_space": S("properties", "addressSpace") >> Bend(AzureAddressSpace.mapping),
        "bgp_communities": S("properties", "bgpCommunities") >> Bend(AzureVirtualNetworkBgpCommunities.mapping),
        "ddos_protection_plan": S("properties", "ddosProtectionPlan", "id"),
        "dhcp_options": S("properties", "dhcpOptions") >> Bend(AzureDhcpOptions.mapping),
        "enable_ddos_protection": S("properties", "enableDdosProtection"),
        "enable_vm_protection": S("properties", "enableVmProtection"),
        "virtual_network_encryption": S("properties", "encryption") >> Bend(AzureVirtualNetworkEncryption.mapping),
        "etag": S("etag"),
        "extended_location": S("extendedLocation") >> Bend(AzureExtendedLocation.mapping),
        "flow_logs": S("properties", "flowLogs") >> ForallBend(AzureFlowLog.mapping),
        "flow_timeout_in_minutes": S("properties", "flowTimeoutInMinutes"),
        "ip_allocations": S("properties") >> S("ipAllocations", default=[]) >> ForallBend(S("id")),
        "provisioning_state": S("properties", "provisioningState"),
        "resource_guid": S("properties", "resourceGuid"),
        "_subnet_ids": S("properties", "subnets", default=[]) >> ForallBend(S("id")),
        "virtual_network_peerings": S("properties", "virtualNetworkPeerings")
        >> ForallBend(AzureVirtualNetworkPeering.mapping),
        "location": S("location"),
    }
    address_space: Optional[AzureAddressSpace] = field(default=None, metadata={'description': 'AddressSpace contains an array of IP address ranges that can be used by subnets of the virtual network.'})  # fmt: skip
    bgp_communities: Optional[AzureVirtualNetworkBgpCommunities] = field(default=None, metadata={'description': 'Bgp Communities sent over ExpressRoute with each route corresponding to a prefix in this VNET.'})  # fmt: skip
    ddos_protection_plan: Optional[str] = field(default=None, metadata={'description': 'Reference to another subresource.'})  # fmt: skip
    dhcp_options: Optional[AzureDhcpOptions] = field(default=None, metadata={'description': 'DhcpOptions contains an array of DNS servers available to VMs deployed in the virtual network. Standard DHCP option for a subnet overrides VNET DHCP options.'})  # fmt: skip
    enable_ddos_protection: Optional[bool] = field(default=None, metadata={'description': 'Indicates if DDoS protection is enabled for all the protected resources in the virtual network. It requires a DDoS protection plan associated with the resource.'})  # fmt: skip
    enable_vm_protection: Optional[bool] = field(default=None, metadata={'description': 'Indicates if VM protection is enabled for all the subnets in the virtual network.'})  # fmt: skip
    virtual_network_encryption: Optional[AzureVirtualNetworkEncryption] = field(default=None, metadata={'description': 'Indicates if encryption is enabled on virtual network and if VM without encryption is allowed in encrypted VNet.'})  # fmt: skip
    etag: Optional[str] = field(default=None, metadata={'description': 'A unique read-only string that changes whenever the resource is updated.'})  # fmt: skip
    extended_location: Optional[AzureExtendedLocation] = field(default=None, metadata={'description': 'ExtendedLocation complex type.'})  # fmt: skip
    flow_logs: Optional[List[AzureFlowLog]] = field(default=None, metadata={'description': 'A collection of references to flow log resources.'})  # fmt: skip
    flow_timeout_in_minutes: Optional[int] = field(default=None, metadata={'description': 'The FlowTimeout value (in minutes) for the Virtual Network'})  # fmt: skip
    ip_allocations: Optional[List[str]] = field(default=None, metadata={'description': 'Array of IpAllocation which reference this VNET.'})  # fmt: skip
    provisioning_state: Optional[str] = field(default=None, metadata={'description': 'The current provisioning state.'})  # fmt: skip
    resource_guid: Optional[str] = field(default=None, metadata={'description': 'The resourceGuid property of the Virtual Network resource.'})  # fmt: skip
    _subnet_ids: Optional[List[str]] = field(default=None, metadata={'description': 'A list of subnets in a Virtual Network.'})  # fmt: skip
    virtual_network_peerings: Optional[List[AzureVirtualNetworkPeering]] = field(default=None, metadata={'description': 'A list of peerings in a Virtual Network.'})  # fmt: skip
    location: Optional[str] = field(default=None, metadata={"description": "Resource location."})

    def post_process(self, graph_builder: GraphBuilder, source: Json) -> None:
        def collect_subnets() -> None:
            api_spec = AzureApiSpec(
                service="network",
                version="2023-05-01",
                path=f"{self.id}/subnets",
                path_parameters=[],
                query_parameters=["api-version"],
                access_path="value",
                expect_array=True,
            )

            items = graph_builder.client.list(api_spec)
            AzureSubnet.collect(items, graph_builder)

        graph_builder.submit_work("azure_virtual_network", collect_subnets)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if subnets := self._subnet_ids:
            for subnet_id in subnets:
                builder.add_edge(self, edge_type=EdgeType.default, clazz=AzureSubnet, id=subnet_id)


@define(eq=False, slots=False)
class AzureVirtualRouter(AzureResource):
    kind: ClassVar[str] = "azure_virtual_router"
    api_spec: ClassVar[AzureApiSpec] = AzureApiSpec(
        service="network",
        version="2023-05-01",
        path="/subscriptions/{subscriptionId}/providers/Microsoft.Network/virtualRouters",
        path_parameters=["subscriptionId"],
        query_parameters=["api-version"],
        access_path="value",
        expect_array=True,
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "etag": S("etag"),
        "hosted_gateway": S("properties", "hostedGateway", "id"),
        "hosted_subnet": S("properties", "hostedSubnet", "id"),
        "peerings": S("properties") >> S("peerings", default=[]) >> ForallBend(S("id")),
        "provisioning_state": S("properties", "provisioningState"),
        "virtual_router_asn": S("properties", "virtualRouterAsn"),
        "virtual_router_ips": S("properties", "virtualRouterIps"),
    }
    etag: Optional[str] = field(default=None, metadata={'description': 'A unique read-only string that changes whenever the resource is updated.'})  # fmt: skip
    hosted_gateway: Optional[str] = field(default=None, metadata={"description": "Reference to another subresource."})
    hosted_subnet: Optional[str] = field(default=None, metadata={"description": "Reference to another subresource."})
    peerings: Optional[List[str]] = field(default=None, metadata={'description': 'List of references to VirtualRouterPeerings.'})  # fmt: skip
    provisioning_state: Optional[str] = field(default=None, metadata={'description': 'The current provisioning state.'})  # fmt: skip
    virtual_router_asn: Optional[int] = field(default=None, metadata={"description": "VirtualRouter ASN."})
    virtual_router_ips: Optional[List[str]] = field(default=None, metadata={"description": "VirtualRouter IPs."})


@define(eq=False, slots=False)
class AzureVirtualWAN(AzureResource):
    kind: ClassVar[str] = "azure_virtual_wan"
    api_spec: ClassVar[AzureApiSpec] = AzureApiSpec(
        service="network",
        version="2023-05-01",
        path="/subscriptions/{subscriptionId}/providers/Microsoft.Network/virtualWans",
        path_parameters=["subscriptionId"],
        query_parameters=["api-version"],
        access_path="value",
        expect_array=True,
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "allow_branch_to_branch_traffic": S("properties", "allowBranchToBranchTraffic"),
        "allow_vnet_to_vnet_traffic": S("properties", "allowVnetToVnetTraffic"),
        "disable_vpn_encryption": S("properties", "disableVpnEncryption"),
        "etag": S("etag"),
        "office365_local_breakout_category": S("properties", "office365LocalBreakoutCategory"),
        "provisioning_state": S("properties", "provisioningState"),
        "virtual_hubs": S("properties") >> S("virtualHubs", default=[]) >> ForallBend(S("id")),
        "vpn_sites": S("properties") >> S("vpnSites", default=[]) >> ForallBend(S("id")),
    }
    allow_branch_to_branch_traffic: Optional[bool] = field(default=None, metadata={'description': 'True if branch to branch traffic is allowed.'})  # fmt: skip
    allow_vnet_to_vnet_traffic: Optional[bool] = field(default=None, metadata={'description': 'True if Vnet to Vnet traffic is allowed.'})  # fmt: skip
    disable_vpn_encryption: Optional[bool] = field(default=None, metadata={'description': 'Vpn encryption to be disabled or not.'})  # fmt: skip
    etag: Optional[str] = field(default=None, metadata={'description': 'A unique read-only string that changes whenever the resource is updated.'})  # fmt: skip
    office365_local_breakout_category: Optional[str] = field(default=None, metadata={'description': 'The office traffic category.'})  # fmt: skip
    provisioning_state: Optional[str] = field(default=None, metadata={'description': 'The current provisioning state.'})  # fmt: skip
    virtual_hubs: Optional[List[str]] = field(default=None, metadata={'description': 'List of VirtualHubs in the VirtualWAN.'})  # fmt: skip
    vpn_sites: Optional[List[str]] = field(
        default=None, metadata={"description": "List of VpnSites in the VirtualWAN."}
    )


@define(eq=False, slots=False)
class AzureIpsecPolicy:
    kind: ClassVar[str] = "azure_ipsec_policy"
    mapping: ClassVar[Dict[str, Bender]] = {
        "dh_group": S("dhGroup"),
        "ike_encryption": S("ikeEncryption"),
        "ike_integrity": S("ikeIntegrity"),
        "ipsec_encryption": S("ipsecEncryption"),
        "ipsec_integrity": S("ipsecIntegrity"),
        "pfs_group": S("pfsGroup"),
        "sa_data_size_kilobytes": S("saDataSizeKilobytes"),
        "sa_life_time_seconds": S("saLifeTimeSeconds"),
    }
    dh_group: Optional[str] = field(default=None, metadata={'description': 'The DH Groups used in IKE Phase 1 for initial SA.'})  # fmt: skip
    ike_encryption: Optional[str] = field(default=None, metadata={'description': 'The IKE encryption algorithm (IKE phase 2).'})  # fmt: skip
    ike_integrity: Optional[str] = field(default=None, metadata={'description': 'The IKE integrity algorithm (IKE phase 2).'})  # fmt: skip
    ipsec_encryption: Optional[str] = field(default=None, metadata={'description': 'The IPSec encryption algorithm (IKE phase 1).'})  # fmt: skip
    ipsec_integrity: Optional[str] = field(default=None, metadata={'description': 'The IPSec integrity algorithm (IKE phase 1).'})  # fmt: skip
    pfs_group: Optional[str] = field(default=None, metadata={'description': 'The Pfs Groups used in IKE Phase 2 for new child SA.'})  # fmt: skip
    sa_data_size_kilobytes: Optional[int] = field(default=None, metadata={'description': 'The IPSec Security Association (also called Quick Mode or Phase 2 SA) payload size in KB for a site to site VPN tunnel.'})  # fmt: skip
    sa_life_time_seconds: Optional[int] = field(default=None, metadata={'description': 'The IPSec Security Association (also called Quick Mode or Phase 2 SA) lifetime in seconds for a site to site VPN tunnel.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureTrafficSelectorPolicy:
    kind: ClassVar[str] = "azure_traffic_selector_policy"
    mapping: ClassVar[Dict[str, Bender]] = {
        "local_address_ranges": S("localAddressRanges"),
        "remote_address_ranges": S("remoteAddressRanges"),
    }
    local_address_ranges: Optional[List[str]] = field(default=None, metadata={'description': 'A collection of local address spaces in CIDR format.'})  # fmt: skip
    remote_address_ranges: Optional[List[str]] = field(default=None, metadata={'description': 'A collection of remote address spaces in CIDR format.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureGatewayCustomBgpIpAddressIpConfiguration:
    kind: ClassVar[str] = "azure_gateway_custom_bgp_ip_address_ip_configuration"
    mapping: ClassVar[Dict[str, Bender]] = {
        "custom_bgp_ip_address": S("customBgpIpAddress"),
        "ip_configuration_id": S("ipConfigurationId"),
    }
    custom_bgp_ip_address: Optional[str] = field(default=None, metadata={'description': 'The custom BgpPeeringAddress which belongs to IpconfigurationId.'})  # fmt: skip
    ip_configuration_id: Optional[str] = field(default=None, metadata={'description': 'The IpconfigurationId of ipconfiguration which belongs to gateway.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureVpnSiteLinkConnection(AzureSubResource):
    kind: ClassVar[str] = "azure_vpn_site_link_connection"
    mapping: ClassVar[Dict[str, Bender]] = AzureSubResource.mapping | {
        "connection_bandwidth": S("properties", "connectionBandwidth"),
        "connection_status": S("properties", "connectionStatus"),
        "egress_bytes_transferred": S("properties", "egressBytesTransferred"),
        "egress_nat_rules": S("properties") >> S("egressNatRules", default=[]) >> ForallBend(S("id")),
        "enable_bgp": S("properties", "enableBgp"),
        "enable_rate_limiting": S("properties", "enableRateLimiting"),
        "etag": S("etag"),
        "ingress_bytes_transferred": S("properties", "ingressBytesTransferred"),
        "ingress_nat_rules": S("properties") >> S("ingressNatRules", default=[]) >> ForallBend(S("id")),
        "ipsec_policies": S("properties", "ipsecPolicies") >> ForallBend(AzureIpsecPolicy.mapping),
        "name": S("name"),
        "provisioning_state": S("properties", "provisioningState"),
        "routing_weight": S("properties", "routingWeight"),
        "shared_key": S("properties", "sharedKey"),
        "type": S("type"),
        "use_local_azure_ip_address": S("properties", "useLocalAzureIpAddress"),
        "use_policy_based_traffic_selectors": S("properties", "usePolicyBasedTrafficSelectors"),
        "vpn_connection_protocol_type": S("properties", "vpnConnectionProtocolType"),
        "vpn_gateway_custom_bgp_addresses": S("properties", "vpnGatewayCustomBgpAddresses")
        >> ForallBend(AzureGatewayCustomBgpIpAddressIpConfiguration.mapping),
        "vpn_link_connection_mode": S("properties", "vpnLinkConnectionMode"),
        "vpn_site_link": S("properties", "vpnSiteLink", "id"),
    }
    connection_bandwidth: Optional[int] = field(default=None, metadata={"description": "Expected bandwidth in MBPS."})
    connection_status: Optional[str] = field(default=None, metadata={'description': 'The current state of the vpn connection.'})  # fmt: skip
    egress_bytes_transferred: Optional[int] = field(default=None, metadata={'description': 'Egress bytes transferred.'})  # fmt: skip
    egress_nat_rules: Optional[List[str]] = field(default=None, metadata={"description": "List of egress NatRules."})
    enable_bgp: Optional[bool] = field(default=None, metadata={"description": "EnableBgp flag."})
    enable_rate_limiting: Optional[bool] = field(default=None, metadata={"description": "EnableBgp flag."})
    etag: Optional[str] = field(default=None, metadata={'description': 'A unique read-only string that changes whenever the resource is updated.'})  # fmt: skip
    ingress_bytes_transferred: Optional[int] = field(default=None, metadata={'description': 'Ingress bytes transferred.'})  # fmt: skip
    ingress_nat_rules: Optional[List[str]] = field(default=None, metadata={"description": "List of ingress NatRules."})
    ipsec_policies: Optional[List[AzureIpsecPolicy]] = field(default=None, metadata={'description': 'The IPSec Policies to be considered by this connection.'})  # fmt: skip
    name: Optional[str] = field(default=None, metadata={'description': 'The name of the resource that is unique within a resource group. This name can be used to access the resource.'})  # fmt: skip
    provisioning_state: Optional[str] = field(default=None, metadata={'description': 'The current provisioning state.'})  # fmt: skip
    routing_weight: Optional[int] = field(default=None, metadata={"description": "Routing weight for vpn connection."})
    shared_key: Optional[str] = field(default=None, metadata={"description": "SharedKey for the vpn connection."})
    type: Optional[str] = field(default=None, metadata={"description": "Resource type."})
    use_local_azure_ip_address: Optional[bool] = field(default=None, metadata={'description': 'Use local azure ip to initiate connection.'})  # fmt: skip
    use_policy_based_traffic_selectors: Optional[bool] = field(default=None, metadata={'description': 'Enable policy-based traffic selectors.'})  # fmt: skip
    vpn_connection_protocol_type: Optional[str] = field(default=None, metadata={'description': 'Gateway connection protocol.'})  # fmt: skip
    vpn_gateway_custom_bgp_addresses: Optional[List[AzureGatewayCustomBgpIpAddressIpConfiguration]] = field(default=None, metadata={'description': 'vpnGatewayCustomBgpAddresses used by this connection.'})  # fmt: skip
    vpn_link_connection_mode: Optional[str] = field(default=None, metadata={'description': 'Vpn link connection mode.'})  # fmt: skip
    vpn_site_link: Optional[str] = field(default=None, metadata={"description": "Reference to another subresource."})


@define(eq=False, slots=False)
class AzureVpnConnection(AzureSubResource):
    kind: ClassVar[str] = "azure_vpn_connection"
    mapping: ClassVar[Dict[str, Bender]] = AzureSubResource.mapping | {
        "connection_bandwidth": S("properties", "connectionBandwidth"),
        "connection_status": S("properties", "connectionStatus"),
        "dpd_timeout_seconds": S("properties", "dpdTimeoutSeconds"),
        "egress_bytes_transferred": S("properties", "egressBytesTransferred"),
        "enable_bgp": S("properties", "enableBgp"),
        "enable_internet_security": S("properties", "enableInternetSecurity"),
        "enable_rate_limiting": S("properties", "enableRateLimiting"),
        "etag": S("etag"),
        "ingress_bytes_transferred": S("properties", "ingressBytesTransferred"),
        "ipsec_policies": S("properties", "ipsecPolicies") >> ForallBend(AzureIpsecPolicy.mapping),
        "name": S("name"),
        "provisioning_state": S("properties", "provisioningState"),
        "remote_vpn_site": S("properties", "remoteVpnSite", "id"),
        "routing_configuration": S("properties", "routingConfiguration") >> Bend(AzureRoutingConfiguration.mapping),
        "routing_weight": S("properties", "routingWeight"),
        "shared_key": S("properties", "sharedKey"),
        "traffic_selector_policies": S("properties", "trafficSelectorPolicies")
        >> ForallBend(AzureTrafficSelectorPolicy.mapping),
        "use_local_azure_ip_address": S("properties", "useLocalAzureIpAddress"),
        "use_policy_based_traffic_selectors": S("properties", "usePolicyBasedTrafficSelectors"),
        "vpn_connection_protocol_type": S("properties", "vpnConnectionProtocolType"),
        "vpn_link_connections": S("properties", "vpnLinkConnections") >> ForallBend(AzureVpnSiteLinkConnection.mapping),
    }
    connection_bandwidth: Optional[int] = field(default=None, metadata={"description": "Expected bandwidth in MBPS."})
    connection_status: Optional[str] = field(default=None, metadata={'description': 'The current state of the vpn connection.'})  # fmt: skip
    dpd_timeout_seconds: Optional[int] = field(default=None, metadata={'description': 'DPD timeout in seconds for vpn connection.'})  # fmt: skip
    egress_bytes_transferred: Optional[int] = field(default=None, metadata={'description': 'Egress bytes transferred.'})  # fmt: skip
    enable_bgp: Optional[bool] = field(default=None, metadata={"description": "EnableBgp flag."})
    enable_internet_security: Optional[bool] = field(default=None, metadata={'description': 'Enable internet security.'})  # fmt: skip
    enable_rate_limiting: Optional[bool] = field(default=None, metadata={"description": "EnableBgp flag."})
    etag: Optional[str] = field(default=None, metadata={'description': 'A unique read-only string that changes whenever the resource is updated.'})  # fmt: skip
    ingress_bytes_transferred: Optional[int] = field(default=None, metadata={'description': 'Ingress bytes transferred.'})  # fmt: skip
    ipsec_policies: Optional[List[AzureIpsecPolicy]] = field(default=None, metadata={'description': 'The IPSec Policies to be considered by this connection.'})  # fmt: skip
    name: Optional[str] = field(default=None, metadata={'description': 'The name of the resource that is unique within a resource group. This name can be used to access the resource.'})  # fmt: skip
    provisioning_state: Optional[str] = field(default=None, metadata={'description': 'The current provisioning state.'})  # fmt: skip
    remote_vpn_site: Optional[str] = field(default=None, metadata={"description": "Reference to another subresource."})
    routing_configuration: Optional[AzureRoutingConfiguration] = field(default=None, metadata={'description': 'Routing Configuration indicating the associated and propagated route tables for this connection.'})  # fmt: skip
    routing_weight: Optional[int] = field(default=None, metadata={"description": "Routing weight for vpn connection."})
    shared_key: Optional[str] = field(default=None, metadata={"description": "SharedKey for the vpn connection."})
    traffic_selector_policies: Optional[List[AzureTrafficSelectorPolicy]] = field(default=None, metadata={'description': 'The Traffic Selector Policies to be considered by this connection.'})  # fmt: skip
    use_local_azure_ip_address: Optional[bool] = field(default=None, metadata={'description': 'Use local azure ip to initiate connection.'})  # fmt: skip
    use_policy_based_traffic_selectors: Optional[bool] = field(default=None, metadata={'description': 'Enable policy-based traffic selectors.'})  # fmt: skip
    vpn_connection_protocol_type: Optional[str] = field(default=None, metadata={'description': 'Gateway connection protocol.'})  # fmt: skip
    vpn_link_connections: Optional[List[AzureVpnSiteLinkConnection]] = field(default=None, metadata={'description': 'List of all vpn site link connections to the gateway.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureIPConfigurationBgpPeeringAddress:
    kind: ClassVar[str] = "azure_ip_configuration_bgp_peering_address"
    mapping: ClassVar[Dict[str, Bender]] = {
        "custom_bgp_ip_addresses": S("customBgpIpAddresses"),
        "default_bgp_ip_addresses": S("defaultBgpIpAddresses"),
        "ipconfiguration_id": S("ipconfigurationId"),
        "tunnel_ip_addresses": S("tunnelIpAddresses"),
    }
    custom_bgp_ip_addresses: Optional[List[str]] = field(default=None, metadata={'description': 'The list of custom BGP peering addresses which belong to IP configuration.'})  # fmt: skip
    default_bgp_ip_addresses: Optional[List[str]] = field(default=None, metadata={'description': 'The list of default BGP peering addresses which belong to IP configuration.'})  # fmt: skip
    ipconfiguration_id: Optional[str] = field(default=None, metadata={'description': 'The ID of IP configuration which belongs to gateway.'})  # fmt: skip
    tunnel_ip_addresses: Optional[List[str]] = field(default=None, metadata={'description': 'The list of tunnel public IP addresses which belong to IP configuration.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureBgpSettings:
    kind: ClassVar[str] = "azure_bgp_settings"
    mapping: ClassVar[Dict[str, Bender]] = {
        "asn": S("asn"),
        "bgp_peering_address": S("bgpPeeringAddress"),
        "bgp_peering_addresses": S("bgpPeeringAddresses") >> ForallBend(AzureIPConfigurationBgpPeeringAddress.mapping),
        "peer_weight": S("peerWeight"),
    }
    asn: Optional[int] = field(default=None, metadata={"description": "The BGP speaker s ASN."})
    bgp_peering_address: Optional[str] = field(default=None, metadata={'description': 'The BGP peering address and BGP identifier of this BGP speaker.'})  # fmt: skip
    bgp_peering_addresses: Optional[List[AzureIPConfigurationBgpPeeringAddress]] = field(default=None, metadata={'description': 'BGP peering address with IP configuration ID for virtual network gateway.'})  # fmt: skip
    peer_weight: Optional[int] = field(default=None, metadata={'description': 'The weight added to routes learned from this BGP speaker.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureVpnGatewayIpConfiguration:
    kind: ClassVar[str] = "azure_vpn_gateway_ip_configuration"
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "private_ip_address": S("privateIpAddress"),
        "public_ip_address": S("publicIpAddress"),
    }
    id: Optional[str] = field(default=None, metadata={'description': 'The identifier of the IP configuration for a VPN Gateway.'})  # fmt: skip
    private_ip_address: Optional[str] = field(default=None, metadata={'description': 'The private IP address of this IP configuration.'})  # fmt: skip
    public_ip_address: Optional[str] = field(default=None, metadata={'description': 'The public IP address of this IP configuration.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureVpnNatRuleMapping:
    kind: ClassVar[str] = "azure_vpn_nat_rule_mapping"
    mapping: ClassVar[Dict[str, Bender]] = {"address_space": S("addressSpace"), "port_range": S("portRange")}
    address_space: Optional[str] = field(default=None, metadata={'description': 'Address space for Vpn NatRule mapping.'})  # fmt: skip
    port_range: Optional[str] = field(default=None, metadata={"description": "Port range for Vpn NatRule mapping."})


@define(eq=False, slots=False)
class AzureVpnGatewayNatRule(AzureSubResource):
    kind: ClassVar[str] = "azure_vpn_gateway_nat_rule"
    mapping: ClassVar[Dict[str, Bender]] = AzureSubResource.mapping | {
        "egress_vpn_site_link_connections": S("properties")
        >> S("egressVpnSiteLinkConnections", default=[])
        >> ForallBend(S("id")),
        "etag": S("etag"),
        "external_mappings": S("properties", "externalMappings") >> ForallBend(AzureVpnNatRuleMapping.mapping),
        "ingress_vpn_site_link_connections": S("properties")
        >> S("ingressVpnSiteLinkConnections", default=[])
        >> ForallBend(S("id")),
        "internal_mappings": S("properties", "internalMappings") >> ForallBend(AzureVpnNatRuleMapping.mapping),
        "ip_configuration_id": S("properties", "ipConfigurationId"),
        "mode": S("properties", "mode"),
        "name": S("name"),
        "provisioning_state": S("properties", "provisioningState"),
        "type": S("type"),
    }
    egress_vpn_site_link_connections: Optional[List[str]] = field(default=None, metadata={'description': 'List of egress VpnSiteLinkConnections.'})  # fmt: skip
    etag: Optional[str] = field(default=None, metadata={'description': 'A unique read-only string that changes whenever the resource is updated.'})  # fmt: skip
    external_mappings: Optional[List[AzureVpnNatRuleMapping]] = field(default=None, metadata={'description': 'The private IP address external mapping for NAT.'})  # fmt: skip
    ingress_vpn_site_link_connections: Optional[List[str]] = field(default=None, metadata={'description': 'List of ingress VpnSiteLinkConnections.'})  # fmt: skip
    internal_mappings: Optional[List[AzureVpnNatRuleMapping]] = field(default=None, metadata={'description': 'The private IP address internal mapping for NAT.'})  # fmt: skip
    ip_configuration_id: Optional[str] = field(default=None, metadata={'description': 'The IP Configuration ID this NAT rule applies to.'})  # fmt: skip
    mode: Optional[str] = field(default=None, metadata={"description": "The Source NAT direction of a VPN NAT."})
    name: Optional[str] = field(default=None, metadata={'description': 'The name of the resource that is unique within a resource group. This name can be used to access the resource.'})  # fmt: skip
    provisioning_state: Optional[str] = field(default=None, metadata={'description': 'The current provisioning state.'})  # fmt: skip
    type: Optional[str] = field(default=None, metadata={"description": "Resource type."})


@define(eq=False, slots=False)
class AzureVpnGateway(AzureResource, BaseGateway):
    kind: ClassVar[str] = "azure_vpn_gateway"
    api_spec: ClassVar[AzureApiSpec] = AzureApiSpec(
        service="network",
        version="2023-05-01",
        path="/subscriptions/{subscriptionId}/providers/Microsoft.Network/vpnGateways",
        path_parameters=["subscriptionId"],
        query_parameters=["api-version"],
        access_path="value",
        expect_array=True,
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "bgp_settings": S("properties", "bgpSettings") >> Bend(AzureBgpSettings.mapping),
        "connections": S("properties", "connections") >> ForallBend(AzureVpnConnection.mapping),
        "enable_bgp_route_translation_for_nat": S("properties", "enableBgpRouteTranslationForNat"),
        "etag": S("etag"),
        "gateway_ip_configurations": S("properties", "ipConfigurations")
        >> ForallBend(AzureVpnGatewayIpConfiguration.mapping),
        "is_routing_preference_internet": S("properties", "isRoutingPreferenceInternet"),
        "nat_rules": S("properties", "natRules") >> ForallBend(AzureVpnGatewayNatRule.mapping),
        "provisioning_state": S("properties", "provisioningState"),
        "virtual_hub": S("properties", "virtualHub", "id"),
        "vpn_gateway_scale_unit": S("properties", "vpnGatewayScaleUnit"),
    }
    bgp_settings: Optional[AzureBgpSettings] = field(default=None, metadata={"description": "BGP settings details."})
    connections: Optional[List[AzureVpnConnection]] = field(default=None, metadata={'description': 'List of all vpn connections to the gateway.'})  # fmt: skip
    enable_bgp_route_translation_for_nat: Optional[bool] = field(default=None, metadata={'description': 'Enable BGP routes translation for NAT on this VpnGateway.'})  # fmt: skip
    etag: Optional[str] = field(default=None, metadata={'description': 'A unique read-only string that changes whenever the resource is updated.'})  # fmt: skip
    gateway_ip_configurations: Optional[List[AzureVpnGatewayIpConfiguration]] = field(default=None, metadata={'description': 'List of all IPs configured on the gateway.'})  # fmt: skip
    is_routing_preference_internet: Optional[bool] = field(default=None, metadata={'description': 'Enable Routing Preference property for the Public IP Interface of the VpnGateway.'})  # fmt: skip
    nat_rules: Optional[List[AzureVpnGatewayNatRule]] = field(default=None, metadata={'description': 'List of all the nat Rules associated with the gateway.'})  # fmt: skip
    provisioning_state: Optional[str] = field(default=None, metadata={'description': 'The current provisioning state.'})  # fmt: skip
    virtual_hub: Optional[str] = field(default=None, metadata={"description": "Reference to another subresource."})
    vpn_gateway_scale_unit: Optional[int] = field(default=None, metadata={'description': 'The scale unit for this vpn gateway.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureVpnServerConfigVpnClientRootCertificate:
    kind: ClassVar[str] = "azure_vpn_server_config_vpn_client_root_certificate"
    mapping: ClassVar[Dict[str, Bender]] = {"name": S("name"), "public_cert_data": S("publicCertData")}
    name: Optional[str] = field(default=None, metadata={"description": "The certificate name."})
    public_cert_data: Optional[str] = field(default=None, metadata={"description": "The certificate public data."})


@define(eq=False, slots=False)
class AzureVpnServerConfigVpnClientRevokedCertificate:
    kind: ClassVar[str] = "azure_vpn_server_config_vpn_client_revoked_certificate"
    mapping: ClassVar[Dict[str, Bender]] = {"name": S("name"), "thumbprint": S("thumbprint")}
    name: Optional[str] = field(default=None, metadata={"description": "The certificate name."})
    thumbprint: Optional[str] = field(default=None, metadata={'description': 'The revoked VPN client certificate thumbprint.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureVpnServerConfigRadiusServerRootCertificate:
    kind: ClassVar[str] = "azure_vpn_server_config_radius_server_root_certificate"
    mapping: ClassVar[Dict[str, Bender]] = {"name": S("name"), "public_cert_data": S("publicCertData")}
    name: Optional[str] = field(default=None, metadata={"description": "The certificate name."})
    public_cert_data: Optional[str] = field(default=None, metadata={"description": "The certificate public data."})


@define(eq=False, slots=False)
class AzureVpnServerConfigRadiusClientRootCertificate:
    kind: ClassVar[str] = "azure_vpn_server_config_radius_client_root_certificate"
    mapping: ClassVar[Dict[str, Bender]] = {"name": S("name"), "thumbprint": S("thumbprint")}
    name: Optional[str] = field(default=None, metadata={"description": "The certificate name."})
    thumbprint: Optional[str] = field(default=None, metadata={'description': 'The Radius client root certificate thumbprint.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureRadiusServer:
    kind: ClassVar[str] = "azure_radius_server"
    mapping: ClassVar[Dict[str, Bender]] = {
        "radius_server_address": S("radiusServerAddress"),
        "radius_server_score": S("radiusServerScore"),
        "radius_server_secret": S("radiusServerSecret"),
    }
    radius_server_address: Optional[str] = field(default=None, metadata={'description': 'The address of this radius server.'})  # fmt: skip
    radius_server_score: Optional[int] = field(default=None, metadata={'description': 'The initial score assigned to this radius server.'})  # fmt: skip
    radius_server_secret: Optional[str] = field(default=None, metadata={'description': 'The secret used for this radius server.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureAadAuthenticationParameters:
    kind: ClassVar[str] = "azure_aad_authentication_parameters"
    mapping: ClassVar[Dict[str, Bender]] = {
        "aad_audience": S("aadAudience"),
        "aad_issuer": S("aadIssuer"),
        "aad_tenant": S("aadTenant"),
    }
    aad_audience: Optional[str] = field(default=None, metadata={'description': 'AAD Vpn authentication parameter AAD audience.'})  # fmt: skip
    aad_issuer: Optional[str] = field(default=None, metadata={'description': 'AAD Vpn authentication parameter AAD issuer.'})  # fmt: skip
    aad_tenant: Optional[str] = field(default=None, metadata={'description': 'AAD Vpn authentication parameter AAD tenant.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureVpnServerConfiguration(AzureResource):
    kind: ClassVar[str] = "azure_vpn_server_configuration"
    api_spec: ClassVar[AzureApiSpec] = AzureApiSpec(
        service="network",
        version="2023-05-01",
        path="/subscriptions/{subscriptionId}/providers/Microsoft.Network/vpnServerConfigurations",
        path_parameters=["subscriptionId"],
        query_parameters=["api-version"],
        access_path="value",
        expect_array=True,
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "aad_authentication_parameters": S("properties", "aadAuthenticationParameters")
        >> Bend(AzureAadAuthenticationParameters.mapping),
        "configuration_policy_groups": S("properties", "configurationPolicyGroups")
        >> ForallBend(AzureVpnServerConfigurationPolicyGroup.mapping),
        "etag": S("etag"),
        "_p2s_vpn_gateway_ids": S("properties", "p2SVpnGateways", default=[]) >> ForallBend(S("id")),
        "provisioning_state": S("properties", "provisioningState"),
        "radius_client_root_certificates": S("properties", "radiusClientRootCertificates")
        >> ForallBend(AzureVpnServerConfigRadiusClientRootCertificate.mapping),
        "radius_server_address": S("properties", "radiusServerAddress"),
        "radius_server_root_certificates": S("properties", "radiusServerRootCertificates")
        >> ForallBend(AzureVpnServerConfigRadiusServerRootCertificate.mapping),
        "radius_server_secret": S("properties", "radiusServerSecret"),
        "radius_servers": S("properties", "radiusServers") >> ForallBend(AzureRadiusServer.mapping),
        "vpn_authentication_types": S("properties", "vpnAuthenticationTypes"),
        "vpn_client_ipsec_policies": S("properties", "vpnClientIpsecPolicies") >> ForallBend(AzureIpsecPolicy.mapping),
        "vpn_client_revoked_certificates": S("properties", "vpnClientRevokedCertificates")
        >> ForallBend(AzureVpnServerConfigVpnClientRevokedCertificate.mapping),
        "vpn_client_root_certificates": S("properties", "vpnClientRootCertificates")
        >> ForallBend(AzureVpnServerConfigVpnClientRootCertificate.mapping),
        "vpn_protocols": S("properties", "vpnProtocols"),
    }
    aad_authentication_parameters: Optional[AzureAadAuthenticationParameters] = field(default=None, metadata={'description': 'AAD Vpn authentication type related parameters.'})  # fmt: skip
    configuration_policy_groups: Optional[List[AzureVpnServerConfigurationPolicyGroup]] = field(default=None, metadata={'description': 'List of all VpnServerConfigurationPolicyGroups.'})  # fmt: skip
    etag: Optional[str] = field(default=None, metadata={'description': 'A unique read-only string that changes whenever the resource is updated.'})  # fmt: skip
    _p2s_vpn_gateway_ids: Optional[List[str]] = field(default=None, metadata={'description': 'List of references to P2SVpnGateways.'})  # fmt: skip
    provisioning_state: Optional[str] = field(default=None, metadata={'description': 'The provisioning state of the VpnServerConfiguration resource. Possible values are: Updating , Deleting , and Failed .'})  # fmt: skip
    radius_client_root_certificates: Optional[List[AzureVpnServerConfigRadiusClientRootCertificate]] = field(default=None, metadata={'description': 'Radius client root certificate of VpnServerConfiguration.'})  # fmt: skip
    radius_server_address: Optional[str] = field(default=None, metadata={'description': 'The radius server address property of the VpnServerConfiguration resource for point to site client connection.'})  # fmt: skip
    radius_server_root_certificates: Optional[List[AzureVpnServerConfigRadiusServerRootCertificate]] = field(default=None, metadata={'description': 'Radius Server root certificate of VpnServerConfiguration.'})  # fmt: skip
    radius_server_secret: Optional[str] = field(default=None, metadata={'description': 'The radius secret property of the VpnServerConfiguration resource for point to site client connection.'})  # fmt: skip
    radius_servers: Optional[List[AzureRadiusServer]] = field(default=None, metadata={'description': 'Multiple Radius Server configuration for VpnServerConfiguration.'})  # fmt: skip
    vpn_authentication_types: Optional[List[str]] = field(default=None, metadata={'description': 'VPN authentication types for the VpnServerConfiguration.'})  # fmt: skip
    vpn_client_ipsec_policies: Optional[List[AzureIpsecPolicy]] = field(default=None, metadata={'description': 'VpnClientIpsecPolicies for VpnServerConfiguration.'})  # fmt: skip
    vpn_client_revoked_certificates: Optional[List[AzureVpnServerConfigVpnClientRevokedCertificate]] = field(default=None, metadata={'description': 'VPN client revoked certificate of VpnServerConfiguration.'})  # fmt: skip
    vpn_client_root_certificates: Optional[List[AzureVpnServerConfigVpnClientRootCertificate]] = field(default=None, metadata={'description': 'VPN client root certificate of VpnServerConfiguration.'})  # fmt: skip
    vpn_protocols: Optional[List[str]] = field(default=None, metadata={'description': 'VPN protocols for the VpnServerConfiguration.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureDeviceProperties:
    kind: ClassVar[str] = "azure_device_properties"
    mapping: ClassVar[Dict[str, Bender]] = {
        "device_model": S("deviceModel"),
        "device_vendor": S("deviceVendor"),
        "link_speed_in_mbps": S("linkSpeedInMbps"),
    }
    device_model: Optional[str] = field(default=None, metadata={"description": "Model of the device."})
    device_vendor: Optional[str] = field(default=None, metadata={"description": "Name of the device Vendor."})
    link_speed_in_mbps: Optional[int] = field(default=None, metadata={"description": "Link speed."})


@define(eq=False, slots=False)
class AzureVpnLinkProviderProperties:
    kind: ClassVar[str] = "azure_vpn_link_provider_properties"
    mapping: ClassVar[Dict[str, Bender]] = {
        "link_provider_name": S("linkProviderName"),
        "link_speed_in_mbps": S("linkSpeedInMbps"),
    }
    link_provider_name: Optional[str] = field(default=None, metadata={"description": "Name of the link provider."})
    link_speed_in_mbps: Optional[int] = field(default=None, metadata={"description": "Link speed."})


@define(eq=False, slots=False)
class AzureVpnLinkBgpSettings:
    kind: ClassVar[str] = "azure_vpn_link_bgp_settings"
    mapping: ClassVar[Dict[str, Bender]] = {"asn": S("asn"), "bgp_peering_address": S("bgpPeeringAddress")}
    asn: Optional[int] = field(default=None, metadata={"description": "The BGP speaker s ASN."})
    bgp_peering_address: Optional[str] = field(default=None, metadata={'description': 'The BGP peering address and BGP identifier of this BGP speaker.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureVpnSiteLink(AzureSubResource):
    kind: ClassVar[str] = "azure_vpn_site_link"
    mapping: ClassVar[Dict[str, Bender]] = AzureSubResource.mapping | {
        "bgp_properties": S("properties", "bgpProperties") >> Bend(AzureVpnLinkBgpSettings.mapping),
        "etag": S("etag"),
        "fqdn": S("properties", "fqdn"),
        "ip_address": S("properties", "ipAddress"),
        "link_properties": S("properties", "linkProperties") >> Bend(AzureVpnLinkProviderProperties.mapping),
        "name": S("name"),
        "provisioning_state": S("properties", "provisioningState"),
        "type": S("type"),
    }
    bgp_properties: Optional[AzureVpnLinkBgpSettings] = field(default=None, metadata={'description': 'BGP settings details for a link.'})  # fmt: skip
    etag: Optional[str] = field(default=None, metadata={'description': 'A unique read-only string that changes whenever the resource is updated.'})  # fmt: skip
    fqdn: Optional[str] = field(default=None, metadata={"description": "FQDN of vpn-site-link."})
    ip_address: Optional[str] = field(default=None, metadata={"description": "The ip-address for the vpn-site-link."})
    link_properties: Optional[AzureVpnLinkProviderProperties] = field(default=None, metadata={'description': 'List of properties of a link provider.'})  # fmt: skip
    name: Optional[str] = field(default=None, metadata={'description': 'The name of the resource that is unique within a resource group. This name can be used to access the resource.'})  # fmt: skip
    provisioning_state: Optional[str] = field(default=None, metadata={'description': 'The current provisioning state.'})  # fmt: skip
    type: Optional[str] = field(default=None, metadata={"description": "Resource type."})


@define(eq=False, slots=False)
class AzureO365BreakOutCategoryPolicies:
    kind: ClassVar[str] = "azure_o365_break_out_category_policies"
    mapping: ClassVar[Dict[str, Bender]] = {"allow": S("allow"), "default": S("default"), "optimize": S("optimize")}
    allow: Optional[bool] = field(default=None, metadata={"description": "Flag to control allow category."})
    default: Optional[bool] = field(default=None, metadata={"description": "Flag to control default category."})
    optimize: Optional[bool] = field(default=None, metadata={"description": "Flag to control optimize category."})


@define(eq=False, slots=False)
class AzureO365PolicyProperties:
    kind: ClassVar[str] = "azure_o365_policy_properties"
    mapping: ClassVar[Dict[str, Bender]] = {
        "break_out_categories": S("breakOutCategories") >> Bend(AzureO365BreakOutCategoryPolicies.mapping)
    }
    break_out_categories: Optional[AzureO365BreakOutCategoryPolicies] = field(default=None, metadata={'description': 'Office365 breakout categories.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureVpnSite(AzureResource, BasePeeringConnection):
    kind: ClassVar[str] = "azure_vpn_site"
    api_spec: ClassVar[AzureApiSpec] = AzureApiSpec(
        service="network",
        version="2023-05-01",
        path="/subscriptions/{subscriptionId}/providers/Microsoft.Network/vpnSites",
        path_parameters=["subscriptionId"],
        query_parameters=["api-version"],
        access_path="value",
        expect_array=True,
    )
    reference_kinds: ClassVar[ModelReference] = {
        "predecessors": {"default": ["azure_virtual_wan"]},
    }
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "address_space": S("properties", "addressSpace") >> Bend(AzureAddressSpace.mapping),
        "bgp_properties": S("properties", "bgpProperties") >> Bend(AzureBgpSettings.mapping),
        "device_properties": S("properties", "deviceProperties") >> Bend(AzureDeviceProperties.mapping),
        "etag": S("etag"),
        "ip_address": S("properties", "ipAddress"),
        "is_security_site": S("properties", "isSecuritySite"),
        "o365_policy": S("properties", "o365Policy") >> Bend(AzureO365PolicyProperties.mapping),
        "provisioning_state": S("properties", "provisioningState"),
        "site_key": S("properties", "siteKey"),
        "virtual_wan": S("properties", "virtualWan", "id"),
        "vpn_site_links": S("properties", "vpnSiteLinks") >> ForallBend(AzureVpnSiteLink.mapping),
    }
    address_space: Optional[AzureAddressSpace] = field(default=None, metadata={'description': 'AddressSpace contains an array of IP address ranges that can be used by subnets of the virtual network.'})  # fmt: skip
    bgp_properties: Optional[AzureBgpSettings] = field(default=None, metadata={"description": "BGP settings details."})
    device_properties: Optional[AzureDeviceProperties] = field(default=None, metadata={'description': 'List of properties of the device.'})  # fmt: skip
    etag: Optional[str] = field(default=None, metadata={'description': 'A unique read-only string that changes whenever the resource is updated.'})  # fmt: skip
    ip_address: Optional[str] = field(default=None, metadata={"description": "The ip-address for the vpn-site."})
    is_security_site: Optional[bool] = field(default=None, metadata={"description": "IsSecuritySite flag."})
    o365_policy: Optional[AzureO365PolicyProperties] = field(default=None, metadata={'description': 'The Office365 breakout policy.'})  # fmt: skip
    provisioning_state: Optional[str] = field(default=None, metadata={'description': 'The current provisioning state.'})  # fmt: skip
    site_key: Optional[str] = field(default=None, metadata={'description': 'The key for vpn-site that can be used for connections.'})  # fmt: skip
    virtual_wan: Optional[str] = field(default=None, metadata={"description": "Reference to another subresource."})
    vpn_site_links: Optional[List[AzureVpnSiteLink]] = field(default=None, metadata={'description': 'List of all vpn site links.'})  # fmt: skip

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if vw_id := self.virtual_wan:
            builder.add_edge(self, edge_type=EdgeType.default, reverse=True, clazz=AzureVirtualWAN, id=vw_id)


@define(eq=False, slots=False)
class AzureWebApplicationFirewallScrubbingRules:
    kind: ClassVar[str] = "azure_web_application_firewall_scrubbing_rules"
    mapping: ClassVar[Dict[str, Bender]] = {
        "match_variable": S("matchVariable"),
        "selector": S("selector"),
        "selector_match_operator": S("selectorMatchOperator"),
        "state": S("state"),
    }
    match_variable: Optional[str] = field(default=None, metadata={'description': 'The variable to be scrubbed from the logs.'})  # fmt: skip
    selector: Optional[str] = field(default=None, metadata={'description': 'When matchVariable is a collection, operator used to specify which elements in the collection this rule applies to.'})  # fmt: skip
    selector_match_operator: Optional[str] = field(default=None, metadata={'description': 'When matchVariable is a collection, operate on the selector to specify which elements in the collection this rule applies to.'})  # fmt: skip
    state: Optional[str] = field(default=None, metadata={'description': 'Defines the state of log scrubbing rule. Default value is Enabled.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureStateScrubbingrules:
    kind: ClassVar[str] = "azure_state_scrubbingrules"
    mapping: ClassVar[Dict[str, Bender]] = {
        "scrubbing_rules": S("scrubbingRules") >> ForallBend(AzureWebApplicationFirewallScrubbingRules.mapping),
        "state": S("state"),
    }
    scrubbing_rules: Optional[List[AzureWebApplicationFirewallScrubbingRules]] = field(default=None, metadata={'description': 'The rules that are applied to the logs for scrubbing.'})  # fmt: skip
    state: Optional[str] = field(default=None, metadata={'description': 'State of the log scrubbing config. Default value is Enabled.'})  # fmt: skip


@define(eq=False, slots=False)
class AzurePolicySettings:
    kind: ClassVar[str] = "azure_policy_settings"
    mapping: ClassVar[Dict[str, Bender]] = {
        "custom_block_response_body": S("customBlockResponseBody"),
        "custom_block_response_status_code": S("customBlockResponseStatusCode"),
        "file_upload_enforcement": S("fileUploadEnforcement"),
        "file_upload_limit_in_mb": S("fileUploadLimitInMb"),
        "log_scrubbing": S("logScrubbing") >> Bend(AzureStateScrubbingrules.mapping),
        "max_request_body_size_in_kb": S("maxRequestBodySizeInKb"),
        "mode": S("mode"),
        "request_body_check": S("requestBodyCheck"),
        "request_body_enforcement": S("requestBodyEnforcement"),
        "request_body_inspect_limit_in_kb": S("requestBodyInspectLimitInKB"),
        "state": S("state"),
    }
    custom_block_response_body: Optional[str] = field(default=None, metadata={'description': 'If the action type is block, customer can override the response body. The body must be specified in base64 encoding.'})  # fmt: skip
    custom_block_response_status_code: Optional[int] = field(default=None, metadata={'description': 'If the action type is block, customer can override the response status code.'})  # fmt: skip
    file_upload_enforcement: Optional[bool] = field(default=None, metadata={'description': 'Whether allow WAF to enforce file upload limits.'})  # fmt: skip
    file_upload_limit_in_mb: Optional[int] = field(default=None, metadata={'description': 'Maximum file upload size in Mb for WAF.'})  # fmt: skip
    log_scrubbing: Optional[AzureStateScrubbingrules] = field(default=None, metadata={'description': 'To scrub sensitive log fields'})  # fmt: skip
    max_request_body_size_in_kb: Optional[int] = field(default=None, metadata={'description': 'Maximum request body size in Kb for WAF.'})  # fmt: skip
    mode: Optional[str] = field(default=None, metadata={"description": "The mode of the policy."})
    request_body_check: Optional[bool] = field(default=None, metadata={'description': 'Whether to allow WAF to check request Body.'})  # fmt: skip
    request_body_enforcement: Optional[bool] = field(default=None, metadata={'description': 'Whether allow WAF to enforce request body limits.'})  # fmt: skip
    request_body_inspect_limit_in_kb: Optional[int] = field(default=None, metadata={'description': 'Max inspection limit in KB for request body inspection for WAF.'})  # fmt: skip
    state: Optional[str] = field(default=None, metadata={"description": "The state of the policy."})


@define(eq=False, slots=False)
class AzureMatchVariable:
    kind: ClassVar[str] = "azure_match_variable"
    mapping: ClassVar[Dict[str, Bender]] = {"selector": S("selector"), "variable_name": S("variableName")}
    selector: Optional[str] = field(default=None, metadata={"description": "The selector of match variable."})
    variable_name: Optional[str] = field(default=None, metadata={"description": "Match Variable."})


@define(eq=False, slots=False)
class AzureMatchCondition:
    kind: ClassVar[str] = "azure_match_condition"
    mapping: ClassVar[Dict[str, Bender]] = {
        "match_values": S("matchValues"),
        "match_variables": S("matchVariables") >> ForallBend(AzureMatchVariable.mapping),
        "negation_conditon": S("negationConditon"),
        "operator": S("operator"),
        "transforms": S("transforms"),
    }
    match_values: Optional[List[str]] = field(default=None, metadata={"description": "Match value."})
    match_variables: Optional[List[AzureMatchVariable]] = field(default=None, metadata={'description': 'List of match variables.'})  # fmt: skip
    negation_conditon: Optional[bool] = field(default=None, metadata={'description': 'Whether this is negate condition or not.'})  # fmt: skip
    operator: Optional[str] = field(default=None, metadata={"description": "The operator to be matched."})
    transforms: Optional[List[str]] = field(default=None, metadata={"description": "List of transforms."})


@define(eq=False, slots=False)
class AzureGroupByUserSession:
    kind: ClassVar[str] = "azure_group_by_user_session"
    mapping: ClassVar[Dict[str, Bender]] = {
        "group_by_variables": S("groupByVariables", default=[]) >> ForallBend(S("variableName"))
    }
    group_by_variables: Optional[List[str]] = field(default=None, metadata={'description': 'List of group by clause variables.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureWebApplicationFirewallCustomRule:
    kind: ClassVar[str] = "azure_web_application_firewall_custom_rule"
    mapping: ClassVar[Dict[str, Bender]] = {
        "action": S("action"),
        "etag": S("etag"),
        "group_by_user_session": S("groupByUserSession") >> ForallBend(AzureGroupByUserSession.mapping),
        "match_conditions": S("matchConditions") >> ForallBend(AzureMatchCondition.mapping),
        "name": S("name"),
        "priority": S("priority"),
        "rate_limit_duration": S("rateLimitDuration"),
        "rate_limit_threshold": S("rateLimitThreshold"),
        "rule_type": S("ruleType"),
        "state": S("state"),
    }
    action: Optional[str] = field(default=None, metadata={"description": "Type of Actions."})
    etag: Optional[str] = field(default=None, metadata={'description': 'A unique read-only string that changes whenever the resource is updated.'})  # fmt: skip
    group_by_user_session: Optional[List[AzureGroupByUserSession]] = field(default=None, metadata={'description': 'List of user session identifier group by clauses.'})  # fmt: skip
    match_conditions: Optional[List[AzureMatchCondition]] = field(default=None, metadata={'description': 'List of match conditions.'})  # fmt: skip
    name: Optional[str] = field(default=None, metadata={'description': 'The name of the resource that is unique within a policy. This name can be used to access the resource.'})  # fmt: skip
    priority: Optional[int] = field(default=None, metadata={'description': 'Priority of the rule. Rules with a lower value will be evaluated before rules with a higher value.'})  # fmt: skip
    rate_limit_duration: Optional[str] = field(default=None, metadata={'description': 'Duration over which Rate Limit policy will be applied. Applies only when ruleType is RateLimitRule.'})  # fmt: skip
    rate_limit_threshold: Optional[int] = field(default=None, metadata={'description': 'Rate Limit threshold to apply in case ruleType is RateLimitRule. Must be greater than or equal to 1'})  # fmt: skip
    rule_type: Optional[str] = field(default=None, metadata={"description": "The rule type."})
    state: Optional[str] = field(default=None, metadata={'description': 'Describes if the custom rule is in enabled or disabled state. Defaults to Enabled if not specified.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureExclusionManagedRuleGroup:
    kind: ClassVar[str] = "azure_exclusion_managed_rule_group"
    mapping: ClassVar[Dict[str, Bender]] = {
        "rule_group_name": S("ruleGroupName"),
        "rules": S("rules", default=[]) >> ForallBend(S("ruleId")),
    }
    rule_group_name: Optional[str] = field(default=None, metadata={'description': 'The managed rule group for exclusion.'})  # fmt: skip
    rules: Optional[List[str]] = field(default=None, metadata={'description': 'List of rules that will be excluded. If none specified, all rules in the group will be excluded.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureExclusionManagedRuleSet:
    kind: ClassVar[str] = "azure_exclusion_managed_rule_set"
    mapping: ClassVar[Dict[str, Bender]] = {
        "rule_groups": S("ruleGroups") >> ForallBend(AzureExclusionManagedRuleGroup.mapping),
        "rule_set_type": S("ruleSetType"),
        "rule_set_version": S("ruleSetVersion"),
    }
    rule_groups: Optional[List[AzureExclusionManagedRuleGroup]] = field(default=None, metadata={'description': 'Defines the rule groups to apply to the rule set.'})  # fmt: skip
    rule_set_type: Optional[str] = field(default=None, metadata={"description": "Defines the rule set type to use."})
    rule_set_version: Optional[str] = field(default=None, metadata={'description': 'Defines the version of the rule set to use.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureOwaspCrsExclusionEntry:
    kind: ClassVar[str] = "azure_owasp_crs_exclusion_entry"
    mapping: ClassVar[Dict[str, Bender]] = {
        "exclusion_managed_rule_sets": S("exclusionManagedRuleSets")
        >> ForallBend(AzureExclusionManagedRuleSet.mapping),
        "match_variable": S("matchVariable"),
        "selector": S("selector"),
        "selector_match_operator": S("selectorMatchOperator"),
    }
    exclusion_managed_rule_sets: Optional[List[AzureExclusionManagedRuleSet]] = field(default=None, metadata={'description': 'The managed rule sets that are associated with the exclusion.'})  # fmt: skip
    match_variable: Optional[str] = field(default=None, metadata={"description": "The variable to be excluded."})
    selector: Optional[str] = field(default=None, metadata={'description': 'When matchVariable is a collection, operator used to specify which elements in the collection this exclusion applies to.'})  # fmt: skip
    selector_match_operator: Optional[str] = field(default=None, metadata={'description': 'When matchVariable is a collection, operate on the selector to specify which elements in the collection this exclusion applies to.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureManagedRuleOverride:
    kind: ClassVar[str] = "azure_managed_rule_override"
    mapping: ClassVar[Dict[str, Bender]] = {"action": S("action"), "rule_id": S("ruleId"), "state": S("state")}
    action: Optional[str] = field(default=None, metadata={"description": "Defines the action to take on rule match."})
    rule_id: Optional[str] = field(default=None, metadata={"description": "Identifier for the managed rule."})
    state: Optional[str] = field(default=None, metadata={'description': 'The state of the managed rule. Defaults to Disabled if not specified.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureManagedRuleGroupOverride:
    kind: ClassVar[str] = "azure_managed_rule_group_override"
    mapping: ClassVar[Dict[str, Bender]] = {
        "rule_group_name": S("ruleGroupName"),
        "rules": S("rules") >> ForallBend(AzureManagedRuleOverride.mapping),
    }
    rule_group_name: Optional[str] = field(default=None, metadata={'description': 'The managed rule group to override.'})  # fmt: skip
    rules: Optional[List[AzureManagedRuleOverride]] = field(default=None, metadata={'description': 'List of rules that will be disabled. If none specified, all rules in the group will be disabled.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureManagedRuleSet:
    kind: ClassVar[str] = "azure_managed_rule_set"
    mapping: ClassVar[Dict[str, Bender]] = {
        "rule_group_overrides": S("ruleGroupOverrides") >> ForallBend(AzureManagedRuleGroupOverride.mapping),
        "rule_set_type": S("ruleSetType"),
        "rule_set_version": S("ruleSetVersion"),
    }
    rule_group_overrides: Optional[List[AzureManagedRuleGroupOverride]] = field(default=None, metadata={'description': 'Defines the rule group overrides to apply to the rule set.'})  # fmt: skip
    rule_set_type: Optional[str] = field(default=None, metadata={"description": "Defines the rule set type to use."})
    rule_set_version: Optional[str] = field(default=None, metadata={'description': 'Defines the version of the rule set to use.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureManagedRulesDefinition:
    kind: ClassVar[str] = "azure_managed_rules_definition"
    mapping: ClassVar[Dict[str, Bender]] = {
        "exclusions": S("exclusions") >> ForallBend(AzureOwaspCrsExclusionEntry.mapping),
        "managed_rule_sets": S("managedRuleSets") >> ForallBend(AzureManagedRuleSet.mapping),
    }
    exclusions: Optional[List[AzureOwaspCrsExclusionEntry]] = field(default=None, metadata={'description': 'The Exclusions that are applied on the policy.'})  # fmt: skip
    managed_rule_sets: Optional[List[AzureManagedRuleSet]] = field(default=None, metadata={'description': 'The managed rule sets that are associated with the policy.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureWebApplicationFirewallPolicy(AzureResource):
    kind: ClassVar[str] = "azure_web_application_firewall_policy"
    api_spec: ClassVar[AzureApiSpec] = AzureApiSpec(
        service="network",
        version="2023-05-01",
        path="/subscriptions/{subscriptionId}/providers/Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies",
        path_parameters=["subscriptionId"],
        query_parameters=["api-version"],
        access_path="value",
        expect_array=True,
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "_application_gateway_ids": S("properties", "applicationGateways", default=[]) >> ForallBend(S("id")),
        "custom_rules": S("properties", "customRules") >> ForallBend(AzureWebApplicationFirewallCustomRule.mapping),
        "etag": S("etag"),
        "gateway_http_listeners": S("properties") >> S("httpListeners", default=[]) >> ForallBend(S("id")),
        "managed_rules": S("properties", "managedRules") >> Bend(AzureManagedRulesDefinition.mapping),
        "path_based_rules": S("properties") >> S("pathBasedRules", default=[]) >> ForallBend(S("id")),
        "policy_settings": S("properties", "policySettings") >> Bend(AzurePolicySettings.mapping),
        "provisioning_state": S("properties", "provisioningState"),
        "resource_state": S("properties", "resourceState"),
    }
    _application_gateway_ids: Optional[List[str]] = field(default=None, metadata={'description': 'A collection of references to application gateways.'})  # fmt: skip
    custom_rules: Optional[List[AzureWebApplicationFirewallCustomRule]] = field(default=None, metadata={'description': 'The custom rules inside the policy.'})  # fmt: skip
    etag: Optional[str] = field(default=None, metadata={'description': 'A unique read-only string that changes whenever the resource is updated.'})  # fmt: skip
    gateway_http_listeners: Optional[List[str]] = field(default=None, metadata={'description': 'A collection of references to application gateway http listeners.'})  # fmt: skip
    managed_rules: Optional[AzureManagedRulesDefinition] = field(default=None, metadata={'description': 'Allow to exclude some variable satisfy the condition for the WAF check.'})  # fmt: skip
    path_based_rules: Optional[List[str]] = field(default=None, metadata={'description': 'A collection of references to application gateway path rules.'})  # fmt: skip
    policy_settings: Optional[AzurePolicySettings] = field(default=None, metadata={'description': 'Defines contents of a web application firewall global configuration.'})  # fmt: skip
    provisioning_state: Optional[str] = field(default=None, metadata={'description': 'The current provisioning state.'})  # fmt: skip
    resource_state: Optional[str] = field(default=None, metadata={"description": "Resource status of the policy."})


resources: List[Type[AzureResource]] = [
    AzureApplicationGateway,
    AzureApplicationGatewayFirewallRuleSet,
    AzureFirewall,
    AzureBastionHost,
    AzureCustomIpPrefix,
    AzureDdosProtectionPlan,
    AzureDscpConfiguration,
    AzureExpressRouteCircuit,
    # AzureExpressRouteCrossConnection, # API is listed but not available
    AzureExpressRouteGateway,
    AzureExpressRoutePort,
    AzureExpressRoutePortsLocation,
    AzureFirewallPolicy,
    AzureIpAllocation,
    AzureIpGroup,
    AzureLoadBalancer,
    AzureNatGateway,
    AzureNetworkInterface,
    AzureNetworkProfile,
    AzureNetworkSecurityGroup,
    AzureNetworkVirtualAppliance,
    AzureNetworkVirtualApplianceSku,
    AzureNetworkWatcher,
    AzureP2SVpnGateway,
    AzurePrivateLinkService,
    AzurePublicIPAddress,
    AzurePublicIPPrefix,
    AzureRouteFilter,
    AzureSecurityPartnerProvider,
    AzureUsage,
    AzureVirtualHub,
    AzureVirtualNetwork,
    AzureVirtualNetworkTap,
    AzureVirtualRouter,
    AzureVirtualWAN,
    AzureVpnGateway,
    AzureVpnServerConfiguration,
    AzureVpnSite,
    AzureWebApplicationFirewallPolicy,
]
