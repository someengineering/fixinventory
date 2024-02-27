from datetime import datetime
from typing import ClassVar, Dict, Optional, List

from attr import define, field

from fix_plugin_gcp.gcp_client import GcpApiSpec
from fix_plugin_gcp.resources.base import GcpResource, GcpDeprecationStatus, GraphBuilder
from fixlib.baseresources import ModelReference, BaseManagedKubernetesClusterProvider
from fixlib.json_bender import Bender, S, Bend, ForallBend, MapDict
from fixlib.types import Json

# This service is called Google Kubernetes Engine in the docs
# https://cloud.google.com/kubernetes-engine/docs


@define(eq=False, slots=False)
class GcpContainerCloudRunConfig:
    kind: ClassVar[str] = "gcp_container_cloud_run_config"
    kind_display: ClassVar[str] = "GCP Container Cloud Run Configuration"
    kind_description: ClassVar[str] = (
        "GCP Container Cloud Run Config allows users to define and configure runtime"
        " settings for applications running on Google Cloud's serverless platform,"
        " Cloud Run."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"disabled": S("disabled"), "load_balancer_type": S("loadBalancerType")}
    disabled: Optional[bool] = field(default=None)
    load_balancer_type: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpContainerAddonsConfig:
    kind: ClassVar[str] = "gcp_container_addons_config"
    kind_display: ClassVar[str] = "GCP Container Addons Config"
    kind_description: ClassVar[str] = (
        "GCP Container Addons Config is a configuration setting in Google Cloud"
        " Platform that allows users to enable or disable add-ons for Kubernetes"
        " Engine clusters."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "cloud_run_config": S("cloudRunConfig", default={}) >> Bend(GcpContainerCloudRunConfig.mapping),
        "config_connector_config": S("configConnectorConfig", "enabled"),
        "dns_cache_config": S("dnsCacheConfig", "enabled"),
        "gce_persistent_disk_csi_driver_config": S("gcePersistentDiskCsiDriverConfig", "enabled"),
        "gcp_filestore_csi_driver_config": S("gcpFilestoreCsiDriverConfig", "enabled"),
        "gke_backup_agent_config": S("gkeBackupAgentConfig", "enabled"),
        "horizontal_pod_autoscaling": S("horizontalPodAutoscaling", "disabled"),
        "http_load_balancing": S("httpLoadBalancing", "disabled"),
        "kubernetes_dashboard": S("kubernetesDashboard", "disabled"),
        "network_policy_config": S("networkPolicyConfig", "disabled"),
    }
    cloud_run_config: Optional[GcpContainerCloudRunConfig] = field(default=None)
    config_connector_config: Optional[bool] = field(default=None)
    dns_cache_config: Optional[bool] = field(default=None)
    gce_persistent_disk_csi_driver_config: Optional[bool] = field(default=None)
    gcp_filestore_csi_driver_config: Optional[bool] = field(default=None)
    gke_backup_agent_config: Optional[bool] = field(default=None)
    horizontal_pod_autoscaling: Optional[bool] = field(default=None)
    http_load_balancing: Optional[bool] = field(default=None)
    kubernetes_dashboard: Optional[bool] = field(default=None)
    network_policy_config: Optional[bool] = field(default=None)


@define(eq=False, slots=False)
class GcpContainerAuthenticatorGroupsConfig:
    kind: ClassVar[str] = "gcp_container_authenticator_groups_config"
    kind_display: ClassVar[str] = "GCP Container Authenticator Groups Config"
    kind_description: ClassVar[str] = (
        "In the context of GCP Container, the Authenticator Groups Config specifies whether"
        " a security group is enabled for authenticating containers."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"enabled": S("enabled"), "security_group": S("securityGroup")}
    enabled: Optional[bool] = field(default=None)
    security_group: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpContainerAutoUpgradeOptions:
    kind: ClassVar[str] = "gcp_container_auto_upgrade_options"
    kind_display: ClassVar[str] = "GCP Container Auto-Upgrade Options"
    kind_description: ClassVar[str] = (
        "GCP Container Auto-Upgrade Options refer to the settings available for"
        " automatically upgrading Kubernetes clusters in the Google Cloud Platform,"
        " ensuring that they are always running the latest version of Kubernetes for"
        " enhanced security and performance."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "auto_upgrade_start_time": S("autoUpgradeStartTime"),
        "description": S("description"),
    }
    auto_upgrade_start_time: Optional[datetime] = field(default=None)
    description: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpContainerNodeManagement:
    kind: ClassVar[str] = "gcp_container_node_management"
    kind_display: ClassVar[str] = "GCP Container Node Management"
    kind_description: ClassVar[str] = (
        "GCP Container Node Management is a service provided by Google Cloud Platform"
        " for managing and orchestrating containers running on GCP Kubernetes Engine."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "auto_repair": S("autoRepair"),
        "auto_upgrade": S("autoUpgrade"),
        "upgrade_options": S("upgradeOptions", default={}) >> Bend(GcpContainerAutoUpgradeOptions.mapping),
    }
    auto_repair: Optional[bool] = field(default=None)
    auto_upgrade: Optional[bool] = field(default=None)
    upgrade_options: Optional[GcpContainerAutoUpgradeOptions] = field(default=None)


@define(eq=False, slots=False)
class GcpContainerShieldedInstanceConfig:
    kind: ClassVar[str] = "gcp_container_shielded_instance_config"
    kind_display: ClassVar[str] = "GCP Container Shielded Instance Config"
    kind_description: ClassVar[str] = (
        "The GCP Container Shielded Instance Config ensures enhanced security for GKE nodes by offering"
        " options to enable integrity monitoring and secure boot features."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "enable_integrity_monitoring": S("enableIntegrityMonitoring"),
        "enable_secure_boot": S("enableSecureBoot"),
    }
    enable_integrity_monitoring: Optional[bool] = field(default=None)
    enable_secure_boot: Optional[bool] = field(default=None)


@define(eq=False, slots=False)
class GcpContainerStandardRolloutPolicy:
    kind: ClassVar[str] = "gcp_container_standard_rollout_policy"
    kind_display: ClassVar[str] = "GCP Container Standard Rollout Policy"
    kind_description: ClassVar[str] = (
        "A rollout policy in Google Cloud Platform (GCP) Container is a standard"
        " mechanism that defines how new versions of a container should be gradually"
        " deployed to a cluster in a controlled manner."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "batch_node_count": S("batchNodeCount"),
        "batch_percentage": S("batchPercentage"),
        "batch_soak_duration": S("batchSoakDuration"),
    }
    batch_node_count: Optional[int] = field(default=None)
    batch_percentage: Optional[float] = field(default=None)
    batch_soak_duration: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpContainerBlueGreenSettings:
    kind: ClassVar[str] = "gcp_container_blue_green_settings"
    kind_display: ClassVar[str] = "GCP Container Blue-Green Settings"
    kind_description: ClassVar[str] = (
        "GCP Container Blue-Green Settings refer to the configuration options for managing the node"
        " pool upgrade process, including the soak time for new nodes and the policy for rolling out"
        " upgrades across node pools."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "node_pool_soak_duration": S("nodePoolSoakDuration"),
        "standard_rollout_policy": S("standardRolloutPolicy", default={})
        >> Bend(GcpContainerStandardRolloutPolicy.mapping),
    }
    node_pool_soak_duration: Optional[str] = field(default=None)
    standard_rollout_policy: Optional[GcpContainerStandardRolloutPolicy] = field(default=None)


@define(eq=False, slots=False)
class GcpContainerUpgradeSettings:
    kind: ClassVar[str] = "gcp_container_upgrade_settings"
    kind_display: ClassVar[str] = "GCP Container Upgrade Settings"
    kind_description: ClassVar[str] = (
        "GCP Container Upgrade Settings are configurations that allow users to manage"
        " and control the upgrade process of their containerized applications in"
        " Google Cloud Platform."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "blue_green_settings": S("blueGreenSettings", default={}) >> Bend(GcpContainerBlueGreenSettings.mapping),
        "max_surge": S("maxSurge"),
        "max_unavailable": S("maxUnavailable"),
        "strategy": S("strategy"),
    }
    blue_green_settings: Optional[GcpContainerBlueGreenSettings] = field(default=None)
    max_surge: Optional[int] = field(default=None)
    max_unavailable: Optional[int] = field(default=None)
    strategy: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpContainerAutoprovisioningNodePoolDefaults:
    kind: ClassVar[str] = "gcp_container_autoprovisioning_node_pool_defaults"
    kind_display: ClassVar[str] = "GCP Container Autoprovisioning Node Pool Defaults"
    kind_description: ClassVar[str] = (
        "In GCP Container Autoprovisioning, Node Pool Defaults determine the configuration for nodes created"
        " automatically, including settings for disk encryption, disk size and type, image type, access scopes,"
        " and instance configuration options."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "boot_disk_kms_key": S("bootDiskKmsKey"),
        "disk_size_gb": S("diskSizeGb"),
        "disk_type": S("diskType"),
        "image_type": S("imageType"),
        "management": S("management", default={}) >> Bend(GcpContainerNodeManagement.mapping),
        "min_cpu_platform": S("minCpuPlatform"),
        "oauth_scopes": S("oauthScopes", default=[]),
        "service_account": S("serviceAccount"),
        "shielded_instance_config": S("shieldedInstanceConfig", default={})
        >> Bend(GcpContainerShieldedInstanceConfig.mapping),
        "upgrade_settings": S("upgradeSettings", default={}) >> Bend(GcpContainerUpgradeSettings.mapping),
    }
    boot_disk_kms_key: Optional[str] = field(default=None)
    disk_size_gb: Optional[int] = field(default=None)
    disk_type: Optional[str] = field(default=None)
    image_type: Optional[str] = field(default=None)
    management: Optional[GcpContainerNodeManagement] = field(default=None)
    min_cpu_platform: Optional[str] = field(default=None)
    oauth_scopes: Optional[List[str]] = field(default=None)
    service_account: Optional[str] = field(default=None)
    shielded_instance_config: Optional[GcpContainerShieldedInstanceConfig] = field(default=None)
    upgrade_settings: Optional[GcpContainerUpgradeSettings] = field(default=None)


@define(eq=False, slots=False)
class GcpContainerResourceLimit:
    kind: ClassVar[str] = "gcp_container_resource_limit"
    kind_display: ClassVar[str] = "GCP Container Resource Limit"
    kind_description: ClassVar[str] = (
        "Container Resource Limit in Google Cloud Platform (GCP) is a feature that"
        " allows you to set resource constraints on containers, such as CPU and memory"
        " limits, to ensure efficient resource allocation and prevent resource"
        " starvation."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "maximum": S("maximum"),
        "minimum": S("minimum"),
        "resource_type": S("resourceType"),
    }
    maximum: Optional[str] = field(default=None)
    minimum: Optional[str] = field(default=None)
    resource_type: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpContainerClusterAutoscaling:
    kind: ClassVar[str] = "gcp_container_cluster_autoscaling"
    kind_display: ClassVar[str] = "GCP Container Cluster Autoscaling"
    kind_description: ClassVar[str] = (
        "Container Cluster Autoscaling is a feature in Google Cloud Platform (GCP)"
        " that dynamically adjusts the number of nodes in a container cluster based on"
        " application demand and resource utilization."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "autoprovisioning_locations": S("autoprovisioningLocations", default=[]),
        "autoprovisioning_node_pool_defaults": S("autoprovisioningNodePoolDefaults", default={})
        >> Bend(GcpContainerAutoprovisioningNodePoolDefaults.mapping),
        "autoscaling_profile": S("autoscalingProfile"),
        "enable_node_autoprovisioning": S("enableNodeAutoprovisioning"),
        "resource_limits": S("resourceLimits", default=[]) >> ForallBend(GcpContainerResourceLimit.mapping),
    }
    autoprovisioning_locations: Optional[List[str]] = field(default=None)
    autoprovisioning_node_pool_defaults: Optional[GcpContainerAutoprovisioningNodePoolDefaults] = field(default=None)
    autoscaling_profile: Optional[str] = field(default=None)
    enable_node_autoprovisioning: Optional[bool] = field(default=None)
    resource_limits: Optional[List[GcpContainerResourceLimit]] = field(default=None)


@define(eq=False, slots=False)
class GcpContainerBinaryAuthorization:
    kind: ClassVar[str] = "gcp_container_binary_authorization"
    kind_display: ClassVar[str] = "GCP Container Binary Authorization"
    kind_description: ClassVar[str] = (
        "GCP Container Binary Authorization is a service that ensures only trusted"
        " container images are deployed in your Google Cloud environment, helping to"
        " prevent unauthorized or vulnerable images from running in production."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"enabled": S("enabled"), "evaluation_mode": S("evaluationMode")}
    enabled: Optional[bool] = field(default=None)
    evaluation_mode: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpContainerStatusCondition:
    kind: ClassVar[str] = "gcp_container_status_condition"
    kind_display: ClassVar[str] = "GCP Container Status Condition"
    kind_description: ClassVar[str] = (
        "The GCP Container Status Condition provides detailed status codes and messages that"
        " help to diagnose the health and operational state of GKE node pools and operations."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "canonical_code": S("canonicalCode"),
        "code": S("code"),
        "message": S("message"),
    }
    canonical_code: Optional[str] = field(default=None)
    code: Optional[str] = field(default=None)
    message: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpContainerDatabaseEncryption:
    kind: ClassVar[str] = "gcp_container_database_encryption"
    kind_display: ClassVar[str] = "GCP Container Database Encryption"
    kind_description: ClassVar[str] = (
        "GCP Container Database Encryption settings in a container cluster define"
        " the encryption key used for database encryption and its operational state."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"key_name": S("keyName"), "state": S("state")}
    key_name: Optional[str] = field(default=None)
    state: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpContainerIPAllocationPolicy:
    kind: ClassVar[str] = "gcp_container_ip_allocation_policy"
    kind_display: ClassVar[str] = "GCP Container IP Allocation Policy"
    kind_description: ClassVar[str] = (
        "Container IP Allocation Policy is a feature in Google Cloud Platform that"
        " allows users to define and manage the IP address allocation policy for"
        " containers in a Kubernetes cluster."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "cluster_ipv4_cidr": S("clusterIpv4Cidr"),
        "cluster_ipv4_cidr_block": S("clusterIpv4CidrBlock"),
        "cluster_secondary_range_name": S("clusterSecondaryRangeName"),
        "create_subnetwork": S("createSubnetwork"),
        "ipv6_access_type": S("ipv6AccessType"),
        "node_ipv4_cidr": S("nodeIpv4Cidr"),
        "node_ipv4_cidr_block": S("nodeIpv4CidrBlock"),
        "services_ipv4_cidr": S("servicesIpv4Cidr"),
        "services_ipv4_cidr_block": S("servicesIpv4CidrBlock"),
        "services_secondary_range_name": S("servicesSecondaryRangeName"),
        "stack_type": S("stackType"),
        "subnetwork_name": S("subnetworkName"),
        "tpu_ipv4_cidr_block": S("tpuIpv4CidrBlock"),
        "use_ip_aliases": S("useIpAliases"),
        "use_routes": S("useRoutes"),
    }
    cluster_ipv4_cidr: Optional[str] = field(default=None)
    cluster_ipv4_cidr_block: Optional[str] = field(default=None)
    cluster_secondary_range_name: Optional[str] = field(default=None)
    create_subnetwork: Optional[bool] = field(default=None)
    ipv6_access_type: Optional[str] = field(default=None)
    node_ipv4_cidr: Optional[str] = field(default=None)
    node_ipv4_cidr_block: Optional[str] = field(default=None)
    services_ipv4_cidr: Optional[str] = field(default=None)
    services_ipv4_cidr_block: Optional[str] = field(default=None)
    services_secondary_range_name: Optional[str] = field(default=None)
    stack_type: Optional[str] = field(default=None)
    subnetwork_name: Optional[str] = field(default=None)
    tpu_ipv4_cidr_block: Optional[str] = field(default=None)
    use_ip_aliases: Optional[bool] = field(default=None)
    use_routes: Optional[bool] = field(default=None)


@define(eq=False, slots=False)
class GcpContainerLoggingComponentConfig:
    kind: ClassVar[str] = "gcp_container_logging_component_config"
    kind_display: ClassVar[str] = "GCP Container Logging Component Config"
    kind_description: ClassVar[str] = (
        "Container Logging Component Config is a configuration setting for logging"
        " containers in the Google Cloud Platform."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"enable_components": S("enableComponents", default=[])}
    enable_components: Optional[List[str]] = field(default=None)


@define(eq=False, slots=False)
class GcpContainerLoggingConfig:
    kind: ClassVar[str] = "gcp_container_logging_config"
    kind_display: ClassVar[str] = "GCP Container Logging Config"
    kind_description: ClassVar[str] = (
        "Container Logging Config is a feature in Google Cloud Platform (GCP) that"
        " allows users to configure and manage logging for their containerized"
        " applications running on GCP's Kubernetes Engine clusters."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "component_config": S("componentConfig", default={}) >> Bend(GcpContainerLoggingComponentConfig.mapping)
    }
    component_config: Optional[GcpContainerLoggingComponentConfig] = field(default=None)


@define(eq=False, slots=False)
class GcpContainerDailyMaintenanceWindow:
    kind: ClassVar[str] = "gcp_container_daily_maintenance_window"
    kind_display: ClassVar[str] = "GCP Container Daily Maintenance Window"
    kind_description: ClassVar[str] = (
        "This resource represents the daily maintenance window for Google Cloud"
        " Platform (GCP) containers, during which routine maintenance activities can"
        " take place."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"duration": S("duration"), "start_time": S("startTime")}
    duration: Optional[str] = field(default=None)
    start_time: Optional[datetime] = field(default=None)


@define(eq=False, slots=False)
class GcpContainerTimeWindow:
    kind: ClassVar[str] = "gcp_container_time_window"
    kind_display: ClassVar[str] = "GCP Container Time Window"
    kind_description: ClassVar[str] = (
        "The GCP Container Time Window specifies the start and end times for maintenance windows, including"
        " any specific exclusions to accommodate operational preferences within Google Kubernetes Engine."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "end_time": S("endTime"),
        "maintenance_exclusion_options": S("maintenanceExclusionOptions", "scope"),
        "start_time": S("startTime"),
    }
    end_time: Optional[datetime] = field(default=None)
    maintenance_exclusion_options: Optional[str] = field(default=None)
    start_time: Optional[datetime] = field(default=None)


@define(eq=False, slots=False)
class GcpContainerRecurringTimeWindow:
    kind: ClassVar[str] = "gcp_container_recurring_time_window"
    kind_display: ClassVar[str] = "GCP Container Recurring Time Window"
    kind_description: ClassVar[str] = (
        "Container Recurring Time Window defines the schedule for regular maintenance operations."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "recurrence": S("recurrence"),
        "window": S("window", default={}) >> Bend(GcpContainerTimeWindow.mapping),
    }
    recurrence: Optional[str] = field(default=None)
    window: Optional[GcpContainerTimeWindow] = field(default=None)


@define(eq=False, slots=False)
class GcpContainerMaintenanceWindow:
    kind: ClassVar[str] = "gcp_container_maintenance_window"
    kind_display: ClassVar[str] = "GCP Container Maintenance Window"
    kind_description: ClassVar[str] = (
        "The Container Maintenance Window specifies the preferred times and days for maintenance operations,"
        " including options for daily maintenance and recurring windows, along with any exclusions to the"
        " standard schedule."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "daily_maintenance_window": S("dailyMaintenanceWindow", default={})
        >> Bend(GcpContainerDailyMaintenanceWindow.mapping),
        "maintenance_exclusions": S("maintenanceExclusions", default={})
        >> MapDict(value_bender=Bend(GcpContainerTimeWindow.mapping)),
        "recurring_window": S("recurringWindow", default={}) >> Bend(GcpContainerRecurringTimeWindow.mapping),
    }
    daily_maintenance_window: Optional[GcpContainerDailyMaintenanceWindow] = field(default=None)
    maintenance_exclusions: Optional[Dict[str, GcpContainerTimeWindow]] = field(default=None)
    recurring_window: Optional[GcpContainerRecurringTimeWindow] = field(default=None)


@define(eq=False, slots=False)
class GcpContainerMaintenancePolicy:
    kind: ClassVar[str] = "gcp_container_maintenance_policy"
    kind_display: ClassVar[str] = "GCP Container Maintenance Policy"
    kind_description: ClassVar[str] = (
        "GCP Container Maintenance Policy is a feature in Google Cloud Platform that"
        " allows users to define how their container clusters will be updated and"
        " maintained by specifying maintenance windows and auto-upgrade settings."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "resource_version": S("resourceVersion"),
        "window": S("window", default={}) >> Bend(GcpContainerMaintenanceWindow.mapping),
    }
    resource_version: Optional[str] = field(default=None)
    window: Optional[GcpContainerMaintenanceWindow] = field(default=None)


@define(eq=False, slots=False)
class GcpContainerMasterAuth:
    kind: ClassVar[str] = "gcp_container_master_auth"
    kind_display: ClassVar[str] = "GCP Container Cluster Master Authentication"
    kind_description: ClassVar[str] = (
        "GCP Container Cluster Master Authentication provides secure access and"
        " authentication to the master controller of a Google Cloud Platform (GCP)"
        " container cluster, allowing users to manage and control their container"
        " cluster resources."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "client_certificate": S("clientCertificate"),
        "client_certificate_config": S("clientCertificateConfig", "issueClientCertificate"),
        "client_key": S("clientKey"),
        "cluster_ca_certificate": S("clusterCaCertificate"),
        "password": S("password"),
        "username": S("username"),
    }
    client_certificate: Optional[str] = field(default=None)
    client_certificate_config: Optional[bool] = field(default=None)
    client_key: Optional[str] = field(default=None)
    cluster_ca_certificate: Optional[str] = field(default=None)
    password: Optional[str] = field(default=None)
    username: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpContainerCidrBlock:
    kind: ClassVar[str] = "gcp_container_cidr_block"
    kind_display: ClassVar[str] = "GCP Container CIDR Block"
    kind_description: ClassVar[str] = (
        "GCP Container CIDR Block is a range of IP addresses that can be used for the"
        " pods within a Google Cloud Platform (GCP) container cluster."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"cidr_block": S("cidrBlock"), "display_name": S("displayName")}
    cidr_block: Optional[str] = field(default=None)
    display_name: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpContainerMasterAuthorizedNetworksConfig:
    kind: ClassVar[str] = "gcp_container_master_authorized_networks_config"
    kind_display: ClassVar[str] = "GCP Container Master Authorized Networks Configuration"
    kind_description: ClassVar[str] = (
        "Container Master Authorized Networks Configuration allows you to configure"
        " the IP address ranges that have access to the Kubernetes master of a Google"
        " Cloud Platform (GCP) container."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "cidr_blocks": S("cidrBlocks", default=[]) >> ForallBend(GcpContainerCidrBlock.mapping),
        "enabled": S("enabled"),
    }
    cidr_blocks: Optional[List[GcpContainerCidrBlock]] = field(default=None)
    enabled: Optional[bool] = field(default=None)


@define(eq=False, slots=False)
class GcpContainerMonitoringComponentConfig:
    kind: ClassVar[str] = "gcp_container_monitoring_component_config"
    kind_display: ClassVar[str] = "GCP Container Monitoring Component Config"
    kind_description: ClassVar[str] = (
        "GCP Container Monitoring Component Config is a configuration component used"
        " for monitoring containers in the Google Cloud Platform. It allows users to"
        " configure various settings and parameters for container monitoring."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"enable_components": S("enableComponents", default=[])}
    enable_components: Optional[List[str]] = field(default=None)


@define(eq=False, slots=False)
class GcpContainerMonitoringConfig:
    kind: ClassVar[str] = "gcp_container_monitoring_config"
    kind_display: ClassVar[str] = "GCP Container Monitoring Config"
    kind_description: ClassVar[str] = (
        "GCP Container Monitoring Config is a feature provided by Google Cloud"
        " Platform that allows users to configure and monitor the containers running"
        " on their cloud infrastructure."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "component_config": S("componentConfig", default={}) >> Bend(GcpContainerMonitoringComponentConfig.mapping),
        "managed_prometheus_config": S("managedPrometheusConfig", "enabled"),
    }
    component_config: Optional[GcpContainerMonitoringComponentConfig] = field(default=None)
    managed_prometheus_config: Optional[bool] = field(default=None)


@define(eq=False, slots=False)
class GcpContainerDNSConfig:
    kind: ClassVar[str] = "gcp_container_dns_config"
    kind_display: ClassVar[str] = "GCP Container DNS Config"
    kind_description: ClassVar[str] = (
        "Container DNS Config is a feature in Google Cloud Platform that allows users"
        " to configure DNS settings for containers running in Google Kubernetes Engine"
        " (GKE)."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "cluster_dns": S("clusterDns"),
        "cluster_dns_domain": S("clusterDnsDomain"),
        "cluster_dns_scope": S("clusterDnsScope"),
    }
    cluster_dns: Optional[str] = field(default=None)
    cluster_dns_domain: Optional[str] = field(default=None)
    cluster_dns_scope: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpContainerNetworkConfig:
    kind: ClassVar[str] = "gcp_container_network_config"
    kind_display: ClassVar[str] = "GCP Container Network Config"
    kind_description: ClassVar[str] = (
        "Container Network Config is a feature provided by Google Cloud Platform that"
        " allows users to configure network settings for their containerized"
        " applications running in Google Kubernetes Engine (GKE), such as IP"
        " addresses, subnets, and network policies."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "datapath_provider": S("datapathProvider"),
        "default_snat_status": S("defaultSnatStatus", "disabled"),
        "dns_config": S("dnsConfig", default={}) >> Bend(GcpContainerDNSConfig.mapping),
        "enable_intra_node_visibility": S("enableIntraNodeVisibility"),
        "enable_l4ilb_subsetting": S("enableL4ilbSubsetting"),
        "network": S("network"),
        "private_ipv6_google_access": S("privateIpv6GoogleAccess"),
        "service_external_ips_config": S("serviceExternalIpsConfig", "enabled"),
        "subnetwork": S("subnetwork"),
    }
    datapath_provider: Optional[str] = field(default=None)
    default_snat_status: Optional[bool] = field(default=None)
    dns_config: Optional[GcpContainerDNSConfig] = field(default=None)
    enable_intra_node_visibility: Optional[bool] = field(default=None)
    enable_l4ilb_subsetting: Optional[bool] = field(default=None)
    network: Optional[str] = field(default=None)
    private_ipv6_google_access: Optional[str] = field(default=None)
    service_external_ips_config: Optional[bool] = field(default=None)
    subnetwork: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpContainerNetworkPolicy:
    kind: ClassVar[str] = "gcp_container_network_policy"
    kind_display: ClassVar[str] = "GCP Container Network Policy"
    kind_description: ClassVar[str] = (
        "GCP Container Network Policy is a resource in Google Cloud Platform that"
        " allows users to control network traffic between containers within a"
        " Kubernetes Engine cluster."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"enabled": S("enabled"), "provider": S("provider")}
    enabled: Optional[bool] = field(default=None)
    provider: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpContainerGPUSharingConfig:
    kind: ClassVar[str] = "gcp_container_gpu_sharing_config"
    kind_display: ClassVar[str] = "GCP Container GPU Sharing Config"
    kind_description: ClassVar[str] = (
        "GCP Container GPU Sharing Config, within the scope of GCP Container Accelerator Config, determines how"
        " GPUs are shared among container instances and sets the maximum number of clients that can"
        " simultaneously utilize a single GPU."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "gpu_sharing_strategy": S("gpuSharingStrategy"),
        "max_shared_clients_per_gpu": S("maxSharedClientsPerGpu"),
    }
    gpu_sharing_strategy: Optional[str] = field(default=None)
    max_shared_clients_per_gpu: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpContainerAcceleratorConfig:
    kind: ClassVar[str] = "gcp_container_accelerator_config"
    kind_display: ClassVar[str] = "GCP Container Accelerator Config"
    kind_description: ClassVar[str] = (
        "Container Accelerator Config is a feature in Google Cloud Platform that"
        " allows you to attach GPUs (Graphical Processing Units) to your containers,"
        " enabling faster and more efficient workload processing."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "accelerator_count": S("acceleratorCount"),
        "accelerator_type": S("acceleratorType"),
        "gpu_partition_size": S("gpuPartitionSize"),
        "gpu_sharing_config": S("gpuSharingConfig", default={}) >> Bend(GcpContainerGPUSharingConfig.mapping),
    }
    accelerator_count: Optional[str] = field(default=None)
    accelerator_type: Optional[str] = field(default=None)
    gpu_partition_size: Optional[str] = field(default=None)
    gpu_sharing_config: Optional[GcpContainerGPUSharingConfig] = field(default=None)


@define(eq=False, slots=False)
class GcpContainerNodeKubeletConfig:
    kind: ClassVar[str] = "gcp_container_node_kubelet_config"
    kind_display: ClassVar[str] = "GCP Container Node Kubelet Config"
    kind_description: ClassVar[str] = (
        "The GCP Container Node Kubelet Config is a configuration file used by Google"
        " Cloud Platform (GCP) to configure the Kubelet component of container nodes"
        " in a Kubernetes cluster. Kubelet is responsible for managing the state of"
        " each container running on the node."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "cpu_cfs_quota": S("cpuCfsQuota"),
        "cpu_cfs_quota_period": S("cpuCfsQuotaPeriod"),
        "cpu_manager_policy": S("cpuManagerPolicy"),
        "pod_pids_limit": S("podPidsLimit"),
    }
    cpu_cfs_quota: Optional[bool] = field(default=None)
    cpu_cfs_quota_period: Optional[str] = field(default=None)
    cpu_manager_policy: Optional[str] = field(default=None)
    pod_pids_limit: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpContainerLinuxNodeConfig:
    kind: ClassVar[str] = "gcp_container_linux_node_config"
    kind_display: ClassVar[str] = "GCP Container Linux Node Config"
    kind_description: ClassVar[str] = (
        "GCP Container Linux Node Config is a configuration for Linux nodes in Google"
        " Cloud Platform's container service, allowing users to define the settings"
        " and behavior for their Linux-based container nodes."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"sysctls": S("sysctls")}
    sysctls: Optional[Dict[str, str]] = field(default=None)


@define(eq=False, slots=False)
class GcpContainerNodePoolLoggingConfig:
    kind: ClassVar[str] = "gcp_container_node_pool_logging_config"
    kind_display: ClassVar[str] = "GCP Container Node Pool Logging Config"
    kind_description: ClassVar[str] = (
        "Container Node Pool Logging Config is a configuration setting in Google"
        " Cloud Platform (GCP) for specifying logging options for container node pools"
        " in Kubernetes clusters."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"variant_config": S("variantConfig", "variant")}
    variant_config: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpContainerReservationAffinity:
    kind: ClassVar[str] = "gcp_container_reservation_affinity"
    kind_display: ClassVar[str] = "GCP Container Reservation Affinity"
    kind_description: ClassVar[str] = (
        "Container Reservation Affinity is a setting that controls how instances are scheduled on reservations."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "consume_reservation_type": S("consumeReservationType"),
        "key": S("key"),
        "values": S("values", default=[]),
    }
    consume_reservation_type: Optional[str] = field(default=None)
    key: Optional[str] = field(default=None)
    values: Optional[List[str]] = field(default=None)


@define(eq=False, slots=False)
class GcpContainerNodeTaint:
    kind: ClassVar[str] = "gcp_container_node_taint"
    kind_display: ClassVar[str] = "GCP Container Node Taint"
    kind_description: ClassVar[str] = (
        "Container Node Taints are a feature in Google Cloud Platform's container"
        " service that allow users to add constraints and preferences to nodes in a"
        " Kubernetes cluster."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"effect": S("effect"), "key": S("key"), "value": S("value")}
    effect: Optional[str] = field(default=None)
    key: Optional[str] = field(default=None)
    value: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpContainerNodeConfig:
    kind: ClassVar[str] = "gcp_container_node_config"
    kind_display: ClassVar[str] = "GCP Container Node Config"
    kind_description: ClassVar[str] = (
        "GCP Container Node Config is a configuration for a node in Google Cloud"
        " Platform's container service, allowing users to specify settings such as"
        " machine type, disk size, and network configuration for a container node."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "accelerators": S("accelerators", default=[]) >> ForallBend(GcpContainerAcceleratorConfig.mapping),
        "advanced_machine_features": S("advancedMachineFeatures", "threadsPerCore"),
        "boot_disk_kms_key": S("bootDiskKmsKey"),
        "confidential_nodes": S("confidentialNodes", "enabled"),
        "disk_size_gb": S("diskSizeGb"),
        "disk_type": S("diskType"),
        "gcfs_config": S("gcfsConfig", "enabled"),
        "gvnic": S("gvnic", "enabled"),
        "image_type": S("imageType"),
        "kubelet_config": S("kubeletConfig", default={}) >> Bend(GcpContainerNodeKubeletConfig.mapping),
        "labels": S("labels"),
        "linux_node_config": S("linuxNodeConfig", default={}) >> Bend(GcpContainerLinuxNodeConfig.mapping),
        "local_ssd_count": S("localSsdCount"),
        "logging_config": S("loggingConfig", default={}) >> Bend(GcpContainerNodePoolLoggingConfig.mapping),
        "machine_type": S("machineType"),
        "metadata": S("metadata"),
        "min_cpu_platform": S("minCpuPlatform"),
        "node_group": S("nodeGroup"),
        "oauth_scopes": S("oauthScopes", default=[]),
        "preemptible": S("preemptible"),
        "reservation_affinity": S("reservationAffinity", default={}) >> Bend(GcpContainerReservationAffinity.mapping),
        "sandbox_config": S("sandboxConfig", "type"),
        "service_account": S("serviceAccount"),
        "shielded_instance_config": S("shieldedInstanceConfig", default={})
        >> Bend(GcpContainerShieldedInstanceConfig.mapping),
        "spot": S("spot"),
        "tags": S("tags", default=[]),
        "taints": S("taints", default=[]) >> ForallBend(GcpContainerNodeTaint.mapping),
        "workload_metadata_config": S("workloadMetadataConfig", "mode"),
    }
    accelerators: Optional[List[GcpContainerAcceleratorConfig]] = field(default=None)
    advanced_machine_features: Optional[str] = field(default=None)
    boot_disk_kms_key: Optional[str] = field(default=None)
    confidential_nodes: Optional[bool] = field(default=None)
    disk_size_gb: Optional[int] = field(default=None)
    disk_type: Optional[str] = field(default=None)
    gcfs_config: Optional[bool] = field(default=None)
    gvnic: Optional[bool] = field(default=None)
    image_type: Optional[str] = field(default=None)
    kubelet_config: Optional[GcpContainerNodeKubeletConfig] = field(default=None)
    labels: Optional[Dict[str, str]] = field(default=None)
    linux_node_config: Optional[GcpContainerLinuxNodeConfig] = field(default=None)
    local_ssd_count: Optional[int] = field(default=None)
    logging_config: Optional[GcpContainerNodePoolLoggingConfig] = field(default=None)
    machine_type: Optional[str] = field(default=None)
    metadata: Optional[Dict[str, str]] = field(default=None)
    min_cpu_platform: Optional[str] = field(default=None)
    node_group: Optional[str] = field(default=None)
    oauth_scopes: Optional[List[str]] = field(default=None)
    preemptible: Optional[bool] = field(default=None)
    reservation_affinity: Optional[GcpContainerReservationAffinity] = field(default=None)
    sandbox_config: Optional[str] = field(default=None)
    service_account: Optional[str] = field(default=None)
    shielded_instance_config: Optional[GcpContainerShieldedInstanceConfig] = field(default=None)
    spot: Optional[bool] = field(default=None)
    tags: Optional[List[str]] = field(default=None)
    taints: Optional[List[GcpContainerNodeTaint]] = field(default=None)
    workload_metadata_config: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpContainerNetworkTags:
    kind: ClassVar[str] = "gcp_container_network_tags"
    kind_display: ClassVar[str] = "GCP Container Network Tags"
    kind_description: ClassVar[str] = (
        "Within the GCP Container Node Pool Auto Configuration, Container Network Tags are labels applied"
        " to virtual machine instances, allowing for the setup of network firewall rules and routes that"
        " apply to tagged instances within the container cluster."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"tags": S("tags", default=[])}
    tags: Optional[List[str]] = field(default=None)


@define(eq=False, slots=False)
class GcpContainerNodePoolAutoConfig:
    kind: ClassVar[str] = "gcp_container_node_pool_auto_config"
    kind_display: ClassVar[str] = "GCP Container Node Pool Auto Config"
    kind_description: ClassVar[str] = (
        "The Container Node Pool Auto Config refers to settings that automatically determine the network tags"
        " for nodes within a node pool. These tags are used to configure network firewall rules that apply to"
        " the instances in the node pool."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "network_tags": S("networkTags", default={}) >> Bend(GcpContainerNetworkTags.mapping)
    }
    network_tags: Optional[GcpContainerNetworkTags] = field(default=None)


@define(eq=False, slots=False)
class GcpContainerNodeConfigDefaults:
    kind: ClassVar[str] = "gcp_container_node_config_defaults"
    kind_display: ClassVar[str] = "GCP Container Node Config Defaults"
    kind_description: ClassVar[str] = (
        "GCP Container Node Config Defaults represents the default configuration"
        " settings for nodes in a Google Cloud Platform container cluster."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "gcfs_config": S("gcfsConfig", "enabled"),
        "logging_config": S("loggingConfig", default={}) >> Bend(GcpContainerNodePoolLoggingConfig.mapping),
    }
    gcfs_config: Optional[bool] = field(default=None)
    logging_config: Optional[GcpContainerNodePoolLoggingConfig] = field(default=None)


@define(eq=False, slots=False)
class GcpContainerNodePoolDefaults:
    kind: ClassVar[str] = "gcp_container_node_pool_defaults"
    kind_display: ClassVar[str] = "GCP Container Node Pool Defaults"
    kind_description: ClassVar[str] = (
        "GCP Container Node Pool Defaults is a feature in Google Cloud Platform that"
        " allows users to set default configurations for their container node pools,"
        " which are groups of nodes that host containerized applications."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "node_config_defaults": S("nodeConfigDefaults", default={}) >> Bend(GcpContainerNodeConfigDefaults.mapping)
    }
    node_config_defaults: Optional[GcpContainerNodeConfigDefaults] = field(default=None)


@define(eq=False, slots=False)
class GcpContainerNodePoolAutoscaling:
    kind: ClassVar[str] = "gcp_container_node_pool_autoscaling"
    kind_display: ClassVar[str] = "GCP Container Node Pool Autoscaling"
    kind_description: ClassVar[str] = (
        "Container Node Pool Autoscaling is a feature in Google Cloud Platform that"
        " automatically adjusts the number of nodes in a container cluster based on"
        " demand, ensuring optimal resource utilization and scalability."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "autoprovisioned": S("autoprovisioned"),
        "enabled": S("enabled"),
        "location_policy": S("locationPolicy"),
        "max_node_count": S("maxNodeCount"),
        "min_node_count": S("minNodeCount"),
        "total_max_node_count": S("totalMaxNodeCount"),
        "total_min_node_count": S("totalMinNodeCount"),
    }
    autoprovisioned: Optional[bool] = field(default=None)
    enabled: Optional[bool] = field(default=None)
    location_policy: Optional[str] = field(default=None)
    max_node_count: Optional[int] = field(default=None)
    min_node_count: Optional[int] = field(default=None)
    total_max_node_count: Optional[int] = field(default=None)
    total_min_node_count: Optional[int] = field(default=None)


@define(eq=False, slots=False)
class GcpContainerNodeNetworkConfig:
    kind: ClassVar[str] = "gcp_container_node_network_config"
    kind_display: ClassVar[str] = "GCP Container Node Network Config"
    kind_description: ClassVar[str] = (
        "GCP Container Node Network Config is a network configuration for nodes in"
        " Google Cloud Platform's container service. It defines the network settings"
        " for containers running on the nodes."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "create_pod_range": S("createPodRange"),
        "network_performance_config": S("networkPerformanceConfig", "totalEgressBandwidthTier"),
        "pod_ipv4_cidr_block": S("podIpv4CidrBlock"),
        "pod_range": S("podRange"),
    }
    create_pod_range: Optional[bool] = field(default=None)
    network_performance_config: Optional[str] = field(default=None)
    pod_ipv4_cidr_block: Optional[str] = field(default=None)
    pod_range: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpContainerBlueGreenInfo:
    kind: ClassVar[str] = "gcp_container_blue_green_info"
    kind_display: ClassVar[str] = "GCP Container Blue-Green Info"
    kind_description: ClassVar[str] = (
        "Blue-Green deployment strategy in Google Cloud Platform (GCP) container"
        " where two identical production environments, blue and green, are used to"
        " minimize downtime during software releases."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "blue_instance_group_urls": S("blueInstanceGroupUrls", default=[]),
        "blue_pool_deletion_start_time": S("bluePoolDeletionStartTime"),
        "green_instance_group_urls": S("greenInstanceGroupUrls", default=[]),
        "green_pool_version": S("greenPoolVersion"),
        "phase": S("phase"),
    }
    blue_instance_group_urls: Optional[List[str]] = field(default=None)
    blue_pool_deletion_start_time: Optional[datetime] = field(default=None)
    green_instance_group_urls: Optional[List[str]] = field(default=None)
    green_pool_version: Optional[str] = field(default=None)
    phase: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpContainerUpdateInfo:
    kind: ClassVar[str] = "gcp_container_update_info"
    kind_display: ClassVar[str] = "GCP Container Update Info"
    kind_description: ClassVar[str] = (
        "GCP Container Update Info outlines details about blue-green deployment strategies"
        " for node pools in Google Kubernetes Engine."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "blue_green_info": S("blueGreenInfo", default={}) >> Bend(GcpContainerBlueGreenInfo.mapping)
    }
    blue_green_info: Optional[GcpContainerBlueGreenInfo] = field(default=None)


@define(eq=False, slots=False)
class GcpContainerNodePool:
    kind: ClassVar[str] = "gcp_container_node_pool"
    kind_display: ClassVar[str] = "GCP Container Node Pool"
    kind_description: ClassVar[str] = (
        "Container Node Pool is a resource in Google Cloud Platform that allows you"
        " to create and manage a pool of virtual machines to run your containerized"
        " applications in Google Kubernetes Engine."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "autoscaling": S("autoscaling", default={}) >> Bend(GcpContainerNodePoolAutoscaling.mapping),
        "conditions": S("conditions", default=[]) >> ForallBend(GcpContainerStatusCondition.mapping),
        "config": S("config", default={}) >> Bend(GcpContainerNodeConfig.mapping),
        "initial_node_count": S("initialNodeCount"),
        "instance_group_urls": S("instanceGroupUrls", default=[]),
        "locations": S("locations", default=[]),
        "management": S("management", default={}) >> Bend(GcpContainerNodeManagement.mapping),
        "max_pods_constraint": S("maxPodsConstraint", "maxPodsPerNode"),
        "name": S("name"),
        "network_config": S("networkConfig", default={}) >> Bend(GcpContainerNodeNetworkConfig.mapping),
        "pod_ipv4_cidr_size": S("podIpv4CidrSize"),
        "self_link": S("selfLink"),
        "status": S("status"),
        "status_message": S("statusMessage"),
        "update_info": S("updateInfo", default={}) >> Bend(GcpContainerUpdateInfo.mapping),
        "upgrade_settings": S("upgradeSettings", default={}) >> Bend(GcpContainerUpgradeSettings.mapping),
        "version": S("version"),
    }
    autoscaling: Optional[GcpContainerNodePoolAutoscaling] = field(default=None)
    conditions: Optional[List[GcpContainerStatusCondition]] = field(default=None)
    config: Optional[GcpContainerNodeConfig] = field(default=None)
    initial_node_count: Optional[int] = field(default=None)
    instance_group_urls: Optional[List[str]] = field(default=None)
    locations: Optional[List[str]] = field(default=None)
    management: Optional[GcpContainerNodeManagement] = field(default=None)
    max_pods_constraint: Optional[str] = field(default=None)
    name: Optional[str] = field(default=None)
    network_config: Optional[GcpContainerNodeNetworkConfig] = field(default=None)
    pod_ipv4_cidr_size: Optional[int] = field(default=None)
    self_link: Optional[str] = field(default=None)
    status: Optional[str] = field(default=None)
    status_message: Optional[str] = field(default=None)
    update_info: Optional[GcpContainerUpdateInfo] = field(default=None)
    upgrade_settings: Optional[GcpContainerUpgradeSettings] = field(default=None)
    version: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpContainerFilter:
    kind: ClassVar[str] = "gcp_container_filter"
    kind_display: ClassVar[str] = "GCP Container Filter"
    kind_description: ClassVar[str] = (
        "GCP Container Filter specifies the type of events that should trigger the container,"
        " typically based on Pub/Sub messages."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"event_type": S("eventType", default=[])}
    event_type: Optional[List[str]] = field(default=None)


@define(eq=False, slots=False)
class GcpContainerPubSub:
    kind: ClassVar[str] = "gcp_container_pub_sub"
    kind_display: ClassVar[str] = "GCP Container Pub/Sub"
    kind_description: ClassVar[str] = (
        "In the context of GCP Container Notification Config, the Container Pub/Sub setting enables you to configure"
        " Google Cloud's Pub/Sub for receiving notifications. When enabled, it allows you to specify a filter"
        " to determine the types of cluster events that should trigger notifications, and the Pub/Sub topic"
        " to which these notifications will be sent."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "enabled": S("enabled"),
        "filter": S("filter", default={}) >> Bend(GcpContainerFilter.mapping),
        "topic": S("topic"),
    }
    enabled: Optional[bool] = field(default=None)
    filter: Optional[GcpContainerFilter] = field(default=None)
    topic: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpContainerNotificationConfig:
    kind: ClassVar[str] = "gcp_container_notification_config"
    kind_display: ClassVar[str] = "GCP Container Notification Config"
    kind_description: ClassVar[str] = (
        "The Container Notification Config is a setting that specifies the Pub/Sub topic to which notifications"
        " for the cluster are published."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"pubsub": S("pubsub", default={}) >> Bend(GcpContainerPubSub.mapping)}
    pubsub: Optional[GcpContainerPubSub] = field(default=None)


@define(eq=False, slots=False)
class GcpContainerPrivateClusterConfig:
    kind: ClassVar[str] = "gcp_container_private_cluster_config"
    kind_display: ClassVar[str] = "GCP Container Private Cluster Config"
    kind_description: ClassVar[str] = (
        "Private cluster configuration option for running Kubernetes clusters in"
        " Google Cloud Platform (GCP) container engine. Private clusters offer"
        " enhanced security by isolating the cluster's control plane and worker nodes"
        " from the public internet."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "enable_private_endpoint": S("enablePrivateEndpoint"),
        "enable_private_nodes": S("enablePrivateNodes"),
        "master_global_access_config": S("masterGlobalAccessConfig", "enabled"),
        "master_ipv4_cidr_block": S("masterIpv4CidrBlock"),
        "peering_name": S("peeringName"),
        "private_endpoint": S("privateEndpoint"),
        "public_endpoint": S("publicEndpoint"),
    }
    enable_private_endpoint: Optional[bool] = field(default=None)
    enable_private_nodes: Optional[bool] = field(default=None)
    master_global_access_config: Optional[bool] = field(default=None)
    master_ipv4_cidr_block: Optional[str] = field(default=None)
    peering_name: Optional[str] = field(default=None)
    private_endpoint: Optional[str] = field(default=None)
    public_endpoint: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpContainerResourceUsageExportConfig:
    kind: ClassVar[str] = "gcp_container_resource_usage_export_config"
    kind_display: ClassVar[str] = "GCP Container Resource Usage Export Config"
    kind_description: ClassVar[str] = (
        "The GCP Container Resource Usage Export Config is a feature that facilitates the analysis of cluster"
        " resource usage by exporting data to BigQuery and providing options for detailed consumption tracking"
        " and network egress monitoring."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "bigquery_destination": S("bigqueryDestination", "datasetId"),
        "consumption_metering_config": S("consumptionMeteringConfig", "enabled"),
        "enable_network_egress_metering": S("enableNetworkEgressMetering"),
    }
    bigquery_destination: Optional[str] = field(default=None)
    consumption_metering_config: Optional[bool] = field(default=None)
    enable_network_egress_metering: Optional[bool] = field(default=None)


@define(eq=False, slots=False)
class GcpContainerCluster(BaseManagedKubernetesClusterProvider, GcpResource):
    kind: ClassVar[str] = "gcp_container_cluster"
    kind_display: ClassVar[str] = "GCP Container Cluster"
    kind_description: ClassVar[str] = (
        "Container Cluster is a managed Kubernetes cluster service provided by Google"
        " Cloud Platform, which allows users to deploy, manage, and scale"
        " containerized applications using Kubernetes."
    )
    api_spec: ClassVar[GcpApiSpec] = GcpApiSpec(
        service="container",
        version="v1",
        accessors=["projects", "locations", "clusters"],
        action="list",
        request_parameter={"parent": "projects/{project}/locations/-"},
        request_parameter_in={"project"},
        response_path="clusters",
        response_regional_sub_path=None,
        required_iam_permissions=["container.clusters.list"],
        mutate_iam_permissions=["container.clusters.update", "container.clusters.delete"],
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("name").or_else(S("id")).or_else(S("selfLink")),
        "tags": S("labels", default={}),
        "name": S("name"),
        "ctime": S("creationTimestamp"),
        "description": S("description"),
        "link": S("selfLink"),
        "label_fingerprint": S("labelFingerprint"),
        "deprecation_status": S("deprecated", default={}) >> Bend(GcpDeprecationStatus.mapping),
        "addons_config": S("addonsConfig", default={}) >> Bend(GcpContainerAddonsConfig.mapping),
        "authenticator_groups_config": S("authenticatorGroupsConfig", default={})
        >> Bend(GcpContainerAuthenticatorGroupsConfig.mapping),
        "autopilot": S("autopilot", "enabled"),
        "autoscaling": S("autoscaling", default={}) >> Bend(GcpContainerClusterAutoscaling.mapping),
        "binary_authorization": S("binaryAuthorization", default={}) >> Bend(GcpContainerBinaryAuthorization.mapping),
        "cluster_ipv4_cidr": S("clusterIpv4Cidr"),
        "conditions": S("conditions", default=[]) >> ForallBend(GcpContainerStatusCondition.mapping),
        "confidential_nodes": S("confidentialNodes", "enabled"),
        "cost_management_config": S("costManagementConfig", "enabled"),
        "create_time": S("createTime"),
        "current_master_version": S("currentMasterVersion"),
        "version": S("currentMasterVersion"),
        "current_node_count": S("currentNodeCount"),
        "current_node_version": S("currentNodeVersion"),
        "database_encryption": S("databaseEncryption", default={}) >> Bend(GcpContainerDatabaseEncryption.mapping),
        "default_max_pods_constraint": S("defaultMaxPodsConstraint", "maxPodsPerNode"),
        "enable_kubernetes_alpha": S("enableKubernetesAlpha"),
        "enable_tpu": S("enableTpu"),
        "endpoint": S("endpoint"),
        "etag": S("etag"),
        "expire_time": S("expireTime"),
        "identity_service_config": S("identityServiceConfig", "enabled"),
        "initial_cluster_version": S("initialClusterVersion"),
        "initial_node_count": S("initialNodeCount"),
        "instance_group_urls": S("instanceGroupUrls", default=[]),
        "ip_allocation_policy": S("ipAllocationPolicy", default={}) >> Bend(GcpContainerIPAllocationPolicy.mapping),
        "legacy_abac": S("legacyAbac", "enabled"),
        "location": S("location"),
        "locations": S("locations", default=[]),
        "logging_config": S("loggingConfig", default={}) >> Bend(GcpContainerLoggingConfig.mapping),
        "logging_service": S("loggingService"),
        "container_cluster_maintenance_policy": S("maintenancePolicy", default={})
        >> Bend(GcpContainerMaintenancePolicy.mapping),
        "master_auth": S("masterAuth", default={}) >> Bend(GcpContainerMasterAuth.mapping),
        "master_authorized_networks_config": S("masterAuthorizedNetworksConfig", default={})
        >> Bend(GcpContainerMasterAuthorizedNetworksConfig.mapping),
        "mesh_certificates": S("meshCertificates", "enableCertificates"),
        "monitoring_config": S("monitoringConfig", default={}) >> Bend(GcpContainerMonitoringConfig.mapping),
        "monitoring_service": S("monitoringService"),
        "network": S("network"),
        "network_config": S("networkConfig", default={}) >> Bend(GcpContainerNetworkConfig.mapping),
        "network_policy": S("networkPolicy", default={}) >> Bend(GcpContainerNetworkPolicy.mapping),
        "node_config": S("nodeConfig", default={}) >> Bend(GcpContainerNodeConfig.mapping),
        "node_ipv4_cidr_size": S("nodeIpv4CidrSize"),
        "node_pool_auto_config": S("nodePoolAutoConfig", default={}) >> Bend(GcpContainerNodePoolAutoConfig.mapping),
        "node_pool_defaults": S("nodePoolDefaults", default={}) >> Bend(GcpContainerNodePoolDefaults.mapping),
        "node_pools": S("nodePools", default=[]) >> ForallBend(GcpContainerNodePool.mapping),
        "notification_config": S("notificationConfig", default={}) >> Bend(GcpContainerNotificationConfig.mapping),
        "private_cluster_config": S("privateClusterConfig", default={})
        >> Bend(GcpContainerPrivateClusterConfig.mapping),
        "release_channel": S("releaseChannel", "channel"),
        "resource_labels": S("resourceLabels"),
        "resource_usage_export_config": S("resourceUsageExportConfig", default={})
        >> Bend(GcpContainerResourceUsageExportConfig.mapping),
        "services_ipv4_cidr": S("servicesIpv4Cidr"),
        "shielded_nodes": S("shieldedNodes", "enabled"),
        "status": S("status"),
        "status_message": S("statusMessage"),
        "subnetwork": S("subnetwork"),
        "tpu_ipv4_cidr_block": S("tpuIpv4CidrBlock"),
        "vertical_pod_autoscaling": S("verticalPodAutoscaling", "enabled"),
        "workload_identity_config": S("workloadIdentityConfig", "workloadPool"),
    }
    addons_config: Optional[GcpContainerAddonsConfig] = field(default=None)
    authenticator_groups_config: Optional[GcpContainerAuthenticatorGroupsConfig] = field(default=None)
    autopilot: Optional[bool] = field(default=None)
    autoscaling: Optional[GcpContainerClusterAutoscaling] = field(default=None)
    binary_authorization: Optional[GcpContainerBinaryAuthorization] = field(default=None)
    cluster_ipv4_cidr: Optional[str] = field(default=None)
    conditions: Optional[List[GcpContainerStatusCondition]] = field(default=None)
    confidential_nodes: Optional[bool] = field(default=None)
    cost_management_config: Optional[bool] = field(default=None)
    create_time: Optional[datetime] = field(default=None)
    current_master_version: Optional[str] = field(default=None)
    current_node_count: Optional[int] = field(default=None)
    current_node_version: Optional[str] = field(default=None)
    database_encryption: Optional[GcpContainerDatabaseEncryption] = field(default=None)
    default_max_pods_constraint: Optional[str] = field(default=None)
    enable_kubernetes_alpha: Optional[bool] = field(default=None)
    enable_tpu: Optional[bool] = field(default=None)
    etag: Optional[str] = field(default=None)
    expire_time: Optional[datetime] = field(default=None)
    identity_service_config: Optional[bool] = field(default=None)
    initial_cluster_version: Optional[str] = field(default=None)
    initial_node_count: Optional[int] = field(default=None)
    instance_group_urls: Optional[List[str]] = field(default=None)
    ip_allocation_policy: Optional[GcpContainerIPAllocationPolicy] = field(default=None)
    legacy_abac: Optional[bool] = field(default=None)
    location: Optional[str] = field(default=None)
    locations: Optional[List[str]] = field(default=None)
    logging_config: Optional[GcpContainerLoggingConfig] = field(default=None)
    logging_service: Optional[str] = field(default=None)
    container_cluster_maintenance_policy: Optional[GcpContainerMaintenancePolicy] = field(default=None)
    master_auth: Optional[GcpContainerMasterAuth] = field(default=None)
    master_authorized_networks_config: Optional[GcpContainerMasterAuthorizedNetworksConfig] = field(default=None)
    mesh_certificates: Optional[bool] = field(default=None)
    monitoring_config: Optional[GcpContainerMonitoringConfig] = field(default=None)
    monitoring_service: Optional[str] = field(default=None)
    network: Optional[str] = field(default=None)
    network_config: Optional[GcpContainerNetworkConfig] = field(default=None)
    network_policy: Optional[GcpContainerNetworkPolicy] = field(default=None)
    node_config: Optional[GcpContainerNodeConfig] = field(default=None)
    node_ipv4_cidr_size: Optional[int] = field(default=None)
    node_pool_auto_config: Optional[GcpContainerNodePoolAutoConfig] = field(default=None)
    node_pool_defaults: Optional[GcpContainerNodePoolDefaults] = field(default=None)
    node_pools: Optional[List[GcpContainerNodePool]] = field(default=None)
    notification_config: Optional[GcpContainerNotificationConfig] = field(default=None)
    private_cluster_config: Optional[GcpContainerPrivateClusterConfig] = field(default=None)
    release_channel: Optional[str] = field(default=None)
    resource_labels: Optional[Dict[str, str]] = field(default=None)
    resource_usage_export_config: Optional[GcpContainerResourceUsageExportConfig] = field(default=None)
    services_ipv4_cidr: Optional[str] = field(default=None)
    shielded_nodes: Optional[bool] = field(default=None)
    status: Optional[str] = field(default=None)
    status_message: Optional[str] = field(default=None)
    subnetwork: Optional[str] = field(default=None)
    tpu_ipv4_cidr_block: Optional[str] = field(default=None)
    vertical_pod_autoscaling: Optional[bool] = field(default=None)
    workload_identity_config: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpContainerStatus:
    kind: ClassVar[str] = "gcp_container_status"
    kind_display: ClassVar[str] = "GCP Container Status"
    kind_description: ClassVar[str] = (
        "GCP Container Status provides information about the current status, health,"
        " and availability of containers running on Google Cloud Platform (GCP)."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "code": S("code"),
        "details": S("details", default=[]),
        "message": S("message"),
    }
    code: Optional[int] = field(default=None)
    details: Optional[List[Json]] = field(default=None)
    message: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpContainerMetric:
    kind: ClassVar[str] = "gcp_container_metric"
    kind_display: ClassVar[str] = "GCP Container Metric"
    kind_description: ClassVar[str] = (
        "Container Metrics in Google Cloud Platform (GCP) are measurements of"
        " resource utilization and performance for containers running on GCP's managed"
        " Kubernetes Engine."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "double_value": S("doubleValue"),
        "int_value": S("intValue"),
        "name": S("name"),
        "string_value": S("stringValue"),
    }
    double_value: Optional[float] = field(default=None)
    int_value: Optional[str] = field(default=None)
    name: Optional[str] = field(default=None)
    string_value: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpContainerOperationProgress:
    kind: ClassVar[str] = "gcp_container_operation_progress"
    kind_display: ClassVar[str] = "GCP Container Operation Progress"
    kind_description: ClassVar[str] = (
        "GCP Container Operation Progress refers to the status and progress of an"
        " operation involving containers in Google Cloud Platform. It provides"
        " information on the current state and completion progress of container-"
        " related operations."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "metrics": S("metrics", default=[]) >> ForallBend(GcpContainerMetric.mapping),
        "name": S("name"),
        "status": S("status"),
    }
    metrics: Optional[List[GcpContainerMetric]] = field(default=None)
    name: Optional[str] = field(default=None)
    status: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpContainerOperation(GcpResource):
    kind: ClassVar[str] = "gcp_container_operation"
    kind_display: ClassVar[str] = "GCP Container Operation"
    kind_description: ClassVar[str] = (
        "Container Operations are management tasks performed on containers in Google"
        " Cloud Platform, including creating, starting, stopping, and deleting"
        " containers."
    )
    reference_kinds: ClassVar[ModelReference] = {"predecessors": {"default": ["gcp_container_cluster"]}}
    api_spec: ClassVar[GcpApiSpec] = GcpApiSpec(
        service="container",
        version="v1",
        accessors=["projects", "locations", "operations"],
        action="list",
        request_parameter={"parent": "projects/{project}/locations/-"},
        request_parameter_in={"project"},
        response_path="operations",
        response_regional_sub_path=None,
        required_iam_permissions=["container.operations.list"],
        mutate_iam_permissions=[],
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("name").or_else(S("id")).or_else(S("selfLink")),
        "tags": S("labels", default={}),
        "name": S("name"),
        "ctime": S("creationTimestamp"),
        "description": S("description"),
        "link": S("selfLink"),
        "label_fingerprint": S("labelFingerprint"),
        "deprecation_status": S("deprecated", default={}) >> Bend(GcpDeprecationStatus.mapping),
        "cluster_conditions": S("clusterConditions", default=[]) >> ForallBend(GcpContainerStatusCondition.mapping),
        "detail": S("detail"),
        "end_time": S("endTime"),
        "container_operation_error": S("error", default={}) >> Bend(GcpContainerStatus.mapping),
        "location": S("location"),
        "nodepool_conditions": S("nodepoolConditions", default=[]) >> ForallBend(GcpContainerStatusCondition.mapping),
        "operation_type": S("operationType"),
        "container_operation_progress": S("progress", default={}) >> Bend(GcpContainerOperationProgress.mapping),
        "start_time": S("startTime"),
        "status": S("status"),
        "status_message": S("statusMessage"),
        "target_link": S("targetLink"),
    }
    cluster_conditions: Optional[List[GcpContainerStatusCondition]] = field(default=None)
    detail: Optional[str] = field(default=None)
    end_time: Optional[datetime] = field(default=None)
    container_operation_error: Optional[GcpContainerStatus] = field(default=None)
    location: Optional[str] = field(default=None)
    nodepool_conditions: Optional[List[GcpContainerStatusCondition]] = field(default=None)
    operation_type: Optional[str] = field(default=None)
    container_operation_progress: Optional[GcpContainerOperationProgress] = field(default=None)
    start_time: Optional[datetime] = field(default=None)
    status: Optional[str] = field(default=None)
    status_message: Optional[str] = field(default=None)
    target_link: Optional[str] = field(default=None)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if self.target_link:
            builder.add_edge(self, reverse=True, clazz=GcpContainerCluster, link=self.target_link)


resources = [GcpContainerCluster, GcpContainerOperation]
