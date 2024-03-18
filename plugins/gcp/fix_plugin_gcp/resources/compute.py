import logging
from datetime import datetime
from typing import ClassVar, Dict, Optional, List, Tuple, Type

from attr import define, field

from fix_plugin_gcp.gcp_client import GcpApiSpec, InternalZoneProp
from fix_plugin_gcp.resources.base import GcpResource, GcpDeprecationStatus, GraphBuilder
from fix_plugin_gcp.resources.billing import GcpSku
from fixlib.baseresources import (
    BaseInstanceType,
    BaseVolumeType,
    ModelReference,
    BaseVolume,
    VolumeStatus,
    BaseInstance,
    InstanceStatus,
)
from fixlib.json_bender import Bender, S, Bend, ForallBend, MapDict, F, MapEnum, AsInt
from fixlib.types import Json

log = logging.getLogger("fix.plugins.gcp")


# This service is called Compute Engine in the GCP API.
# https://cloud.google.com/kubernetes-engine/docs


def health_check_types() -> Tuple[Type[GcpResource], ...]:
    return GcpHealthCheck, GcpHttpsHealthCheck, GcpHttpHealthCheck


@define(eq=False, slots=False)
class GcpAcceleratorType(GcpResource):
    kind: ClassVar[str] = "gcp_accelerator_type"
    kind_display: ClassVar[str] = "GCP Accelerator Type"
    kind_description: ClassVar[str] = (
        "GCP Accelerator Types are specialized hardware accelerators offered by"
        " Google Cloud Platform (GCP) that are designed to enhance the performance of"
        " certain workloads, such as machine learning models or graphics processing."
    )
    api_spec: ClassVar[GcpApiSpec] = GcpApiSpec(
        service="compute",
        version="v1",
        accessors=["acceleratorTypes"],
        action="aggregatedList",
        request_parameter={"project": "{project}"},
        request_parameter_in={"project"},
        response_path="items",
        response_regional_sub_path="acceleratorTypes",
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
        "type_maximum_cards_per_instance": S("maximumCardsPerInstance"),
    }
    type_maximum_cards_per_instance: Optional[int] = field(default=None)


@define(eq=False, slots=False)
class GcpAddress(GcpResource):
    kind: ClassVar[str] = "gcp_address"
    kind_display: ClassVar[str] = "GCP Address"
    kind_description: ClassVar[str] = (
        "GCP Address is a resource in Google Cloud Platform that provides a static IP"
        " address for virtual machine instances or other resources within the Google"
        " Cloud network."
    )
    reference_kinds: ClassVar[ModelReference] = {
        "predecessors": {"default": ["gcp_subnetwork"]},
        "successors": {
            "delete": ["gcp_subnetwork"],
        },
    }
    api_spec: ClassVar[GcpApiSpec] = GcpApiSpec(
        service="compute",
        version="v1",
        accessors=["addresses"],
        action="aggregatedList",
        request_parameter={"project": "{project}"},
        request_parameter_in={"project"},
        response_path="items",
        response_regional_sub_path="addresses",
        get_identifier="address",
        mutate_iam_permissions=["compute.addresses.delete"],
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
        "address": S("address"),
        "address_type": S("addressType"),
        "ip_version": S("ipVersion"),
        "ipv6_endpoint_type": S("ipv6EndpointType"),
        "network": S("network"),
        "network_tier": S("networkTier"),
        "prefix_length": S("prefixLength"),
        "purpose": S("purpose"),
        "status": S("status"),
        "subnetwork": S("subnetwork"),
        "users": S("users", default=[]),
    }
    address: Optional[str] = field(default=None)
    address_type: Optional[str] = field(default=None)
    ip_version: Optional[str] = field(default=None)
    ipv6_endpoint_type: Optional[str] = field(default=None)
    network: Optional[str] = field(default=None)
    network_tier: Optional[str] = field(default=None)
    prefix_length: Optional[int] = field(default=None)
    purpose: Optional[str] = field(default=None)
    status: Optional[str] = field(default=None)
    subnetwork: Optional[str] = field(default=None)
    users: Optional[List[str]] = field(default=None)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if self.subnetwork:
            builder.dependant_node(self, reverse=True, clazz=GcpSubnetwork, link=self.subnetwork)


@define(eq=False, slots=False)
class GcpAutoscalingPolicyCpuUtilization:
    kind: ClassVar[str] = "gcp_autoscaling_policy_cpu_utilization"
    kind_display: ClassVar[str] = "GCP Autoscaling Policy - CPU Utilization"
    kind_description: ClassVar[str] = (
        "GCP Autoscaling Policy - CPU Utilization is a resource in Google Cloud"
        " Platform that allows for automatic scaling of resources based on CPU"
        " utilization metrics. This helps optimize resource allocation and ensures"
        " optimal performance."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "predictive_method": S("predictiveMethod"),
        "utilization_target": S("utilizationTarget"),
    }
    predictive_method: Optional[str] = field(default=None)
    utilization_target: Optional[float] = field(default=None)


@define(eq=False, slots=False)
class GcpAutoscalingPolicyCustomMetricUtilization:
    kind: ClassVar[str] = "gcp_autoscaling_policy_custom_metric_utilization"
    kind_display: ClassVar[str] = "GCP Autoscaling Policy Custom Metric Utilization"
    kind_description: ClassVar[str] = (
        "GCP Autoscaling Policy Custom Metric Utilization is a feature in Google"
        " Cloud Platform that allows users to define custom metrics to automatically"
        " scale resources based on specific utilization levels."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "filter": S("filter"),
        "metric": S("metric"),
        "single_instance_assignment": S("singleInstanceAssignment"),
        "utilization_target": S("utilizationTarget"),
        "utilization_target_type": S("utilizationTargetType"),
    }
    filter: Optional[str] = field(default=None)
    metric: Optional[str] = field(default=None)
    single_instance_assignment: Optional[float] = field(default=None)
    utilization_target: Optional[float] = field(default=None)
    utilization_target_type: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpFixedOrPercent:
    kind: ClassVar[str] = "gcp_fixed_or_percent"
    kind_display: ClassVar[str] = "GCP Fixed or Percent"
    kind_description: ClassVar[str] = (
        "GCP Fixed or Percent refers to a configuration within GCP's autoscaling policy that allows"
        " for scale-in control based on either a fixed number or a percentage of instances."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"calculated": S("calculated"), "fixed": S("fixed"), "percent": S("percent")}
    calculated: Optional[int] = field(default=None)
    fixed: Optional[int] = field(default=None)
    percent: Optional[int] = field(default=None)


@define(eq=False, slots=False)
class GcpAutoscalingPolicyScaleInControl:
    kind: ClassVar[str] = "gcp_autoscaling_policy_scale_in_control"
    kind_display: ClassVar[str] = "GCP Autoscaling Policy Scale In Control"
    kind_description: ClassVar[str] = (
        "The GCP Autoscaling Policy Scale In Control allows users to control how"
        " instances are scaled in during autoscaling events in the Google Cloud"
        " Platform."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "max_scaled_in_replicas": S("maxScaledInReplicas", default={}) >> Bend(GcpFixedOrPercent.mapping),
        "time_window_sec": S("timeWindowSec"),
    }
    max_scaled_in_replicas: Optional[GcpFixedOrPercent] = field(default=None)
    time_window_sec: Optional[int] = field(default=None)


@define(eq=False, slots=False)
class GcpAutoscalingPolicyScalingSchedule:
    kind: ClassVar[str] = "gcp_autoscaling_policy_scaling_schedule"
    kind_display: ClassVar[str] = "GCP Autoscaling Policy Scaling Schedule"
    kind_description: ClassVar[str] = (
        "A scaling schedule is used in Google Cloud Platform (GCP) autoscaling"
        " policies to define when and how many instances should be added or removed"
        " from an autoscaling group based on predefined time intervals or conditions."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "description": S("description"),
        "disabled": S("disabled"),
        "duration_sec": S("durationSec"),
        "min_required_replicas": S("minRequiredReplicas"),
        "schedule": S("schedule"),
        "time_zone": S("timeZone"),
    }
    description: Optional[str] = field(default=None)
    disabled: Optional[bool] = field(default=None)
    duration_sec: Optional[int] = field(default=None)
    min_required_replicas: Optional[int] = field(default=None)
    schedule: Optional[str] = field(default=None)
    time_zone: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpAutoscalingPolicy:
    kind: ClassVar[str] = "gcp_autoscaling_policy"
    kind_display: ClassVar[str] = "GCP Autoscaling Policy"
    kind_description: ClassVar[str] = (
        "Autoscaling policies in Google Cloud Platform allow automatic adjustment of"
        " resources based on predefined conditions, ensuring efficient utilization and"
        " responsiveness in handling varying workloads."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "cool_down_period_sec": S("coolDownPeriodSec"),
        "cpu_utilization": S("cpuUtilization", default={}) >> Bend(GcpAutoscalingPolicyCpuUtilization.mapping),
        "custom_metric_utilizations": S("customMetricUtilizations", default=[])
        >> ForallBend(GcpAutoscalingPolicyCustomMetricUtilization.mapping),
        "load_balancing_utilization": S("loadBalancingUtilization", "utilizationTarget"),
        "max_num_replicas": S("maxNumReplicas"),
        "min_num_replicas": S("minNumReplicas"),
        "mode": S("mode"),
        "scale_in_control": S("scaleInControl", default={}) >> Bend(GcpAutoscalingPolicyScaleInControl.mapping),
        "scaling_schedules": S("scalingSchedules", default={})
        >> MapDict(value_bender=Bend(GcpAutoscalingPolicyScalingSchedule.mapping)),
    }
    cool_down_period_sec: Optional[int] = field(default=None)
    cpu_utilization: Optional[GcpAutoscalingPolicyCpuUtilization] = field(default=None)
    custom_metric_utilizations: Optional[List[GcpAutoscalingPolicyCustomMetricUtilization]] = field(default=None)
    load_balancing_utilization: Optional[float] = field(default=None)
    max_num_replicas: Optional[int] = field(default=None)
    min_num_replicas: Optional[int] = field(default=None)
    mode: Optional[str] = field(default=None)
    scale_in_control: Optional[GcpAutoscalingPolicyScaleInControl] = field(default=None)
    scaling_schedules: Optional[Dict[str, GcpAutoscalingPolicyScalingSchedule]] = field(default=None)


@define(eq=False, slots=False)
class GcpScalingScheduleStatus:
    kind: ClassVar[str] = "gcp_scaling_schedule_status"
    kind_display: ClassVar[str] = "GCP Scaling Schedule Status"
    kind_description: ClassVar[str] = (
        "GCP Scaling Schedule Status represents the current status of a scaling"
        " schedule in Google Cloud Platform, providing information about when and how"
        " the scaling is performed."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "last_start_time": S("lastStartTime"),
        "next_start_time": S("nextStartTime"),
        "scaling_schedule_status_state": S("state"),
    }
    last_start_time: Optional[datetime] = field(default=None)
    next_start_time: Optional[datetime] = field(default=None)
    scaling_schedule_status_state: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpAutoscalerStatusDetails:
    kind: ClassVar[str] = "gcp_autoscaler_status_details"
    kind_display: ClassVar[str] = "GCP Autoscaler Status Details"
    kind_description: ClassVar[str] = (
        "Autoscaler Status Details provide information about the scaling behavior of"
        " an autoscaler in the Google Cloud Platform."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"message": S("message"), "type": S("type")}
    message: Optional[str] = field(default=None)
    type: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpAutoscaler(GcpResource):
    kind: ClassVar[str] = "gcp_autoscaler"
    kind_display: ClassVar[str] = "GCP Autoscaler"
    kind_description: ClassVar[str] = (
        "GCP Autoscaler is a feature in Google Cloud Platform that automatically"
        " adjusts the number of instances in a managed instance group based on the"
        " workload, helping to maintain cost efficiency and performance."
    )
    reference_kinds: ClassVar[ModelReference] = {
        "successors": {
            "default": ["gcp_instance_group_manager"],
            "delete": ["gcp_instance_group_manager"],
        }
    }
    api_spec: ClassVar[GcpApiSpec] = GcpApiSpec(
        service="compute",
        version="v1",
        accessors=["autoscalers"],
        action="aggregatedList",
        request_parameter={"project": "{project}"},
        request_parameter_in={"project"},
        response_path="items",
        response_regional_sub_path="autoscalers",
        mutate_iam_permissions=["compute.autoscalers.update", "compute.autoscalers.delete"],
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
        "autoscaler_autoscaling_policy": S("autoscalingPolicy", default={}) >> Bend(GcpAutoscalingPolicy.mapping),
        "autoscaler_recommended_size": S("recommendedSize"),
        "autoscaler_scaling_schedule_status": S("scalingScheduleStatus", default={})
        >> MapDict(value_bender=Bend(GcpScalingScheduleStatus.mapping)),
        "autoscaler_status": S("status"),
        "autoscaler_status_details": S("statusDetails", default=[]) >> ForallBend(GcpAutoscalerStatusDetails.mapping),
        "autoscaler_target": S("target"),
    }
    autoscaler_autoscaling_policy: Optional[GcpAutoscalingPolicy] = field(default=None)
    autoscaler_recommended_size: Optional[int] = field(default=None)
    autoscaler_scaling_schedule_status: Optional[Dict[str, GcpScalingScheduleStatus]] = field(default=None)
    autoscaler_status: Optional[str] = field(default=None)
    autoscaler_status_details: Optional[List[GcpAutoscalerStatusDetails]] = field(default=None)
    autoscaler_target: Optional[str] = field(default=None)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if self.autoscaler_target:
            builder.dependant_node(
                self, delete_same_as_default=True, clazz=GcpInstanceGroupManager, link=self.autoscaler_target
            )


@define(eq=False, slots=False)
class GcpBackendBucketCdnPolicyCacheKeyPolicy:
    kind: ClassVar[str] = "gcp_backend_bucket_cdn_policy_cache_key_policy"
    kind_display: ClassVar[str] = "GCP Backend Bucket CDN Policy Cache Key Policy"
    kind_description: ClassVar[str] = (
        "The GCP Backend Bucket CDN Policy Cache Key Policy is a policy that"
        " specifies how content is cached on the CDN (Content Delivery Network) for a"
        " backend bucket in Google Cloud Platform (GCP)."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "include_http_headers": S("includeHttpHeaders", default=[]),
        "query_string_whitelist": S("queryStringWhitelist", default=[]),
    }
    include_http_headers: Optional[List[str]] = field(default=None)
    query_string_whitelist: Optional[List[str]] = field(default=None)


@define(eq=False, slots=False)
class GcpBackendBucketCdnPolicyNegativeCachingPolicy:
    kind: ClassVar[str] = "gcp_backend_bucket_cdn_policy_negative_caching_policy"
    kind_display: ClassVar[str] = "GCP Backend Bucket CDN Policy Negative Caching Policy"
    kind_description: ClassVar[str] = (
        "This resource represents the negative caching policy of a CDN policy for a"
        " Google Cloud Platform backend bucket. Negative caching allows the CDN to"
        " cache and serve error responses to clients, improving performance and"
        " reducing load on the backend servers."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"code": S("code"), "ttl": S("ttl")}
    code: Optional[int] = field(default=None)
    ttl: Optional[int] = field(default=None)


@define(eq=False, slots=False)
class GcpBackendBucketCdnPolicy:
    kind: ClassVar[str] = "gcp_backend_bucket_cdn_policy"
    kind_display: ClassVar[str] = "GCP Backend Bucket CDN Policy"
    kind_description: ClassVar[str] = (
        "CDN Policy is a feature in Google Cloud Platform that allows you to"
        " configure the behavior of the Content Delivery Network (CDN) for a Backend"
        " Bucket. It includes settings such as cache expiration, cache control, and"
        " content encoding."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "bypass_cache_on_request_headers": S("bypassCacheOnRequestHeaders", default=[]) >> ForallBend(S("headerName")),
        "cache_key_policy": S("cacheKeyPolicy", default={}) >> Bend(GcpBackendBucketCdnPolicyCacheKeyPolicy.mapping),
        "cache_mode": S("cacheMode"),
        "client_ttl": S("clientTtl"),
        "default_ttl": S("defaultTtl"),
        "max_ttl": S("maxTtl"),
        "negative_caching": S("negativeCaching"),
        "negative_caching_policy": S("negativeCachingPolicy", default=[])
        >> ForallBend(GcpBackendBucketCdnPolicyNegativeCachingPolicy.mapping),
        "request_coalescing": S("requestCoalescing"),
        "serve_while_stale": S("serveWhileStale"),
        "signed_url_cache_max_age_sec": S("signedUrlCacheMaxAgeSec"),
        "signed_url_key_names": S("signedUrlKeyNames", default=[]),
    }
    bypass_cache_on_request_headers: Optional[List[str]] = field(default=None)
    cache_key_policy: Optional[GcpBackendBucketCdnPolicyCacheKeyPolicy] = field(default=None)
    cache_mode: Optional[str] = field(default=None)
    client_ttl: Optional[int] = field(default=None)
    default_ttl: Optional[int] = field(default=None)
    max_ttl: Optional[int] = field(default=None)
    negative_caching: Optional[bool] = field(default=None)
    negative_caching_policy: Optional[List[GcpBackendBucketCdnPolicyNegativeCachingPolicy]] = field(default=None)
    request_coalescing: Optional[bool] = field(default=None)
    serve_while_stale: Optional[int] = field(default=None)
    signed_url_cache_max_age_sec: Optional[str] = field(default=None)
    signed_url_key_names: Optional[List[str]] = field(default=None)


@define(eq=False, slots=False)
class GcpBackendBucket(GcpResource):
    kind: ClassVar[str] = "gcp_backend_bucket"
    kind_display: ClassVar[str] = "GCP Backend Bucket"
    kind_description: ClassVar[str] = (
        "A GCP Backend Bucket is a storage bucket used to distribute static content"
        " for a load balanced website or application running on Google Cloud Platform."
    )
    api_spec: ClassVar[GcpApiSpec] = GcpApiSpec(
        service="compute",
        version="v1",
        accessors=["backendBuckets"],
        action="list",
        request_parameter={"project": "{project}"},
        request_parameter_in={"project"},
        response_path="items",
        response_regional_sub_path=None,
        mutate_iam_permissions=["compute.backendBuckets.update", "compute.backendBuckets.delete"],
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id").or_else(S("bucketName")).or_else(S("selfLink")),
        "tags": S("labels", default={}),
        "name": S("bucketName"),
        "ctime": S("creationTimestamp"),
        "description": S("description"),
        "link": S("selfLink"),
        "label_fingerprint": S("labelFingerprint"),
        "deprecation_status": S("deprecated", default={}) >> Bend(GcpDeprecationStatus.mapping),
        "bucket_name": S("bucketName"),
        "backend_bucket_cdn_policy": S("cdnPolicy", default={}) >> Bend(GcpBackendBucketCdnPolicy.mapping),
        "compression_mode": S("compressionMode"),
        "custom_response_headers": S("customResponseHeaders", default=[]),
        "edge_security_policy": S("edgeSecurityPolicy"),
        "enable_cdn": S("enableCdn"),
    }
    bucket_name: Optional[str] = field(default=None)
    backend_bucket_cdn_policy: Optional[GcpBackendBucketCdnPolicy] = field(default=None)
    compression_mode: Optional[str] = field(default=None)
    custom_response_headers: Optional[List[str]] = field(default=None)
    edge_security_policy: Optional[str] = field(default=None)
    enable_cdn: Optional[bool] = field(default=None)


@define(eq=False, slots=False)
class GcpBackend:
    kind: ClassVar[str] = "gcp_backend"
    kind_display: ClassVar[str] = "GCP Backend"
    kind_description: ClassVar[str] = (
        "A GCP backend refers to the infrastructure and services that power"
        " applications and services on the Google Cloud Platform. It includes compute,"
        " storage, networking, and other resources needed to support the backend"
        " operations of GCP applications."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "balancing_mode": S("balancingMode"),
        "capacity_scaler": S("capacityScaler"),
        "description": S("description"),
        "failover": S("failover"),
        "group": S("group"),
        "max_connections": S("maxConnections"),
        "max_connections_per_endpoint": S("maxConnectionsPerEndpoint"),
        "max_connections_per_instance": S("maxConnectionsPerInstance"),
        "max_rate": S("maxRate"),
        "max_rate_per_endpoint": S("maxRatePerEndpoint"),
        "max_rate_per_instance": S("maxRatePerInstance"),
        "max_utilization": S("maxUtilization"),
    }
    balancing_mode: Optional[str] = field(default=None)
    capacity_scaler: Optional[float] = field(default=None)
    description: Optional[str] = field(default=None)
    failover: Optional[bool] = field(default=None)
    group: Optional[str] = field(default=None)
    max_connections: Optional[int] = field(default=None)
    max_connections_per_endpoint: Optional[int] = field(default=None)
    max_connections_per_instance: Optional[int] = field(default=None)
    max_rate: Optional[int] = field(default=None)
    max_rate_per_endpoint: Optional[float] = field(default=None)
    max_rate_per_instance: Optional[float] = field(default=None)
    max_utilization: Optional[float] = field(default=None)


@define(eq=False, slots=False)
class GcpCacheKeyPolicy:
    kind: ClassVar[str] = "gcp_cache_key_policy"
    kind_display: ClassVar[str] = "GCP Cache Key Policy"
    kind_description: ClassVar[str] = (
        "A cache key policy in Google Cloud Platform (GCP) is used to define the"
        " criteria for caching content in a cache storage system."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "include_host": S("includeHost"),
        "include_http_headers": S("includeHttpHeaders", default=[]),
        "include_named_cookies": S("includeNamedCookies", default=[]),
        "include_protocol": S("includeProtocol"),
        "include_query_string": S("includeQueryString"),
        "query_string_blacklist": S("queryStringBlacklist", default=[]),
        "query_string_whitelist": S("queryStringWhitelist", default=[]),
    }
    include_host: Optional[bool] = field(default=None)
    include_http_headers: Optional[List[str]] = field(default=None)
    include_named_cookies: Optional[List[str]] = field(default=None)
    include_protocol: Optional[bool] = field(default=None)
    include_query_string: Optional[bool] = field(default=None)
    query_string_blacklist: Optional[List[str]] = field(default=None)
    query_string_whitelist: Optional[List[str]] = field(default=None)


@define(eq=False, slots=False)
class GcpBackendServiceCdnPolicyNegativeCachingPolicy:
    kind: ClassVar[str] = "gcp_backend_service_cdn_policy_negative_caching_policy"
    kind_display: ClassVar[str] = "GCP Backend Service CDN Policy - Negative Caching Policy"
    kind_description: ClassVar[str] = (
        "Negative Caching Policy is a feature of the GCP Backend Service CDN Policy"
        " that allows caching of responses with error status codes, reducing the load"
        " on the origin server for subsequent requests."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"code": S("code"), "ttl": S("ttl")}
    code: Optional[int] = field(default=None)
    ttl: Optional[int] = field(default=None)


@define(eq=False, slots=False)
class GcpBackendServiceCdnPolicy:
    kind: ClassVar[str] = "gcp_backend_service_cdn_policy"
    kind_display: ClassVar[str] = "GCP Backend Service CDN Policy"
    kind_description: ClassVar[str] = (
        "A CDN Policy is a configuration that specifies how a content delivery"
        " network (CDN) delivers content for a backend service in Google Cloud"
        " Platform (GCP). It includes rules for cache settings, cache key"
        " preservation, and request routing."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "bypass_cache_on_request_headers": S("bypassCacheOnRequestHeaders", default=[]) >> ForallBend(S("headerName")),
        "cache_key_policy": S("cacheKeyPolicy", default={}) >> Bend(GcpCacheKeyPolicy.mapping),
        "cache_mode": S("cacheMode"),
        "client_ttl": S("clientTtl"),
        "default_ttl": S("defaultTtl"),
        "max_ttl": S("maxTtl"),
        "negative_caching": S("negativeCaching"),
        "negative_caching_policy": S("negativeCachingPolicy", default=[])
        >> ForallBend(GcpBackendServiceCdnPolicyNegativeCachingPolicy.mapping),
        "request_coalescing": S("requestCoalescing"),
        "serve_while_stale": S("serveWhileStale"),
        "signed_url_cache_max_age_sec": S("signedUrlCacheMaxAgeSec"),
        "signed_url_key_names": S("signedUrlKeyNames", default=[]),
    }
    bypass_cache_on_request_headers: Optional[List[str]] = field(default=None)
    cache_key_policy: Optional[GcpCacheKeyPolicy] = field(default=None)
    cache_mode: Optional[str] = field(default=None)
    client_ttl: Optional[int] = field(default=None)
    default_ttl: Optional[int] = field(default=None)
    max_ttl: Optional[int] = field(default=None)
    negative_caching: Optional[bool] = field(default=None)
    negative_caching_policy: Optional[List[GcpBackendServiceCdnPolicyNegativeCachingPolicy]] = field(default=None)
    request_coalescing: Optional[bool] = field(default=None)
    serve_while_stale: Optional[int] = field(default=None)
    signed_url_cache_max_age_sec: Optional[str] = field(default=None)
    signed_url_key_names: Optional[List[str]] = field(default=None)


@define(eq=False, slots=False)
class GcpCircuitBreakers:
    kind: ClassVar[str] = "gcp_circuit_breakers"
    kind_display: ClassVar[str] = "GCP Circuit Breakers"
    kind_description: ClassVar[str] = (
        "GCP Backend Service Circuit Breakers set limits on connections, pending"
        " requests, and retries to prevent overloading backend resources."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "max_connections": S("maxConnections"),
        "max_pending_requests": S("maxPendingRequests"),
        "max_requests": S("maxRequests"),
        "max_requests_per_connection": S("maxRequestsPerConnection"),
        "max_retries": S("maxRetries"),
    }
    max_connections: Optional[int] = field(default=None)
    max_pending_requests: Optional[int] = field(default=None)
    max_requests: Optional[int] = field(default=None)
    max_requests_per_connection: Optional[int] = field(default=None)
    max_retries: Optional[int] = field(default=None)


@define(eq=False, slots=False)
class GcpBackendServiceConnectionTrackingPolicy:
    kind: ClassVar[str] = "gcp_backend_service_connection_tracking_policy"
    kind_display: ClassVar[str] = "GCP Backend Service Connection Tracking Policy"
    kind_description: ClassVar[str] = (
        "GCP Backend Service Connection Tracking Policy defines the parameters for managing connections,"
        " including persistence on unhealthy backends, affinity strength, idle timeout, and tracking mode."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "connection_persistence_on_unhealthy_backends": S("connectionPersistenceOnUnhealthyBackends"),
        "enable_strong_affinity": S("enableStrongAffinity"),
        "idle_timeout_sec": S("idleTimeoutSec"),
        "tracking_mode": S("trackingMode"),
    }
    connection_persistence_on_unhealthy_backends: Optional[str] = field(default=None)
    enable_strong_affinity: Optional[bool] = field(default=None)
    idle_timeout_sec: Optional[int] = field(default=None)
    tracking_mode: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpDuration:
    kind: ClassVar[str] = "gcp_duration"
    kind_display: ClassVar[str] = "GCP Duration"
    kind_description: ClassVar[str] = "Duration represents a length of time in Google Cloud Platform (GCP) services."
    mapping: ClassVar[Dict[str, Bender]] = {"nanos": S("nanos"), "seconds": S("seconds")}
    nanos: Optional[int] = field(default=None)
    seconds: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpConsistentHashLoadBalancerSettingsHttpCookie:
    kind: ClassVar[str] = "gcp_consistent_hash_load_balancer_settings_http_cookie"
    kind_display: ClassVar[str] = "GCP Consistent Hash Load Balancer with HTTP Cookie"
    kind_description: ClassVar[str] = (
        "Consistent Hash Load Balancer with HTTP Cookie is a load balancing setting"
        " in Google Cloud Platform (GCP) that uses consistent hashing with the HTTP"
        " cookie to route requests to backend services."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "name": S("name"),
        "path": S("path"),
        "ttl": S("ttl", default={}) >> Bend(GcpDuration.mapping),
    }
    name: Optional[str] = field(default=None)
    path: Optional[str] = field(default=None)
    ttl: Optional[GcpDuration] = field(default=None)


@define(eq=False, slots=False)
class GcpConsistentHashLoadBalancerSettings:
    kind: ClassVar[str] = "gcp_consistent_hash_load_balancer_settings"
    kind_display: ClassVar[str] = "GCP Consistent Hash Load Balancer Settings"
    kind_description: ClassVar[str] = (
        "Consistent Hash Load Balancer Settings in Google Cloud Platform (GCP) allow"
        " you to route incoming requests to different backend instances based on the"
        " hashed value of certain request components, providing a consistent routing"
        " mechanism."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "http_cookie": S("httpCookie", default={}) >> Bend(GcpConsistentHashLoadBalancerSettingsHttpCookie.mapping),
        "http_header_name": S("httpHeaderName"),
        "minimum_ring_size": S("minimumRingSize"),
    }
    http_cookie: Optional[GcpConsistentHashLoadBalancerSettingsHttpCookie] = field(default=None)
    http_header_name: Optional[str] = field(default=None)
    minimum_ring_size: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpBackendServiceFailoverPolicy:
    kind: ClassVar[str] = "gcp_backend_service_failover_policy"
    kind_display: ClassVar[str] = "GCP Backend Service Failover Policy"
    kind_description: ClassVar[str] = (
        "A failover policy for Google Cloud Platform backend services, which"
        " determines how traffic is redirected to different backends in the event of a"
        " failure."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "disable_connection_drain_on_failover": S("disableConnectionDrainOnFailover"),
        "drop_traffic_if_unhealthy": S("dropTrafficIfUnhealthy"),
        "failover_ratio": S("failoverRatio"),
    }
    disable_connection_drain_on_failover: Optional[bool] = field(default=None)
    drop_traffic_if_unhealthy: Optional[bool] = field(default=None)
    failover_ratio: Optional[float] = field(default=None)


@define(eq=False, slots=False)
class GcpBackendServiceIAP:
    kind: ClassVar[str] = "gcp_backend_service_iap"
    kind_display: ClassVar[str] = "GCP Backend Service IAP"
    kind_description: ClassVar[str] = (
        "GCP Backend Service IAP is a feature in Google Cloud Platform that provides"
        " Identity-Aware Proxy (IAP) for a backend service, allowing fine-grained"
        " access control to the backend resources based on user identity and context."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "enabled": S("enabled"),
        "oauth2_client_id": S("oauth2ClientId"),
        "oauth2_client_secret": S("oauth2ClientSecret"),
        "oauth2_client_secret_sha256": S("oauth2ClientSecretSha256"),
    }
    enabled: Optional[bool] = field(default=None)
    oauth2_client_id: Optional[str] = field(default=None)
    oauth2_client_secret: Optional[str] = field(default=None)
    oauth2_client_secret_sha256: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpBackendServiceLocalityLoadBalancingPolicyConfigCustomPolicy:
    kind: ClassVar[str] = "gcp_backend_service_locality_load_balancing_policy_config_custom_policy"
    kind_display: ClassVar[str] = "GCP Backend Service Locality Load Balancing Policy Config Custom Policy"
    kind_description: ClassVar[str] = (
        "This resource allows customization of the locality load balancing policy"
        " configuration for a Google Cloud Platform (GCP) Backend Service. Locality"
        " load balancing is a policy that optimizes traffic distribution based on the"
        " proximity of backend services to clients, improving the overall performance"
        " and latency of the system."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"data": S("data"), "name": S("name")}
    data: Optional[str] = field(default=None)
    name: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpBackendServiceLocalityLoadBalancingPolicyConfig:
    kind: ClassVar[str] = "gcp_backend_service_locality_load_balancing_policy_config"
    kind_display: ClassVar[str] = "GCP Backend Service Locality Load Balancing Policy Config"
    kind_description: ClassVar[str] = (
        "This is a configuration for the locality load balancing policy in Google"
        " Cloud Platform's Backend Service, which enables routing of traffic to"
        " backend instances based on their geographical locality for better"
        " performance and availability."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "custom_policy": S("customPolicy", default={})
        >> Bend(GcpBackendServiceLocalityLoadBalancingPolicyConfigCustomPolicy.mapping),
        "policy": S("policy", "name"),
    }
    custom_policy: Optional[GcpBackendServiceLocalityLoadBalancingPolicyConfigCustomPolicy] = field(default=None)
    policy: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpBackendServiceLogConfig:
    kind: ClassVar[str] = "gcp_backend_service_log_config"
    kind_display: ClassVar[str] = "GCP Backend Service Log Config"
    kind_description: ClassVar[str] = (
        "Backend Service Log Config allows you to configure logging for a Google"
        " Cloud Platform (GCP) backend service, providing visibility into the requests"
        " and responses processed by the service."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"enable": S("enable"), "sample_rate": S("sampleRate")}
    enable: Optional[bool] = field(default=None)
    sample_rate: Optional[float] = field(default=None)


@define(eq=False, slots=False)
class GcpOutlierDetection:
    kind: ClassVar[str] = "gcp_outlier_detection"
    kind_display: ClassVar[str] = "GCP Outlier Detection"
    kind_description: ClassVar[str] = (
        "GCP Outlier Detection is a service feature within Google Cloud's Backend Services that identifies"
        " instances in a load balancing pool which are performing suboptimally and temporarily removes them"
        " from the service rotation based on various health checks and error thresholds."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "base_ejection_time": S("baseEjectionTime", default={}) >> Bend(GcpDuration.mapping),
        "consecutive_errors": S("consecutiveErrors"),
        "consecutive_gateway_failure": S("consecutiveGatewayFailure"),
        "enforcing_consecutive_errors": S("enforcingConsecutiveErrors"),
        "enforcing_consecutive_gateway_failure": S("enforcingConsecutiveGatewayFailure"),
        "enforcing_success_rate": S("enforcingSuccessRate"),
        "interval": S("interval", default={}) >> Bend(GcpDuration.mapping),
        "max_ejection_percent": S("maxEjectionPercent"),
        "success_rate_minimum_hosts": S("successRateMinimumHosts"),
        "success_rate_request_volume": S("successRateRequestVolume"),
        "success_rate_stdev_factor": S("successRateStdevFactor"),
    }
    base_ejection_time: Optional[GcpDuration] = field(default=None)
    consecutive_errors: Optional[int] = field(default=None)
    consecutive_gateway_failure: Optional[int] = field(default=None)
    enforcing_consecutive_errors: Optional[int] = field(default=None)
    enforcing_consecutive_gateway_failure: Optional[int] = field(default=None)
    enforcing_success_rate: Optional[int] = field(default=None)
    interval: Optional[GcpDuration] = field(default=None)
    max_ejection_percent: Optional[int] = field(default=None)
    success_rate_minimum_hosts: Optional[int] = field(default=None)
    success_rate_request_volume: Optional[int] = field(default=None)
    success_rate_stdev_factor: Optional[int] = field(default=None)


@define(eq=False, slots=False)
class GcpSecuritySettings:
    kind: ClassVar[str] = "gcp_security_settings"
    kind_display: ClassVar[str] = "GCP Security Settings"
    kind_description: ClassVar[str] = (
        "GCP Security Settings refers to the configuration options and policies that"
        " are put in place to ensure the security of resources and data on the Google"
        " Cloud Platform."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "client_tls_policy": S("clientTlsPolicy"),
        "subject_alt_names": S("subjectAltNames", default=[]),
    }
    client_tls_policy: Optional[str] = field(default=None)
    subject_alt_names: Optional[List[str]] = field(default=None)


@define(eq=False, slots=False)
class GcpBackendService(GcpResource):
    kind: ClassVar[str] = "gcp_backend_service"
    kind_display: ClassVar[str] = "GCP Backend Service"
    kind_description: ClassVar[str] = (
        "GCP Backend Service is a managed load balancing service provided by Google"
        " Cloud Platform that allows you to distribute traffic across multiple"
        " backends and regions in a flexible and scalable manner."
    )
    reference_kinds: ClassVar[ModelReference] = {
        "predecessors": {
            "default": ["gcp_network"],
            "delete": [
                "gcp_instance_group",
                "gcp_network_endpoint_group",
                "gcp_health_check",
                "gcp_http_health_check",
                "gcp_https_health_check",
            ],
        },
        "successors": {
            "default": [
                "gcp_instance_group",
                "gcp_network_endpoint_group",
                "gcp_health_check",
                "gcp_http_health_check",
                "gcp_https_health_check",
            ],
            "delete": ["gcp_target_tcp_proxy", "gcp_target_ssl_proxy"],
        },
    }
    api_spec: ClassVar[GcpApiSpec] = GcpApiSpec(
        service="compute",
        version="v1",
        accessors=["backendServices"],
        action="aggregatedList",
        request_parameter={"project": "{project}"},
        request_parameter_in={"project"},
        response_path="items",
        response_regional_sub_path="backendServices",
        mutate_iam_permissions=["compute.backendServices.update", "compute.backendServices.delete"],
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
        "affinity_cookie_ttl_sec": S("affinityCookieTtlSec"),
        "backend_service_backends": S("backends", default=[]) >> ForallBend(GcpBackend.mapping),
        "backend_service_cdn_policy": S("cdnPolicy", default={}) >> Bend(GcpBackendServiceCdnPolicy.mapping),
        "circuit_breakers": S("circuitBreakers", default={}) >> Bend(GcpCircuitBreakers.mapping),
        "compression_mode": S("compressionMode"),
        "connection_draining": S("connectionDraining", "drainingTimeoutSec"),
        "connection_tracking_policy": S("connectionTrackingPolicy", default={})
        >> Bend(GcpBackendServiceConnectionTrackingPolicy.mapping),
        "consistent_hash": S("consistentHash", default={}) >> Bend(GcpConsistentHashLoadBalancerSettings.mapping),
        "custom_request_headers": S("customRequestHeaders", default=[]),
        "custom_response_headers": S("customResponseHeaders", default=[]),
        "edge_security_policy": S("edgeSecurityPolicy"),
        "enable_cdn": S("enableCDN"),
        "failover_policy": S("failoverPolicy", default={}) >> Bend(GcpBackendServiceFailoverPolicy.mapping),
        "fingerprint": S("fingerprint"),
        "health_checks": S("healthChecks", default=[]),
        "iap": S("iap", default={}) >> Bend(GcpBackendServiceIAP.mapping),
        "load_balancing_scheme": S("loadBalancingScheme"),
        "locality_lb_policies": S("localityLbPolicies", default=[])
        >> ForallBend(GcpBackendServiceLocalityLoadBalancingPolicyConfig.mapping),
        "locality_lb_policy": S("localityLbPolicy"),
        "backend_service_log_config": S("logConfig", default={}) >> Bend(GcpBackendServiceLogConfig.mapping),
        "max_stream_duration": S("maxStreamDuration", default={}) >> Bend(GcpDuration.mapping),
        "network": S("network"),
        "outlier_detection": S("outlierDetection", default={}) >> Bend(GcpOutlierDetection.mapping),
        "port": S("port"),
        "port_name": S("portName"),
        "protocol": S("protocol"),
        "security_policy": S("securityPolicy"),
        "security_settings": S("securitySettings", default={}) >> Bend(GcpSecuritySettings.mapping),
        "service_bindings": S("serviceBindings", default=[]),
        "session_affinity": S("sessionAffinity"),
        "subsetting": S("subsetting", "policy"),
        "timeout_sec": S("timeoutSec"),
    }
    affinity_cookie_ttl_sec: Optional[int] = field(default=None)
    backend_service_backends: Optional[List[GcpBackend]] = field(default=None)
    backend_service_cdn_policy: Optional[GcpBackendServiceCdnPolicy] = field(default=None)
    circuit_breakers: Optional[GcpCircuitBreakers] = field(default=None)
    compression_mode: Optional[str] = field(default=None)
    connection_draining: Optional[int] = field(default=None)
    connection_tracking_policy: Optional[GcpBackendServiceConnectionTrackingPolicy] = field(default=None)
    consistent_hash: Optional[GcpConsistentHashLoadBalancerSettings] = field(default=None)
    custom_request_headers: Optional[List[str]] = field(default=None)
    custom_response_headers: Optional[List[str]] = field(default=None)
    edge_security_policy: Optional[str] = field(default=None)
    enable_cdn: Optional[bool] = field(default=None)
    failover_policy: Optional[GcpBackendServiceFailoverPolicy] = field(default=None)
    fingerprint: Optional[str] = field(default=None)
    health_checks: Optional[List[str]] = field(default=None)
    iap: Optional[GcpBackendServiceIAP] = field(default=None)
    load_balancing_scheme: Optional[str] = field(default=None)
    locality_lb_policies: Optional[List[GcpBackendServiceLocalityLoadBalancingPolicyConfig]] = field(default=None)
    locality_lb_policy: Optional[str] = field(default=None)
    backend_service_log_config: Optional[GcpBackendServiceLogConfig] = field(default=None)
    max_stream_duration: Optional[GcpDuration] = field(default=None)
    network: Optional[str] = field(default=None)
    outlier_detection: Optional[GcpOutlierDetection] = field(default=None)
    port: Optional[int] = field(default=None)
    port_name: Optional[str] = field(default=None)
    protocol: Optional[str] = field(default=None)
    security_policy: Optional[str] = field(default=None)
    security_settings: Optional[GcpSecuritySettings] = field(default=None)
    service_bindings: Optional[List[str]] = field(default=None)
    session_affinity: Optional[str] = field(default=None)
    subsetting: Optional[str] = field(default=None)
    timeout_sec: Optional[int] = field(default=None)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        for check in self.health_checks or []:
            builder.dependant_node(self, clazz=health_check_types(), link=check)
        for backend in self.backend_service_backends or []:
            if backend.group:
                builder.dependant_node(self, link=backend.group)
        if self.network:
            builder.add_edge(self, reverse=True, clazz=GcpNetwork, link=self.network)


@define(eq=False, slots=False)
class GcpDiskType(GcpResource, BaseVolumeType):
    kind: ClassVar[str] = "gcp_disk_type"
    kind_display: ClassVar[str] = "GCP Disk Type"
    kind_description: ClassVar[str] = (
        "GCP Disk Types are storage options provided by Google Cloud Platform, which"
        " define the performance characteristics and pricing of persistent disks."
    )
    api_spec: ClassVar[GcpApiSpec] = GcpApiSpec(
        service="compute",
        version="v1",
        accessors=["diskTypes"],
        action="aggregatedList",
        request_parameter={"project": "{project}"},
        request_parameter_in={"project"},
        response_path="items",
        response_regional_sub_path="diskTypes",
        mutate_iam_permissions=[],  # can not be mutated
    )
    reference_kinds: ClassVar[ModelReference] = {"predecessors": {"default": ["gcp_sku"]}}
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("name").or_else(S("id")).or_else(S("selfLink")),
        "tags": S("labels", default={}),
        "name": S("name"),
        "ctime": S("creationTimestamp"),
        "description": S("description"),
        "link": S("selfLink"),
        "label_fingerprint": S("labelFingerprint"),
        "deprecation_status": S("deprecated", default={}) >> Bend(GcpDeprecationStatus.mapping),
        "default_disk_size_gb": S("defaultDiskSizeGb") >> AsInt(),
        "valid_disk_size": S("validDiskSize"),
    }
    default_disk_size_gb: Optional[int] = field(default=None)
    valid_disk_size: Optional[str] = field(default=None)

    resource_group_map: ClassVar[Dict[str, str]] = {
        "local-ssd": "LocalSSD",
        "pd-balanced": "SSD",
        "pd-ssd": "SSD",
        "pd-standard": "PDStandard",
    }

    def post_process_instance(self, builder: GraphBuilder, source: Json) -> None:
        """Adds edges from disk_types type to SKUs and determines ondemand pricing"""
        if not self.name:
            return

        log.debug((f"Looking up pricing for {self.rtdname} in {self.region().rtdname}"))
        resource_group = self.resource_group_map.get(self.name)

        def sku_filter(sku: GcpSku) -> bool:
            if not self.name:
                return False
            if not sku.description or not sku.category or not sku.geo_taxonomy:
                return False
            if self.region().name not in sku.geo_taxonomy.regions:
                return False

            if sku.category.resource_family != "Storage" or sku.category.usage_type != "OnDemand":
                return False
            if not sku.category.resource_group == resource_group:
                return False

            if self.name == "pd-balanced" and not sku.description.startswith("Balanced"):
                return False
            if self.name != "pd-balanced" and "Balanced" in sku.description:
                return False
            if self.zone().name != "undefined" and sku.description.startswith("Regional"):
                # Zonal (i.e. not regional?) disk_type but regional SKU
                return False
            if (
                # Zonal disk_type, but regional SKU and ALSO
                # not of type pd-balanced
                self.zone().name == "undefined"
                and not sku.description.startswith("Regional")
                and self.name != "pd-balanced"
            ):
                return False
            return True

        skus = builder.nodes(GcpSku, filter=sku_filter)
        if len(skus) == 1 and skus[0].usage_unit_nanos:
            builder.add_edge(self, reverse=True, node=skus[0])
            self.ondemand_cost = skus[0].usage_unit_nanos / 1000000000
        else:
            log.debug(f"Unable to determine SKU for {self.rtdname}")


@define(eq=False, slots=False)
class GcpCustomerEncryptionKey:
    kind: ClassVar[str] = "gcp_customer_encryption_key"
    kind_display: ClassVar[str] = "GCP Customer Encryption Key"
    kind_description: ClassVar[str] = (
        "Customer Encryption Keys (CEK) allow Google Cloud Platform customers to"
        " encrypt their data using keys that they manage and control, providing an"
        " extra layer of security for sensitive data."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "kms_key_name": S("kmsKeyName"),
        "kms_key_service_account": S("kmsKeyServiceAccount"),
        "raw_key": S("rawKey"),
        "rsa_encrypted_key": S("rsaEncryptedKey"),
        "sha256": S("sha256"),
    }
    kms_key_name: Optional[str] = field(default=None)
    kms_key_service_account: Optional[str] = field(default=None)
    raw_key: Optional[str] = field(default=None)
    rsa_encrypted_key: Optional[str] = field(default=None)
    sha256: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpDiskParams:
    kind: ClassVar[str] = "gcp_disk_params"
    kind_display: ClassVar[str] = "GCP Disk Params"
    kind_description: ClassVar[str] = (
        "GCP Disk Params refers to the parameters associated with disks in the Google"
        " Cloud Platform (GCP). Disks in GCP provide a persistent block storage option"
        " for virtual machine instances in GCP."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"resource_manager_tags": S("resourceManagerTags")}
    resource_manager_tags: Optional[Dict[str, str]] = field(default=None)


@define(eq=False, slots=False)
class GcpDisk(GcpResource, BaseVolume):
    kind: ClassVar[str] = "gcp_disk"
    kind_display: ClassVar[str] = "GCP Disk"
    kind_description: ClassVar[str] = (
        "GCP Disk is a persistent block storage service provided by Google Cloud"
        " Platform, allowing users to store and manage data in the cloud."
    )
    reference_kinds: ClassVar[ModelReference] = {
        "predecessors": {"default": ["gcp_disk_type", "gcp_instance"]},
        "successors": {"delete": ["gcp_instance"]},
    }
    api_spec: ClassVar[GcpApiSpec] = GcpApiSpec(
        service="compute",
        version="v1",
        accessors=["disks"],
        action="aggregatedList",
        request_parameter={"project": "{project}"},
        request_parameter_in={"project"},
        response_path="items",
        response_regional_sub_path="disks",
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
        "architecture": S("architecture"),
        "disk_encryption_key": S("diskEncryptionKey", default={}) >> Bend(GcpCustomerEncryptionKey.mapping),
        "guest_os_features": S("guestOsFeatures", default=[]) >> ForallBend(S("type")),
        "last_attach_timestamp": S("lastAttachTimestamp"),
        "last_detach_timestamp": S("lastDetachTimestamp"),
        "license_codes": S("licenseCodes", default=[]),
        "licenses": S("licenses", default=[]),
        "location_hint": S("locationHint"),
        "options": S("options"),
        "disk_params": S("params", default={}) >> Bend(GcpDiskParams.mapping),
        "physical_block_size_bytes": S("physicalBlockSizeBytes"),
        "provisioned_iops": S("provisionedIops") >> AsInt(),
        "replica_zones": S("replicaZones", default=[]),
        "resource_policies": S("resourcePolicies", default=[]),
        "satisfies_pzs": S("satisfiesPzs"),
        "size_gb": S("sizeGb"),
        "source_disk": S("sourceDisk"),
        "source_disk_id": S("sourceDiskId"),
        "source_image": S("sourceImage"),
        "source_image_encryption_key": S("sourceImageEncryptionKey", default={})
        >> Bend(GcpCustomerEncryptionKey.mapping),
        "source_image_id": S("sourceImageId"),
        "source_snapshot": S("sourceSnapshot"),
        "source_snapshot_encryption_key": S("sourceSnapshotEncryptionKey", default={})
        >> Bend(GcpCustomerEncryptionKey.mapping),
        "source_snapshot_id": S("sourceSnapshotId"),
        "source_storage_object": S("sourceStorageObject"),
        "status": S("status"),
        "type": S("type"),
        "users": S("users", default=[]),
        "volume_status": S("status")
        >> MapEnum(
            {
                "CREATING": VolumeStatus.BUSY,
                "RESTORING": VolumeStatus.BUSY,
                "FAILED": VolumeStatus.ERROR,
                "READY": VolumeStatus.IN_USE,
                "AVAILABLE": VolumeStatus.AVAILABLE,
                "DELETING": VolumeStatus.BUSY,
            },
            default=VolumeStatus.UNKNOWN,
        ),
        "volume_size": S("sizeGb") >> F(float),
        "volume_type": S("type"),
        "volume_iops": S("provisionedIops"),
        "volume_encrypted": S("diskEncryptionKey") >> F(lambda x: x is not None),
    }

    architecture: Optional[str] = field(default=None)
    disk_encryption_key: Optional[GcpCustomerEncryptionKey] = field(default=None)
    guest_os_features: Optional[List[str]] = field(default=None)
    last_attach_timestamp: Optional[datetime] = field(default=None)
    last_detach_timestamp: Optional[datetime] = field(default=None)
    license_codes: Optional[List[str]] = field(default=None)
    licenses: Optional[List[str]] = field(default=None)
    location_hint: Optional[str] = field(default=None)
    options: Optional[str] = field(default=None)
    disk_params: Optional[GcpDiskParams] = field(default=None)
    physical_block_size_bytes: Optional[str] = field(default=None)
    provisioned_iops: Optional[int] = field(default=None)
    replica_zones: Optional[List[str]] = field(default=None)
    resource_policies: Optional[List[str]] = field(default=None)
    satisfies_pzs: Optional[bool] = field(default=None)
    size_gb: Optional[str] = field(default=None)
    source_disk: Optional[str] = field(default=None)
    source_disk_id: Optional[str] = field(default=None)
    source_image: Optional[str] = field(default=None)
    source_image_encryption_key: Optional[GcpCustomerEncryptionKey] = field(default=None)
    source_image_id: Optional[str] = field(default=None)
    source_snapshot: Optional[str] = field(default=None)
    source_snapshot_encryption_key: Optional[GcpCustomerEncryptionKey] = field(default=None)
    source_snapshot_id: Optional[str] = field(default=None)
    source_storage_object: Optional[str] = field(default=None)
    status: Optional[str] = field(default=None)
    type: Optional[str] = field(default=None)
    users: Optional[List[str]] = field(default=None)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        for user in source.get("users", []):
            builder.dependant_node(self, clazz=GcpInstance, link=user, reverse=True, delete_same_as_default=False)
        builder.add_edge(self, reverse=True, clazz=GcpDiskType, link=self.volume_type)


@define(eq=False, slots=False)
class GcpExternalVpnGatewayInterface:
    kind: ClassVar[str] = "gcp_external_vpn_gateway_interface"
    kind_display: ClassVar[str] = "GCP External VPN Gateway Interface"
    kind_description: ClassVar[str] = (
        "External VPN Gateway Interface is a network interface in Google Cloud"
        " Platform used to connect on-premises networks to virtual private networks"
        " (VPNs) in GCP."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"id": S("id"), "ip_address": S("ipAddress")}
    id: Optional[int] = field(default=None)
    ip_address: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpExternalVpnGateway(GcpResource):
    kind: ClassVar[str] = "gcp_external_vpn_gateway"
    kind_display: ClassVar[str] = "GCP External VPN Gateway"
    kind_description: ClassVar[str] = (
        "GCP External VPN Gateway is a resource that provides connectivity from Google Cloud to external networks"
        " via VPN, featuring interfaces for tunnel configuration and redundancy options for high availability."
    )
    api_spec: ClassVar[GcpApiSpec] = GcpApiSpec(
        service="compute",
        version="v1",
        accessors=["externalVpnGateways"],
        action="list",
        request_parameter={"project": "{project}"},
        request_parameter_in={"project"},
        response_path="items",
        response_regional_sub_path=None,
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
        "external_vpn_gateway_interfaces": S("interfaces", default=[])
        >> ForallBend(GcpExternalVpnGatewayInterface.mapping),
        "redundancy_type": S("redundancyType"),
    }
    external_vpn_gateway_interfaces: Optional[List[GcpExternalVpnGatewayInterface]] = field(default=None)
    redundancy_type: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpFirewallPolicyAssociation:
    kind: ClassVar[str] = "gcp_firewall_policy_association"
    kind_display: ClassVar[str] = "GCP Firewall Policy Association"
    kind_description: ClassVar[str] = (
        "Firewall Policy Association is a feature in Google Cloud Platform that"
        " allows you to associate firewall policies with target resources, such as"
        " virtual machines or subnets, to control incoming and outgoing traffic based"
        " on predefined rules."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "attachment_target": S("attachmentTarget"),
        "display_name": S("displayName"),
        "firewall_policy_id": S("firewallPolicyId"),
        "name": S("name"),
        "short_name": S("shortName"),
    }
    attachment_target: Optional[str] = field(default=None)
    display_name: Optional[str] = field(default=None)
    firewall_policy_id: Optional[str] = field(default=None)
    name: Optional[str] = field(default=None)
    short_name: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpFirewallPolicyRuleMatcherLayer4Config:
    kind: ClassVar[str] = "gcp_firewall_policy_rule_matcher_layer4_config"
    kind_display: ClassVar[str] = "GCP Firewall Policy Rule Matcher Layer4 Config"
    kind_description: ClassVar[str] = (
        "GCP Firewall Policy Rule Matcher Layer4 Config is a configuration for"
        " matching Layer 4 (transport layer) parameters in firewall rules in Google"
        " Cloud Platform. This configuration allows you to customize and control"
        " network traffic based on protocols, ports, and IP addresses."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"ip_protocol": S("ipProtocol"), "ports": S("ports", default=[])}
    ip_protocol: Optional[str] = field(default=None)
    ports: Optional[List[str]] = field(default=None)


@define(eq=False, slots=False)
class GcpFirewallPolicyRuleSecureTag:
    kind: ClassVar[str] = "gcp_firewall_policy_rule_secure_tag"
    kind_display: ClassVar[str] = "GCP Firewall Policy Rule Secure Tag"
    kind_description: ClassVar[str] = (
        "GCP Firewall Policy Rule Secure Tag is an identifier used to specify a secure tag"
        " for matching criteria within a firewall policy rule in Google Cloud Platform."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"name": S("name"), "firewall_policy_rule_secure_tag_state": S("state")}
    name: Optional[str] = field(default=None)
    firewall_policy_rule_secure_tag_state: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpFirewallPolicyRuleMatcher:
    kind: ClassVar[str] = "gcp_firewall_policy_rule_matcher"
    kind_display: ClassVar[str] = "GCP Firewall Policy Rule Matcher"
    kind_description: ClassVar[str] = (
        "This resource represents a rule matcher within a firewall policy in Google"
        " Cloud Platform (GCP). It is used to define specific match criteria for"
        " incoming or outgoing traffic."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "dest_ip_ranges": S("destIpRanges", default=[]),
        "layer4_configs": S("layer4Configs", default=[])
        >> ForallBend(GcpFirewallPolicyRuleMatcherLayer4Config.mapping),
        "src_ip_ranges": S("srcIpRanges", default=[]),
        "src_secure_tags": S("srcSecureTags", default=[]) >> ForallBend(GcpFirewallPolicyRuleSecureTag.mapping),
    }
    dest_ip_ranges: Optional[List[str]] = field(default=None)
    layer4_configs: Optional[List[GcpFirewallPolicyRuleMatcherLayer4Config]] = field(default=None)
    src_ip_ranges: Optional[List[str]] = field(default=None)
    src_secure_tags: Optional[List[GcpFirewallPolicyRuleSecureTag]] = field(default=None)


@define(eq=False, slots=False)
class GcpFirewallPolicyRule:
    kind: ClassVar[str] = "gcp_firewall_policy_rule"
    kind_display: ClassVar[str] = "GCP Firewall Policy Rule"
    kind_description: ClassVar[str] = (
        "A GCP Firewall Policy Rule is a set of instructions that define how traffic"
        " is allowed or denied on a Google Cloud Platform virtual network."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "action": S("action"),
        "description": S("description"),
        "direction": S("direction"),
        "disabled": S("disabled"),
        "enable_logging": S("enableLogging"),
        "match": S("match", default={}) >> Bend(GcpFirewallPolicyRuleMatcher.mapping),
        "priority": S("priority"),
        "rule_name": S("ruleName"),
        "rule_tuple_count": S("ruleTupleCount"),
        "target_resources": S("targetResources", default=[]),
        "target_secure_tags": S("targetSecureTags", default=[]) >> ForallBend(GcpFirewallPolicyRuleSecureTag.mapping),
        "target_service_accounts": S("targetServiceAccounts", default=[]),
    }
    action: Optional[str] = field(default=None)
    description: Optional[str] = field(default=None)
    direction: Optional[str] = field(default=None)
    disabled: Optional[bool] = field(default=None)
    enable_logging: Optional[bool] = field(default=None)
    match: Optional[GcpFirewallPolicyRuleMatcher] = field(default=None)
    priority: Optional[int] = field(default=None)
    rule_name: Optional[str] = field(default=None)
    rule_tuple_count: Optional[int] = field(default=None)
    target_resources: Optional[List[str]] = field(default=None)
    target_secure_tags: Optional[List[GcpFirewallPolicyRuleSecureTag]] = field(default=None)
    target_service_accounts: Optional[List[str]] = field(default=None)


# TODO Firewall Policies are on org level, parentId is org id or folder id
@define(eq=False, slots=False)
class GcpFirewallPolicy(GcpResource):
    kind: ClassVar[str] = "gcp_firewall_policy"
    kind_display: ClassVar[str] = "GCP Firewall Policy"
    kind_description: ClassVar[str] = (
        "GCP Firewall Policy is a security rule set that controls incoming and"
        " outgoing network traffic for resources in the Google Cloud Platform."
    )
    reference_kinds: ClassVar[ModelReference] = {"successors": {"default": ["gcp_network"]}}
    api_spec: ClassVar[GcpApiSpec] = GcpApiSpec(
        service="compute",
        version="v1",
        accessors=["firewallPolicies"],
        action="list",
        request_parameter={},
        request_parameter_in=set(),
        response_path="items",
        response_regional_sub_path=None,
        mutate_iam_permissions=["compute.firewallPolicies.update", "compute.firewallPolicies.delete"],
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
        "associations": S("associations", default=[]) >> ForallBend(GcpFirewallPolicyAssociation.mapping),
        "display_name": S("displayName"),
        "fingerprint": S("fingerprint"),
        "parent": S("parent"),
        "rule_tuple_count": S("ruleTupleCount"),
        "firewall_policy_rules": S("rules", default=[]) >> ForallBend(GcpFirewallPolicyRule.mapping),
        "self_link_with_id": S("selfLinkWithId"),
        "short_name": S("shortName"),
    }
    associations: Optional[List[GcpFirewallPolicyAssociation]] = field(default=None)
    display_name: Optional[str] = field(default=None)
    fingerprint: Optional[str] = field(default=None)
    parent: Optional[str] = field(default=None)
    rule_tuple_count: Optional[int] = field(default=None)
    firewall_policy_rules: Optional[List[GcpFirewallPolicyRule]] = field(default=None)
    self_link_with_id: Optional[str] = field(default=None)
    short_name: Optional[str] = field(default=None)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        for rule in self.firewall_policy_rules or []:
            for resource in rule.target_resources or []:
                builder.add_edge(self, clazz=GcpNetwork, link=resource)


@define(eq=False, slots=False)
class GcpAllowed:
    kind: ClassVar[str] = "gcp_allowed"
    kind_display: ClassVar[str] = "GCP Allowed"
    kind_description: ClassVar[str] = (
        "GCP Allowed defines the protocols and ports that are permitted to pass through"
        " a firewall rule in Google Cloud Platform."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"ip_protocol": S("IPProtocol"), "ports": S("ports", default=[])}
    ip_protocol: Optional[str] = field(default=None)
    ports: Optional[List[str]] = field(default=None)


@define(eq=False, slots=False)
class GcpDenied:
    kind: ClassVar[str] = "gcp_denied"
    kind_display: ClassVar[str] = "GCP Denied"
    kind_description: ClassVar[str] = (
        "GCP Denied settings within a GCP Firewall rule specify the types of network traffic"
        " that are not allowed through, based on the IP protocol and port numbers."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"ip_protocol": S("IPProtocol"), "ports": S("ports", default=[])}
    ip_protocol: Optional[str] = field(default=None)
    ports: Optional[List[str]] = field(default=None)


@define(eq=False, slots=False)
class GcpFirewallLogConfig:
    kind: ClassVar[str] = "gcp_firewall_log_config"
    kind_display: ClassVar[str] = "GCP Firewall Log Config"
    kind_description: ClassVar[str] = (
        "Firewall Log Config is a feature in Google Cloud Platform that allows you to"
        " configure logging for network firewall rules. It provides detailed"
        " information about the traffic that matches the firewall rules, helping you"
        " monitor and analyze network activities in your GCP environment."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"enable": S("enable"), "metadata": S("metadata")}
    enable: Optional[bool] = field(default=None)
    metadata: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpFirewall(GcpResource):
    kind: ClassVar[str] = "gcp_firewall"
    kind_display: ClassVar[str] = "GCP Firewall"
    kind_description: ClassVar[str] = (
        "GCP Firewall is a network security feature provided by Google Cloud Platform"
        " that controls incoming and outgoing traffic to and from virtual machine"
        " instances."
    )
    reference_kinds: ClassVar[ModelReference] = {"successors": {"default": ["gcp_network"]}}
    api_spec: ClassVar[GcpApiSpec] = GcpApiSpec(
        service="compute",
        version="v1",
        accessors=["firewalls"],
        action="list",
        request_parameter={"project": "{project}"},
        request_parameter_in={"project"},
        response_path="items",
        response_regional_sub_path=None,
        mutate_iam_permissions=["compute.firewalls.update", "compute.firewalls.delete"],
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
        "allowed": S("allowed", default=[]) >> ForallBend(GcpAllowed.mapping),
        "denied": S("denied", default=[]) >> ForallBend(GcpDenied.mapping),
        "destination_ranges": S("destinationRanges", default=[]),
        "direction": S("direction"),
        "disabled": S("disabled"),
        "firewall_log_config": S("logConfig", default={}) >> Bend(GcpFirewallLogConfig.mapping),
        "network": S("network"),
        "priority": S("priority"),
        "source_ranges": S("sourceRanges", default=[]),
        "source_service_accounts": S("sourceServiceAccounts", default=[]),
        "source_tags": S("sourceTags", default=[]),
        "target_service_accounts": S("targetServiceAccounts", default=[]),
        "target_tags": S("targetTags", default=[]),
    }
    allowed: Optional[List[GcpAllowed]] = field(default=None)
    denied: Optional[List[GcpDenied]] = field(default=None)
    destination_ranges: Optional[List[str]] = field(default=None)
    direction: Optional[str] = field(default=None)
    disabled: Optional[bool] = field(default=None)
    firewall_log_config: Optional[GcpFirewallLogConfig] = field(default=None)
    network: Optional[str] = field(default=None)
    priority: Optional[int] = field(default=None)
    source_ranges: Optional[List[str]] = field(default=None)
    source_service_accounts: Optional[List[str]] = field(default=None)
    source_tags: Optional[List[str]] = field(default=None)
    target_service_accounts: Optional[List[str]] = field(default=None)
    target_tags: Optional[List[str]] = field(default=None)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if self.network:
            builder.add_edge(self, clazz=GcpNetwork, link=self.network)


@define(eq=False, slots=False)
class GcpMetadataFilterLabelMatch:
    kind: ClassVar[str] = "gcp_metadata_filter_label_match"
    kind_display: ClassVar[str] = "GCP Metadata Filter Label Match"
    kind_description: ClassVar[str] = (
        "GCP Metadata Filter Label Match is a feature that allows you to filter"
        " virtual machine instances based on labels in Google Cloud Platform metadata."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"name": S("name"), "value": S("value")}
    name: Optional[str] = field(default=None)
    value: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpMetadataFilter:
    kind: ClassVar[str] = "gcp_metadata_filter"
    kind_display: ClassVar[str] = "GCP Metadata Filter"
    kind_description: ClassVar[str] = ""
    mapping: ClassVar[Dict[str, Bender]] = {
        "filter_labels": S("filterLabels", default=[]) >> ForallBend(GcpMetadataFilterLabelMatch.mapping),
        "filter_match_criteria": S("filterMatchCriteria"),
    }
    filter_labels: Optional[List[GcpMetadataFilterLabelMatch]] = field(default=None)
    filter_match_criteria: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpForwardingRuleServiceDirectoryRegistration:
    kind: ClassVar[str] = "gcp_forwarding_rule_service_directory_registration"
    kind_display: ClassVar[str] = "GCP Forwarding Rule Service Directory Registration"
    kind_description: ClassVar[str] = (
        "The GCP Forwarding Rule Service Directory Registration enables a forwarding rule to register itself with a"
        " specific service in Google Cloud's Service Directory, specifying the namespace and region for service"
        " discovery and routing."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "namespace": S("namespace"),
        "service": S("service"),
        "service_directory_region": S("serviceDirectoryRegion"),
    }
    namespace: Optional[str] = field(default=None)
    service: Optional[str] = field(default=None)
    service_directory_region: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpForwardingRule(GcpResource):
    kind: ClassVar[str] = "gcp_forwarding_rule"
    kind_display: ClassVar[str] = "GCP Forwarding Rule"
    kind_description: ClassVar[str] = (
        "Forwarding rules are used in Google Cloud Platform to route traffic to"
        " different destinations based on the configuration settings. They can be used"
        " to load balance or redirect traffic within a network or between networks."
    )
    reference_kinds: ClassVar[ModelReference] = {
        "predecessors": {"default": ["gcp_network"]},
        "successors": {
            "default": [
                "gcp_target_vpn_gateway",
                "gcp_target_tcp_proxy",
                "gcp_target_ssl_proxy",
                "gcp_target_grpc_proxy",
                "gcp_target_http_proxy",
                "gcp_target_https_proxy",
                "gcp_target_pool",
            ],
            "delete": [],
        },
    }
    api_spec: ClassVar[GcpApiSpec] = GcpApiSpec(
        service="compute",
        version="v1",
        accessors=["forwardingRules"],
        action="aggregatedList",
        request_parameter={"project": "{project}"},
        request_parameter_in={"project"},
        response_path="items",
        response_regional_sub_path="forwardingRules",
        mutate_iam_permissions=["compute.forwardingRules.delete"],
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
        "ip_address": S("IPAddress"),
        "ip_protocol": S("IPProtocol"),
        "all_ports": S("allPorts"),
        "allow_global_access": S("allowGlobalAccess"),
        "backend_service": S("backendService"),
        "fingerprint": S("fingerprint"),
        "ip_version": S("ipVersion"),
        "is_mirroring_collector": S("isMirroringCollector"),
        "load_balancing_scheme": S("loadBalancingScheme"),
        "metadata_filters": S("metadataFilters", default=[]) >> ForallBend(GcpMetadataFilter.mapping),
        "network": S("network"),
        "network_tier": S("networkTier"),
        "no_automate_dns_zone": S("noAutomateDnsZone"),
        "port_range": S("portRange"),
        "ports": S("ports", default=[]),
        "psc_connection_id": S("pscConnectionId"),
        "psc_connection_status": S("pscConnectionStatus"),
        "service_directory_registrations": S("serviceDirectoryRegistrations", default=[])
        >> ForallBend(GcpForwardingRuleServiceDirectoryRegistration.mapping),
        "service_label": S("serviceLabel"),
        "service_name": S("serviceName"),
        "subnetwork": S("subnetwork"),
        "target": S("target"),
    }
    ip_address: Optional[str] = field(default=None)
    ip_protocol: Optional[str] = field(default=None)
    all_ports: Optional[bool] = field(default=None)
    allow_global_access: Optional[bool] = field(default=None)
    backend_service: Optional[str] = field(default=None)
    fingerprint: Optional[str] = field(default=None)
    ip_version: Optional[str] = field(default=None)
    is_mirroring_collector: Optional[bool] = field(default=None)
    load_balancing_scheme: Optional[str] = field(default=None)
    metadata_filters: Optional[List[GcpMetadataFilter]] = field(default=None)
    network: Optional[str] = field(default=None)
    network_tier: Optional[str] = field(default=None)
    no_automate_dns_zone: Optional[bool] = field(default=None)
    port_range: Optional[str] = field(default=None)
    ports: Optional[List[str]] = field(default=None)
    psc_connection_id: Optional[str] = field(default=None)
    psc_connection_status: Optional[str] = field(default=None)
    service_directory_registrations: Optional[List[GcpForwardingRuleServiceDirectoryRegistration]] = field(default=None)
    service_label: Optional[str] = field(default=None)
    service_name: Optional[str] = field(default=None)
    subnetwork: Optional[str] = field(default=None)
    target: Optional[str] = field(default=None)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if self.network:
            builder.add_edge(self, reverse=True, clazz=GcpNetwork, link=self.network)
        if self.target:
            target_classes = (
                GcpTargetVpnGateway,
                GcpTargetTcpProxy,
                GcpTargetSslProxy,
                GcpTargetGrpcProxy,
                GcpTargetHttpProxy,
                GcpTargetHttpsProxy,
                GcpTargetPool,
            )
            builder.add_edge(self, clazz=target_classes, link=self.target)


@define(eq=False, slots=False)
class GcpNetworkEndpointGroupAppEngine:
    kind: ClassVar[str] = "gcp_network_endpoint_group_app_engine"
    kind_display: ClassVar[str] = "GCP Network Endpoint Group App Engine"
    kind_description: ClassVar[str] = (
        "The GCP Network Endpoint Group App Engine configuration defines how traffic is directed to different"
        " versions of a deployed App Engine service, potentially using URL masks for routing."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"service": S("service"), "url_mask": S("urlMask"), "version": S("version")}
    service: Optional[str] = field(default=None)
    url_mask: Optional[str] = field(default=None)
    version: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpNetworkEndpointGroupCloudFunction:
    kind: ClassVar[str] = "gcp_network_endpoint_group_cloud_function"
    kind_display: ClassVar[str] = "GCP Network Endpoint Group Cloud Function"
    kind_description: ClassVar[str] = (
        "The GCP Network Endpoint Group Cloud Function configuration specifies the details for routing network"
        " traffic to a particular Google Cloud Function, including the function identifier and the URL"
        " mask for matching request paths."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"function": S("function"), "url_mask": S("urlMask")}
    function: Optional[str] = field(default=None)
    url_mask: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpNetworkEndpointGroupCloudRun:
    kind: ClassVar[str] = "gcp_network_endpoint_group_cloud_run"
    kind_display: ClassVar[str] = "GCP Network Endpoint Group Cloud Run"
    kind_description: ClassVar[str] = (
        "The GCP Network Endpoint Group Cloud Run configuration determines how traffic is directed to a specific"
        " Cloud Run service, utilizing a URL mask for path matching and an optional tag to identify a specific"
        " service deployment or revision."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"service": S("service"), "tag": S("tag"), "url_mask": S("urlMask")}
    service: Optional[str] = field(default=None)
    tag: Optional[str] = field(default=None)
    url_mask: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpNetworkEndpointGroupPscData:
    kind: ClassVar[str] = "gcp_network_endpoint_group_psc_data"
    kind_display: ClassVar[str] = "GCP Network Endpoint Group PSC Data"
    kind_description: ClassVar[str] = (
        "The GCP Network Endpoint Group PSC Data settings manage the Private Service Connect (PSC) endpoint"
        " connections, detailing the consumer's PSC address, the unique connection identifier, and the"
        " current status of the PSC connection."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "consumer_psc_address": S("consumerPscAddress"),
        "psc_connection_id": S("pscConnectionId"),
        "psc_connection_status": S("pscConnectionStatus"),
    }
    consumer_psc_address: Optional[str] = field(default=None)
    psc_connection_id: Optional[str] = field(default=None)
    psc_connection_status: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpNetworkEndpointGroup(GcpResource):
    kind: ClassVar[str] = "gcp_network_endpoint_group"
    kind_display: ClassVar[str] = "GCP Network Endpoint Group"
    kind_description: ClassVar[str] = (
        "A GCP Network Endpoint Group is a logical grouping of network endpoints,"
        " allowing users to distribute network traffic across multiple endpoints in"
        " Google Cloud Platform."
    )
    reference_kinds: ClassVar[ModelReference] = {
        "predecessors": {"default": ["gcp_network", "gcp_subnetwork"], "delete": ["gcp_network", "gcp_subnetwork"]}
    }
    api_spec: ClassVar[GcpApiSpec] = GcpApiSpec(
        service="compute",
        version="v1",
        accessors=["networkEndpointGroups"],
        action="aggregatedList",
        request_parameter={"project": "{project}"},
        request_parameter_in={"project"},
        response_path="items",
        response_regional_sub_path="networkEndpointGroups",
        mutate_iam_permissions=["compute.networkEndpointGroups.delete"],
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
        "annotations": S("annotations"),
        "app_engine": S("appEngine", default={}) >> Bend(GcpNetworkEndpointGroupAppEngine.mapping),
        "cloud_function": S("cloudFunction", default={}) >> Bend(GcpNetworkEndpointGroupCloudFunction.mapping),
        "cloud_run": S("cloudRun", default={}) >> Bend(GcpNetworkEndpointGroupCloudRun.mapping),
        "default_port": S("defaultPort"),
        "network": S("network"),
        "network_endpoint_type": S("networkEndpointType"),
        "psc_data": S("pscData", default={}) >> Bend(GcpNetworkEndpointGroupPscData.mapping),
        "psc_target_service": S("pscTargetService"),
        "size": S("size"),
        "subnetwork": S("subnetwork"),
    }
    annotations: Optional[Dict[str, str]] = field(default=None)
    app_engine: Optional[GcpNetworkEndpointGroupAppEngine] = field(default=None)
    cloud_function: Optional[GcpNetworkEndpointGroupCloudFunction] = field(default=None)
    cloud_run: Optional[GcpNetworkEndpointGroupCloudRun] = field(default=None)
    default_port: Optional[int] = field(default=None)
    network: Optional[str] = field(default=None)
    network_endpoint_type: Optional[str] = field(default=None)
    psc_data: Optional[GcpNetworkEndpointGroupPscData] = field(default=None)
    psc_target_service: Optional[str] = field(default=None)
    size: Optional[int] = field(default=None)
    subnetwork: Optional[str] = field(default=None)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if self.network:
            builder.dependant_node(self, reverse=True, delete_same_as_default=True, clazz=GcpNetwork, link=self.network)
        if self.subnetwork:
            builder.dependant_node(
                self, reverse=True, delete_same_as_default=True, clazz=GcpSubnetwork, link=self.subnetwork
            )


@define(eq=False, slots=False)
class GcpErrorInfo:
    kind: ClassVar[str] = "gcp_error_info"
    kind_display: ClassVar[str] = "GCP Error Info"
    kind_description: ClassVar[str] = (
        "GCP Error Info provides information about errors encountered in Google Cloud Platform services."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"domain": S("domain"), "metadatas": S("metadatas"), "reason": S("reason")}
    domain: Optional[str] = field(default=None)
    metadatas: Optional[Dict[str, str]] = field(default=None)
    reason: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpHelpLink:
    kind: ClassVar[str] = "gcp_help_link"
    kind_display: ClassVar[str] = "GCP Help Link"
    kind_description: ClassVar[str] = (
        "A link to the Google Cloud Platform documentation and support resources to"
        " help users troubleshoot and find information about GCP services and"
        " features."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"description": S("description"), "url": S("url")}
    description: Optional[str] = field(default=None)
    url: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpHelp:
    kind: ClassVar[str] = "gcp_help"
    kind_display: ClassVar[str] = "GCP Help"
    kind_description: ClassVar[str] = (
        "GCP Help is a service provided by Google Cloud Platform that offers"
        " assistance and support to users in using and managing their resources and"
        " services on GCP."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"links": S("links", default=[]) >> ForallBend(GcpHelpLink.mapping)}
    links: Optional[List[GcpHelpLink]] = field(default=None)


@define(eq=False, slots=False)
class GcpLocalizedMessage:
    kind: ClassVar[str] = "gcp_localized_message"
    kind_display: ClassVar[str] = "GCP Localized Message"
    kind_description: ClassVar[str] = (
        "GCP Localized Message provides user-friendly error messages appropriate to the locale specified"
        " in the context of Google Cloud Platform operations."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"locale": S("locale"), "message": S("message")}
    locale: Optional[str] = field(default=None)
    message: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpErrordetails:
    kind: ClassVar[str] = "gcp_errordetails"
    kind_display: ClassVar[str] = "GCP Error Details"
    kind_description: ClassVar[str] = (
        "Error details in Google Cloud Platform (GCP) provide additional information"
        " about errors that occur while using GCP services."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "error_info": S("errorInfo", default={}) >> Bend(GcpErrorInfo.mapping),
        "help": S("help", default={}) >> Bend(GcpHelp.mapping),
        "localized_message": S("localizedMessage", default={}) >> Bend(GcpLocalizedMessage.mapping),
    }
    error_info: Optional[GcpErrorInfo] = field(default=None)
    help: Optional[GcpHelp] = field(default=None)
    localized_message: Optional[GcpLocalizedMessage] = field(default=None)


@define(eq=False, slots=False)
class GcpErrors:
    kind: ClassVar[str] = "gcp_errors"
    kind_display: ClassVar[str] = "GCP Errors"
    kind_description: ClassVar[str] = (
        "GCP Errors refer to any kind of error encountered while using Google Cloud Platform services."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "code": S("code"),
        "error_details": S("errorDetails", default=[]) >> ForallBend(GcpErrordetails.mapping),
        "location": S("location"),
        "message": S("message"),
    }
    code: Optional[str] = field(default=None)
    error_details: Optional[List[GcpErrordetails]] = field(default=None)
    location: Optional[str] = field(default=None)
    message: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpError:
    kind: ClassVar[str] = "gcp_error"
    kind_display: ClassVar[str] = "GCP Error"
    kind_description: ClassVar[str] = (
        "An error that occurs within Google Cloud Platform (GCP). Please provide more"
        " specific information about the error message for further assistance."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"errors": S("errors", default=[]) >> ForallBend(GcpErrors.mapping)}
    errors: Optional[List[GcpErrors]] = field(default=None)


@define(eq=False, slots=False)
class GcpData:
    kind: ClassVar[str] = "gcp_data"
    kind_display: ClassVar[str] = "GCP Data"
    kind_description: ClassVar[str] = (
        "GCP Data refers to data storage and processing services offered by Google"
        " Cloud Platform, such as Cloud Storage, BigQuery, and Dataflow."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"key": S("key"), "value": S("value")}
    key: Optional[str] = field(default=None)
    value: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpWarnings:
    kind: ClassVar[str] = "gcp_warnings"
    kind_display: ClassVar[str] = "GCP Warnings"
    kind_description: ClassVar[str] = (
        "GCP Warnings are notifications issued by Google Cloud Platform to alert"
        " users about potential issues or concerns in their cloud resources."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "code": S("code"),
        "data": S("data", default=[]) >> ForallBend(GcpData.mapping),
        "message": S("message"),
    }
    code: Optional[str] = field(default=None)
    data: Optional[List[GcpData]] = field(default=None)
    message: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpOperation(GcpResource):
    kind: ClassVar[str] = "gcp_operation"
    kind_display: ClassVar[str] = "GCP Operation"
    kind_description: ClassVar[str] = (
        "An operation represents a long-running asynchronous API call in Google Cloud"
        " Platform (GCP), allowing users to create, update, or delete resources"
    )
    reference_kinds: ClassVar[ModelReference] = {
        "successors": {
            # operation can target multiple resources, unclear which others are possible
            "default": ["gcp_disk"],
        }
    }
    api_spec: ClassVar[GcpApiSpec] = GcpApiSpec(
        service="compute",
        version="v1",
        accessors=["globalOperations"],
        action="aggregatedList",
        request_parameter={"project": "{project}"},
        request_parameter_in={"project"},
        response_path="items",
        response_regional_sub_path="operations",
        mutate_iam_permissions=["compute.globalOperations.delete"],
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
        "client_operation_id": S("clientOperationId"),
        "end_time": S("endTime"),
        "error": S("error", default={}) >> Bend(GcpError.mapping),
        "http_error_message": S("httpErrorMessage"),
        "http_error_status_code": S("httpErrorStatusCode"),
        "insert_time": S("insertTime"),
        "operation_group_id": S("operationGroupId"),
        "operation_type": S("operationType"),
        "progress": S("progress"),
        "start_time": S("startTime"),
        "status": S("status"),
        "status_message": S("statusMessage"),
        "target_id": S("targetId"),
        "target_link": S("targetLink"),
        "user": S("user"),
        "warnings": S("warnings", default=[]) >> ForallBend(GcpWarnings.mapping),
    }
    client_operation_id: Optional[str] = field(default=None)
    end_time: Optional[datetime] = field(default=None)
    error: Optional[GcpError] = field(default=None)
    http_error_message: Optional[str] = field(default=None)
    http_error_status_code: Optional[int] = field(default=None)
    insert_time: Optional[datetime] = field(default=None)
    operation_group_id: Optional[str] = field(default=None)
    operation_type: Optional[str] = field(default=None)
    progress: Optional[int] = field(default=None)
    start_time: Optional[datetime] = field(default=None)
    status: Optional[str] = field(default=None)
    status_message: Optional[str] = field(default=None)
    target_id: Optional[str] = field(default=None)
    target_link: Optional[str] = field(default=None)
    user: Optional[str] = field(default=None)
    warnings: Optional[List[GcpWarnings]] = field(default=None)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if self.target_link:
            builder.add_edge(self, clazz=GcpDisk, link=self.target_link)


@define(eq=False, slots=False)
class GcpPublicDelegatedPrefixPublicDelegatedSubPrefix:
    kind: ClassVar[str] = "gcp_public_delegated_prefix_public_delegated_sub_prefix"
    kind_display: ClassVar[str] = "GCP Public Delegated Sub-Prefix"
    kind_description: ClassVar[str] = (
        "A GCP Public Delegated Sub-Prefix is a range of public IP addresses that can"
        " be used within a Google Cloud Platform (GCP) project."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "delegatee_project": S("delegateeProject"),
        "description": S("description"),
        "ip_cidr_range": S("ipCidrRange"),
        "is_address": S("isAddress"),
        "name": S("name"),
        "region": S("region"),
        "status": S("status"),
    }
    delegatee_project: Optional[str] = field(default=None)
    description: Optional[str] = field(default=None)
    ip_cidr_range: Optional[str] = field(default=None)
    is_address: Optional[bool] = field(default=None)
    name: Optional[str] = field(default=None)
    region: Optional[str] = field(default=None)
    status: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpPublicDelegatedPrefix(GcpResource):
    kind: ClassVar[str] = "gcp_public_delegated_prefix"
    kind_display: ClassVar[str] = "GCP Public Delegated Prefix"
    kind_description: ClassVar[str] = (
        "A Public Delegated Prefix in Google Cloud Platform (GCP) allows customers to"
        " use their own IPv6 addresses on GCP resources for public internet"
        " connectivity."
    )
    api_spec: ClassVar[GcpApiSpec] = GcpApiSpec(
        service="compute",
        version="v1",
        accessors=["publicDelegatedPrefixes"],
        action="aggregatedList",
        request_parameter={"project": "{project}"},
        request_parameter_in={"project"},
        response_path="items",
        response_regional_sub_path="publicDelegatedPrefixes",
        mutate_iam_permissions=["compute.publicDelegatedPrefixes.update", "compute.publicDelegatedPrefixes.delete"],
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
        "fingerprint": S("fingerprint"),
        "ip_cidr_range": S("ipCidrRange"),
        "is_live_migration": S("isLiveMigration"),
        "parent_prefix": S("parentPrefix"),
        "public_delegated_sub_prefixs": S("publicDelegatedSubPrefixs", default=[])
        >> ForallBend(GcpPublicDelegatedPrefixPublicDelegatedSubPrefix.mapping),
        "status": S("status"),
    }
    fingerprint: Optional[str] = field(default=None)
    ip_cidr_range: Optional[str] = field(default=None)
    is_live_migration: Optional[bool] = field(default=None)
    parent_prefix: Optional[str] = field(default=None)
    public_delegated_sub_prefixs: Optional[List[GcpPublicDelegatedPrefixPublicDelegatedSubPrefix]] = field(default=None)
    status: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpGRPCHealthCheck:
    kind: ClassVar[str] = "gcp_grpc_health_check"
    kind_display: ClassVar[str] = "GCP gRPC Health Check"
    kind_description: ClassVar[str] = (
        "gRPC Health Check is a health checking mechanism in Google Cloud Platform"
        " (GCP) that allows monitoring and validating the health of gRPC-based"
        " services running on GCP infrastructure."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "grpc_service_name": S("grpcServiceName"),
        "port": S("port"),
        "port_name": S("portName"),
        "port_specification": S("portSpecification"),
    }
    grpc_service_name: Optional[str] = field(default=None)
    port: Optional[int] = field(default=None)
    port_name: Optional[str] = field(default=None)
    port_specification: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpHTTP2HealthCheck:
    kind: ClassVar[str] = "gcp_http2_health_check"
    kind_display: ClassVar[str] = "GCP HTTP/2 Health Check"
    kind_description: ClassVar[str] = (
        "HTTP/2 Health Check is a health monitoring mechanism provided by Google"
        " Cloud Platform, which allows you to check the health of your HTTP/2 services"
        " or endpoints."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "host": S("host"),
        "port": S("port"),
        "port_name": S("portName"),
        "port_specification": S("portSpecification"),
        "proxy_header": S("proxyHeader"),
        "request_path": S("requestPath"),
        "response": S("response"),
    }
    host: Optional[str] = field(default=None)
    port: Optional[int] = field(default=None)
    port_name: Optional[str] = field(default=None)
    port_specification: Optional[str] = field(default=None)
    proxy_header: Optional[str] = field(default=None)
    request_path: Optional[str] = field(default=None)
    response: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpHTTPHealthCheckSpec:
    kind: ClassVar[str] = "gcp_http_health_check_spec"
    kind_display: ClassVar[str] = "GCP HTTP Health Check Specification"
    kind_description: ClassVar[str] = (
        "GCP HTTP Health Check Specification is a configuration for monitoring the"
        " health of HTTP-based services in Google Cloud Platform by periodically"
        " sending health check requests and verifying the responses."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "host": S("host"),
        "port": S("port"),
        "port_name": S("portName"),
        "port_specification": S("portSpecification"),
        "proxy_header": S("proxyHeader"),
        "request_path": S("requestPath"),
        "response": S("response"),
    }
    host: Optional[str] = field(default=None)
    port: Optional[int] = field(default=None)
    port_name: Optional[str] = field(default=None)
    port_specification: Optional[str] = field(default=None)
    proxy_header: Optional[str] = field(default=None)
    request_path: Optional[str] = field(default=None)
    response: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpHTTPSHealthCheckSpec:
    kind: ClassVar[str] = "gcp_https_health_check_spec"
    kind_display: ClassVar[str] = "GCP HTTPS Health Check Spec"
    kind_description: ClassVar[str] = (
        "GCP HTTPS Health Check Spec is a specification for a health check resource"
        " in Google Cloud Platform (GCP), used to monitor the health of HTTPS-based"
        " services by sending periodic requests and checking for valid responses."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "host": S("host"),
        "port": S("port"),
        "port_name": S("portName"),
        "port_specification": S("portSpecification"),
        "proxy_header": S("proxyHeader"),
        "request_path": S("requestPath"),
        "response": S("response"),
    }
    host: Optional[str] = field(default=None)
    port: Optional[int] = field(default=None)
    port_name: Optional[str] = field(default=None)
    port_specification: Optional[str] = field(default=None)
    proxy_header: Optional[str] = field(default=None)
    request_path: Optional[str] = field(default=None)
    response: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpSSLHealthCheck:
    kind: ClassVar[str] = "gcp_ssl_health_check"
    kind_display: ClassVar[str] = "GCP SSL Health Check"
    kind_description: ClassVar[str] = (
        "GCP SSL Health Check is a monitoring service used to check the health of SSL-based services by sending"
        " a request and verifying the response over the specified port, optionally using a named port and"
        " managing proxy header configurations."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "port": S("port"),
        "port_name": S("portName"),
        "port_specification": S("portSpecification"),
        "proxy_header": S("proxyHeader"),
        "request": S("request"),
        "response": S("response"),
    }
    port: Optional[int] = field(default=None)
    port_name: Optional[str] = field(default=None)
    port_specification: Optional[str] = field(default=None)
    proxy_header: Optional[str] = field(default=None)
    request: Optional[str] = field(default=None)
    response: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpTCPHealthCheck:
    kind: ClassVar[str] = "gcp_tcp_health_check"
    kind_display: ClassVar[str] = "GCP TCP Health Check"
    kind_description: ClassVar[str] = (
        "GCP TCP Health Check is a feature in the Google Cloud Platform which"
        " monitors the availability and health of TCP-based services by periodically"
        " sending TCP connection requests to the specified endpoint."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "port": S("port"),
        "port_name": S("portName"),
        "port_specification": S("portSpecification"),
        "proxy_header": S("proxyHeader"),
        "request": S("request"),
        "response": S("response"),
    }
    port: Optional[int] = field(default=None)
    port_name: Optional[str] = field(default=None)
    port_specification: Optional[str] = field(default=None)
    proxy_header: Optional[str] = field(default=None)
    request: Optional[str] = field(default=None)
    response: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpHealthCheck(GcpResource):
    kind: ClassVar[str] = "gcp_health_check"
    kind_display: ClassVar[str] = "GCP Health Check"
    kind_description: ClassVar[str] = (
        "Health Check is a feature in Google Cloud Platform that allows you to"
        " monitor the health and availability of your resources by periodically"
        " sending requests to them and verifying the responses."
    )
    api_spec: ClassVar[GcpApiSpec] = GcpApiSpec(
        service="compute",
        version="v1",
        accessors=["healthChecks"],
        action="aggregatedList",
        request_parameter={"project": "{project}"},
        request_parameter_in={"project"},
        response_path="items",
        response_regional_sub_path="healthChecks",
        mutate_iam_permissions=["compute.healthChecks.update", "compute.healthChecks.delete"],
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
        "check_interval_sec": S("checkIntervalSec"),
        "grpc_health_check": S("grpcHealthCheck", default={}) >> Bend(GcpGRPCHealthCheck.mapping),
        "healthy_threshold": S("healthyThreshold"),
        "http2_health_check": S("http2HealthCheck", default={}) >> Bend(GcpHTTP2HealthCheck.mapping),
        "http_health_check": S("httpHealthCheck", default={}) >> Bend(GcpHTTPHealthCheckSpec.mapping),
        "https_health_check": S("httpsHealthCheck", default={}) >> Bend(GcpHTTPSHealthCheckSpec.mapping),
        "health_check_log_config": S("logConfig", "enable"),
        "ssl_health_check": S("sslHealthCheck", default={}) >> Bend(GcpSSLHealthCheck.mapping),
        "tcp_health_check": S("tcpHealthCheck", default={}) >> Bend(GcpTCPHealthCheck.mapping),
        "timeout_sec": S("timeoutSec"),
        "type": S("type"),
        "unhealthy_threshold": S("unhealthyThreshold"),
    }
    check_interval_sec: Optional[int] = field(default=None)
    grpc_health_check: Optional[GcpGRPCHealthCheck] = field(default=None)
    healthy_threshold: Optional[int] = field(default=None)
    http2_health_check: Optional[GcpHTTP2HealthCheck] = field(default=None)
    http_health_check: Optional[GcpHTTPHealthCheckSpec] = field(default=None)
    https_health_check: Optional[GcpHTTPSHealthCheckSpec] = field(default=None)
    health_check_log_config: Optional[bool] = field(default=None)
    ssl_health_check: Optional[GcpSSLHealthCheck] = field(default=None)
    tcp_health_check: Optional[GcpTCPHealthCheck] = field(default=None)
    timeout_sec: Optional[int] = field(default=None)
    type: Optional[str] = field(default=None)
    unhealthy_threshold: Optional[int] = field(default=None)


@define(eq=False, slots=False)
class GcpHttpHealthCheck(GcpResource):
    kind: ClassVar[str] = "gcp_http_health_check"
    kind_display: ClassVar[str] = "GCP HTTP Health Check"
    kind_description: ClassVar[str] = (
        "HTTP Health Checks are used by Google Cloud Platform to monitor the health"
        " of web services and determine if they are reachable and responding correctly"
        " to requests."
    )
    api_spec: ClassVar[GcpApiSpec] = GcpApiSpec(
        service="compute",
        version="v1",
        accessors=["httpHealthChecks"],
        action="list",
        request_parameter={"project": "{project}"},
        request_parameter_in={"project"},
        response_path="items",
        response_regional_sub_path=None,
        mutate_iam_permissions=["compute.httpHealthChecks.update", "compute.httpHealthChecks.delete"],
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
        "check_interval_sec": S("checkIntervalSec"),
        "healthy_threshold": S("healthyThreshold"),
        "host": S("host"),
        "port": S("port"),
        "request_path": S("requestPath"),
        "timeout_sec": S("timeoutSec"),
        "unhealthy_threshold": S("unhealthyThreshold"),
    }
    check_interval_sec: Optional[int] = field(default=None)
    healthy_threshold: Optional[int] = field(default=None)
    host: Optional[str] = field(default=None)
    port: Optional[int] = field(default=None)
    request_path: Optional[str] = field(default=None)
    timeout_sec: Optional[int] = field(default=None)
    unhealthy_threshold: Optional[int] = field(default=None)


@define(eq=False, slots=False)
class GcpHttpsHealthCheck(GcpResource):
    kind: ClassVar[str] = "gcp_https_health_check"
    kind_display: ClassVar[str] = "GCP HTTPS Health Check"
    kind_description: ClassVar[str] = (
        "The GCP HTTPS Health Check is a monitoring service that allows users to"
        " check the availability and performance of their HTTPS endpoints on Google"
        " Cloud Platform."
    )
    api_spec: ClassVar[GcpApiSpec] = GcpApiSpec(
        service="compute",
        version="v1",
        accessors=["httpsHealthChecks"],
        action="list",
        request_parameter={"project": "{project}"},
        request_parameter_in={"project"},
        response_path="items",
        response_regional_sub_path=None,
        mutate_iam_permissions=["compute.httpsHealthChecks.update", "compute.httpsHealthChecks.delete"],
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
        "check_interval_sec": S("checkIntervalSec"),
        "healthy_threshold": S("healthyThreshold"),
        "host": S("host"),
        "port": S("port"),
        "request_path": S("requestPath"),
        "timeout_sec": S("timeoutSec"),
        "unhealthy_threshold": S("unhealthyThreshold"),
    }
    check_interval_sec: Optional[int] = field(default=None)
    healthy_threshold: Optional[int] = field(default=None)
    host: Optional[str] = field(default=None)
    port: Optional[int] = field(default=None)
    request_path: Optional[str] = field(default=None)
    timeout_sec: Optional[int] = field(default=None)
    unhealthy_threshold: Optional[int] = field(default=None)


@define(eq=False, slots=False)
class GcpRawdisk:
    kind: ClassVar[str] = "gcp_rawdisk"
    kind_display: ClassVar[str] = "GCP Raw Disk"
    kind_description: ClassVar[str] = (
        "GCP Raw Disk are a property of a GCP Image. They are a disk image that represents the exact"
        " byte-for-byte contents of a disk."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "container_type": S("containerType"),
        "sha1_checksum": S("sha1Checksum"),
        "source": S("source"),
    }
    container_type: Optional[str] = field(default=None)
    sha1_checksum: Optional[str] = field(default=None)
    source: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpFileContentBuffer:
    kind: ClassVar[str] = "gcp_file_content_buffer"
    kind_display: ClassVar[str] = "GCP File Content Buffer"
    kind_description: ClassVar[str] = (
        "GCP File Content Buffer is a specification for storing initial content and defining its"
        " type within a file for a virtual machine image in Google Cloud."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"content": S("content"), "file_type": S("fileType")}
    content: Optional[str] = field(default=None)
    file_type: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpInitialStateConfig:
    kind: ClassVar[str] = "gcp_initial_state_config"
    kind_display: ClassVar[str] = "GCP Initial State Config"
    kind_description: ClassVar[str] = (
        "GCP Initial State Config refers to the configuration parameters for the initial setup"
        " of a virtual machine image."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "dbs": S("dbs", default=[]) >> ForallBend(GcpFileContentBuffer.mapping),
        "dbxs": S("dbxs", default=[]) >> ForallBend(GcpFileContentBuffer.mapping),
        "keks": S("keks", default=[]) >> ForallBend(GcpFileContentBuffer.mapping),
        "pk": S("pk", default={}) >> Bend(GcpFileContentBuffer.mapping),
    }
    dbs: Optional[List[GcpFileContentBuffer]] = field(default=None)
    dbxs: Optional[List[GcpFileContentBuffer]] = field(default=None)
    keks: Optional[List[GcpFileContentBuffer]] = field(default=None)
    pk: Optional[GcpFileContentBuffer] = field(default=None)


@define(eq=False, slots=False)
class GcpImage(GcpResource):
    kind: ClassVar[str] = "gcp_image"
    kind_display: ClassVar[str] = "GCP Image"
    kind_description: ClassVar[str] = (
        "GCP Images are pre-configured virtual machine templates that can be used to"
        " create and deploy virtual machines in the Google Cloud Platform."
    )
    reference_kinds: ClassVar[ModelReference] = {"predecessors": {"default": ["gcp_disk"]}}

    api_spec: ClassVar[GcpApiSpec] = GcpApiSpec(
        service="compute",
        version="v1",
        accessors=["images"],
        action="list",
        request_parameter={"project": "{project}"},
        request_parameter_in={"project"},
        response_path="items",
        response_regional_sub_path=None,
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
        "architecture": S("architecture"),
        "archive_size_bytes": S("archiveSizeBytes"),
        "disk_size_gb": S("diskSizeGb") >> AsInt(),
        "family": S("family"),
        "guest_os_features": S("guestOsFeatures", default=[]) >> ForallBend(S("type")),
        "image_encryption_key": S("imageEncryptionKey", default={}) >> Bend(GcpCustomerEncryptionKey.mapping),
        "license_codes": S("licenseCodes", default=[]),
        "licenses": S("licenses", default=[]),
        "raw_disk": S("rawDisk", default={}) >> Bend(GcpRawdisk.mapping),
        "satisfies_pzs": S("satisfiesPzs"),
        "shielded_instance_initial_state": S("shieldedInstanceInitialState", default={})
        >> Bend(GcpInitialStateConfig.mapping),
        "source_disk": S("sourceDisk"),
        "source_disk_encryption_key": S("sourceDiskEncryptionKey", default={})
        >> Bend(GcpCustomerEncryptionKey.mapping),
        "source_disk_id": S("sourceDiskId"),
        "source_image": S("sourceImage"),
        "source_image_encryption_key": S("sourceImageEncryptionKey", default={})
        >> Bend(GcpCustomerEncryptionKey.mapping),
        "source_image_id": S("sourceImageId"),
        "source_snapshot": S("sourceSnapshot"),
        "source_snapshot_encryption_key": S("sourceSnapshotEncryptionKey", default={})
        >> Bend(GcpCustomerEncryptionKey.mapping),
        "source_snapshot_id": S("sourceSnapshotId"),
        "source_type": S("sourceType"),
        "status": S("status"),
        "storage_locations": S("storageLocations", default=[]),
    }
    architecture: Optional[str] = field(default=None)
    archive_size_bytes: Optional[str] = field(default=None)
    disk_size_gb: Optional[int] = field(default=None)
    family: Optional[str] = field(default=None)
    guest_os_features: Optional[List[str]] = field(default=None)
    image_encryption_key: Optional[GcpCustomerEncryptionKey] = field(default=None)
    license_codes: Optional[List[str]] = field(default=None)
    licenses: Optional[List[str]] = field(default=None)
    raw_disk: Optional[GcpRawdisk] = field(default=None)
    satisfies_pzs: Optional[bool] = field(default=None)
    shielded_instance_initial_state: Optional[GcpInitialStateConfig] = field(default=None)
    source_disk: Optional[str] = field(default=None)
    source_disk_encryption_key: Optional[GcpCustomerEncryptionKey] = field(default=None)
    source_disk_id: Optional[str] = field(default=None)
    source_image: Optional[str] = field(default=None)
    source_image_encryption_key: Optional[GcpCustomerEncryptionKey] = field(default=None)
    source_image_id: Optional[str] = field(default=None)
    source_snapshot: Optional[str] = field(default=None)
    source_snapshot_encryption_key: Optional[GcpCustomerEncryptionKey] = field(default=None)
    source_snapshot_id: Optional[str] = field(default=None)
    source_type: Optional[str] = field(default=None)
    status: Optional[str] = field(default=None)
    storage_locations: Optional[List[str]] = field(default=None)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if self.source_disk:
            builder.add_edge(self, reverse=True, clazz=GcpDisk, link=self.source_disk)


@define(eq=False, slots=False)
class GcpInstanceGroupManagerAutoHealingPolicy:
    kind: ClassVar[str] = "gcp_instance_group_manager_auto_healing_policy"
    kind_display: ClassVar[str] = "GCP Instance Group Manager Auto Healing Policy"
    kind_description: ClassVar[str] = (
        "Auto Healing Policy is a feature of GCP Instance Group Manager that"
        " automatically replaces unhealthy instances within an instance group to"
        " maintain availability and ensure application uptime."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"health_check": S("healthCheck"), "initial_delay_sec": S("initialDelaySec")}
    health_check: Optional[str] = field(default=None)
    initial_delay_sec: Optional[int] = field(default=None)


@define(eq=False, slots=False)
class GcpInstanceGroupManagerActionsSummary:
    kind: ClassVar[str] = "gcp_instance_group_manager_actions_summary"
    kind_display: ClassVar[str] = "GCP Instance Group Manager Actions Summary"
    kind_description: ClassVar[str] = (
        "The GCP Instance Group Manager Actions Summary provides a summary of the"
        " actions performed on instance groups in the Google Cloud Platform, such as"
        " scaling, updating, or deleting instances in a group."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "abandoning": S("abandoning"),
        "creating": S("creating"),
        "creating_without_retries": S("creatingWithoutRetries"),
        "deleting": S("deleting"),
        "none": S("none"),
        "recreating": S("recreating"),
        "refreshing": S("refreshing"),
        "restarting": S("restarting"),
        "resuming": S("resuming"),
        "starting": S("starting"),
        "stopping": S("stopping"),
        "suspending": S("suspending"),
        "verifying": S("verifying"),
    }
    abandoning: Optional[int] = field(default=None)
    creating: Optional[int] = field(default=None)
    creating_without_retries: Optional[int] = field(default=None)
    deleting: Optional[int] = field(default=None)
    none: Optional[int] = field(default=None)
    recreating: Optional[int] = field(default=None)
    refreshing: Optional[int] = field(default=None)
    restarting: Optional[int] = field(default=None)
    resuming: Optional[int] = field(default=None)
    starting: Optional[int] = field(default=None)
    stopping: Optional[int] = field(default=None)
    suspending: Optional[int] = field(default=None)
    verifying: Optional[int] = field(default=None)


@define(eq=False, slots=False)
class GcpDistributionPolicy:
    kind: ClassVar[str] = "gcp_distribution_policy"
    kind_display: ClassVar[str] = "GCP Distribution Policy"
    kind_description: ClassVar[str] = (
        "GCP Distribution Policy is a feature provided by Google Cloud Platform that"
        " allows users to define how resources are distributed across multiple zones"
        " within a region. This enables users to ensure high availability and fault"
        " tolerance for their applications and services by ensuring that they are"
        " spread across multiple physical locations."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "target_shape": S("targetShape"),
        "zones": S("zones", default=[]) >> ForallBend(S("zone")),
    }
    target_shape: Optional[str] = field(default=None)
    zones: Optional[List[str]] = field(default=None)


@define(eq=False, slots=False)
class GcpNamedPort:
    kind: ClassVar[str] = "gcp_named_port"
    kind_display: ClassVar[str] = "GCP Named Port"
    kind_description: ClassVar[str] = (
        "A named port is a service port with a user-defined name associated with a"
        " specific port number. It is used in Google Cloud Platform to help identify"
        " and manage networking services."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"name": S("name"), "port": S("port")}
    name: Optional[str] = field(default=None)
    port: Optional[int] = field(default=None)


@define(eq=False, slots=False)
class GcpStatefulPolicyPreservedStateDiskDevice:
    kind: ClassVar[str] = "gcp_stateful_policy_preserved_state_disk_device"
    kind_display: ClassVar[str] = "GCP Stateful Policy Preserved State Disk Device"
    kind_description: ClassVar[str] = (
        "The GCP Stateful Policy Preserved State Disk Device setting determines whether a disk attached to a virtual"
        " machine in a managed instance group should be automatically deleted when the virtual machine is deleted."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"auto_delete": S("autoDelete")}
    auto_delete: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpStatefulPolicyPreservedState:
    kind: ClassVar[str] = "gcp_stateful_policy_preserved_state"
    kind_display: ClassVar[str] = "GCP Stateful Policy Preserved State"
    kind_description: ClassVar[str] = (
        "The GCP Stateful Policy's Preserved State feature involves a set of rules defining how individual disks"
        " should be treated on instances within a managed instance group, such as whether they should be retained"
        " or deleted during specific group operations."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "stateful_policy_preserved_state_disks": S("disks", default={})
        >> MapDict(value_bender=Bend(GcpStatefulPolicyPreservedStateDiskDevice.mapping))
    }
    stateful_policy_preserved_state_disks: Optional[Dict[str, GcpStatefulPolicyPreservedStateDiskDevice]] = field(
        default=None
    )


@define(eq=False, slots=False)
class GcpStatefulPolicy:
    kind: ClassVar[str] = "gcp_stateful_policy"
    kind_display: ClassVar[str] = "GCP Stateful Policy"
    kind_description: ClassVar[str] = (
        "GCP Stateful Policy refers to a configuration that specifies how certain resources and disk states should be"
        " maintained when managing instances within a group, ensuring that specific instance properties persist"
        " across various lifecycle events."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "preserved_state": S("preservedState", default={}) >> Bend(GcpStatefulPolicyPreservedState.mapping)
    }
    preserved_state: Optional[GcpStatefulPolicyPreservedState] = field(default=None)


@define(eq=False, slots=False)
class GcpInstanceGroupManagerStatusStateful:
    kind: ClassVar[str] = "gcp_instance_group_manager_status_stateful"
    kind_display: ClassVar[str] = "GCP Instance Group Manager Status Stateful"
    kind_description: ClassVar[str] = (
        "GCP Instance Group Manager Status Stateful indicates the status of an instance group manager's stateful"
        " configuration, showing whether a stateful configuration is applied and the status of instance-specific"
        " configurations within the group."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "has_stateful_config": S("hasStatefulConfig"),
        "per_instance_configs": S("perInstanceConfigs", "allEffective"),
    }
    has_stateful_config: Optional[bool] = field(default=None)
    per_instance_configs: Optional[bool] = field(default=None)


@define(eq=False, slots=False)
class GcpInstanceGroupManagerStatus:
    kind: ClassVar[str] = "gcp_instance_group_manager_status"
    kind_display: ClassVar[str] = "GCP Instance Group Manager Status"
    kind_description: ClassVar[str] = (
        "Instance Group Manager Status represents the current state of an instance"
        " group manager in Google Cloud Platform. It provides information about the"
        " status of the managed instances within the group and their health."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "autoscaler": S("autoscaler"),
        "is_stable": S("isStable"),
        "stateful": S("stateful", default={}) >> Bend(GcpInstanceGroupManagerStatusStateful.mapping),
        "version_target": S("versionTarget", "isReached"),
    }
    autoscaler: Optional[str] = field(default=None)
    is_stable: Optional[bool] = field(default=None)
    stateful: Optional[GcpInstanceGroupManagerStatusStateful] = field(default=None)
    version_target: Optional[bool] = field(default=None)


@define(eq=False, slots=False)
class GcpInstanceGroupManagerUpdatePolicy:
    kind: ClassVar[str] = "gcp_instance_group_manager_update_policy"
    kind_display: ClassVar[str] = "GCP Instance Group Manager Update Policy"
    kind_description: ClassVar[str] = (
        "The GCP Instance Group Manager Update Policy is a configuration setting that"
        " determines how a managed instance group is automatically updated with new"
        " instance template versions."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "instance_redistribution_type": S("instanceRedistributionType"),
        "max_surge": S("maxSurge", default={}) >> Bend(GcpFixedOrPercent.mapping),
        "max_unavailable": S("maxUnavailable", default={}) >> Bend(GcpFixedOrPercent.mapping),
        "minimal_action": S("minimalAction"),
        "most_disruptive_allowed_action": S("mostDisruptiveAllowedAction"),
        "replacement_method": S("replacementMethod"),
        "type": S("type"),
    }
    instance_redistribution_type: Optional[str] = field(default=None)
    max_surge: Optional[GcpFixedOrPercent] = field(default=None)
    max_unavailable: Optional[GcpFixedOrPercent] = field(default=None)
    minimal_action: Optional[str] = field(default=None)
    most_disruptive_allowed_action: Optional[str] = field(default=None)
    replacement_method: Optional[str] = field(default=None)
    type: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpInstanceGroupManagerVersion:
    kind: ClassVar[str] = "gcp_instance_group_manager_version"
    kind_display: ClassVar[str] = "GCP Instance Group Manager Version"
    kind_description: ClassVar[str] = (
        "GCP Instance Group Manager Version outlines the template and size details for a specific version of managed"
        " instances, enabling the management of different instance templates and scaling properties within a"
        " single group manager."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "instance_template": S("instanceTemplate"),
        "name": S("name"),
        "target_size": S("targetSize", default={}) >> Bend(GcpFixedOrPercent.mapping),
    }
    instance_template: Optional[str] = field(default=None)
    name: Optional[str] = field(default=None)
    target_size: Optional[GcpFixedOrPercent] = field(default=None)


@define(eq=False, slots=False)
class GcpInstanceGroupManager(GcpResource):
    kind: ClassVar[str] = "gcp_instance_group_manager"
    kind_display: ClassVar[str] = "GCP Instance Group Manager"
    kind_description: ClassVar[str] = (
        "GCP Instance Group Manager is a resource in Google Cloud Platform that helps"
        " manage and scale groups of Compute Engine instances."
    )
    reference_kinds: ClassVar[ModelReference] = {
        "predecessors": {
            "default": ["gcp_instance_group"],
            "delete": ["gcp_instance_group", "gcp_health_check", "gcp_http_health_check", "gcp_https_health_check"],
        },
        "successors": {"default": ["gcp_health_check", "gcp_http_health_check", "gcp_https_health_check"]},
    }
    api_spec: ClassVar[GcpApiSpec] = GcpApiSpec(
        service="compute",
        version="v1",
        accessors=["instanceGroupManagers"],
        action="aggregatedList",
        request_parameter={"project": "{project}"},
        request_parameter_in={"project"},
        response_path="items",
        response_regional_sub_path="instanceGroupManagers",
        mutate_iam_permissions=["compute.instanceGroupManagers.update", "compute.instanceGroupManagers.delete"],
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
        "auto_healing_policies": S("autoHealingPolicies", default=[])
        >> ForallBend(GcpInstanceGroupManagerAutoHealingPolicy.mapping),
        "base_instance_name": S("baseInstanceName"),
        "current_actions": S("currentActions", default={}) >> Bend(GcpInstanceGroupManagerActionsSummary.mapping),
        "distribution_policy": S("distributionPolicy", default={}) >> Bend(GcpDistributionPolicy.mapping),
        "fingerprint": S("fingerprint"),
        "instance_group": S("instanceGroup"),
        "instance_template": S("instanceTemplate"),
        "list_managed_instances_results": S("listManagedInstancesResults"),
        "named_ports": S("namedPorts", default=[]) >> ForallBend(GcpNamedPort.mapping),
        "stateful_policy": S("statefulPolicy", default={}) >> Bend(GcpStatefulPolicy.mapping),
        "instance_group_manager_status": S("status", default={}) >> Bend(GcpInstanceGroupManagerStatus.mapping),
        "target_pools": S("targetPools", default=[]),
        "target_size": S("targetSize"),
        "update_policy": S("updatePolicy", default={}) >> Bend(GcpInstanceGroupManagerUpdatePolicy.mapping),
        "versions": S("versions", default=[]) >> ForallBend(GcpInstanceGroupManagerVersion.mapping),
    }
    auto_healing_policies: Optional[List[GcpInstanceGroupManagerAutoHealingPolicy]] = field(default=None)
    base_instance_name: Optional[str] = field(default=None)
    current_actions: Optional[GcpInstanceGroupManagerActionsSummary] = field(default=None)
    distribution_policy: Optional[GcpDistributionPolicy] = field(default=None)
    fingerprint: Optional[str] = field(default=None)
    instance_group: Optional[str] = field(default=None)
    instance_template: Optional[str] = field(default=None)
    list_managed_instances_results: Optional[str] = field(default=None)
    named_ports: Optional[List[GcpNamedPort]] = field(default=None)
    stateful_policy: Optional[GcpStatefulPolicy] = field(default=None)
    instance_group_manager_status: Optional[GcpInstanceGroupManagerStatus] = field(default=None)
    target_pools: Optional[List[str]] = field(default=None)
    target_size: Optional[int] = field(default=None)
    update_policy: Optional[GcpInstanceGroupManagerUpdatePolicy] = field(default=None)
    versions: Optional[List[GcpInstanceGroupManagerVersion]] = field(default=None)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if self.instance_group:
            builder.dependant_node(
                self,
                reverse=True,
                delete_same_as_default=True,
                clazz=GcpInstanceGroup,
                link=self.instance_group,
            )
        if ahp := self.auto_healing_policies:
            for policy in ahp:
                builder.dependant_node(self, clazz=health_check_types(), link=policy.health_check)


@define(eq=False, slots=False)
class GcpInstanceGroup(GcpResource):
    kind: ClassVar[str] = "gcp_instance_group"
    kind_display: ClassVar[str] = "GCP Instance Group"
    kind_description: ClassVar[str] = (
        "Instance Group is a resource in Google Cloud Platform that allows you to"
        " manage and scale multiple instances together as a single unit."
    )
    reference_kinds: ClassVar[ModelReference] = {
        "predecessors": {"default": ["gcp_network", "gcp_subnetwork"], "delete": ["gcp_network", "gcp_subnetwork"]}
    }
    api_spec: ClassVar[GcpApiSpec] = GcpApiSpec(
        service="compute",
        version="v1",
        accessors=["instanceGroups"],
        action="aggregatedList",
        request_parameter={"project": "{project}"},
        request_parameter_in={"project"},
        response_path="items",
        response_regional_sub_path="instanceGroups",
        mutate_iam_permissions=["compute.instanceGroups.update", "compute.instanceGroups.delete"],
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
        "fingerprint": S("fingerprint"),
        "named_ports": S("namedPorts", default=[]) >> ForallBend(GcpNamedPort.mapping),
        "network": S("network"),
        "size": S("size"),
        "subnetwork": S("subnetwork"),
    }
    fingerprint: Optional[str] = field(default=None)
    named_ports: Optional[List[GcpNamedPort]] = field(default=None)
    network: Optional[str] = field(default=None)
    size: Optional[int] = field(default=None)
    subnetwork: Optional[str] = field(default=None)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if self.network:
            builder.dependant_node(self, reverse=True, delete_same_as_default=True, clazz=GcpNetwork, link=self.network)
        if self.subnetwork:
            builder.dependant_node(
                self, reverse=True, delete_same_as_default=True, clazz=GcpSubnetwork, link=self.subnetwork
            )


@define(eq=False, slots=False)
class GcpAdvancedMachineFeatures:
    kind: ClassVar[str] = "gcp_advanced_machine_features"
    kind_display: ClassVar[str] = "GCP Advanced Machine Features"
    kind_description: ClassVar[str] = (
        "Advanced Machine Features are advanced functionalities provided by Google"
        " Cloud Platform (GCP) that enhance the capabilities of virtual machine"
        " instances and improve performance, scalability, and security."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "enable_nested_virtualization": S("enableNestedVirtualization"),
        "enable_uefi_networking": S("enableUefiNetworking"),
        "threads_per_core": S("threadsPerCore"),
        "visible_core_count": S("visibleCoreCount"),
    }
    enable_nested_virtualization: Optional[bool] = field(default=None)
    enable_uefi_networking: Optional[bool] = field(default=None)
    threads_per_core: Optional[int] = field(default=None)
    visible_core_count: Optional[int] = field(default=None)


@define(eq=False, slots=False)
class GcpAttachedDiskInitializeParams:
    kind: ClassVar[str] = "gcp_attached_disk_initialize_params"
    kind_display: ClassVar[str] = "GCP Attached Disk Initialize Params"
    kind_description: ClassVar[str] = (
        "Initialize parameters for a Google Cloud Platform attached disk, used to"
        " specify the size and type of the disk, as well as other configuration"
        " options."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "architecture": S("architecture"),
        "description": S("description"),
        "disk_name": S("diskName"),
        "disk_size_gb": S("diskSizeGb") >> AsInt(),
        "disk_type": S("diskType"),
        "labels": S("labels"),
        "licenses": S("licenses", default=[]),
        "on_update_action": S("onUpdateAction"),
        "provisioned_iops": S("provisionedIops") >> AsInt(),
        "resource_manager_tags": S("resourceManagerTags"),
        "resource_policies": S("resourcePolicies", default=[]),
        "source_image": S("sourceImage"),
        "source_image_encryption_key": S("sourceImageEncryptionKey", default={})
        >> Bend(GcpCustomerEncryptionKey.mapping),
        "source_snapshot": S("sourceSnapshot"),
        "source_snapshot_encryption_key": S("sourceSnapshotEncryptionKey", default={})
        >> Bend(GcpCustomerEncryptionKey.mapping),
    }
    architecture: Optional[str] = field(default=None)
    description: Optional[str] = field(default=None)
    disk_name: Optional[str] = field(default=None)
    disk_size_gb: Optional[int] = field(default=None)
    disk_type: Optional[str] = field(default=None)
    labels: Optional[Dict[str, str]] = field(default=None)
    licenses: Optional[List[str]] = field(default=None)
    on_update_action: Optional[str] = field(default=None)
    provisioned_iops: Optional[int] = field(default=None)
    resource_manager_tags: Optional[Dict[str, str]] = field(default=None)
    resource_policies: Optional[List[str]] = field(default=None)
    source_image: Optional[str] = field(default=None)
    source_image_encryption_key: Optional[GcpCustomerEncryptionKey] = field(default=None)
    source_snapshot: Optional[str] = field(default=None)
    source_snapshot_encryption_key: Optional[GcpCustomerEncryptionKey] = field(default=None)


@define(eq=False, slots=False)
class GcpAttachedDisk:
    kind: ClassVar[str] = "gcp_attached_disk"
    kind_display: ClassVar[str] = "GCP Attached Disk"
    kind_description: ClassVar[str] = (
        "GCP Attached Disk is a disk storage resource that can be attached to compute"
        " instances in Google Cloud Platform, providing persistent block storage for"
        " your data."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "architecture": S("architecture"),
        "auto_delete": S("autoDelete"),
        "boot": S("boot"),
        "device_name": S("deviceName"),
        "disk_encryption_key": S("diskEncryptionKey", default={}) >> Bend(GcpCustomerEncryptionKey.mapping),
        "disk_size_gb": S("diskSizeGb") >> AsInt(),
        "force_attach": S("forceAttach"),
        "guest_os_features": S("guestOsFeatures", default=[]) >> ForallBend(S("type")),
        "index": S("index"),
        "initialize_params": S("initializeParams", default={}) >> Bend(GcpAttachedDiskInitializeParams.mapping),
        "interface": S("interface"),
        "licenses": S("licenses", default=[]),
        "mode": S("mode"),
        "shielded_instance_initial_state": S("shieldedInstanceInitialState", default={})
        >> Bend(GcpInitialStateConfig.mapping),
        "source": S("source"),
        "type": S("type"),
    }
    architecture: Optional[str] = field(default=None)
    auto_delete: Optional[bool] = field(default=None)
    boot: Optional[bool] = field(default=None)
    device_name: Optional[str] = field(default=None)
    disk_encryption_key: Optional[GcpCustomerEncryptionKey] = field(default=None)
    disk_size_gb: Optional[int] = field(default=None)
    force_attach: Optional[bool] = field(default=None)
    guest_os_features: Optional[List[str]] = field(default=None)
    index: Optional[int] = field(default=None)
    initialize_params: Optional[GcpAttachedDiskInitializeParams] = field(default=None)
    interface: Optional[str] = field(default=None)
    licenses: Optional[List[str]] = field(default=None)
    mode: Optional[str] = field(default=None)
    shielded_instance_initial_state: Optional[GcpInitialStateConfig] = field(default=None)
    source: Optional[str] = field(default=None)
    type: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpAcceleratorConfig:
    kind: ClassVar[str] = "gcp_accelerator_config"
    kind_display: ClassVar[str] = "GCP Accelerator Config"
    kind_description: ClassVar[str] = (
        "GCP Accelerator Config is a configuration option for Google Cloud Platform"
        " (GCP) that allows users to attach Nvidia GPUs to their virtual machine"
        " instances for faster computational processing."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "accelerator_count": S("acceleratorCount"),
        "accelerator_type": S("acceleratorType"),
    }
    accelerator_count: Optional[int] = field(default=None)
    accelerator_type: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpItems:
    kind: ClassVar[str] = "gcp_items"
    kind_display: ClassVar[str] = "GCP Items"
    kind_description: ClassVar[str] = (
        "GCP Items refer to the metadata key-value pairs associated with a Google Cloud instance,"
        " allowing customization of instance configuration and behavior."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"key": S("key"), "value": S("value")}
    key: Optional[str] = field(default=None)
    value: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpMetadata:
    kind: ClassVar[str] = "gcp_metadata"
    kind_display: ClassVar[str] = "GCP Metadata"
    kind_description: ClassVar[str] = (
        "GCP Metadata provides information about the Google Cloud Platform virtual"
        " machine instance, such as its attributes, startup scripts, and custom"
        " metadata."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "fingerprint": S("fingerprint"),
        "items": S("items", default=[]) >> ForallBend(GcpItems.mapping),
    }
    fingerprint: Optional[str] = field(default=None)
    items: Optional[List[GcpItems]] = field(default=None)


@define(eq=False, slots=False)
class GcpAccessConfig:
    kind: ClassVar[str] = "gcp_access_config"
    kind_display: ClassVar[str] = "GCP Access Config"
    kind_description: ClassVar[str] = (
        "Access Config is a GCP feature that allows you to assign internal and"
        " external IP addresses to your virtual machine instances."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "external_ipv6": S("externalIpv6"),
        "external_ipv6_prefix_length": S("externalIpv6PrefixLength"),
        "name": S("name"),
        "nat_ip": S("natIP"),
        "network_tier": S("networkTier"),
        "public_ptr_domain_name": S("publicPtrDomainName"),
        "set_public_ptr": S("setPublicPtr"),
        "type": S("type"),
    }
    external_ipv6: Optional[str] = field(default=None)
    external_ipv6_prefix_length: Optional[int] = field(default=None)
    name: Optional[str] = field(default=None)
    nat_ip: Optional[str] = field(default=None)
    network_tier: Optional[str] = field(default=None)
    public_ptr_domain_name: Optional[str] = field(default=None)
    set_public_ptr: Optional[bool] = field(default=None)
    type: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpAliasIpRange:
    kind: ClassVar[str] = "gcp_alias_ip_range"
    kind_display: ClassVar[str] = "GCP Alias IP Range"
    kind_description: ClassVar[str] = (
        "Alias IP Range is a feature in Google Cloud Platform that allows you to"
        " assign additional IP addresses to virtual machines within a subnet."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "ip_cidr_range": S("ipCidrRange"),
        "subnetwork_range_name": S("subnetworkRangeName"),
    }
    ip_cidr_range: Optional[str] = field(default=None)
    subnetwork_range_name: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpNetworkInterface:
    kind: ClassVar[str] = "gcp_network_interface"
    kind_display: ClassVar[str] = "GCP Network Interface"
    kind_description: ClassVar[str] = (
        "A network interface is a virtual network interface card (NIC) that enables"
        " VM instances to send and receive network packets."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "access_configs": S("accessConfigs", default=[]) >> ForallBend(GcpAccessConfig.mapping),
        "alias_ip_ranges": S("aliasIpRanges", default=[]) >> ForallBend(GcpAliasIpRange.mapping),
        "fingerprint": S("fingerprint"),
        "internal_ipv6_prefix_length": S("internalIpv6PrefixLength"),
        "ipv6_access_configs": S("ipv6AccessConfigs", default=[]) >> ForallBend(GcpAccessConfig.mapping),
        "ipv6_access_type": S("ipv6AccessType"),
        "ipv6_address": S("ipv6Address"),
        "name": S("name"),
        "network": S("network"),
        "network_ip": S("networkIP"),
        "nic_type": S("nicType"),
        "queue_count": S("queueCount"),
        "stack_type": S("stackType"),
        "subnetwork": S("subnetwork"),
    }
    access_configs: Optional[List[GcpAccessConfig]] = field(default=None)
    alias_ip_ranges: Optional[List[GcpAliasIpRange]] = field(default=None)
    fingerprint: Optional[str] = field(default=None)
    internal_ipv6_prefix_length: Optional[int] = field(default=None)
    ipv6_access_configs: Optional[List[GcpAccessConfig]] = field(default=None)
    ipv6_access_type: Optional[str] = field(default=None)
    ipv6_address: Optional[str] = field(default=None)
    name: Optional[str] = field(default=None)
    network: Optional[str] = field(default=None)
    network_ip: Optional[str] = field(default=None)
    nic_type: Optional[str] = field(default=None)
    queue_count: Optional[int] = field(default=None)
    stack_type: Optional[str] = field(default=None)
    subnetwork: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpReservationAffinity:
    kind: ClassVar[str] = "gcp_reservation_affinity"
    kind_display: ClassVar[str] = "GCP Reservation Affinity"
    kind_description: ClassVar[str] = (
        "GCP Reservation Affinity is a configuration setting within GCP Instance Properties that controls how"
        " instances use reservations for resources, specifying whether and how instances should consume"
        " reserved compute capacity in GCP."
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
class GcpSchedulingNodeAffinity:
    kind: ClassVar[str] = "gcp_scheduling_node_affinity"
    kind_display: ClassVar[str] = "GCP Scheduling Node Affinity"
    kind_description: ClassVar[str] = (
        "GCP Scheduling Node Affinity allows you to schedule your workloads on"
        " specific nodes in Google Cloud Platform, based on node labels and"
        " expressions."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "key": S("key"),
        "operator": S("operator"),
        "values": S("values", default=[]),
    }
    key: Optional[str] = field(default=None)
    operator: Optional[str] = field(default=None)
    values: Optional[List[str]] = field(default=None)


@define(eq=False, slots=False)
class GcpScheduling:
    kind: ClassVar[str] = "gcp_scheduling"
    kind_display: ClassVar[str] = "GCP Scheduling"
    kind_description: ClassVar[str] = (
        "GCP Scheduling refers to the ability to set up automated, recurring tasks on"
        " Google Cloud Platform, allowing users to schedule actions like running"
        " scripts or executing compute instances at specified intervals."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "automatic_restart": S("automaticRestart"),
        "instance_termination_action": S("instanceTerminationAction"),
        "location_hint": S("locationHint"),
        "min_node_cpus": S("minNodeCpus"),
        "node_affinities": S("nodeAffinities", default=[]) >> ForallBend(GcpSchedulingNodeAffinity.mapping),
        "on_host_maintenance": S("onHostMaintenance"),
        "preemptible": S("preemptible"),
        "provisioning_model": S("provisioningModel"),
    }
    automatic_restart: Optional[bool] = field(default=None)
    instance_termination_action: Optional[str] = field(default=None)
    location_hint: Optional[str] = field(default=None)
    min_node_cpus: Optional[int] = field(default=None)
    node_affinities: Optional[List[GcpSchedulingNodeAffinity]] = field(default=None)
    on_host_maintenance: Optional[str] = field(default=None)
    preemptible: Optional[bool] = field(default=None)
    provisioning_model: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpServiceAccount:
    kind: ClassVar[str] = "gcp_service_account"
    kind_display: ClassVar[str] = "GCP Service Account"
    kind_description: ClassVar[str] = (
        "A GCP Service Account is a special account that represents an application"
        " rather than an individual user. It allows applications to authenticate and"
        " access Google Cloud Platform resources securely."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"email": S("email"), "scopes": S("scopes", default=[])}
    email: Optional[str] = field(default=None)
    scopes: Optional[List[str]] = field(default=None)


@define(eq=False, slots=False)
class GcpShieldedInstanceConfig:
    kind: ClassVar[str] = "gcp_shielded_instance_config"
    kind_display: ClassVar[str] = "GCP Shielded Instance Config"
    kind_description: ClassVar[str] = (
        "Shielded Instance Config enables enhanced security and protection for"
        " virtual machines on Google Cloud Platform by validating the integrity of the"
        " boot firmware and verifying the virtual machine's identity."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "enable_integrity_monitoring": S("enableIntegrityMonitoring"),
        "enable_secure_boot": S("enableSecureBoot"),
        "enable_vtpm": S("enableVtpm"),
    }
    enable_integrity_monitoring: Optional[bool] = field(default=None)
    enable_secure_boot: Optional[bool] = field(default=None)
    enable_vtpm: Optional[bool] = field(default=None)


@define(eq=False, slots=False)
class GcpTags:
    kind: ClassVar[str] = "gcp_tags"
    kind_display: ClassVar[str] = "GCP Tags"
    kind_description: ClassVar[str] = (
        "GCP Tags are used to identify and group virtual machine instances within the Google Cloud Platform, allowing"
        " for batch management and network firewall rule application based on these identifiers."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"fingerprint": S("fingerprint"), "items": S("items", default=[])}
    fingerprint: Optional[str] = field(default=None)
    items: Optional[List[str]] = field(default=None)


@define(eq=False, slots=False)
class GcpInstanceProperties:
    kind: ClassVar[str] = "gcp_instance_properties"
    kind_display: ClassVar[str] = "GCP Instance Properties"
    kind_description: ClassVar[str] = (
        "GCP Instance Properties are specific attributes and configurations for"
        " virtual machine instances in Google Cloud Platform."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "advanced_machine_features": S("advancedMachineFeatures", default={})
        >> Bend(GcpAdvancedMachineFeatures.mapping),
        "can_ip_forward": S("canIpForward"),
        "confidential_instance_config": S("confidentialInstanceConfig", "enableConfidentialCompute"),
        "description": S("description"),
        "disks": S("disks", default=[]) >> ForallBend(GcpAttachedDisk.mapping),
        "guest_accelerators": S("guestAccelerators", default=[]) >> ForallBend(GcpAcceleratorConfig.mapping),
        "key_revocation_action_type": S("keyRevocationActionType"),
        "labels": S("labels"),
        "machine_type": S("machineType"),
        "metadata": S("metadata", default={}) >> Bend(GcpMetadata.mapping),
        "min_cpu_platform": S("minCpuPlatform"),
        "network_interfaces": S("networkInterfaces", default=[]) >> ForallBend(GcpNetworkInterface.mapping),
        "network_performance_config": S("networkPerformanceConfig", "totalEgressBandwidthTier"),
        "private_ipv6_google_access": S("privateIpv6GoogleAccess"),
        "reservation_affinity": S("reservationAffinity", default={}) >> Bend(GcpReservationAffinity.mapping),
        "resource_manager_tags": S("resourceManagerTags"),
        "resource_policies": S("resourcePolicies", default=[]),
        "scheduling": S("scheduling", default={}) >> Bend(GcpScheduling.mapping),
        "service_accounts": S("serviceAccounts", default=[]) >> ForallBend(GcpServiceAccount.mapping),
        "shielded_instance_config": S("shieldedInstanceConfig", default={}) >> Bend(GcpShieldedInstanceConfig.mapping),
        "tags": S("tags", default={}) >> Bend(GcpTags.mapping),
    }
    advanced_machine_features: Optional[GcpAdvancedMachineFeatures] = field(default=None)
    can_ip_forward: Optional[bool] = field(default=None)
    confidential_instance_config: Optional[bool] = field(default=None)
    description: Optional[str] = field(default=None)
    disks: Optional[List[GcpAttachedDisk]] = field(default=None)
    guest_accelerators: Optional[List[GcpAcceleratorConfig]] = field(default=None)
    key_revocation_action_type: Optional[str] = field(default=None)
    labels: Optional[Dict[str, str]] = field(default=None)
    machine_type: Optional[str] = field(default=None)
    metadata: Optional[GcpMetadata] = field(default=None)
    min_cpu_platform: Optional[str] = field(default=None)
    network_interfaces: Optional[List[GcpNetworkInterface]] = field(default=None)
    network_performance_config: Optional[str] = field(default=None)
    private_ipv6_google_access: Optional[str] = field(default=None)
    reservation_affinity: Optional[GcpReservationAffinity] = field(default=None)
    resource_manager_tags: Optional[Dict[str, str]] = field(default=None)
    resource_policies: Optional[List[str]] = field(default=None)
    scheduling: Optional[GcpScheduling] = field(default=None)
    service_accounts: Optional[List[GcpServiceAccount]] = field(default=None)
    shielded_instance_config: Optional[GcpShieldedInstanceConfig] = field(default=None)
    tags: Optional[GcpTags] = field(default=None)


@define(eq=False, slots=False)
class GcpDiskInstantiationConfig:
    kind: ClassVar[str] = "gcp_disk_instantiation_config"
    kind_display: ClassVar[str] = "GCP Disk Instantiation Config"
    kind_description: ClassVar[str] = (
        "GCP Disk Instantiation Config is a configuration used for creating and"
        " customizing disks in Google Cloud Platform (GCP) that are used for storing"
        " data and attaching to virtual machines."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "auto_delete": S("autoDelete"),
        "custom_image": S("customImage"),
        "device_name": S("deviceName"),
        "instantiate_from": S("instantiateFrom"),
    }
    auto_delete: Optional[bool] = field(default=None)
    custom_image: Optional[str] = field(default=None)
    device_name: Optional[str] = field(default=None)
    instantiate_from: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpSourceInstanceParams:
    kind: ClassVar[str] = "gcp_source_instance_params"
    kind_display: ClassVar[str] = "GCP Source Instance Params"
    kind_description: ClassVar[str] = (
        "GCP Source Instance Params within an Instance Template define the configurations for disks when"
        " creating instances from the template, allowing for customization of storage options."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "disk_configs": S("diskConfigs", default=[]) >> ForallBend(GcpDiskInstantiationConfig.mapping)
    }
    disk_configs: Optional[List[GcpDiskInstantiationConfig]] = field(default=None)


@define(eq=False, slots=False)
class GcpInstanceTemplate(GcpResource):
    kind: ClassVar[str] = "gcp_instance_template"
    kind_display: ClassVar[str] = "GCP Instance Template"
    kind_description: ClassVar[str] = (
        "GCP Instance Templates are reusable configuration templates that define the"
        " settings for Google Compute Engine virtual machine instances."
    )
    reference_kinds: ClassVar[ModelReference] = {"predecessors": {"default": ["gcp_machine_type"]}}
    api_spec: ClassVar[GcpApiSpec] = GcpApiSpec(
        service="compute",
        version="v1",
        accessors=["instanceTemplates"],
        action="list",
        request_parameter={"project": "{project}"},
        request_parameter_in={"project"},
        response_path="items",
        response_regional_sub_path=None,
        mutate_iam_permissions=["compute.instanceTemplates.delete"],
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
        "template_properties": S("properties", default={}) >> Bend(GcpInstanceProperties.mapping),
        "source_instance": S("sourceInstance"),
        "source_instance_params": S("sourceInstanceParams", default={}) >> Bend(GcpSourceInstanceParams.mapping),
    }
    template_properties: Optional[GcpInstanceProperties] = field(default=None)
    source_instance: Optional[str] = field(default=None)
    source_instance_params: Optional[GcpSourceInstanceParams] = field(default=None)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if p := self.template_properties:
            if p.machine_type:
                builder.add_edge(self, reverse=True, clazz=GcpMachineType, link=p.machine_type)


@define(eq=False, slots=False)
class GcpInstanceParams:
    kind: ClassVar[str] = "gcp_instance_params"
    kind_display: ClassVar[str] = "GCP Instance Parameters"
    kind_description: ClassVar[str] = (
        "GCP Instance Parameters are specific settings and configurations, such as"
        " machine type, disk size, and network settings, that can be applied to Google"
        " Cloud Platform virtual machine instances."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"resource_manager_tags": S("resourceManagerTags")}
    resource_manager_tags: Optional[Dict[str, str]] = field(default=None)


@define(eq=False, slots=False)
class GcpInstance(GcpResource, BaseInstance):
    kind: ClassVar[str] = "gcp_instance"
    kind_display: ClassVar[str] = "GCP Instance"
    kind_description: ClassVar[str] = (
        "GCP Instances are virtual machines in Google Cloud Platform that can be used"
        " to run applications and services on Google's infrastructure."
    )
    reference_kinds: ClassVar[ModelReference] = {
        "predecessors": {
            "default": ["gcp_network", "gcp_subnetwork", "gcp_machine_type"],
            "delete": ["gcp_network", "gcp_subnetwork"],
        }
    }
    api_spec: ClassVar[GcpApiSpec] = GcpApiSpec(
        service="compute",
        version="v1",
        accessors=["instances"],
        action="aggregatedList",
        request_parameter={"project": "{project}"},
        request_parameter_in={"project"},
        response_path="items",
        response_regional_sub_path="instances",
        set_label_identifier="instance",
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
        "advanced_machine_features": S("advancedMachineFeatures", default={})
        >> Bend(GcpAdvancedMachineFeatures.mapping),
        "can_ip_forward": S("canIpForward"),
        "confidential_instance_config": S("confidentialInstanceConfig", "enableConfidentialCompute"),
        "cpu_platform": S("cpuPlatform"),
        "deletion_protection": S("deletionProtection"),
        "disks": S("disks", default=[]) >> ForallBend(GcpAttachedDisk.mapping),
        "display_device": S("displayDevice", "enableDisplay"),
        "fingerprint": S("fingerprint"),
        "guest_accelerators": S("guestAccelerators", default=[]) >> ForallBend(GcpAcceleratorConfig.mapping),
        "hostname": S("hostname"),
        "key_revocation_action_type": S("keyRevocationActionType"),
        "last_start_timestamp": S("lastStartTimestamp"),
        "last_stop_timestamp": S("lastStopTimestamp"),
        "last_suspended_timestamp": S("lastSuspendedTimestamp"),
        "machine_type": S("machineType"),
        "instance_metadata": S("metadata", default={}) >> Bend(GcpMetadata.mapping),
        "min_cpu_platform": S("minCpuPlatform"),
        "network_interfaces": S("networkInterfaces", default=[]) >> ForallBend(GcpNetworkInterface.mapping),
        "network_performance_config": S("networkPerformanceConfig", "totalEgressBandwidthTier"),
        "instance_params": S("params", default={}) >> Bend(GcpInstanceParams.mapping),
        "private_ipv6_google_access": S("privateIpv6GoogleAccess"),
        "reservation_affinity": S("reservationAffinity", default={}) >> Bend(GcpReservationAffinity.mapping),
        "resource_policies": S("resourcePolicies", default=[]),
        "resource_status": S("resourceStatus", "physicalHost"),
        "satisfies_pzs": S("satisfiesPzs"),
        "scheduling": S("scheduling", default={}) >> Bend(GcpScheduling.mapping),
        "service_accounts": S("serviceAccounts", default=[]) >> ForallBend(GcpServiceAccount.mapping),
        "shielded_instance_config": S("shieldedInstanceConfig", default={}) >> Bend(GcpShieldedInstanceConfig.mapping),
        "shielded_instance_integrity_policy": S("shieldedInstanceIntegrityPolicy", "updateAutoLearnPolicy"),
        "source_machine_image": S("sourceMachineImage"),
        "source_machine_image_encryption_key": S("sourceMachineImageEncryptionKey", default={})
        >> Bend(GcpCustomerEncryptionKey.mapping),
        "start_restricted": S("startRestricted"),
        "status": S("status"),
        "status_message": S("statusMessage"),
        "instance_status": S("status")
        >> MapEnum(
            {
                "PROVISIONING": InstanceStatus.BUSY,
                "STAGING": InstanceStatus.BUSY,
                "RUNNING": InstanceStatus.RUNNING,
                "STOPPING": InstanceStatus.BUSY,
                "SUSPENDING": InstanceStatus.BUSY,
                "SUSPENDED": InstanceStatus.STOPPED,
                "REPAIRING": InstanceStatus.BUSY,
                "TERMINATED": InstanceStatus.TERMINATED,
            },
            default=InstanceStatus.UNKNOWN,
        ),
        "instance_tags": S("tags", default={}) >> Bend(GcpTags.mapping),
    }

    advanced_machine_features: Optional[GcpAdvancedMachineFeatures] = field(default=None)
    can_ip_forward: Optional[bool] = field(default=None)
    confidential_instance_config: Optional[bool] = field(default=None)
    cpu_platform: Optional[str] = field(default=None)
    deletion_protection: Optional[bool] = field(default=None)
    disks: Optional[List[GcpAttachedDisk]] = field(default=None)
    display_device: Optional[bool] = field(default=None)
    fingerprint: Optional[str] = field(default=None)
    guest_accelerators: Optional[List[GcpAcceleratorConfig]] = field(default=None)
    hostname: Optional[str] = field(default=None)
    key_revocation_action_type: Optional[str] = field(default=None)
    last_start_timestamp: Optional[datetime] = field(default=None)
    last_stop_timestamp: Optional[datetime] = field(default=None)
    last_suspended_timestamp: Optional[datetime] = field(default=None)
    machine_type: Optional[str] = field(default=None)
    instance_metadata: Optional[GcpMetadata] = field(default=None)
    min_cpu_platform: Optional[str] = field(default=None)
    network_interfaces: Optional[List[GcpNetworkInterface]] = field(default=None)
    network_performance_config: Optional[str] = field(default=None)
    instance_params: Optional[GcpInstanceParams] = field(default=None)
    private_ipv6_google_access: Optional[str] = field(default=None)
    reservation_affinity: Optional[GcpReservationAffinity] = field(default=None)
    resource_policies: Optional[List[str]] = field(default=None)
    resource_status: Optional[str] = field(default=None)
    satisfies_pzs: Optional[bool] = field(default=None)
    scheduling: Optional[GcpScheduling] = field(default=None)
    service_accounts: Optional[List[GcpServiceAccount]] = field(default=None)
    shielded_instance_config: Optional[GcpShieldedInstanceConfig] = field(default=None)
    shielded_instance_integrity_policy: Optional[bool] = field(default=None)
    source_machine_image: Optional[str] = field(default=None)
    source_machine_image_encryption_key: Optional[GcpCustomerEncryptionKey] = field(default=None)
    start_restricted: Optional[bool] = field(default=None)
    status: Optional[str] = field(default=None)
    status_message: Optional[str] = field(default=None)
    instance_tags: Optional[GcpTags] = field(default=None)

    def post_process(self, graph_builder: GraphBuilder, source: Json) -> None:
        if self.instance_status == InstanceStatus.TERMINATED:
            self._cleaned = True

    def connect_machine_type(self, machine_type_link_ish: str, builder: GraphBuilder) -> None:
        if not machine_type_link_ish.startswith("https://"):
            machine_type_link_ish = (
                f"https://www.googleapis.com/compute/v1/projects/{builder.project.id}/{machine_type_link_ish}"
            )
        machine_type = builder.node(clazz=GcpMachineType, link=machine_type_link_ish)
        if machine_type:
            self.instance_cores = machine_type.instance_cores
            self.instance_memory = machine_type.instance_memory
            self.instance_type = machine_type.name
            builder.add_edge(from_node=self, reverse=True, node=machine_type)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        super().connect_in_graph(builder, source)
        if self.machine_type:
            self.connect_machine_type(self.machine_type, builder)

        for nic in self.network_interfaces or []:
            builder.dependant_node(self, reverse=True, delete_same_as_default=True, clazz=GcpNetwork, link=nic.network)
            builder.dependant_node(
                self, reverse=True, delete_same_as_default=True, clazz=GcpSubnetwork, link=nic.subnetwork
            )

    @classmethod
    def collect(cls: Type[GcpResource], raw: List[Json], builder: GraphBuilder) -> List[GcpResource]:
        # Additional behavior: iterate over list of collected GcpInstances and for each:
        # - extract machineType if custom
        # - then create GcpMachineType object for each unique custom machine type
        # - add the new objects to the graph
        result: List[GcpInstance] = super().collect(raw, builder)  # type: ignore
        custom_machine_types = list(
            set(
                [
                    instance.machine_type
                    for instance in result
                    if instance.machine_type and "custom" in instance.machine_type
                ]
            )
        )
        for machine_type in custom_machine_types:
            # example:
            # https://www.googleapis.com/compute/v1/projects/proj/zones/us-east1-b/machineTypes/e2-custom-medium-1024
            zone, _, name = machine_type.split("/")[-3:]
            builder.submit_work(GcpMachineType.collect_individual, builder, zone, name)

        return result  # type: ignore # list is not covariant

    @classmethod
    def called_collect_apis(cls) -> List[GcpApiSpec]:
        return [cls.api_spec, GcpMachineType.collect_individual_api_spec]


@define(eq=False, slots=False)
class GcpInterconnectAttachmentPartnerMetadata:
    kind: ClassVar[str] = "gcp_interconnect_attachment_partner_metadata"
    kind_display: ClassVar[str] = "GCP Interconnect Attachment Partner Metadata"
    kind_description: ClassVar[str] = (
        "Partner metadata for a Google Cloud Platform (GCP) Interconnect Attachment,"
        " which provides additional information about the partner associated with the"
        " interconnect attachment."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "interconnect_name": S("interconnectName"),
        "partner_name": S("partnerName"),
        "portal_url": S("portalUrl"),
    }
    interconnect_name: Optional[str] = field(default=None)
    partner_name: Optional[str] = field(default=None)
    portal_url: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpInterconnectAttachment(GcpResource):
    kind: ClassVar[str] = "gcp_interconnect_attachment"
    kind_display: ClassVar[str] = "GCP Interconnect Attachment"
    kind_description: ClassVar[str] = (
        "Interconnect Attachment is a resource that allows you to connect your on-"
        " premises network to Google Cloud Platform (GCP) using a dedicated physical"
        " link."
    )
    api_spec: ClassVar[GcpApiSpec] = GcpApiSpec(
        service="compute",
        version="v1",
        accessors=["interconnectAttachments"],
        action="aggregatedList",
        request_parameter={"project": "{project}"},
        request_parameter_in={"project"},
        response_path="items",
        response_regional_sub_path="interconnectAttachments",
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
        "admin_enabled": S("adminEnabled"),
        "bandwidth": S("bandwidth"),
        "candidate_ipv6_subnets": S("candidateIpv6Subnets", default=[]),
        "candidate_subnets": S("candidateSubnets", default=[]),
        "cloud_router_ip_address": S("cloudRouterIpAddress"),
        "cloud_router_ipv6_address": S("cloudRouterIpv6Address"),
        "cloud_router_ipv6_interface_id": S("cloudRouterIpv6InterfaceId"),
        "customer_router_ip_address": S("customerRouterIpAddress"),
        "customer_router_ipv6_address": S("customerRouterIpv6Address"),
        "customer_router_ipv6_interface_id": S("customerRouterIpv6InterfaceId"),
        "dataplane_version": S("dataplaneVersion"),
        "edge_availability_domain": S("edgeAvailabilityDomain"),
        "encryption": S("encryption"),
        "google_reference_id": S("googleReferenceId"),
        "interconnect": S("interconnect"),
        "ipsec_internal_addresses": S("ipsecInternalAddresses", default=[]),
        "mtu": S("mtu"),
        "operational_status": S("operationalStatus"),
        "pairing_key": S("pairingKey"),
        "partner_asn": S("partnerAsn"),
        "partner_metadata": S("partnerMetadata", default={}) >> Bend(GcpInterconnectAttachmentPartnerMetadata.mapping),
        "private_interconnect_info": S("privateInterconnectInfo", "tag8021q"),
        "router": S("router"),
        "satisfies_pzs": S("satisfiesPzs"),
        "stack_type": S("stackType"),
        "interconnect_attachment_state": S("state"),
        "type": S("type"),
        "vlan_tag8021q": S("vlanTag8021q"),
    }
    admin_enabled: Optional[bool] = field(default=None)
    bandwidth: Optional[str] = field(default=None)
    candidate_ipv6_subnets: Optional[List[str]] = field(default=None)
    candidate_subnets: Optional[List[str]] = field(default=None)
    cloud_router_ip_address: Optional[str] = field(default=None)
    cloud_router_ipv6_address: Optional[str] = field(default=None)
    cloud_router_ipv6_interface_id: Optional[str] = field(default=None)
    customer_router_ip_address: Optional[str] = field(default=None)
    customer_router_ipv6_address: Optional[str] = field(default=None)
    customer_router_ipv6_interface_id: Optional[str] = field(default=None)
    dataplane_version: Optional[int] = field(default=None)
    edge_availability_domain: Optional[str] = field(default=None)
    encryption: Optional[str] = field(default=None)
    google_reference_id: Optional[str] = field(default=None)
    interconnect: Optional[str] = field(default=None)
    ipsec_internal_addresses: Optional[List[str]] = field(default=None)
    mtu: Optional[int] = field(default=None)
    operational_status: Optional[str] = field(default=None)
    pairing_key: Optional[str] = field(default=None)
    partner_asn: Optional[str] = field(default=None)
    partner_metadata: Optional[GcpInterconnectAttachmentPartnerMetadata] = field(default=None)
    private_interconnect_info: Optional[int] = field(default=None)
    router: Optional[str] = field(default=None)
    satisfies_pzs: Optional[bool] = field(default=None)
    stack_type: Optional[str] = field(default=None)
    interconnect_attachment_state: Optional[str] = field(default=None)
    type: Optional[str] = field(default=None)
    vlan_tag8021q: Optional[int] = field(default=None)


@define(eq=False, slots=False)
class GcpInterconnectLocationRegionInfo:
    kind: ClassVar[str] = "gcp_interconnect_location_region_info"
    kind_display: ClassVar[str] = "GCP Interconnect Location Region Info"
    kind_description: ClassVar[str] = (
        "GCP Interconnect Location Region Info pertains to the specifications of network latency"
        " and regional availability for a Google Cloud interconnection point."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "expected_rtt_ms": S("expectedRttMs"),
        "location_presence": S("locationPresence"),
        "region": S("region"),
    }
    expected_rtt_ms: Optional[str] = field(default=None)
    location_presence: Optional[str] = field(default=None)
    region: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpInterconnectLocation(GcpResource):
    kind: ClassVar[str] = "gcp_interconnect_location"
    kind_display: ClassVar[str] = "GCP Interconnect Location"
    kind_description: ClassVar[str] = (
        "GCP Interconnect Location refers to the physical location where Google Cloud"
        " Platform (GCP) Interconnects are available. Interconnects provide dedicated"
        " connectivity options between an organization's on-premises network and GCP's"
        " network."
    )
    api_spec: ClassVar[GcpApiSpec] = GcpApiSpec(
        service="compute",
        version="v1",
        accessors=["interconnectLocations"],
        action="list",
        request_parameter={"project": "{project}"},
        request_parameter_in={"project"},
        response_path="items",
        response_regional_sub_path=None,
        mutate_iam_permissions=[],  # can not be mutated
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
        "address": S("address"),
        "availability_zone": S("availabilityZone"),
        "city": S("city"),
        "continent": S("continent"),
        "facility_provider": S("facilityProvider"),
        "facility_provider_facility_id": S("facilityProviderFacilityId"),
        "peeringdb_facility_id": S("peeringdbFacilityId"),
        "region_infos": S("regionInfos", default=[]) >> ForallBend(GcpInterconnectLocationRegionInfo.mapping),
        "status": S("status"),
        "supports_pzs": S("supportsPzs"),
    }
    address: Optional[str] = field(default=None)
    availability_zone: Optional[str] = field(default=None)
    city: Optional[str] = field(default=None)
    continent: Optional[str] = field(default=None)
    facility_provider: Optional[str] = field(default=None)
    facility_provider_facility_id: Optional[str] = field(default=None)
    peeringdb_facility_id: Optional[str] = field(default=None)
    region_infos: Optional[List[GcpInterconnectLocationRegionInfo]] = field(default=None)
    status: Optional[str] = field(default=None)
    supports_pzs: Optional[bool] = field(default=None)


@define(eq=False, slots=False)
class GcpInterconnectCircuitInfo:
    kind: ClassVar[str] = "gcp_interconnect_circuit_info"
    kind_display: ClassVar[str] = "GCP Interconnect Circuit Info"
    kind_description: ClassVar[str] = (
        "Interconnect Circuit Info provides details about the dedicated network"
        " connection between an on-premises network and Google Cloud Platform (GCP)"
        " for faster and more reliable communication."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "customer_demarc_id": S("customerDemarcId"),
        "google_circuit_id": S("googleCircuitId"),
        "google_demarc_id": S("googleDemarcId"),
    }
    customer_demarc_id: Optional[str] = field(default=None)
    google_circuit_id: Optional[str] = field(default=None)
    google_demarc_id: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpInterconnectOutageNotification:
    kind: ClassVar[str] = "gcp_interconnect_outage_notification"
    kind_display: ClassVar[str] = "GCP Interconnect Outage Notification"
    kind_description: ClassVar[str] = (
        "GCP Interconnect Outage Notification is a service provided by Google Cloud"
        " Platform to inform users about any disruptions or outages in their"
        " Interconnect connectivity to the GCP network."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "affected_circuits": S("affectedCircuits", default=[]),
        "description": S("description"),
        "end_time": S("endTime"),
        "issue_type": S("issueType"),
        "name": S("name"),
        "source": S("source"),
        "start_time": S("startTime"),
        "interconnect_outage_notification_state": S("state"),
    }
    affected_circuits: Optional[List[str]] = field(default=None)
    description: Optional[str] = field(default=None)
    end_time: Optional[str] = field(default=None)
    issue_type: Optional[str] = field(default=None)
    name: Optional[str] = field(default=None)
    source: Optional[str] = field(default=None)
    start_time: Optional[str] = field(default=None)
    state: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpInterconnect(GcpResource):
    kind: ClassVar[str] = "gcp_interconnect"
    kind_display: ClassVar[str] = "GCP Interconnect"
    kind_description: ClassVar[str] = (
        "GCP Interconnect is a dedicated connection between your on-premises network"
        " and Google Cloud Platform, providing a high-speed and reliable link for data"
        " transfer."
    )
    api_spec: ClassVar[GcpApiSpec] = GcpApiSpec(
        service="compute",
        version="v1",
        accessors=["interconnects"],
        action="list",
        request_parameter={"project": "{project}"},
        request_parameter_in={"project"},
        response_path="items",
        response_regional_sub_path=None,
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
        "admin_enabled": S("adminEnabled"),
        "circuit_infos": S("circuitInfos", default=[]) >> ForallBend(GcpInterconnectCircuitInfo.mapping),
        "customer_name": S("customerName"),
        "expected_outages": S("expectedOutages", default=[]) >> ForallBend(GcpInterconnectOutageNotification.mapping),
        "google_ip_address": S("googleIpAddress"),
        "google_reference_id": S("googleReferenceId"),
        "interconnect_attachments": S("interconnectAttachments", default=[]),
        "interconnect_type": S("interconnectType"),
        "link_type": S("linkType"),
        "location": S("location"),
        "noc_contact_email": S("nocContactEmail"),
        "operational_status": S("operationalStatus"),
        "peer_ip_address": S("peerIpAddress"),
        "provisioned_link_count": S("provisionedLinkCount"),
        "requested_link_count": S("requestedLinkCount"),
        "satisfies_pzs": S("satisfiesPzs"),
        "interconnect_state": S("state"),
    }
    admin_enabled: Optional[bool] = field(default=None)
    circuit_infos: Optional[List[GcpInterconnectCircuitInfo]] = field(default=None)
    customer_name: Optional[str] = field(default=None)
    expected_outages: Optional[List[GcpInterconnectOutageNotification]] = field(default=None)
    google_ip_address: Optional[str] = field(default=None)
    google_reference_id: Optional[str] = field(default=None)
    interconnect_attachments: Optional[List[str]] = field(default=None)
    interconnect_type: Optional[str] = field(default=None)
    link_type: Optional[str] = field(default=None)
    location: Optional[str] = field(default=None)
    noc_contact_email: Optional[str] = field(default=None)
    operational_status: Optional[str] = field(default=None)
    peer_ip_address: Optional[str] = field(default=None)
    provisioned_link_count: Optional[int] = field(default=None)
    requested_link_count: Optional[int] = field(default=None)
    satisfies_pzs: Optional[bool] = field(default=None)
    interconnect_state: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpLicenseResourceRequirements:
    kind: ClassVar[str] = "gcp_license_resource_requirements"
    kind_display: ClassVar[str] = "GCP License Resource Requirements"
    kind_description: ClassVar[str] = (
        "GCP License Resource Requirements refers to the set of criteria that must be met in terms of computational"
        " resources when you want to bring your own licenses (BYOL) to the Google Cloud Platform."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "min_guest_cpu_count": S("minGuestCpuCount"),
        "min_memory_mb": S("minMemoryMb"),
    }
    min_guest_cpu_count: Optional[int] = field(default=None)
    min_memory_mb: Optional[int] = field(default=None)


@define(eq=False, slots=False)
class GcpLicense(GcpResource):
    kind: ClassVar[str] = "gcp_license"
    kind_display: ClassVar[str] = "GCP License"
    kind_description: ClassVar[str] = (
        "GCP Licenses are used to authorize the use of certain Google Cloud Platform services and resources."
    )
    api_spec: ClassVar[GcpApiSpec] = GcpApiSpec(
        service="compute",
        version="v1",
        accessors=["licenses"],
        action="list",
        request_parameter={"project": "{project}"},
        request_parameter_in={"project"},
        response_path="items",
        response_regional_sub_path=None,
        mutate_iam_permissions=["compute.licenses.delete"],
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
        "charges_use_fee": S("chargesUseFee"),
        "license_code": S("licenseCode"),
        "resource_requirements": S("resourceRequirements", default={}) >> Bend(GcpLicenseResourceRequirements.mapping),
        "transferable": S("transferable"),
    }
    charges_use_fee: Optional[bool] = field(default=None)
    license_code: Optional[str] = field(default=None)
    resource_requirements: Optional[GcpLicenseResourceRequirements] = field(default=None)
    transferable: Optional[bool] = field(default=None)


@define(eq=False, slots=False)
class GcpSavedDisk:
    kind: ClassVar[str] = "gcp_saved_disk"
    kind_display: ClassVar[str] = "GCP Saved Disk"
    kind_description: ClassVar[str] = (
        "The GCP Saved Disk refers to a snapshot of a virtual machine disk that has been saved within a machine"
        " image, which includes details about the architecture, the original disk source, the size of the stored"
        " data, and the status of the storage usage."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "architecture": S("architecture"),
        "source_disk": S("sourceDisk"),
        "storage_bytes": S("storageBytes"),
        "storage_bytes_status": S("storageBytesStatus"),
    }
    architecture: Optional[str] = field(default=None)
    source_disk: Optional[str] = field(default=None)
    storage_bytes: Optional[str] = field(default=None)
    storage_bytes_status: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpSourceDiskEncryptionKey:
    kind: ClassVar[str] = "gcp_source_disk_encryption_key"
    kind_display: ClassVar[str] = "GCP Source Disk Encryption Key"
    kind_description: ClassVar[str] = (
        "A GCP Source Disk Encryption Key is used to encrypt the disk images that are"
        " used as the sources for creating new disk images in Google Cloud Platform,"
        " ensuring data privacy and security."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "disk_encryption_key": S("diskEncryptionKey", default={}) >> Bend(GcpCustomerEncryptionKey.mapping),
        "source_disk": S("sourceDisk"),
    }
    disk_encryption_key: Optional[GcpCustomerEncryptionKey] = field(default=None)
    source_disk: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpSavedAttachedDisk:
    kind: ClassVar[str] = "gcp_saved_attached_disk"
    kind_display: ClassVar[str] = "GCP Saved Attached Disk"
    kind_description: ClassVar[str] = (
        "GCP Saved Attached Disk is a disk storage resource in Google Cloud Platform"
        " that is attached to a virtual machine instance and can be saved as a"
        " separate resource for future use."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "auto_delete": S("autoDelete"),
        "boot": S("boot"),
        "device_name": S("deviceName"),
        "disk_encryption_key": S("diskEncryptionKey", default={}) >> Bend(GcpCustomerEncryptionKey.mapping),
        "disk_size_gb": S("diskSizeGb") >> AsInt(),
        "disk_type": S("diskType"),
        "guest_os_features": S("guestOsFeatures", default=[]) >> ForallBend(S("type")),
        "index": S("index"),
        "interface": S("interface"),
        "licenses": S("licenses", default=[]),
        "mode": S("mode"),
        "source": S("source"),
        "storage_bytes": S("storageBytes"),
        "storage_bytes_status": S("storageBytesStatus"),
        "type": S("type"),
    }
    auto_delete: Optional[bool] = field(default=None)
    boot: Optional[bool] = field(default=None)
    device_name: Optional[str] = field(default=None)
    disk_encryption_key: Optional[GcpCustomerEncryptionKey] = field(default=None)
    disk_size_gb: Optional[int] = field(default=None)
    disk_type: Optional[str] = field(default=None)
    guest_os_features: Optional[List[str]] = field(default=None)
    index: Optional[int] = field(default=None)
    interface: Optional[str] = field(default=None)
    licenses: Optional[List[str]] = field(default=None)
    mode: Optional[str] = field(default=None)
    source: Optional[str] = field(default=None)
    storage_bytes: Optional[str] = field(default=None)
    storage_bytes_status: Optional[str] = field(default=None)
    type: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpSourceInstanceProperties:
    kind: ClassVar[str] = "gcp_source_instance_properties"
    kind_display: ClassVar[str] = "GCP Source Instance Properties"
    kind_description: ClassVar[str] = (
        "GCP Source Instance Properties refers to the configuration and"
        " characteristics of a virtual machine instance in Google Cloud Platform"
        " (GCP). It includes information such as the instance name, machine type,"
        " network settings, and attached disks."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "can_ip_forward": S("canIpForward"),
        "deletion_protection": S("deletionProtection"),
        "description": S("description"),
        "saved_disks": S("disks", default=[]) >> ForallBend(GcpSavedAttachedDisk.mapping),
        "guest_accelerators": S("guestAccelerators", default=[]) >> ForallBend(GcpAcceleratorConfig.mapping),
        "key_revocation_action_type": S("keyRevocationActionType"),
        "labels": S("labels"),
        "machine_type": S("machineType"),
        "metadata": S("metadata", default={}) >> Bend(GcpMetadata.mapping),
        "min_cpu_platform": S("minCpuPlatform"),
        "network_interfaces": S("networkInterfaces", default=[]) >> ForallBend(GcpNetworkInterface.mapping),
        "scheduling": S("scheduling", default={}) >> Bend(GcpScheduling.mapping),
        "service_accounts": S("serviceAccounts", default=[]) >> ForallBend(GcpServiceAccount.mapping),
        "tags": S("tags", default={}) >> Bend(GcpTags.mapping),
    }
    can_ip_forward: Optional[bool] = field(default=None)
    deletion_protection: Optional[bool] = field(default=None)
    description: Optional[str] = field(default=None)
    saved_disks: Optional[List[GcpSavedAttachedDisk]] = field(default=None)
    guest_accelerators: Optional[List[GcpAcceleratorConfig]] = field(default=None)
    key_revocation_action_type: Optional[str] = field(default=None)
    labels: Optional[Dict[str, str]] = field(default=None)
    machine_type: Optional[str] = field(default=None)
    metadata: Optional[GcpMetadata] = field(default=None)
    min_cpu_platform: Optional[str] = field(default=None)
    network_interfaces: Optional[List[GcpNetworkInterface]] = field(default=None)
    scheduling: Optional[GcpScheduling] = field(default=None)
    service_accounts: Optional[List[GcpServiceAccount]] = field(default=None)
    tags: Optional[GcpTags] = field(default=None)


@define(eq=False, slots=False)
class GcpMachineImage(GcpResource):
    kind: ClassVar[str] = "gcp_machine_image"
    kind_display: ClassVar[str] = "GCP Machine Image"
    kind_description: ClassVar[str] = (
        "Machine Images in Google Cloud Platform are snapshots of a virtual machine's"
        " disk that can be used to create new instances with the same configuration"
        " and data."
    )
    reference_kinds: ClassVar[ModelReference] = {
        "predecessors": {
            "default": ["gcp_disk"],
        }
    }
    api_spec: ClassVar[GcpApiSpec] = GcpApiSpec(
        service="compute",
        version="v1",
        accessors=["machineImages"],
        action="list",
        request_parameter={"project": "{project}"},
        request_parameter_in={"project"},
        response_path="items",
        response_regional_sub_path=None,
        mutate_iam_permissions=["compute.machineImages.delete"],
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
        "guest_flush": S("guestFlush"),
        "instance_properties": S("instanceProperties", default={}) >> Bend(GcpInstanceProperties.mapping),
        "machine_image_encryption_key": S("machineImageEncryptionKey", default={})
        >> Bend(GcpCustomerEncryptionKey.mapping),
        "satisfies_pzs": S("satisfiesPzs"),
        "saved_disks": S("savedDisks", default=[]) >> ForallBend(GcpSavedDisk.mapping),
        "source_disk_encryption_keys": S("sourceDiskEncryptionKeys", default=[])
        >> ForallBend(GcpSourceDiskEncryptionKey.mapping),
        "source_instance": S("sourceInstance"),
        "source_instance_properties": S("sourceInstanceProperties", default={})
        >> Bend(GcpSourceInstanceProperties.mapping),
        "status": S("status"),
        "storage_locations": S("storageLocations", default=[]),
        "total_storage_bytes": S("totalStorageBytes"),
    }
    guest_flush: Optional[bool] = field(default=None)
    instance_properties: Optional[GcpInstanceProperties] = field(default=None)
    machine_image_encryption_key: Optional[GcpCustomerEncryptionKey] = field(default=None)
    satisfies_pzs: Optional[bool] = field(default=None)
    saved_disks: Optional[List[GcpSavedDisk]] = field(default=None)
    source_disk_encryption_keys: Optional[List[GcpSourceDiskEncryptionKey]] = field(default=None)
    source_instance: Optional[str] = field(default=None)
    source_instance_properties: Optional[GcpSourceInstanceProperties] = field(default=None)
    status: Optional[str] = field(default=None)
    storage_locations: Optional[List[str]] = field(default=None)
    total_storage_bytes: Optional[str] = field(default=None)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        for disk in self.saved_disks or []:
            if disk.source_disk:
                builder.add_edge(self, reverse=True, clazz=GcpDisk, link=disk.source_disk)
        if p := self.instance_properties:
            for attached_disk in p.disks or []:
                builder.add_edge(self, reverse=True, clazz=GcpDisk, link=attached_disk.source)


@define(eq=False, slots=False)
class GcpAccelerators:
    kind: ClassVar[str] = "gcp_accelerators"
    kind_display: ClassVar[str] = "GCP Accelerators"
    kind_description: ClassVar[str] = (
        "Accelerators in Google Cloud Platform provide specialized hardware to"
        " enhance the performance of compute-intensive workloads, such as machine"
        " learning and high-performance computing tasks."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "guest_accelerator_count": S("guestAcceleratorCount"),
        "guest_accelerator_type": S("guestAcceleratorType"),
    }
    guest_accelerator_count: Optional[int] = field(default=None)
    guest_accelerator_type: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpMachineType(GcpResource, BaseInstanceType):
    kind: ClassVar[str] = "gcp_machine_type"
    kind_display: ClassVar[str] = "GCP Machine Type"
    kind_description: ClassVar[str] = (
        "GCP Machine Types are predefined hardware configurations that define the"
        " virtualized hardware resources for Google Cloud Platform virtual machines."
    )
    api_spec: ClassVar[GcpApiSpec] = GcpApiSpec(
        service="compute",
        version="v1",
        accessors=["machineTypes"],
        action="aggregatedList",
        request_parameter={"project": "{project}"},
        request_parameter_in={"project"},
        response_path="items",
        response_regional_sub_path="machineTypes",
        mutate_iam_permissions=[],  # can not be mutated
    )
    collect_individual_api_spec: ClassVar[GcpApiSpec] = GcpApiSpec(
        service="compute",
        version="v1",
        accessors=["machineTypes"],
        action="get",
        response_path="",
        request_parameter={"project": "{project}", "zone": "{zone}", "machineType": "{machineType}"},
        request_parameter_in={"project", "zone", "machineType"},
    )
    reference_kinds: ClassVar[ModelReference] = {
        "predecessors": {"default": ["gcp_sku"]},
        "successors": {"default": ["gcp_accelerator_type"]},
    }
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("name").or_else(S("id")).or_else(S("selfLink")),
        "tags": S("labels", default={}),
        "name": S("name"),
        "ctime": S("creationTimestamp"),
        "description": S("description"),
        "link": S("selfLink"),
        "label_fingerprint": S("labelFingerprint"),
        "deprecation_status": S("deprecated", default={}) >> Bend(GcpDeprecationStatus.mapping),
        "accelerators": S("accelerators", default=[]) >> ForallBend(GcpAccelerators.mapping),
        "image_space_gb": S("imageSpaceGb"),
        "is_shared_cpu": S("isSharedCpu"),
        "maximum_persistent_disks": S("maximumPersistentDisks"),
        "maximum_persistent_disks_size_gb": S("maximumPersistentDisksSizeGb"),
        "scratch_disks": S("scratchDisks", default=[]) >> ForallBend(S("diskGb")),
        "instance_type": S("name"),
        "instance_cores": S("guestCpus") >> F(lambda x: float(x)),
        "instance_memory": S("memoryMb") >> F(lambda x: float(x) / 1024),
    }
    accelerators: Optional[List[GcpAccelerators]] = field(default=None)
    image_space_gb: Optional[int] = field(default=None)
    is_shared_cpu: Optional[bool] = field(default=None)
    maximum_persistent_disks: Optional[int] = field(default=None)
    maximum_persistent_disks_size_gb: Optional[str] = field(default=None)
    scratch_disks: Optional[List[int]] = field(default=None)

    @classmethod
    def collect_individual(cls: Type[GcpResource], builder: GraphBuilder, zone: str, name: str) -> None:
        result = builder.client.get(
            GcpMachineType.collect_individual_api_spec,
            zone=zone,
            machineType=name,
        )
        result[InternalZoneProp] = zone  # `add_node()` picks this up and sets proper zone/region
        machine_type_obj = GcpMachineType.from_api(result)
        builder.add_node(machine_type_obj, result)

    def _machine_type_matches_sku_description(self, sku_description: str) -> bool:
        if not self.name:
            return False
        mappings = [
            ("n2d-", "N2D AMD "),
            ("n2-", "N2 "),
            (("m1-", "m2-"), "Memory-optimized "),
            ("c2-", "Compute optimized "),
            ("a2-", "A2 "),
            ("c2d-", "C2D AMD "),
            ("c3-", "C3 "),
            ("m3-", "M3 "),
            ("t2a-", "T2A "),
            ("t2d-", "T2D AMD "),
        ]
        for mapping in mappings:
            if (self.name.startswith(mapping[0]) and not sku_description.startswith(mapping[1])) or (  # type: ignore
                not self.name.startswith(mapping[0]) and sku_description.startswith(mapping[1])  # type: ignore
            ):
                return False

        if "custom" not in self.name:
            if (self.name.startswith("e2-") and not sku_description.startswith("E2 ")) or (
                not self.name.startswith("e2-") and sku_description.startswith("E2 ")
            ):
                return False
        return True

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        # Add edge from machine type to accelerator type
        for at in self.accelerators or []:
            # The accelerator type resource name, not a full URL, e.g. nvidia-tesla-t4.
            builder.add_edge(self, clazz=GcpAcceleratorType, id=at.guest_accelerator_type, reverse=True)

    def post_process_instance(self, builder: GraphBuilder, source: Json) -> None:
        # Adds edges from machine type to SKUs and determines ondemand pricing
        if not self.name:
            return

        def filter(sku: GcpSku) -> bool:
            if not self.name or not self._region:
                return False
            if not sku.description or not sku.category or not sku.geo_taxonomy:
                return False

            if not (sku.category.resource_family == "Compute" and sku.category.usage_type == "OnDemand"):
                return False
            if sku.category.resource_group not in (
                "G1Small",
                "F1Micro",
                "N1Standard",  # ?
                "CPU",
                "RAM",
            ):
                return False
            if ("custom" not in self.name and "Custom" in sku.description) or (
                "custom" in self.name and "Custom" not in sku.description
            ):
                return False
            if self._region.name not in sku.geo_taxonomy.regions:
                return False
            if self.name == "g1-small" and sku.category.resource_group != "G1Small":
                return False
            if self.name == "f1-micro" and sku.category.resource_group != "F1Micro":
                return False

            if self.name.startswith("n1-") and sku.category.resource_group != "N1Standard":
                return False

            return self._machine_type_matches_sku_description(sku.description)

        skus = builder.nodes(GcpSku, filter=filter)
        if len(skus) == 1 and self.name in ("g1-small", "f1-micro") and skus[0].usage_unit_nanos:
            builder.add_edge(self, reverse=True, node=skus[0])
            self.ondemand_cost = skus[0].usage_unit_nanos / 1000000000
            return

        if len(skus) == 2 or (len(skus) == 3 and "custom" in self.name):
            ondemand_cost = 0.0
            cores = self.instance_cores
            ram = self.instance_memory
            extended_memory_pricing: bool = False
            if "custom" in self.name:
                extended_memory_pricing = ram / cores > 8

            for sku in skus:
                if sku.description and sku.usage_unit_nanos:
                    if "Core" in sku.description:
                        ondemand_cost += sku.usage_unit_nanos * cores
                    elif "Ram" in sku.description or "RAM" in sku.description:
                        if (extended_memory_pricing and "Extended" not in sku.description) or (
                            not extended_memory_pricing and "Extended" in sku.description
                        ):
                            continue
                        ondemand_cost += sku.usage_unit_nanos * ram
                    builder.add_edge(self, reverse=True, node=sku)

            if ondemand_cost > 0:
                self.ondemand_cost = ondemand_cost / 1000000000
            return


@define(eq=False, slots=False)
class GcpNetworkEdgeSecurityService(GcpResource):
    kind: ClassVar[str] = "gcp_network_edge_security_service"
    kind_display: ClassVar[str] = "GCP Network Edge Security Service"
    kind_description: ClassVar[str] = (
        "GCP Network Edge Security Service provides secure and reliable access to"
        " resources in the Google Cloud Platform network, reducing the risk of"
        " unauthorized access and data breaches."
    )
    api_spec: ClassVar[GcpApiSpec] = GcpApiSpec(
        service="compute",
        version="v1",
        accessors=["networkEdgeSecurityServices"],
        action="aggregatedList",
        request_parameter={"project": "{project}"},
        request_parameter_in={"project"},
        response_path="items",
        response_regional_sub_path="networkEdgeSecurityServices",
        mutate_iam_permissions=[
            "compute.networkEdgeSecurityServices.update",
            "compute.networkEdgeSecurityServices.delete",
        ],
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
        "service_fingerprint": S("fingerprint"),
        "service_security_policy": S("securityPolicy"),
        "service_self_link_with_id": S("selfLinkWithId"),
    }
    service_fingerprint: Optional[str] = field(default=None)
    service_security_policy: Optional[str] = field(default=None)
    service_self_link_with_id: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpNetworkPeering:
    kind: ClassVar[str] = "gcp_network_peering"
    kind_display: ClassVar[str] = "GCP Network Peering"
    kind_description: ClassVar[str] = (
        "Network Peering in Google Cloud Platform enables direct connectivity between"
        " two Virtual Private Cloud (VPC) networks, allowing them to communicate"
        " securely and efficiently with each other."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "auto_create_routes": S("autoCreateRoutes"),
        "exchange_subnet_routes": S("exchangeSubnetRoutes"),
        "export_custom_routes": S("exportCustomRoutes"),
        "export_subnet_routes_with_public_ip": S("exportSubnetRoutesWithPublicIp"),
        "import_custom_routes": S("importCustomRoutes"),
        "import_subnet_routes_with_public_ip": S("importSubnetRoutesWithPublicIp"),
        "name": S("name"),
        "network": S("network"),
        "peer_mtu": S("peerMtu"),
        "stack_type": S("stackType"),
        "network_peering_state": S("state"),
        "state_details": S("stateDetails"),
    }
    auto_create_routes: Optional[bool] = field(default=None)
    exchange_subnet_routes: Optional[bool] = field(default=None)
    export_custom_routes: Optional[bool] = field(default=None)
    export_subnet_routes_with_public_ip: Optional[bool] = field(default=None)
    import_custom_routes: Optional[bool] = field(default=None)
    import_subnet_routes_with_public_ip: Optional[bool] = field(default=None)
    name: Optional[str] = field(default=None)
    network: Optional[str] = field(default=None)
    peer_mtu: Optional[int] = field(default=None)
    stack_type: Optional[str] = field(default=None)
    network_peering_state: Optional[str] = field(default=None)
    state_details: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpNetwork(GcpResource):
    kind: ClassVar[str] = "gcp_network"
    kind_display: ClassVar[str] = "GCP Network"
    kind_description: ClassVar[str] = (
        "GCP Network is a virtual network infrastructure that allows users to"
        " securely connect and isolate their resources in the Google Cloud Platform."
    )
    api_spec: ClassVar[GcpApiSpec] = GcpApiSpec(
        service="compute",
        version="v1",
        accessors=["networks"],
        action="list",
        request_parameter={"project": "{project}"},
        request_parameter_in={"project"},
        response_path="items",
        response_regional_sub_path=None,
        mutate_iam_permissions=["compute.networks.delete"],
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
        "ipv4_range": S("IPv4Range"),
        "auto_create_subnetworks": S("autoCreateSubnetworks"),
        "enable_ula_internal_ipv6": S("enableUlaInternalIpv6"),
        "firewall_policy": S("firewallPolicy"),
        "gateway_ipv4": S("gatewayIPv4"),
        "internal_ipv6_range": S("internalIpv6Range"),
        "mtu": S("mtu"),
        "network_firewall_policy_enforcement_order": S("networkFirewallPolicyEnforcementOrder"),
        "network_peerings": S("peerings", default=[]) >> ForallBend(GcpNetworkPeering.mapping),
        "routing_config": S("routingConfig", "routingMode"),
        "self_link_with_id": S("selfLinkWithId"),
        "subnetworks": S("subnetworks", default=[]),
    }
    ipv4_range: Optional[str] = field(default=None)
    auto_create_subnetworks: Optional[bool] = field(default=None)
    enable_ula_internal_ipv6: Optional[bool] = field(default=None)
    firewall_policy: Optional[str] = field(default=None)
    gateway_ipv4: Optional[str] = field(default=None)
    internal_ipv6_range: Optional[str] = field(default=None)
    mtu: Optional[int] = field(default=None)
    network_firewall_policy_enforcement_order: Optional[str] = field(default=None)
    network_peerings: Optional[List[GcpNetworkPeering]] = field(default=None)
    routing_config: Optional[str] = field(default=None)
    self_link_with_id: Optional[str] = field(default=None)
    subnetworks: Optional[List[str]] = field(default=None)


@define(eq=False, slots=False)
class GcpNodeGroupAutoscalingPolicy:
    kind: ClassVar[str] = "gcp_node_group_autoscaling_policy"
    kind_display: ClassVar[str] = "GCP Node Group Autoscaling Policy"
    kind_description: ClassVar[str] = (
        "GCP Node Group Autoscaling Policy is a feature in Google Cloud Platform that"
        " allows automatic adjustment of the number of nodes in a node group based on"
        " demand, ensuring optimal resource utilization and performance."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"max_nodes": S("maxNodes"), "min_nodes": S("minNodes"), "mode": S("mode")}
    max_nodes: Optional[int] = field(default=None)
    min_nodes: Optional[int] = field(default=None)
    mode: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpNodeGroupMaintenanceWindow:
    kind: ClassVar[str] = "gcp_node_group_maintenance_window"
    kind_display: ClassVar[str] = "GCP Node Group Maintenance Window"
    kind_description: ClassVar[str] = (
        "GCP Node Group Maintenance Window is a feature in Google Cloud Platform that"
        " allows users to schedule maintenance windows for node groups, during which"
        " the nodes can undergo maintenance operations without disrupting the"
        " applications running on them."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "maintenance_duration": S("maintenanceDuration", default={}) >> Bend(GcpDuration.mapping),
        "start_time": S("startTime"),
    }
    maintenance_duration: Optional[GcpDuration] = field(default=None)
    start_time: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpShareSettingsProjectConfig:
    kind: ClassVar[str] = "gcp_share_settings_project_config"
    kind_display: ClassVar[str] = "GCP Share Settings Project Config"
    kind_description: ClassVar[str] = (
        "The GCP Share Settings Project Config within the Node Group service framework outlines the specific"
        " project identifier for which the share settings are applicable."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"project_id": S("projectId")}
    project_id: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpShareSettings:
    kind: ClassVar[str] = "gcp_share_settings"
    kind_display: ClassVar[str] = "GCP Share Settings"
    kind_description: ClassVar[str] = (
        "GCP Share Settings in the context of a Node Group dictate how compute resources are distributed and"
        " shared among various projects within a specific group or type."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "project_map": S("projectMap", default={}) >> MapDict(value_bender=Bend(GcpShareSettingsProjectConfig.mapping)),
        "share_type": S("shareType"),
    }
    project_map: Optional[Dict[str, GcpShareSettingsProjectConfig]] = field(default=None)
    share_type: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpNodeGroup(GcpResource):
    kind: ClassVar[str] = "gcp_node_group"
    kind_display: ClassVar[str] = "GCP Node Group"
    kind_description: ClassVar[str] = (
        "The GCP Node Group is a service that manages groups of sole-tenant nodes in Google Cloud, providing"
        " capabilities for autoscaling, scheduled maintenance, and specifying node affinity to optimize placement"
        " and utilization."
    )
    reference_kinds: ClassVar[ModelReference] = {"predecessors": {"default": ["gcp_node_template"]}}
    api_spec: ClassVar[GcpApiSpec] = GcpApiSpec(
        service="compute",
        version="v1",
        accessors=["nodeGroups"],
        action="aggregatedList",
        request_parameter={"project": "{project}"},
        request_parameter_in={"project"},
        response_path="items",
        response_regional_sub_path="nodeGroups",
        mutate_iam_permissions=["compute.nodeGroups.update", "compute.nodeGroups.delete"],
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
        "autoscaling_policy": S("autoscalingPolicy", default={}) >> Bend(GcpNodeGroupAutoscalingPolicy.mapping),
        "fingerprint": S("fingerprint"),
        "location_hint": S("locationHint"),
        "maintenance_policy": S("maintenancePolicy"),
        "maintenance_window": S("maintenanceWindow", default={}) >> Bend(GcpNodeGroupMaintenanceWindow.mapping),
        "node_template": S("nodeTemplate"),
        "share_settings": S("shareSettings", default={}) >> Bend(GcpShareSettings.mapping),
        "size": S("size"),
        "status": S("status"),
    }
    autoscaling_policy: Optional[GcpNodeGroupAutoscalingPolicy] = field(default=None)
    fingerprint: Optional[str] = field(default=None)
    location_hint: Optional[str] = field(default=None)
    maintenance_policy: Optional[str] = field(default=None)
    maintenance_window: Optional[GcpNodeGroupMaintenanceWindow] = field(default=None)
    node_template: Optional[str] = field(default=None)
    share_settings: Optional[GcpShareSettings] = field(default=None)
    size: Optional[int] = field(default=None)
    status: Optional[str] = field(default=None)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if self.node_template:
            builder.add_edge(self, reverse=True, clazz=GcpNodeTemplate, link=self.node_template)


@define(eq=False, slots=False)
class GcpLocalDisk:
    kind: ClassVar[str] = "gcp_local_disk"
    kind_display: ClassVar[str] = "GCP Local Disk"
    kind_description: ClassVar[str] = (
        "GCP Local Disk is a type of storage device provided by Google Cloud Platform"
        " that allows users to store and access data on a virtual machine's local"
        " disk. It provides high-performance and low-latency storage for temporary or"
        " frequently accessed data."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "disk_count": S("diskCount"),
        "disk_size_gb": S("diskSizeGb"),
        "disk_type": S("diskType"),
    }
    disk_count: Optional[int] = field(default=None)
    disk_size_gb: Optional[int] = field(default=None)
    disk_type: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpNodeTemplateNodeTypeFlexibility:
    kind: ClassVar[str] = "gcp_node_template_node_type_flexibility"
    kind_display: ClassVar[str] = "GCP Node Template Node Type Flexibility"
    kind_description: ClassVar[str] = (
        "This resource allows for flexible node type configuration in Google Cloud Platform node templates."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"cpus": S("cpus"), "local_ssd": S("localSsd"), "memory": S("memory")}
    cpus: Optional[str] = field(default=None)
    local_ssd: Optional[str] = field(default=None)
    memory: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpNodeTemplate(GcpResource):
    kind: ClassVar[str] = "gcp_node_template"
    kind_display: ClassVar[str] = "GCP Node Template"
    kind_description: ClassVar[str] = (
        "GCP Node Template is a reusable configuration template used to create and"
        " manage virtual machine instances in the Google Cloud Platform."
    )
    reference_kinds: ClassVar[ModelReference] = {"predecessors": {"default": ["gcp_disk_type"]}}
    api_spec: ClassVar[GcpApiSpec] = GcpApiSpec(
        service="compute",
        version="v1",
        accessors=["nodeTemplates"],
        action="aggregatedList",
        request_parameter={"project": "{project}"},
        request_parameter_in={"project"},
        response_path="items",
        response_regional_sub_path="nodeTemplates",
        mutate_iam_permissions=["compute.nodeTemplates.delete"],
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
        "guest_accelerators": S("accelerators", default=[]) >> ForallBend(GcpAcceleratorConfig.mapping),
        "cpu_overcommit_type": S("cpuOvercommitType"),
        "local_disks": S("disks", default=[]) >> ForallBend(GcpLocalDisk.mapping),
        "node_affinity_labels": S("nodeAffinityLabels"),
        "node_type": S("nodeType"),
        "node_type_flexibility": S("nodeTypeFlexibility", default={})
        >> Bend(GcpNodeTemplateNodeTypeFlexibility.mapping),
        "server_binding": S("serverBinding", "type"),
        "status": S("status"),
        "status_message": S("statusMessage"),
    }
    guest_accelerators: Optional[List[GcpAcceleratorConfig]] = field(default=None)
    cpu_overcommit_type: Optional[str] = field(default=None)
    local_disks: Optional[List[GcpLocalDisk]] = field(default=None)
    node_affinity_labels: Optional[Dict[str, str]] = field(default=None)
    node_type: Optional[str] = field(default=None)
    node_type_flexibility: Optional[GcpNodeTemplateNodeTypeFlexibility] = field(default=None)
    server_binding: Optional[str] = field(default=None)
    status: Optional[str] = field(default=None)
    status_message: Optional[str] = field(default=None)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if self.local_disks:
            for disk in self.local_disks:
                builder.add_edge(self, reverse=True, clazz=GcpDiskType, link=disk.disk_type)


@define(eq=False, slots=False)
class GcpNodeType(GcpResource):
    kind: ClassVar[str] = "gcp_node_type"
    kind_display: ClassVar[str] = "GCP Node Type"
    kind_description: ClassVar[str] = (
        "GCP Node Types determine the hardware configuration of virtual machines in"
        " Google Cloud Platform (GCP). Each node type has specific CPU, memory, and"
        " storage capacity."
    )
    api_spec: ClassVar[GcpApiSpec] = GcpApiSpec(
        service="compute",
        version="v1",
        accessors=["nodeTypes"],
        action="aggregatedList",
        request_parameter={"project": "{project}"},
        request_parameter_in={"project"},
        response_path="items",
        response_regional_sub_path="nodeTypes",
        mutate_iam_permissions=[],  # can not be mutated
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
        "cpu_platform": S("cpuPlatform"),
        "guest_cpus": S("guestCpus"),
        "local_ssd_gb": S("localSsdGb"),
        "memory_mb": S("memoryMb"),
    }
    cpu_platform: Optional[str] = field(default=None)
    guest_cpus: Optional[int] = field(default=None)
    local_ssd_gb: Optional[int] = field(default=None)
    memory_mb: Optional[int] = field(default=None)


@define(eq=False, slots=False)
class GcpPacketMirroringForwardingRuleInfo:
    kind: ClassVar[str] = "gcp_packet_mirroring_forwarding_rule_info"
    kind_display: ClassVar[str] = "GCP Packet Mirroring Forwarding Rule Info"
    kind_description: ClassVar[str] = (
        "Packet Mirroring Forwarding Rule Info provides information about the"
        " forwarding rules used for packet mirroring in Google Cloud Platform (GCP)."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"canonical_url": S("canonicalUrl"), "url": S("url")}
    canonical_url: Optional[str] = field(default=None)
    url: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpPacketMirroringFilter:
    kind: ClassVar[str] = "gcp_packet_mirroring_filter"
    kind_display: ClassVar[str] = "GCP Packet Mirroring Filter"
    kind_description: ClassVar[str] = (
        "GCP Packet Mirroring Filter is a feature in Google Cloud Platform that"
        " allows filtering of network packets for traffic analysis and troubleshooting"
        " purposes."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "ip_protocols": S("IPProtocols", default=[]),
        "cidr_ranges": S("cidrRanges", default=[]),
        "direction": S("direction"),
    }
    ip_protocols: Optional[List[str]] = field(default=None)
    cidr_ranges: Optional[List[str]] = field(default=None)
    direction: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpPacketMirroringMirroredResourceInfoInstanceInfo:
    kind: ClassVar[str] = "gcp_packet_mirroring_mirrored_resource_info_instance_info"
    kind_display: ClassVar[str] = "GCP Packet Mirroring Mirrored Resource Instance Info"
    kind_description: ClassVar[str] = (
        "Packet Mirroring in Google Cloud Platform allows you to monitor and capture"
        " network traffic in real-time. This particular resource provides information"
        " about the instance being mirrored."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"canonical_url": S("canonicalUrl"), "url": S("url")}
    canonical_url: Optional[str] = field(default=None)
    url: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpPacketMirroringMirroredResourceInfoSubnetInfo:
    kind: ClassVar[str] = "gcp_packet_mirroring_mirrored_resource_info_subnet_info"
    kind_display: ClassVar[str] = "GCP Packet Mirroring Mirrored Resource Info Subnet Info"
    kind_description: ClassVar[str] = (
        "GCP Packet Mirroring Mirrored Resource Info Subnet Info is related to the configuration for selecting"
        " specific subnets whose traffic is to be mirrored for inspection or monitoring purposes in the Google"
        " Cloud Packet Mirroring service."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"canonical_url": S("canonicalUrl"), "url": S("url")}
    canonical_url: Optional[str] = field(default=None)
    url: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpPacketMirroringMirroredResourceInfo:
    kind: ClassVar[str] = "gcp_packet_mirroring_mirrored_resource_info"
    kind_display: ClassVar[str] = "GCP Packet Mirroring Mirrored Resource Info"
    kind_description: ClassVar[str] = (
        "Packet Mirroring Mirrored Resource Info is a feature in Google Cloud"
        " Platform that allows users to collect and analyze network traffic by"
        " duplicating packets from a specific resource in the network."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "instances": S("instances", default=[])
        >> ForallBend(GcpPacketMirroringMirroredResourceInfoInstanceInfo.mapping),
        "subnetworks": S("subnetworks", default=[])
        >> ForallBend(GcpPacketMirroringMirroredResourceInfoSubnetInfo.mapping),
        "tags": S("tags", default=[]),
    }
    instances: Optional[List[GcpPacketMirroringMirroredResourceInfoInstanceInfo]] = field(default=None)
    subnetworks: Optional[List[GcpPacketMirroringMirroredResourceInfoSubnetInfo]] = field(default=None)
    tags: Optional[List[str]] = field(default=None)


@define(eq=False, slots=False)
class GcpPacketMirroringNetworkInfo:
    kind: ClassVar[str] = "gcp_packet_mirroring_network_info"
    kind_display: ClassVar[str] = "GCP Packet Mirroring Network Info"
    kind_description: ClassVar[str] = (
        "Packet Mirroring Network Info in Google Cloud Platform allows users to copy"
        " and analyze network traffic in virtual machine instances for monitoring,"
        " troubleshooting, and security purposes."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"canonical_url": S("canonicalUrl"), "url": S("url")}
    canonical_url: Optional[str] = field(default=None)
    url: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpPacketMirroring(GcpResource):
    kind: ClassVar[str] = "gcp_packet_mirroring"
    kind_display: ClassVar[str] = "GCP Packet Mirroring"
    kind_description: ClassVar[str] = (
        "GCP Packet Mirroring is a service provided by Google Cloud Platform that"
        " allows users to capture and mirror network traffic in order to monitor and"
        " analyze network data for security and troubleshooting purposes."
    )
    reference_kinds: ClassVar[ModelReference] = {"predecessors": {"default": ["gcp_instance", "gcp_subnetwork"]}}
    api_spec: ClassVar[GcpApiSpec] = GcpApiSpec(
        service="compute",
        version="v1",
        accessors=["packetMirrorings"],
        action="aggregatedList",
        request_parameter={"project": "{project}"},
        request_parameter_in={"project"},
        response_path="items",
        response_regional_sub_path="packetMirrorings",
        mutate_iam_permissions=["compute.packetMirrorings.update", "compute.packetMirrorings.delete"],
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
        "collector_ilb": S("collectorIlb", default={}) >> Bend(GcpPacketMirroringForwardingRuleInfo.mapping),
        "enable": S("enable"),
        "filter": S("filter", default={}) >> Bend(GcpPacketMirroringFilter.mapping),
        "mirrored_resources": S("mirroredResources", default={})
        >> Bend(GcpPacketMirroringMirroredResourceInfo.mapping),
        "packet_mirroring_network": S("network", default={}) >> Bend(GcpPacketMirroringNetworkInfo.mapping),
        "priority": S("priority"),
    }
    collector_ilb: Optional[GcpPacketMirroringForwardingRuleInfo] = field(default=None)
    enable: Optional[str] = field(default=None)
    filter: Optional[GcpPacketMirroringFilter] = field(default=None)
    mirrored_resources: Optional[GcpPacketMirroringMirroredResourceInfo] = field(default=None)
    packet_mirroring_network: Optional[GcpPacketMirroringNetworkInfo] = field(default=None)
    priority: Optional[int] = field(default=None)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if mmr := self.mirrored_resources:
            for subnet in mmr.subnetworks or []:
                builder.add_edge(self, reverse=True, clazz=GcpSubnetwork, link=subnet.url)
            for instance in mmr.instances or []:
                builder.add_edge(self, reverse=True, clazz=GcpInstance, link=instance.url)


@define(eq=False, slots=False)
class GcpPublicAdvertisedPrefixPublicDelegatedPrefix:
    kind: ClassVar[str] = "gcp_public_advertised_prefix_public_delegated_prefix"
    kind_display: ClassVar[str] = "GCP Public Advertised Prefix - Public Delegated Prefix"
    kind_description: ClassVar[str] = (
        "A GCP Public Advertised Prefix - Public Delegated Prefix is a range of IP"
        " addresses that can be advertised and delegated within the Google Cloud"
        " Platform network for public connectivity."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "ip_range": S("ipRange"),
        "name": S("name"),
        "project": S("project"),
        "region": S("region"),
        "status": S("status"),
    }
    ip_range: Optional[str] = field(default=None)
    name: Optional[str] = field(default=None)
    project: Optional[str] = field(default=None)
    region: Optional[str] = field(default=None)
    status: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpPublicAdvertisedPrefix(GcpResource):
    kind: ClassVar[str] = "gcp_public_advertised_prefix"
    kind_display: ClassVar[str] = "GCP Public Advertised Prefix"
    kind_description: ClassVar[str] = (
        "A GCP Public Advertised Prefix is a range of IP addresses that can be"
        " advertised over the internet to allow communication with GCP resources."
    )
    reference_kinds: ClassVar[ModelReference] = {"predecessors": {"default": ["gcp_public_delegated_prefix"]}}
    api_spec: ClassVar[GcpApiSpec] = GcpApiSpec(
        service="compute",
        version="v1",
        accessors=["publicAdvertisedPrefixes"],
        action="list",
        request_parameter={"project": "{project}"},
        request_parameter_in={"project"},
        response_path="items",
        response_regional_sub_path=None,
        mutate_iam_permissions=["compute.publicAdvertisedPrefixes.update", "compute.publicAdvertisedPrefixes.delete"],
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
        "dns_verification_ip": S("dnsVerificationIp"),
        "fingerprint": S("fingerprint"),
        "ip_cidr_range": S("ipCidrRange"),
        "public_delegated_prefixs": S("publicDelegatedPrefixs", default=[])
        >> ForallBend(GcpPublicAdvertisedPrefixPublicDelegatedPrefix.mapping),
        "shared_secret": S("sharedSecret"),
        "status": S("status"),
    }
    dns_verification_ip: Optional[str] = field(default=None)
    fingerprint: Optional[str] = field(default=None)
    ip_cidr_range: Optional[str] = field(default=None)
    public_delegated_prefixs: Optional[List[GcpPublicAdvertisedPrefixPublicDelegatedPrefix]] = field(default=None)
    shared_secret: Optional[str] = field(default=None)
    status: Optional[str] = field(default=None)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if pdp := self.public_delegated_prefixs:
            for prefix in pdp:
                if prefix.name:
                    builder.add_edge(self, reverse=True, clazz=GcpPublicDelegatedPrefix, name=prefix.name)


@define(eq=False, slots=False)
class GcpLicenseResourceCommitment:
    kind: ClassVar[str] = "gcp_license_resource_commitment"
    kind_display: ClassVar[str] = "GCP License Resource Commitment"
    kind_description: ClassVar[str] = (
        "A GCP license resource commitment is a commitment made by a customer to use"
        " a specific software license offered by Google Cloud Platform (GCP) for a"
        " predetermined period of time. This commitment ensures consistent usage and"
        " cost savings for the customer."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "amount": S("amount"),
        "cores_per_license": S("coresPerLicense"),
        "license": S("license"),
    }
    amount: Optional[str] = field(default=None)
    cores_per_license: Optional[str] = field(default=None)
    license: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpAllocationSpecificSKUAllocationAllocatedInstancePropertiesReservedDisk:
    kind: ClassVar[str] = "gcp_allocation_specific_sku_allocation_allocated_instance_properties_reserved_disk"
    kind_display: ClassVar[str] = "GCP Specific SKU Allocation Allocated Instance Properties Reserved Disk"
    kind_description: ClassVar[str] = (
        "This resource refers to the reserved disk attached to a specific SKU"
        " allocation in Google Cloud Platform. Reserved disks are persistent storage"
        " devices used by virtual machine instances."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"disk_size_gb": S("diskSizeGb") >> AsInt(), "interface": S("interface")}
    disk_size_gb: Optional[int] = field(default=None)
    interface: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpAllocationSpecificSKUAllocationReservedInstanceProperties:
    kind: ClassVar[str] = "gcp_allocation_specific_sku_allocation_reserved_instance_properties"
    kind_display: ClassVar[str] = "GCP Allocation Specific SKU Allocation Reserved Instance Properties"
    kind_description: ClassVar[str] = (
        "Reserved Instance Properties allow users to allocate specific SKUs for"
        " reserved instances in Google Cloud Platform, optimizing usage and cost"
        " management."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "guest_accelerators": S("guestAccelerators", default=[]) >> ForallBend(GcpAcceleratorConfig.mapping),
        "local_ssds": S("localSsds", default=[])
        >> ForallBend(GcpAllocationSpecificSKUAllocationAllocatedInstancePropertiesReservedDisk.mapping),
        "location_hint": S("locationHint"),
        "machine_type": S("machineType"),
        "min_cpu_platform": S("minCpuPlatform"),
    }
    guest_accelerators: Optional[List[GcpAcceleratorConfig]] = field(default=None)
    local_ssds: Optional[List[GcpAllocationSpecificSKUAllocationAllocatedInstancePropertiesReservedDisk]] = field(
        default=None
    )
    location_hint: Optional[str] = field(default=None)
    machine_type: Optional[str] = field(default=None)
    min_cpu_platform: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpAllocationSpecificSKUReservation:
    kind: ClassVar[str] = "gcp_allocation_specific_sku_reservation"
    kind_display: ClassVar[str] = "GCP Allocation Specific SKU Reservation"
    kind_description: ClassVar[str] = (
        "A reservation for a specified SKU in Google Cloud Platform, allowing users"
        " to allocate and secure resources for future use."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "assured_count": S("assuredCount"),
        "count": S("count"),
        "in_use_count": S("inUseCount"),
        "instance_properties": S("instanceProperties", default={})
        >> Bend(GcpAllocationSpecificSKUAllocationReservedInstanceProperties.mapping),
    }
    assured_count: Optional[str] = field(default=None)
    count: Optional[str] = field(default=None)
    in_use_count: Optional[str] = field(default=None)
    instance_properties: Optional[GcpAllocationSpecificSKUAllocationReservedInstanceProperties] = field(default=None)


@define(eq=False, slots=False)
class GcpReservation:
    kind: ClassVar[str] = "gcp_reservation"
    kind_display: ClassVar[str] = "GCP Reservation"
    kind_description: ClassVar[str] = (
        "GCP Reservation is a feature in Google Cloud Platform that allows users to"
        " reserve resources like virtual machine instances for future use, ensuring"
        " availability and cost savings."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "commitment": S("commitment"),
        "creation_timestamp": S("creationTimestamp"),
        "description": S("description"),
        "id": S("id"),
        "name": S("name"),
        "satisfies_pzs": S("satisfiesPzs"),
        "self_link": S("selfLink"),
        "share_settings": S("shareSettings", default={}) >> Bend(GcpShareSettings.mapping),
        "specific_reservation": S("specificReservation", default={})
        >> Bend(GcpAllocationSpecificSKUReservation.mapping),
        "specific_reservation_required": S("specificReservationRequired"),
        "status": S("status"),
        "zone": S("zone"),
    }
    commitment: Optional[str] = field(default=None)
    creation_timestamp: Optional[datetime] = field(default=None)
    description: Optional[str] = field(default=None)
    id: Optional[str] = field(default=None)
    name: Optional[str] = field(default=None)
    satisfies_pzs: Optional[bool] = field(default=None)
    self_link: Optional[str] = field(default=None)
    share_settings: Optional[GcpShareSettings] = field(default=None)
    specific_reservation: Optional[GcpAllocationSpecificSKUReservation] = field(default=None)
    specific_reservation_required: Optional[bool] = field(default=None)
    status: Optional[str] = field(default=None)
    zone: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpResourceCommitment:
    kind: ClassVar[str] = "gcp_resource_commitment"
    kind_display: ClassVar[str] = "GCP Resource Commitment"
    kind_description: ClassVar[str] = (
        "GCP Resource Commitment is a way to reserve resources in Google Cloud"
        " Platform for a specific period, ensuring availability and capacity for your"
        " applications."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "accelerator_type": S("acceleratorType"),
        "amount": S("amount"),
        "type": S("type"),
    }
    accelerator_type: Optional[str] = field(default=None)
    amount: Optional[str] = field(default=None)
    type: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpCommitment(GcpResource):
    kind: ClassVar[str] = "gcp_commitment"
    kind_display: ClassVar[str] = "GCP Commitment"
    kind_description: ClassVar[str] = (
        "A GCP Commitment is a pre-purchased commitment in Google Cloud Platform,"
        " which provides discounted pricing for certain services and resources."
    )
    api_spec: ClassVar[GcpApiSpec] = GcpApiSpec(
        service="compute",
        version="v1",
        accessors=["regionCommitments"],
        action="aggregatedList",
        request_parameter={"project": "{project}"},
        request_parameter_in={"project"},
        response_path="items",
        response_regional_sub_path="commitments",
        required_iam_permissions=["compute.commitments.list"],
        mutate_iam_permissions=["compute.commitments.update"],
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
        "auto_renew": S("autoRenew"),
        "commitment_category": S("category"),
        "end_timestamp": S("endTimestamp"),
        "license_resource": S("licenseResource", default={}) >> Bend(GcpLicenseResourceCommitment.mapping),
        "merge_source_commitments": S("mergeSourceCommitments", default=[]),
        "plan": S("plan"),
        "reservations": S("reservations", default=[]) >> ForallBend(GcpReservation.mapping),
        "resources": S("resources", default=[]) >> ForallBend(GcpResourceCommitment.mapping),
        "split_source_commitment": S("splitSourceCommitment"),
        "start_timestamp": S("startTimestamp"),
        "status": S("status"),
        "status_message": S("statusMessage"),
        "type": S("type"),
    }
    auto_renew: Optional[bool] = field(default=None)
    commitment_category: Optional[str] = field(default=None)
    end_timestamp: Optional[datetime] = field(default=None)
    license_resource: Optional[GcpLicenseResourceCommitment] = field(default=None)
    merge_source_commitments: Optional[List[str]] = field(default=None)
    plan: Optional[str] = field(default=None)
    reservations: Optional[List[GcpReservation]] = field(default=None)
    resources: Optional[List[GcpResourceCommitment]] = field(default=None)
    split_source_commitment: Optional[str] = field(default=None)
    start_timestamp: Optional[datetime] = field(default=None)
    status: Optional[str] = field(default=None)
    status_message: Optional[str] = field(default=None)
    type: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpHealthCheckService(GcpResource):
    kind: ClassVar[str] = "gcp_health_check_service"
    kind_display: ClassVar[str] = "GCP Health Check Service"
    kind_description: ClassVar[str] = (
        "The GCP Health Check Service is a feature provided by Google Cloud Platform"
        " (GCP) that monitors the health and availability of backend services and"
        " instances."
    )
    api_spec: ClassVar[GcpApiSpec] = GcpApiSpec(
        service="compute",
        version="v1",
        accessors=["regionHealthCheckServices"],
        action="list",
        request_parameter={"project": "{project}", "region": "{region}"},
        request_parameter_in={"project", "region"},
        response_path="items",
        response_regional_sub_path=None,
        mutate_iam_permissions=["compute.regionHealthCheckServices.update", "compute.regionHealthCheckServices.delete"],
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
        "fingerprint": S("fingerprint"),
        "health_checks": S("healthChecks", default=[]),
        "health_status_aggregation_policy": S("healthStatusAggregationPolicy"),
        "network_endpoint_groups": S("networkEndpointGroups", default=[]),
        "notification_endpoints": S("notificationEndpoints", default=[]),
    }
    fingerprint: Optional[str] = field(default=None)
    health_checks: Optional[List[str]] = field(default=None)
    health_status_aggregation_policy: Optional[str] = field(default=None)
    network_endpoint_groups: Optional[List[str]] = field(default=None)
    notification_endpoints: Optional[List[str]] = field(default=None)


@define(eq=False, slots=False)
class GcpNotificationEndpointGrpcSettings:
    kind: ClassVar[str] = "gcp_notification_endpoint_grpc_settings"
    kind_display: ClassVar[str] = "GCP Notification Endpoint gRPC Settings"
    kind_description: ClassVar[str] = (
        "gRPC settings for a notification endpoint in Google Cloud Platform (GCP)."
        " gRPC is a high-performance, open-source remote procedure call (RPC)"
        " framework that can be used to build efficient and scalable communication"
        " between client and server applications."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "authority": S("authority"),
        "endpoint": S("endpoint"),
        "payload_name": S("payloadName"),
        "resend_interval": S("resendInterval", default={}) >> Bend(GcpDuration.mapping),
        "retry_duration_sec": S("retryDurationSec"),
    }
    authority: Optional[str] = field(default=None)
    endpoint: Optional[str] = field(default=None)
    payload_name: Optional[str] = field(default=None)
    resend_interval: Optional[GcpDuration] = field(default=None)
    retry_duration_sec: Optional[int] = field(default=None)


@define(eq=False, slots=False)
class GcpNotificationEndpoint(GcpResource):
    kind: ClassVar[str] = "gcp_notification_endpoint"
    kind_display: ClassVar[str] = "GCP Notification Endpoint"
    kind_description: ClassVar[str] = (
        "A GCP Notification Endpoint is a specific destination to send notifications"
        " from Google Cloud Platform services to, such as Pub/Sub or HTTP endpoints."
    )
    api_spec: ClassVar[GcpApiSpec] = GcpApiSpec(
        service="compute",
        version="v1",
        accessors=["regionNotificationEndpoints"],
        action="list",
        request_parameter={"project": "{project}", "region": "{region}"},
        request_parameter_in={"project", "region"},
        response_path="items",
        response_regional_sub_path=None,
        mutate_iam_permissions=[
            "compute.regionNotificationEndpoints.update",
            "compute.regionNotificationEndpoints.delete",
        ],
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
        "grpc_settings": S("grpcSettings", default={}) >> Bend(GcpNotificationEndpointGrpcSettings.mapping),
    }
    grpc_settings: Optional[GcpNotificationEndpointGrpcSettings] = field(default=None)


@define(eq=False, slots=False)
class GcpSecurityPolicyAdaptiveProtectionConfigLayer7DdosDefenseConfig:
    kind: ClassVar[str] = "gcp_security_policy_adaptive_protection_config_layer7_ddos_defense_config"
    kind_display: ClassVar[str] = "GCP Security Policy Adaptive Protection Config Layer 7 DDoS Defense Config"
    kind_description: ClassVar[str] = (
        "The Layer 7 DDoS Defense Config in a GCP Security Policy Adaptive Protection Config refers to the options"
        " that control the activation and transparency of rules designed to mitigate Distributed Denial of Service"
        " (DDoS) attacks at the application layer."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"enable": S("enable"), "rule_visibility": S("ruleVisibility")}
    enable: Optional[bool] = field(default=None)
    rule_visibility: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpSecurityPolicyAdaptiveProtectionConfig:
    kind: ClassVar[str] = "gcp_security_policy_adaptive_protection_config"
    kind_display: ClassVar[str] = "GCP Security Policy Adaptive Protection Config"
    kind_description: ClassVar[str] = (
        "GCP Security Policy Adaptive Protection Config within a GCP Security Policy pertains to the configuration"
        " settings that govern the adaptive security mechanisms against Layer 7 DDoS attacks."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "layer7_ddos_defense_config": S("layer7DdosDefenseConfig", default={})
        >> Bend(GcpSecurityPolicyAdaptiveProtectionConfigLayer7DdosDefenseConfig.mapping)
    }
    layer7_ddos_defense_config: Optional[GcpSecurityPolicyAdaptiveProtectionConfigLayer7DdosDefenseConfig] = field(
        default=None
    )


@define(eq=False, slots=False)
class GcpSecurityPolicyAdvancedOptionsConfigJsonCustomConfig:
    kind: ClassVar[str] = "gcp_security_policy_advanced_options_config_json_custom_config"
    kind_display: ClassVar[str] = "GCP Security Policy Advanced Options Config JSON Custom Config"
    kind_description: ClassVar[str] = (
        "This resource allows users to configure advanced options for security"
        " policies in Google Cloud Platform (GCP) using custom config in JSON format."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"content_types": S("contentTypes", default=[])}
    content_types: Optional[List[str]] = field(default=None)


@define(eq=False, slots=False)
class GcpSecurityPolicyAdvancedOptionsConfig:
    kind: ClassVar[str] = "gcp_security_policy_advanced_options_config"
    kind_display: ClassVar[str] = "GCP Security Policy Advanced Options Config"
    kind_description: ClassVar[str] = (
        "This is a configuration for advanced options in a Google Cloud Platform"
        " (GCP) Security Policy. It allows for fine-grained control and customization"
        " of the security policies for different resources in the GCP environment."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "json_custom_config": S("jsonCustomConfig", default={})
        >> Bend(GcpSecurityPolicyAdvancedOptionsConfigJsonCustomConfig.mapping),
        "json_parsing": S("jsonParsing"),
        "log_level": S("logLevel"),
    }
    json_custom_config: Optional[GcpSecurityPolicyAdvancedOptionsConfigJsonCustomConfig] = field(default=None)
    json_parsing: Optional[str] = field(default=None)
    log_level: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpSecurityPolicyRuleHttpHeaderActionHttpHeaderOption:
    kind: ClassVar[str] = "gcp_security_policy_rule_http_header_action_http_header_option"
    kind_display: ClassVar[str] = "GCP Security Policy Rule HTTP Header Action HTTP Header Option"
    kind_description: ClassVar[str] = (
        "GCP Security Policy Rule HTTP Header Option allows for the specification of custom header names and"
        " values that can be added to requests matched by security policy rules."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"header_name": S("headerName"), "header_value": S("headerValue")}
    header_name: Optional[str] = field(default=None)
    header_value: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpSecurityPolicyRuleHttpHeaderAction:
    kind: ClassVar[str] = "gcp_security_policy_rule_http_header_action"
    kind_display: ClassVar[str] = "GCP Security Policy Rule HTTP Header Action"
    kind_description: ClassVar[str] = (
        "The HTTP Header Action within a GCP Security Policy Rule specifies headers that are added to requests"
        " as they are forwarded to a backend service."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "request_headers_to_adds": S("requestHeadersToAdds", default=[])
        >> ForallBend(GcpSecurityPolicyRuleHttpHeaderActionHttpHeaderOption.mapping)
    }
    request_headers_to_adds: Optional[List[GcpSecurityPolicyRuleHttpHeaderActionHttpHeaderOption]] = field(default=None)


@define(eq=False, slots=False)
class GcpSecurityPolicyRuleMatcherConfig:
    kind: ClassVar[str] = "gcp_security_policy_rule_matcher_config"
    kind_display: ClassVar[str] = "GCP Security Policy Rule Matcher Config"
    kind_description: ClassVar[str] = (
        "GCP Security Policy Rule Matcher Config represents the configuration"
        " settings used to specify the matching criteria for security policy rules in"
        " Google Cloud Platform."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"src_ip_ranges": S("srcIpRanges", default=[])}
    src_ip_ranges: Optional[List[str]] = field(default=None)


@define(eq=False, slots=False)
class GcpExpr:
    kind: ClassVar[str] = "gcp_expr"
    kind_display: ClassVar[str] = "GCP Expr"
    kind_description: ClassVar[str] = (
        "GCP Expr refers to an expression in a GCP Security Policy Rule Matcher that defines conditions"
        " for enforcing security rules, with fields to specify its logic, location within the request,"
        " and additional metadata."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "description": S("description"),
        "expression": S("expression"),
        "location": S("location"),
        "title": S("title"),
    }
    description: Optional[str] = field(default=None)
    expression: Optional[str] = field(default=None)
    location: Optional[str] = field(default=None)
    title: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpSecurityPolicyRuleMatcher:
    kind: ClassVar[str] = "gcp_security_policy_rule_matcher"
    kind_display: ClassVar[str] = "GCP Security Policy Rule Matcher"
    kind_description: ClassVar[str] = (
        "A rule matcher in the Google Cloud Platform (GCP) Security Policy that"
        " defines the conditions for matching traffic and applying relevant security"
        " policy rules."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "config": S("config", default={}) >> Bend(GcpSecurityPolicyRuleMatcherConfig.mapping),
        "expr": S("expr", default={}) >> Bend(GcpExpr.mapping),
        "versioned_expr": S("versionedExpr"),
    }
    config: Optional[GcpSecurityPolicyRuleMatcherConfig] = field(default=None)
    expr: Optional[GcpExpr] = field(default=None)
    versioned_expr: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpSecurityPolicyRuleRateLimitOptionsThreshold:
    kind: ClassVar[str] = "gcp_security_policy_rule_rate_limit_options_threshold"
    kind_display: ClassVar[str] = "GCP Security Policy Rate Limit Options Threshold"
    kind_description: ClassVar[str] = (
        "GCP Security Policy Rate Limit Options Threshold is a set of parameters that specify the number of requests"
        " (count) allowed over a defined interval in seconds (interval_sec) before triggering rate limiting actions"
        " under a security policy."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"count": S("count"), "interval_sec": S("intervalSec")}
    count: Optional[int] = field(default=None)
    interval_sec: Optional[int] = field(default=None)


@define(eq=False, slots=False)
class GcpSecurityPolicyRuleRedirectOptions:
    kind: ClassVar[str] = "gcp_security_policy_rule_redirect_options"
    kind_display: ClassVar[str] = "GCP Security Policy Rule Redirect Options"
    kind_description: ClassVar[str] = (
        "The GCP Security Policy Rule Redirect Options specify how traffic should be redirected; it defines the target"
        " to which the traffic should be sent and the type of redirect that should be applied."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"target": S("target"), "type": S("type")}
    target: Optional[str] = field(default=None)
    type: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpSecurityPolicyRuleRateLimitOptions:
    kind: ClassVar[str] = "gcp_security_policy_rule_rate_limit_options"
    kind_display: ClassVar[str] = "GCP Security Policy Rule Rate Limit Options"
    kind_description: ClassVar[str] = (
        "GCP Security Policy Rule Rate Limit Options define the parameters for rate limiting requests that match"
        " specific conditions in a security policy, including actions to take when thresholds are exceeded and"
        " settings for banning offenders for a specified duration."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "ban_duration_sec": S("banDurationSec"),
        "ban_threshold": S("banThreshold", default={}) >> Bend(GcpSecurityPolicyRuleRateLimitOptionsThreshold.mapping),
        "conform_action": S("conformAction"),
        "enforce_on_key": S("enforceOnKey"),
        "enforce_on_key_name": S("enforceOnKeyName"),
        "exceed_action": S("exceedAction"),
        "exceed_redirect_options": S("exceedRedirectOptions", default={})
        >> Bend(GcpSecurityPolicyRuleRedirectOptions.mapping),
        "rate_limit_threshold": S("rateLimitThreshold", default={})
        >> Bend(GcpSecurityPolicyRuleRateLimitOptionsThreshold.mapping),
    }
    ban_duration_sec: Optional[int] = field(default=None)
    ban_threshold: Optional[GcpSecurityPolicyRuleRateLimitOptionsThreshold] = field(default=None)
    conform_action: Optional[str] = field(default=None)
    enforce_on_key: Optional[str] = field(default=None)
    enforce_on_key_name: Optional[str] = field(default=None)
    exceed_action: Optional[str] = field(default=None)
    exceed_redirect_options: Optional[GcpSecurityPolicyRuleRedirectOptions] = field(default=None)
    rate_limit_threshold: Optional[GcpSecurityPolicyRuleRateLimitOptionsThreshold] = field(default=None)


@define(eq=False, slots=False)
class GcpSecurityPolicyRule:
    kind: ClassVar[str] = "gcp_security_policy_rule"
    kind_display: ClassVar[str] = "GCP Security Policy Rule"
    kind_description: ClassVar[str] = (
        "A GCP Security Policy Rule defines the allowed or denied traffic for a"
        " particular network resource in Google Cloud Platform."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "action": S("action"),
        "description": S("description"),
        "header_action": S("headerAction", default={}) >> Bend(GcpSecurityPolicyRuleHttpHeaderAction.mapping),
        "match": S("match", default={}) >> Bend(GcpSecurityPolicyRuleMatcher.mapping),
        "preview": S("preview"),
        "priority": S("priority"),
        "rate_limit_options": S("rateLimitOptions", default={}) >> Bend(GcpSecurityPolicyRuleRateLimitOptions.mapping),
        "redirect_options": S("redirectOptions", default={}) >> Bend(GcpSecurityPolicyRuleRedirectOptions.mapping),
    }
    action: Optional[str] = field(default=None)
    description: Optional[str] = field(default=None)
    header_action: Optional[GcpSecurityPolicyRuleHttpHeaderAction] = field(default=None)
    match: Optional[GcpSecurityPolicyRuleMatcher] = field(default=None)
    preview: Optional[bool] = field(default=None)
    priority: Optional[int] = field(default=None)
    rate_limit_options: Optional[GcpSecurityPolicyRuleRateLimitOptions] = field(default=None)
    redirect_options: Optional[GcpSecurityPolicyRuleRedirectOptions] = field(default=None)


@define(eq=False, slots=False)
class GcpSecurityPolicy(GcpResource):
    kind: ClassVar[str] = "gcp_security_policy"
    kind_display: ClassVar[str] = "GCP Security Policy"
    kind_description: ClassVar[str] = (
        "GCP Security Policy is a feature of Google Cloud Platform that allows users"
        " to define and enforce security rules and policies for their virtual machine"
        " instances."
    )
    api_spec: ClassVar[GcpApiSpec] = GcpApiSpec(
        service="compute",
        version="v1",
        accessors=["securityPolicies"],
        action="aggregatedList",
        request_parameter={"project": "{project}"},
        request_parameter_in={"project"},
        response_path="items",
        response_regional_sub_path="securityPolicies",
        mutate_iam_permissions=["compute.securityPolicies.setLabels"],
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
        "adaptive_protection_config": S("adaptiveProtectionConfig", default={})
        >> Bend(GcpSecurityPolicyAdaptiveProtectionConfig.mapping),
        "advanced_options_config": S("advancedOptionsConfig", default={})
        >> Bend(GcpSecurityPolicyAdvancedOptionsConfig.mapping),
        "ddos_protection_config": S("ddosProtectionConfig", "ddosProtection"),
        "fingerprint": S("fingerprint"),
        "recaptcha_options_config": S("recaptchaOptionsConfig", "redirectSiteKey"),
        "security_policy_rules": S("rules", default=[]) >> ForallBend(GcpSecurityPolicyRule.mapping),
        "type": S("type"),
    }
    adaptive_protection_config: Optional[GcpSecurityPolicyAdaptiveProtectionConfig] = field(default=None)
    advanced_options_config: Optional[GcpSecurityPolicyAdvancedOptionsConfig] = field(default=None)
    ddos_protection_config: Optional[str] = field(default=None)
    fingerprint: Optional[str] = field(default=None)
    recaptcha_options_config: Optional[str] = field(default=None)
    security_policy_rules: Optional[List[GcpSecurityPolicyRule]] = field(default=None)
    type: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpSslCertificateManagedSslCertificate:
    kind: ClassVar[str] = "gcp_ssl_certificate_managed_ssl_certificate"
    kind_display: ClassVar[str] = "GCP SSL Certificate (Managed SSL Certificate)"
    kind_description: ClassVar[str] = (
        "Managed SSL Certificates in Google Cloud Platform provide secure HTTPS"
        " connections for websites and applications, safeguarding data transmitted"
        " over the internet."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "domain_status": S("domainStatus"),
        "domains": S("domains", default=[]),
        "status": S("status"),
    }
    domain_status: Optional[Dict[str, str]] = field(default=None)
    domains: Optional[List[str]] = field(default=None)
    status: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpSslCertificateSelfManagedSslCertificate:
    kind: ClassVar[str] = "gcp_ssl_certificate_self_managed_ssl_certificate"
    kind_display: ClassVar[str] = "GCP Self-Managed SSL Certificate"
    kind_description: ClassVar[str] = (
        "A self-managed SSL certificate is a digital certificate issued by an"
        " organization for its own use, allowing secure communication between a client"
        " and a server. GCP allows users to manage their own SSL certificates."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"certificate": S("certificate"), "private_key": S("privateKey")}
    certificate: Optional[str] = field(default=None)
    private_key: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpSslCertificate(GcpResource):
    kind: ClassVar[str] = "gcp_ssl_certificate"
    kind_display: ClassVar[str] = "GCP SSL Certificate"
    kind_description: ClassVar[str] = (
        "SSL Certificate is a digital certificate that authenticates the identity of"
        " a website and encrypts information sent to the server, ensuring secure"
        " communication over the Google Cloud Platform."
    )
    api_spec: ClassVar[GcpApiSpec] = GcpApiSpec(
        service="compute",
        version="v1",
        accessors=["sslCertificates"],
        action="aggregatedList",
        request_parameter={"project": "{project}"},
        request_parameter_in={"project"},
        response_path="items",
        response_regional_sub_path="sslCertificates",
        mutate_iam_permissions=["compute.sslCertificates.delete"],
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
        "certificate": S("certificate"),
        "expire_time": S("expireTime"),
        "certificate_managed": S("managed", default={}) >> Bend(GcpSslCertificateManagedSslCertificate.mapping),
        "private_key": S("privateKey"),
        "self_managed": S("selfManaged", default={}) >> Bend(GcpSslCertificateSelfManagedSslCertificate.mapping),
        "subject_alternative_names": S("subjectAlternativeNames", default=[]),
        "type": S("type"),
    }
    certificate: Optional[str] = field(default=None)
    expire_time: Optional[datetime] = field(default=None)
    certificate_managed: Optional[GcpSslCertificateManagedSslCertificate] = field(default=None)
    private_key: Optional[str] = field(default=None)
    self_managed: Optional[GcpSslCertificateSelfManagedSslCertificate] = field(default=None)
    subject_alternative_names: Optional[List[str]] = field(default=None)
    type: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpSslPolicy(GcpResource):
    kind: ClassVar[str] = "gcp_ssl_policy"
    kind_display: ClassVar[str] = "GCP SSL Policy"
    kind_description: ClassVar[str] = (
        "SSL policies in Google Cloud Platform (GCP) manage how SSL/TLS connections"
        " are established and maintained for HTTPS services."
    )
    api_spec: ClassVar[GcpApiSpec] = GcpApiSpec(
        service="compute",
        version="v1",
        accessors=["sslPolicies"],
        action="aggregatedList",
        request_parameter={"project": "{project}"},
        request_parameter_in={"project"},
        response_path="items",
        response_regional_sub_path="sslPolicies",
        mutate_iam_permissions=["compute.sslPolicies.delete"],
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
        "custom_features": S("customFeatures", default=[]),
        "enabled_features": S("enabledFeatures", default=[]),
        "fingerprint": S("fingerprint"),
        "min_tls_version": S("minTlsVersion"),
        "profile": S("profile"),
        "warnings": S("warnings", default=[]) >> ForallBend(GcpWarnings.mapping),
    }
    custom_features: Optional[List[str]] = field(default=None)
    enabled_features: Optional[List[str]] = field(default=None)
    fingerprint: Optional[str] = field(default=None)
    min_tls_version: Optional[str] = field(default=None)
    profile: Optional[str] = field(default=None)
    warnings: Optional[List[GcpWarnings]] = field(default=None)


@define(eq=False, slots=False)
class GcpTargetHttpProxy(GcpResource):
    kind: ClassVar[str] = "gcp_target_http_proxy"
    kind_display: ClassVar[str] = "GCP Target HTTP Proxy"
    kind_description: ClassVar[str] = (
        "GCP Target HTTP Proxy is a resource in Google Cloud Platform that allows for"
        " load balancing and routing of HTTP traffic to backend services."
    )
    reference_kinds: ClassVar[ModelReference] = {
        "predecessors": {"delete": ["gcp_url_map"]},
        "successors": {"default": ["gcp_url_map"]},
    }
    api_spec: ClassVar[GcpApiSpec] = GcpApiSpec(
        service="compute",
        version="v1",
        accessors=["targetHttpProxies"],
        action="aggregatedList",
        request_parameter={"project": "{project}"},
        request_parameter_in={"project"},
        response_path="items",
        response_regional_sub_path="targetHttpProxies",
        mutate_iam_permissions=["compute.targetHttpProxies.delete", "compute.targetHttpProxies.update"],
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
        "fingerprint": S("fingerprint"),
        "proxy_bind": S("proxyBind"),
        "url_map": S("urlMap"),
    }
    fingerprint: Optional[str] = field(default=None)
    proxy_bind: Optional[bool] = field(default=None)
    url_map: Optional[str] = field(default=None)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if self.url_map:
            builder.dependant_node(self, clazz=GcpUrlMap, link=self.url_map)


@define(eq=False, slots=False)
class GcpTargetHttpsProxy(GcpResource):
    kind: ClassVar[str] = "gcp_target_https_proxy"
    kind_display: ClassVar[str] = "GCP Target HTTPS Proxy"
    kind_description: ClassVar[str] = (
        "A GCP Target HTTPS Proxy is a Google Cloud Platform resource that enables"
        " you to configure SSL/TLS termination for HTTP(S) load balancing, allowing"
        " secure communication between clients and your backend services."
    )
    reference_kinds: ClassVar[ModelReference] = {
        "predecessors": {"default": ["gcp_ssl_certificate", "gcp_ssl_policy"], "delete": ["gcp_url_map"]},
        "successors": {"default": ["gcp_url_map"]},
    }
    api_spec: ClassVar[GcpApiSpec] = GcpApiSpec(
        service="compute",
        version="v1",
        accessors=["targetHttpsProxies"],
        action="aggregatedList",
        request_parameter={"project": "{project}"},
        request_parameter_in={"project"},
        response_path="items",
        response_regional_sub_path="targetHttpsProxies",
        mutate_iam_permissions=["compute.targetHttpsProxies.delete", "compute.targetHttpsProxies.update"],
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
        "authorization_policy": S("authorizationPolicy"),
        "certificate_map": S("certificateMap"),
        "fingerprint": S("fingerprint"),
        "proxy_bind": S("proxyBind"),
        "quic_override": S("quicOverride"),
        "server_tls_policy": S("serverTlsPolicy"),
        "ssl_certificates": S("sslCertificates", default=[]),
        "ssl_policy": S("sslPolicy"),
        "url_map": S("urlMap"),
    }
    authorization_policy: Optional[str] = field(default=None)
    certificate_map: Optional[str] = field(default=None)
    fingerprint: Optional[str] = field(default=None)
    proxy_bind: Optional[bool] = field(default=None)
    quic_override: Optional[str] = field(default=None)
    server_tls_policy: Optional[str] = field(default=None)
    ssl_certificates: Optional[List[str]] = field(default=None)
    ssl_policy: Optional[str] = field(default=None)
    url_map: Optional[str] = field(default=None)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if self.ssl_certificates:
            for cert in self.ssl_certificates:
                builder.add_edge(self, reverse=True, clazz=GcpSslCertificate, link=cert)
        if self.ssl_policy:
            builder.add_edge(self, reverse=True, clazz=GcpSslPolicy, link=self.ssl_policy)
        if self.url_map:
            builder.dependant_node(self, clazz=GcpUrlMap, link=self.url_map)


@define(eq=False, slots=False)
class GcpTargetTcpProxy(GcpResource):
    kind: ClassVar[str] = "gcp_target_tcp_proxy"
    kind_display: ClassVar[str] = "GCP Target TCP Proxy"
    kind_description: ClassVar[str] = (
        "Target TCP Proxy is a Google Cloud Platform service that allows you to load"
        " balance TCP traffic to backend instances based on target proxy"
        " configuration."
    )
    reference_kinds: ClassVar[ModelReference] = {
        "predecessors": {"delete": ["gcp_backend_service"]},
        "successors": {"default": ["gcp_backend_service"]},
    }
    api_spec: ClassVar[GcpApiSpec] = GcpApiSpec(
        service="compute",
        version="v1",
        accessors=["targetTcpProxies"],
        action="list",
        request_parameter={"project": "{project}"},
        request_parameter_in={"project"},
        response_path="items",
        response_regional_sub_path=None,
        mutate_iam_permissions=["compute.targetTcpProxies.delete", "compute.targetTcpProxies.update"],
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
        "proxy_bind": S("proxyBind"),
        "proxy_header": S("proxyHeader"),
        "service": S("service"),
    }
    proxy_bind: Optional[bool] = field(default=None)
    proxy_header: Optional[str] = field(default=None)
    service: Optional[str] = field(default=None)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if self.service:
            builder.dependant_node(self, clazz=GcpBackendService, link=self.service)


@define(eq=False, slots=False)
class GcpCorsPolicy:
    kind: ClassVar[str] = "gcp_cors_policy"
    kind_display: ClassVar[str] = "GCP CORS Policy"
    kind_description: ClassVar[str] = (
        "CORS (Cross-Origin Resource Sharing) Policy in Google Cloud Platform allows"
        " controlled sharing of resources between different origins, enabling web"
        " applications to make requests to resources from other domains."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "allow_credentials": S("allowCredentials"),
        "allow_headers": S("allowHeaders", default=[]),
        "allow_methods": S("allowMethods", default=[]),
        "allow_origin_regexes": S("allowOriginRegexes", default=[]),
        "allow_origins": S("allowOrigins", default=[]),
        "disabled": S("disabled"),
        "expose_headers": S("exposeHeaders", default=[]),
        "max_age": S("maxAge"),
    }
    allow_credentials: Optional[bool] = field(default=None)
    allow_headers: Optional[List[str]] = field(default=None)
    allow_methods: Optional[List[str]] = field(default=None)
    allow_origin_regexes: Optional[List[str]] = field(default=None)
    allow_origins: Optional[List[str]] = field(default=None)
    disabled: Optional[bool] = field(default=None)
    expose_headers: Optional[List[str]] = field(default=None)
    max_age: Optional[int] = field(default=None)


@define(eq=False, slots=False)
class GcpHttpFaultAbort:
    kind: ClassVar[str] = "gcp_http_fault_abort"
    kind_display: ClassVar[str] = "GCP HTTP Fault Abort"
    kind_description: ClassVar[str] = (
        "GCP HTTP Fault Abort allows you to specify an HTTP status code that the load balancer should return,"
        " simulating an abort condition for a set percentage of requests to test the client's handling of"
        " backend failures."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"http_status": S("httpStatus"), "percentage": S("percentage")}
    http_status: Optional[int] = field(default=None)
    percentage: Optional[float] = field(default=None)


@define(eq=False, slots=False)
class GcpHttpFaultDelay:
    kind: ClassVar[str] = "gcp_http_fault_delay"
    kind_display: ClassVar[str] = "GCP HTTP Fault Delay"
    kind_description: ClassVar[str] = (
        "GCP HTTP Fault Delay introduces a specified delay for a percentage of requests, testing the"
        " client's tolerance to increased latencies from the backend service."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "fixed_delay": S("fixedDelay", default={}) >> Bend(GcpDuration.mapping),
        "percentage": S("percentage"),
    }
    fixed_delay: Optional[GcpDuration] = field(default=None)
    percentage: Optional[float] = field(default=None)


@define(eq=False, slots=False)
class GcpHttpFaultInjection:
    kind: ClassVar[str] = "gcp_http_fault_injection"
    kind_display: ClassVar[str] = "GCP HTTP Fault Injection"
    kind_description: ClassVar[str] = (
        "GCP HTTP Fault Injection is a feature in Google Cloud Platform that allows"
        " injecting faults into HTTP requests to test the resilience of applications"
        " and services."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "abort": S("abort", default={}) >> Bend(GcpHttpFaultAbort.mapping),
        "delay": S("delay", default={}) >> Bend(GcpHttpFaultDelay.mapping),
    }
    abort: Optional[GcpHttpFaultAbort] = field(default=None)
    delay: Optional[GcpHttpFaultDelay] = field(default=None)


@define(eq=False, slots=False)
class GcpHttpRetryPolicy:
    kind: ClassVar[str] = "gcp_http_retry_policy"
    kind_display: ClassVar[str] = "GCP HTTP Retry Policy"
    kind_description: ClassVar[str] = (
        "GCP HTTP Retry Policy allows users to define and configure retry behavior"
        " for HTTP requests made to resources in the Google Cloud Platform"
        " infrastructure."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "num_retries": S("numRetries"),
        "per_try_timeout": S("perTryTimeout", default={}) >> Bend(GcpDuration.mapping),
        "retry_conditions": S("retryConditions", default=[]),
    }
    num_retries: Optional[int] = field(default=None)
    per_try_timeout: Optional[GcpDuration] = field(default=None)
    retry_conditions: Optional[List[str]] = field(default=None)


@define(eq=False, slots=False)
class GcpUrlRewrite:
    kind: ClassVar[str] = "gcp_url_rewrite"
    kind_display: ClassVar[str] = "GCP URL Rewrite"
    kind_description: ClassVar[str] = (
        "GCP URL Rewrite is a feature in Google Cloud Platform that allows users to"
        " modify and redirect incoming URLs based on predefined rules."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "host_rewrite": S("hostRewrite"),
        "path_prefix_rewrite": S("pathPrefixRewrite"),
    }
    host_rewrite: Optional[str] = field(default=None)
    path_prefix_rewrite: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpHttpHeaderOption:
    kind: ClassVar[str] = "gcp_http_header_option"
    kind_display: ClassVar[str] = "GCP HTTP Header Option"
    kind_description: ClassVar[str] = (
        "GCP HTTP Header Option allows the specification of custom HTTP header names and values, with an option"
        " to replace existing headers, to tailor how requests and responses are handled by services such"
        " as load balancers or routing rules."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "header_name": S("headerName"),
        "header_value": S("headerValue"),
        "replace": S("replace"),
    }
    header_name: Optional[str] = field(default=None)
    header_value: Optional[str] = field(default=None)
    replace: Optional[bool] = field(default=None)


@define(eq=False, slots=False)
class GcpHttpHeaderAction:
    kind: ClassVar[str] = "gcp_http_header_action"
    kind_display: ClassVar[str] = "GCP HTTP Header Action"
    kind_description: ClassVar[str] = (
        "The GCP HTTP Header Action feature enables you to add or remove specified HTTP headers from requests and"
        " responses as they route through load balancers, allowing for customized content delivery and client"
        " request handling."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "request_headers_to_add": S("requestHeadersToAdd", default=[]) >> ForallBend(GcpHttpHeaderOption.mapping),
        "request_headers_to_remove": S("requestHeadersToRemove", default=[]),
        "response_headers_to_add": S("responseHeadersToAdd", default=[]) >> ForallBend(GcpHttpHeaderOption.mapping),
        "response_headers_to_remove": S("responseHeadersToRemove", default=[]),
    }
    request_headers_to_add: Optional[List[GcpHttpHeaderOption]] = field(default=None)
    request_headers_to_remove: Optional[List[str]] = field(default=None)
    response_headers_to_add: Optional[List[GcpHttpHeaderOption]] = field(default=None)
    response_headers_to_remove: Optional[List[str]] = field(default=None)


@define(eq=False, slots=False)
class GcpWeightedBackendService:
    kind: ClassVar[str] = "gcp_weighted_backend_service"
    kind_display: ClassVar[str] = "GCP Weighted Backend Service"
    kind_description: ClassVar[str] = (
        "A GCP Weighted Backend Service is a load balancer that distributes traffic"
        " across multiple backend services using weights assigned to each service."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "backend_service": S("backendService"),
        "header_action": S("headerAction", default={}) >> Bend(GcpHttpHeaderAction.mapping),
        "weight": S("weight"),
    }
    backend_service: Optional[str] = field(default=None)
    header_action: Optional[GcpHttpHeaderAction] = field(default=None)
    weight: Optional[int] = field(default=None)


@define(eq=False, slots=False)
class GcpHttpRouteAction:
    kind: ClassVar[str] = "gcp_http_route_action"
    kind_display: ClassVar[str] = "GCP HTTP Route Action"
    kind_description: ClassVar[str] = (
        "HTTP Route Action is a feature in Google Cloud Platform that allows users to"
        " define the actions to be performed on HTTP requests (e.g., forwarding,"
        " redirecting) within a route."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "cors_policy": S("corsPolicy", default={}) >> Bend(GcpCorsPolicy.mapping),
        "fault_injection_policy": S("faultInjectionPolicy", default={}) >> Bend(GcpHttpFaultInjection.mapping),
        "max_stream_duration": S("maxStreamDuration", default={}) >> Bend(GcpDuration.mapping),
        "request_mirror_policy": S("requestMirrorPolicy", "backendService"),
        "retry_policy": S("retryPolicy", default={}) >> Bend(GcpHttpRetryPolicy.mapping),
        "timeout": S("timeout", default={}) >> Bend(GcpDuration.mapping),
        "url_rewrite": S("urlRewrite", default={}) >> Bend(GcpUrlRewrite.mapping),
        "weighted_backend_services": S("weightedBackendServices", default=[])
        >> ForallBend(GcpWeightedBackendService.mapping),
    }
    cors_policy: Optional[GcpCorsPolicy] = field(default=None)
    fault_injection_policy: Optional[GcpHttpFaultInjection] = field(default=None)
    max_stream_duration: Optional[GcpDuration] = field(default=None)
    request_mirror_policy: Optional[str] = field(default=None)
    retry_policy: Optional[GcpHttpRetryPolicy] = field(default=None)
    timeout: Optional[GcpDuration] = field(default=None)
    url_rewrite: Optional[GcpUrlRewrite] = field(default=None)
    weighted_backend_services: Optional[List[GcpWeightedBackendService]] = field(default=None)


@define(eq=False, slots=False)
class GcpHttpRedirectAction:
    kind: ClassVar[str] = "gcp_http_redirect_action"
    kind_display: ClassVar[str] = "GCP HTTP Redirect Action"
    kind_description: ClassVar[str] = (
        "HTTP Redirect Action is a resource in Google Cloud Platform (GCP) that"
        " allows you to redirect incoming HTTP requests to another URL."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "host_redirect": S("hostRedirect"),
        "https_redirect": S("httpsRedirect"),
        "path_redirect": S("pathRedirect"),
        "prefix_redirect": S("prefixRedirect"),
        "redirect_response_code": S("redirectResponseCode"),
        "strip_query": S("stripQuery"),
    }
    host_redirect: Optional[str] = field(default=None)
    https_redirect: Optional[bool] = field(default=None)
    path_redirect: Optional[str] = field(default=None)
    prefix_redirect: Optional[str] = field(default=None)
    redirect_response_code: Optional[str] = field(default=None)
    strip_query: Optional[bool] = field(default=None)


@define(eq=False, slots=False)
class GcpHostRule:
    kind: ClassVar[str] = "gcp_host_rule"
    kind_display: ClassVar[str] = "GCP Host Rule"
    kind_description: ClassVar[str] = (
        "A GCP Host Rule is a configuration that maps a hostname to a specific"
        " backend service in Google Cloud Platform, allowing for customized routing of"
        " incoming traffic based on the requested domain name."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "description": S("description"),
        "hosts": S("hosts", default=[]),
        "path_matcher": S("pathMatcher"),
    }
    description: Optional[str] = field(default=None)
    hosts: Optional[List[str]] = field(default=None)
    path_matcher: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpPathRule:
    kind: ClassVar[str] = "gcp_path_rule"
    kind_display: ClassVar[str] = "GCP Path Rule"
    kind_description: ClassVar[str] = (
        "GCP Path Rule is a routing rule defined in Google Cloud Platform (GCP) to"
        " direct incoming traffic to specific destinations based on the URL path."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "paths": S("paths", default=[]),
        "route_action": S("routeAction", default={}) >> Bend(GcpHttpRouteAction.mapping),
        "service": S("service"),
        "url_redirect": S("urlRedirect", default={}) >> Bend(GcpHttpRedirectAction.mapping),
    }
    paths: Optional[List[str]] = field(default=None)
    route_action: Optional[GcpHttpRouteAction] = field(default=None)
    service: Optional[str] = field(default=None)
    url_redirect: Optional[GcpHttpRedirectAction] = field(default=None)


@define(eq=False, slots=False)
class GcpInt64RangeMatch:
    kind: ClassVar[str] = "gcp_int64_range_match"
    kind_display: ClassVar[str] = "GCP Int64 Range Match"
    kind_description: ClassVar[str] = (
        "GCP Int64 Range Match allows for the comparison of integer values within HTTP headers against a defined"
        " start and end range."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"range_end": S("rangeEnd"), "range_start": S("rangeStart")}
    range_end: Optional[str] = field(default=None)
    range_start: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpHttpHeaderMatch:
    kind: ClassVar[str] = "gcp_http_header_match"
    kind_display: ClassVar[str] = "GCP HTTP Header Match"
    kind_description: ClassVar[str] = (
        "GCP HTTP Header Match is a feature in Google Cloud Platform that allows"
        " users to match HTTP headers in order to control traffic routing, load"
        " balancing, and other network operations."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "exact_match": S("exactMatch"),
        "header_name": S("headerName"),
        "invert_match": S("invertMatch"),
        "prefix_match": S("prefixMatch"),
        "present_match": S("presentMatch"),
        "range_match": S("rangeMatch", default={}) >> Bend(GcpInt64RangeMatch.mapping),
        "regex_match": S("regexMatch"),
        "suffix_match": S("suffixMatch"),
    }
    exact_match: Optional[str] = field(default=None)
    header_name: Optional[str] = field(default=None)
    invert_match: Optional[bool] = field(default=None)
    prefix_match: Optional[str] = field(default=None)
    present_match: Optional[bool] = field(default=None)
    range_match: Optional[GcpInt64RangeMatch] = field(default=None)
    regex_match: Optional[str] = field(default=None)
    suffix_match: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpHttpQueryParameterMatch:
    kind: ClassVar[str] = "gcp_http_query_parameter_match"
    kind_display: ClassVar[str] = "GCP HTTP Query Parameter Match"
    kind_description: ClassVar[str] = (
        "GCP HTTP Query Parameter Match defines criteria for matching HTTP query parameters in requests"
        " against specified patterns or conditions to determine if an HTTP Route Rule should apply."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "exact_match": S("exactMatch"),
        "name": S("name"),
        "present_match": S("presentMatch"),
        "regex_match": S("regexMatch"),
    }
    exact_match: Optional[str] = field(default=None)
    name: Optional[str] = field(default=None)
    present_match: Optional[bool] = field(default=None)
    regex_match: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpHttpRouteRuleMatch:
    kind: ClassVar[str] = "gcp_http_route_rule_match"
    kind_display: ClassVar[str] = "GCP HTTP Route Rule Match"
    kind_description: ClassVar[str] = (
        "HTTP Route Rule Match is a feature in Google Cloud Platform (GCP) that"
        " allows fine-grained control and management of HTTP traffic routing within"
        " GCP infrastructure."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "full_path_match": S("fullPathMatch"),
        "header_matches": S("headerMatches", default=[]) >> ForallBend(GcpHttpHeaderMatch.mapping),
        "ignore_case": S("ignoreCase"),
        "metadata_filters": S("metadataFilters", default=[]) >> ForallBend(GcpMetadataFilter.mapping),
        "prefix_match": S("prefixMatch"),
        "query_parameter_matches": S("queryParameterMatches", default=[])
        >> ForallBend(GcpHttpQueryParameterMatch.mapping),
        "regex_match": S("regexMatch"),
    }
    full_path_match: Optional[str] = field(default=None)
    header_matches: Optional[List[GcpHttpHeaderMatch]] = field(default=None)
    ignore_case: Optional[bool] = field(default=None)
    metadata_filters: Optional[List[GcpMetadataFilter]] = field(default=None)
    prefix_match: Optional[str] = field(default=None)
    query_parameter_matches: Optional[List[GcpHttpQueryParameterMatch]] = field(default=None)
    regex_match: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpHttpRouteRule:
    kind: ClassVar[str] = "gcp_http_route_rule"
    kind_display: ClassVar[str] = "GCP HTTP Route Rule"
    kind_description: ClassVar[str] = (
        "HTTP Route Rule is a configuration in Google Cloud Platform (GCP) that"
        " defines how incoming HTTP requests should be routed to different backend"
        " services or resources based on matching conditions."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "description": S("description"),
        "header_action": S("headerAction", default={}) >> Bend(GcpHttpHeaderAction.mapping),
        "match_rules": S("matchRules", default=[]) >> ForallBend(GcpHttpRouteRuleMatch.mapping),
        "priority": S("priority"),
        "route_action": S("routeAction", default={}) >> Bend(GcpHttpRouteAction.mapping),
        "service": S("service"),
        "url_redirect": S("urlRedirect", default={}) >> Bend(GcpHttpRedirectAction.mapping),
    }
    description: Optional[str] = field(default=None)
    header_action: Optional[GcpHttpHeaderAction] = field(default=None)
    match_rules: Optional[List[GcpHttpRouteRuleMatch]] = field(default=None)
    priority: Optional[int] = field(default=None)
    route_action: Optional[GcpHttpRouteAction] = field(default=None)
    service: Optional[str] = field(default=None)
    url_redirect: Optional[GcpHttpRedirectAction] = field(default=None)


@define(eq=False, slots=False)
class GcpPathMatcher:
    kind: ClassVar[str] = "gcp_path_matcher"
    kind_display: ClassVar[str] = "GCP Path Matcher"
    kind_description: ClassVar[str] = (
        "A GCP Path Matcher is used for defining the path patterns that a request URL"
        " must match in order to be routed to a specific backend service."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "default_route_action": S("defaultRouteAction", default={}) >> Bend(GcpHttpRouteAction.mapping),
        "default_service": S("defaultService"),
        "default_url_redirect": S("defaultUrlRedirect", default={}) >> Bend(GcpHttpRedirectAction.mapping),
        "description": S("description"),
        "header_action": S("headerAction", default={}) >> Bend(GcpHttpHeaderAction.mapping),
        "name": S("name"),
        "path_rules": S("pathRules", default=[]) >> ForallBend(GcpPathRule.mapping),
        "route_rules": S("routeRules", default=[]) >> ForallBend(GcpHttpRouteRule.mapping),
    }
    default_route_action: Optional[GcpHttpRouteAction] = field(default=None)
    default_service: Optional[str] = field(default=None)
    default_url_redirect: Optional[GcpHttpRedirectAction] = field(default=None)
    description: Optional[str] = field(default=None)
    header_action: Optional[GcpHttpHeaderAction] = field(default=None)
    name: Optional[str] = field(default=None)
    path_rules: Optional[List[GcpPathRule]] = field(default=None)
    route_rules: Optional[List[GcpHttpRouteRule]] = field(default=None)


@define(eq=False, slots=False)
class GcpUrlMapTestHeader:
    kind: ClassVar[str] = "gcp_url_map_test_header"
    kind_display: ClassVar[str] = "GCP URL Map Test Header"
    kind_description: ClassVar[str] = (
        "GCP URL Map Test Header is a configuration feature in Google Cloud Platform"
        " that allows users to test and validate different HTTP headers for load"
        " balancing purposes."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"name": S("name"), "value": S("value")}
    name: Optional[str] = field(default=None)
    value: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpUrlMapTest:
    kind: ClassVar[str] = "gcp_url_map_test"
    kind_display: ClassVar[str] = "GCP URL Map Test"
    kind_description: ClassVar[str] = (
        "GCP URL Map Test is a test configuration for mapping URLs to backend services in Google Cloud Platform."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "description": S("description"),
        "expected_output_url": S("expectedOutputUrl"),
        "expected_redirect_response_code": S("expectedRedirectResponseCode"),
        "headers": S("headers", default=[]) >> ForallBend(GcpUrlMapTestHeader.mapping),
        "host": S("host"),
        "path": S("path"),
        "service": S("service"),
    }
    description: Optional[str] = field(default=None)
    expected_output_url: Optional[str] = field(default=None)
    expected_redirect_response_code: Optional[int] = field(default=None)
    headers: Optional[List[GcpUrlMapTestHeader]] = field(default=None)
    host: Optional[str] = field(default=None)
    path: Optional[str] = field(default=None)
    service: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpUrlMap(GcpResource):
    kind: ClassVar[str] = "gcp_url_map"
    kind_display: ClassVar[str] = "GCP URL Map"
    kind_description: ClassVar[str] = (
        "A GCP URL Map is a resource that maps a URL path to a specific backend"
        " service in Google Cloud Platform. It allows for routing of requests based on"
        " the URL path."
    )
    reference_kinds: ClassVar[ModelReference] = {"successors": {"default": ["gcp_backend_service"]}}
    api_spec: ClassVar[GcpApiSpec] = GcpApiSpec(
        service="compute",
        version="v1",
        accessors=["urlMaps"],
        action="aggregatedList",
        request_parameter={"project": "{project}"},
        request_parameter_in={"project"},
        response_path="items",
        response_regional_sub_path="urlMaps",
        mutate_iam_permissions=["compute.urlMaps.delete"],
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
        "default_route_action": S("defaultRouteAction", default={}) >> Bend(GcpHttpRouteAction.mapping),
        "default_service": S("defaultService"),
        "default_url_redirect": S("defaultUrlRedirect", default={}) >> Bend(GcpHttpRedirectAction.mapping),
        "fingerprint": S("fingerprint"),
        "header_action": S("headerAction", default={}) >> Bend(GcpHttpHeaderAction.mapping),
        "host_rules": S("hostRules", default=[]) >> ForallBend(GcpHostRule.mapping),
        "path_matchers": S("pathMatchers", default=[]) >> ForallBend(GcpPathMatcher.mapping),
        "map_tests": S("tests", default=[]) >> ForallBend(GcpUrlMapTest.mapping),
    }
    default_route_action: Optional[GcpHttpRouteAction] = field(default=None)
    default_service: Optional[str] = field(default=None)
    default_url_redirect: Optional[GcpHttpRedirectAction] = field(default=None)
    fingerprint: Optional[str] = field(default=None)
    header_action: Optional[GcpHttpHeaderAction] = field(default=None)
    host_rules: Optional[List[GcpHostRule]] = field(default=None)
    path_matchers: Optional[List[GcpPathMatcher]] = field(default=None)
    map_tests: Optional[List[GcpUrlMapTest]] = field(default=None)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if self.default_service:
            builder.add_edge(self, clazz=GcpBackendService, link=self.default_service)


@define(eq=False, slots=False)
class GcpResourcePolicyGroupPlacementPolicy:
    kind: ClassVar[str] = "gcp_resource_policy_group_placement_policy"
    kind_display: ClassVar[str] = "GCP Resource Policy Group Placement Policy"
    kind_description: ClassVar[str] = (
        "The GCP Resource Policy Group Placement Policy is a configuration within Google Cloud's Resource Policies"
        " that manages the physical placement of VM instances to optimize for either availability or co-location,"
        " with settings that include the number of availability domains used and the number of VMs that should be"
        " grouped together."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "availability_domain_count": S("availabilityDomainCount"),
        "collocation": S("collocation"),
        "vm_count": S("vmCount"),
    }
    availability_domain_count: Optional[int] = field(default=None)
    collocation: Optional[str] = field(default=None)
    vm_count: Optional[int] = field(default=None)


@define(eq=False, slots=False)
class GcpResourcePolicyInstanceSchedulePolicy:
    kind: ClassVar[str] = "gcp_resource_policy_instance_schedule_policy"
    kind_display: ClassVar[str] = "GCP Resource Policy Instance Schedule Policy"
    kind_description: ClassVar[str] = (
        "Resource policy instance schedule policy is a policy in Google Cloud"
        " Platform that allows users to define schedules for starting and stopping"
        " instances to optimize cost and manage resource usage."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "expiration_time": S("expirationTime"),
        "start_time": S("startTime"),
        "time_zone": S("timeZone"),
        "vm_start_schedule": S("vmStartSchedule", "schedule"),
        "vm_stop_schedule": S("vmStopSchedule", "schedule"),
    }
    expiration_time: Optional[datetime] = field(default=None)
    start_time: Optional[datetime] = field(default=None)
    time_zone: Optional[str] = field(default=None)
    vm_start_schedule: Optional[str] = field(default=None)
    vm_stop_schedule: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpResourcePolicyResourceStatusInstanceSchedulePolicyStatus:
    kind: ClassVar[str] = "gcp_resource_policy_resource_status_instance_schedule_policy_status"
    kind_display: ClassVar[str] = "GCP Resource Policy Resource Status Instance Schedule Policy Status"
    kind_description: ClassVar[str] = (
        "GCP Resource Policy Resource Status Instance Schedule Policy Status tracks the timing of the scheduled"
        " operations for resources, indicating the most recent and upcoming start times for policy-driven actions."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "last_run_start_time": S("lastRunStartTime"),
        "next_run_start_time": S("nextRunStartTime"),
    }
    last_run_start_time: Optional[datetime] = field(default=None)
    next_run_start_time: Optional[datetime] = field(default=None)


@define(eq=False, slots=False)
class GcpResourcePolicyResourceStatus:
    kind: ClassVar[str] = "gcp_resource_policy_resource_status"
    kind_display: ClassVar[str] = "GCP Resource Policy Resource Status"
    kind_description: ClassVar[str] = (
        "The GCP Resource Policy Resource Status provides the operational status of an instance schedule policy"
        " within a resource policy, indicating whether it's active or in any other state based on the scheduling"
        " configurations set."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "instance_schedule_policy": S("instanceSchedulePolicy", default={})
        >> Bend(GcpResourcePolicyResourceStatusInstanceSchedulePolicyStatus.mapping)
    }
    instance_schedule_policy: Optional[GcpResourcePolicyResourceStatusInstanceSchedulePolicyStatus] = field(
        default=None
    )


@define(eq=False, slots=False)
class GcpResourcePolicySnapshotSchedulePolicyRetentionPolicy:
    kind: ClassVar[str] = "gcp_resource_policy_snapshot_schedule_policy_retention_policy"
    kind_display: ClassVar[str] = "GCP Resource Policy Snapshot Schedule Policy Retention Policy"
    kind_description: ClassVar[str] = (
        "Retention policy for snapshot schedules in Google Cloud Platform's resource"
        " policy allows users to define how long the snapshots will be retained."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "max_retention_days": S("maxRetentionDays"),
        "on_source_disk_delete": S("onSourceDiskDelete"),
    }
    max_retention_days: Optional[int] = field(default=None)
    on_source_disk_delete: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpResourcePolicyDailyCycle:
    kind: ClassVar[str] = "gcp_resource_policy_daily_cycle"
    kind_display: ClassVar[str] = "GCP Resource Policy Daily Cycle"
    kind_description: ClassVar[str] = (
        "GCP Resource Policy Daily Cycle is a feature in Google Cloud Platform that"
        " allows you to define and enforce policies for your cloud resources on a"
        " daily basis."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "days_in_cycle": S("daysInCycle"),
        "duration": S("duration"),
        "start_time": S("startTime"),
    }
    days_in_cycle: Optional[int] = field(default=None)
    duration: Optional[str] = field(default=None)
    start_time: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpResourcePolicyHourlyCycle:
    kind: ClassVar[str] = "gcp_resource_policy_hourly_cycle"
    kind_display: ClassVar[str] = "GCP Resource Policy Hourly Cycle"
    kind_description: ClassVar[str] = (
        "The GCP Resource Policy Hourly Cycle dictates how a specific resource policy, such as a snapshot schedule,"
        " should operate on an hourly basis, including the frequency per cycle, the cycle's duration, and the"
        " precise start time for the policy's action to be triggered."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "duration": S("duration"),
        "hours_in_cycle": S("hoursInCycle"),
        "start_time": S("startTime"),
    }
    duration: Optional[str] = field(default=None)
    hours_in_cycle: Optional[int] = field(default=None)
    start_time: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpResourcePolicyWeeklyCycleDayOfWeek:
    kind: ClassVar[str] = "gcp_resource_policy_weekly_cycle_day_of_week"
    kind_display: ClassVar[str] = "GCP Resource Policy Weekly Cycle Day of Week"
    kind_description: ClassVar[str] = (
        "The GCP Resource Policy Weekly Cycle Day of Week defines the specific days within the week when particular"
        " operations or actions should occur, including the start time and duration of these actions."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"day": S("day"), "duration": S("duration"), "start_time": S("startTime")}
    day: Optional[str] = field(default=None)
    duration: Optional[str] = field(default=None)
    start_time: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpResourcePolicyWeeklyCycle:
    kind: ClassVar[str] = "gcp_resource_policy_weekly_cycle"
    kind_display: ClassVar[str] = "GCP Resource Policy Weekly Cycle"
    kind_description: ClassVar[str] = (
        "The GCP Resource Policy Weekly Cycle is a scheduling configuration that specifies on which days of the"
        " week, at what times, and for how long certain operations on resources should take place as part of the"
        " resource policy."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "day_of_weeks": S("dayOfWeeks", default=[]) >> ForallBend(GcpResourcePolicyWeeklyCycleDayOfWeek.mapping)
    }
    day_of_weeks: Optional[List[GcpResourcePolicyWeeklyCycleDayOfWeek]] = field(default=None)


@define(eq=False, slots=False)
class GcpResourcePolicySnapshotSchedulePolicySchedule:
    kind: ClassVar[str] = "gcp_resource_policy_snapshot_schedule_policy_schedule"
    kind_display: ClassVar[str] = "GCP Resource Policy Snapshot Schedule Policy Schedule"
    kind_description: ClassVar[str] = (
        "This resource represents a schedule for snapshot policies in Google Cloud"
        " Platform's resource policy framework."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "daily_schedule": S("dailySchedule", default={}) >> Bend(GcpResourcePolicyDailyCycle.mapping),
        "hourly_schedule": S("hourlySchedule", default={}) >> Bend(GcpResourcePolicyHourlyCycle.mapping),
        "weekly_schedule": S("weeklySchedule", default={}) >> Bend(GcpResourcePolicyWeeklyCycle.mapping),
    }
    daily_schedule: Optional[GcpResourcePolicyDailyCycle] = field(default=None)
    hourly_schedule: Optional[GcpResourcePolicyHourlyCycle] = field(default=None)
    weekly_schedule: Optional[GcpResourcePolicyWeeklyCycle] = field(default=None)


@define(eq=False, slots=False)
class GcpResourcePolicySnapshotSchedulePolicySnapshotProperties:
    kind: ClassVar[str] = "gcp_resource_policy_snapshot_schedule_policy_snapshot_properties"
    kind_display: ClassVar[str] = "GCP Resource Policy Snapshot Schedule Policy Snapshot Properties"
    kind_description: ClassVar[str] = (
        "This represents the snapshot schedule policy properties for GCP resource"
        " policies, allowing users to configure automated snapshot creation and"
        " deletion for their resources in Google Cloud Platform."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "chain_name": S("chainName"),
        "guest_flush": S("guestFlush"),
        "labels": S("labels"),
        "storage_locations": S("storageLocations", default=[]),
    }
    chain_name: Optional[str] = field(default=None)
    guest_flush: Optional[bool] = field(default=None)
    labels: Optional[Dict[str, str]] = field(default=None)
    storage_locations: Optional[List[str]] = field(default=None)


@define(eq=False, slots=False)
class GcpResourcePolicySnapshotSchedulePolicy:
    kind: ClassVar[str] = "gcp_resource_policy_snapshot_schedule_policy"
    kind_display: ClassVar[str] = "GCP Resource Policy Snapshot Schedule Policy"
    kind_description: ClassVar[str] = (
        "Resource Policy Snapshot Schedule Policy is a feature in Google Cloud"
        " Platform that allows users to define a policy for creating and managing"
        " scheduled snapshots of resources."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "retention_policy": S("retentionPolicy", default={})
        >> Bend(GcpResourcePolicySnapshotSchedulePolicyRetentionPolicy.mapping),
        "schedule": S("schedule", default={}) >> Bend(GcpResourcePolicySnapshotSchedulePolicySchedule.mapping),
        "snapshot_properties": S("snapshotProperties", default={})
        >> Bend(GcpResourcePolicySnapshotSchedulePolicySnapshotProperties.mapping),
    }
    retention_policy: Optional[GcpResourcePolicySnapshotSchedulePolicyRetentionPolicy] = field(default=None)
    schedule: Optional[GcpResourcePolicySnapshotSchedulePolicySchedule] = field(default=None)
    snapshot_properties: Optional[GcpResourcePolicySnapshotSchedulePolicySnapshotProperties] = field(default=None)


@define(eq=False, slots=False)
class GcpResourcePolicy(GcpResource):
    kind: ClassVar[str] = "gcp_resource_policy"
    kind_display: ClassVar[str] = "GCP Resource Policy"
    kind_description: ClassVar[str] = (
        "GCP Resource Policy is a tool that helps manage compute resources for VM instances in Google"
        " Cloud, enabling users to define scheduling for instance creation, automated snapshots, and"
        " resource grouping, which can optimize costs and maintain the necessary resource availability."
    )
    api_spec: ClassVar[GcpApiSpec] = GcpApiSpec(
        service="compute",
        version="v1",
        accessors=["resourcePolicies"],
        action="aggregatedList",
        request_parameter={"project": "{project}"},
        request_parameter_in={"project"},
        response_path="items",
        response_regional_sub_path="resourcePolicies",
        mutate_iam_permissions=["compute.resourcePolicies.update", "compute.resourcePolicies.delete"],
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
        "group_placement_policy": S("groupPlacementPolicy", default={})
        >> Bend(GcpResourcePolicyGroupPlacementPolicy.mapping),
        "instance_schedule_policy": S("instanceSchedulePolicy", default={})
        >> Bend(GcpResourcePolicyInstanceSchedulePolicy.mapping),
        "resource_policy_resource_status": S("resourceStatus", default={})
        >> Bend(GcpResourcePolicyResourceStatus.mapping),
        "snapshot_schedule_policy": S("snapshotSchedulePolicy", default={})
        >> Bend(GcpResourcePolicySnapshotSchedulePolicy.mapping),
        "status": S("status"),
    }
    group_placement_policy: Optional[GcpResourcePolicyGroupPlacementPolicy] = field(default=None)
    instance_schedule_policy: Optional[GcpResourcePolicyInstanceSchedulePolicy] = field(default=None)
    resource_policy_resource_status: Optional[GcpResourcePolicyResourceStatus] = field(default=None)
    snapshot_schedule_policy: Optional[GcpResourcePolicySnapshotSchedulePolicy] = field(default=None)
    status: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpRouterAdvertisedIpRange:
    kind: ClassVar[str] = "gcp_router_advertised_ip_range"
    kind_display: ClassVar[str] = "GCP Router Advertised IP Range"
    kind_description: ClassVar[str] = (
        "GCP Router Advertised IP Range is a range of IP addresses that are"
        " advertised by the Google Cloud Platform (GCP) router, allowing communication"
        " between different networks within the GCP infrastructure."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"description": S("description"), "range": S("range")}
    description: Optional[str] = field(default=None)
    range: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpRouterBgp:
    kind: ClassVar[str] = "gcp_router_bgp"
    kind_display: ClassVar[str] = "GCP Router BGP"
    kind_description: ClassVar[str] = (
        "GCP Router BGP is a feature in Google Cloud Platform that enables Border"
        " Gateway Protocol (BGP) routing between Google's network and external"
        " networks, providing improved network scalability and flexibility."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "advertise_mode": S("advertiseMode"),
        "advertised_groups": S("advertisedGroups", default=[]),
        "advertised_ip_ranges": S("advertisedIpRanges", default=[]) >> ForallBend(GcpRouterAdvertisedIpRange.mapping),
        "asn": S("asn"),
        "keepalive_interval": S("keepaliveInterval"),
    }
    advertise_mode: Optional[str] = field(default=None)
    advertised_groups: Optional[List[str]] = field(default=None)
    advertised_ip_ranges: Optional[List[GcpRouterAdvertisedIpRange]] = field(default=None)
    asn: Optional[int] = field(default=None)
    keepalive_interval: Optional[int] = field(default=None)


@define(eq=False, slots=False)
class GcpRouterBgpPeerBfd:
    kind: ClassVar[str] = "gcp_router_bgp_peer_bfd"
    kind_display: ClassVar[str] = "GCP Router BGP Peer BFD"
    kind_description: ClassVar[str] = (
        "BFD (Bidirectional Forwarding Detection) is a feature in Google Cloud"
        " Platform (GCP) that allows BGP (Border Gateway Protocol) peers to quickly"
        " detect and recover from network failures."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "min_receive_interval": S("minReceiveInterval"),
        "min_transmit_interval": S("minTransmitInterval"),
        "multiplier": S("multiplier"),
        "session_initialization_mode": S("sessionInitializationMode"),
    }
    min_receive_interval: Optional[int] = field(default=None)
    min_transmit_interval: Optional[int] = field(default=None)
    multiplier: Optional[int] = field(default=None)
    session_initialization_mode: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpRouterBgpPeer:
    kind: ClassVar[str] = "gcp_router_bgp_peer"
    kind_display: ClassVar[str] = "GCP Router BGP Peer"
    kind_description: ClassVar[str] = (
        "A BGP (Border Gateway Protocol) Peer associated with a Google Cloud Platform"
        " (GCP) Router. BGP Peers are used to establish and manage a routing session"
        " between routers in order to exchange routing information."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "advertise_mode": S("advertiseMode"),
        "advertised_groups": S("advertisedGroups", default=[]),
        "advertised_ip_ranges": S("advertisedIpRanges", default=[]) >> ForallBend(GcpRouterAdvertisedIpRange.mapping),
        "advertised_route_priority": S("advertisedRoutePriority"),
        "bfd": S("bfd", default={}) >> Bend(GcpRouterBgpPeerBfd.mapping),
        "enable": S("enable"),
        "enable_ipv6": S("enableIpv6"),
        "interface_name": S("interfaceName"),
        "ip_address": S("ipAddress"),
        "ipv6_nexthop_address": S("ipv6NexthopAddress"),
        "management_type": S("managementType"),
        "md5_authentication_key_name": S("md5AuthenticationKeyName"),
        "name": S("name"),
        "peer_asn": S("peerAsn"),
        "peer_ip_address": S("peerIpAddress"),
        "peer_ipv6_nexthop_address": S("peerIpv6NexthopAddress"),
        "router_appliance_instance": S("routerApplianceInstance"),
    }
    advertise_mode: Optional[str] = field(default=None)
    advertised_groups: Optional[List[str]] = field(default=None)
    advertised_ip_ranges: Optional[List[GcpRouterAdvertisedIpRange]] = field(default=None)
    advertised_route_priority: Optional[int] = field(default=None)
    bfd: Optional[GcpRouterBgpPeerBfd] = field(default=None)
    enable: Optional[str] = field(default=None)
    enable_ipv6: Optional[bool] = field(default=None)
    interface_name: Optional[str] = field(default=None)
    ip_address: Optional[str] = field(default=None)
    ipv6_nexthop_address: Optional[str] = field(default=None)
    management_type: Optional[str] = field(default=None)
    md5_authentication_key_name: Optional[str] = field(default=None)
    name: Optional[str] = field(default=None)
    peer_asn: Optional[int] = field(default=None)
    peer_ip_address: Optional[str] = field(default=None)
    peer_ipv6_nexthop_address: Optional[str] = field(default=None)
    router_appliance_instance: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpRouterInterface:
    kind: ClassVar[str] = "gcp_router_interface"
    kind_display: ClassVar[str] = "GCP Router Interface"
    kind_description: ClassVar[str] = (
        "A router interface in Google Cloud Platform (GCP) is a connection point for"
        " a virtual network to interconnect with other networks or the internet."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "ip_range": S("ipRange"),
        "linked_interconnect_attachment": S("linkedInterconnectAttachment"),
        "linked_vpn_tunnel": S("linkedVpnTunnel"),
        "management_type": S("managementType"),
        "name": S("name"),
        "private_ip_address": S("privateIpAddress"),
        "redundant_interface": S("redundantInterface"),
        "subnetwork": S("subnetwork"),
    }
    ip_range: Optional[str] = field(default=None)
    linked_interconnect_attachment: Optional[str] = field(default=None)
    linked_vpn_tunnel: Optional[str] = field(default=None)
    management_type: Optional[str] = field(default=None)
    name: Optional[str] = field(default=None)
    private_ip_address: Optional[str] = field(default=None)
    redundant_interface: Optional[str] = field(default=None)
    subnetwork: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpRouterMd5AuthenticationKey:
    kind: ClassVar[str] = "gcp_router_md5_authentication_key"
    kind_display: ClassVar[str] = "GCP Router MD5 Authentication Key"
    kind_description: ClassVar[str] = (
        "The GCP Router MD5 Authentication Key is a security feature for routers that uses an MD5 key for"
        " authentication, ensuring secure exchange of routing updates."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"key": S("key"), "name": S("name")}
    key: Optional[str] = field(default=None)
    name: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpRouterNatLogConfig:
    kind: ClassVar[str] = "gcp_router_nat_log_config"
    kind_display: ClassVar[str] = "GCP Router NAT Log Config"
    kind_description: ClassVar[str] = (
        "The GCP Router NAT Log Config is a configuration option for logging NAT"
        " (Network Address Translation) events in Google Cloud Platform routers."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"enable": S("enable"), "filter": S("filter")}
    enable: Optional[bool] = field(default=None)
    filter: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpRouterNatRuleAction:
    kind: ClassVar[str] = "gcp_router_nat_rule_action"
    kind_display: ClassVar[str] = "GCP Router NAT Rule Action"
    kind_description: ClassVar[str] = (
        "A GCP Router NAT Rule Action is used in Google Cloud Platform to configure"
        " the action for Network Address Translation (NAT) rules on a router. NAT"
        " rules determine how network traffic is translated between different IP"
        " address ranges."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "source_nat_active_ips": S("sourceNatActiveIps", default=[]),
        "source_nat_drain_ips": S("sourceNatDrainIps", default=[]),
    }
    source_nat_active_ips: Optional[List[str]] = field(default=None)
    source_nat_drain_ips: Optional[List[str]] = field(default=None)


@define(eq=False, slots=False)
class GcpRouterNatRule:
    kind: ClassVar[str] = "gcp_router_nat_rule"
    kind_display: ClassVar[str] = "GCP Router NAT Rule"
    kind_description: ClassVar[str] = (
        "GCP Router NAT Rule allows users to configure Network Address Translation"
        " (NAT) rules on Google Cloud Platform's routers, enabling communication"
        " between networks with different IP address ranges."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "action": S("action", default={}) >> Bend(GcpRouterNatRuleAction.mapping),
        "description": S("description"),
        "match": S("match"),
        "rule_number": S("ruleNumber"),
    }
    action: Optional[GcpRouterNatRuleAction] = field(default=None)
    description: Optional[str] = field(default=None)
    match: Optional[str] = field(default=None)
    rule_number: Optional[int] = field(default=None)


@define(eq=False, slots=False)
class GcpRouterNatSubnetworkToNat:
    kind: ClassVar[str] = "gcp_router_nat_subnetwork_to_nat"
    kind_display: ClassVar[str] = "GCP Router NAT Subnetwork-to-NAT"
    kind_description: ClassVar[str] = (
        "This resource in Google Cloud Platform (GCP) allows you to configure Network"
        " Address Translation (NAT) for subnetworks, enabling communication between"
        " private subnet resources and external networks."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "name": S("name"),
        "secondary_ip_range_names": S("secondaryIpRangeNames", default=[]),
        "source_ip_ranges_to_nat": S("sourceIpRangesToNat", default=[]),
    }
    name: Optional[str] = field(default=None)
    secondary_ip_range_names: Optional[List[str]] = field(default=None)
    source_ip_ranges_to_nat: Optional[List[str]] = field(default=None)


@define(eq=False, slots=False)
class GcpRouterNat:
    kind: ClassVar[str] = "gcp_router_nat"
    kind_display: ClassVar[str] = "GCP Router NAT"
    kind_description: ClassVar[str] = (
        "GCP Router NAT is a Cloud NAT service provided by Google Cloud Platform,"
        " which allows virtual machine instances without external IP addresses to"
        " access the internet and receive inbound traffic."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "drain_nat_ips": S("drainNatIps", default=[]),
        "enable_dynamic_port_allocation": S("enableDynamicPortAllocation"),
        "enable_endpoint_independent_mapping": S("enableEndpointIndependentMapping"),
        "endpoint_types": S("endpointTypes", default=[]),
        "icmp_idle_timeout_sec": S("icmpIdleTimeoutSec"),
        "router_nat_log_config": S("logConfig", default={}) >> Bend(GcpRouterNatLogConfig.mapping),
        "max_ports_per_vm": S("maxPortsPerVm"),
        "min_ports_per_vm": S("minPortsPerVm"),
        "name": S("name"),
        "nat_ip_allocate_option": S("natIpAllocateOption"),
        "nat_ips": S("natIps", default=[]),
        "router_nat_rules": S("rules", default=[]) >> ForallBend(GcpRouterNatRule.mapping),
        "source_subnetwork_ip_ranges_to_nat": S("sourceSubnetworkIpRangesToNat"),
        "subnetworks": S("subnetworks", default=[]) >> ForallBend(GcpRouterNatSubnetworkToNat.mapping),
        "tcp_established_idle_timeout_sec": S("tcpEstablishedIdleTimeoutSec"),
        "tcp_time_wait_timeout_sec": S("tcpTimeWaitTimeoutSec"),
        "tcp_transitory_idle_timeout_sec": S("tcpTransitoryIdleTimeoutSec"),
        "udp_idle_timeout_sec": S("udpIdleTimeoutSec"),
    }
    drain_nat_ips: Optional[List[str]] = field(default=None)
    enable_dynamic_port_allocation: Optional[bool] = field(default=None)
    enable_endpoint_independent_mapping: Optional[bool] = field(default=None)
    endpoint_types: Optional[List[str]] = field(default=None)
    icmp_idle_timeout_sec: Optional[int] = field(default=None)
    router_nat_log_config: Optional[GcpRouterNatLogConfig] = field(default=None)
    max_ports_per_vm: Optional[int] = field(default=None)
    min_ports_per_vm: Optional[int] = field(default=None)
    name: Optional[str] = field(default=None)
    nat_ip_allocate_option: Optional[str] = field(default=None)
    nat_ips: Optional[List[str]] = field(default=None)
    router_nat_rules: Optional[List[GcpRouterNatRule]] = field(default=None)
    source_subnetwork_ip_ranges_to_nat: Optional[str] = field(default=None)
    subnetworks: Optional[List[GcpRouterNatSubnetworkToNat]] = field(default=None)
    tcp_established_idle_timeout_sec: Optional[int] = field(default=None)
    tcp_time_wait_timeout_sec: Optional[int] = field(default=None)
    tcp_transitory_idle_timeout_sec: Optional[int] = field(default=None)
    udp_idle_timeout_sec: Optional[int] = field(default=None)


@define(eq=False, slots=False)
class GcpRouter(GcpResource):
    kind: ClassVar[str] = "gcp_router"
    kind_display: ClassVar[str] = "GCP Router"
    kind_description: ClassVar[str] = (
        "GCP Router is a networking component in Google Cloud Platform that directs"
        " traffic between virtual networks."
    )
    reference_kinds: ClassVar[ModelReference] = {
        "predecessors": {"default": ["gcp_network"], "delete": ["gcp_network"]}
    }
    api_spec: ClassVar[GcpApiSpec] = GcpApiSpec(
        service="compute",
        version="v1",
        accessors=["routers"],
        action="aggregatedList",
        request_parameter={"project": "{project}"},
        request_parameter_in={"project"},
        response_path="items",
        response_regional_sub_path="routers",
        mutate_iam_permissions=["compute.routers.update", "compute.routers.delete"],
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
        "bgp": S("bgp", default={}) >> Bend(GcpRouterBgp.mapping),
        "bgp_peers": S("bgpPeers", default=[]) >> ForallBend(GcpRouterBgpPeer.mapping),
        "encrypted_interconnect_router": S("encryptedInterconnectRouter"),
        "router_interfaces": S("interfaces", default=[]) >> ForallBend(GcpRouterInterface.mapping),
        "md5_authentication_keys": S("md5AuthenticationKeys", default=[])
        >> ForallBend(GcpRouterMd5AuthenticationKey.mapping),
        "nats": S("nats", default=[]) >> ForallBend(GcpRouterNat.mapping),
        "network": S("network"),
    }
    bgp: Optional[GcpRouterBgp] = field(default=None)
    bgp_peers: Optional[List[GcpRouterBgpPeer]] = field(default=None)
    encrypted_interconnect_router: Optional[bool] = field(default=None)
    router_interfaces: Optional[List[GcpRouterInterface]] = field(default=None)
    md5_authentication_keys: Optional[List[GcpRouterMd5AuthenticationKey]] = field(default=None)
    nats: Optional[List[GcpRouterNat]] = field(default=None)
    network: Optional[str] = field(default=None)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if self.network:
            builder.dependant_node(self, reverse=True, delete_same_as_default=True, clazz=GcpNetwork, link=self.network)


@define(eq=False, slots=False)
class GcpRouteAsPath:
    kind: ClassVar[str] = "gcp_route_as_path"
    kind_display: ClassVar[str] = "GCP Route AS Path"
    kind_description: ClassVar[str] = (
        "AS Path is a attribute in BGP routing protocol that represents the sequence"
        " of Autonomous System numbers that a route has traversed."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "as_lists": S("asLists", default=[]),
        "path_segment_type": S("pathSegmentType"),
    }
    as_lists: Optional[List[int]] = field(default=None)
    path_segment_type: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpRoute(GcpResource):
    kind: ClassVar[str] = "gcp_route"
    kind_display: ClassVar[str] = "GCP Route"
    kind_description: ClassVar[str] = (
        "A GCP Route is a rule that specifies the next-hop information for network"
        " traffic within a Google Cloud Platform virtual network."
    )
    reference_kinds: ClassVar[ModelReference] = {
        "predecessors": {"default": ["gcp_network"], "delete": ["gcp_network"]}
    }
    api_spec: ClassVar[GcpApiSpec] = GcpApiSpec(
        service="compute",
        version="v1",
        accessors=["routes"],
        action="list",
        request_parameter={"project": "{project}"},
        request_parameter_in={"project"},
        response_path="items",
        response_regional_sub_path=None,
        mutate_iam_permissions=["compute.routes.delete"],
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
        "as_paths": S("asPaths", default=[]) >> ForallBend(GcpRouteAsPath.mapping),
        "dest_range": S("destRange"),
        "network": S("network"),
        "next_hop_gateway": S("nextHopGateway"),
        "next_hop_ilb": S("nextHopIlb"),
        "next_hop_instance": S("nextHopInstance"),
        "next_hop_ip": S("nextHopIp"),
        "next_hop_network": S("nextHopNetwork"),
        "next_hop_peering": S("nextHopPeering"),
        "next_hop_vpn_tunnel": S("nextHopVpnTunnel"),
        "priority": S("priority"),
        "route_status": S("routeStatus"),
        "route_type": S("routeType"),
        "route_tags": S("tags", default=[]),
        "warnings": S("warnings", default=[]) >> ForallBend(GcpWarnings.mapping),
    }
    as_paths: Optional[List[GcpRouteAsPath]] = field(default=None)
    dest_range: Optional[str] = field(default=None)
    network: Optional[str] = field(default=None)
    next_hop_gateway: Optional[str] = field(default=None)
    next_hop_ilb: Optional[str] = field(default=None)
    next_hop_instance: Optional[str] = field(default=None)
    next_hop_ip: Optional[str] = field(default=None)
    next_hop_network: Optional[str] = field(default=None)
    next_hop_peering: Optional[str] = field(default=None)
    next_hop_vpn_tunnel: Optional[str] = field(default=None)
    priority: Optional[int] = field(default=None)
    route_status: Optional[str] = field(default=None)
    route_type: Optional[str] = field(default=None)
    route_tags: Optional[List[str]] = field(default=None)
    warnings: Optional[List[GcpWarnings]] = field(default=None)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if self.network:
            builder.dependant_node(self, reverse=True, delete_same_as_default=True, clazz=GcpNetwork, link=self.network)


@define(eq=False, slots=False)
class GcpServiceAttachmentConnectedEndpoint:
    kind: ClassVar[str] = "gcp_service_attachment_connected_endpoint"
    kind_display: ClassVar[str] = "GCP Service Attachment Connected Endpoint"
    kind_description: ClassVar[str] = (
        "A connected endpoint in Google Cloud Platform (GCP) service attachment"
        " represents the network endpoint that is connected to a service attachment,"
        " allowing communication between the attachment and the endpoint."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "endpoint": S("endpoint"),
        "psc_connection_id": S("pscConnectionId"),
        "status": S("status"),
    }
    endpoint: Optional[str] = field(default=None)
    psc_connection_id: Optional[str] = field(default=None)
    status: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpServiceAttachmentConsumerProjectLimit:
    kind: ClassVar[str] = "gcp_service_attachment_consumer_project_limit"
    kind_display: ClassVar[str] = "GCP Service Attachment Consumer Project Limit"
    kind_description: ClassVar[str] = (
        "GCP Service Attachment Consumer Project Limit manages the maximum number of connections a specific consumer"
        " project can establish with a service provider through the service attachment feature."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "connection_limit": S("connectionLimit"),
        "project_id_or_num": S("projectIdOrNum"),
    }
    connection_limit: Optional[int] = field(default=None)
    project_id_or_num: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpUint128:
    kind: ClassVar[str] = "gcp_uint128"
    kind_display: ClassVar[str] = "GCP Uint128"
    kind_description: ClassVar[str] = (
        "A GCP Uint128 is a large numerical identifier comprising two sequential numerical parts that"
        " enable a vast range of unique identifiers, typically utilized for resources requiring a very"
        " large space of IDs."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"high": S("high"), "low": S("low")}
    high: Optional[str] = field(default=None)
    low: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpServiceAttachment(GcpResource):
    kind: ClassVar[str] = "gcp_service_attachment"
    kind_display: ClassVar[str] = "GCP Service Attachment"
    kind_description: ClassVar[str] = (
        "GCP Service Attachment is a networking feature that manages connectivity and security policies between"
        " Google Cloud services and external services, offering controls like connection preferences, domain"
        " names management, and protocol support."
    )
    reference_kinds: ClassVar[ModelReference] = {"successors": {"default": ["gcp_backend_service", "gcp_subnetwork"]}}
    api_spec: ClassVar[GcpApiSpec] = GcpApiSpec(
        service="compute",
        version="v1",
        accessors=["serviceAttachments"],
        action="aggregatedList",
        request_parameter={"project": "{project}"},
        request_parameter_in={"project"},
        response_path="items",
        response_regional_sub_path="serviceAttachments",
        mutate_iam_permissions=["compute.serviceAttachments.update", "compute.serviceAttachments.delete"],
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
        "connected_endpoints": S("connectedEndpoints", default=[])
        >> ForallBend(GcpServiceAttachmentConnectedEndpoint.mapping),
        "connection_preference": S("connectionPreference"),
        "consumer_accept_lists": S("consumerAcceptLists", default=[])
        >> ForallBend(GcpServiceAttachmentConsumerProjectLimit.mapping),
        "consumer_reject_lists": S("consumerRejectLists", default=[]),
        "domain_names": S("domainNames", default=[]),
        "enable_proxy_protocol": S("enableProxyProtocol"),
        "fingerprint": S("fingerprint"),
        "nat_subnets": S("natSubnets", default=[]),
        "producer_forwarding_rule": S("producerForwardingRule"),
        "psc_service_attachment_id": S("pscServiceAttachmentId", default={}) >> Bend(GcpUint128.mapping),
        "target_service": S("targetService"),
    }
    connected_endpoints: Optional[List[GcpServiceAttachmentConnectedEndpoint]] = field(default=None)
    connection_preference: Optional[str] = field(default=None)
    consumer_accept_lists: Optional[List[GcpServiceAttachmentConsumerProjectLimit]] = field(default=None)
    consumer_reject_lists: Optional[List[str]] = field(default=None)
    domain_names: Optional[List[str]] = field(default=None)
    enable_proxy_protocol: Optional[bool] = field(default=None)
    fingerprint: Optional[str] = field(default=None)
    nat_subnets: Optional[List[str]] = field(default=None)
    producer_forwarding_rule: Optional[str] = field(default=None)
    psc_service_attachment_id: Optional[GcpUint128] = field(default=None)
    target_service: Optional[str] = field(default=None)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if self.target_service:
            builder.add_edge(self, clazz=GcpBackendService, link=self.target_service)
        if self.nat_subnets:
            for subnet in self.nat_subnets:
                builder.add_edge(self, clazz=GcpSubnetwork, link=subnet)


@define(eq=False, slots=False)
class GcpSnapshot(GcpResource):
    kind: ClassVar[str] = "gcp_snapshot"
    kind_display: ClassVar[str] = "GCP Snapshot"
    kind_description: ClassVar[str] = (
        "GCP Snapshot is a point-in-time copy of the data in a persistent disk in"
        " Google Cloud Platform, allowing for data backup and recovery."
    )
    reference_kinds: ClassVar[ModelReference] = {"predecessors": {"default": ["gcp_disk"]}}
    api_spec: ClassVar[GcpApiSpec] = GcpApiSpec(
        service="compute",
        version="v1",
        accessors=["snapshots"],
        action="list",
        request_parameter={"project": "{project}"},
        request_parameter_in={"project"},
        response_path="items",
        response_regional_sub_path=None,
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
        "snapshot_architecture": S("architecture"),
        "snapshot_auto_created": S("autoCreated"),
        "snapshot_chain_name": S("chainName"),
        "snapshot_creation_size_bytes": S("creationSizeBytes"),
        "snapshot_disk_size_gb": S("diskSizeGb") >> AsInt(),
        "snapshot_download_bytes": S("downloadBytes"),
        "snapshot_license_codes": S("licenseCodes", default=[]),
        "snapshot_licenses": S("licenses", default=[]),
        "snapshot_location_hint": S("locationHint"),
        "snapshot_satisfies_pzs": S("satisfiesPzs"),
        "snapshot_snapshot_encryption_key": S("snapshotEncryptionKey", default={})
        >> Bend(GcpCustomerEncryptionKey.mapping),
        "snapshot_snapshot_type": S("snapshotType"),
        "snapshot_source_disk": S("sourceDisk"),
        "snapshot_source_disk_encryption_key": S("sourceDiskEncryptionKey", default={})
        >> Bend(GcpCustomerEncryptionKey.mapping),
        "snapshot_source_disk_id": S("sourceDiskId"),
        "snapshot_source_snapshot_schedule_policy": S("sourceSnapshotSchedulePolicy"),
        "snapshot_source_snapshot_schedule_policy_id": S("sourceSnapshotSchedulePolicyId"),
        "snapshot_status": S("status"),
        "snapshot_storage_bytes": S("storageBytes"),
        "snapshot_storage_bytes_status": S("storageBytesStatus"),
        "snapshot_storage_locations": S("storageLocations", default=[]),
    }
    snapshot_architecture: Optional[str] = field(default=None)
    snapshot_auto_created: Optional[bool] = field(default=None)
    snapshot_chain_name: Optional[str] = field(default=None)
    snapshot_creation_size_bytes: Optional[str] = field(default=None)
    snapshot_disk_size_gb: Optional[int] = field(default=None)
    snapshot_download_bytes: Optional[str] = field(default=None)
    snapshot_license_codes: Optional[List[str]] = field(default=None)
    snapshot_licenses: Optional[List[str]] = field(default=None)
    snapshot_location_hint: Optional[str] = field(default=None)
    snapshot_satisfies_pzs: Optional[bool] = field(default=None)
    snapshot_snapshot_encryption_key: Optional[GcpCustomerEncryptionKey] = field(default=None)
    snapshot_snapshot_type: Optional[str] = field(default=None)
    snapshot_source_disk: Optional[str] = field(default=None)
    snapshot_source_disk_encryption_key: Optional[GcpCustomerEncryptionKey] = field(default=None)
    snapshot_source_disk_id: Optional[str] = field(default=None)
    snapshot_source_snapshot_schedule_policy: Optional[str] = field(default=None)
    snapshot_source_snapshot_schedule_policy_id: Optional[str] = field(default=None)
    snapshot_status: Optional[str] = field(default=None)
    snapshot_storage_bytes: Optional[str] = field(default=None)
    snapshot_storage_bytes_status: Optional[str] = field(default=None)
    snapshot_storage_locations: Optional[List[str]] = field(default=None)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if self.snapshot_source_disk:
            builder.add_edge(self, reverse=True, clazz=GcpDisk, link=self.snapshot_source_disk)


@define(eq=False, slots=False)
class GcpSubnetworkLogConfig:
    kind: ClassVar[str] = "gcp_subnetwork_log_config"
    kind_display: ClassVar[str] = "GCP Subnetwork Log Config"
    kind_description: ClassVar[str] = (
        "GCP Subnetwork Log Config is a feature provided by Google Cloud Platform"
        " (GCP) that allows users to configure logging for subnetworks. It enables the"
        " collection and analysis of network traffic logs for better network security"
        " and troubleshooting."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "aggregation_interval": S("aggregationInterval"),
        "enable": S("enable"),
        "filter_expr": S("filterExpr"),
        "flow_sampling": S("flowSampling"),
        "metadata": S("metadata"),
        "metadata_fields": S("metadataFields", default=[]),
    }
    aggregation_interval: Optional[str] = field(default=None)
    enable: Optional[bool] = field(default=None)
    filter_expr: Optional[str] = field(default=None)
    flow_sampling: Optional[float] = field(default=None)
    metadata: Optional[str] = field(default=None)
    metadata_fields: Optional[List[str]] = field(default=None)


@define(eq=False, slots=False)
class GcpSubnetworkSecondaryRange:
    kind: ClassVar[str] = "gcp_subnetwork_secondary_range"
    kind_display: ClassVar[str] = "GCP Subnetwork Secondary Range"
    kind_description: ClassVar[str] = (
        "GCP Subnetwork Secondary Range is a range of IP addresses that can be used"
        " for assigning to instances or services within a Google Cloud Platform"
        " subnetwork."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"ip_cidr_range": S("ipCidrRange"), "range_name": S("rangeName")}
    ip_cidr_range: Optional[str] = field(default=None)
    range_name: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpSubnetwork(GcpResource):
    kind: ClassVar[str] = "gcp_subnetwork"
    kind_display: ClassVar[str] = "GCP Subnetwork"
    kind_description: ClassVar[str] = (
        "A GCP Subnetwork is a segmented network within a Virtual Private Cloud (VPC)"
        " that allows for more granular control over network traffic and IP address"
        " allocation."
    )
    reference_kinds: ClassVar[ModelReference] = {
        "predecessors": {"default": ["gcp_network"], "delete": ["gcp_network"]}
    }
    api_spec: ClassVar[GcpApiSpec] = GcpApiSpec(
        service="compute",
        version="v1",
        accessors=["subnetworks"],
        action="aggregatedList",
        request_parameter={"project": "{project}"},
        request_parameter_in={"project"},
        response_path="items",
        response_regional_sub_path="subnetworks",
        mutate_iam_permissions=["compute.subnetworks.delete"],
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
        "enable_flow_logs": S("enableFlowLogs"),
        "external_ipv6_prefix": S("externalIpv6Prefix"),
        "fingerprint": S("fingerprint"),
        "gateway_address": S("gatewayAddress"),
        "internal_ipv6_prefix": S("internalIpv6Prefix"),
        "ip_cidr_range": S("ipCidrRange"),
        "ipv6_access_type": S("ipv6AccessType"),
        "ipv6_cidr_range": S("ipv6CidrRange"),
        "subnetwork_log_config": S("logConfig", default={}) >> Bend(GcpSubnetworkLogConfig.mapping),
        "network": S("network"),
        "private_ip_google_access": S("privateIpGoogleAccess"),
        "private_ipv6_google_access": S("privateIpv6GoogleAccess"),
        "purpose": S("purpose"),
        "role": S("role"),
        "secondary_ip_ranges": S("secondaryIpRanges", default=[]) >> ForallBend(GcpSubnetworkSecondaryRange.mapping),
        "stack_type": S("stackType"),
        "subnetwork_state": S("state"),
    }
    enable_flow_logs: Optional[bool] = field(default=None)
    external_ipv6_prefix: Optional[str] = field(default=None)
    fingerprint: Optional[str] = field(default=None)
    gateway_address: Optional[str] = field(default=None)
    internal_ipv6_prefix: Optional[str] = field(default=None)
    ip_cidr_range: Optional[str] = field(default=None)
    ipv6_access_type: Optional[str] = field(default=None)
    ipv6_cidr_range: Optional[str] = field(default=None)
    subnetwork_log_config: Optional[GcpSubnetworkLogConfig] = field(default=None)
    network: Optional[str] = field(default=None)
    private_ip_google_access: Optional[bool] = field(default=None)
    private_ipv6_google_access: Optional[str] = field(default=None)
    purpose: Optional[str] = field(default=None)
    role: Optional[str] = field(default=None)
    secondary_ip_ranges: Optional[List[GcpSubnetworkSecondaryRange]] = field(default=None)
    stack_type: Optional[str] = field(default=None)
    subnetwork_state: Optional[str] = field(default=None)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if self.network:
            builder.dependant_node(self, reverse=True, delete_same_as_default=True, clazz=GcpNetwork, link=self.network)


@define(eq=False, slots=False)
class GcpTargetGrpcProxy(GcpResource):
    kind: ClassVar[str] = "gcp_target_grpc_proxy"
    kind_display: ClassVar[str] = "GCP Target gRPC Proxy"
    kind_description: ClassVar[str] = (
        "GCP Target gRPC Proxy is a service in Google Cloud Platform that allows you"
        " to load balance gRPC traffic to backend services."
    )
    reference_kinds: ClassVar[ModelReference] = {
        "predecessors": {
            "delete": ["gcp_url_map"],
        },
        "successors": {"default": ["gcp_url_map"]},
    }
    api_spec: ClassVar[GcpApiSpec] = GcpApiSpec(
        service="compute",
        version="v1",
        accessors=["targetGrpcProxies"],
        action="list",
        request_parameter={"project": "{project}"},
        request_parameter_in={"project"},
        response_path="items",
        response_regional_sub_path=None,
        mutate_iam_permissions=["compute.targetGrpcProxies.update", "compute.targetGrpcProxies.delete"],
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
        "fingerprint": S("fingerprint"),
        "self_link_with_id": S("selfLinkWithId"),
        "url_map": S("urlMap"),
        "validate_for_proxyless": S("validateForProxyless"),
    }
    fingerprint: Optional[str] = field(default=None)
    self_link_with_id: Optional[str] = field(default=None)
    url_map: Optional[str] = field(default=None)
    validate_for_proxyless: Optional[bool] = field(default=None)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if self.url_map:
            builder.dependant_node(self, clazz=GcpUrlMap, link=self.url_map)


@define(eq=False, slots=False)
class GcpTargetInstance(GcpResource):
    kind: ClassVar[str] = "gcp_target_instance"
    kind_display: ClassVar[str] = "GCP Target Instance"
    kind_description: ClassVar[str] = (
        "Target Instances in Google Cloud Platform are virtual machine instances that"
        " are used as forwarding targets for load balancing and traffic routing."
    )
    reference_kinds: ClassVar[ModelReference] = {
        "predecessors": {"default": ["gcp_network"], "delete": ["gcp_instance"]},
        "successors": {"default": ["gcp_instance"]},
    }
    api_spec: ClassVar[GcpApiSpec] = GcpApiSpec(
        service="compute",
        version="v1",
        accessors=["targetInstances"],
        action="aggregatedList",
        request_parameter={"project": "{project}"},
        request_parameter_in={"project"},
        response_path="items",
        response_regional_sub_path="targetInstances",
        mutate_iam_permissions=["compute.targetInstances.delete"],
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
        "instance": S("instance"),
        "nat_policy": S("natPolicy"),
        "network": S("network"),
    }
    instance: Optional[str] = field(default=None)
    nat_policy: Optional[str] = field(default=None)
    network: Optional[str] = field(default=None)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if self.network:
            builder.add_edge(self, reverse=True, clazz=GcpNetwork, link=self.network)
        if self.instance:
            builder.dependant_node(self, clazz=GcpInstance, link=self.instance)


@define(eq=False, slots=False)
class GcpTargetPool(GcpResource):
    kind: ClassVar[str] = "gcp_target_pool"
    kind_display: ClassVar[str] = "GCP Target Pool"
    kind_description: ClassVar[str] = (
        "Target Pools in Google Cloud Platform (GCP) are groups of instances that can"
        " receive traffic from a load balancer. They are used to distribute incoming"
        " requests across multiple backend instances."
    )
    reference_kinds: ClassVar[ModelReference] = {
        "predecessors": {"delete": ["gcp_http_health_check", "gcp_instance"]},
        "successors": {"delete": ["gcp_http_health_check", "gcp_instance"]},
    }
    api_spec: ClassVar[GcpApiSpec] = GcpApiSpec(
        service="compute",
        version="v1",
        accessors=["targetPools"],
        action="aggregatedList",
        request_parameter={"project": "{project}"},
        request_parameter_in={"project"},
        response_path="items",
        response_regional_sub_path="targetPools",
        mutate_iam_permissions=["compute.targetPools.delete", "compute.targetPools.update"],
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
        "backup_pool": S("backupPool"),
        "failover_ratio": S("failoverRatio"),
        "health_checks": S("healthChecks", default=[]),
        "instances": S("instances", default=[]),
        "session_affinity": S("sessionAffinity"),
    }
    backup_pool: Optional[str] = field(default=None)
    failover_ratio: Optional[float] = field(default=None)
    health_checks: Optional[List[str]] = field(default=None)
    instances: Optional[List[str]] = field(default=None)
    session_affinity: Optional[str] = field(default=None)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if self.instances:
            for instance in self.instances:
                builder.dependant_node(self, clazz=GcpInstance, link=instance)
        if self.health_checks:
            for check in self.health_checks:
                builder.dependant_node(self, clazz=health_check_types(), reverse=True, link=check)


@define(eq=False, slots=False)
class GcpTargetSslProxy(GcpResource):
    kind: ClassVar[str] = "gcp_target_ssl_proxy"
    kind_display: ClassVar[str] = "GCP Target SSL Proxy"
    kind_description: ClassVar[str] = (
        "A GCP Target SSL Proxy is a resource that terminates SSL/TLS traffic for a"
        " specific target HTTPS or SSL Proxy load balancing setup in Google Cloud"
        " Platform."
    )
    reference_kinds: ClassVar[ModelReference] = {
        "predecessors": {"delete": ["gcp_ssl_certificate", "gcp_backend_service"]},
        "successors": {"default": ["gcp_ssl_certificate", "gcp_backend_service"]},
    }
    api_spec: ClassVar[GcpApiSpec] = GcpApiSpec(
        service="compute",
        version="v1",
        accessors=["targetSslProxies"],
        action="list",
        request_parameter={"project": "{project}"},
        request_parameter_in={"project"},
        response_path="items",
        response_regional_sub_path=None,
        mutate_iam_permissions=["compute.targetSslProxies.delete", "compute.targetSslProxies.update"],
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
        "certificate_map": S("certificateMap"),
        "proxy_header": S("proxyHeader"),
        "service": S("service"),
        "ssl_certificates": S("sslCertificates", default=[]),
        "ssl_policy": S("sslPolicy"),
    }
    certificate_map: Optional[str] = field(default=None)
    proxy_header: Optional[str] = field(default=None)
    service: Optional[str] = field(default=None)
    ssl_certificates: Optional[List[str]] = field(default=None)
    ssl_policy: Optional[str] = field(default=None)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if self.ssl_certificates:
            for cert in self.ssl_certificates:
                builder.dependant_node(self, link=cert)
        if self.service:
            builder.dependant_node(self, clazz=GcpBackendService, link=self.service)


@define(eq=False, slots=False)
class GcpTargetVpnGateway(GcpResource):
    kind: ClassVar[str] = "gcp_target_vpn_gateway"
    kind_display: ClassVar[str] = "GCP Target VPN Gateway"
    kind_description: ClassVar[str] = (
        "Target VPN Gateway is a virtual private network (VPN) gateway that allows"
        " secure communication between on-premises networks and networks running on"
        " Google Cloud Platform (GCP)."
    )
    reference_kinds: ClassVar[ModelReference] = {
        "predecessors": {"default": ["gcp_network"], "delete": ["gcp_network"]},
    }
    api_spec: ClassVar[GcpApiSpec] = GcpApiSpec(
        service="compute",
        version="v1",
        accessors=["targetVpnGateways"],
        action="aggregatedList",
        request_parameter={"project": "{project}"},
        request_parameter_in={"project"},
        response_path="items",
        response_regional_sub_path="targetVpnGateways",
        mutate_iam_permissions=["compute.targetVpnGateways.delete"],
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
        "forwarding_rules": S("forwardingRules", default=[]),
        "network": S("network"),
        "status": S("status"),
        "tunnels": S("tunnels", default=[]),
    }
    forwarding_rules: Optional[List[str]] = field(default=None)
    network: Optional[str] = field(default=None)
    status: Optional[str] = field(default=None)
    tunnels: Optional[List[str]] = field(default=None)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if self.network:
            builder.dependant_node(self, reverse=True, delete_same_as_default=True, clazz=GcpNetwork, link=self.network)


@define(eq=False, slots=False)
class GcpVpnGatewayVpnGatewayInterface:
    kind: ClassVar[str] = "gcp_vpn_gateway_vpn_gateway_interface"
    kind_display: ClassVar[str] = "GCP VPN Gateway VPN Gateway Interface"
    kind_description: ClassVar[str] = (
        "The VPN Gateway Interface is a network interface used by the VPN Gateway in"
        " Google Cloud Platform to establish secure connections between on-premises"
        " networks and GCP virtual networks."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "interconnect_attachment": S("interconnectAttachment"),
        "ip_address": S("ipAddress"),
    }
    id: Optional[int] = field(default=None)
    interconnect_attachment: Optional[str] = field(default=None)
    ip_address: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpVpnGateway(GcpResource):
    kind: ClassVar[str] = "gcp_vpn_gateway"
    kind_display: ClassVar[str] = "GCP VPN Gateway"
    kind_description: ClassVar[str] = (
        "GCP VPN Gateway is a virtual private network (VPN) gateway on Google Cloud"
        " Platform that allows users to securely connect their on-premises network to"
        " their GCP network."
    )
    reference_kinds: ClassVar[ModelReference] = {
        "predecessors": {"default": ["gcp_network"], "delete": ["gcp_network"]},
        "successors": {"default": ["gcp_interconnect_attachment"]},
    }
    api_spec: ClassVar[GcpApiSpec] = GcpApiSpec(
        service="compute",
        version="v1",
        accessors=["vpnGateways"],
        action="aggregatedList",
        request_parameter={"project": "{project}"},
        request_parameter_in={"project"},
        response_path="items",
        response_regional_sub_path="vpnGateways",
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
        "network": S("network"),
        "stack_type": S("stackType"),
        "vpn_interfaces": S("vpnInterfaces", default=[]) >> ForallBend(GcpVpnGatewayVpnGatewayInterface.mapping),
    }
    network: Optional[str] = field(default=None)
    stack_type: Optional[str] = field(default=None)
    vpn_interfaces: Optional[List[GcpVpnGatewayVpnGatewayInterface]] = field(default=None)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if self.network:
            builder.dependant_node(self, reverse=True, delete_same_as_default=True, clazz=GcpNetwork, link=self.network)
        if self.vpn_interfaces:
            for interface in self.vpn_interfaces:
                if interface.interconnect_attachment:
                    builder.add_edge(self, clazz=GcpInterconnectAttachment, link=interface.interconnect_attachment)


@define(eq=False, slots=False)
class GcpVpnTunnel(GcpResource):
    kind: ClassVar[str] = "gcp_vpn_tunnel"
    kind_display: ClassVar[str] = "GCP VPN Tunnel"
    kind_description: ClassVar[str] = (
        "A GCP VPN Tunnel is a secure virtual connection that allows users to connect"
        " their on-premises network to their Google Cloud Platform (GCP) Virtual"
        " Private Cloud (VPC)."
    )
    reference_kinds: ClassVar[ModelReference] = {
        "successors": {
            "default": ["gcp_target_vpn_gateway", "gcp_vpn_gateway", "gcp_router"],
            "delete": ["gcp_target_vpn_gateway", "gcp_vpn_gateway"],
        }
    }
    api_spec: ClassVar[GcpApiSpec] = GcpApiSpec(
        service="compute",
        version="v1",
        accessors=["vpnTunnels"],
        action="aggregatedList",
        request_parameter={"project": "{project}"},
        request_parameter_in={"project"},
        response_path="items",
        response_regional_sub_path="vpnTunnels",
        mutate_iam_permissions=["compute.vpnTunnels.delete"],
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
        "detailed_status": S("detailedStatus"),
        "ike_version": S("ikeVersion"),
        "local_traffic_selector": S("localTrafficSelector", default=[]),
        "peer_external_gateway": S("peerExternalGateway"),
        "peer_external_gateway_interface": S("peerExternalGatewayInterface"),
        "peer_gcp_gateway": S("peerGcpGateway"),
        "peer_ip": S("peerIp"),
        "remote_traffic_selector": S("remoteTrafficSelector", default=[]),
        "router": S("router"),
        "shared_secret": S("sharedSecret"),
        "shared_secret_hash": S("sharedSecretHash"),
        "status": S("status"),
        "target_vpn_gateway": S("targetVpnGateway"),
        "vpn_gateway": S("vpnGateway"),
        "vpn_gateway_interface": S("vpnGatewayInterface"),
    }
    detailed_status: Optional[str] = field(default=None)
    ike_version: Optional[int] = field(default=None)
    local_traffic_selector: Optional[List[str]] = field(default=None)
    peer_external_gateway: Optional[str] = field(default=None)
    peer_external_gateway_interface: Optional[int] = field(default=None)
    peer_gcp_gateway: Optional[str] = field(default=None)
    peer_ip: Optional[str] = field(default=None)
    remote_traffic_selector: Optional[List[str]] = field(default=None)
    router: Optional[str] = field(default=None)
    shared_secret: Optional[str] = field(default=None)
    shared_secret_hash: Optional[str] = field(default=None)
    status: Optional[str] = field(default=None)
    target_vpn_gateway: Optional[str] = field(default=None)
    vpn_gateway: Optional[str] = field(default=None)
    vpn_gateway_interface: Optional[int] = field(default=None)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if self.target_vpn_gateway:
            builder.dependant_node(
                self, delete_same_as_default=True, clazz=GcpTargetVpnGateway, link=self.target_vpn_gateway
            )
        if self.vpn_gateway:
            builder.dependant_node(self, delete_same_as_default=True, clazz=GcpVpnGateway, link=self.vpn_gateway)
        if self.router:
            builder.add_edge(self, link=self.router)


resources = [
    GcpAcceleratorType,
    GcpAddress,
    GcpAutoscaler,
    GcpBackendBucket,
    GcpBackendService,
    GcpDiskType,
    GcpDisk,
    GcpExternalVpnGateway,
    # GcpFirewallPolicy, TODO: fix me
    GcpFirewall,
    GcpForwardingRule,
    GcpNetworkEndpointGroup,
    GcpOperation,
    GcpPublicDelegatedPrefix,
    GcpHealthCheck,
    GcpHttpHealthCheck,
    GcpHttpsHealthCheck,
    GcpImage,
    GcpInstanceGroupManager,
    GcpInstanceGroup,
    GcpInstanceTemplate,
    GcpInstance,
    GcpInterconnectAttachment,
    GcpInterconnectLocation,
    GcpInterconnect,
    GcpLicense,
    GcpMachineImage,
    GcpMachineType,
    GcpNetworkEdgeSecurityService,
    GcpNetwork,
    GcpNodeGroup,
    GcpNodeTemplate,
    GcpNodeType,
    GcpPacketMirroring,
    GcpPublicAdvertisedPrefix,
    GcpCommitment,
    GcpHealthCheckService,
    GcpNotificationEndpoint,
    GcpSecurityPolicy,
    GcpSslCertificate,
    GcpSslPolicy,
    GcpTargetHttpProxy,
    GcpTargetHttpsProxy,
    GcpTargetTcpProxy,
    GcpUrlMap,
    GcpResourcePolicy,
    GcpRouter,
    GcpRoute,
    GcpServiceAttachment,
    GcpSnapshot,
    GcpSubnetwork,
    GcpTargetGrpcProxy,
    GcpTargetInstance,
    GcpTargetPool,
    GcpTargetSslProxy,
    GcpTargetVpnGateway,
    GcpVpnGateway,
    GcpVpnTunnel,
]
