from datetime import datetime
from typing import ClassVar, Dict, List, Optional, Type

from attr import define, field

from resoto_plugin_aws.aws_client import AwsClient
from resoto_plugin_aws.resource.base import AwsApiSpec, AwsResource, GraphBuilder
from resoto_plugin_aws.utils import ToDict
from resotolib.baseresources import ModelReference
from resotolib.json import from_json
from resotolib.json_bender import K, S, Bend, Bender, ForallBend, bend
from resotolib.types import Json


@define(eq=False, slots=False)
class AwsCloudFrontAliases:
    kind: ClassVar[str] = "aws_cloudfront_aliases"
    mapping: ClassVar[Dict[str, Bender]] = {
        "quantity": S("Quantity"),
        "items": S("Items", default=[])
    }
    quantity: Optional[int] = field(default=None)
    items: List[str] = field(factory=list)

@define(eq=False, slots=False)
class AwsCloudFrontOriginCustomHeader:
    kind: ClassVar[str] = "aws_cloudfront_origin_custom_header"
    mapping: ClassVar[Dict[str, Bender]] = {
        "header_name": S("HeaderName"),
        "header_value": S("HeaderValue")
    }
    header_name: Optional[str] = field(default=None)
    header_value: Optional[str] = field(default=None)

@define(eq=False, slots=False)
class AwsCloudFrontCustomHeaders:
    kind: ClassVar[str] = "aws_cloudfront_custom_headers"
    mapping: ClassVar[Dict[str, Bender]] = {
        "quantity": S("Quantity"),
        "items": S("Items", default=[]) >> ForallBend(AwsCloudFrontOriginCustomHeader.mapping)
    }
    quantity: Optional[int] = field(default=None)
    items: List[AwsCloudFrontOriginCustomHeader] = field(factory=list)

@define(eq=False, slots=False)
class AwsCloudFrontOriginSslProtocols:
    kind: ClassVar[str] = "aws_cloudfront_origin_ssl_protocols"
    mapping: ClassVar[Dict[str, Bender]] = {
        "quantity": S("Quantity"),
        "items": S("Items", default=[])
    }
    quantity: Optional[int] = field(default=None)
    items: List[str] = field(factory=list)

@define(eq=False, slots=False)
class AwsCloudFrontCustomOriginConfig:
    kind: ClassVar[str] = "aws_cloudfront_custom_origin_config"
    mapping: ClassVar[Dict[str, Bender]] = {
        "http_port": S("HTTPPort"),
        "https_port": S("HTTPSPort"),
        "origin_protocol_policy": S("OriginProtocolPolicy"),
        "origin_ssl_protocols": S("OriginSslProtocols") >> Bend(AwsCloudFrontOriginSslProtocols.mapping),
        "origin_read_timeout": S("OriginReadTimeout"),
        "origin_keepalive_timeout": S("OriginKeepaliveTimeout")
    }
    http_port: Optional[int] = field(default=None)
    https_port: Optional[int] = field(default=None)
    origin_protocol_policy: Optional[str] = field(default=None)
    origin_ssl_protocols: Optional[AwsCloudFrontOriginSslProtocols] = field(default=None)
    origin_read_timeout: Optional[int] = field(default=None)
    origin_keepalive_timeout: Optional[int] = field(default=None)

@define(eq=False, slots=False)
class AwsCloudFrontOriginShield:
    kind: ClassVar[str] = "aws_cloudfront_origin_shield"
    mapping: ClassVar[Dict[str, Bender]] = {
        "enabled": S("Enabled"),
        "origin_shield_region": S("OriginShieldRegion")
    }
    enabled: Optional[bool] = field(default=None)
    origin_shield_region: Optional[str] = field(default=None)

@define(eq=False, slots=False)
class AwsCloudFrontOrigin:
    kind: ClassVar[str] = "aws_cloudfront_origin"
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("Id"),
        "domain_name": S("DomainName"),
        "origin_path": S("OriginPath"),
        "custom_headers": S("CustomHeaders") >> Bend(AwsCloudFrontCustomHeaders.mapping),
        "s3_origin_config": S("S3OriginConfig","OriginAccessIdentity"),
        "custom_origin_config": S("CustomOriginConfig") >> Bend(AwsCloudFrontCustomOriginConfig.mapping),
        "connection_attempts": S("ConnectionAttempts"),
        "connection_timeout": S("ConnectionTimeout"),
        "origin_shield": S("OriginShield") >> Bend(AwsCloudFrontOriginShield.mapping),
        "origin_access_control_id": S("OriginAccessControlId")
    }
    id: Optional[str] = field(default=None)
    domain_name: Optional[str] = field(default=None)
    origin_path: Optional[str] = field(default=None)
    custom_headers: Optional[AwsCloudFrontCustomHeaders] = field(default=None)
    s3_origin_config: Optional[str] = field(default=None)
    custom_origin_config: Optional[AwsCloudFrontCustomOriginConfig] = field(default=None)
    connection_attempts: Optional[int] = field(default=None)
    connection_timeout: Optional[int] = field(default=None)
    origin_shield: Optional[AwsCloudFrontOriginShield] = field(default=None)
    origin_access_control_id: Optional[str] = field(default=None)

@define(eq=False, slots=False)
class AwsCloudFrontOrigins:
    kind: ClassVar[str] = "aws_cloudfront_origins"
    mapping: ClassVar[Dict[str, Bender]] = {
        "quantity": S("Quantity"),
        "items": S("Items", default=[]) >> ForallBend(AwsCloudFrontOrigin.mapping)
    }
    quantity: Optional[int] = field(default=None)
    items: List[AwsCloudFrontOrigin] = field(factory=list)

@define(eq=False, slots=False)
class AwsCloudFrontStatusCodes:
    kind: ClassVar[str] = "aws_cloudfront_status_codes"
    mapping: ClassVar[Dict[str, Bender]] = {
        "quantity": S("Quantity"),
        "items": S("Items", default=[])
    }
    quantity: Optional[int] = field(default=None)
    items: List[int] = field(factory=list)

@define(eq=False, slots=False)
class AwsCloudFrontOriginGroupFailoverCriteria:
    kind: ClassVar[str] = "aws_cloudfront_origin_group_failover_criteria"
    mapping: ClassVar[Dict[str, Bender]] = {
        "status_codes": S("StatusCodes") >> Bend(AwsCloudFrontStatusCodes.mapping)
    }
    status_codes: Optional[AwsCloudFrontStatusCodes] = field(default=None)

@define(eq=False, slots=False)
class AwsCloudFrontOriginGroupMembers:
    kind: ClassVar[str] = "aws_cloudfront_origin_group_members"
    mapping: ClassVar[Dict[str, Bender]] = {
        "quantity": S("Quantity"),
        "items": S("Items", default=[]) >> ForallBend(S("OriginId"))
    }
    quantity: Optional[int] = field(default=None)
    items: List[str] = field(factory=list)

@define(eq=False, slots=False)
class AwsCloudFrontOriginGroup:
    kind: ClassVar[str] = "aws_cloudfront_origin_group"
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("Id"),
        "failover_criteria": S("FailoverCriteria") >> Bend(AwsCloudFrontOriginGroupFailoverCriteria.mapping),
        "members": S("Members") >> Bend(AwsCloudFrontOriginGroupMembers.mapping)
    }
    id: Optional[str] = field(default=None)
    failover_criteria: Optional[AwsCloudFrontOriginGroupFailoverCriteria] = field(default=None)
    members: Optional[AwsCloudFrontOriginGroupMembers] = field(default=None)

@define(eq=False, slots=False)
class AwsCloudFrontOriginGroups:
    kind: ClassVar[str] = "aws_cloudfront_origin_groups"
    mapping: ClassVar[Dict[str, Bender]] = {
        "quantity": S("Quantity"),
        "items": S("Items", default=[]) >> ForallBend(AwsCloudFrontOriginGroup.mapping)
    }
    quantity: Optional[int] = field(default=None)
    items: List[AwsCloudFrontOriginGroup] = field(factory=list)

@define(eq=False, slots=False)
class AwsCloudFrontTrustedSigners:
    kind: ClassVar[str] = "aws_cloudfront_trusted_signers"
    mapping: ClassVar[Dict[str, Bender]] = {
        "enabled": S("Enabled"),
        "quantity": S("Quantity"),
        "items": S("Items", default=[])
    }
    enabled: Optional[bool] = field(default=None)
    quantity: Optional[int] = field(default=None)
    items: List[str] = field(factory=list)

@define(eq=False, slots=False)
class AwsCloudFrontTrustedKeyGroups:
    kind: ClassVar[str] = "aws_cloudfront_trusted_key_groups"
    mapping: ClassVar[Dict[str, Bender]] = {
        "enabled": S("Enabled"),
        "quantity": S("Quantity"),
        "items": S("Items", default=[])
    }
    enabled: Optional[bool] = field(default=None)
    quantity: Optional[int] = field(default=None)
    items: List[str] = field(factory=list)

@define(eq=False, slots=False)
class AwsCloudFrontCachedMethods:
    kind: ClassVar[str] = "aws_cloudfront_cached_methods"
    mapping: ClassVar[Dict[str, Bender]] = {
        "quantity": S("Quantity"),
        "items": S("Items", default=[])
    }
    quantity: Optional[int] = field(default=None)
    items: List[str] = field(factory=list)

@define(eq=False, slots=False)
class AwsCloudFrontAllowedMethods:
    kind: ClassVar[str] = "aws_cloudfront_allowed_methods"
    mapping: ClassVar[Dict[str, Bender]] = {
        "quantity": S("Quantity"),
        "items": S("Items", default=[]),
        "cached_methods": S("CachedMethods") >> Bend(AwsCloudFrontCachedMethods.mapping)
    }
    quantity: Optional[int] = field(default=None)
    items: List[str] = field(factory=list)
    cached_methods: Optional[AwsCloudFrontCachedMethods] = field(default=None)

@define(eq=False, slots=False)
class AwsCloudFrontLambdaFunctionAssociation:
    kind: ClassVar[str] = "aws_cloudfront_lambda_function_association"
    mapping: ClassVar[Dict[str, Bender]] = {
        "lambda_function_arn": S("LambdaFunctionARN"),
        "event_type": S("EventType"),
        "include_body": S("IncludeBody")
    }
    lambda_function_arn: Optional[str] = field(default=None)
    event_type: Optional[str] = field(default=None)
    include_body: Optional[bool] = field(default=None)

@define(eq=False, slots=False)
class AwsCloudFrontLambdaFunctionAssociations:
    kind: ClassVar[str] = "aws_cloudfront_lambda_function_associations"
    mapping: ClassVar[Dict[str, Bender]] = {
        "quantity": S("Quantity"),
        "items": S("Items", default=[]) >> ForallBend(AwsCloudFrontLambdaFunctionAssociation.mapping)
    }
    quantity: Optional[int] = field(default=None)
    items: List[AwsCloudFrontLambdaFunctionAssociation] = field(factory=list)

@define(eq=False, slots=False)
class AwsCloudFrontFunctionAssociation:
    kind: ClassVar[str] = "aws_cloudfront_function_association"
    mapping: ClassVar[Dict[str, Bender]] = {
        "function_arn": S("FunctionARN"),
        "event_type": S("EventType")
    }
    function_arn: Optional[str] = field(default=None)
    event_type: Optional[str] = field(default=None)

@define(eq=False, slots=False)
class AwsCloudFrontFunctionAssociations:
    kind: ClassVar[str] = "aws_cloudfront_function_associations"
    mapping: ClassVar[Dict[str, Bender]] = {
        "quantity": S("Quantity"),
        "items": S("Items", default=[]) >> ForallBend(AwsCloudFrontFunctionAssociation.mapping)
    }
    quantity: Optional[int] = field(default=None)
    items: List[AwsCloudFrontFunctionAssociation] = field(factory=list)

@define(eq=False, slots=False)
class AwsCloudFrontCookieNames:
    kind: ClassVar[str] = "aws_cloudfront_cookie_names"
    mapping: ClassVar[Dict[str, Bender]] = {
        "quantity": S("Quantity"),
        "items": S("Items", default=[])
    }
    quantity: Optional[int] = field(default=None)
    items: List[str] = field(factory=list)

@define(eq=False, slots=False)
class AwsCloudFrontCookiePreference:
    kind: ClassVar[str] = "aws_cloudfront_cookie_preference"
    mapping: ClassVar[Dict[str, Bender]] = {
        "forward": S("Forward"),
        "whitelisted_names": S("WhitelistedNames") >> Bend(AwsCloudFrontCookieNames.mapping)
    }
    forward: Optional[str] = field(default=None)
    whitelisted_names: Optional[AwsCloudFrontCookieNames] = field(default=None)

@define(eq=False, slots=False)
class AwsCloudFrontHeaders:
    kind: ClassVar[str] = "aws_cloudfront_headers"
    mapping: ClassVar[Dict[str, Bender]] = {
        "quantity": S("Quantity"),
        "items": S("Items", default=[])
    }
    quantity: Optional[int] = field(default=None)
    items: List[str] = field(factory=list)

@define(eq=False, slots=False)
class AwsCloudFrontQueryStringCacheKeys:
    kind: ClassVar[str] = "aws_cloudfront_query_string_cache_keys"
    mapping: ClassVar[Dict[str, Bender]] = {
        "quantity": S("Quantity"),
        "items": S("Items", default=[])
    }
    quantity: Optional[int] = field(default=None)
    items: List[str] = field(factory=list)

@define(eq=False, slots=False)
class AwsCloudFrontForwardedValues:
    kind: ClassVar[str] = "aws_cloudfront_forwarded_values"
    mapping: ClassVar[Dict[str, Bender]] = {
        "query_string": S("QueryString"),
        "cookies": S("Cookies") >> Bend(AwsCloudFrontCookiePreference.mapping),
        "headers": S("Headers") >> Bend(AwsCloudFrontHeaders.mapping),
        "query_string_cache_keys": S("QueryStringCacheKeys") >> Bend(AwsCloudFrontQueryStringCacheKeys.mapping)
    }
    query_string: Optional[bool] = field(default=None)
    cookies: Optional[AwsCloudFrontCookiePreference] = field(default=None)
    headers: Optional[AwsCloudFrontHeaders] = field(default=None)
    query_string_cache_keys: Optional[AwsCloudFrontQueryStringCacheKeys] = field(default=None)

@define(eq=False, slots=False)
class AwsCloudFrontDefaultCacheBehavior:
    kind: ClassVar[str] = "aws_cloudfront_default_cache_behavior"
    mapping: ClassVar[Dict[str, Bender]] = {
        "target_origin_id": S("TargetOriginId"),
        "trusted_signers": S("TrustedSigners") >> Bend(AwsCloudFrontTrustedSigners.mapping),
        "trusted_key_groups": S("TrustedKeyGroups") >> Bend(AwsCloudFrontTrustedKeyGroups.mapping),
        "viewer_protocol_policy": S("ViewerProtocolPolicy"),
        "allowed_methods": S("AllowedMethods") >> Bend(AwsCloudFrontAllowedMethods.mapping),
        "smooth_streaming": S("SmoothStreaming"),
        "compress": S("Compress"),
        "lambda_function_associations": S("LambdaFunctionAssociations") >> Bend(AwsCloudFrontLambdaFunctionAssociations.mapping),
        "function_associations": S("FunctionAssociations") >> Bend(AwsCloudFrontFunctionAssociations.mapping),
        "field_level_encryption_id": S("FieldLevelEncryptionId"),
        "realtime_log_config_arn": S("RealtimeLogConfigArn"),
        "cache_policy_id": S("CachePolicyId"),
        "origin_request_policy_id": S("OriginRequestPolicyId"),
        "response_headers_policy_id": S("ResponseHeadersPolicyId"),
        "forwarded_values": S("ForwardedValues") >> Bend(AwsCloudFrontForwardedValues.mapping),
        "min_ttl": S("MinTTL"),
        "default_ttl": S("DefaultTTL"),
        "max_ttl": S("MaxTTL")
    }
    target_origin_id: Optional[str] = field(default=None)
    trusted_signers: Optional[AwsCloudFrontTrustedSigners] = field(default=None)
    trusted_key_groups: Optional[AwsCloudFrontTrustedKeyGroups] = field(default=None)
    viewer_protocol_policy: Optional[str] = field(default=None)
    allowed_methods: Optional[AwsCloudFrontAllowedMethods] = field(default=None)
    smooth_streaming: Optional[bool] = field(default=None)
    compress: Optional[bool] = field(default=None)
    lambda_function_associations: Optional[AwsCloudFrontLambdaFunctionAssociations] = field(default=None)
    function_associations: Optional[AwsCloudFrontFunctionAssociations] = field(default=None)
    field_level_encryption_id: Optional[str] = field(default=None)
    realtime_log_config_arn: Optional[str] = field(default=None)
    cache_policy_id: Optional[str] = field(default=None)
    origin_request_policy_id: Optional[str] = field(default=None)
    response_headers_policy_id: Optional[str] = field(default=None)
    forwarded_values: Optional[AwsCloudFrontForwardedValues] = field(default=None)
    min_ttl: Optional[int] = field(default=None)
    default_ttl: Optional[int] = field(default=None)
    max_ttl: Optional[int] = field(default=None)

@define(eq=False, slots=False)
class AwsCloudFrontCacheBehavior:
    kind: ClassVar[str] = "aws_cloudfront_cache_behavior"
    mapping: ClassVar[Dict[str, Bender]] = {
        "path_pattern": S("PathPattern"),
        "target_origin_id": S("TargetOriginId"),
        "trusted_signers": S("TrustedSigners") >> Bend(AwsCloudFrontTrustedSigners.mapping),
        "trusted_key_groups": S("TrustedKeyGroups") >> Bend(AwsCloudFrontTrustedKeyGroups.mapping),
        "viewer_protocol_policy": S("ViewerProtocolPolicy"),
        "allowed_methods": S("AllowedMethods") >> Bend(AwsCloudFrontAllowedMethods.mapping),
        "smooth_streaming": S("SmoothStreaming"),
        "compress": S("Compress"),
        "lambda_function_associations": S("LambdaFunctionAssociations") >> Bend(AwsCloudFrontLambdaFunctionAssociations.mapping),
        "function_associations": S("FunctionAssociations") >> Bend(AwsCloudFrontFunctionAssociations.mapping),
        "field_level_encryption_id": S("FieldLevelEncryptionId"),
        "realtime_log_config_arn": S("RealtimeLogConfigArn"),
        "cache_policy_id": S("CachePolicyId"),
        "origin_request_policy_id": S("OriginRequestPolicyId"),
        "response_headers_policy_id": S("ResponseHeadersPolicyId"),
        "forwarded_values": S("ForwardedValues") >> Bend(AwsCloudFrontForwardedValues.mapping),
        "min_ttl": S("MinTTL"),
        "default_ttl": S("DefaultTTL"),
        "max_ttl": S("MaxTTL")
    }
    path_pattern: Optional[str] = field(default=None)
    target_origin_id: Optional[str] = field(default=None)
    trusted_signers: Optional[AwsCloudFrontTrustedSigners] = field(default=None)
    trusted_key_groups: Optional[AwsCloudFrontTrustedKeyGroups] = field(default=None)
    viewer_protocol_policy: Optional[str] = field(default=None)
    allowed_methods: Optional[AwsCloudFrontAllowedMethods] = field(default=None)
    smooth_streaming: Optional[bool] = field(default=None)
    compress: Optional[bool] = field(default=None)
    lambda_function_associations: Optional[AwsCloudFrontLambdaFunctionAssociations] = field(default=None)
    function_associations: Optional[AwsCloudFrontFunctionAssociations] = field(default=None)
    field_level_encryption_id: Optional[str] = field(default=None)
    realtime_log_config_arn: Optional[str] = field(default=None)
    cache_policy_id: Optional[str] = field(default=None)
    origin_request_policy_id: Optional[str] = field(default=None)
    response_headers_policy_id: Optional[str] = field(default=None)
    forwarded_values: Optional[AwsCloudFrontForwardedValues] = field(default=None)
    min_ttl: Optional[int] = field(default=None)
    default_ttl: Optional[int] = field(default=None)
    max_ttl: Optional[int] = field(default=None)

@define(eq=False, slots=False)
class AwsCloudFrontCacheBehaviors:
    kind: ClassVar[str] = "aws_cloudfront_cache_behaviors"
    mapping: ClassVar[Dict[str, Bender]] = {
        "quantity": S("Quantity"),
        "items": S("Items", default=[]) >> ForallBend(AwsCloudFrontCacheBehavior.mapping)
    }
    quantity: Optional[int] = field(default=None)
    items: List[AwsCloudFrontCacheBehavior] = field(factory=list)

@define(eq=False, slots=False)
class AwsCloudFrontCustomErrorResponse:
    kind: ClassVar[str] = "aws_cloudfront_custom_error_response"
    mapping: ClassVar[Dict[str, Bender]] = {
        "error_code": S("ErrorCode"),
        "response_page_path": S("ResponsePagePath"),
        "response_code": S("ResponseCode"),
        "error_caching_min_ttl": S("ErrorCachingMinTTL")
    }
    error_code: Optional[int] = field(default=None)
    response_page_path: Optional[str] = field(default=None)
    response_code: Optional[str] = field(default=None)
    error_caching_min_ttl: Optional[int] = field(default=None)

@define(eq=False, slots=False)
class AwsCloudFrontCustomErrorResponses:
    kind: ClassVar[str] = "aws_cloudfront_custom_error_responses"
    mapping: ClassVar[Dict[str, Bender]] = {
        "quantity": S("Quantity"),
        "items": S("Items", default=[]) >> ForallBend(AwsCloudFrontCustomErrorResponse.mapping)
    }
    quantity: Optional[int] = field(default=None)
    items: List[AwsCloudFrontCustomErrorResponse] = field(factory=list)

@define(eq=False, slots=False)
class AwsCloudFrontViewerCertificate:
    kind: ClassVar[str] = "aws_cloudfront_viewer_certificate"
    mapping: ClassVar[Dict[str, Bender]] = {
        "cloudfront_default_certificate": S("CloudFrontDefaultCertificate"),
        "iam_certificate_id": S("IAMCertificateId"),
        "acm_certificate_arn": S("ACMCertificateArn"),
        "ssl_support_method": S("SSLSupportMethod"),
        "minimum_protocol_version": S("MinimumProtocolVersion"),
        "certificate": S("Certificate"),
        "certificate_source": S("CertificateSource")
    }
    cloudfront_default_certificate: Optional[bool] = field(default=None)
    iam_certificate_id: Optional[str] = field(default=None)
    acm_certificate_arn: Optional[str] = field(default=None)
    ssl_support_method: Optional[str] = field(default=None)
    minimum_protocol_version: Optional[str] = field(default=None)
    certificate: Optional[str] = field(default=None)
    certificate_source: Optional[str] = field(default=None)

@define(eq=False, slots=False)
class AwsCloudFrontGeoRestriction:
    kind: ClassVar[str] = "aws_cloudfront_geo_restriction"
    mapping: ClassVar[Dict[str, Bender]] = {
        "restriction_type": S("RestrictionType"),
        "quantity": S("Quantity"),
        "items": S("Items", default=[])
    }
    restriction_type: Optional[str] = field(default=None)
    quantity: Optional[int] = field(default=None)
    items: List[str] = field(factory=list)

@define(eq=False, slots=False)
class AwsCloudFrontRestrictions:
    kind: ClassVar[str] = "aws_cloudfront_restrictions"
    mapping: ClassVar[Dict[str, Bender]] = {
        "geo_restriction": S("GeoRestriction") >> Bend(AwsCloudFrontGeoRestriction.mapping)
    }
    geo_restriction: Optional[AwsCloudFrontGeoRestriction] = field(default=None)

@define(eq=False, slots=False)
class AwsCloudFrontAliasICPRecordal:
    kind: ClassVar[str] = "aws_cloudfront_alias_icp_recordal"
    mapping: ClassVar[Dict[str, Bender]] = {
        "cname": S("CNAME"),
        "icp_recordal_status": S("ICPRecordalStatus")
    }
    cname: Optional[str] = field(default=None)
    icp_recordal_status: Optional[str] = field(default=None)

@define(eq=False, slots=False)
class AwsCloudFrontDistribution(AwsResource):
    kind: ClassVar[str] = "aws_cloudfront_distribution"
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec("cloudfront", "list-distributions", "DistributionList")
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("Id"),
        "ctime": S("LastModifiedTime"),
        "mtime": K(None),
        "atime": K(None),
        "arn": S("ARN"),
        "distribution_status": S("Status"),
        "distribution_domain_name": S("DomainName"),
        "distribution_aliases": S("Aliases") >> Bend(AwsCloudFrontAliases.mapping),
        "distribution_origins": S("Origins") >> Bend(AwsCloudFrontOrigins.mapping),
        "distribution_origin_groups": S("OriginGroups") >> Bend(AwsCloudFrontOriginGroups.mapping),
        "distribution_default_cache_behavior": S("DefaultCacheBehavior") >> Bend(AwsCloudFrontDefaultCacheBehavior.mapping),
        "distribution_cache_behaviors": S("CacheBehaviors") >> Bend(AwsCloudFrontCacheBehaviors.mapping),
        "distribution_custom_error_responses": S("CustomErrorResponses") >> Bend(AwsCloudFrontCustomErrorResponses.mapping),
        "distribution_comment": S("Comment"),
        "distribution_price_class": S("PriceClass"),
        "distribution_enabled": S("Enabled"),
        "distribution_viewer_certificate": S("ViewerCertificate") >> Bend(AwsCloudFrontViewerCertificate.mapping),
        "distribution_restrictions": S("Restrictions") >> Bend(AwsCloudFrontRestrictions.mapping),
        "distribution_web_acl_id": S("WebACLId"),
        "distribution_http_version": S("HttpVersion"),
        "distribution_is_ipv6_enabled": S("IsIPV6Enabled"),
        "distribution_alias_icp_recordals": S("AliasICPRecordals", default=[]) >> ForallBend(AwsCloudFrontAliasICPRecordal.mapping)
    }
    distribution_status: Optional[str] = field(default=None)
    distribution_domain_name: Optional[str] = field(default=None)
    distribution_aliases: Optional[AwsCloudFrontAliases] = field(default=None)
    distribution_origins: Optional[AwsCloudFrontOrigins] = field(default=None)
    distribution_origin_groups: Optional[AwsCloudFrontOriginGroups] = field(default=None)
    distribution_default_cache_behavior: Optional[AwsCloudFrontDefaultCacheBehavior] = field(default=None)
    distribution_cache_behaviors: Optional[AwsCloudFrontCacheBehaviors] = field(default=None)
    distribution_custom_error_responses: Optional[AwsCloudFrontCustomErrorResponses] = field(default=None)
    distribution_comment: Optional[str] = field(default=None)
    distribution_price_class: Optional[str] = field(default=None)
    distribution_enabled: Optional[bool] = field(default=None)
    distribution_viewer_certificate: Optional[AwsCloudFrontViewerCertificate] = field(default=None)
    distribution_restrictions: Optional[AwsCloudFrontRestrictions] = field(default=None)
    distribution_web_acl_id: Optional[str] = field(default=None)
    distribution_http_version: Optional[str] = field(default=None)
    distribution_is_ipv6_enabled: Optional[bool] = field(default=None)
    distribution_alias_icp_recordals: List[AwsCloudFrontAliasICPRecordal] = field(factory=list)

    @classmethod
    def collect(cls: Type[AwsResource], json: List[Json], builder: GraphBuilder) -> None:
        for js in json["Items"]:
            instance = cls.from_api(js)
            builder.add_node(instance, js)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        #TODO lambda function
        #TODO cloudfront realtime log config
        #TODO acm certificate
        #TODO cloudfront origin access control
        #TODO response headers policy (and cache policy and origin request policy)
        #TODO iam certificate
        #TODO web acl
        #TODO field level encryption
        return super().connect_in_graph(builder, source)

    def delete_resource(self, client: AwsClient) -> bool:
        #TODO
        return super().delete_resource(client)


@define(eq=False, slots=False)
class AwsCloudFrontFunctionConfig:
    kind: ClassVar[str] = "aws_cloudfront_function_config"
    mapping: ClassVar[Dict[str, Bender]] = {
        "comment": S("Comment"),
        "runtime": S("Runtime")
    }
    comment: Optional[str] = field(default=None)
    runtime: Optional[str] = field(default=None)

@define(eq=False, slots=False)
class AwsCloudFrontFunctionMetadata:
    kind: ClassVar[str] = "aws_cloudfront_function_metadata"
    mapping: ClassVar[Dict[str, Bender]] = {
        "function_arn": S("FunctionARN"),
        "stage": S("Stage"),
        "created_time": S("CreatedTime"),
        "last_modified_time": S("LastModifiedTime")
    }
    function_arn: Optional[str] = field(default=None)
    stage: Optional[str] = field(default=None)
    created_time: Optional[datetime] = field(default=None)
    last_modified_time: Optional[datetime] = field(default=None)

@define(eq=False, slots=False)
class AwsCloudFrontFunction(AwsResource):
    kind: ClassVar[str] = "aws_cloudfront_function"
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec("cloudfront", "list-functions", "FunctionList")
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("Name"),
        # "tags": S("Tags", default=[]) >> ToDict(),
        "name": S("Name"),
        "ctime": K(None),
        "mtime": K(None),
        "atime": K(None),
        "function_status": S("Status"),
        "function_config": S("FunctionConfig") >> Bend(AwsCloudFrontFunctionConfig.mapping),
        "function_metadata": S("FunctionMetadata") >> Bend(AwsCloudFrontFunctionMetadata.mapping)
    }
    function_status: Optional[str] = field(default=None)
    function_config: Optional[AwsCloudFrontFunctionConfig] = field(default=None)
    function_metadata: Optional[AwsCloudFrontFunctionMetadata] = field(default=None)

    @classmethod
    def collect(cls: Type[AwsResource], json: List[Json], builder: GraphBuilder) -> None:
        for js in json["Items"]:
            instance = cls.from_api(js)
            builder.add_node(instance, js)


resources: List[Type[AwsResource]] = [AwsCloudFrontDistribution]
