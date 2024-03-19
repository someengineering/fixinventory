import logging
from typing import ClassVar, Dict, List, Optional, Type, Any

from attr import define, field
from boto3.exceptions import Boto3Error

from fix_plugin_aws.aws_client import AwsClient
from fix_plugin_aws.resource.acm import AwsAcmCertificate
from fix_plugin_aws.resource.base import AwsApiSpec, AwsResource, GraphBuilder
from fix_plugin_aws.resource.iam import AwsIamServerCertificate
from fix_plugin_aws.resource.lambda_ import AwsLambdaFunction
from fix_plugin_aws.resource.s3 import AwsS3Bucket
from fix_plugin_aws.resource.waf import AwsWafWebACL
from fix_plugin_aws.utils import ToDict
from fixlib.baseresources import ModelReference
from fixlib.graph import Graph
from fixlib.json_bender import S, Bend, Bender, ForallBend, bend
from fixlib.types import Json

log = logging.getLogger("fix.plugins.aws")
service_name = "cloudfront"


class CloudFrontResource:
    @classmethod
    def collect(cls: Type[AwsResource], json: List[Json], builder: GraphBuilder) -> None:  # type: ignore
        def add_tags(res: AwsResource) -> None:
            tags = builder.client.get(
                service_name, "list-tags-for-resource", "Tags", Resource=res.arn, expected_errors=["InvalidArgument"]
            )
            if tags:
                res.tags = bend(ToDict(), tags["Items"])

        for js in json:
            if instance := cls.from_api(js, builder):
                if instance.arn:
                    builder.submit_work(service_name, add_tags, instance)
                builder.add_node(instance, js)

    @staticmethod
    def delete_cloudfront_resource(client: AwsClient, resource: str, rid: str) -> bool:
        description = client.get(service_name, f"get-{resource}", None, None, Id=rid)
        if description:
            etag = description.get("ETag", None)
            if etag:
                client.call(
                    aws_service=service_name,
                    action=f"delete-{resource}",
                    result_name=None,
                    Id=rid,
                    IfMatch=etag,
                )
                return True
        return False


class CloudFrontTaggable:
    def update_resource_tag(self, client: AwsClient, key: str, value: str) -> bool:
        if isinstance(self, AwsResource):
            client.call(
                aws_service=service_name,
                action="tag-resource",
                result_name=None,
                Resource=self.arn,
                Tags={"Items": [{"Key": key, "Value": value}]},
            )
            return True
        return False

    def delete_resource_tag(self, client: AwsClient, key: str) -> bool:
        if isinstance(self, AwsResource):
            client.call(
                aws_service=service_name,
                action="untag-resource",
                result_name=None,
                Resource=self.arn,
                TagKeys={"Items": [key]},
            )
            return True
        return False

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return [
            AwsApiSpec(service_name, "tag-resource"),
            AwsApiSpec(service_name, "untag-resource"),
        ]


@define(eq=False, slots=False)
class AwsCloudFrontCustomOriginConfig:
    kind: ClassVar[str] = "aws_cloudfront_custom_origin_config"
    kind_display: ClassVar[str] = "AWS CloudFront Custom Origin Configuration"
    kind_description: ClassVar[str] = (
        "CloudFront Custom Origin Configuration allows users to customize the"
        " settings of the origin (source) server for their CloudFront distribution."
        " This includes specifying the origin server's domain name, port, and protocol"
        " settings."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "http_port": S("HTTPPort"),
        "https_port": S("HTTPSPort"),
        "origin_protocol_policy": S("OriginProtocolPolicy"),
        "origin_ssl_protocol": S("OriginSslProtocols", "Items", default=[]),
        "origin_read_timeout": S("OriginReadTimeout"),
        "origin_keepalive_timeout": S("OriginKeepaliveTimeout"),
    }
    http_port: Optional[int] = field(default=None)
    https_port: Optional[int] = field(default=None)
    origin_protocol_policy: Optional[str] = field(default=None)
    origin_ssl_protocol: List[str] = field(factory=list)
    origin_read_timeout: Optional[int] = field(default=None)
    origin_keepalive_timeout: Optional[int] = field(default=None)


@define(eq=False, slots=False)
class AwsCloudFrontOriginShield:
    kind: ClassVar[str] = "aws_cloudfront_origin_shield"
    kind_display: ClassVar[str] = "AWS CloudFront Origin Shield"
    kind_description: ClassVar[str] = (
        "CloudFront Origin Shield is a feature offered by AWS CloudFront that adds an"
        " additional layer of protection and reliability to the origin servers by"
        " caching the content at an intermediate layer."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"enabled": S("Enabled"), "origin_shield_region": S("OriginShieldRegion")}
    enabled: Optional[bool] = field(default=None)
    origin_shield_region: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsCloudFrontOrigin:
    kind: ClassVar[str] = "aws_cloudfront_origin"
    kind_display: ClassVar[str] = "AWS CloudFront Origin"
    kind_description: ClassVar[str] = (
        "CloudFront Origin represents the source of content for distribution through"
        " the Amazon CloudFront content delivery network."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("Id"),
        "domain_name": S("DomainName"),
        "origin_path": S("OriginPath"),
        "custom_header": S("CustomHeaders", "Items", default=[]) >> ToDict("HeaderName", "HeaderValue"),
        "s3_origin_config": S("S3OriginConfig", "OriginAccessIdentity"),
        "custom_origin_config": S("CustomOriginConfig") >> Bend(AwsCloudFrontCustomOriginConfig.mapping),
        "connection_attempts": S("ConnectionAttempts"),
        "connection_timeout": S("ConnectionTimeout"),
        "origin_shield": S("OriginShield") >> Bend(AwsCloudFrontOriginShield.mapping),
        "origin_access_control_id": S("OriginAccessControlId"),
    }
    id: Optional[str] = field(default=None)
    domain_name: Optional[str] = field(default=None)
    origin_path: Optional[str] = field(default=None)
    custom_header: Dict[str, str] = field(factory=list)
    s3_origin_config: Optional[str] = field(default=None)
    custom_origin_config: Optional[AwsCloudFrontCustomOriginConfig] = field(default=None)
    connection_attempts: Optional[int] = field(default=None)
    connection_timeout: Optional[int] = field(default=None)
    origin_shield: Optional[AwsCloudFrontOriginShield] = field(default=None)
    origin_access_control_id: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsCloudFrontOriginGroupFailoverCriteria:
    kind: ClassVar[str] = "aws_cloudfront_origin_group_failover_criteria"
    kind_display: ClassVar[str] = "AWS CloudFront Origin Group Failover Criteria"
    kind_description: ClassVar[str] = (
        "Failover criteria for AWS CloudFront origin groups, which determine when a"
        " secondary origin server is used as a fallback in case the primary origin"
        " server fails."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"status_codes": S("StatusCodes", "Items", default=[])}
    status_codes: List[str] = field(factory=list)


@define(eq=False, slots=False)
class AwsCloudFrontOriginGroupMembers:
    kind: ClassVar[str] = "aws_cloudfront_origin_group_members"
    kind_display: ClassVar[str] = "AWS CloudFront Origin Group Members"
    kind_description: ClassVar[str] = (
        "CloudFront Origin Group Members are the origin servers that are part of an"
        " Origin Group in AWS CloudFront. They serve as the source for content"
        " delivered by CloudFront distributions."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "origin_id": S("OriginId"),
    }
    origin_id: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsCloudFrontOriginGroup:
    kind: ClassVar[str] = "aws_cloudfront_origin_group"
    kind_display: ClassVar[str] = "AWS CloudFront Origin Group"
    kind_description: ClassVar[str] = (
        "An AWS CloudFront Origin Group is a collection of origins that you can"
        " associate with a distribution, allowing you to specify multiple origin"
        " resources for content delivery."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("Id"),
        "failover_criteria": S("FailoverCriteria") >> Bend(AwsCloudFrontOriginGroupFailoverCriteria.mapping),
        "members": S("Members", "Items", default=[]) >> ForallBend(AwsCloudFrontOriginGroupMembers.mapping),
    }
    id: Optional[str] = field(default=None)
    failover_criteria: Optional[AwsCloudFrontOriginGroupFailoverCriteria] = field(default=None)
    members: List[AwsCloudFrontOriginGroupMembers] = field(factory=list)


@define(eq=False, slots=False)
class AwsCloudFrontLambdaFunctionAssociation:
    kind: ClassVar[str] = "aws_cloudfront_lambda_function_association"
    kind_display: ClassVar[str] = "AWS CloudFront Lambda Function Association"
    kind_description: ClassVar[str] = (
        "CloudFront Lambda Function Association allows users to associate Lambda"
        " functions with CloudFront distributions, allowing them to modify the request"
        " or response and customize the content delivery process."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "lambda_function_arn": S("LambdaFunctionARN"),
        "event_type": S("EventType"),
        "include_body": S("IncludeBody"),
    }
    lambda_function_arn: Optional[str] = field(default=None)
    event_type: Optional[str] = field(default=None)
    include_body: Optional[bool] = field(default=None)


@define(eq=False, slots=False)
class AwsCloudFrontFunctionAssociation:
    kind: ClassVar[str] = "aws_cloudfront_function_association"
    kind_display: ClassVar[str] = "AWS CloudFront Function Association"
    kind_description: ClassVar[str] = (
        "CloudFront Function Association is a feature in Amazon CloudFront that"
        " allows associating a CloudFront function with a CloudFront distribution to"
        " modify the behavior of the distribution."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"function_arn": S("FunctionARN"), "event_type": S("EventType")}
    function_arn: Optional[str] = field(default=None)
    event_type: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsCloudFrontCookiePreference:
    kind: ClassVar[str] = "aws_cloudfront_cookie_preference"
    kind_display: ClassVar[str] = "AWS CloudFront Cookie Preference"
    kind_description: ClassVar[str] = (
        "AWS CloudFront Cookie Preference is a feature of Amazon CloudFront that"
        " enables users to specify how CloudFront handles cookies in the client"
        " request and response headers."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "forward": S("Forward"),
        "whitelisted_names": S("WhitelistedNames", "Items", default=[]),
    }
    forward: Optional[str] = field(default=None)
    whitelisted_names: List[str] = field(factory=list)


@define(eq=False, slots=False)
class AwsCloudFrontForwardedValues:
    kind: ClassVar[str] = "aws_cloudfront_forwarded_values"
    kind_display: ClassVar[str] = "AWS CloudFront Forwarded Values"
    kind_description: ClassVar[str] = (
        "CloudFront Forwarded Values allows you to customize how CloudFront handles"
        " and forwards specific HTTP headers in viewer requests to the origin."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "query_string": S("QueryString"),
        "cookies": S("Cookies") >> Bend(AwsCloudFrontCookiePreference.mapping),
        "headers": S("Headers", "Items", default=[]),
        "query_string_cache_keys": S("QueryStringCacheKeys", "Items", default=[]),
    }
    query_string: Optional[bool] = field(default=None)
    cookies: Optional[AwsCloudFrontCookiePreference] = field(default=None)
    headers: List[str] = field(factory=list)
    query_string_cache_keys: List[str] = field(factory=list)


@define(eq=False, slots=False)
class AwsCloudFrontDefaultCacheBehavior:
    kind: ClassVar[str] = "aws_cloudfront_default_cache_behavior"
    kind_display: ClassVar[str] = "AWS CloudFront Default Cache Behavior"
    kind_description: ClassVar[str] = (
        "CloudFront Default Cache Behavior is a configuration setting in AWS"
        " CloudFront that defines the default behavior for caching content on the edge"
        " locations."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "target_origin_id": S("TargetOriginId"),
        "trusted_signers": S("TrustedSigners", "Items", default=[]),
        "trusted_key_groups": S("TrustedKeyGroups", "Items", default=[]),
        "viewer_protocol_policy": S("ViewerProtocolPolicy"),
        "allowed_methods": S("AllowedMethods", "Items", default=[]),
        "smooth_streaming": S("SmoothStreaming"),
        "compress": S("Compress"),
        "lambda_function_associations": S("LambdaFunctionAssociations", "Items", default=[])
        >> ForallBend(AwsCloudFrontLambdaFunctionAssociation.mapping),
        "function_associations": S("FunctionAssociations", "Items", default=[])
        >> ForallBend(AwsCloudFrontFunctionAssociation.mapping),
        "field_level_encryption_id": S("FieldLevelEncryptionId"),
        "realtime_log_config_arn": S("RealtimeLogConfigArn"),
        "cache_policy_id": S("CachePolicyId"),
        "origin_request_policy_id": S("OriginRequestPolicyId"),
        "response_headers_policy_id": S("ResponseHeadersPolicyId"),
        "forwarded_values": S("ForwardedValues") >> Bend(AwsCloudFrontForwardedValues.mapping),
        "min_ttl": S("MinTTL"),
        "default_ttl": S("DefaultTTL"),
        "max_ttl": S("MaxTTL"),
    }
    target_origin_id: Optional[str] = field(default=None)
    trusted_signers: List[str] = field(factory=list)
    trusted_key_groups: List[str] = field(factory=list)
    viewer_protocol_policy: Optional[str] = field(default=None)
    allowed_methods: List[str] = field(factory=list)
    smooth_streaming: Optional[bool] = field(default=None)
    compress: Optional[bool] = field(default=None)
    lambda_function_associations: List[AwsCloudFrontLambdaFunctionAssociation] = field(factory=list)
    function_associations: List[AwsCloudFrontFunctionAssociation] = field(factory=list)
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
    kind_display: ClassVar[str] = "AWS CloudFront Cache Behavior"
    kind_description: ClassVar[str] = (
        "CloudFront Cache Behavior is a configuration setting that determines how"
        " CloudFront behaves when serving content from cache."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "path_pattern": S("PathPattern"),
        "target_origin_id": S("TargetOriginId"),
        "trusted_signers": S("TrustedSigners", "Items", default=[]),
        "trusted_key_groups": S("TrustedKeyGroups", "Items", default=[]),
        "viewer_protocol_policy": S("ViewerProtocolPolicy"),
        "allowed_methods": S("AllowedMethods", "Items", default=[]),
        "smooth_streaming": S("SmoothStreaming"),
        "compress": S("Compress"),
        "lambda_function_associations": S("LambdaFunctionAssociations", "Items", default=[])
        >> ForallBend(AwsCloudFrontLambdaFunctionAssociation.mapping),
        "function_associations": S("FunctionAssociations", "Items", default=[])
        >> ForallBend(AwsCloudFrontFunctionAssociation.mapping),
        "field_level_encryption_id": S("FieldLevelEncryptionId"),
        "realtime_log_config_arn": S("RealtimeLogConfigArn"),
        "cache_policy_id": S("CachePolicyId"),
        "origin_request_policy_id": S("OriginRequestPolicyId"),
        "response_headers_policy_id": S("ResponseHeadersPolicyId"),
        "forwarded_values": S("ForwardedValues") >> Bend(AwsCloudFrontForwardedValues.mapping),
        "min_ttl": S("MinTTL"),
        "default_ttl": S("DefaultTTL"),
        "max_ttl": S("MaxTTL"),
    }
    path_pattern: Optional[str] = field(default=None)
    target_origin_id: Optional[str] = field(default=None)
    trusted_signers: List[str] = field(factory=list)
    trusted_key_groups: List[str] = field(factory=list)
    viewer_protocol_policy: Optional[str] = field(default=None)
    allowed_methods: List[str] = field(factory=list)
    smooth_streaming: Optional[bool] = field(default=None)
    compress: Optional[bool] = field(default=None)
    lambda_function_associations: List[AwsCloudFrontLambdaFunctionAssociation] = field(factory=list)
    function_associations: List[AwsCloudFrontFunctionAssociation] = field(factory=list)
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
class AwsCloudFrontCustomErrorResponse:
    kind: ClassVar[str] = "aws_cloudfront_custom_error_response"
    kind_display: ClassVar[str] = "AWS CloudFront Custom Error Response"
    kind_description: ClassVar[str] = (
        "AWS CloudFront Custom Error Response allows users to customize the error"
        " responses for their CloudFront distributions, providing a more personalized"
        " and user-friendly experience for website visitors when errors occur."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "error_code": S("ErrorCode"),
        "response_page_path": S("ResponsePagePath"),
        "response_code": S("ResponseCode"),
        "error_caching_min_ttl": S("ErrorCachingMinTTL"),
    }
    error_code: Optional[int] = field(default=None)
    response_page_path: Optional[str] = field(default=None)
    response_code: Optional[str] = field(default=None)
    error_caching_min_ttl: Optional[int] = field(default=None)


@define(eq=False, slots=False)
class AwsCloudFrontViewerCertificate:
    kind: ClassVar[str] = "aws_cloudfront_viewer_certificate"
    kind_display: ClassVar[str] = "AWS CloudFront Viewer Certificate"
    kind_description: ClassVar[str] = (
        "AWS CloudFront Viewer Certificate is a SSL/TLS certificate that is used to"
        " encrypt the communication between the viewer (client) and the CloudFront"
        " distribution."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "cloudfront_default_certificate": S("CloudFrontDefaultCertificate"),
        "iam_certificate_id": S("IAMCertificateId"),
        "acm_certificate_arn": S("ACMCertificateArn"),
        "ssl_support_method": S("SSLSupportMethod"),
        "minimum_protocol_version": S("MinimumProtocolVersion"),
        "certificate": S("Certificate"),
        "certificate_source": S("CertificateSource"),
    }
    cloudfront_default_certificate: Optional[bool] = field(default=None)
    iam_certificate_id: Optional[str] = field(default=None)
    acm_certificate_arn: Optional[str] = field(default=None)
    ssl_support_method: Optional[str] = field(default=None)
    minimum_protocol_version: Optional[str] = field(default=None)
    certificate: Optional[str] = field(default=None)
    certificate_source: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsCloudFrontRestrictions:
    kind: ClassVar[str] = "aws_cloudfront_restrictions"
    kind_display: ClassVar[str] = "AWS CloudFront Restrictions"
    kind_description: ClassVar[str] = (
        "CloudFront Restrictions in AWS allow users to control access to their"
        " content by specifying the locations or IP addresses that are allowed to"
        " access it."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"geo_restriction": S("GeoRestriction", "Items", default=[])}
    geo_restriction: List[str] = field(factory=list)


@define(eq=False, slots=False)
class AwsCloudFrontAliasICPRecordal:
    kind: ClassVar[str] = "aws_cloudfront_alias_icp_recordal"
    kind_display: ClassVar[str] = "AWS CloudFront Alias ICP Recordal"
    kind_description: ClassVar[str] = (
        "AWS CloudFront Alias ICP Recordal is a feature that allows you to associate"
        " an Internet Content Provider (ICP) record with a CloudFront distribution in"
        " China."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"cname": S("CNAME"), "icp_recordal_status": S("ICPRecordalStatus")}
    cname: Optional[str] = field(default=None)
    icp_recordal_status: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsCloudFrontSigner:
    kind: ClassVar[str] = "aws_cloudfront_signer"
    mapping: ClassVar[Dict[str, Bender]] = {
        "aws_account_number": S("AwsAccountNumber"),
        "key_pair_ids": S("KeyPairIds", "Items"),
    }
    aws_account_number: Optional[str] = field(default=None, metadata={"description": "An Amazon Web Services account number that contains active CloudFront key pairs that CloudFront can use to verify the signatures of signed URLs and signed cookies. If the Amazon Web Services account that owns the key pairs is the same account that owns the CloudFront distribution, the value of this field is self."})  # fmt: skip
    key_pair_ids: Optional[List[str]] = field(default=None, metadata={"description": "A list of CloudFront key pair identifiers."})  # fmt: skip


@define(eq=False, slots=False)
class AwsCloudFrontActiveTrustedSigners:
    kind: ClassVar[str] = "aws_cloudfront_active_trusted_signers"
    mapping: ClassVar[Dict[str, Bender]] = {
        "enabled": S("Enabled"),
        "quantity": S("Quantity"),
        "items": S("Items", default=[]) >> ForallBend(AwsCloudFrontSigner.mapping),
    }
    enabled: Optional[bool] = field(default=None, metadata={"description": "This field is true if any of the Amazon Web Services accounts in the list are configured as trusted signers. If not, this field is false."})  # fmt: skip
    quantity: Optional[int] = field(default=None, metadata={"description": "The number of Amazon Web Services accounts in the list."})  # fmt: skip
    items: Optional[List[AwsCloudFrontSigner]] = field(factory=list, metadata={"description": "A list of Amazon Web Services accounts and the identifiers of active CloudFront key pairs in each account that CloudFront can use to verify the signatures of signed URLs and signed cookies."})  # fmt: skip


@define(eq=False, slots=False)
class AwsCloudFrontKGKeyPairIds:
    kind: ClassVar[str] = "aws_cloudfront_kg_key_pair_ids"
    mapping: ClassVar[Dict[str, Bender]] = {
        "key_group_id": S("KeyGroupId"),
        "key_pair_ids": S("KeyPairIds", "Items"),
    }
    key_group_id: Optional[str] = field(default=None, metadata={"description": "The identifier of the key group that contains the public keys."})  # fmt: skip
    key_pair_ids: Optional[List[str]] = field(default=None, metadata={"description": "A list of CloudFront key pair identifiers."})  # fmt: skip


@define(eq=False, slots=False)
class AwsCloudFrontActiveTrustedKeyGroups:
    kind: ClassVar[str] = "aws_cloudfront_active_trusted_key_groups"
    mapping: ClassVar[Dict[str, Bender]] = {
        "enabled": S("Enabled"),
        "quantity": S("Quantity"),
        "items": S("Items", default=[]) >> ForallBend(AwsCloudFrontKGKeyPairIds.mapping),
    }
    enabled: Optional[bool] = field(default=None, metadata={"description": "This field is true if any of the key groups have public keys that CloudFront can use to verify the signatures of signed URLs and signed cookies. If not, this field is false."})  # fmt: skip
    quantity: Optional[int] = field(default=None, metadata={"description": "The number of key groups in the list."})  # fmt: skip
    items: Optional[List[AwsCloudFrontKGKeyPairIds]] = field(factory=list, metadata={"description": "A list of key groups, including the identifiers of the public keys in each key group that CloudFront can use to verify the signatures of signed URLs and signed cookies."})  # fmt: skip


@define(eq=False, slots=False)
class AwsCloudFrontAllowedMethods:
    kind: ClassVar[str] = "aws_cloudfront_allowed_methods"
    mapping: ClassVar[Dict[str, Bender]] = {
        "quantity": S("Quantity"),
        "items": S("Items", default=[]),
        "cached_methods": S("CachedMethods", "Items"),
    }
    quantity: Optional[int] = field(default=None, metadata={"description": "The number of HTTP methods that you want CloudFront to forward to your origin. Valid values are 2 (for GET and HEAD requests), 3 (for GET, HEAD, and OPTIONS requests) and 7 (for GET, HEAD, OPTIONS, PUT, PATCH, POST, and DELETE requests)."})  # fmt: skip
    items: Optional[List[str]] = field(factory=list, metadata={"description": "A complex type that contains the HTTP methods that you want CloudFront to process and forward to your origin."})  # fmt: skip
    cached_methods: Optional[List[str]] = field(default=None, metadata={"description": "A complex type that controls whether CloudFront caches the response to requests using the specified HTTP methods. There are two choices:   CloudFront caches responses to GET and HEAD requests.   CloudFront caches responses to GET, HEAD, and OPTIONS requests."})  # fmt: skip


@define(eq=False, slots=False)
class AwsCloudFrontLoggingConfig:
    kind: ClassVar[str] = "aws_cloudfront_logging_config"
    mapping: ClassVar[Dict[str, Bender]] = {
        "enabled": S("Enabled"),
        "include_cookies": S("IncludeCookies"),
        "bucket": S("Bucket"),
        "prefix": S("Prefix"),
    }
    enabled: Optional[bool] = field(default=None, metadata={"description": "Specifies whether you want CloudFront to save access logs to an Amazon S3 bucket. If you don't want to enable logging when you create a distribution or if you want to disable logging for an existing distribution, specify false for Enabled, and specify empty Bucket and Prefix elements."})  # fmt: skip
    include_cookies: Optional[bool] = field(default=None, metadata={"description": "Specifies whether you want CloudFront to include cookies in access logs, specify true for IncludeCookies. If you choose to include cookies in logs, CloudFront logs all cookies regardless of how you configure the cache behaviors for this distribution."})  # fmt: skip
    bucket: Optional[str] = field(default=None, metadata={"description": "The Amazon S3 bucket to store the access logs in, for example, myawslogbucket.s3.amazonaws.com."})  # fmt: skip
    prefix: Optional[str] = field(default=None, metadata={"description": "An optional string that you want CloudFront to prefix to the access log filenames for this distribution, for example, myprefix/. If you want to enable logging, but you don't want to specify a prefix, you still must include an empty Prefix element in the Logging element."})  # fmt: skip


@define(eq=False, slots=False)
class AwsCloudFrontDistributionConfig:
    kind: ClassVar[str] = "aws_cloudfront_distribution_config"
    mapping: ClassVar[Dict[str, Bender]] = {
        "caller_reference": S("CallerReference"),
        "aliases": S("Aliases", "Items"),
        "default_root_object": S("DefaultRootObject"),
        "origins": S("Origins", "Items", default=[]) >> ForallBend(AwsCloudFrontOrigin.mapping),
        "origin_groups": S("OriginGroups", "Items", default=[]) >> ForallBend(AwsCloudFrontOriginGroup.mapping),
        "default_cache_behavior": S("DefaultCacheBehavior") >> Bend(AwsCloudFrontDefaultCacheBehavior.mapping),
        "cache_behaviors": S("CacheBehaviors", "Items", default=[]) >> ForallBend(AwsCloudFrontCacheBehavior.mapping),
        "custom_error_responses": S("CustomErrorResponses", "Items", default=[])
        >> ForallBend(AwsCloudFrontCustomErrorResponse.mapping),
        "comment": S("Comment"),
        "logging": S("Logging") >> Bend(AwsCloudFrontLoggingConfig.mapping),
        "price_class": S("PriceClass"),
        "enabled": S("Enabled"),
        "viewer_certificate": S("ViewerCertificate") >> Bend(AwsCloudFrontViewerCertificate.mapping),
        "restrictions": S("Restrictions") >> Bend(AwsCloudFrontRestrictions.mapping),
        "web_acl_id": S("WebACLId"),
        "http_version": S("HttpVersion"),
        "is_ipv6_enabled": S("IsIPV6Enabled"),
        "continuous_deployment_policy_id": S("ContinuousDeploymentPolicyId"),
        "staging": S("Staging"),
    }
    caller_reference: Optional[str] = field(default=None, metadata={"description": "A unique value (for example, a date-time stamp) that ensures that the request can't be replayed. If the value of CallerReference is new (regardless of the content of the DistributionConfig object), CloudFront creates a new distribution."})  # fmt: skip
    aliases: Optional[List[str]] = field(default=None, metadata={"description": "A complex type that contains information about CNAMEs (alternate domain names), if any, for this distribution."})  # fmt: skip
    default_root_object: Optional[str] = field(default=None, metadata={"description": "The object that you want CloudFront to request from your origin (for example, index.html) when a viewer requests the root URL for your distribution (https://www.example.com) instead of an object in your distribution (https://www.example.com/product-description.html)."})  # fmt: skip
    origins: Optional[List[AwsCloudFrontOrigin]] = field(default=None, metadata={"description": "A complex type that contains information about origins for this distribution."})  # fmt: skip
    origin_groups: Optional[List[AwsCloudFrontOriginGroup]] = field(default=None, metadata={"description": "A complex type that contains information about origin groups for this distribution."})  # fmt: skip
    default_cache_behavior: Optional[AwsCloudFrontDefaultCacheBehavior] = field(default=None, metadata={"description": "A complex type that describes the default cache behavior if you don't specify a CacheBehavior element or if files don't match any of the values of PathPattern in CacheBehavior elements. You must create exactly one default cache behavior."})  # fmt: skip
    cache_behaviors: Optional[List[AwsCloudFrontCacheBehavior]] = field(default=None, metadata={"description": "Optional: A complex type that contains cache behaviors for this distribution. If Quantity is 0, you can omit Items."})  # fmt: skip
    custom_error_responses: Optional[List[AwsCloudFrontCustomErrorResponse]] = field(default=None, metadata={"description": "A complex type that contains a CustomErrorResponse element for each HTTP status code for which you want to specify a custom error page and/or a caching duration."})  # fmt: skip
    comment: Optional[str] = field(default=None, metadata={"description": "A comment to describe the distribution. The comment cannot be longer than 128 characters."})  # fmt: skip
    logging: Optional[AwsCloudFrontLoggingConfig] = field(default=None, metadata={"description": "A complex type that controls whether access logs are written for the distribution. For more information about logging, see Access Logs in the Amazon CloudFront Developer Guide."})  # fmt: skip
    price_class: Optional[str] = field(default=None, metadata={"description": "The price class that corresponds with the maximum price that you want to pay for CloudFront service. If you specify PriceClass_All, CloudFront responds to requests for your objects from all CloudFront edge locations."})  # fmt: skip
    enabled: Optional[bool] = field(default=None, metadata={"description": "From this field, you can enable or disable the selected distribution."})  # fmt: skip
    viewer_certificate: Optional[AwsCloudFrontViewerCertificate] = field(default=None, metadata={"description": "A complex type that determines the distribution's SSL/TLS configuration for communicating with viewers."})  # fmt: skip
    restrictions: Optional[AwsCloudFrontRestrictions] = field(default=None, metadata={"description": "A complex type that identifies ways in which you want to restrict distribution of your content."})  # fmt: skip
    web_acl_id: Optional[str] = field(default=None, metadata={"description": "A unique identifier that specifies the WAF web ACL, if any, to associate with this distribution. To specify a web ACL created using the latest version of WAF, use the ACL ARN, for example arn:aws:wafv2:us-east-1:123456789012:global/webacl/ExampleWebACL/473e64fd-f30b-4765-81a0-62ad96dd167a."})  # fmt: skip
    http_version: Optional[str] = field(default=None, metadata={"description": "(Optional) Specify the maximum HTTP version(s) that you want viewers to use to communicate with CloudFront. The default value for new web distributions is http2. Viewers that don't support HTTP/2 automatically use an earlier HTTP version."})  # fmt: skip
    is_ipv6_enabled: Optional[bool] = field(default=None, metadata={"description": "If you want CloudFront to respond to IPv6 DNS requests with an IPv6 address for your distribution, specify true. If you specify false, CloudFront responds to IPv6 DNS requests with the DNS response code NOERROR and with no IP addresses."})  # fmt: skip
    continuous_deployment_policy_id: Optional[str] = field(default=None, metadata={"description": "The identifier of a continuous deployment policy. For more information, see CreateContinuousDeploymentPolicy."})  # fmt: skip
    staging: Optional[bool] = field(default=None, metadata={"description": "A Boolean that indicates whether this is a staging distribution. When this value is true, this is a staging distribution. When this value is false, this is not a staging distribution."})  # fmt: skip


@define(eq=False, slots=False)
class AwsCloudFrontDistribution(CloudFrontTaggable, CloudFrontResource, AwsResource):
    kind: ClassVar[str] = "aws_cloudfront_distribution"
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec("cloudfront", "get-distribution", "Distribution")
    aws_metadata: ClassVar[Dict[str, Any]] = {"provider_link_tpl": "https://{region_id}.console.aws.amazon.com/cloudfront/v4/home#/distributions/{id}", "arn_tpl": "arn:{partition}:cloudfront::{account}:distribution/{id}"}  # fmt: skip
    kind_display: ClassVar[str] = "AWS CloudFront Distribution"
    kind_description: ClassVar[str] = (
        "CloudFront Distributions are a content delivery network (CDN) offered by"
        " Amazon Web Services, which enables users to deliver their content to end-"
        " users with low latency and high transfer speeds."
    )
    reference_kinds: ClassVar[ModelReference] = {
        "predecessors": {"delete": ["aws_lambda_function"]},
        "successors": {
            "default": [
                "aws_acm_certificate",
                "aws_cloudfront_cache_policy",
                "aws_cloudfront_field_level_encryption_config",
                "aws_cloudfront_function",
                "aws_cloudfront_origin_access_control",
                "aws_cloudfront_realtime_log_config",
                "aws_cloudfront_response_headers_policy",
                "aws_iam_server_certificate",
                "aws_lambda_function",
                "aws_s3_bucket",
                "aws_waf_web_acl",
            ]
        },
    }
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("Id"),
        "tags": S("Tags", default=[]) >> ToDict(),
        "name": S("DomainName"),
        "mtime": S("LastModifiedTime"),
        "arn": S("ARN"),
        "distribution_status": S("Status"),
        "distribution_in_progress_invalidation_batches": S("InProgressInvalidationBatches"),
        "distribution_active_trusted_signers": S("ActiveTrustedSigners")
        >> Bend(AwsCloudFrontActiveTrustedSigners.mapping),
        "distribution_active_trusted_key_groups": S("ActiveTrustedKeyGroups")
        >> Bend(AwsCloudFrontActiveTrustedKeyGroups.mapping),
        "distribution_config": S("DistributionConfig") >> Bend(AwsCloudFrontDistributionConfig.mapping),
        "distribution_alias_icp_recordals": S("AliasICPRecordals", default=[])
        >> ForallBend(AwsCloudFrontAliasICPRecordal.mapping),
    }
    distribution_status: Optional[str] = field(default=None, metadata={"description": "The distribution's status. When the status is Deployed, the distribution's information is fully propagated to all CloudFront edge locations."})  # fmt: skip
    distribution_in_progress_invalidation_batches: Optional[int] = field(default=None, metadata={"description": "The number of invalidation batches currently in progress."})  # fmt: skip
    distribution_active_trusted_signers: Optional[AwsCloudFrontActiveTrustedSigners] = field(default=None, metadata={"description": "We recommend using TrustedKeyGroups instead of TrustedSigners."})  # fmt: skip
    distribution_active_trusted_key_groups: Optional[AwsCloudFrontActiveTrustedKeyGroups] = field(default=None, metadata={"description": "This field contains a list of key groups and the public keys in each key group that CloudFront can use to verify the signatures of signed URLs or signed cookies."})  # fmt: skip
    distribution_config: Optional[AwsCloudFrontDistributionConfig] = field(default=None, metadata={"description": "The distribution's configuration."})  # fmt: skip
    distribution_alias_icp_recordals: Optional[List[AwsCloudFrontAliasICPRecordal]] = field(factory=list, metadata={"description": "Amazon Web Services services in China customers must file for an Internet Content Provider (ICP) recordal if they want to serve content publicly on an alternate domain name, also known as a CNAME, that they've added to CloudFront."})  # fmt: skip

    @classmethod
    def collect_resources(cls: Type[AwsResource], builder: GraphBuilder) -> None:
        def fetch_distribution(did: str) -> None:
            with builder.suppress(f"{service_name}.get-distribution"):
                if js := builder.client.get(service_name, "get-distribution", "Distribution", Id=did):
                    AwsCloudFrontDistribution.collect([js], builder)

        # Default behavior: in case the class has an ApiSpec, call the api and call collect.
        log.debug(f"Collecting {cls.__name__} in region {builder.region.name}")
        try:
            for item in builder.client.list(
                aws_service=service_name, action="list-distributions", result_name="DistributionList.Items"
            ):
                builder.submit_work(service_name, fetch_distribution, item["Id"])
            if builder.config.collect_usage_metrics:
                try:
                    cls.collect_usage_metrics(builder)
                except Exception as e:
                    log.warning(f"Failed to collect usage metrics for {cls.__name__}: {e}")
        except Boto3Error as e:
            msg = f"Error while collecting {cls.__name__} in region {builder.region.name}: {e}"
            builder.core_feedback.error(msg, log)
            raise
        except Exception as e:
            msg = f"Error while collecting {cls.__name__} in region {builder.region.name}: {e}"
            builder.core_feedback.info(msg, log)
            raise

    @classmethod
    def called_collect_apis(cls) -> List[AwsApiSpec]:
        return super().called_mutator_apis() + [
            AwsApiSpec(service_name, "get-distribution"),
            AwsApiSpec(service_name, "list-distributions"),
        ]

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return super().called_mutator_apis() + [
            AwsApiSpec(service_name, "get-distribution-config"),
            AwsApiSpec(service_name, "update-distribution"),
            AwsApiSpec(service_name, "get-distribution"),
            AwsApiSpec(service_name, "delete-distribution"),
        ]

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if cfg := self.distribution_config:
            # edges from default cache behavior
            if dcb := cfg.default_cache_behavior:
                for a in dcb.lambda_function_associations:
                    builder.dependant_node(self, clazz=AwsLambdaFunction, arn=a.lambda_function_arn)
                for b in dcb.function_associations:
                    builder.add_edge(self, clazz=AwsCloudFrontFunction, arn=b.function_arn)
                if dcb.realtime_log_config_arn:
                    builder.add_edge(self, clazz=AwsCloudFrontRealtimeLogConfig, arn=dcb.realtime_log_config_arn)
                if dcb.field_level_encryption_id:
                    builder.add_edge(
                        self, clazz=AwsCloudFrontFieldLevelEncryptionConfig, id=dcb.field_level_encryption_id
                    )
                if dcb.response_headers_policy_id:
                    builder.add_edge(self, clazz=AwsCloudFrontResponseHeadersPolicy, id=dcb.response_headers_policy_id)
                if dcb.cache_policy_id:
                    builder.add_edge(self, clazz=AwsCloudFrontCachePolicy, id=dcb.cache_policy_id)

            # edges from other cache behaviors
            for cb_item in cfg.cache_behaviors or []:
                for c in cb_item.lambda_function_associations:
                    builder.add_edge(self, clazz=AwsLambdaFunction, arn=c.lambda_function_arn)
                for d in cb_item.function_associations:
                    builder.add_edge(self, clazz=AwsCloudFrontFunction, arn=d.function_arn)
                if cb_item.field_level_encryption_id:
                    builder.add_edge(
                        self, clazz=AwsCloudFrontFieldLevelEncryptionConfig, id=cb_item.field_level_encryption_id
                    )
                if cb_item.realtime_log_config_arn:
                    builder.add_edge(self, clazz=AwsCloudFrontRealtimeLogConfig, arn=cb_item.realtime_log_config_arn)
                if cb_item.cache_policy_id:
                    builder.add_edge(self, clazz=AwsCloudFrontCachePolicy, id=cb_item.cache_policy_id)
                if cb_item.response_headers_policy_id:
                    builder.add_edge(
                        self, clazz=AwsCloudFrontResponseHeadersPolicy, id=cb_item.response_headers_policy_id
                    )

            # other edges
            for entry in cfg.origins or []:
                builder.add_edge(self, clazz=AwsCloudFrontOriginAccessControl, id=entry.origin_access_control_id)
                builder.add_edge(self, clazz=AwsS3Bucket, name=entry.id)

            if cfg.viewer_certificate and (cid := cfg.viewer_certificate.iam_certificate_id):
                builder.add_edge(self, clazz=AwsIamServerCertificate, id=cid)

            if cfg.web_acl_id:
                builder.add_edge(self, clazz=AwsWafWebACL, arn=cfg.web_acl_id)

            if (cert := cfg.viewer_certificate) and (arn := cert.acm_certificate_arn):
                builder.add_edge(self, clazz=AwsAcmCertificate, arn=arn)

    def pre_delete_resource(self, client: AwsClient, _: Graph) -> bool:
        dist_config = client.get(service_name, "get-distribution-config", None, None, Id=self.id)
        if dist_config:
            dist_config["DistributionConfig"]["Enabled"] = False
            dist_config["IfMatch"] = dist_config["ETag"]
            dist_config.pop("ETag")
            update = client.call(
                service_name,
                "update-distribution",
                None,
                None,
                DistributionConfig=dist_config["DistributionConfig"],
                Id=self.id,
                IfMatch=dist_config["IfMatch"],
            )
            if update:
                return True
        return False

    def delete_resource(self, client: AwsClient, graph: Graph) -> bool:
        return self.delete_cloudfront_resource(client, "distribution", self.id)


@define(eq=False, slots=False)
class AwsCloudFrontFunctionConfig:
    kind: ClassVar[str] = "aws_cloudfront_function_config"
    kind_display: ClassVar[str] = "AWS CloudFront Function Config"
    kind_description: ClassVar[str] = (
        "CloudFront Function Config is a configuration for a CloudFront function in"
        " the AWS CloudFront service, which allows users to run custom code at the"
        " edge locations of the CloudFront CDN to modify the content delivery"
        " behavior."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"comment": S("Comment"), "runtime": S("Runtime")}
    comment: Optional[str] = field(default=None)
    runtime: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsCloudFrontFunction(CloudFrontTaggable, CloudFrontResource, AwsResource):
    kind: ClassVar[str] = "aws_cloudfront_function"
    kind_display: ClassVar[str] = "AWS CloudFront Function"
    aws_metadata: ClassVar[Dict[str, Any]] = {"provider_link_tpl": "https://{region_id}.console.aws.amazon.com/cloudfront/v3/home?region={region}#/functions/{name}", "arn_tpl": "arn:{partition}:cloudfront:{region}:{account}:function/{name}"}  # fmt: skip
    kind_description: ClassVar[str] = (
        "CloudFront Functions are serverless functions that allow developers to"
        " customize and extend the functionality of CloudFront content delivery"
        " network, enabling advanced edge processing of HTTP requests and responses."
    )
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec(
        service_name, "list-functions", "FunctionList.Items", parameter={"Stage": "LIVE"}
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("Name"),
        "arn": S("FunctionMetadata", "FunctionARN", default=None),
        "name": S("Name"),
        "ctime": S("FunctionMetadata", "CreatedTime", default=None),
        "mtime": S("FunctionMetadata", "LastModifiedTime", default=None),
        "function_status": S("Status"),
        "function_stage": S("FunctionMetadata", "Stage", default=None),
        "function_config": S("FunctionConfig") >> Bend(AwsCloudFrontFunctionConfig.mapping),
    }
    function_status: Optional[str] = field(default=None)
    function_stage: Optional[str] = field(default=None)
    function_config: Optional[AwsCloudFrontFunctionConfig] = field(default=None)

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return super().called_mutator_apis() + [
            AwsApiSpec(service_name, "describe-function"),
            AwsApiSpec(service_name, "delete-function"),
        ]

    def delete_resource(self, client: AwsClient, graph: Graph) -> bool:
        description = client.get(
            self.api_spec.service, "describe-function", None, None, Name=self.name, Stage=self.function_stage
        )
        if description:
            etag = description.get("ETag", None)
            if etag:
                client.call(
                    aws_service=self.api_spec.service,
                    action="delete-function",
                    result_name=None,
                    Name=self.name,
                    IfMatch=etag,
                )
                return True
        return False


@define(eq=False, slots=False)
class AwsCloudFrontPublicKey(CloudFrontResource, AwsResource):
    kind: ClassVar[str] = "aws_cloudfront_public_key"
    kind_display: ClassVar[str] = "AWS CloudFront Public Key"
    aws_metadata: ClassVar[Dict[str, Any]] = {"provider_link_tpl": "https://{region_id}.console.aws.amazon.com/cloudfront/v4/home?region={region}#/publickey/edit/{id}", "arn_tpl": "arn:{partition}:cloudfront:{region}:{account}:public-key/{id}"}  # fmt: skip
    kind_description: ClassVar[str] = (
        "AWS CloudFront Public Key is a public key used in conjunction with a private key for managing the"
        " identity of the content distributors and validating access to content served by AWS CloudFront."
    )
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec(service_name, "list-public-keys", "PublicKeyList.Items")
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("Id"),
        "name": S("Name"),
        "ctime": S("CreatedTime"),
        "public_key_encoded_key": S("EncodedKey"),
        "public_key_comment": S("Comment"),
    }
    public_key_encoded_key: Optional[str] = field(default=None)
    public_key_comment: Optional[str] = field(default=None)

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return super().called_mutator_apis() + [
            AwsApiSpec(service_name, "get-public-key"),
            AwsApiSpec(service_name, "delete-public-key"),
        ]

    def delete_resource(self, client: AwsClient, graph: Graph) -> bool:
        return self.delete_cloudfront_resource(client, "public-key", self.id)


@define(eq=False, slots=False)
class AwsCloudFrontKinesisStreamConfig:
    kind: ClassVar[str] = "aws_cloudfront_kinesis_stream_config"
    kind_display: ClassVar[str] = "AWS CloudFront Kinesis Stream Config"
    kind_description: ClassVar[str] = (
        "The AWS CloudFront Kinesis Stream Config allows users to configure the"
        " integration between CloudFront and Kinesis Streams, enabling real-time data"
        " streaming and processing."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"role_arn": S("RoleARN"), "stream_arn": S("StreamARN")}
    role_arn: Optional[str] = field(default=None)
    stream_arn: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsCloudFrontEndPoint:
    kind: ClassVar[str] = "aws_cloudfront_end_point"
    kind_display: ClassVar[str] = "AWS CloudFront End Point"
    kind_description: ClassVar[str] = (
        "An AWS CloudFront End Point is the DNS domain name that CloudFront assigns when you create a distribution."
        " You use this domain name in all URLs for your files."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "stream_type": S("StreamType"),
        "kinesis_stream_config": S("KinesisStreamConfig") >> Bend(AwsCloudFrontKinesisStreamConfig.mapping),
    }
    stream_type: Optional[str] = field(default=None)
    kinesis_stream_config: Optional[AwsCloudFrontKinesisStreamConfig] = field(default=None)


@define(eq=False, slots=False)
class AwsCloudFrontRealtimeLogConfig(CloudFrontTaggable, CloudFrontResource, AwsResource):
    kind: ClassVar[str] = "aws_cloudfront_realtime_log_config"
    kind_display: ClassVar[str] = "AWS CloudFront Real-time Log Configuration"
    aws_metadata: ClassVar[Dict[str, Any]] = {"provider_link_tpl": "https://{region_id}.console.aws.amazon.com/cloudfront/v4/home?region={region}#/logs/realtime/{name}", "arn_tpl": "arn:{partition}:cloudfront:{region}:{account}:real-time-log-config/{id}"}  # fmt: skip
    kind_description: ClassVar[str] = (
        "CloudFront Real-time Log Configuration allows you to configure real-time"
        " logging for your CloudFront distribution, enabling you to receive real-time"
        " logs for your web traffic."
    )
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec(service_name, "list-realtime-log-configs", "RealtimeLogConfigs.Items")
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("Name"),
        "name": S("Name"),
        "arn": S("ARN"),
        "realtime_log_sampling_rate": S("SamplingRate"),
        "realtime_log_end_points": S("EndPoints", default=[]) >> ForallBend(AwsCloudFrontEndPoint.mapping),
        "realtime_log_fields": S("Fields", default=[]),
    }
    realtime_log_sampling_rate: Optional[int] = field(default=None)
    realtime_log_end_points: List[AwsCloudFrontEndPoint] = field(factory=list)
    realtime_log_fields: List[str] = field(factory=list)

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return super().called_mutator_apis() + [AwsApiSpec(service_name, "delete-realtime-log-config")]

    def delete_resource(self, client: AwsClient, graph: Graph) -> bool:
        client.call(
            aws_service=self.api_spec.service, action="delete-realtime-log-config", result_name=None, Name=self.name
        )
        return True


@define(eq=False, slots=False)
class AwsCloudFrontResponseHeadersPolicyCorsConfig:
    kind: ClassVar[str] = "aws_cloudfront_response_headers_policy_cors_config"
    kind_display: ClassVar[str] = "AWS CloudFront Response Headers Policy CORS Config"
    kind_description: ClassVar[str] = (
        "The AWS CloudFront Response Headers Policy CORS (Cross-Origin Resource"
        " Sharing) Config allows users to specify how CloudFront should handle CORS"
        " headers in the response for a specific CloudFront distribution."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "access_control_allow_origins": S("AccessControlAllowOrigins", "Items", default=[]),
        "access_control_allow_headers": S("AccessControlAllowHeaders", "Items", default=[]),
        "access_control_allow_methods": S("AccessControlAllowMethods", "Items", default=[]),
        "access_control_allow_credentials": S("AccessControlAllowCredentials"),
        "access_control_expose_headers": S("AccessControlExposeHeaders", "Items", default=[]),
        "access_control_max_age_sec": S("AccessControlMaxAgeSec"),
        "origin_override": S("OriginOverride"),
    }
    access_control_allow_origins: List[str] = field(factory=list)
    access_control_allow_headers: List[str] = field(factory=list)
    access_control_allow_methods: List[str] = field(factory=list)
    access_control_allow_credentials: Optional[bool] = field(default=None)
    access_control_expose_headers: List[str] = field(factory=list)
    access_control_max_age_sec: Optional[int] = field(default=None)
    origin_override: Optional[bool] = field(default=None)


@define(eq=False, slots=False)
class AwsCloudFrontResponseHeadersPolicyXSSProtection:
    kind: ClassVar[str] = "aws_cloudfront_response_headers_policy_xss_protection"
    kind_display: ClassVar[str] = "AWS CloudFront Response Headers Policy XSS Protection"
    kind_description: ClassVar[str] = (
        "AWS CloudFront Response Headers Policy XSS Protection are settings within the policy that control the"
        " `X-XSS-Protection` header, which can be used to enable a browser's built-in cross-site scripting (XSS)"
        " filters to prevent and mitigate XSS attacks on web content served through CloudFront."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "override": S("Override"),
        "protection": S("Protection"),
        "mode_block": S("ModeBlock"),
        "report_uri": S("ReportUri"),
    }
    override: Optional[bool] = field(default=None)
    protection: Optional[bool] = field(default=None)
    mode_block: Optional[bool] = field(default=None)
    report_uri: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsCloudFrontResponseHeadersPolicyFrameOptions:
    kind: ClassVar[str] = "aws_cloudfront_response_headers_policy_frame_options"
    kind_display: ClassVar[str] = "AWS CloudFront Response Headers Policy Frame Options"
    kind_description: ClassVar[str] = (
        "AWS CloudFront Response Headers Policy Frame Options within a response headers policy dictate how browsers"
        " should handle the framing of pages, typically used to configure the `X-Frame-Options` header for"
        " clickjacking protection by specifying whether content can be displayed within frames and under"
        " what conditions."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"override": S("Override"), "frame_option": S("FrameOption")}
    override: Optional[bool] = field(default=None)
    frame_option: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsCloudFrontResponseHeadersPolicyReferrerPolicy:
    kind: ClassVar[str] = "aws_cloudfront_response_headers_policy_referrer_policy"
    kind_display: ClassVar[str] = "AWS CloudFront Response Headers Policy Referrer Policy"
    kind_description: ClassVar[str] = (
        "The Referrer Policy in CloudFront determines how the browser should send the"
        " 'Referer' HTTP header when making requests to CloudFront distributions."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"override": S("Override"), "referrer_policy": S("ReferrerPolicy")}
    override: Optional[bool] = field(default=None)
    referrer_policy: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsCloudFrontResponseHeadersPolicyContentSecurityPolicy:
    kind: ClassVar[str] = "aws_cloudfront_response_headers_policy_content_security_policy"
    kind_display: ClassVar[str] = "AWS CloudFront Response Headers Policy - Content-Security-Policy"
    kind_description: ClassVar[str] = (
        "The AWS CloudFront Response Headers Policy - Content-Security-Policy allows"
        " users to define the content security policy (CSP) for their CloudFront"
        " distributions, specifying which content sources are allowed and disallowed."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "override": S("Override"),
        "content_security_policy": S("ContentSecurityPolicy"),
    }
    override: Optional[bool] = field(default=None)
    content_security_policy: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsCloudFrontResponseHeadersPolicyStrictTransportSecurity:
    kind: ClassVar[str] = "aws_cloudfront_response_headers_policy_strict_transport_security"
    kind_display: ClassVar[str] = "AWS CloudFront Response Headers Policy - Strict Transport Security"
    kind_description: ClassVar[str] = (
        "The AWS CloudFront Response Headers Policy - Strict Transport Security is a"
        " security feature that enables websites to declare that their content should"
        " only be accessed over HTTPS, and defines the duration for which the browser"
        " should automatically choose HTTPS for subsequent requests."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "override": S("Override"),
        "include_subdomains": S("IncludeSubdomains"),
        "preload": S("Preload"),
        "access_control_max_age_sec": S("AccessControlMaxAgeSec"),
    }
    override: Optional[bool] = field(default=None)
    include_subdomains: Optional[bool] = field(default=None)
    preload: Optional[bool] = field(default=None)
    access_control_max_age_sec: Optional[int] = field(default=None)


@define(eq=False, slots=False)
class AwsCloudFrontResponseHeadersPolicySecurityHeadersConfig:
    kind: ClassVar[str] = "aws_cloudfront_response_headers_policy_security_headers_config"
    kind_display: ClassVar[str] = "AWS CloudFront Response Headers Policy Security Headers Config"
    kind_description: ClassVar[str] = (
        "The AWS CloudFront Response Headers Policy Security Headers Config allows"
        " configuring security headers for responses served by AWS CloudFront,"
        " providing additional security measures for web applications."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "xss_protection": S("XSSProtection") >> Bend(AwsCloudFrontResponseHeadersPolicyXSSProtection.mapping),
        "frame_options": S("FrameOptions") >> Bend(AwsCloudFrontResponseHeadersPolicyFrameOptions.mapping),
        "referrer_policy": S("ReferrerPolicy") >> Bend(AwsCloudFrontResponseHeadersPolicyReferrerPolicy.mapping),
        "content_security_policy": S("ContentSecurityPolicy")
        >> Bend(AwsCloudFrontResponseHeadersPolicyContentSecurityPolicy.mapping),
        "content_type_options": S("ContentTypeOptions", "Override"),
        "strict_transport_security": S("StrictTransportSecurity")
        >> Bend(AwsCloudFrontResponseHeadersPolicyStrictTransportSecurity.mapping),
    }
    xss_protection: Optional[AwsCloudFrontResponseHeadersPolicyXSSProtection] = field(default=None)
    frame_options: Optional[AwsCloudFrontResponseHeadersPolicyFrameOptions] = field(default=None)
    referrer_policy: Optional[AwsCloudFrontResponseHeadersPolicyReferrerPolicy] = field(default=None)
    content_security_policy: Optional[AwsCloudFrontResponseHeadersPolicyContentSecurityPolicy] = field(default=None)
    content_type_options: Optional[bool] = field(default=None)
    strict_transport_security: Optional[AwsCloudFrontResponseHeadersPolicyStrictTransportSecurity] = field(default=None)


@define(eq=False, slots=False)
class AwsCloudFrontResponseHeadersPolicyServerTimingHeadersConfig:
    kind: ClassVar[str] = "aws_cloudfront_response_headers_policy_server_timing_headers_config"
    kind_display: ClassVar[str] = "AWS CloudFront Response Headers Policy Server Timing Headers Config"
    kind_description: ClassVar[str] = (
        "CloudFront Response Headers Policy Server Timing Headers Config is a"
        " configuration option in AWS CloudFront that allows you to control the"
        " inclusion of Server Timing headers in the response sent to clients."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"enabled": S("Enabled"), "sampling_rate": S("SamplingRate")}
    enabled: Optional[bool] = field(default=None)
    sampling_rate: Optional[float] = field(default=None)


@define(eq=False, slots=False)
class AwsCloudFrontResponseHeadersPolicyCustomHeader:
    kind: ClassVar[str] = "aws_cloudfront_response_headers_policy_custom_header"
    kind_display: ClassVar[str] = "AWS CloudFront Response Headers Policy Custom Header"
    kind_description: ClassVar[str] = (
        "The custom header response policy allows you to add custom headers to the"
        " responses served by CloudFront distributions. This can be used to control"
        " caching behavior or add additional information to the responses."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"header": S("Header"), "value": S("Value"), "override": S("Override")}
    header: Optional[str] = field(default=None)
    value: Optional[str] = field(default=None)
    override: Optional[bool] = field(default=None)


@define(eq=False, slots=False)
class AwsCloudFrontResponseHeadersPolicyConfig:
    kind: ClassVar[str] = "aws_cloudfront_response_headers_policy_config"
    kind_display: ClassVar[str] = "AWS CloudFront Response Headers Policy Configuration"
    kind_description: ClassVar[str] = (
        "The AWS CloudFront Response Headers Policy Configuration allows users to"
        " define and control the HTTP response headers that are included in the"
        " responses served by CloudFront."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "comment": S("Comment"),
        "name": S("Name"),
        "cors_config": S("CorsConfig") >> Bend(AwsCloudFrontResponseHeadersPolicyCorsConfig.mapping),
        "security_headers_config": S("SecurityHeadersConfig")
        >> Bend(AwsCloudFrontResponseHeadersPolicySecurityHeadersConfig.mapping),
        "server_timing_headers_config": S("ServerTimingHeadersConfig")
        >> Bend(AwsCloudFrontResponseHeadersPolicyServerTimingHeadersConfig.mapping),
        "custom_headers_config": S("CustomHeadersConfig", "Items", default=[])
        >> ForallBend(AwsCloudFrontResponseHeadersPolicyCustomHeader.mapping),
    }
    comment: Optional[str] = field(default=None)
    name: Optional[str] = field(default=None)
    cors_config: Optional[AwsCloudFrontResponseHeadersPolicyCorsConfig] = field(default=None)
    security_headers_config: Optional[AwsCloudFrontResponseHeadersPolicySecurityHeadersConfig] = field(default=None)
    server_timing_headers_config: Optional[AwsCloudFrontResponseHeadersPolicyServerTimingHeadersConfig] = field(
        default=None
    )
    custom_headers_config: List[AwsCloudFrontResponseHeadersPolicyCustomHeader] = field(factory=list)


@define(eq=False, slots=False)
class AwsCloudFrontResponseHeadersPolicy(CloudFrontResource, AwsResource):
    kind: ClassVar[str] = "aws_cloudfront_response_headers_policy"
    kind_display: ClassVar[str] = "AWS CloudFront Response Headers Policy"
    aws_metadata: ClassVar[Dict[str, Any]] = {"provider_link_tpl": "https://{region_id}.console.aws.amazon.com/cloudfront/v4/home?region=global#/policies/responseHeaders/{id}", "arn_tpl": "arn:{partition}:cloudfront::{account}:response-headers-policy/{id}"}  # fmt: skip

    kind_description: ClassVar[str] = (
        "The AWS CloudFront Response Headers Policy is a configuration that allows"
        " you to manage and control the response headers that are included in the HTTP"
        " responses delivered by CloudFront."
    )
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec(
        service_name, "list-response-headers-policies", "ResponseHeadersPolicyList.Items"
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("ResponseHeadersPolicy", "Id"),
        "mtime": S("ResponseHeadersPolicy", "LastModifiedTime"),
        "response_headers_policy_type": S("Type"),
        "response_headers_policy_config": S("ResponseHeadersPolicy", "ResponseHeadersPolicyConfig")
        >> Bend(AwsCloudFrontResponseHeadersPolicyConfig.mapping),
    }

    response_headers_policy_type: Optional[str] = field(default=None)
    response_headers_policy_config: Optional[AwsCloudFrontResponseHeadersPolicyConfig] = field(default=None)

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return super().called_mutator_apis() + [
            AwsApiSpec(service_name, "get-response-headers-policy"),
            AwsApiSpec(service_name, "delete-response-headers-policy"),
        ]

    def delete_resource(self, client: AwsClient, graph: Graph) -> bool:
        return self.delete_cloudfront_resource(client, "response-headers-policy", self.id)


@define(eq=False, slots=False)
class AwsCloudFrontS3Origin:
    kind: ClassVar[str] = "aws_cloudfront_s3_origin"
    kind_display: ClassVar[str] = "AWS CloudFront S3 Origin"
    kind_description: ClassVar[str] = (
        "CloudFront S3 Origin is an Amazon Web Services (AWS) service that allows you"
        " to use an Amazon S3 bucket as the origin for your CloudFront distribution."
        " It enables faster content delivery by caching and distributing web content"
        " from the S3 bucket to edge locations around the world."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "domain_name": S("DomainName"),
        "origin_access_identity": S("OriginAccessIdentity"),
    }
    domain_name: Optional[str] = field(default=None)
    origin_access_identity: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsCloudFrontStreamingDistribution(CloudFrontTaggable, CloudFrontResource, AwsResource):
    kind: ClassVar[str] = "aws_cloudfront_streaming_distribution"
    kind_display: ClassVar[str] = "AWS CloudFront Streaming Distribution"
    aws_metadata: ClassVar[Dict[str, Any]] = {"arn_tpl": "arn:{partition}:cloudfront:{region}:{account}:streaming-distribution/{id}"}  # fmt: skip
    kind_description: ClassVar[str] = (
        "CloudFront Streaming Distribution is a content delivery network (CDN)"
        " service provided by AWS that allows for fast and secure streaming of audio"
        " and video content over the internet."
    )
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec(
        service_name, "list-streaming-distributions", "StreamingDistributionList.Items"
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("Id"),
        "mtime": S("LastModifiedTime"),
        "arn": S("ARN"),
        "streaming_distribution_status": S("Status"),
        "streaming_distribution_domain_name": S("DomainName"),
        "streaming_distribution_s3_origin": S("S3Origin") >> Bend(AwsCloudFrontS3Origin.mapping),
        "streaming_distribution_aliases": S("Aliases", "Items", default=[]),
        "streaming_distribution_trusted_signers": S("TrustedSigners", "Items", default=[]),
        "streaming_distribution_comment": S("Comment"),
        "streaming_distribution_price_class": S("PriceClass"),
        "streaming_distribution_enabled": S("Enabled"),
    }
    streaming_distribution_status: Optional[str] = field(default=None)
    streaming_distribution_domain_name: Optional[str] = field(default=None)
    streaming_distribution_trusted_signers: List[str] = field(factory=list)
    streaming_distribution_comment: Optional[str] = field(default=None)
    streaming_distribution_price_class: Optional[str] = field(default=None)
    streaming_distribution_enabled: Optional[bool] = field(default=None)

    # deleting streaming distributions is a multistep process:
    # https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/cloudfront.html#CloudFront.Client.delete_streaming_distribution


@define(eq=False, slots=False)
class AwsCloudFrontOriginAccessControl(CloudFrontResource, AwsResource):
    kind: ClassVar[str] = "aws_cloudfront_origin_access_control"
    kind_display: ClassVar[str] = "AWS CloudFront Origin Access Control"
    aws_metadata: ClassVar[Dict[str, Any]] = {"arn_tpl": "arn:{partition}:cloudfront:{region}:{account}:origin-access-identity/cloudfront/{id}"}  # fmt: skip
    kind_description: ClassVar[str] = (
        "AWS CloudFront Origin Access Control is a security feature that allows you to control access"
        " to your S3 bucket or custom origin, ensuring that your content can only be accessed via"
        " CloudFront distributions and not directly from the origin itself."
    )
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec(
        service_name, "list-origin-access-controls", "OriginAccessControlList.Items"
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("Id"),
        "name": S("Name"),
        "origin_access_control_description": S("Description"),
        "origin_access_control_signing_protocol": S("SigningProtocol"),
        "origin_access_control_signing_behavior": S("SigningBehavior"),
        "origin_access_control_origin_access_control_origin_type": S("OriginAccessControlOriginType"),
    }
    origin_access_control_description: Optional[str] = field(default=None)
    origin_access_control_signing_protocol: Optional[str] = field(default=None)
    origin_access_control_signing_behavior: Optional[str] = field(default=None)
    origin_access_control_origin_access_control_origin_type: Optional[str] = field(default=None)

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return super().called_mutator_apis() + [
            AwsApiSpec(service_name, "get-origin-access-control"),
            AwsApiSpec(service_name, "delete-origin-access-control"),
        ]

    def delete_resource(self, client: AwsClient, graph: Graph) -> bool:
        return self.delete_cloudfront_resource(client, "origin-access-control", self.id)


@define(eq=False, slots=False)
class AwsCloudFrontCachePolicyHeadersConfig:
    kind: ClassVar[str] = "aws_cloudfront_cache_policy_headers_config"
    kind_display: ClassVar[str] = "AWS CloudFront Cache Policy Headers Config"
    kind_description: ClassVar[str] = (
        "AWS CloudFront Cache Policy Headers Config specifies which HTTP headers CloudFront includes in the cache key"
        " and, consequently, which headers it uses to determine whether to serve a cached response or to forward a"
        " request to the origin. This configuration influences cache hit ratios and content delivery performance."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "header_behavior": S("HeaderBehavior"),
        "headers": S("Headers", "Items", default=[]),
    }
    header_behavior: Optional[str] = field(default=None)
    headers: List[str] = field(factory=list)


@define(eq=False, slots=False)
class AwsCloudFrontCachePolicyCookiesConfig:
    kind: ClassVar[str] = "aws_cloudfront_cache_policy_cookies_config"
    kind_display: ClassVar[str] = "AWS CloudFront Cache Policy Cookies Config"
    kind_description: ClassVar[str] = (
        "The AWS CloudFront Cache Policy Cookies Config is a configuration for"
        " customizing caching behavior based on cookies when using AWS CloudFront, a"
        " global content delivery network (CDN) service."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "cookie_behavior": S("CookieBehavior"),
        "cookies": S("Cookies", default=[]),
    }
    cookie_behavior: Optional[str] = field(default=None)
    cookies: List[str] = field(factory=list)


@define(eq=False, slots=False)
class AwsCloudFrontCachePolicyQueryStringsConfig:
    kind: ClassVar[str] = "aws_cloudfront_cache_policy_query_strings_config"
    kind_display: ClassVar[str] = "AWS CloudFront Cache Policy Query Strings Config"
    kind_description: ClassVar[str] = (
        "The AWS CloudFront Cache Policy Query Strings Config provides configuration"
        " settings for how CloudFront handles caching of resources based on query"
        " string parameters."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "query_string_behavior": S("QueryStringBehavior"),
        "query_strings": S("QueryStrings", "Items", default=[]),
    }
    query_string_behavior: Optional[str] = field(default=None)
    query_strings: List[str] = field(factory=list)


@define(eq=False, slots=False)
class AwsCloudFrontParametersInCacheKeyAndForwardedToOrigin:
    kind: ClassVar[str] = "aws_cloudfront_parameters_in_cache_key_and_forwarded_to_origin"
    kind_display: ClassVar[str] = "AWS CloudFront Parameters in Cache Key and Forwarded to Origin"
    kind_description: ClassVar[str] = (
        "AWS CloudFront allows users to customize the cache key and specify which"
        " parameters are forwarded to the origin server for improved caching and"
        " origin response."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "enable_accept_encoding_gzip": S("EnableAcceptEncodingGzip"),
        "enable_accept_encoding_brotli": S("EnableAcceptEncodingBrotli"),
        "headers_config": S("HeadersConfig") >> Bend(AwsCloudFrontCachePolicyHeadersConfig.mapping),
        "cookies_config": S("CookiesConfig") >> Bend(AwsCloudFrontCachePolicyCookiesConfig.mapping),
        "query_strings_config": S("QueryStringsConfig") >> Bend(AwsCloudFrontCachePolicyQueryStringsConfig.mapping),
    }
    enable_accept_encoding_gzip: Optional[bool] = field(default=None)
    enable_accept_encoding_brotli: Optional[bool] = field(default=None)
    headers_config: Optional[AwsCloudFrontCachePolicyHeadersConfig] = field(default=None)
    cookies_config: Optional[AwsCloudFrontCachePolicyCookiesConfig] = field(default=None)
    query_strings_config: Optional[AwsCloudFrontCachePolicyQueryStringsConfig] = field(default=None)


@define(eq=False, slots=False)
class AwsCloudFrontCachePolicyConfig:
    kind: ClassVar[str] = "aws_cloudfront_cache_policy_config"
    kind_display: ClassVar[str] = "AWS CloudFront Cache Policy Configuration"
    kind_description: ClassVar[str] = (
        "CloudFront Cache Policies allow you to define caching behavior for your"
        " content. This resource represents the configuration settings for a cache"
        " policy in Amazon CloudFront."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "comment": S("Comment"),
        "name": S("Name"),
        "default_ttl": S("DefaultTTL"),
        "max_ttl": S("MaxTTL"),
        "min_ttl": S("MinTTL"),
        "parameters_in_cache_key_and_forwarded_to_origin": S("ParametersInCacheKeyAndForwardedToOrigin")
        >> Bend(AwsCloudFrontParametersInCacheKeyAndForwardedToOrigin.mapping),
    }
    comment: Optional[str] = field(default=None)
    name: Optional[str] = field(default=None)
    default_ttl: Optional[int] = field(default=None)
    max_ttl: Optional[int] = field(default=None)
    min_ttl: Optional[int] = field(default=None)
    parameters_in_cache_key_and_forwarded_to_origin: Optional[AwsCloudFrontParametersInCacheKeyAndForwardedToOrigin] = (
        field(default=None)
    )


@define(eq=False, slots=False)
class AwsCloudFrontCachePolicy(CloudFrontResource, AwsResource):
    kind: ClassVar[str] = "aws_cloudfront_cache_policy"
    kind_display: ClassVar[str] = "AWS CloudFront Cache Policy"
    aws_metadata: ClassVar[Dict[str, Any]] = {"provider_link_tpl": "https://{region_id}.console.aws.amazon.com/cloudfront/v4/home?region={region}#/policies/cache/{id}", "arn_tpl": "arn:{partition}:cloudfront:{region}:{account}:cache-policy/{id}"}  # fmt: skip
    kind_description: ClassVar[str] = (
        "CloudFront Cache Policies in AWS specify the caching behavior for CloudFront"
        " distributions, allowing users to control how content is cached and delivered"
        " to end users."
    )
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec(service_name, "list-cache-policies", "CachePolicyList.Items")
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("CachePolicy", "Id"),
        "name": S("CachePolicy", "CachePolicyConfig", "Name"),
        "mtime": S("CachePolicy", "LastModifiedTime"),
        "cache_policy_config": S("CachePolicy", "CachePolicyConfig") >> Bend(AwsCloudFrontCachePolicyConfig.mapping),
    }
    cache_policy_config: Optional[AwsCloudFrontCachePolicyConfig] = field(default=None)

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return super().called_mutator_apis() + [
            AwsApiSpec(service_name, "get-cache-policy"),
            AwsApiSpec(service_name, "delete-cache-policy"),
        ]

    def delete_resource(self, client: AwsClient, graph: Graph) -> bool:
        return self.delete_cloudfront_resource(client, "cache-policy", self.id)


@define(eq=False, slots=False)
class AwsCloudFrontQueryArgProfile:
    kind: ClassVar[str] = "aws_cloudfront_query_arg_profile"
    kind_display: ClassVar[str] = "AWS CloudFront Query Argument Profile"
    kind_description: ClassVar[str] = (
        "AWS CloudFront Query Argument Profile is part of CloudFront's Field-Level Encryption feature;"
        " it specifies how CloudFront handles query arguments by applying field patterns that match and"
        " encrypt query argument values when they are forwarded to the origin, enhancing the security"
        " of sensitive data."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"query_arg": S("QueryArg"), "profile_id": S("ProfileId")}
    query_arg: Optional[str] = field(default=None)
    profile_id: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsCloudFrontQueryArgProfileConfig:
    kind: ClassVar[str] = "aws_cloudfront_query_arg_profile_config"
    kind_display: ClassVar[str] = "AWS CloudFront Query Arg Profile Config"
    kind_description: ClassVar[str] = (
        "CloudFront Query Arg Profile Config is a configuration within AWS CloudFront's Field-Level Encryption"
        " setup that specifies the profiles to use for encrypting specific query arguments in viewer requests,"
        " enhancing security by ensuring sensitive information is encrypted as it passes from CloudFront"
        " to the origin."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "forward_when_query_arg_profile_is_unknown": S("ForwardWhenQueryArgProfileIsUnknown"),
        "query_arg_profiles": S("QueryArgProfiles", "Items", default=[])
        >> ForallBend(AwsCloudFrontQueryArgProfile.mapping),
    }
    forward_when_query_arg_profile_is_unknown: Optional[bool] = field(default=None)
    query_arg_profiles: List[AwsCloudFrontQueryArgProfile] = field(factory=list)


@define(eq=False, slots=False)
class AwsCloudFrontContentTypeProfile:
    kind: ClassVar[str] = "aws_cloudfront_content_type_profile"
    kind_display: ClassVar[str] = "AWS CloudFront Content Type Profile"
    kind_description: ClassVar[str] = (
        "AWS CloudFront Content Type Profile is a configuration option within CloudFront that maps file extensions"
        " to content types, which is used in Field-Level Encryption to apply encryption based on the content type"
        " of the forwarded content in a request."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "format": S("Format"),
        "profile_id": S("ProfileId"),
        "content_type": S("ContentType"),
    }
    format: Optional[str] = field(default=None)
    profile_id: Optional[str] = field(default=None)
    content_type: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsCloudFrontContentTypeProfileConfig:
    kind: ClassVar[str] = "aws_cloudfront_content_type_profile_config"
    kind_display: ClassVar[str] = "AWS CloudFront Content Type Profile Config"
    kind_description: ClassVar[str] = (
        "AWS CloudFront Content Type Profile Config is a setting within AWS CloudFront's Field-Level Encryption"
        " that defines a set of profiles mapping query argument or form field names to their respective content"
        " type, which is used to determine how specified fields in viewer requests are encrypted before being"
        " forwarded to the origin."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "forward_when_content_type_is_unknown": S("ForwardWhenContentTypeIsUnknown"),
        "content_type_profiles": S("ContentTypeProfiles", "Items", default=[])
        >> ForallBend(AwsCloudFrontContentTypeProfile.mapping),
    }
    forward_when_content_type_is_unknown: Optional[bool] = field(default=None)
    content_type_profiles: List[AwsCloudFrontContentTypeProfile] = field(factory=list)


@define(eq=False, slots=False)
class AwsCloudFrontFieldLevelEncryptionConfig(CloudFrontResource, AwsResource):
    kind: ClassVar[str] = "aws_cloudfront_field_level_encryption_config"
    kind_display: ClassVar[str] = "AWS CloudFront Field-Level Encryption Configuration"
    aws_metadata: ClassVar[Dict[str, Any]] = {"arn_tpl": "arn:{partition}:cloudfront:{region}:{account}:field-level-encryption-config/{name}"}  # fmt: skip
    kind_description: ClassVar[str] = (
        "AWS CloudFront Field-Level Encryption Configuration is a feature that helps you to protect sensitive data"
        " by encrypting specific HTTP fields at CloudFront edge locations. It allows you to encrypt data within"
        " each individual field of an HTTPS request or response."
    )
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec(
        service_name, "list-field-level-encryption-configs", "FieldLevelEncryptionList.Items"
    )
    reference_kinds: ClassVar[ModelReference] = {
        "successors": {"default": ["aws_cloudfront_field_level_encryption_profile"]}
    }
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("Id"),
        "mtime": S("LastModifiedTime"),
        "field_level_encryption_config_comment": S("Comment"),
        "field_level_encryption_config_query_arg_profile_config": S("QueryArgProfileConfig")
        >> Bend(AwsCloudFrontQueryArgProfileConfig.mapping),
        "field_level_encryption_config_content_type_profile_config": S("ContentTypeProfileConfig")
        >> Bend(AwsCloudFrontContentTypeProfileConfig.mapping),
    }
    field_level_encryption_config_comment: Optional[str] = field(default=None)
    field_level_encryption_config_query_arg_profile_config: Optional[AwsCloudFrontQueryArgProfileConfig] = field(
        default=None
    )
    field_level_encryption_config_content_type_profile_config: Optional[AwsCloudFrontContentTypeProfileConfig] = field(
        default=None
    )

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return super().called_mutator_apis() + [
            AwsApiSpec(service_name, "get-field-level-encryption-config"),
            AwsApiSpec(service_name, "delete-field-level-encryption-config"),
        ]

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if (
            self.field_level_encryption_config_content_type_profile_config
            and self.field_level_encryption_config_content_type_profile_config.content_type_profiles
        ):
            for entry in self.field_level_encryption_config_content_type_profile_config.content_type_profiles:
                builder.add_edge(
                    self,
                    clazz=AwsCloudFrontFieldLevelEncryptionProfile,
                    id=entry.profile_id,
                )

    def delete_resource(self, client: AwsClient, graph: Graph) -> bool:
        return self.delete_cloudfront_resource(client, "field-level-encryption-config", self.id)


@define(eq=False, slots=False)
class AwsCloudFrontEncryptionEntity:
    kind: ClassVar[str] = "aws_cloudfront_encryption_entity"
    kind_display: ClassVar[str] = "AWS CloudFront Encryption Entity"
    kind_description: ClassVar[str] = (
        "CloudFront Encryption Entities represent the security configuration for"
        " content delivery, ensuring secure and encrypted data transfer between the"
        " user and the CloudFront edge servers."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "public_key_id": S("PublicKeyId"),
        "provider_id": S("ProviderId"),
        "field_patterns": S("FieldPatterns", "Items", default=[]),
    }
    public_key_id: Optional[str] = field(default=None)
    provider_id: Optional[str] = field(default=None)
    field_patterns: List[str] = field(factory=list)


@define(eq=False, slots=False)
class AwsCloudFrontFieldLevelEncryptionProfile(CloudFrontResource, AwsResource):
    kind: ClassVar[str] = "aws_cloudfront_field_level_encryption_profile"
    kind_display: ClassVar[str] = "AWS CloudFront Field Level Encryption Profile"
    aws_metadata: ClassVar[Dict[str, Any]] = {"arn_tpl": "arn:{partition}:cloudfront:{region}:{account}:field-level-encryption-profile/{name}"}  # fmt: skip
    kind_description: ClassVar[str] = (
        "Field Level Encryption Profiles in AWS CloudFront allow users to encrypt"
        " specific fields in a web form, providing an extra layer of security to"
        " sensitive data."
    )
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec(
        service_name, "list-field-level-encryption-profiles", "FieldLevelEncryptionProfileList.Items"
    )
    reference_kinds: ClassVar[ModelReference] = {
        "successors": {"default": ["aws_cloudfront_public_key"]},
    }
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("Id"),
        "name": S("Name"),
        "mtime": S("LastModifiedTime"),
        "field_level_encryption_profile_encryption_entities": S("EncryptionEntities", "Items", default=[])
        >> ForallBend(AwsCloudFrontEncryptionEntity.mapping),
        "field_level_encryption_profile_comment": S("Comment"),
    }
    field_level_encryption_profile_encryption_entities: List[AwsCloudFrontEncryptionEntity] = field(factory=list)
    field_level_encryption_profile_comment: Optional[str] = field(default=None)

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return super().called_mutator_apis() + [
            AwsApiSpec(service_name, "get-field-level-encryption-profile"),
            AwsApiSpec(service_name, "delete-field-level-encryption-profile"),
        ]

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if self.field_level_encryption_profile_encryption_entities:
            for entry in self.field_level_encryption_profile_encryption_entities:
                builder.add_edge(
                    self,
                    clazz=AwsCloudFrontPublicKey,
                    id=entry.public_key_id,
                )

    def delete_resource(self, client: AwsClient, graph: Graph) -> bool:
        return self.delete_cloudfront_resource(client, "field-level-encryption-profile", self.id)


resources: List[Type[AwsResource]] = [
    AwsCloudFrontDistribution,
    AwsCloudFrontFunction,
    AwsCloudFrontPublicKey,
    AwsCloudFrontRealtimeLogConfig,
    AwsCloudFrontResponseHeadersPolicy,
    AwsCloudFrontStreamingDistribution,
    AwsCloudFrontOriginAccessControl,
    AwsCloudFrontCachePolicy,
    AwsCloudFrontFieldLevelEncryptionConfig,
    AwsCloudFrontFieldLevelEncryptionProfile,
]
