import logging
from typing import ClassVar, Dict, List, Optional, Type

from attr import define, field

from resoto_plugin_aws.aws_client import AwsClient
from resoto_plugin_aws.resource.base import AwsApiSpec, AwsResource, GraphBuilder
from resoto_plugin_aws.resource.iam import AwsIamServerCertificate
from resoto_plugin_aws.resource.lambda_ import AwsLambdaFunction
from resoto_plugin_aws.resource.s3 import AwsS3Bucket
from resoto_plugin_aws.utils import ToDict
from resotolib.baseresources import ModelReference
from resotolib.graph import Graph
from resotolib.json_bender import S, Bend, Bender, ForallBend, bend
from resotolib.types import Json

log = logging.getLogger("resoto.plugins.aws")


class CloudFrontResource:
    @classmethod
    def collect(cls: Type[AwsResource], json: List[Json], builder: GraphBuilder) -> None:  # type: ignore
        def add_tags(res: AwsResource) -> None:
            tags = builder.client.get("cloudfront", "list-tags-for-resource", "Tags", Resource=res.arn)
            if tags:
                res.tags = bend(ToDict(), tags["Items"])

        for js in json:
            instance = cls.from_api(js)
            builder.add_node(instance, js)
            if instance.arn:
                builder.submit_work(add_tags, instance)

    @staticmethod
    def delete_cloudfront_resource(client: AwsClient, resource: str, id: str) -> bool:
        description = client.get("cloudfront", f"get-{resource}", None, None, Id=id)
        if description:
            etag = description.get("ETag", None)
            if etag:
                client.call(
                    aws_service="cloudfront",
                    action=f"delete-{resource}",
                    result_name=None,
                    Id=id,
                    IfMatch=etag,
                )
                return True
        return False


class CloudFrontTaggable:
    def update_resource_tag(self, client: AwsClient, key: str, value: str) -> bool:
        if isinstance(self, AwsResource):
            client.call(
                aws_service="cloudfront",
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
                aws_service="cloudfront",
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
            AwsApiSpec("cloudfront", "tag-resource"),
            AwsApiSpec("cloudfront", "untag-resource"),
        ]


@define(eq=False, slots=False)
class AwsCloudFrontOriginCustomHeader:
    kind: ClassVar[str] = "aws_cloudfront_origin_custom_header"
    mapping: ClassVar[Dict[str, Bender]] = {"header_name": S("HeaderName"), "header_value": S("HeaderValue")}
    header_name: Optional[str] = field(default=None)
    header_value: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsCloudFrontCustomOriginConfig:
    kind: ClassVar[str] = "aws_cloudfront_custom_origin_config"
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
    mapping: ClassVar[Dict[str, Bender]] = {"enabled": S("Enabled"), "origin_shield_region": S("OriginShieldRegion")}
    enabled: Optional[bool] = field(default=None)
    origin_shield_region: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsCloudFrontOrigin:
    kind: ClassVar[str] = "aws_cloudfront_origin"
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("Id"),
        "domain_name": S("DomainName"),
        "origin_path": S("OriginPath"),
        "custom_header": S("CustomHeaders", "Items", default=[]) >> ForallBend(AwsCloudFrontOriginCustomHeader.mapping),
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
    custom_header: List[AwsCloudFrontOriginCustomHeader] = field(factory=list)
    s3_origin_config: Optional[str] = field(default=None)
    custom_origin_config: Optional[AwsCloudFrontCustomOriginConfig] = field(default=None)
    connection_attempts: Optional[int] = field(default=None)
    connection_timeout: Optional[int] = field(default=None)
    origin_shield: Optional[AwsCloudFrontOriginShield] = field(default=None)
    origin_access_control_id: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsCloudFrontOriginGroupFailoverCriteria:
    kind: ClassVar[str] = "aws_cloudfront_origin_group_failover_criteria"
    mapping: ClassVar[Dict[str, Bender]] = {"status_codes": S("StatusCodes", "Items", default=[])}
    status_codes: List[str] = field(factory=list)


@define(eq=False, slots=False)
class AwsCloudFrontOriginGroupMembers:
    kind: ClassVar[str] = "aws_cloudfront_origin_group_members"
    mapping: ClassVar[Dict[str, Bender]] = {
        "origin_id": S("OriginId"),
    }
    members: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsCloudFrontOriginGroup:
    kind: ClassVar[str] = "aws_cloudfront_origin_group"
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
    mapping: ClassVar[Dict[str, Bender]] = {"function_arn": S("FunctionARN"), "event_type": S("EventType")}
    function_arn: Optional[str] = field(default=None)
    event_type: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsCloudFrontCookiePreference:
    kind: ClassVar[str] = "aws_cloudfront_cookie_preference"
    mapping: ClassVar[Dict[str, Bender]] = {
        "forward": S("Forward"),
        "whitelisted_names": S("WhitelistedNames", "Items", default=[]),
    }
    forward: Optional[str] = field(default=None)
    whitelisted_names: List[str] = field(factory=list)


@define(eq=False, slots=False)
class AwsCloudFrontForwardedValues:
    kind: ClassVar[str] = "aws_cloudfront_forwarded_values"
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
        "function_association": S("FunctionAssociations", "Items", default=[])
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
    lambda_function_association: List[AwsCloudFrontLambdaFunctionAssociation] = field(factory=list)
    function_association: List[AwsCloudFrontFunctionAssociation] = field(factory=list)
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
        "trusted_signers": S("TrustedSigners", "Items", default=[]),
        "trusted_key_groups": S("TrustedKeyGroups", "Items", default=[]),
        "viewer_protocol_policy": S("ViewerProtocolPolicy"),
        "allowed_methods": S("AllowedMethods", "Items", default=[]),
        "smooth_streaming": S("SmoothStreaming"),
        "compress": S("Compress"),
        "lambda_function_association": S("LambdaFunctionAssociations", "Items", default=[])
        >> ForallBend(AwsCloudFrontLambdaFunctionAssociation.mapping),
        "function_association": S("FunctionAssociations", "Items", default=[])
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
    lambda_function_association: List[AwsCloudFrontLambdaFunctionAssociation] = field(factory=list)
    function_association: List[AwsCloudFrontFunctionAssociation] = field(factory=list)
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
    mapping: ClassVar[Dict[str, Bender]] = {"geo_restriction": S("GeoRestriction", "Items", default=[])}
    geo_restriction: List[str] = field(factory=list)


@define(eq=False, slots=False)
class AwsCloudFrontAliasICPRecordal:
    kind: ClassVar[str] = "aws_cloudfront_alias_icp_recordal"
    mapping: ClassVar[Dict[str, Bender]] = {"cname": S("CNAME"), "icp_recordal_status": S("ICPRecordalStatus")}
    cname: Optional[str] = field(default=None)
    icp_recordal_status: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsCloudFrontDistribution(CloudFrontTaggable, CloudFrontResource, AwsResource):
    kind: ClassVar[str] = "aws_cloudfront_distribution"
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec("cloudfront", "list-distributions", "DistributionList.Items")
    reference_kinds: ClassVar[ModelReference] = {
        "predecessors": {"delete": ["aws_lambda_function"]},
        "successors": {
            "default": [
                "aws_lambda_function",
                "aws_iam_server_certificate",
                "aws_cloudfront_function",
                "aws_cloudfront_realtime_log_config",
                "aws_cloudfront_field_level_encryption_config",
                "aws_cloudfront_response_headers_policy",
                "aws_cloudfront_cache_policy",
                "aws_cloudfront_origin_access_control",
                "aws_s3_bucket",
            ]
        },
    }
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("Id"),
        "mtime": S("LastModifiedTime"),
        "arn": S("ARN"),
        "distribution_status": S("Status"),
        "distribution_domain_name": S("DomainName"),
        "distribution_aliases": S("Aliases", "Items", default=[]),
        "distribution_origin": S("Origins", "Items", default=[]) >> ForallBend(AwsCloudFrontOrigin.mapping),
        "distribution_origin_group": S("OriginGroups", "Items", default=[])
        >> ForallBend(AwsCloudFrontOriginGroup.mapping),
        "distribution_default_cache_behavior": S("DefaultCacheBehavior")
        >> Bend(AwsCloudFrontDefaultCacheBehavior.mapping),
        "distribution_cache_behavior": S("CacheBehaviors", "Items", default=[])
        >> ForallBend(AwsCloudFrontCacheBehavior.mapping),
        "distribution_custom_error_response": S("CustomErrorResponses", "Items", default=[])
        >> ForallBend(AwsCloudFrontCustomErrorResponse.mapping),
        "distribution_comment": S("Comment"),
        "distribution_price_class": S("PriceClass"),
        "distribution_enabled": S("Enabled"),
        "distribution_viewer_certificate": S("ViewerCertificate") >> Bend(AwsCloudFrontViewerCertificate.mapping),
        "distribution_restrictions": S("Restrictions") >> Bend(AwsCloudFrontRestrictions.mapping),
        "distribution_web_acl_id": S("WebACLId"),
        "distribution_http_version": S("HttpVersion"),
        "distribution_is_ipv6_enabled": S("IsIPV6Enabled"),
        "distribution_alias_icp_recordals": S("AliasICPRecordals", default=[])
        >> ForallBend(AwsCloudFrontAliasICPRecordal.mapping),
    }
    distribution_status: Optional[str] = field(default=None)
    distribution_domain_name: Optional[str] = field(default=None)
    distribution_aliases: List[str] = field(factory=list)
    distribution_origin: List[AwsCloudFrontOrigin] = field(factory=list)
    distribution_origin_group: List[AwsCloudFrontOriginGroup] = field(factory=list)
    distribution_default_cache_behavior: Optional[AwsCloudFrontDefaultCacheBehavior] = field(default=None)
    distribution_cache_behavior: List[AwsCloudFrontCacheBehavior] = field(factory=list)
    distribution_custom_error_response: List[AwsCloudFrontCustomErrorResponse] = field(factory=list)
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
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return super().called_mutator_apis() + [
            AwsApiSpec("cloudfront", "get-distribution-config"),
            AwsApiSpec("cloudfront", "update-distribution"),
            AwsApiSpec("cloudfront", "get-distribution"),
            AwsApiSpec("cloudfront", "delete-distribution"),
        ]

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        # edges from default cache behaviour
        if dcb := self.distribution_default_cache_behavior:
            for a in dcb.lambda_function_association:
                builder.dependant_node(self, clazz=AwsLambdaFunction, arn=a.lambda_function_arn)
            for b in dcb.function_association:
                builder.add_edge(self, clazz=AwsCloudFrontFunction, arn=b.function_arn)
            if dcb.realtime_log_config_arn:
                builder.add_edge(self, clazz=AwsCloudFrontRealtimeLogConfig, arn=dcb.realtime_log_config_arn)
            if dcb.field_level_encryption_id:
                builder.add_edge(self, clazz=AwsCloudFrontFieldLevelEncryptionConfig, id=dcb.field_level_encryption_id)
            if dcb.response_headers_policy_id:
                builder.add_edge(self, clazz=AwsCloudFrontResponseHeadersPolicy, id=dcb.response_headers_policy_id)
            if dcb.cache_policy_id:
                builder.add_edge(self, clazz=AwsCloudFrontCachePolicy, id=dcb.cache_policy_id)

        # edges from other cache behaviours
        for cb_item in self.distribution_cache_behavior:
            for c in cb_item.lambda_function_association:
                builder.add_edge(self, clazz=AwsLambdaFunction, arn=c.lambda_function_arn)
            for d in cb_item.function_association:
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
                builder.add_edge(self, clazz=AwsCloudFrontResponseHeadersPolicy, id=cb_item.response_headers_policy_id)

        # other edges
        if self.distribution_origin:
            for entry in self.distribution_origin:
                builder.add_edge(self, clazz=AwsCloudFrontOriginAccessControl, id=entry.origin_access_control_id)
                builder.add_edge(self, clazz=AwsS3Bucket, name=entry.id)

        if self.distribution_viewer_certificate and self.distribution_viewer_certificate.iam_certificate_id:
            builder.add_edge(
                self, clazz=AwsIamServerCertificate, id=self.distribution_viewer_certificate.iam_certificate_id
            )

        # TODO edge to ACM certificate when applicable (via self.distribution_viewer_certificate.acm_certificate_arn)
        # TODO edge to Web Acl when applicable (via self.distribution_web_acl_id)

    def pre_delete_resource(self, client: AwsClient, graph: Graph) -> bool:
        dist_config = client.get("cloudfront", "get-distribution-config", None, None, Id=self.id)
        if dist_config:
            dist_config["DistributionConfig"]["Enabled"] = False
            dist_config["IfMatch"] = dist_config["ETag"]
            dist_config.pop("ETag")
            update = client.call(
                "cloudfront",
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

    def delete_resource(self, client: AwsClient) -> bool:
        return self.delete_cloudfront_resource(client, "distribution", self.id)


@define(eq=False, slots=False)
class AwsCloudFrontFunctionConfig:
    kind: ClassVar[str] = "aws_cloudfront_function_config"
    mapping: ClassVar[Dict[str, Bender]] = {"comment": S("Comment"), "runtime": S("Runtime")}
    comment: Optional[str] = field(default=None)
    runtime: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsCloudFrontFunction(CloudFrontTaggable, CloudFrontResource, AwsResource):
    kind: ClassVar[str] = "aws_cloudfront_function"
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec("cloudfront", "list-functions", "FunctionList.Items")
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
            AwsApiSpec("cloudfront", "describe-function"),
            AwsApiSpec("cloudfront", "delete-function"),
        ]

    def delete_resource(self, client: AwsClient) -> bool:
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
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec("cloudfront", "list-public-keys", "PublicKeyList.Items")
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
            AwsApiSpec("cloudfront", "get-public-key"),
            AwsApiSpec("cloudfront", "delete-public-key"),
        ]

    def delete_resource(self, client: AwsClient) -> bool:
        return self.delete_cloudfront_resource(client, "public-key", self.id)


@define(eq=False, slots=False)
class AwsCloudFrontKinesisStreamConfig:
    kind: ClassVar[str] = "aws_cloudfront_kinesis_stream_config"
    mapping: ClassVar[Dict[str, Bender]] = {"role_arn": S("RoleARN"), "stream_arn": S("StreamARN")}
    role_arn: Optional[str] = field(default=None)
    stream_arn: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsCloudFrontEndPoint:
    kind: ClassVar[str] = "aws_cloudfront_end_point"
    mapping: ClassVar[Dict[str, Bender]] = {
        "stream_type": S("StreamType"),
        "kinesis_stream_config": S("KinesisStreamConfig") >> Bend(AwsCloudFrontKinesisStreamConfig.mapping),
    }
    stream_type: Optional[str] = field(default=None)
    kinesis_stream_config: Optional[AwsCloudFrontKinesisStreamConfig] = field(default=None)


@define(eq=False, slots=False)
class AwsCloudFrontRealtimeLogConfig(CloudFrontTaggable, CloudFrontResource, AwsResource):
    kind: ClassVar[str] = "aws_cloudfront_realtime_log_config"
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec("cloudfront", "list-realtime-log-configs", "RealtimeLogConfigs.Items")
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
        return super().called_mutator_apis() + [AwsApiSpec("cloudfront", "delete-realtime-log-config")]

    def delete_resource(self, client: AwsClient) -> bool:
        client.call(
            aws_service=self.api_spec.service, action="delete-realtime-log-config", result_name=None, Name=self.name
        )
        return True


@define(eq=False, slots=False)
class AwsCloudFrontResponseHeadersPolicyCorsConfig:
    kind: ClassVar[str] = "aws_cloudfront_response_headers_policy_cors_config"
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
    mapping: ClassVar[Dict[str, Bender]] = {"override": S("Override"), "frame_option": S("FrameOption")}
    override: Optional[bool] = field(default=None)
    frame_option: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsCloudFrontResponseHeadersPolicyReferrerPolicy:
    kind: ClassVar[str] = "aws_cloudfront_response_headers_policy_referrer_policy"
    mapping: ClassVar[Dict[str, Bender]] = {"override": S("Override"), "referrer_policy": S("ReferrerPolicy")}
    override: Optional[bool] = field(default=None)
    referrer_policy: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsCloudFrontResponseHeadersPolicyContentSecurityPolicy:
    kind: ClassVar[str] = "aws_cloudfront_response_headers_policy_content_security_policy"
    mapping: ClassVar[Dict[str, Bender]] = {
        "override": S("Override"),
        "content_security_policy": S("ContentSecurityPolicy"),
    }
    override: Optional[bool] = field(default=None)
    content_security_policy: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsCloudFrontResponseHeadersPolicyStrictTransportSecurity:
    kind: ClassVar[str] = "aws_cloudfront_response_headers_policy_strict_transport_security"
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
    mapping: ClassVar[Dict[str, Bender]] = {"enabled": S("Enabled"), "sampling_rate": S("SamplingRate")}
    enabled: Optional[bool] = field(default=None)
    sampling_rate: Optional[float] = field(default=None)


@define(eq=False, slots=False)
class AwsCloudFrontResponseHeadersPolicyCustomHeader:
    kind: ClassVar[str] = "aws_cloudfront_response_headers_policy_custom_header"
    mapping: ClassVar[Dict[str, Bender]] = {"header": S("Header"), "value": S("Value"), "override": S("Override")}
    header: Optional[str] = field(default=None)
    value: Optional[str] = field(default=None)
    override: Optional[bool] = field(default=None)


@define(eq=False, slots=False)
class AwsCloudFrontResponseHeadersPolicyConfig:
    kind: ClassVar[str] = "aws_cloudfront_response_headers_policy_config"
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
    name: str = field(default=None)
    cors_config: Optional[AwsCloudFrontResponseHeadersPolicyCorsConfig] = field(default=None)
    security_headers_config: Optional[AwsCloudFrontResponseHeadersPolicySecurityHeadersConfig] = field(default=None)
    server_timing_headers_config: Optional[AwsCloudFrontResponseHeadersPolicyServerTimingHeadersConfig] = field(
        default=None
    )
    custom_headers_config: List[AwsCloudFrontResponseHeadersPolicyCustomHeader] = field(factory=list)


@define(eq=False, slots=False)
class AwsCloudFrontResponseHeadersPolicy(CloudFrontResource, AwsResource):
    kind: ClassVar[str] = "aws_cloudfront_response_headers_policy"
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec(
        "cloudfront", "list-response-headers-policies", "ResponseHeadersPolicyList.Items"
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
            AwsApiSpec("cloudfront", "get-response-headers-policy"),
            AwsApiSpec("cloudfront", "delete-response-headers-policy"),
        ]

    def delete_resource(self, client: AwsClient) -> bool:
        return self.delete_cloudfront_resource(client, "response-headers-policy", self.id)


@define(eq=False, slots=False)
class AwsCloudFrontS3Origin:
    kind: ClassVar[str] = "aws_cloudfront_s3_origin"
    mapping: ClassVar[Dict[str, Bender]] = {
        "domain_name": S("DomainName"),
        "origin_access_identity": S("OriginAccessIdentity"),
    }
    domain_name: Optional[str] = field(default=None)
    origin_access_identity: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsCloudFrontStreamingDistribution(CloudFrontTaggable, CloudFrontResource, AwsResource):
    kind: ClassVar[str] = "aws_cloudfront_streaming_distribution"
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec(
        "cloudfront", "list-streaming-distributions", "StreamingDistributionList.Items"
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
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec(
        "cloudfront", "list-origin-access-controls", "OriginAccessControlList.Items"
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
            AwsApiSpec("cloudfront", "get-origin-access-control"),
            AwsApiSpec("cloudfront", "delete-origin-access-control"),
        ]

    def delete_resource(self, client: AwsClient) -> bool:
        return self.delete_cloudfront_resource(client, "origin-access-control", self.id)


@define(eq=False, slots=False)
class AwsCloudFrontCachePolicyHeadersConfig:
    kind: ClassVar[str] = "aws_cloudfront_cache_policy_headers_config"
    mapping: ClassVar[Dict[str, Bender]] = {
        "header_behavior": S("HeaderBehavior"),
        "headers": S("Headers", "Items", default=[]),
    }
    header_behavior: Optional[str] = field(default=None)
    headers: List[str] = field(factory=list)


@define(eq=False, slots=False)
class AwsCloudFrontCachePolicyCookiesConfig:
    kind: ClassVar[str] = "aws_cloudfront_cache_policy_cookies_config"
    mapping: ClassVar[Dict[str, Bender]] = {
        "cookie_behavior": S("CookieBehavior"),
        "cookies": S("Cookies", default=[]),
    }
    cookie_behavior: Optional[str] = field(default=None)
    cookies: List[str] = field(factory=list)


@define(eq=False, slots=False)
class AwsCloudFrontCachePolicyQueryStringsConfig:
    kind: ClassVar[str] = "aws_cloudfront_cache_policy_query_strings_config"
    mapping: ClassVar[Dict[str, Bender]] = {
        "query_string_behavior": S("QueryStringBehavior"),
        "query_strings": S("QueryStrings", "Items", default=[]),
    }
    query_string_behavior: Optional[str] = field(default=None)
    query_strings: List[str] = field(factory=list)


@define(eq=False, slots=False)
class AwsCloudFrontParametersInCacheKeyAndForwardedToOrigin:
    kind: ClassVar[str] = "aws_cloudfront_parameters_in_cache_key_and_forwarded_to_origin"
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
    name: str = field(default=None)
    default_ttl: Optional[int] = field(default=None)
    max_ttl: Optional[int] = field(default=None)
    min_ttl: Optional[int] = field(default=None)
    parameters_in_cache_key_and_forwarded_to_origin: Optional[
        AwsCloudFrontParametersInCacheKeyAndForwardedToOrigin
    ] = field(default=None)


@define(eq=False, slots=False)
class AwsCloudFrontCachePolicy(CloudFrontResource, AwsResource):
    kind: ClassVar[str] = "aws_cloudfront_cache_policy"
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec("cloudfront", "list-cache-policies", "CachePolicyList.Items")
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
            AwsApiSpec("cloudfront", "get-cache-policy"),
            AwsApiSpec("cloudfront", "delete-cache-policy"),
        ]

    def delete_resource(self, client: AwsClient) -> bool:
        return self.delete_cloudfront_resource(client, "cache-policy", self.id)


@define(eq=False, slots=False)
class AwsCloudFrontQueryArgProfile:
    kind: ClassVar[str] = "aws_cloudfront_query_arg_profile"
    mapping: ClassVar[Dict[str, Bender]] = {"query_arg": S("QueryArg"), "profile_id": S("ProfileId")}
    query_arg: Optional[str] = field(default=None)
    profile_id: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsCloudFrontQueryArgProfileConfig:
    kind: ClassVar[str] = "aws_cloudfront_query_arg_profile_config"
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
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec(
        "cloudfront", "list-field-level-encryption-configs", "FieldLevelEncryptionList.Items"
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
            AwsApiSpec("cloudfront", "get-field-level-encryption-config"),
            AwsApiSpec("cloudfront", "delete-field-level-encryption-config"),
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

    def delete_resource(self, client: AwsClient) -> bool:
        return self.delete_cloudfront_resource(client, "field-level-encryption-config", self.id)


@define(eq=False, slots=False)
class AwsCloudFrontEncryptionEntity:
    kind: ClassVar[str] = "aws_cloudfront_encryption_entity"
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
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec(
        "cloudfront", "list-field-level-encryption-profiles", "FieldLevelEncryptionProfileList.Items"
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
            AwsApiSpec("cloudfront", "get-field-level-encryption-profile"),
            AwsApiSpec("cloudfront", "delete-field-level-encryption-profile"),
        ]

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if self.field_level_encryption_profile_encryption_entities:
            for entry in self.field_level_encryption_profile_encryption_entities:
                builder.add_edge(
                    self,
                    clazz=AwsCloudFrontPublicKey,
                    id=entry.public_key_id,
                )

    def delete_resource(self, client: AwsClient) -> bool:
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
