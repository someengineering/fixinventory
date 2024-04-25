import logging
from json import loads as json_loads
from typing import ClassVar, Dict, List, Type, Optional, cast, Any

from attr import field
from attrs import define

from fix_plugin_aws.aws_client import AwsClient
from fix_plugin_aws.resource.base import AwsResource, AwsApiSpec, GraphBuilder, parse_json
from fix_plugin_aws.resource.cloudwatch import (
    AwsCloudwatchMetricData,
    AwsCloudwatchQuery,
    update_resource_metrics,
)
from fix_plugin_aws.utils import MetricNormalization, tags_as_dict
from fixlib.baseresources import BaseBucket, MetricName, MetricUnit, PhantomBaseResource, ModelReference
from fixlib.graph import Graph
from fixlib.json import is_empty, sort_json
from fixlib.json_bender import Bender, S, bend, Bend, ForallBend
from fixlib.types import Json

service_name = "s3"
log = logging.getLogger("fix.plugins.aws")


@define(eq=False, slots=False)
class AwsS3ServerSideEncryptionRule:
    kind: ClassVar[str] = "aws_s3_server_side_encryption_rule"
    kind_display: ClassVar[str] = "AWS S3 Server-side Encryption Rule"
    kind_description: ClassVar[str] = (
        "Server-side encryption rules are used in AWS S3 to specify encryption"
        " settings for objects stored in the S3 bucket, ensuring data confidentiality"
        " and integrity."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "sse_algorithm": S("ApplyServerSideEncryptionByDefault", "SSEAlgorithm"),
        "kms_master_key_id": S("ApplyServerSideEncryptionByDefault", "KMSMasterKeyID"),
        "bucket_key_enabled": S("BucketKeyEnabled"),
    }
    sse_algorithm: Optional[str] = field(default=None)
    kms_master_key_id: Optional[str] = field(default=None)
    bucket_key_enabled: Optional[bool] = field(default=None)


@define(eq=False, slots=False)
class AwsS3PublicAccessBlockConfiguration:
    kind: ClassVar[str] = "aws_s3_public_access_block_configuration"
    kind_display: ClassVar[str] = "AWS S3 Public Access Block Configuration"
    kind_description: ClassVar[str] = (
        "S3 Public Access Block Configuration is a feature in AWS S3 that allows"
        " users to manage and restrict public access to their S3 buckets and objects."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "block_public_acls": S("BlockPublicAcls"),
        "ignore_public_acls": S("IgnorePublicAcls"),
        "block_public_policy": S("BlockPublicPolicy"),
        "restrict_public_buckets": S("RestrictPublicBuckets"),
    }
    block_public_acls: Optional[bool] = field(default=False)
    ignore_public_acls: Optional[bool] = field(default=False)
    block_public_policy: Optional[bool] = field(default=False)
    restrict_public_buckets: Optional[bool] = field(default=False)


@define(eq=False, slots=False)
class AwsS3Owner:
    kind: ClassVar[str] = "aws_s3_owner"
    kind_display: ClassVar[str] = "AWS S3 Owner"
    kind_description: ClassVar[str] = (
        "The AWS S3 Owner refers to the account or entity that owns the Amazon S3"
        " bucket, which is a storage resource provided by Amazon Web Services."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"display_name": S("DisplayName"), "id": S("ID")}
    display_name: Optional[str] = field(default=None)
    id: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsS3Grantee:
    kind: ClassVar[str] = "aws_s3_grantee"
    kind_display: ClassVar[str] = "AWS S3 Grantee"
    kind_description: ClassVar[str] = (
        "AWS S3 Grantees are entities that have been given permission to access objects in an S3 bucket."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "display_name": S("DisplayName"),
        "email_address": S("EmailAddress"),
        "id": S("ID"),
        "type": S("Type"),
        "uri": S("URI"),
    }
    display_name: Optional[str] = field(default=None)
    email_address: Optional[str] = field(default=None)
    id: Optional[str] = field(default=None)
    type: Optional[str] = field(default=None)
    uri: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsS3Grant:
    kind: ClassVar[str] = "aws_s3_grant"
    kind_display: ClassVar[str] = "AWS S3 Grant"
    kind_description: ClassVar[str] = (
        "AWS S3 Grant is a permission that allows a specific user or group to access"
        " and perform operations on an S3 bucket or object in the Amazon S3 storage"
        " service."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "grantee": S("Grantee") >> Bend(AwsS3Grantee.mapping),
        "permission": S("Permission"),
    }
    grantee: Optional[AwsS3Grantee] = field(default=None)
    permission: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsS3BucketAcl:
    kind: ClassVar[str] = "aws_s3_bucket_acl"
    kind_display: ClassVar[str] = "AWS S3 Bucket ACL"
    kind_description: ClassVar[str] = (
        "S3 Bucket ACL (Access Control List) is a set of permissions that defines who"
        " can access objects (files) stored in an Amazon S3 bucket and what actions"
        " they can perform on those objects."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "owner": S("Owner") >> Bend(AwsS3Owner.mapping),
        "grants": S("Grants", default=[]) >> ForallBend(AwsS3Grant.mapping),
    }
    owner: Optional[AwsS3Owner] = field(default=None)
    grants: List[AwsS3Grant] = field(factory=list)


@define(eq=False, slots=False)
class AwsS3TargetGrant:
    kind: ClassVar[str] = "aws_s3_target_grant"
    kind_display: ClassVar[str] = "AWS S3 Target Grant"
    kind_description: ClassVar[str] = (
        "The AWS S3 Target Grant is a Container for granting information."
        " By specifying a grantee and the type of permission, you can control how your S3 content is shared."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "grantee": S("Grantee") >> Bend(AwsS3Grantee.mapping),
        "permission": S("Permission"),
    }
    grantee: Optional[AwsS3Grantee] = field(default=None)
    permission: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsS3Logging:
    kind: ClassVar[str] = "aws_s3_logging"
    kind_display: ClassVar[str] = "AWS S3 Logging"
    kind_description: ClassVar[str] = (
        "S3 Logging is a feature in Amazon Simple Storage Service that allows users"
        " to track and record access logs for their S3 buckets."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "target_bucket": S("TargetBucket"),
        "target_grants": S("TargetGrants") >> ForallBend(AwsS3TargetGrant.mapping),
        "target_prefix": S("TargetPrefix"),
    }
    target_bucket: Optional[str] = field(default=None)
    target_grants: Optional[List[AwsS3TargetGrant]] = field(default=None)
    target_prefix: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsS3Bucket(AwsResource, BaseBucket):
    kind: ClassVar[str] = "aws_s3_bucket"
    kind_display: ClassVar[str] = "AWS S3 Bucket"
    aws_metadata: ClassVar[Dict[str, Any]] = {"provider_link_tpl": "https://s3.console.aws.amazon.com/s3/buckets/{name}?region={region_id}&bucketType=general&tab=objects", "arn_tpl": "arn:{partition}:s3:{region}:{account}:bucket/{name}"}  # fmt: skip
    kind_description: ClassVar[str] = (
        "S3 buckets are simple storage containers in Amazon's cloud, offering a"
        " scalable storage solution for various types of data."
    )
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec(
        service_name, "list-buckets", "Buckets", override_iam_permission="s3:ListAllMyBuckets"
    )
    mapping: ClassVar[Dict[str, Bender]] = {"id": S("Name"), "name": S("Name"), "ctime": S("CreationDate")}
    bucket_encryption_rules: Optional[List[AwsS3ServerSideEncryptionRule]] = field(default=None)
    bucket_policy: Optional[Json] = field(default=None)
    bucket_versioning: Optional[bool] = field(default=None)
    bucket_mfa_delete: Optional[bool] = field(default=None)
    bucket_public_access_block_configuration: Optional[AwsS3PublicAccessBlockConfiguration] = field(default=None)
    bucket_acl: Optional[AwsS3BucketAcl] = field(default=None)
    bucket_logging: Optional[AwsS3Logging] = field(default=None)

    @classmethod
    def called_collect_apis(cls) -> List[AwsApiSpec]:
        return [
            cls.api_spec,
            AwsApiSpec(service_name, "get-bucket-tagging"),
            AwsApiSpec(service_name, "get-bucket-encryption", override_iam_permission="s3:GetEncryptionConfiguration"),
            AwsApiSpec(service_name, "get-bucket-policy"),
            AwsApiSpec(service_name, "get-bucket-versioning"),
            AwsApiSpec(
                service_name, "get-public-access-block", override_iam_permission="s3:GetAccountPublicAccessBlock"
            ),
            AwsApiSpec(service_name, "get-bucket-acl"),
            AwsApiSpec(service_name, "get-bucket-logging"),
        ]

    @classmethod
    def collect(cls: Type[AwsResource], json: List[Json], builder: GraphBuilder) -> None:
        def add_tags(bucket: AwsS3Bucket) -> None:
            tags = bucket._get_tags(builder.client)
            if tags:
                bucket.tags = cast(Dict[str, Optional[str]], tags)

        def add_bucket_encryption(bck: AwsS3Bucket) -> None:
            with builder.suppress(f"{service_name}.get-bucket-encryption"):
                bck.bucket_encryption_rules = []
                for raw in builder.client.list(
                    service_name,
                    "get-bucket-encryption",
                    "ServerSideEncryptionConfiguration.Rules",
                    Bucket=bck.name,
                    expected_errors=["ServerSideEncryptionConfigurationNotFoundError", "NoSuchBucket"],
                ):
                    mapped = bend(AwsS3ServerSideEncryptionRule.mapping, raw)
                    if rule := parse_json(mapped, AwsS3ServerSideEncryptionRule, builder):
                        bck.bucket_encryption_rules.append(rule)

        def add_bucket_policy(bck: AwsS3Bucket) -> None:
            with builder.suppress(f"{service_name}.get-bucket-policy"):
                if raw_policy := builder.client.get(
                    service_name,
                    "get-bucket-policy",
                    "Policy",
                    Bucket=bck.name,
                    expected_errors=["NoSuchBucketPolicy", "NoSuchBucket"],
                ):
                    bck.bucket_policy = sort_json(json_loads(raw_policy), sort_list=True)  # type: ignore

        def add_bucket_versioning(bck: AwsS3Bucket) -> None:
            with builder.suppress(f"{service_name}.get-bucket-versioning"):
                if raw_versioning := builder.client.get(
                    service_name, "get-bucket-versioning", None, Bucket=bck.name, expected_errors=["NoSuchBucket"]
                ):
                    bck.bucket_versioning = raw_versioning.get("Status") == "Enabled"
                    bck.bucket_mfa_delete = raw_versioning.get("MFADelete") == "Enabled"
                else:
                    bck.bucket_versioning = False
                    bck.bucket_mfa_delete = False

        def add_public_access(bck: AwsS3Bucket) -> None:
            with builder.suppress(f"{service_name}.get-public-access-block"):
                if raw_access := builder.client.get(
                    service_name,
                    "get-public-access-block",
                    "PublicAccessBlockConfiguration",
                    Bucket=bck.name,
                    expected_errors=["NoSuchPublicAccessBlockConfiguration", "NoSuchBucket"],
                ):
                    mapped = bend(AwsS3PublicAccessBlockConfiguration.mapping, raw_access)
                    bck.bucket_public_access_block_configuration = parse_json(
                        mapped, AwsS3PublicAccessBlockConfiguration, builder
                    )

        def add_acls(bck: AwsS3Bucket) -> None:
            with builder.suppress(f"{service_name}.get-bucket-acl"):
                if raw := builder.client.get(
                    service_name, "get-bucket-acl", Bucket=bck.name, expected_errors=["NoSuchBucket"]
                ):
                    mapped = bend(AwsS3BucketAcl.mapping, raw)
                    bck.bucket_acl = parse_json(mapped, AwsS3BucketAcl, builder)

        def add_bucket_logging(bck: AwsS3Bucket) -> None:
            with builder.suppress(f"{service_name}.get-bucket-logging"):
                if raw := builder.client.get(
                    service_name,
                    "get-bucket-logging",
                    "LoggingEnabled",
                    Bucket=bck.name,
                    expected_errors=["NoSuchBucket"],
                ):
                    mapped = bend(AwsS3Logging.mapping, raw)
                    # do not set, if no property is set
                    if not is_empty(mapped):
                        bck.bucket_logging = parse_json(mapped, AwsS3Logging, builder)

        for js in json:
            if bucket := cls.from_api(js, builder):
                bucket.set_arn(builder=builder, region="", account="", resource=bucket.safe_name)
                builder.add_node(bucket, js)
                builder.submit_work(service_name, add_tags, bucket)
                builder.submit_work(service_name, add_bucket_encryption, bucket)
                builder.submit_work(service_name, add_bucket_policy, bucket)
                builder.submit_work(service_name, add_bucket_versioning, bucket)
                builder.submit_work(service_name, add_public_access, bucket)
                builder.submit_work(service_name, add_acls, bucket)
                builder.submit_work(service_name, add_bucket_logging, bucket)

    def _set_tags(self, client: AwsClient, tags: Dict[str, str]) -> bool:
        tag_set = [{"Key": k, "Value": v} for k, v in tags.items()]
        client.call(
            aws_service=service_name,
            action="put-bucket-tagging",
            result_name=None,
            Bucket=self.name,
            Tagging={"TagSet": tag_set},
        )
        return True

    def _get_tags(self, client: AwsClient) -> Dict[str, str]:
        """Fetch the S3 buckets tags from the AWS API."""
        tag_list = client.list(
            aws_service=service_name,
            action="get-bucket-tagging",
            result_name="TagSet",
            expected_errors=["NoSuchTagSet", "NoSuchBucket"],
            Bucket=self.name,
        )
        return tags_as_dict(tag_list)  # type: ignore

    @classmethod
    def collect_usage_metrics(cls: Type[AwsResource], builder: GraphBuilder) -> None:
        s3s = {s3.id: s3 for s3 in builder.nodes(clazz=AwsS3Bucket) if s3.region().id == builder.region.id}
        queries = []
        delta = builder.metrics_delta
        start = builder.metrics_start
        now = builder.created_at

        for s3_id, s3 in s3s.items():
            queries.append(
                AwsCloudwatchQuery.create(
                    metric_name="NumberOfObjects",
                    namespace="AWS/S3",
                    period=delta,
                    ref_id=s3_id,
                    stat="Average",  # only one valid statistic
                    unit="Count",
                    BucketName=s3.name or s3.safe_name,
                )
            )
            queries.append(
                AwsCloudwatchQuery.create(
                    metric_name="BucketSizeBytes",
                    namespace="AWS/S3",
                    period=delta,
                    ref_id=s3_id,
                    stat="Average",  # only one valid statistic
                    unit="Bytes",
                    BucketName=s3.name or s3.safe_name,
                )
            )
        metric_normalizers = {
            "BucketSizeBytes": MetricNormalization(
                metric_name=MetricName.BucketSizeBytes,
                unit=MetricUnit.Bytes,
                normalize_value=lambda x: round(x, ndigits=4),
            ),
            "NumberOfObjects": MetricNormalization(
                metric_name=MetricName.NumberOfObjects,
                unit=MetricUnit.Count,
                normalize_value=lambda x: round(x, ndigits=4),
            ),
        }

        cloudwatch_result = AwsCloudwatchMetricData.query_for(builder, queries, start, now)

        update_resource_metrics(s3s, cloudwatch_result, metric_normalizers)

    def update_resource_tag(self, client: AwsClient, key: str, value: str) -> bool:
        tags = self._get_tags(client)
        tags[key] = value
        return self._set_tags(client, tags)

    def delete_resource_tag(self, client: AwsClient, key: str) -> bool:
        tags = self._get_tags(client)
        if key in tags:
            del tags[key]
        else:
            raise KeyError(key)
        return self._set_tags(client, tags)

    def delete_resource(self, client: AwsClient, graph: Graph) -> bool:
        def delete_bucket_content(s3: Any) -> bool:
            bucket = s3.Bucket(self.name)
            bucket.objects.delete()
            bucket.delete()
            return True

        return client.with_resource(service_name, delete_bucket_content) or False

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return [
            AwsApiSpec(service_name, "put-bucket-tagging"),
            AwsApiSpec(service_name, "delete-object"),
            AwsApiSpec(service_name, "delete-bucket"),
        ]

    @staticmethod
    def name_from_path(path_or_uri: str) -> str:
        # https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-bucket-intro.html
        # Accessing a bucket using S3://
        if path_or_uri.startswith("s3://") or path_or_uri.startswith("S3://"):
            return path_or_uri.split("/")[2]
        # Path-style access
        if path_or_uri.startswith("https://s3"):
            bucket_and_key = path_or_uri.split("amazonaws.com/")[-1]
            return bucket_and_key.split("/")[0]
        # Virtual-hosted–style access
        if path_or_uri.startswith("https://"):
            bucket_and_key = path_or_uri.split("//")[-1]
            return bucket_and_key.split(".")[0]
        return path_or_uri


@define(eq=False)
class AwsS3AccountSettings(AwsResource, PhantomBaseResource):
    # This resource is fetched once for every account.

    kind: ClassVar[str] = "aws_s3_account_settings"
    kind_display: ClassVar[str] = "AWS S3 Account Settings"
    aws_metadata: ClassVar[Dict[str, Any]] = {"provider_link_tpl": "https://s3.console.aws.amazon.com/s3/settings?region={region_id}", "arn_tpl": "arn:{partition}:s3control:{region}:{account}:account/{name}"}  # fmt: skip

    kind_description: ClassVar[str] = (
        "AWS S3 Account Settings refer to the configuration options and preferences"
        " available for an Amazon S3 (Simple Storage Service) account."
    )
    reference_kinds: ClassVar[ModelReference] = {
        "successors": {"default": ["aws_account"]},
    }
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec(
        "s3control",
        "get-public-access-block",
        override_iam_permission="s3:GetAccountPublicAccessBlock",
    )

    bucket_public_access_block_configuration: Optional[AwsS3PublicAccessBlockConfiguration] = field(default=None)

    @classmethod
    def collect_resources(cls: Type[AwsResource], builder: GraphBuilder) -> None:
        node = AwsS3AccountSettings(
            id=builder.account.id,
            name=builder.account.name,
            ctime=builder.account.ctime,
            bucket_public_access_block_configuration=AwsS3PublicAccessBlockConfiguration(),
        )
        if raw := builder.client.get(
            "s3control",
            "get-public-access-block",
            "PublicAccessBlockConfiguration",
            AccountId=builder.account.id,
            expected_errors=["NoSuchPublicAccessBlockConfiguration"],
        ):
            mapped = bend(AwsS3PublicAccessBlockConfiguration.mapping, raw)
            node.bucket_public_access_block_configuration = parse_json(
                mapped, AwsS3PublicAccessBlockConfiguration, builder
            )
        builder.add_node(node)
        builder.add_edge(builder.account, node=node)


resources: List[Type[AwsResource]] = [AwsS3AccountSettings, AwsS3Bucket]
