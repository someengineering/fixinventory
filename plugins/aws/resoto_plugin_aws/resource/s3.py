from typing import ClassVar, Dict, List, Type, Optional, cast, Any

from attrs import define

from resoto_plugin_aws.aws_client import AwsClient
from resoto_plugin_aws.resource.base import AwsResource, AwsApiSpec, GraphBuilder
from resoto_plugin_aws.utils import tags_as_dict
from resotolib.baseresources import BaseBucket
from resotolib.json_bender import Bender, S
from resotolib.types import Json


@define(eq=False, slots=False)
class AwsS3Bucket(AwsResource, BaseBucket):
    kind: ClassVar[str] = "aws_s3_bucket"
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec(
        "s3", "list-buckets", "Buckets", override_iam_permission="s3:ListBucket"
    )
    mapping: ClassVar[Dict[str, Bender]] = {"id": S("Name"), "name": S("Name"), "ctime": S("CreationDate")}

    @classmethod
    def called_collect_apis(cls) -> List[AwsApiSpec]:
        return [cls.api_spec, AwsApiSpec("s3", "get-bucket-tagging")]

    @classmethod
    def collect(cls: Type[AwsResource], json: List[Json], builder: GraphBuilder) -> None:
        def add_tags(bucket: AwsS3Bucket, client: AwsClient) -> None:
            tags = bucket._get_tags(client)
            if tags:
                bucket.tags = cast(Dict[str, Optional[str]], tags)

        for js in json:
            bucket = cls.from_api(js)
            bucket.set_arn(builder=builder, region="", account="", resource=bucket.safe_name)
            builder.add_node(bucket, js)
            builder.submit_work(add_tags, bucket, builder.client)

    def _set_tags(self, client: AwsClient, tags: Dict[str, str]) -> bool:
        tag_set = [{"Key": k, "Value": v} for k, v in tags.items()]
        client.call(
            aws_service="s3",
            action="put-bucket-tagging",
            result_name=None,
            Bucket=self.name,
            Tagging={"TagSet": tag_set},
        )
        return True

    def _get_tags(self, client: AwsClient) -> Dict[str, str]:
        """Fetch the S3 buckets tags from the AWS API."""
        tag_list = client.list(
            aws_service="s3",
            action="get-bucket-tagging",
            result_name="TagSet",
            expected_errors=["NoSuchTagSet"],
            Bucket=self.name,
        )
        return tags_as_dict(tag_list)  # type: ignore

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

    def delete_resource(self, client: AwsClient) -> bool:
        def delete_bucket_content(s3: Any) -> bool:
            bucket = s3.Bucket(self.name)
            bucket.objects.delete()
            bucket.delete()
            return True

        return client.with_resource("s3", delete_bucket_content) or False

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return [
            AwsApiSpec("s3", "put-bucket-tagging"),
            AwsApiSpec("s3", "delete-object"),
            AwsApiSpec("s3", "delete-bucket"),
        ]


resources: List[Type[AwsResource]] = [AwsS3Bucket]
