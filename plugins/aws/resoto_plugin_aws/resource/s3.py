from typing import ClassVar, Dict, List, Type, Optional  # noqa: F401

from attrs import define
import botocore.exceptions
from resoto_plugin_aws.resource.base import AwsResource, AwsApiSpec, GraphBuilder
from resotolib.baseresources import BaseBucket, BaseAccount  # noqa: F401
from resotolib.json_bender import Bender, S
from resoto_plugin_aws.aws_client import AwsClient
from resoto_plugin_aws.utils import tags_as_dict

from resotolib.types import Json
from resoto_plugin_aws.utils import arn_partition


@define(eq=False, slots=False)
class AwsS3Bucket(AwsResource, BaseBucket):
    kind: ClassVar[str] = "aws_s3_bucket"
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec("s3", "list-buckets", "Buckets")
    mapping: ClassVar[Dict[str, Bender]] = {"id": S("Name"), "name": S("Name"), "ctime": S("CreationDate")}

    @classmethod
    def collect(cls: Type[AwsResource], json: List[Json], builder: GraphBuilder) -> None:
        for js in json:
            bucket = cls.from_api(js)
            bucket.arn = f"arn:{arn_partition(builder.region)}:s3:::{bucket.name}"
            builder.add_node(bucket, js)

    def _set_tags(self, client: AwsClient, tags: Dict[str, str]) -> bool:
        tag_set = [{"Key": k, "Value": v} for k, v in tags.items()]
        client.call(
            service="s3", action="put-bucket-tagging", result_name=None, Bucket=self.name, Tagging={"TagSet": tag_set}
        )
        return True

    def _get_tags(self, client: AwsClient) -> Dict[str, str]:
        """Fetch the S3 buckets tags from the AWS API."""
        tags: Dict[str, str] = {}
        try:
            response = client.call(service="s3", action="get_bucket_tagging", result_name="TagSet", Bucket=self.name)
            tags = tags_as_dict(response)  # type: ignore
        except botocore.exceptions.ClientError as e:
            if e.response["Error"]["Code"] != "NoSuchTagSet":
                raise
        return tags

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
        client.call(service="s3", action="delete_bucket", result_name=None, Bucket=self.name)
        return True


resources: List[Type[AwsResource]] = [AwsS3Bucket]
