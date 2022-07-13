from typing import ClassVar, Dict, List, Type, Optional  # noqa: F401

from attrs import define

from resoto_plugin_aws.resource.base import AwsResource, AwsApiSpec
from resotolib.baseresources import BaseBucket, BaseAccount  # noqa: F401
from resotolib.json_bender import Bender, S


@define(eq=False, slots=False)
class AwsS3Bucket(AwsResource, BaseBucket):
    kind: ClassVar[str] = "aws_s3_bucket"
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec("s3", "list-buckets", "Buckets")
    mapping: ClassVar[Dict[str, Bender]] = {"id": S("Name"), "name": S("Name"), "ctime": S("CreationDate")}


resources: List[Type[AwsResource]] = [AwsS3Bucket]
