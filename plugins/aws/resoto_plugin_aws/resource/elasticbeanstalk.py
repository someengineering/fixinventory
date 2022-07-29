from typing import ClassVar, Dict, List, Optional, Type
from attrs import define, field
import botocore.exceptions
from resoto_plugin_aws.aws_client import AwsClient
from resoto_plugin_aws.resource.base import AwsApiSpec, AwsResource
from resotolib.json_bender import Bender, S, Bend
from resoto_plugin_aws.utils import tags_as_dict


@define(eq=False, slots=False)
class AwsBeanstalkMaxCountRule:
    kind: ClassVar[str] = "aws_beanstalk_max_count_rule"
    mapping: ClassVar[Dict[str, Bender]] = {
        "enabled": S("Enabled"),
        "max_count": S("MaxCount"),
        "delete_source_from_s3": S("DeleteSourceFromS3"),
    }
    enabled: Optional[bool] = field(default=None)
    max_count: Optional[int] = field(default=None)
    delete_source_from_s3: Optional[bool] = field(default=None)


@define(eq=False, slots=False)
class AwsBeanstalkMaxAgeRule:
    kind: ClassVar[str] = "aws_beanstalk_max_age_rule"
    mapping: ClassVar[Dict[str, Bender]] = {
        "enabled": S("Enabled"),
        "max_age_in_days": S("MaxAgeInDays"),
        "delete_source_from_s3": S("DeleteSourceFromS3"),
    }
    enabled: Optional[bool] = field(default=None)
    max_age_in_days: Optional[int] = field(default=None)
    delete_source_from_s3: Optional[bool] = field(default=None)


@define(eq=False, slots=False)
class AwsBeanstalkApplicationVersionLifecycleConfig:
    kind: ClassVar[str] = "aws_beanstalk_application_version_lifecycle_config"
    mapping: ClassVar[Dict[str, Bender]] = {
        "max_count_rule": S("MaxCountRule") >> Bend(AwsBeanstalkMaxCountRule.mapping),
        "max_age_rule": S("MaxAgeRule") >> Bend(AwsBeanstalkMaxAgeRule.mapping),
    }
    max_count_rule: Optional[AwsBeanstalkMaxCountRule] = field(default=None)
    max_age_rule: Optional[AwsBeanstalkMaxAgeRule] = field(default=None)


@define(eq=False, slots=False)
class AwsBeanstalkApplicationResourceLifecycleConfig:
    kind: ClassVar[str] = "aws_beanstalk_application_resource_lifecycle_config"
    mapping: ClassVar[Dict[str, Bender]] = {
        "service_role": S("ServiceRole"),
        "version_lifecycle_config": S("VersionLifecycleConfig")
        >> Bend(AwsBeanstalkApplicationVersionLifecycleConfig.mapping),
    }
    service_role: Optional[str] = field(default=None)
    version_lifecycle_config: Optional[AwsBeanstalkApplicationVersionLifecycleConfig] = field(default=None)


@define(eq=False, slots=False)
class AwsBeanstalkApplication(AwsResource):
    kind: ClassVar[str] = "aws_beanstalk_application"
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec("elasticbeanstalk", "describe-applications", "Applications")
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("ApplicationName"),
        "name": S("ApplicationName"),
        "ctime": S("DateCreated"),
        "mtime": S("DateUpdated"),
        "arn": S("ApplicationArn"),
        "description": S("Description"),
        "versions": S("Versions", default=[]),
        "configuration_templates": S("ConfigurationTemplates", default=[]),
        "resource_lifecycle_config": S("ResourceLifecycleConfig")
        >> Bend(AwsBeanstalkApplicationResourceLifecycleConfig.mapping),
    }
    arn: Optional[str] = field(default=None)
    description: Optional[str] = field(default=None)
    versions: List[str] = field(factory=list)
    configuration_templates: List[str] = field(factory=list)
    resource_lifecycle_config: Optional[AwsBeanstalkApplicationResourceLifecycleConfig] = field(default=None)


    def _get_tags(self, client: AwsClient) -> Dict[str, str]:
        """Fetch the Elasticbeanstalk Application tags from the AWS API."""
        tags: Dict[str, str] = {}
        try:
            response = client.call(
                service="elasticbeanstalk", action="list-tags-for-resource", result_name="TagSet", ResourceArn=self.arn
            )
            tags = tags_as_dict(response)  # type: ignore
        except botocore.exceptions.ClientError as e:
            if e.response["Error"]["Code"] != "NoSuchTagSet":
                raise
        return tags

    def update_resource_tag(self, client: AwsClient, key: str, value: str) -> bool:
        client.call(
            service=self.api_spec.service,
            action="update-tags-for-resource",
            result_name=None,
            ResourceArn=self.arn,
            TagsToAdd=[{"Key": key, "Value": value}],
        )
        return True

    def delete_resource_tag(self, client: AwsClient, key: str) -> bool:
        client.call(
            service=self.api_spec.service,
            action="update-tags-for-resource",
            result_name=None,
            ResourceArn=self.arn,
            TagsToRemove=[key],
        )
        return True

    def delete_resource(self, client: AwsClient) -> bool:
        client.call(
            service=self.api_spec.service, action="delete-application", result_name=None, ApplicationName=self.name
        )
        return True


resources: List[Type[AwsResource]] = [AwsBeanstalkApplication]
