from typing import ClassVar, Dict, List, Optional, Type
from attr import define, field
from resoto_plugin_aws.resource.base import AwsApiSpec, AwsResource
from resotolib.json_bender import Bender, S, Bend


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


resources: List[Type[AwsResource]] = [AwsBeanstalkApplication]
