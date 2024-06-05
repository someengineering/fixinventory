from datetime import datetime
from typing import ClassVar, Dict, Optional, List, Type, Any

from attrs import define, field

from fix_plugin_aws.resource.base import AwsResource, AwsApiSpec, GraphBuilder
from fix_plugin_aws.resource.kms import AwsKmsKey
from fix_plugin_aws.utils import ToDict
from fixlib.json_bender import Bender, S, Bend
from fixlib.types import Json

service_name = "secretsmanager"


@define(eq=False, slots=False)
class AwsSecretsManagerRotationRulesType:
    kind: ClassVar[str] = "aws_secretsmanager_rotation_rules_type"
    mapping: ClassVar[Dict[str, Bender]] = {
        "automatically_after_days": S("AutomaticallyAfterDays"),
        "duration": S("Duration"),
        "schedule_expression": S("ScheduleExpression"),
    }
    automatically_after_days: Optional[int] = field(default=None, metadata={"description": "The number of days between rotations of the secret. You can use this value to check that your secret meets your compliance guidelines for how often secrets must be rotated. If you use this field to set the rotation schedule, Secrets Manager calculates the next rotation date based on the previous rotation. Manually updating the secret value by calling PutSecretValue or UpdateSecret is considered a valid rotation. In DescribeSecret and ListSecrets, this value is calculated from the rotation schedule after every successful rotation. In RotateSecret, you can set the rotation schedule in RotationRules with AutomaticallyAfterDays or ScheduleExpression, but not both. To set a rotation schedule in hours, use ScheduleExpression."})  # fmt: skip
    duration: Optional[str] = field(default=None, metadata={"description": "The length of the rotation window in hours, for example 3h for a three hour window. Secrets Manager rotates your secret at any time during this window. The window must not extend into the next rotation window or the next UTC day. The window starts according to the ScheduleExpression. If you don't specify a Duration, for a ScheduleExpression in hours, the window automatically closes after one hour. For a ScheduleExpression in days, the window automatically closes at the end of the UTC day. For more information, including examples, see Schedule expressions in Secrets Manager rotation in the Secrets Manager Users Guide."})  # fmt: skip
    schedule_expression: Optional[str] = field(default=None, metadata={"description": "A cron() or rate() expression that defines the schedule for rotating your secret. Secrets Manager rotation schedules use UTC time zone. Secrets Manager rotates your secret any time during a rotation window. Secrets Manager rate() expressions represent the interval in hours or days that you want to rotate your secret, for example rate(12 hours) or rate(10 days). You can rotate a secret as often as every four hours. If you use a rate() expression, the rotation window starts at midnight. For a rate in hours, the default rotation window closes after one hour. For a rate in days, the default rotation window closes at the end of the day. You can set the Duration to change the rotation window. The rotation window must not extend into the next UTC day or into the next rotation window. You can use a cron() expression to create a rotation schedule that is more detailed than a rotation interval. For more information, including examples, see Schedule expressions in Secrets Manager rotation in the Secrets Manager Users Guide. For a cron expression that represents a schedule in hours, the default rotation window closes after one hour. For a cron expression that represents a schedule in days, the default rotation window closes at the end of the day. You can set the Duration to change the rotation window. The rotation window must not extend into the next UTC day or into the next rotation window."})  # fmt: skip


@define(eq=False, slots=False)
class AwsSecretsManagerSecret(AwsResource):
    kind: ClassVar[str] = "aws_secretsmanager_secret"
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec(service_name, "list-secrets", "SecretList")
    kind_display: ClassVar[str] = "AWS Secrets Manager Secret"
    kind_description: ClassVar[str] = "An AWS Secrets Manager Secret is used for securely storing and managing sensitive information, such as passwords, API keys, and database credentials, in AWS environments."  # fmt: skip
    aws_metadata: ClassVar[Dict[str, Any]] = {"provider_link_tpl": "https://{region_id}.console.aws.amazon.com/secretsmanager/home?region={region}#/secret?name={name}", "arn_tpl": "arn:{partition}:secretsmanager:{region}:{account}:secret/{name}"}  # fmt: skip
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("Name"),
        "tags": S("Tags", default=[]) >> ToDict(),
        "name": S("Name"),
        "ctime": S("CreatedDate"),
        "mtime": S("LastChangedDate"),
        "atime": S("LastAccessedDate"),
        "arn": S("ARN"),
        "description": S("Description"),
        "rotation_enabled": S("RotationEnabled"),
        "rotation_lambda_arn": S("RotationLambdaARN"),
        "rotation_rules": S("RotationRules") >> Bend(AwsSecretsManagerRotationRulesType.mapping),
        "last_rotated_date": S("LastRotatedDate"),
        "last_changed_date": S("LastChangedDate"),
        "last_accessed_date": S("LastAccessedDate"),
        "deleted_date": S("DeletedDate"),
        "next_rotation_date": S("NextRotationDate"),
        "secret_versions_to_stages": S("SecretVersionsToStages"),
        "owning_service": S("OwningService"),
        "created_date": S("CreatedDate"),
        "primary_region": S("PrimaryRegion"),
    }
    arn: Optional[str] = field(default=None, metadata={"description": "The Amazon Resource Name (ARN) of the secret."})  # fmt: skip
    name: Optional[str] = field(default=None, metadata={"description": "The friendly name of the secret."})  # fmt: skip
    description: Optional[str] = field(default=None, metadata={"description": "The user-provided description of the secret."})  # fmt: skip
    rotation_enabled: Optional[bool] = field(default=None, metadata={"description": "Indicates whether automatic, scheduled rotation is enabled for this secret."})  # fmt: skip
    rotation_lambda_arn: Optional[str] = field(default=None, metadata={"description": "The ARN of an Amazon Web Services Lambda function invoked by Secrets Manager to rotate and expire the secret either automatically per the schedule or manually by a call to  RotateSecret ."})  # fmt: skip
    rotation_rules: Optional[AwsSecretsManagerRotationRulesType] = field(default=None, metadata={"description": "A structure that defines the rotation configuration for the secret."})  # fmt: skip
    last_rotated_date: Optional[datetime] = field(default=None, metadata={"description": "The most recent date and time that the Secrets Manager rotation process was successfully completed. This value is null if the secret hasn't ever rotated."})  # fmt: skip
    last_changed_date: Optional[datetime] = field(default=None, metadata={"description": "The last date and time that this secret was modified in any way."})  # fmt: skip
    last_accessed_date: Optional[datetime] = field(default=None, metadata={"ignore_history": True, "description": "The date that the secret was last accessed in the Region. This field is omitted if the secret has never been retrieved in the Region."})  # fmt: skip
    deleted_date: Optional[datetime] = field(default=None, metadata={"description": "The date and time the deletion of the secret occurred. Not present on active secrets. The secret can be recovered until the number of days in the recovery window has passed, as specified in the RecoveryWindowInDays parameter of the  DeleteSecret  operation."})  # fmt: skip
    next_rotation_date: Optional[datetime] = field(default=None, metadata={"description": "The next rotation is scheduled to occur on or before this date. If the secret isn't configured for rotation, Secrets Manager returns null."})  # fmt: skip
    secret_versions_to_stages: Optional[Dict[str, List[str]]] = field(default=None, metadata={"description": "A list of all of the currently assigned SecretVersionStage staging labels and the SecretVersionId attached to each one. Staging labels are used to keep track of the different versions during the rotation process.  A version that does not have any SecretVersionStage is considered deprecated and subject to deletion. Such versions are not included in this list."})  # fmt: skip
    owning_service: Optional[str] = field(default=None, metadata={"description": "Returns the name of the service that created the secret."})  # fmt: skip
    created_date: Optional[datetime] = field(default=None, metadata={"description": "The date and time when a secret was created."})  # fmt: skip
    primary_region: Optional[str] = field(default=None, metadata={"description": "The Region where Secrets Manager originated the secret."})  # fmt: skip

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if kms_key_id := source.get("KmsKeyId"):
            builder.dependant_node(from_node=self, clazz=AwsKmsKey, id=AwsKmsKey.normalise_id(kms_key_id))


resources: List[Type[AwsResource]] = [AwsSecretsManagerSecret]
