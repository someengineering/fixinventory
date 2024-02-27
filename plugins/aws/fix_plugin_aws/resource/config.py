from datetime import datetime
from typing import ClassVar, Dict, Optional, List, Type, Any

from attr import define, field

from fix_plugin_aws.aws_client import AwsClient
from fix_plugin_aws.resource.base import AwsApiSpec, GraphBuilder, parse_json
from fix_plugin_aws.resource.base import AwsResource
from fix_plugin_aws.utils import ToDict
from fixlib.graph import Graph
from fixlib.json_bender import Bender, S, Bend, bend
from fixlib.types import Json

service_name = "config"


@define(eq=False, slots=False)
class AwsConfigRecorderStatus:
    kind: ClassVar[str] = "aws_config_recorder_status"
    kind_display: ClassVar[str] = "AWS Config Recorder Status"
    kind_description: ClassVar[str] = (
        "AWS Config Recorder Status helps you to understand and manage the configurations of your AWS resources."
        " It provides an overview of whether your AWS Config Recorder is recording resource configuration and"
        " compliance data correctly or facing issues."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "last_start_time": S("lastStartTime"),
        "last_stop_time": S("lastStopTime"),
        "recording": S("recording"),
        "last_status": S("lastStatus"),
        "last_error_code": S("lastErrorCode"),
        "last_error_message": S("lastErrorMessage"),
        "last_status_change_time": S("lastStatusChangeTime"),
    }
    last_start_time: Optional[datetime] = field(default=None)
    last_stop_time: Optional[datetime] = field(default=None)
    recording: Optional[bool] = field(default=None)
    last_status: Optional[str] = field(default=None)
    last_error_code: Optional[str] = field(default=None)
    last_error_message: Optional[str] = field(default=None)
    last_status_change_time: Optional[datetime] = field(default=None)


@define(eq=False, slots=False)
class AwsConfigRecordingGroup:
    kind: ClassVar[str] = "aws_config_recording_group"
    kind_display: ClassVar[str] = "AWS Config Recording Group"
    kind_description: ClassVar[str] = (
        "AWS Config Recording Group is a feature of AWS Config that allows users to"
        " specify the types of AWS resources to be recorded and the details to include"
        " in the recorded configurations."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "all_supported": S("allSupported"),
        "include_global_resource_types": S("includeGlobalResourceTypes"),
        "resource_types": S("resourceTypes", default=[]),
    }
    all_supported: Optional[bool] = field(default=None)
    include_global_resource_types: Optional[bool] = field(default=None)
    resource_types: List[str] = field(factory=list)


@define(eq=False, slots=False)
class AwsConfigRecorder(AwsResource):
    kind: ClassVar[str] = "aws_config_recorder"
    kind_display: ClassVar[str] = "AWS Config Recorder"
    aws_metadata: ClassVar[Dict[str, Any]] = {"arn_tpl": "arn:{partition}:config:{region}:{account}:config-recorder/{name}"}  # fmt: skip
    kind_description: ClassVar[str] = (
        "AWS Config Recorder is a service provided by Amazon Web Services that"
        " continuously records the configuration changes made to resources in an AWS"
        " account."
    )
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec(
        service_name, "describe-configuration-recorders", "ConfigurationRecorders"
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("name"),
        "tags": S("Tags", default=[]) >> ToDict(),
        "name": S("name"),
        "arn": S("roleARN"),
        "recorder_group": S("recordingGroup") >> Bend(AwsConfigRecordingGroup.mapping),
    }
    recorder_group: Optional[AwsConfigRecordingGroup] = field(default=None)
    recorder_status: Optional[AwsConfigRecorderStatus] = field(default=None, metadata=dict(ignore_history=True))

    @classmethod
    def collect(cls: Type[AwsResource], json: List[Json], builder: GraphBuilder) -> None:
        # get all statuses
        statuses: Dict[str, AwsConfigRecorderStatus] = {}
        for r in builder.client.list(
            service_name, "describe-configuration-recorder-status", "ConfigurationRecordersStatus"
        ):
            if status := parse_json(bend(AwsConfigRecorderStatus.mapping, r), AwsConfigRecorderStatus, builder):
                statuses[r["name"]] = status

        for js in json:
            if instance := AwsConfigRecorder.from_api(js, builder):
                if status := statuses.get(instance.id):
                    instance.recorder_status = status
                    instance.mtime = status.last_status_change_time
                builder.add_node(instance, js)

    def delete_resource(self, client: AwsClient, graph: Graph) -> bool:
        client.call(service_name, "delete-configuration-recorder", self.name)
        return True

    @classmethod
    def called_collect_apis(cls) -> List[AwsApiSpec]:
        return [cls.api_spec, AwsApiSpec(service_name, "describe-configuration-recorder-status")]

    # this resource does not allow tags
    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return [AwsApiSpec(service_name, "delete-configuration-recorder")]


resources: List[Type[AwsResource]] = [AwsConfigRecorder]
