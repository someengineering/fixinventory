import json
import logging
from contextlib import suppress
from datetime import datetime
from typing import ClassVar, Dict, Optional, List, Type

import yaml
from attrs import define, field
from boto3.exceptions import Boto3Error

from resoto_plugin_aws.resource.base import AwsApiSpec, AwsResource, GraphBuilder, parse_json
from resoto_plugin_aws.resource.ec2 import AwsEc2Instance
from resoto_plugin_aws.utils import ToDict
from resotolib.baseresources import ModelReference
from resotolib.json_bender import Bender, S, Bend, AsDateString, ForallBend
from resotolib.types import Json

log = logging.getLogger("resoto.plugins.aws")
service_name = "ssm"


@define(eq=False, slots=False)
class AwsSSMInstanceAggregatedAssociationOverview:
    kind: ClassVar[str] = "aws_ssm_instance_aggregated_association_overview"
    mapping: ClassVar[Dict[str, Bender]] = {
        "detailed_status": S("DetailedStatus"),
        "instance_association_status_aggregated_count": S("InstanceAssociationStatusAggregatedCount"),
    }
    detailed_status: Optional[str] = field(default=None, metadata={"description": "Detailed status information about the aggregated associations."})  # fmt: skip
    instance_association_status_aggregated_count: Optional[Dict[str, int]] = field(default=None, metadata={"description": "The number of associations for the managed node(s)."})  # fmt: skip


@define(eq=False, slots=False)
class AwsSSMInstanceInformation(AwsResource):
    kind: ClassVar[str] = "aws_ssm_instance_information"
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec("ssm", "describe-instance-information", "InstanceInformationList")
    reference_kinds: ClassVar[ModelReference] = {
        "successors": {"default": ["aws_ec2_instance"]},
    }
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "tags": S("Tags", default=[]) >> ToDict(),
        "name": S("Name"),
        "instance_id": S("InstanceId"),
        "ping_status": S("PingStatus"),
        "last_ping": S("LastPingDateTime") >> AsDateString(),
        "agent_version": S("AgentVersion"),
        "is_latest_version": S("IsLatestVersion"),
        "platform_type": S("PlatformType"),
        "platform_name": S("PlatformName"),
        "platform_version": S("PlatformVersion"),
        "activation_id": S("ActivationId"),
        "iam_role": S("IamRole"),
        "registration_date": S("RegistrationDate") >> AsDateString(),
        "resource_type": S("ResourceType"),
        "ip_address": S("IPAddress"),
        "computer_name": S("ComputerName"),
        "association_status": S("AssociationStatus"),
        "last_association_execution_date": S("LastAssociationExecutionDate") >> AsDateString(),
        "last_successful_association_execution_date": S("LastSuccessfulAssociationExecutionDate") >> AsDateString(),
        "association_overview": S("AssociationOverview") >> Bend(AwsSSMInstanceAggregatedAssociationOverview.mapping),
        "source_id": S("SourceId"),
        "source_type": S("SourceType"),
    }
    instance_id: Optional[str] = field(default=None, metadata={"description": "The managed node ID."})  # fmt: skip
    ping_status: Optional[str] = field(default=None, metadata={"description": "Connection status of SSM Agent.   The status Inactive has been deprecated and is no longer in use."})  # fmt: skip
    last_ping: Optional[datetime] = field(default=None, metadata={"description": "The date and time when the agent last pinged the Systems Manager service."})  # fmt: skip
    agent_version: Optional[str] = field(default=None, metadata={"description": "The version of SSM Agent running on your Linux managed node."})  # fmt: skip
    is_latest_version: Optional[bool] = field(default=None, metadata={"description": "Indicates whether the latest version of SSM Agent is running on your Linux managed node. This field doesn't indicate whether or not the latest version is installed on Windows managed nodes, because some older versions of Windows Server use the EC2Config service to process Systems Manager requests."})  # fmt: skip
    platform_type: Optional[str] = field(default=None, metadata={"description": "The operating system platform type."})  # fmt: skip
    platform_name: Optional[str] = field(default=None, metadata={"description": "The name of the operating system platform running on your managed node."})  # fmt: skip
    platform_version: Optional[str] = field(default=None, metadata={"description": "The version of the OS platform running on your managed node."})  # fmt: skip
    activation_id: Optional[str] = field(default=None, metadata={"description": "The activation ID created by Amazon Web Services Systems Manager when the server or virtual machine (VM) was registered."})  # fmt: skip
    iam_role: Optional[str] = field(default=None, metadata={"description": "The Identity and Access Management (IAM) role assigned to the on-premises Systems Manager managed node. This call doesn't return the IAM role for Amazon Elastic Compute Cloud (Amazon EC2) instances. To retrieve the IAM role for an EC2 instance, use the Amazon EC2 DescribeInstances operation. For information, see DescribeInstances in the Amazon EC2 API Reference or describe-instances in the Amazon Web Services CLI Command Reference."})  # fmt: skip
    registration_date: Optional[datetime] = field(default=None, metadata={"description": "The date the server or VM was registered with Amazon Web Services as a managed node."})  # fmt: skip
    resource_type: Optional[str] = field(default=None, metadata={"description": "The type of instance. Instances are either EC2 instances or managed instances."})  # fmt: skip
    name: Optional[str] = field(default=None, metadata={"description": "The name assigned to an on-premises server, edge device, or virtual machine (VM) when it is activated as a Systems Manager managed node. The name is specified as the DefaultInstanceName property using the CreateActivation command. It is applied to the managed node by specifying the Activation Code and Activation ID when you install SSM Agent on the node, as explained in Install SSM Agent for a hybrid environment (Linux) and Install SSM Agent for a hybrid environment (Windows). To retrieve the Name tag of an EC2 instance, use the Amazon EC2 DescribeInstances operation. For information, see DescribeInstances in the Amazon EC2 API Reference or describe-instances in the Amazon Web Services CLI Command Reference."})  # fmt: skip
    ip_address: Optional[str] = field(default=None, metadata={"description": "The IP address of the managed node."})  # fmt: skip
    computer_name: Optional[str] = field(default=None, metadata={"description": "The fully qualified host name of the managed node."})  # fmt: skip
    association_status: Optional[str] = field(default=None, metadata={"description": "The status of the association."})  # fmt: skip
    last_association_execution_date: Optional[datetime] = field(default=None, metadata={"description": "The date the association was last run."})  # fmt: skip
    last_successful_association_execution_date: Optional[datetime] = field(default=None, metadata={"description": "The last date the association was successfully run."})  # fmt: skip
    association_overview: Optional[AwsSSMInstanceAggregatedAssociationOverview] = field(default=None, metadata={"description": "Information about the association."})  # fmt: skip
    source_id: Optional[str] = field(default=None, metadata={"description": "The ID of the source resource. For IoT Greengrass devices, SourceId is the Thing name."})  # fmt: skip
    source_type: Optional[str] = field(default=None, metadata={"description": "The type of the source resource. For IoT Greengrass devices, SourceType is AWS::IoT::Thing."})  # fmt: skip

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if self.resource_type == "EC2Instance" and (instance_id := self.instance_id):
            builder.dependant_node(self, clazz=AwsEc2Instance, id=instance_id)


@define(eq=False, slots=False)
class AwsSSMDocumentParameter:
    kind: ClassVar[str] = "aws_ssm_document_parameter"
    mapping: ClassVar[Dict[str, Bender]] = {
        "name": S("Name"),
        "type": S("Type"),
        "description": S("Description"),
        "default_value": S("DefaultValue"),
    }
    name: Optional[str] = field(default=None, metadata={"description": "The name of the parameter."})  # fmt: skip
    type: Optional[str] = field(default=None, metadata={"description": "The type of parameter. The type can be either String or StringList."})  # fmt: skip
    description: Optional[str] = field(default=None, metadata={"description": "A description of what the parameter does, how to use it, the default value, and whether or not the parameter is optional."})  # fmt: skip
    default_value: Optional[str] = field(default=None, metadata={"description": "If specified, the default values for the parameters. Parameters without a default value are required. Parameters with a default value are optional."})  # fmt: skip


@define(eq=False, slots=False)
class AwsSSMDocumentRequires:
    kind: ClassVar[str] = "aws_ssm_document_requires"
    mapping: ClassVar[Dict[str, Bender]] = {
        "name": S("Name"),
        "version": S("Version"),
        "require_type": S("RequireType"),
        "version_name": S("VersionName"),
    }
    name: Optional[str] = field(default=None, metadata={"description": "The name of the required SSM document. The name can be an Amazon Resource Name (ARN)."})  # fmt: skip
    version: Optional[str] = field(default=None, metadata={"description": "The document version required by the current document."})  # fmt: skip
    require_type: Optional[str] = field(default=None, metadata={"description": "The document type of the required SSM document."})  # fmt: skip
    version_name: Optional[str] = field(default=None, metadata={"description": "An optional field specifying the version of the artifact associated with the document. For example, Release 12, Update 6. This value is unique across all versions of a document, and can't be changed."})  # fmt: skip


@define(eq=False, slots=False)
class AwsSSMReviewInformation:
    kind: ClassVar[str] = "aws_ssm_review_information"
    mapping: ClassVar[Dict[str, Bender]] = {
        "reviewed_time": S("ReviewedTime"),
        "status": S("Status"),
        "reviewer": S("Reviewer"),
    }
    reviewed_time: Optional[datetime] = field(default=None, metadata={"description": "The time that the reviewer took action on the document review request."})  # fmt: skip
    status: Optional[str] = field(default=None, metadata={"description": "The current status of the document review request."})  # fmt: skip
    reviewer: Optional[str] = field(default=None, metadata={"description": "The reviewer assigned to take action on the document review request."})  # fmt: skip


@define(eq=False, slots=False)
class AwsSSMAccountSharingInfo:
    kind: ClassVar[str] = "aws_ssm_account_sharing_info"
    mapping: ClassVar[Dict[str, Bender]] = {
        "account_id": S("AccountId"),
        "shared_document_version": S("SharedDocumentVersion"),
    }
    account_id: Optional[str] = field(default=None, metadata={"description": "The Amazon Web Services account ID where the current document is shared."})  # fmt: skip
    shared_document_version: Optional[str] = field(default=None, metadata={"description": "The version of the current document shared with the account."})  # fmt: skip


@define(eq=False, slots=False)
class AwsSSMDocument(AwsResource):
    kind: ClassVar[str] = "aws_ssm_document"
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("Name"),
        "tags": S("Tags", default=[]) >> ToDict(),
        "name": S("Name"),
        "ctime": S("CreatedDate"),
        "sha1": S("Sha1"),
        "hash": S("Hash"),
        "hash_type": S("HashType"),
        "display_name": S("DisplayName"),
        "version_name": S("VersionName"),
        "owner": S("Owner"),
        "status": S("Status"),
        "status_information": S("StatusInformation"),
        "document_version": S("DocumentVersion"),
        "description": S("Description"),
        "parameters": S("Parameters", default=[]) >> ForallBend(AwsSSMDocumentParameter.mapping),
        "platform_types": S("PlatformTypes", default=[]),
        "document_type": S("DocumentType"),
        "schema_version": S("SchemaVersion"),
        "latest_version": S("LatestVersion"),
        "default_version": S("DefaultVersion"),
        "document_format": S("DocumentFormat"),
        "target_type": S("TargetType"),
        "attachments_information": S("AttachmentsInformation", default=[]) >> ForallBend(S("Name")),
        "requires": S("Requires", default=[]) >> ForallBend(AwsSSMDocumentRequires.mapping),
        "author": S("Author"),
        "review_information": S("ReviewInformation", default=[]) >> ForallBend(AwsSSMReviewInformation.mapping),
        "approved_version": S("ApprovedVersion"),
        "pending_review_version": S("PendingReviewVersion"),
        "review_status": S("ReviewStatus"),
        "category": S("Category", default=[]),
        "category_enum": S("CategoryEnum", default=[]),
    }
    sha1: Optional[str] = field(default=None, metadata={"description": "The SHA1 hash of the document, which you can use for verification."})  # fmt: skip
    hash: Optional[str] = field(default=None, metadata={"description": "The Sha256 or Sha1 hash created by the system when the document was created.   Sha1 hashes have been deprecated."})  # fmt: skip
    hash_type: Optional[str] = field(default=None, metadata={"description": "The hash type of the document. Valid values include Sha256 or Sha1.  Sha1 hashes have been deprecated."})  # fmt: skip
    name: Optional[str] = field(default=None, metadata={"description": "The name of the SSM document."})  # fmt: skip
    display_name: Optional[str] = field(default=None, metadata={"description": "The friendly name of the SSM document. This value can differ for each version of the document. If you want to update this value, see UpdateDocument."})  # fmt: skip
    version_name: Optional[str] = field(default=None, metadata={"description": "The version of the artifact associated with the document."})  # fmt: skip
    owner: Optional[str] = field(default=None, metadata={"description": "The Amazon Web Services user that created the document."})  # fmt: skip
    status: Optional[str] = field(default=None, metadata={"description": "The status of the SSM document."})  # fmt: skip
    status_information: Optional[str] = field(default=None, metadata={"description": "A message returned by Amazon Web Services Systems Manager that explains the Status value. For example, a Failed status might be explained by the StatusInformation message, The specified S3 bucket doesn't exist. Verify that the URL of the S3 bucket is correct."})  # fmt: skip
    document_version: Optional[str] = field(default=None, metadata={"description": "The document version."})  # fmt: skip
    description: Optional[str] = field(default=None, metadata={"description": "A description of the document."})  # fmt: skip
    parameters: Optional[List[AwsSSMDocumentParameter]] = field(factory=list, metadata={"description": "A description of the parameters for a document."})  # fmt: skip
    platform_types: Optional[List[str]] = field(factory=list, metadata={"description": "The list of operating system (OS) platforms compatible with this SSM document."})  # fmt: skip
    document_type: Optional[str] = field(default=None, metadata={"description": "The type of document."})  # fmt: skip
    schema_version: Optional[str] = field(default=None, metadata={"description": "The schema version."})  # fmt: skip
    latest_version: Optional[str] = field(default=None, metadata={"description": "The latest version of the document."})  # fmt: skip
    default_version: Optional[str] = field(default=None, metadata={"description": "The default version."})  # fmt: skip
    document_format: Optional[str] = field(default=None, metadata={"description": "The document format, either JSON or YAML."})  # fmt: skip
    target_type: Optional[str] = field(default=None, metadata={"description": "The target type which defines the kinds of resources the document can run on. For example, /AWS::EC2::Instance. For a list of valid resource types, see Amazon Web Services resource and property types reference in the CloudFormation User Guide."})  # fmt: skip
    attachments_information: Optional[List[str]] = field(factory=list, metadata={"description": "Details about the document attachments, including names, locations, sizes, and so on."})  # fmt: skip
    requires: Optional[List[AwsSSMDocumentRequires]] = field(factory=list, metadata={"description": "A list of SSM documents required by a document. For example, an ApplicationConfiguration document requires an ApplicationConfigurationSchema document."})  # fmt: skip
    author: Optional[str] = field(default=None, metadata={"description": "The user in your organization who created the document."})  # fmt: skip
    review_information: Optional[List[AwsSSMReviewInformation]] = field(factory=list, metadata={"description": "Details about the review of a document."})  # fmt: skip
    approved_version: Optional[str] = field(default=None, metadata={"description": "The version of the document currently approved for use in the organization."})  # fmt: skip
    pending_review_version: Optional[str] = field(default=None, metadata={"description": "The version of the document that is currently under review."})  # fmt: skip
    review_status: Optional[str] = field(default=None, metadata={"description": "The current status of the review."})  # fmt: skip
    category: Optional[List[str]] = field(factory=list, metadata={"description": "The classification of a document to help you identify and categorize its use."})  # fmt: skip
    category_enum: Optional[List[str]] = field(factory=list, metadata={"description": "The value that identifies a document's category."})  # fmt: skip
    content: Optional[Json] = field(default=None, metadata={"description": "The content of the document"})  # fmt: skip
    document_shared_with_accounts: Optional[List[str]] = field(factory=list, metadata={"description": "The account IDs that have permission to use this document. The ID can be either an Amazon Web Services account or All."})  # fmt: skip
    document_sharing_info: Optional[List[AwsSSMAccountSharingInfo]] = field(factory=list, metadata={"description": "A list of Amazon Web Services accounts where the current document is shared and the version shared with each account."})  # fmt: skip

    @classmethod
    def collect_resources(cls, builder: GraphBuilder) -> None:
        def collect_document(name: str) -> None:
            with suppress(Exception):
                js = builder.client.get(service_name, "describe-document", "Document", Name=name)
                doc = builder.client.get(service_name, "get-document", Name=name)
                share = builder.client.get(
                    service_name, "describe-document-permission", Name=name, PermissionType="Share"
                )

                if (
                    (js and doc and share)
                    and (content := doc.get("Content"))
                    and (content_format := doc.get("DocumentFormat"))
                    and (instance := cls.from_api(js, builder))
                ):
                    if content_format == "JSON":
                        instance.content = json.loads(content)
                    elif content_format == "YAML":
                        instance.content = yaml.safe_load(content)
                    else:
                        instance.content = content
                    instance.document_shared_with_accounts = share.get("AccountIds", [])
                    instance.document_sharing_info = [
                        sharing_info
                        for sharing_info in [
                            parse_json(jsi, AwsSSMAccountSharingInfo, builder, AwsSSMAccountSharingInfo.mapping)
                            for jsi in share.get("AccountSharingInfoList", [])
                        ]
                        if sharing_info is not None
                    ]
                    builder.add_node(instance, js)

        # Default behavior: in case the class has an ApiSpec, call the api and call collect.
        log.debug(f"Collecting {cls.__name__} in region {builder.region.name}")
        try:
            for item in builder.client.list(
                aws_service=service_name,
                action="list-documents",
                result_name="DocumentIdentifiers",
                Filters=[{"Key": "Owner", "Values": ["Self"]}],
            ):
                builder.submit_work(service_name, collect_document, item["Name"])
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
        return [
            AwsApiSpec(service_name, "list-documents"),
            AwsApiSpec(service_name, "describe-document"),
            AwsApiSpec(service_name, "get-document"),
        ]

    @classmethod
    def service_name(cls) -> Optional[str]:
        return service_name


resources: List[Type[AwsResource]] = [AwsSSMInstanceInformation, AwsSSMDocument]
