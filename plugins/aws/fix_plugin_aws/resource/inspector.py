import logging
from datetime import datetime
from typing import ClassVar, Dict, Optional, List, Type, Any

from attrs import define, field

from fix_plugin_aws.aws_client import AwsClient
from fix_plugin_aws.resource.base import AwsResource, AwsApiSpec, GraphBuilder
from fix_plugin_aws.resource.ec2 import AwsEc2Instance
from fix_plugin_aws.resource.ecr import AwsEcrRepository
from fix_plugin_aws.resource.lambda_ import AwsLambdaFunction
from fixlib.baseresources import ModelReference
from fixlib.graph import Graph
from fixlib.json_bender import Bender, S, ForallBend, Bend, F
from fixlib.types import Json

log = logging.getLogger("fix.plugins.aws")
service_name = "inspector2"


class InspectorResourceTaggable:
    def update_resource_tag(self, client: AwsClient, key: str, value: str) -> bool:
        if isinstance(self, AwsResource):
            client.call(
                aws_service=service_name,
                action="tag-resource",
                result_name=None,
                resourceArn=self.arn,
                tags={key: value},
            )
            return True
        return False

    def delete_resource_tag(self, client: AwsClient, key: str) -> bool:
        if isinstance(self, AwsResource):
            client.call(
                aws_service=service_name,
                action="untag-resource",
                result_name=None,
                resourceArn=self.arn,
                tagKeys=[key],
            )
            return True
        return False

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return [AwsApiSpec(service_name, "tag-resource"), AwsApiSpec(service_name, "untag-resource")]


@define(eq=False, slots=False)
class AwsInspectorV2CodeFilePath:
    kind: ClassVar[str] = "aws_inspector_v2_code_file_path"
    mapping: ClassVar[Dict[str, Bender]] = {
        "end_line": S("endLine"),
        "file_name": S("fileName"),
        "file_path": S("filePath"),
        "start_line": S("startLine"),
    }
    end_line: Optional[int] = field(default=None, metadata={"description": "The line number of the last line of code that a vulnerability was found in."})  # fmt: skip
    file_name: Optional[str] = field(default=None, metadata={"description": "The name of the file the code vulnerability was found in."})  # fmt: skip
    file_path: Optional[str] = field(default=None, metadata={"description": "The file path to the code that a vulnerability was found in."})  # fmt: skip
    start_line: Optional[int] = field(default=None, metadata={"description": "The line number of the first line of code that a vulnerability was found in."})  # fmt: skip


@define(eq=False, slots=False)
class AwsInspectorV2CodeVulnerabilityDetails:
    kind: ClassVar[str] = "aws_inspector_v2_code_vulnerability_details"
    mapping: ClassVar[Dict[str, Bender]] = {
        "cwes": S("cwes", default=[]),
        "detector_id": S("detectorId"),
        "detector_name": S("detectorName"),
        "detector_tags": S("detectorTags", default=[]),
        "file_path": S("filePath") >> Bend(AwsInspectorV2CodeFilePath.mapping),
        "reference_urls": S("referenceUrls", default=[]),
        "rule_id": S("ruleId"),
        "source_lambda_layer_arn": S("sourceLambdaLayerArn"),
    }
    cwes: Optional[List[str]] = field(factory=list, metadata={"description": "The Common Weakness Enumeration (CWE) item associated with the detected vulnerability."})  # fmt: skip
    detector_id: Optional[str] = field(default=None, metadata={"description": "The ID for the Amazon CodeGuru detector associated with the finding. For more information on detectors see Amazon CodeGuru Detector Library."})  # fmt: skip
    detector_name: Optional[str] = field(default=None, metadata={"description": "The name of the detector used to identify the code vulnerability. For more information on detectors see CodeGuru Detector Library."})  # fmt: skip
    detector_tags: Optional[List[str]] = field(factory=list, metadata={"description": "The detector tag associated with the vulnerability. Detector tags group related vulnerabilities by common themes or tactics. For a list of available tags by programming language, see Java tags, or Python tags."})  # fmt: skip
    file_path: Optional[AwsInspectorV2CodeFilePath] = field(default=None, metadata={"description": "Contains information on where the code vulnerability is located in your code."})  # fmt: skip
    reference_urls: Optional[List[str]] = field(factory=list, metadata={"description": "A URL containing supporting documentation about the code vulnerability detected."})  # fmt: skip
    rule_id: Optional[str] = field(default=None, metadata={"description": "The identifier for a rule that was used to detect the code vulnerability."})  # fmt: skip
    source_lambda_layer_arn: Optional[str] = field(default=None, metadata={"description": "The Amazon Resource Name (ARN) of the Lambda layer that the code vulnerability was detected in."})  # fmt: skip


@define(eq=False, slots=False)
class AwsInspectorV2CvssScoreAdjustment:
    kind: ClassVar[str] = "aws_inspector_v2_cvss_score_adjustment"
    mapping: ClassVar[Dict[str, Bender]] = {"metric": S("metric"), "reason": S("reason")}
    metric: Optional[str] = field(default=None, metadata={"description": "The metric used to adjust the CVSS score."})  # fmt: skip
    reason: Optional[str] = field(default=None, metadata={"description": "The reason the CVSS score has been adjustment."})  # fmt: skip


@define(eq=False, slots=False)
class AwsInspectorV2CvssScoreDetails:
    kind: ClassVar[str] = "aws_inspector_v2_cvss_score_details"
    mapping: ClassVar[Dict[str, Bender]] = {
        "adjustments": S("adjustments", default=[]) >> ForallBend(AwsInspectorV2CvssScoreAdjustment.mapping),
        "cvss_source": S("cvssSource"),
        "score": S("score"),
        "score_source": S("scoreSource"),
        "scoring_vector": S("scoringVector"),
        "version": S("version"),
    }
    adjustments: Optional[List[AwsInspectorV2CvssScoreAdjustment]] = field(factory=list, metadata={"description": "An object that contains details about adjustment Amazon Inspector made to the CVSS score."})  # fmt: skip
    cvss_source: Optional[str] = field(default=None, metadata={"description": "The source of the CVSS data."})  # fmt: skip
    score: Optional[float] = field(default=None, metadata={"description": "The CVSS score."})  # fmt: skip
    score_source: Optional[str] = field(default=None, metadata={"description": "The source for the CVSS score."})  # fmt: skip
    scoring_vector: Optional[str] = field(default=None, metadata={"description": "The vector for the CVSS score."})  # fmt: skip
    version: Optional[str] = field(default=None, metadata={"description": "The CVSS version used in scoring."})  # fmt: skip


@define(eq=False, slots=False)
class AwsInspectorV2InspectorScoreDetails:
    kind: ClassVar[str] = "aws_inspector_v2_inspector_score_details"
    mapping: ClassVar[Dict[str, Bender]] = {
        "adjusted_cvss": S("adjustedCvss") >> Bend(AwsInspectorV2CvssScoreDetails.mapping)
    }
    adjusted_cvss: Optional[AwsInspectorV2CvssScoreDetails] = field(default=None, metadata={"description": "An object that contains details about the CVSS score given to a finding."})  # fmt: skip


@define(eq=False, slots=False)
class AwsInspectorV2Step:
    kind: ClassVar[str] = "aws_inspector_v2_step"
    mapping: ClassVar[Dict[str, Bender]] = {"component_id": S("componentId"), "component_type": S("componentType")}
    component_id: Optional[str] = field(default=None, metadata={"description": "The component ID."})  # fmt: skip
    component_type: Optional[str] = field(default=None, metadata={"description": "The component type."})  # fmt: skip


@define(eq=False, slots=False)
class AwsInspectorV2NetworkPath:
    kind: ClassVar[str] = "aws_inspector_v2_network_path"
    mapping: ClassVar[Dict[str, Bender]] = {"steps": S("steps", default=[]) >> ForallBend(AwsInspectorV2Step.mapping)}
    steps: Optional[List[AwsInspectorV2Step]] = field(factory=list, metadata={"description": "The details on the steps in the network path."})  # fmt: skip


@define(eq=False, slots=False)
class AwsInspectorV2PortRange:
    kind: ClassVar[str] = "aws_inspector_v2_port_range"
    mapping: ClassVar[Dict[str, Bender]] = {"begin": S("begin"), "end": S("end")}
    begin: Optional[int] = field(default=None, metadata={"description": "The beginning port in a port range."})  # fmt: skip
    end: Optional[int] = field(default=None, metadata={"description": "The ending port in a port range."})  # fmt: skip


@define(eq=False, slots=False)
class AwsInspectorV2NetworkReachabilityDetails:
    kind: ClassVar[str] = "aws_inspector_v2_network_reachability_details"
    mapping: ClassVar[Dict[str, Bender]] = {
        "network_path": S("networkPath") >> Bend(AwsInspectorV2NetworkPath.mapping),
        "open_port_range": S("openPortRange") >> Bend(AwsInspectorV2PortRange.mapping),
        "protocol": S("protocol"),
    }
    network_path: Optional[AwsInspectorV2NetworkPath] = field(default=None, metadata={"description": "An object that contains details about a network path associated with a finding."})  # fmt: skip
    open_port_range: Optional[AwsInspectorV2PortRange] = field(default=None, metadata={"description": "An object that contains details about the open port range associated with a finding."})  # fmt: skip
    protocol: Optional[str] = field(default=None, metadata={"description": "The protocol associated with a finding."})  # fmt: skip


@define(eq=False, slots=False)
class AwsInspectorV2CvssScore:
    kind: ClassVar[str] = "aws_inspector_v2_cvss_score"
    mapping: ClassVar[Dict[str, Bender]] = {
        "base_score": S("baseScore"),
        "scoring_vector": S("scoringVector"),
        "source": S("source"),
        "version": S("version"),
    }
    base_score: Optional[float] = field(default=None, metadata={"description": "The base CVSS score used for the finding."})  # fmt: skip
    scoring_vector: Optional[str] = field(default=None, metadata={"description": "The vector string of the CVSS score."})  # fmt: skip
    source: Optional[str] = field(default=None, metadata={"description": "The source of the CVSS score."})  # fmt: skip
    version: Optional[str] = field(default=None, metadata={"description": "The version of CVSS used for the score."})  # fmt: skip


@define(eq=False, slots=False)
class AwsInspectorV2VulnerablePackage:
    kind: ClassVar[str] = "aws_inspector_v2_vulnerable_package"
    mapping: ClassVar[Dict[str, Bender]] = {
        "arch": S("arch"),
        "epoch": S("epoch"),
        "file_path": S("filePath"),
        "fixed_in_version": S("fixedInVersion"),
        "name": S("name"),
        "package_manager": S("packageManager"),
        "release": S("release"),
        "remediation": S("remediation"),
        "source_lambda_layer_arn": S("sourceLambdaLayerArn"),
        "source_layer_hash": S("sourceLayerHash"),
        "version": S("version"),
    }
    arch: Optional[str] = field(default=None, metadata={"description": "The architecture of the vulnerable package."})  # fmt: skip
    epoch: Optional[int] = field(default=None, metadata={"description": "The epoch of the vulnerable package."})  # fmt: skip
    file_path: Optional[str] = field(default=None, metadata={"description": "The file path of the vulnerable package."})  # fmt: skip
    fixed_in_version: Optional[str] = field(default=None, metadata={"description": "The version of the package that contains the vulnerability fix."})  # fmt: skip
    name: Optional[str] = field(default=None, metadata={"description": "The name of the vulnerable package."})  # fmt: skip
    package_manager: Optional[str] = field(default=None, metadata={"description": "The package manager of the vulnerable package."})  # fmt: skip
    release: Optional[str] = field(default=None, metadata={"description": "The release of the vulnerable package."})  # fmt: skip
    remediation: Optional[str] = field(default=None, metadata={"description": "The code to run in your environment to update packages with a fix available."})  # fmt: skip
    source_lambda_layer_arn: Optional[str] = field(default=None, metadata={"description": "The Amazon Resource Number (ARN) of the Amazon Web Services Lambda function affected by a finding."})  # fmt: skip
    source_layer_hash: Optional[str] = field(default=None, metadata={"description": "The source layer hash of the vulnerable package."})  # fmt: skip
    version: Optional[str] = field(default=None, metadata={"description": "The version of the vulnerable package."})  # fmt: skip


@define(eq=False, slots=False)
class AwsInspectorV2PackageVulnerabilityDetails:
    kind: ClassVar[str] = "aws_inspector_v2_package_vulnerability_details"
    mapping: ClassVar[Dict[str, Bender]] = {
        "cvss": S("cvss", default=[]) >> ForallBend(AwsInspectorV2CvssScore.mapping),
        "reference_urls": S("referenceUrls", default=[]),
        "related_vulnerabilities": S("relatedVulnerabilities", default=[]),
        "source": S("source"),
        "source_url": S("sourceUrl"),
        "vendor_created_at": S("vendorCreatedAt"),
        "vendor_severity": S("vendorSeverity"),
        "vendor_updated_at": S("vendorUpdatedAt"),
        "vulnerability_id": S("vulnerabilityId"),
        "vulnerable_packages": S("vulnerablePackages", default=[])
        >> ForallBend(AwsInspectorV2VulnerablePackage.mapping),
    }
    cvss: Optional[List[AwsInspectorV2CvssScore]] = field(factory=list, metadata={"description": "An object that contains details about the CVSS score of a finding."})  # fmt: skip
    reference_urls: Optional[List[str]] = field(factory=list, metadata={"description": "One or more URLs that contain details about this vulnerability type."})  # fmt: skip
    related_vulnerabilities: Optional[List[str]] = field(factory=list, metadata={"description": "One or more vulnerabilities related to the one identified in this finding."})  # fmt: skip
    source: Optional[str] = field(default=None, metadata={"description": "The source of the vulnerability information."})  # fmt: skip
    source_url: Optional[str] = field(default=None, metadata={"description": "A URL to the source of the vulnerability information."})  # fmt: skip
    vendor_created_at: Optional[datetime] = field(default=None, metadata={"description": "The date and time that this vulnerability was first added to the vendor's database."})  # fmt: skip
    vendor_severity: Optional[str] = field(default=None, metadata={"description": "The severity the vendor has given to this vulnerability type."})  # fmt: skip
    vendor_updated_at: Optional[datetime] = field(default=None, metadata={"description": "The date and time the vendor last updated this vulnerability in their database."})  # fmt: skip
    vulnerability_id: Optional[str] = field(default=None, metadata={"description": "The ID given to this vulnerability."})  # fmt: skip
    vulnerable_packages: Optional[List[AwsInspectorV2VulnerablePackage]] = field(factory=list, metadata={"description": "The packages impacted by this vulnerability."})  # fmt: skip


@define(eq=False, slots=False)
class AwsInspectorV2Recommendation:
    kind: ClassVar[str] = "aws_inspector_v2_recommendation"
    mapping: ClassVar[Dict[str, Bender]] = {"url": S("Url"), "text": S("text")}
    url: Optional[str] = field(default=None, metadata={"description": "The URL address to the CVE remediation recommendations."})  # fmt: skip
    text: Optional[str] = field(default=None, metadata={"description": "The recommended course of action to remediate the finding."})  # fmt: skip


@define(eq=False, slots=False)
class AwsInspectorV2Remediation:
    kind: ClassVar[str] = "aws_inspector_v2_remediation"
    mapping: ClassVar[Dict[str, Bender]] = {
        "recommendation": S("recommendation") >> Bend(AwsInspectorV2Recommendation.mapping)
    }
    recommendation: Optional[AwsInspectorV2Recommendation] = field(default=None, metadata={"description": "An object that contains information about the recommended course of action to remediate the finding."})  # fmt: skip


@define(eq=False, slots=False)
class AwsInspectorV2AwsEc2InstanceDetails:
    kind: ClassVar[str] = "aws_inspector_v2_aws_ec2_instance_details"
    mapping: ClassVar[Dict[str, Bender]] = {
        "iam_instance_profile_arn": S("iamInstanceProfileArn"),
        "image_id": S("imageId"),
        "ip_v4_addresses": S("ipV4Addresses", default=[]),
        "ip_v6_addresses": S("ipV6Addresses", default=[]),
        "key_name": S("keyName"),
        "launched_at": S("launchedAt"),
        "platform": S("platform"),
        "subnet_id": S("subnetId"),
        "type": S("type"),
        "vpc_id": S("vpcId"),
    }
    iam_instance_profile_arn: Optional[str] = field(default=None, metadata={"description": "The IAM instance profile ARN of the Amazon EC2 instance."})  # fmt: skip
    image_id: Optional[str] = field(default=None, metadata={"description": "The image ID of the Amazon EC2 instance."})  # fmt: skip
    ip_v4_addresses: Optional[List[str]] = field(factory=list, metadata={"description": "The IPv4 addresses of the Amazon EC2 instance."})  # fmt: skip
    ip_v6_addresses: Optional[List[str]] = field(factory=list, metadata={"description": "The IPv6 addresses of the Amazon EC2 instance."})  # fmt: skip
    key_name: Optional[str] = field(default=None, metadata={"description": "The name of the key pair used to launch the Amazon EC2 instance."})  # fmt: skip
    launched_at: Optional[datetime] = field(default=None, metadata={"description": "The date and time the Amazon EC2 instance was launched at."})  # fmt: skip
    platform: Optional[str] = field(default=None, metadata={"description": "The platform of the Amazon EC2 instance."})  # fmt: skip
    subnet_id: Optional[str] = field(default=None, metadata={"description": "The subnet ID of the Amazon EC2 instance."})  # fmt: skip
    type: Optional[str] = field(default=None, metadata={"description": "The type of the Amazon EC2 instance."})  # fmt: skip
    vpc_id: Optional[str] = field(default=None, metadata={"description": "The VPC ID of the Amazon EC2 instance."})  # fmt: skip


@define(eq=False, slots=False)
class AwsInspectorV2AwsEcrContainerImageDetails:
    kind: ClassVar[str] = "aws_inspector_v2_aws_ecr_container_image_details"
    mapping: ClassVar[Dict[str, Bender]] = {
        "architecture": S("architecture"),
        "author": S("author"),
        "image_hash": S("imageHash"),
        "image_tags": S("imageTags", default=[]),
        "platform": S("platform"),
        "pushed_at": S("pushedAt"),
        "registry": S("registry"),
        "repository_name": S("repositoryName"),
    }
    architecture: Optional[str] = field(default=None, metadata={"description": "The architecture of the Amazon ECR container image."})  # fmt: skip
    author: Optional[str] = field(default=None, metadata={"description": "The image author of the Amazon ECR container image."})  # fmt: skip
    image_hash: Optional[str] = field(default=None, metadata={"description": "The image hash of the Amazon ECR container image."})  # fmt: skip
    image_tags: Optional[List[str]] = field(factory=list, metadata={"description": "The image tags attached to the Amazon ECR container image."})  # fmt: skip
    platform: Optional[str] = field(default=None, metadata={"description": "The platform of the Amazon ECR container image."})  # fmt: skip
    pushed_at: Optional[datetime] = field(default=None, metadata={"description": "The date and time the Amazon ECR container image was pushed."})  # fmt: skip
    registry: Optional[str] = field(default=None, metadata={"description": "The registry for the Amazon ECR container image."})  # fmt: skip
    repository_name: Optional[str] = field(default=None, metadata={"description": "The name of the repository the Amazon ECR container image resides in."})  # fmt: skip


@define(eq=False, slots=False)
class AwsInspectorV2LambdaVpcConfig:
    kind: ClassVar[str] = "aws_inspector_v2_lambda_vpc_config"
    mapping: ClassVar[Dict[str, Bender]] = {
        "security_group_ids": S("securityGroupIds", default=[]),
        "subnet_ids": S("subnetIds", default=[]),
        "vpc_id": S("vpcId"),
    }
    security_group_ids: Optional[List[str]] = field(factory=list, metadata={"description": "The VPC security groups and subnets that are attached to an Amazon Web Services Lambda function. For more information, see VPC Settings."})  # fmt: skip
    subnet_ids: Optional[List[str]] = field(factory=list, metadata={"description": "A list of VPC subnet IDs."})  # fmt: skip
    vpc_id: Optional[str] = field(default=None, metadata={"description": "The ID of the VPC."})  # fmt: skip


@define(eq=False, slots=False)
class AwsInspectorV2AwsLambdaFunctionDetails:
    kind: ClassVar[str] = "aws_inspector_v2_aws_lambda_function_details"
    mapping: ClassVar[Dict[str, Bender]] = {
        "architectures": S("architectures", default=[]),
        "code_sha256": S("codeSha256"),
        "execution_role_arn": S("executionRoleArn"),
        "function_name": S("functionName"),
        "last_modified_at": S("lastModifiedAt"),
        "layers": S("layers", default=[]),
        "package_type": S("packageType"),
        "runtime": S("runtime"),
        "version": S("version"),
        "vpc_config": S("vpcConfig") >> Bend(AwsInspectorV2LambdaVpcConfig.mapping),
    }
    architectures: Optional[List[str]] = field(factory=list, metadata={"description": "The instruction set architecture that the Amazon Web Services Lambda function supports. Architecture is a string array with one of the valid values. The default architecture value is x86_64."})  # fmt: skip
    code_sha256: Optional[str] = field(default=None, metadata={"description": "The SHA256 hash of the Amazon Web Services Lambda function's deployment package."})  # fmt: skip
    execution_role_arn: Optional[str] = field(default=None, metadata={"description": "The Amazon Web Services Lambda function's execution role."})  # fmt: skip
    function_name: Optional[str] = field(default=None, metadata={"description": "The name of the Amazon Web Services Lambda function."})  # fmt: skip
    last_modified_at: Optional[datetime] = field(default=None, metadata={"description": "The date and time that a user last updated the configuration, in ISO 8601 format"})  # fmt: skip
    layers: Optional[List[str]] = field(factory=list, metadata={"description": "The Amazon Web Services Lambda function's  layers. A Lambda function can have up to five layers."})  # fmt: skip
    package_type: Optional[str] = field(default=None, metadata={"description": "The type of deployment package. Set to Image for container image and set Zip for .zip file archive."})  # fmt: skip
    runtime: Optional[str] = field(default=None, metadata={"description": "The runtime environment for the Amazon Web Services Lambda function."})  # fmt: skip
    version: Optional[str] = field(default=None, metadata={"description": "The version of the Amazon Web Services Lambda function."})  # fmt: skip
    vpc_config: Optional[AwsInspectorV2LambdaVpcConfig] = field(default=None, metadata={"description": "The Amazon Web Services Lambda function's networking configuration."})  # fmt: skip


@define(eq=False, slots=False)
class AwsInspectorV2ResourceDetails:
    kind: ClassVar[str] = "aws_inspector_v2_resource_details"
    mapping: ClassVar[Dict[str, Bender]] = {
        "aws_ec2_instance": S("awsEc2Instance") >> Bend(AwsInspectorV2AwsEc2InstanceDetails.mapping),
        "aws_ecr_container_image": S("awsEcrContainerImage") >> Bend(AwsInspectorV2AwsEcrContainerImageDetails.mapping),
        "aws_lambda_function": S("awsLambdaFunction") >> Bend(AwsInspectorV2AwsLambdaFunctionDetails.mapping),
    }
    aws_ec2_instance: Optional[AwsInspectorV2AwsEc2InstanceDetails] = field(default=None, metadata={"description": "An object that contains details about the Amazon EC2 instance involved in the finding."})  # fmt: skip
    aws_ecr_container_image: Optional[AwsInspectorV2AwsEcrContainerImageDetails] = field(default=None, metadata={"description": "An object that contains details about the Amazon ECR container image involved in the finding."})  # fmt: skip
    aws_lambda_function: Optional[AwsInspectorV2AwsLambdaFunctionDetails] = field(default=None, metadata={"description": "A summary of the information about an Amazon Web Services Lambda function affected by a finding."})  # fmt: skip


@define(eq=False, slots=False)
class AwsInspectorV2Resource:
    kind: ClassVar[str] = "aws_inspector_v2_resource"
    mapping: ClassVar[Dict[str, Bender]] = {
        "details": S("details") >> Bend(AwsInspectorV2ResourceDetails.mapping),
        "id": S("id"),
        "partition": S("partition"),
        "region": S("region"),
        "type": S("type"),
    }
    details: Optional[AwsInspectorV2ResourceDetails] = field(default=None, metadata={"description": "An object that contains details about the resource involved in a finding."})  # fmt: skip
    id: Optional[str] = field(default=None, metadata={"description": "The ID of the resource."})  # fmt: skip
    partition: Optional[str] = field(default=None, metadata={"description": "The partition of the resource."})  # fmt: skip
    region: Optional[str] = field(default=None, metadata={"description": "The Amazon Web Services Region the impacted resource is located in."})  # fmt: skip
    type: Optional[str] = field(default=None, metadata={"description": "The type of resource."})  # fmt: skip


@define(eq=False, slots=False)
class AwsInspectorV2Finding(AwsResource):
    kind: ClassVar[str] = "aws_inspector_v2_finding"
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec(
        "inspector2", "list-findings", "findings", expected_errors=["AccessDeniedException"]
    )
    _reference_kinds: ClassVar[ModelReference] = {
        "successors": {"default": [AwsResource.kind]},
    }
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("findingArn") >> F(AwsResource.id_from_arn),
        "name": S("title"),
        "mtime": S("updatedAt"),
        "arn": S("findingArn"),
        "aws_account_id": S("awsAccountId"),
        "code_vulnerability_details": S("codeVulnerabilityDetails")
        >> Bend(AwsInspectorV2CodeVulnerabilityDetails.mapping),
        "description": S("description"),
        "epss": S("epss", "score"),
        "exploit_available": S("exploitAvailable"),
        "exploitability_details": S("exploitabilityDetails", "lastKnownExploitAt"),
        "finding_arn": S("findingArn"),
        "first_observed_at": S("firstObservedAt"),
        "fix_available": S("fixAvailable"),
        "inspector_score": S("inspectorScore"),
        "inspector_score_details": S("inspectorScoreDetails") >> Bend(AwsInspectorV2InspectorScoreDetails.mapping),
        "last_observed_at": S("lastObservedAt"),
        "network_reachability_details": S("networkReachabilityDetails")
        >> Bend(AwsInspectorV2NetworkReachabilityDetails.mapping),
        "package_vulnerability_details": S("packageVulnerabilityDetails")
        >> Bend(AwsInspectorV2PackageVulnerabilityDetails.mapping),
        "remediation": S("remediation") >> Bend(AwsInspectorV2Remediation.mapping),
        "finding_resources": S("resources", default=[]) >> ForallBend(AwsInspectorV2Resource.mapping),
        "finding_severity": S("severity"),
        "status": S("status"),
        "title": S("title"),
        "type": S("type"),
        "updated_at": S("updatedAt"),
    }
    aws_account_id: Optional[str] = field(default=None, metadata={"description": "The Amazon Web Services account ID associated with the finding."})  # fmt: skip
    code_vulnerability_details: Optional[AwsInspectorV2CodeVulnerabilityDetails] = field(default=None, metadata={"description": "Details about the code vulnerability identified in a Lambda function used to filter findings."})  # fmt: skip
    description: Optional[str] = field(default=None, metadata={"description": "The description of the finding."})  # fmt: skip
    epss: Optional[float] = field(default=None, metadata={"description": "The finding's EPSS score."})  # fmt: skip
    exploit_available: Optional[str] = field(default=None, metadata={"description": "If a finding discovered in your environment has an exploit available."})  # fmt: skip
    exploitability_details: Optional[datetime] = field(default=None, metadata={"description": "The details of an exploit available for a finding discovered in your environment."})  # fmt: skip
    finding_arn: Optional[str] = field(default=None, metadata={"description": "The Amazon Resource Number (ARN) of the finding."})  # fmt: skip
    first_observed_at: Optional[datetime] = field(default=None, metadata={"description": "The date and time that the finding was first observed."})  # fmt: skip
    fix_available: Optional[str] = field(default=None, metadata={"description": "Details on whether a fix is available through a version update. This value can be YES, NO, or PARTIAL. A PARTIAL fix means that some, but not all, of the packages identified in the finding have fixes available through updated versions."})  # fmt: skip
    inspector_score: Optional[float] = field(default=None, metadata={"description": "The Amazon Inspector score given to the finding."})  # fmt: skip
    inspector_score_details: Optional[AwsInspectorV2InspectorScoreDetails] = field(default=None, metadata={"description": "An object that contains details of the Amazon Inspector score."})  # fmt: skip
    last_observed_at: Optional[datetime] = field(default=None, metadata={"description": "The date and time the finding was last observed. This timestamp for this field remains unchanged until a finding is updated."})  # fmt: skip
    network_reachability_details: Optional[AwsInspectorV2NetworkReachabilityDetails] = field(default=None, metadata={"description": "An object that contains the details of a network reachability finding."})  # fmt: skip
    package_vulnerability_details: Optional[AwsInspectorV2PackageVulnerabilityDetails] = field(default=None, metadata={"description": "An object that contains the details of a package vulnerability finding."})  # fmt: skip
    remediation: Optional[AwsInspectorV2Remediation] = field(default=None, metadata={"description": "An object that contains the details about how to remediate a finding."})  # fmt: skip
    finding_resources: Optional[List[AwsInspectorV2Resource]] = field(factory=list, metadata={"description": "Contains information on the resources involved in a finding. The resource value determines the valid values for type in your request. For more information, see Finding types in the Amazon Inspector user guide."})  # fmt: skip
    finding_severity: Optional[str] = field(default=None, metadata={"description": "The severity of the finding. UNTRIAGED applies to PACKAGE_VULNERABILITY type findings that the vendor has not assigned a severity yet. For more information, see Severity levels for findings in the Amazon Inspector user guide."})  # fmt: skip
    status: Optional[str] = field(default=None, metadata={"description": "The status of the finding."})  # fmt: skip
    title: Optional[str] = field(default=None, metadata={"description": "The title of the finding."})  # fmt: skip
    type: Optional[str] = field(default=None, metadata={"description": "The type of the finding. The type value determines the valid values for resource in your request. For more information, see Finding types in the Amazon Inspector user guide."})  # fmt: skip
    updated_at: Optional[datetime] = field(default=None, metadata={"description": "The date and time the finding was last updated at."})  # fmt: skip

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if finding_resources := self.finding_resources:
            for finding_resource in finding_resources:
                if rid := finding_resource.id:
                    builder.add_edge(
                        self,
                        clazz=AwsResource,
                        id=rid,
                    )


@define(eq=False, slots=False)
class AwsInspectorV2CisTargets:
    kind: ClassVar[str] = "aws_inspector_v2_cis_targets"
    mapping: ClassVar[Dict[str, Bender]] = {
        "account_ids": S("accountIds", default=[]),
        "target_resource_tags": S("targetResourceTags"),
    }
    account_ids: Optional[List[str]] = field(factory=list, metadata={"description": "The CIS target account ids."})  # fmt: skip
    target_resource_tags: Optional[Dict[str, List[str]]] = field(default=None, metadata={"description": "The CIS target resource tags."})  # fmt: skip


@define(eq=False, slots=False)
class AwsInspectorV2CisScan(AwsResource):
    kind: ClassVar[str] = "aws_inspector_v2_cis_scan"
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec(
        "inspector2", "list-cis-scans", "scans", expected_errors=["AccessDeniedException"]
    )
    _reference_kinds: ClassVar[ModelReference] = {
        "successors": {"default": ["aws_inspector_v2_cis_scan_configuration"]}
    }
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("scanArn") >> F(AwsResource.id_from_arn),
        "name": S("scanName"),
        "arn": S("scanArn"),
        "failed_checks": S("failedChecks"),
        "scan_arn": S("scanArn"),
        "scan_configuration_arn": S("scanConfigurationArn"),
        "scan_date": S("scanDate"),
        "scan_name": S("scanName"),
        "scheduled_by": S("scheduledBy"),
        "security_level": S("securityLevel"),
        "status": S("status"),
        "cis_targets": S("targets") >> Bend(AwsInspectorV2CisTargets.mapping),
        "total_checks": S("totalChecks"),
    }
    failed_checks: Optional[int] = field(default=None, metadata={"description": "The CIS scan's failed checks."})  # fmt: skip
    scan_arn: Optional[str] = field(default=None, metadata={"description": "The CIS scan's ARN."})  # fmt: skip
    scan_configuration_arn: Optional[str] = field(default=None, metadata={"description": "The CIS scan's configuration ARN."})  # fmt: skip
    scan_date: Optional[datetime] = field(default=None, metadata={"description": "The CIS scan's date."})  # fmt: skip
    scan_name: Optional[str] = field(default=None, metadata={"description": "The the name of the scan configuration that's associated with this scan."})  # fmt: skip
    scheduled_by: Optional[str] = field(default=None, metadata={"description": "The account or organization that schedules the CIS scan."})  # fmt: skip
    security_level: Optional[str] = field(default=None, metadata={"description": "The security level for the CIS scan. Security level refers to the Benchmark levels that CIS assigns to a profile."})  # fmt: skip
    status: Optional[str] = field(default=None, metadata={"description": "The CIS scan's status."})  # fmt: skip
    cis_targets: Optional[AwsInspectorV2CisTargets] = field(default=None, metadata={"description": "The CIS scan's targets."})  # fmt: skip
    total_checks: Optional[int] = field(default=None, metadata={"description": "The CIS scan's total checks."})  # fmt: skip

    def post_process(self, builder: GraphBuilder, source: Json) -> None:
        if (targets := self.cis_targets) and (tags := targets.target_resource_tags):
            tags_map: Dict[str, str] = {}
            for key, value in tags.items():
                tags_map[key] = value[0]
            self.tags = tags_map  # type: ignore

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if conf_arn := self.scan_configuration_arn:
            builder.add_edge(self, clazz=AwsInspectorV2CisScanConfiguration, arn=conf_arn)


@define(eq=False, slots=False)
class AwsInspectorV2Time:
    kind: ClassVar[str] = "aws_inspector_v2_time"
    mapping: ClassVar[Dict[str, Bender]] = {"time_of_day": S("timeOfDay"), "timezone": S("timezone")}
    time_of_day: Optional[str] = field(default=None, metadata={"description": "The time of day in 24-hour format (00:00)."})  # fmt: skip
    timezone: Optional[str] = field(default=None, metadata={"description": "The timezone."})  # fmt: skip


@define(eq=False, slots=False)
class AwsInspectorV2DailySchedule:
    kind: ClassVar[str] = "aws_inspector_v2_daily_schedule"
    mapping: ClassVar[Dict[str, Bender]] = {"start_time": S("startTime") >> Bend(AwsInspectorV2Time.mapping)}
    start_time: Optional[AwsInspectorV2Time] = field(default=None, metadata={"description": "The schedule start time."})  # fmt: skip


@define(eq=False, slots=False)
class AwsInspectorV2MonthlySchedule:
    kind: ClassVar[str] = "aws_inspector_v2_monthly_schedule"
    mapping: ClassVar[Dict[str, Bender]] = {
        "day": S("day"),
        "start_time": S("startTime") >> Bend(AwsInspectorV2Time.mapping),
    }
    day: Optional[str] = field(default=None, metadata={"description": "The monthly schedule's day."})  # fmt: skip
    start_time: Optional[AwsInspectorV2Time] = field(default=None, metadata={"description": "The monthly schedule's start time."})  # fmt: skip


@define(eq=False, slots=False)
class AwsInspectorV2WeeklySchedule:
    kind: ClassVar[str] = "aws_inspector_v2_weekly_schedule"
    mapping: ClassVar[Dict[str, Bender]] = {
        "days": S("days", default=[]),
        "start_time": S("startTime") >> Bend(AwsInspectorV2Time.mapping),
    }
    days: Optional[List[str]] = field(factory=list, metadata={"description": "The weekly schedule's days."})  # fmt: skip
    start_time: Optional[AwsInspectorV2Time] = field(default=None, metadata={"description": "The weekly schedule's start time."})  # fmt: skip


@define(eq=False, slots=False)
class AwsInspectorV2Schedule:
    kind: ClassVar[str] = "aws_inspector_v2_schedule"
    mapping: ClassVar[Dict[str, Bender]] = {
        "daily": S("daily") >> Bend(AwsInspectorV2DailySchedule.mapping),
        "monthly": S("monthly") >> Bend(AwsInspectorV2MonthlySchedule.mapping),
        "weekly": S("weekly") >> Bend(AwsInspectorV2WeeklySchedule.mapping),
        "one_time": S("oneTime"),
    }
    daily: Optional[AwsInspectorV2DailySchedule] = field(default=None, metadata={"description": "The schedule's daily."})  # fmt: skip
    one_time: Optional[Dict[str, Any]] = field(default=None, metadata={"description": "The schedule's one time."})  # fmt: skip
    monthly: Optional[AwsInspectorV2MonthlySchedule] = field(default=None, metadata={"description": "The schedule's monthly."})  # fmt: skip
    weekly: Optional[AwsInspectorV2WeeklySchedule] = field(default=None, metadata={"description": "The schedule's weekly."})  # fmt: skip


@define(eq=False, slots=False)
class AwsInspectorV2CisScanConfiguration(InspectorResourceTaggable, AwsResource):
    kind: ClassVar[str] = "aws_inspector_v2_cis_scan_configuration"
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec(
        "inspector2", "list-cis-scan-configurations", "scans", expected_errors=["AccessDeniedException"]
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("scanConfigurationArn") >> F(AwsResource.id_from_arn),
        "tags": S("tags"),
        "name": S("scanName"),
        "arn": S("scanConfigurationArn"),
        "owner_id": S("ownerId"),
        "scan_configuration_arn": S("scanConfigurationArn"),
        "scan_name": S("scanName"),
        "cis_schedule": S("schedule") >> Bend(AwsInspectorV2Schedule.mapping),
        "security_level": S("securityLevel"),
        "cis_targets": S("targets") >> Bend(AwsInspectorV2CisTargets.mapping),
    }
    owner_id: Optional[str] = field(default=None, metadata={"description": "The CIS scan configuration's owner ID."})  # fmt: skip
    scan_configuration_arn: Optional[str] = field(default=None, metadata={"description": "The CIS scan configuration's scan configuration ARN."})  # fmt: skip
    scan_name: Optional[str] = field(default=None, metadata={"description": "The name of the CIS scan configuration."})  # fmt: skip
    cis_schedule: Optional[AwsInspectorV2Schedule] = field(default=None, metadata={"description": "The CIS scan configuration's schedule."})  # fmt: skip
    security_level: Optional[str] = field(default=None, metadata={"description": "The CIS scan configuration's security level."})  # fmt: skip
    cis_targets: Optional[AwsInspectorV2CisTargets] = field(default=None, metadata={"description": "The CIS scan configuration's targets."})  # fmt: skip

    def delete_resource(self, client: AwsClient, graph: Graph) -> bool:
        client.call(
            aws_service=self.api_spec.service,
            action="delete-cis-scan-configuration",
            result_name=None,
            scanConfigurationArn=self.arn,
        )
        return True

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return super().called_mutator_apis() + [AwsApiSpec(service_name, "delete-cis-scan-configuration")]


@define(eq=False, slots=False)
class AwsInspectorV2Ec2Metadata:
    kind: ClassVar[str] = "aws_inspector_v2_ec2_metadata"
    mapping: ClassVar[Dict[str, Bender]] = {"ami_id": S("amiId"), "platform": S("platform")}
    ami_id: Optional[str] = field(default=None, metadata={"description": "The ID of the Amazon Machine Image (AMI) used to launch the instance."})  # fmt: skip
    platform: Optional[str] = field(default=None, metadata={"description": "The platform of the instance."})  # fmt: skip


@define(eq=False, slots=False)
class AwsInspectorV2EcrContainerImageMetadata:
    kind: ClassVar[str] = "aws_inspector_v2_ecr_container_image_metadata"
    mapping: ClassVar[Dict[str, Bender]] = {"image_pulled_at": S("imagePulledAt")}
    image_pulled_at: Optional[datetime] = field(default=None, metadata={"description": "The date an image was last pulled at."})  # fmt: skip


@define(eq=False, slots=False)
class AwsInspectorV2EcrRepositoryMetadata:
    kind: ClassVar[str] = "aws_inspector_v2_ecr_repository_metadata"
    mapping: ClassVar[Dict[str, Bender]] = {"name": S("name"), "scan_frequency": S("scanFrequency")}
    name: Optional[str] = field(default=None, metadata={"description": "The name of the Amazon ECR repository."})  # fmt: skip
    scan_frequency: Optional[str] = field(default=None, metadata={"description": "The frequency of scans."})  # fmt: skip


@define(eq=False, slots=False)
class AwsInspectorV2LambdaFunctionMetadata:
    kind: ClassVar[str] = "aws_inspector_v2_lambda_function_metadata"
    mapping: ClassVar[Dict[str, Bender]] = {
        "function_name": S("functionName"),
        "function_tags": S("functionTags"),
        "layers": S("layers", default=[]),
        "runtime": S("runtime"),
    }
    function_name: Optional[str] = field(default=None, metadata={"description": "The name of a function."})  # fmt: skip
    function_tags: Optional[Dict[str, str]] = field(default=None, metadata={"description": "The resource tags on an Amazon Web Services Lambda function."})  # fmt: skip
    layers: Optional[List[str]] = field(factory=list, metadata={"description": "The layers for an Amazon Web Services Lambda function. A Lambda function can have up to five layers."})  # fmt: skip
    runtime: Optional[str] = field(default=None, metadata={"description": "An Amazon Web Services Lambda function's runtime."})  # fmt: skip


@define(eq=False, slots=False)
class AwsInspectorV2ResourceScanMetadata:
    kind: ClassVar[str] = "aws_inspector_v2_resource_scan_metadata"
    mapping: ClassVar[Dict[str, Bender]] = {
        "ec2": S("ec2") >> Bend(AwsInspectorV2Ec2Metadata.mapping),
        "ecr_image": S("ecrImage") >> Bend(AwsInspectorV2EcrContainerImageMetadata.mapping),
        "ecr_repository": S("ecrRepository") >> Bend(AwsInspectorV2EcrRepositoryMetadata.mapping),
        "lambda_function": S("lambdaFunction") >> Bend(AwsInspectorV2LambdaFunctionMetadata.mapping),
    }
    ec2: Optional[AwsInspectorV2Ec2Metadata] = field(default=None, metadata={"description": "An object that contains metadata details for an Amazon EC2 instance."})  # fmt: skip
    ecr_image: Optional[AwsInspectorV2EcrContainerImageMetadata] = field(default=None, metadata={"description": "An object that contains details about the container metadata for an Amazon ECR image."})  # fmt: skip
    ecr_repository: Optional[AwsInspectorV2EcrRepositoryMetadata] = field(default=None, metadata={"description": "An object that contains details about the repository an Amazon ECR image resides in."})  # fmt: skip
    lambda_function: Optional[AwsInspectorV2LambdaFunctionMetadata] = field(default=None, metadata={"description": "An object that contains metadata details for an Amazon Web Services Lambda function."})  # fmt: skip


@define(eq=False, slots=False)
class AwsInspectorV2ScanStatus:
    kind: ClassVar[str] = "aws_inspector_v2_scan_status"
    mapping: ClassVar[Dict[str, Bender]] = {"reason": S("reason"), "status_code": S("statusCode")}
    reason: Optional[str] = field(default=None, metadata={"description": "The scan status. Possible return values and descriptions are:   PENDING_INITIAL_SCAN - This resource has been identified for scanning, results will be available soon.  ACCESS_DENIED - Resource access policy restricting Amazon Inspector access. Please update the IAM policy.  INTERNAL_ERROR - Amazon Inspector has encountered an internal error for this resource. Amazon Inspector service will automatically resolve the issue and resume the scanning. No action required from the user.  UNMANAGED_EC2_INSTANCE - The EC2 instance is not managed by SSM, please use the following SSM automation to remediate the issue: https://docs.aws.amazon.com/systems-manager-automation-runbooks/latest/userguide/automation-awssupport-troubleshoot-managed-instance.html. Once the instance becomes managed by SSM, Inspector will automatically begin scanning this instance.   UNSUPPORTED_OS - Amazon Inspector does not support this OS, architecture, or image manifest type at this time. To see a complete list of supported operating systems see: https://docs.aws.amazon.com/inspector/latest/user/supported.html.  SCAN_ELIGIBILITY_EXPIRED - The configured scan duration has lapsed for this image.  RESOURCE_TERMINATED - This resource has been terminated. The findings and coverage associated with this resource are in the process of being cleaned up.  SUCCESSFUL - The scan was successful.  NO_RESOURCES_FOUND - Reserved for future use.  IMAGE_SIZE_EXCEEDED - Reserved for future use.  SCAN_FREQUENCY_MANUAL - This image will not be covered by Amazon Inspector due to the repository scan frequency configuration.  SCAN_FREQUENCY_SCAN_ON_PUSH - This image will be scanned one time and will not new findings because of the scan frequency configuration.  EC2_INSTANCE_STOPPED - This EC2 instance is in a stopped state, therefore, Amazon Inspector will pause scanning. The existing findings will continue to exist until the instance is terminated. Once the instance is re-started, Inspector will automatically start scanning the instance again. Please note that you will not be charged for this instance while it’s in a stopped state.  PENDING_DISABLE - This resource is pending cleanup during disablement. The customer will not be billed while a resource is in the pending disable status.  NO INVENTORY - Amazon Inspector couldn’t find software application inventory to scan for vulnerabilities. This might be caused due to required Amazon Inspector associations being deleted or failing to run on your resource. Please verify the status of InspectorInventoryCollection-do-not-delete association in the SSM console for the resource. Additionally, you can verify the instance’s inventory in the SSM Fleet Manager console.  STALE_INVENTORY - Amazon Inspector wasn’t able to collect an updated software application inventory in the last 7 days. Please confirm the required Amazon Inspector associations still exist and you can still see an updated inventory in the SSM console.  EXCLUDED_BY_TAG - This resource was not scanned because it has been excluded by a tag.  UNSUPPORTED_RUNTIME - The function was not scanned because it has an unsupported runtime. To see a complete list of supported runtimes see: https://docs.aws.amazon.com/inspector/latest/user/supported.html.  UNSUPPORTED_MEDIA_TYPE - The ECR image has an unsupported media type.  UNSUPPORTED_CONFIG_FILE - Reserved for future use.  DEEP_INSPECTION_PACKAGE_COLLECTION_LIMIT_EXCEEDED - The instance has exceeded the 5000 package limit for Amazon Inspector Deep inspection. To resume Deep inspection for this instance you can try to adjust the custom paths associated with the account.  DEEP_INSPECTION_DAILY_SSM_INVENTORY_LIMIT_EXCEEDED - The SSM agent couldn't send inventory to Amazon Inspector because the SSM quota for Inventory data collected per instance per day has already been reached for this instance.  DEEP_INSPECTION_COLLECTION_TIME_LIMIT_EXCEEDED - Amazon Inspector failed to extract the package inventory because the package collection time exceeding the maximum threshold of 15 minutes.  DEEP_INSPECTION_NO_INVENTORY The Amazon Inspector plugin hasn't yet been able to collect an inventory of packages for this instance. This is usually the result of a pending scan, however, if this status persists after 6 hours, use SSM to ensure that the required Amazon Inspector associations exist and are running for the instance."})  # fmt: skip
    status_code: Optional[str] = field(default=None, metadata={"description": "The status code of the scan."})  # fmt: skip


@define(eq=False, slots=False)
class AwsInspectorV2Coverage(AwsResource):
    kind: ClassVar[str] = "aws_inspector_v2_coverage"
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec(
        "inspector2", "list-coverage", "coveredResources", expected_errors=["AccessDeniedException"]
    )
    _reference_kinds: ClassVar[ModelReference] = {
        "successors": {"default": [AwsLambdaFunction.kind, AwsEcrRepository.kind, AwsLambdaFunction.kind]},
    }
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("resourceId"),
        "name": S("resourceId"),
        "arn": S("resourceId"),
        "account_id": S("accountId"),
        "last_scanned_at": S("lastScannedAt"),
        "resource_id": S("resourceId"),
        "resource_metadata": S("resourceMetadata") >> Bend(AwsInspectorV2ResourceScanMetadata.mapping),
        "resource_type": S("resourceType"),
        "scan_mode": S("scanMode"),
        "scan_status": S("scanStatus") >> Bend(AwsInspectorV2ScanStatus.mapping),
        "scan_type": S("scanType"),
    }
    account_id: Optional[str] = field(default=None, metadata={"description": "The Amazon Web Services account ID of the covered resource."})  # fmt: skip
    last_scanned_at: Optional[datetime] = field(default=None, metadata={"description": "The date and time the resource was last checked for vulnerabilities."})  # fmt: skip
    resource_id: Optional[str] = field(default=None, metadata={"description": "The ID of the covered resource."})  # fmt: skip
    resource_metadata: Optional[AwsInspectorV2ResourceScanMetadata] = field(default=None, metadata={"description": "An object that contains details about the metadata."})  # fmt: skip
    resource_type: Optional[str] = field(default=None, metadata={"description": "The type of the covered resource."})  # fmt: skip
    scan_mode: Optional[str] = field(default=None, metadata={"description": "The scan method that is applied to the instance."})  # fmt: skip
    scan_status: Optional[AwsInspectorV2ScanStatus] = field(default=None, metadata={"description": "The status of the scan covering the resource."})  # fmt: skip
    scan_type: Optional[str] = field(default=None, metadata={"description": "The Amazon Inspector scan type covering the resource."})  # fmt: skip

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if self.id:
            builder.add_edge(
                self,
                clazz=AwsEc2Instance,
                id=self.id,
            )
        if resource_metadata := self.resource_metadata:
            if lambda_metadata := resource_metadata.lambda_function:
                builder.add_edge(
                    self,
                    clazz=AwsLambdaFunction,
                    id=lambda_metadata.function_name,
                )
            if ecr_metadata := resource_metadata.ecr_repository:
                builder.add_edge(
                    self,
                    clazz=AwsEcrRepository,
                    id=ecr_metadata.name,
                )


@define(eq=False, slots=False)
class AwsInspectorV2StringFilter:
    kind: ClassVar[str] = "aws_inspector_v2_string_filter"
    mapping: ClassVar[Dict[str, Bender]] = {"comparison": S("comparison"), "value": S("value")}
    comparison: Optional[str] = field(default=None, metadata={"description": "The operator to use when comparing values in the filter."})  # fmt: skip
    value: Optional[str] = field(default=None, metadata={"description": "The value to filter on."})  # fmt: skip


@define(eq=False, slots=False)
class AwsInspectorV2DateFilter:
    kind: ClassVar[str] = "aws_inspector_v2_date_filter"
    mapping: ClassVar[Dict[str, Bender]] = {"end_inclusive": S("endInclusive"), "start_inclusive": S("startInclusive")}
    end_inclusive: Optional[datetime] = field(default=None, metadata={"description": "A timestamp representing the end of the time period filtered on."})  # fmt: skip
    start_inclusive: Optional[datetime] = field(default=None, metadata={"description": "A timestamp representing the start of the time period filtered on."})  # fmt: skip


@define(eq=False, slots=False)
class AwsInspectorV2NumberFilter:
    kind: ClassVar[str] = "aws_inspector_v2_number_filter"
    mapping: ClassVar[Dict[str, Bender]] = {
        "lower_inclusive": S("lowerInclusive"),
        "upper_inclusive": S("upperInclusive"),
    }
    lower_inclusive: Optional[float] = field(default=None, metadata={"description": "The lowest number to be included in the filter."})  # fmt: skip
    upper_inclusive: Optional[float] = field(default=None, metadata={"description": "The highest number to be included in the filter."})  # fmt: skip


@define(eq=False, slots=False)
class AwsInspectorV2PortRangeFilter:
    kind: ClassVar[str] = "aws_inspector_v2_port_range_filter"
    mapping: ClassVar[Dict[str, Bender]] = {"begin_inclusive": S("beginInclusive"), "end_inclusive": S("endInclusive")}
    begin_inclusive: Optional[int] = field(default=None, metadata={"description": "The port number the port range begins at."})  # fmt: skip
    end_inclusive: Optional[int] = field(default=None, metadata={"description": "The port number the port range ends at."})  # fmt: skip


@define(eq=False, slots=False)
class AwsInspectorV2MapFilter:
    kind: ClassVar[str] = "aws_inspector_v2_map_filter"
    mapping: ClassVar[Dict[str, Bender]] = {"comparison": S("comparison"), "key": S("key"), "value": S("value")}
    comparison: Optional[str] = field(default=None, metadata={"description": "The operator to use when comparing values in the filter."})  # fmt: skip
    key: Optional[str] = field(default=None, metadata={"description": "The tag key used in the filter."})  # fmt: skip
    value: Optional[str] = field(default=None, metadata={"description": "The tag value used in the filter."})  # fmt: skip


@define(eq=False, slots=False)
class AwsInspectorV2PackageFilter:
    kind: ClassVar[str] = "aws_inspector_v2_package_filter"
    mapping: ClassVar[Dict[str, Bender]] = {
        "architecture": S("architecture") >> Bend(AwsInspectorV2StringFilter.mapping),
        "epoch": S("epoch") >> Bend(AwsInspectorV2NumberFilter.mapping),
        "name": S("name") >> Bend(AwsInspectorV2StringFilter.mapping),
        "release": S("release") >> Bend(AwsInspectorV2StringFilter.mapping),
        "source_lambda_layer_arn": S("sourceLambdaLayerArn") >> Bend(AwsInspectorV2StringFilter.mapping),
        "source_layer_hash": S("sourceLayerHash") >> Bend(AwsInspectorV2StringFilter.mapping),
        "version": S("version") >> Bend(AwsInspectorV2StringFilter.mapping),
    }
    architecture: Optional[AwsInspectorV2StringFilter] = field(default=None, metadata={"description": "An object that contains details on the package architecture type to filter on."})  # fmt: skip
    epoch: Optional[AwsInspectorV2NumberFilter] = field(default=None, metadata={"description": "An object that contains details on the package epoch to filter on."})  # fmt: skip
    name: Optional[AwsInspectorV2StringFilter] = field(default=None, metadata={"description": "An object that contains details on the name of the package to filter on."})  # fmt: skip
    release: Optional[AwsInspectorV2StringFilter] = field(default=None, metadata={"description": "An object that contains details on the package release to filter on."})  # fmt: skip
    source_lambda_layer_arn: Optional[AwsInspectorV2StringFilter] = field(default=None, metadata={"description": "An object that describes the details of a string filter."})  # fmt: skip
    source_layer_hash: Optional[AwsInspectorV2StringFilter] = field(default=None, metadata={"description": "An object that contains details on the source layer hash to filter on."})  # fmt: skip
    version: Optional[AwsInspectorV2StringFilter] = field(default=None, metadata={"description": "The package version to filter on."})  # fmt: skip


@define(eq=False, slots=False)
class AwsInspectorV2FilterCriteria:
    kind: ClassVar[str] = "aws_inspector_v2_filter_criteria"
    mapping: ClassVar[Dict[str, Bender]] = {
        "aws_account_id": S("awsAccountId", default=[]) >> ForallBend(AwsInspectorV2StringFilter.mapping),
        "code_vulnerability_detector_name": S("codeVulnerabilityDetectorName", default=[])
        >> ForallBend(AwsInspectorV2StringFilter.mapping),
        "code_vulnerability_detector_tags": S("codeVulnerabilityDetectorTags", default=[])
        >> ForallBend(AwsInspectorV2StringFilter.mapping),
        "code_vulnerability_file_path": S("codeVulnerabilityFilePath", default=[])
        >> ForallBend(AwsInspectorV2StringFilter.mapping),
        "component_id": S("componentId", default=[]) >> ForallBend(AwsInspectorV2StringFilter.mapping),
        "component_type": S("componentType", default=[]) >> ForallBend(AwsInspectorV2StringFilter.mapping),
        "ec2_instance_image_id": S("ec2InstanceImageId", default=[]) >> ForallBend(AwsInspectorV2StringFilter.mapping),
        "ec2_instance_subnet_id": S("ec2InstanceSubnetId", default=[])
        >> ForallBend(AwsInspectorV2StringFilter.mapping),
        "ec2_instance_vpc_id": S("ec2InstanceVpcId", default=[]) >> ForallBend(AwsInspectorV2StringFilter.mapping),
        "ecr_image_architecture": S("ecrImageArchitecture", default=[])
        >> ForallBend(AwsInspectorV2StringFilter.mapping),
        "ecr_image_hash": S("ecrImageHash", default=[]) >> ForallBend(AwsInspectorV2StringFilter.mapping),
        "ecr_image_pushed_at": S("ecrImagePushedAt", default=[]) >> ForallBend(AwsInspectorV2DateFilter.mapping),
        "ecr_image_registry": S("ecrImageRegistry", default=[]) >> ForallBend(AwsInspectorV2StringFilter.mapping),
        "ecr_image_repository_name": S("ecrImageRepositoryName", default=[])
        >> ForallBend(AwsInspectorV2StringFilter.mapping),
        "ecr_image_tags": S("ecrImageTags", default=[]) >> ForallBend(AwsInspectorV2StringFilter.mapping),
        "epss_score": S("epssScore", default=[]) >> ForallBend(AwsInspectorV2NumberFilter.mapping),
        "exploit_available": S("exploitAvailable", default=[]) >> ForallBend(AwsInspectorV2StringFilter.mapping),
        "finding_arn": S("findingArn", default=[]) >> ForallBend(AwsInspectorV2StringFilter.mapping),
        "finding_status": S("findingStatus", default=[]) >> ForallBend(AwsInspectorV2StringFilter.mapping),
        "finding_type": S("findingType", default=[]) >> ForallBend(AwsInspectorV2StringFilter.mapping),
        "first_observed_at": S("firstObservedAt", default=[]) >> ForallBend(AwsInspectorV2DateFilter.mapping),
        "fix_available": S("fixAvailable", default=[]) >> ForallBend(AwsInspectorV2StringFilter.mapping),
        "inspector_score": S("inspectorScore", default=[]) >> ForallBend(AwsInspectorV2NumberFilter.mapping),
        "lambda_function_execution_role_arn": S("lambdaFunctionExecutionRoleArn", default=[])
        >> ForallBend(AwsInspectorV2StringFilter.mapping),
        "lambda_function_last_modified_at": S("lambdaFunctionLastModifiedAt", default=[])
        >> ForallBend(AwsInspectorV2DateFilter.mapping),
        "lambda_function_layers": S("lambdaFunctionLayers", default=[])
        >> ForallBend(AwsInspectorV2StringFilter.mapping),
        "lambda_function_name": S("lambdaFunctionName", default=[]) >> ForallBend(AwsInspectorV2StringFilter.mapping),
        "lambda_function_runtime": S("lambdaFunctionRuntime", default=[])
        >> ForallBend(AwsInspectorV2StringFilter.mapping),
        "last_observed_at": S("lastObservedAt", default=[]) >> ForallBend(AwsInspectorV2DateFilter.mapping),
        "network_protocol": S("networkProtocol", default=[]) >> ForallBend(AwsInspectorV2StringFilter.mapping),
        "port_range": S("portRange", default=[]) >> ForallBend(AwsInspectorV2PortRangeFilter.mapping),
        "related_vulnerabilities": S("relatedVulnerabilities", default=[])
        >> ForallBend(AwsInspectorV2StringFilter.mapping),
        "resource_id": S("resourceId", default=[]) >> ForallBend(AwsInspectorV2StringFilter.mapping),
        "resource_tags": S("resourceTags", default=[]) >> ForallBend(AwsInspectorV2MapFilter.mapping),
        "resource_type": S("resourceType", default=[]) >> ForallBend(AwsInspectorV2StringFilter.mapping),
        "severity": S("severity", default=[]) >> ForallBend(AwsInspectorV2StringFilter.mapping),
        "title": S("title", default=[]) >> ForallBend(AwsInspectorV2StringFilter.mapping),
        "updated_at": S("updatedAt", default=[]) >> ForallBend(AwsInspectorV2DateFilter.mapping),
        "vendor_severity": S("vendorSeverity", default=[]) >> ForallBend(AwsInspectorV2StringFilter.mapping),
        "vulnerability_id": S("vulnerabilityId", default=[]) >> ForallBend(AwsInspectorV2StringFilter.mapping),
        "vulnerability_source": S("vulnerabilitySource", default=[]) >> ForallBend(AwsInspectorV2StringFilter.mapping),
        "vulnerable_packages": S("vulnerablePackages", default=[]) >> ForallBend(AwsInspectorV2PackageFilter.mapping),
    }
    aws_account_id: Optional[List[AwsInspectorV2StringFilter]] = field(factory=list, metadata={"description": "Details of the Amazon Web Services account IDs used to filter findings."})  # fmt: skip
    code_vulnerability_detector_name: Optional[List[AwsInspectorV2StringFilter]] = field(factory=list, metadata={"description": "The name of the detector used to identify a code vulnerability in a Lambda function used to filter findings."})  # fmt: skip
    code_vulnerability_detector_tags: Optional[List[AwsInspectorV2StringFilter]] = field(factory=list, metadata={"description": "The detector type tag associated with the vulnerability used to filter findings. Detector tags group related vulnerabilities by common themes or tactics. For a list of available tags by programming language, see Java tags, or Python tags."})  # fmt: skip
    code_vulnerability_file_path: Optional[List[AwsInspectorV2StringFilter]] = field(factory=list, metadata={"description": "The file path to the file in a Lambda function that contains a code vulnerability used to filter findings."})  # fmt: skip
    component_id: Optional[List[AwsInspectorV2StringFilter]] = field(factory=list, metadata={"description": "Details of the component IDs used to filter findings."})  # fmt: skip
    component_type: Optional[List[AwsInspectorV2StringFilter]] = field(factory=list, metadata={"description": "Details of the component types used to filter findings."})  # fmt: skip
    ec2_instance_image_id: Optional[List[AwsInspectorV2StringFilter]] = field(factory=list, metadata={"description": "Details of the Amazon EC2 instance image IDs used to filter findings."})  # fmt: skip
    ec2_instance_subnet_id: Optional[List[AwsInspectorV2StringFilter]] = field(factory=list, metadata={"description": "Details of the Amazon EC2 instance subnet IDs used to filter findings."})  # fmt: skip
    ec2_instance_vpc_id: Optional[List[AwsInspectorV2StringFilter]] = field(factory=list, metadata={"description": "Details of the Amazon EC2 instance VPC IDs used to filter findings."})  # fmt: skip
    ecr_image_architecture: Optional[List[AwsInspectorV2StringFilter]] = field(factory=list, metadata={"description": "Details of the Amazon ECR image architecture types used to filter findings."})  # fmt: skip
    ecr_image_hash: Optional[List[AwsInspectorV2StringFilter]] = field(factory=list, metadata={"description": "Details of the Amazon ECR image hashes used to filter findings."})  # fmt: skip
    ecr_image_pushed_at: Optional[List[AwsInspectorV2DateFilter]] = field(factory=list, metadata={"description": "Details on the Amazon ECR image push date and time used to filter findings."})  # fmt: skip
    ecr_image_registry: Optional[List[AwsInspectorV2StringFilter]] = field(factory=list, metadata={"description": "Details on the Amazon ECR registry used to filter findings."})  # fmt: skip
    ecr_image_repository_name: Optional[List[AwsInspectorV2StringFilter]] = field(factory=list, metadata={"description": "Details on the name of the Amazon ECR repository used to filter findings."})  # fmt: skip
    ecr_image_tags: Optional[List[AwsInspectorV2StringFilter]] = field(factory=list, metadata={"description": "The tags attached to the Amazon ECR container image."})  # fmt: skip
    epss_score: Optional[List[AwsInspectorV2NumberFilter]] = field(factory=list, metadata={"description": "The EPSS score used to filter findings."})  # fmt: skip
    exploit_available: Optional[List[AwsInspectorV2StringFilter]] = field(factory=list, metadata={"description": "Filters the list of Amazon Web Services Lambda findings by the availability of exploits."})  # fmt: skip
    finding_arn: Optional[List[AwsInspectorV2StringFilter]] = field(factory=list, metadata={"description": "Details on the finding ARNs used to filter findings."})  # fmt: skip
    finding_status: Optional[List[AwsInspectorV2StringFilter]] = field(factory=list, metadata={"description": "Details on the finding status types used to filter findings."})  # fmt: skip
    finding_type: Optional[List[AwsInspectorV2StringFilter]] = field(factory=list, metadata={"description": "Details on the finding types used to filter findings."})  # fmt: skip
    first_observed_at: Optional[List[AwsInspectorV2DateFilter]] = field(factory=list, metadata={"description": "Details on the date and time a finding was first seen used to filter findings."})  # fmt: skip
    fix_available: Optional[List[AwsInspectorV2StringFilter]] = field(factory=list, metadata={"description": "Details on whether a fix is available through a version update. This value can be YES, NO, or PARTIAL. A PARTIAL fix means that some, but not all, of the packages identified in the finding have fixes available through updated versions."})  # fmt: skip
    inspector_score: Optional[List[AwsInspectorV2NumberFilter]] = field(factory=list, metadata={"description": "The Amazon Inspector score to filter on."})  # fmt: skip
    lambda_function_execution_role_arn: Optional[List[AwsInspectorV2StringFilter]] = field(factory=list, metadata={"description": "Filters the list of Amazon Web Services Lambda functions by execution role."})  # fmt: skip
    lambda_function_last_modified_at: Optional[List[AwsInspectorV2DateFilter]] = field(factory=list, metadata={"description": "Filters the list of Amazon Web Services Lambda functions by the date and time that a user last updated the configuration, in ISO 8601 format"})  # fmt: skip
    lambda_function_layers: Optional[List[AwsInspectorV2StringFilter]] = field(factory=list, metadata={"description": "Filters the list of Amazon Web Services Lambda functions by the function's  layers. A Lambda function can have up to five layers."})  # fmt: skip
    lambda_function_name: Optional[List[AwsInspectorV2StringFilter]] = field(factory=list, metadata={"description": "Filters the list of Amazon Web Services Lambda functions by the name of the function."})  # fmt: skip
    lambda_function_runtime: Optional[List[AwsInspectorV2StringFilter]] = field(factory=list, metadata={"description": "Filters the list of Amazon Web Services Lambda functions by the runtime environment for the Lambda function."})  # fmt: skip
    last_observed_at: Optional[List[AwsInspectorV2DateFilter]] = field(factory=list, metadata={"description": "Details on the date and time a finding was last seen used to filter findings."})  # fmt: skip
    network_protocol: Optional[List[AwsInspectorV2StringFilter]] = field(factory=list, metadata={"description": "Details on network protocol used to filter findings."})  # fmt: skip
    port_range: Optional[List[AwsInspectorV2PortRangeFilter]] = field(factory=list, metadata={"description": "Details on the port ranges used to filter findings."})  # fmt: skip
    related_vulnerabilities: Optional[List[AwsInspectorV2StringFilter]] = field(factory=list, metadata={"description": "Details on the related vulnerabilities used to filter findings."})  # fmt: skip
    resource_id: Optional[List[AwsInspectorV2StringFilter]] = field(factory=list, metadata={"description": "Details on the resource IDs used to filter findings."})  # fmt: skip
    resource_tags: Optional[List[AwsInspectorV2MapFilter]] = field(factory=list, metadata={"description": "Details on the resource tags used to filter findings."})  # fmt: skip
    resource_type: Optional[List[AwsInspectorV2StringFilter]] = field(factory=list, metadata={"description": "Details on the resource types used to filter findings."})  # fmt: skip
    severity: Optional[List[AwsInspectorV2StringFilter]] = field(factory=list, metadata={"description": "Details on the severity used to filter findings."})  # fmt: skip
    title: Optional[List[AwsInspectorV2StringFilter]] = field(factory=list, metadata={"description": "Details on the finding title used to filter findings."})  # fmt: skip
    updated_at: Optional[List[AwsInspectorV2DateFilter]] = field(factory=list, metadata={"description": "Details on the date and time a finding was last updated at used to filter findings."})  # fmt: skip
    vendor_severity: Optional[List[AwsInspectorV2StringFilter]] = field(factory=list, metadata={"description": "Details on the vendor severity used to filter findings."})  # fmt: skip
    vulnerability_id: Optional[List[AwsInspectorV2StringFilter]] = field(factory=list, metadata={"description": "Details on the vulnerability ID used to filter findings."})  # fmt: skip
    vulnerability_source: Optional[List[AwsInspectorV2StringFilter]] = field(factory=list, metadata={"description": "Details on the vulnerability type used to filter findings."})  # fmt: skip
    vulnerable_packages: Optional[List[AwsInspectorV2PackageFilter]] = field(factory=list, metadata={"description": "Details on the vulnerable packages used to filter findings."})  # fmt: skip


@define(eq=False, slots=False)
class AwsInspectorV2Filter(InspectorResourceTaggable, AwsResource):
    kind: ClassVar[str] = "aws_inspector_v2_filter"
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec(
        "inspector2", "list-filters", "filters", expected_errors=["AccessDeniedException"]
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("arn") >> F(AwsResource.id_from_arn),
        "name": S("name"),
        "tags": S("tags"),
        "mtime": S("updatedAt"),
        "action": S("action"),
        "arn": S("arn"),
        "created_at": S("createdAt"),
        "filter_criteria": S("criteria") >> Bend(AwsInspectorV2FilterCriteria.mapping),
        "description": S("description"),
        "owner_id": S("ownerId"),
        "reason": S("reason"),
        "updated_at": S("updatedAt"),
    }
    action: Optional[str] = field(default=None, metadata={"description": "The action that is to be applied to the findings that match the filter."})  # fmt: skip
    created_at: Optional[datetime] = field(default=None, metadata={"description": "The date and time this filter was created at."})  # fmt: skip
    filter_criteria: Optional[AwsInspectorV2FilterCriteria] = field(default=None, metadata={"description": "Details on the filter criteria associated with this filter."})  # fmt: skip
    description: Optional[str] = field(default=None, metadata={"description": "A description of the filter."})  # fmt: skip
    owner_id: Optional[str] = field(default=None, metadata={"description": "The Amazon Web Services account ID of the account that created the filter."})  # fmt: skip
    reason: Optional[str] = field(default=None, metadata={"description": "The reason for the filter."})  # fmt: skip
    updated_at: Optional[datetime] = field(default=None, metadata={"description": "The date and time the filter was last updated at."})  # fmt: skip

    def delete_resource(self, client: AwsClient, graph: Graph) -> bool:
        client.call(aws_service=self.api_spec.service, action="delete-filter", result_name=None, arn=self.arn)
        return True

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return super().called_mutator_apis() + [AwsApiSpec(service_name, "delete-filter")]


resources: List[Type[AwsResource]] = [
    AwsInspectorV2Finding,
    AwsInspectorV2CisScan,
    AwsInspectorV2CisScanConfiguration,
    AwsInspectorV2Coverage,
    AwsInspectorV2Filter,
]
