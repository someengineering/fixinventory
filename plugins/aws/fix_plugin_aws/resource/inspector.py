import logging
from datetime import datetime
from typing import ClassVar, Dict, Optional, List, Tuple, Type, Any

from attrs import define, field
from boto3.exceptions import Boto3Error

from fix_plugin_aws.resource.base import AwsResource, AwsApiSpec, GraphBuilder
from fixlib.baseresources import Assessment, PhantomBaseResource, Severity, Finding
from fixlib.types import Json
from fixlib.json_bender import Bender, S, ForallBend, Bend, F

log = logging.getLogger("fix.plugins.aws")
service_name = "inspector2"


@define(eq=False, slots=False)
class AwsInspectorCodeFilePath:
    kind: ClassVar[str] = "aws_inspector_code_file_path"
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
class AwsInspectorCodeVulnerabilityDetails:
    kind: ClassVar[str] = "aws_inspector_code_vulnerability_details"
    mapping: ClassVar[Dict[str, Bender]] = {
        "cwes": S("cwes", default=[]),
        "detector_id": S("detectorId"),
        "detector_name": S("detectorName"),
        "detector_tags": S("detectorTags", default=[]),
        "file_path": S("filePath") >> Bend(AwsInspectorCodeFilePath.mapping),
        "reference_urls": S("referenceUrls", default=[]),
        "rule_id": S("ruleId"),
        "source_lambda_layer_arn": S("sourceLambdaLayerArn"),
    }
    cwes: Optional[List[str]] = field(factory=list, metadata={"description": "The Common Weakness Enumeration (CWE) item associated with the detected vulnerability."})  # fmt: skip
    detector_id: Optional[str] = field(default=None, metadata={"description": "The ID for the Amazon CodeGuru detector associated with the finding. For more information on detectors see Amazon CodeGuru Detector Library."})  # fmt: skip
    detector_name: Optional[str] = field(default=None, metadata={"description": "The name of the detector used to identify the code vulnerability. For more information on detectors see CodeGuru Detector Library."})  # fmt: skip
    detector_tags: Optional[List[str]] = field(factory=list, metadata={"description": "The detector tag associated with the vulnerability. Detector tags group related vulnerabilities by common themes or tactics. For a list of available tags by programming language, see Java tags, or Python tags."})  # fmt: skip
    file_path: Optional[AwsInspectorCodeFilePath] = field(default=None, metadata={"description": "Contains information on where the code vulnerability is located in your code."})  # fmt: skip
    reference_urls: Optional[List[str]] = field(factory=list, metadata={"description": "A URL containing supporting documentation about the code vulnerability detected."})  # fmt: skip
    rule_id: Optional[str] = field(default=None, metadata={"description": "The identifier for a rule that was used to detect the code vulnerability."})  # fmt: skip
    source_lambda_layer_arn: Optional[str] = field(default=None, metadata={"description": "The Amazon Resource Name (ARN) of the Lambda layer that the code vulnerability was detected in."})  # fmt: skip


@define(eq=False, slots=False)
class AwsInspectorCvssScoreAdjustment:
    kind: ClassVar[str] = "aws_inspector_cvss_score_adjustment"
    mapping: ClassVar[Dict[str, Bender]] = {"metric": S("metric"), "reason": S("reason")}
    metric: Optional[str] = field(default=None, metadata={"description": "The metric used to adjust the CVSS score."})  # fmt: skip
    reason: Optional[str] = field(default=None, metadata={"description": "The reason the CVSS score has been adjustment."})  # fmt: skip


@define(eq=False, slots=False)
class AwsInspectorCvssScoreDetails:
    kind: ClassVar[str] = "aws_inspector_cvss_score_details"
    mapping: ClassVar[Dict[str, Bender]] = {
        "adjustments": S("adjustments", default=[]) >> ForallBend(AwsInspectorCvssScoreAdjustment.mapping),
        "cvss_source": S("cvssSource"),
        "score": S("score"),
        "score_source": S("scoreSource"),
        "scoring_vector": S("scoringVector"),
        "version": S("version"),
    }
    adjustments: Optional[List[AwsInspectorCvssScoreAdjustment]] = field(factory=list, metadata={"description": "An object that contains details about adjustment Amazon Inspector made to the CVSS score."})  # fmt: skip
    cvss_source: Optional[str] = field(default=None, metadata={"description": "The source of the CVSS data."})  # fmt: skip
    score: Optional[float] = field(default=None, metadata={"description": "The CVSS score."})  # fmt: skip
    score_source: Optional[str] = field(default=None, metadata={"description": "The source for the CVSS score."})  # fmt: skip
    scoring_vector: Optional[str] = field(default=None, metadata={"description": "The vector for the CVSS score."})  # fmt: skip
    version: Optional[str] = field(default=None, metadata={"description": "The CVSS version used in scoring."})  # fmt: skip


@define(eq=False, slots=False)
class AwsInspectorInspectorScoreDetails:
    kind: ClassVar[str] = "aws_inspector_inspector_score_details"
    mapping: ClassVar[Dict[str, Bender]] = {
        "adjusted_cvss": S("adjustedCvss") >> Bend(AwsInspectorCvssScoreDetails.mapping)
    }
    adjusted_cvss: Optional[AwsInspectorCvssScoreDetails] = field(default=None, metadata={"description": "An object that contains details about the CVSS score given to a finding."})  # fmt: skip


@define(eq=False, slots=False)
class AwsInspectorStep:
    kind: ClassVar[str] = "aws_inspector_step"
    mapping: ClassVar[Dict[str, Bender]] = {"component_id": S("componentId"), "component_type": S("componentType")}
    component_id: Optional[str] = field(default=None, metadata={"description": "The component ID."})  # fmt: skip
    component_type: Optional[str] = field(default=None, metadata={"description": "The component type."})  # fmt: skip


@define(eq=False, slots=False)
class AwsInspectorNetworkPath:
    kind: ClassVar[str] = "aws_inspector_network_path"
    mapping: ClassVar[Dict[str, Bender]] = {"steps": S("steps", default=[]) >> ForallBend(AwsInspectorStep.mapping)}
    steps: Optional[List[AwsInspectorStep]] = field(factory=list, metadata={"description": "The details on the steps in the network path."})  # fmt: skip


@define(eq=False, slots=False)
class AwsInspectorPortRange:
    kind: ClassVar[str] = "aws_inspector_port_range"
    mapping: ClassVar[Dict[str, Bender]] = {"begin": S("begin"), "end": S("end")}
    begin: Optional[int] = field(default=None, metadata={"description": "The beginning port in a port range."})  # fmt: skip
    end: Optional[int] = field(default=None, metadata={"description": "The ending port in a port range."})  # fmt: skip


@define(eq=False, slots=False)
class AwsInspectorNetworkReachabilityDetails:
    kind: ClassVar[str] = "aws_inspector_network_reachability_details"
    mapping: ClassVar[Dict[str, Bender]] = {
        "network_path": S("networkPath") >> Bend(AwsInspectorNetworkPath.mapping),
        "open_port_range": S("openPortRange") >> Bend(AwsInspectorPortRange.mapping),
        "protocol": S("protocol"),
    }
    network_path: Optional[AwsInspectorNetworkPath] = field(default=None, metadata={"description": "An object that contains details about a network path associated with a finding."})  # fmt: skip
    open_port_range: Optional[AwsInspectorPortRange] = field(default=None, metadata={"description": "An object that contains details about the open port range associated with a finding."})  # fmt: skip
    protocol: Optional[str] = field(default=None, metadata={"description": "The protocol associated with a finding."})  # fmt: skip


@define(eq=False, slots=False)
class AwsInspectorCvssScore:
    kind: ClassVar[str] = "aws_inspector_cvss_score"
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
class AwsInspectorVulnerablePackage:
    kind: ClassVar[str] = "aws_inspector_vulnerable_package"
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
class AwsInspectorPackageVulnerabilityDetails:
    kind: ClassVar[str] = "aws_inspector_package_vulnerability_details"
    mapping: ClassVar[Dict[str, Bender]] = {
        "cvss": S("cvss", default=[]) >> ForallBend(AwsInspectorCvssScore.mapping),
        "reference_urls": S("referenceUrls", default=[]),
        "related_vulnerabilities": S("relatedVulnerabilities", default=[]),
        "source": S("source"),
        "source_url": S("sourceUrl"),
        "vendor_created_at": S("vendorCreatedAt"),
        "vendor_severity": S("vendorSeverity"),
        "vendor_updated_at": S("vendorUpdatedAt"),
        "vulnerability_id": S("vulnerabilityId"),
        "vulnerable_packages": S("vulnerablePackages", default=[]) >> ForallBend(AwsInspectorVulnerablePackage.mapping),
    }
    cvss: Optional[List[AwsInspectorCvssScore]] = field(factory=list, metadata={"description": "An object that contains details about the CVSS score of a finding."})  # fmt: skip
    reference_urls: Optional[List[str]] = field(factory=list, metadata={"description": "One or more URLs that contain details about this vulnerability type."})  # fmt: skip
    related_vulnerabilities: Optional[List[str]] = field(factory=list, metadata={"description": "One or more vulnerabilities related to the one identified in this finding."})  # fmt: skip
    source: Optional[str] = field(default=None, metadata={"description": "The source of the vulnerability information."})  # fmt: skip
    source_url: Optional[str] = field(default=None, metadata={"description": "A URL to the source of the vulnerability information."})  # fmt: skip
    vendor_created_at: Optional[datetime] = field(default=None, metadata={"description": "The date and time that this vulnerability was first added to the vendor's database."})  # fmt: skip
    vendor_severity: Optional[str] = field(default=None, metadata={"description": "The severity the vendor has given to this vulnerability type."})  # fmt: skip
    vendor_updated_at: Optional[datetime] = field(default=None, metadata={"description": "The date and time the vendor last updated this vulnerability in their database."})  # fmt: skip
    vulnerability_id: Optional[str] = field(default=None, metadata={"description": "The ID given to this vulnerability."})  # fmt: skip
    vulnerable_packages: Optional[List[AwsInspectorVulnerablePackage]] = field(factory=list, metadata={"description": "The packages impacted by this vulnerability."})  # fmt: skip


@define(eq=False, slots=False)
class AwsInspectorRecommendation:
    kind: ClassVar[str] = "aws_inspector_recommendation"
    mapping: ClassVar[Dict[str, Bender]] = {"url": S("Url"), "text": S("text")}
    url: Optional[str] = field(default=None, metadata={"description": "The URL address to the CVE remediation recommendations."})  # fmt: skip
    text: Optional[str] = field(default=None, metadata={"description": "The recommended course of action to remediate the finding."})  # fmt: skip


@define(eq=False, slots=False)
class AwsInspectorRemediation:
    kind: ClassVar[str] = "aws_inspector_remediation"
    mapping: ClassVar[Dict[str, Bender]] = {
        "recommendation": S("recommendation") >> Bend(AwsInspectorRecommendation.mapping)
    }
    recommendation: Optional[AwsInspectorRecommendation] = field(default=None, metadata={"description": "An object that contains information about the recommended course of action to remediate the finding."})  # fmt: skip


@define(eq=False, slots=False)
class AwsInspectorAwsEc2InstanceDetails:
    kind: ClassVar[str] = "aws_inspector_aws_ec2_instance_details"
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
class AwsInspectorAwsEcrContainerImageDetails:
    kind: ClassVar[str] = "aws_inspector_aws_ecr_container_image_details"
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
class AwsInspectorLambdaVpcConfig:
    kind: ClassVar[str] = "aws_inspector_lambda_vpc_config"
    mapping: ClassVar[Dict[str, Bender]] = {
        "security_group_ids": S("securityGroupIds", default=[]),
        "subnet_ids": S("subnetIds", default=[]),
        "vpc_id": S("vpcId"),
    }
    security_group_ids: Optional[List[str]] = field(factory=list, metadata={"description": "The VPC security groups and subnets that are attached to an Amazon Web Services Lambda function. For more information, see VPC Settings."})  # fmt: skip
    subnet_ids: Optional[List[str]] = field(factory=list, metadata={"description": "A list of VPC subnet IDs."})  # fmt: skip
    vpc_id: Optional[str] = field(default=None, metadata={"description": "The ID of the VPC."})  # fmt: skip


@define(eq=False, slots=False)
class AwsInspectorAwsLambdaFunctionDetails:
    kind: ClassVar[str] = "aws_inspector_aws_lambda_function_details"
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
        "vpc_config": S("vpcConfig") >> Bend(AwsInspectorLambdaVpcConfig.mapping),
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
    vpc_config: Optional[AwsInspectorLambdaVpcConfig] = field(default=None, metadata={"description": "The Amazon Web Services Lambda function's networking configuration."})  # fmt: skip


@define(eq=False, slots=False)
class AwsInspectorResourceDetails:
    kind: ClassVar[str] = "aws_inspector_resource_details"
    mapping: ClassVar[Dict[str, Bender]] = {
        "aws_ec2_instance": S("awsEc2Instance") >> Bend(AwsInspectorAwsEc2InstanceDetails.mapping),
        "aws_ecr_container_image": S("awsEcrContainerImage") >> Bend(AwsInspectorAwsEcrContainerImageDetails.mapping),
        "aws_lambda_function": S("awsLambdaFunction") >> Bend(AwsInspectorAwsLambdaFunctionDetails.mapping),
    }
    aws_ec2_instance: Optional[AwsInspectorAwsEc2InstanceDetails] = field(default=None, metadata={"description": "An object that contains details about the Amazon EC2 instance involved in the finding."})  # fmt: skip
    aws_ecr_container_image: Optional[AwsInspectorAwsEcrContainerImageDetails] = field(default=None, metadata={"description": "An object that contains details about the Amazon ECR container image involved in the finding."})  # fmt: skip
    aws_lambda_function: Optional[AwsInspectorAwsLambdaFunctionDetails] = field(default=None, metadata={"description": "A summary of the information about an Amazon Web Services Lambda function affected by a finding."})  # fmt: skip


@define(eq=False, slots=False)
class AwsInspectorResource:
    kind: ClassVar[str] = "aws_inspector_resource"
    mapping: ClassVar[Dict[str, Bender]] = {
        "details": S("details") >> Bend(AwsInspectorResourceDetails.mapping),
        "id": S("id"),
        "partition": S("partition"),
        "region": S("region"),
        "type": S("type"),
    }
    details: Optional[AwsInspectorResourceDetails] = field(default=None, metadata={"description": "An object that contains details about the resource involved in a finding."})  # fmt: skip
    id: Optional[str] = field(default=None, metadata={"description": "The ID of the resource."})  # fmt: skip
    partition: Optional[str] = field(default=None, metadata={"description": "The partition of the resource."})  # fmt: skip
    region: Optional[str] = field(default=None, metadata={"description": "The Amazon Web Services Region the impacted resource is located in."})  # fmt: skip
    type: Optional[str] = field(default=None, metadata={"description": "The type of resource."})  # fmt: skip


@define(eq=False, slots=False)
class AwsInspectorFinding(AwsResource, PhantomBaseResource):
    kind: ClassVar[str] = "aws_inspector_finding"
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec(
        "inspector2", "list-findings", "findings", expected_errors=["AccessDeniedException"]
    )
    _kind_display: ClassVar[str] = "Amazon Inspector Finding"
    _kind_service: ClassVar[str] = service_name
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "log", "group": "management"}
    _docs_url: ClassVar[str] = "https://docs.aws.amazon.com/inspector/latest/user/findings-understanding.html"
    _aws_metadata: ClassVar[Dict[str, Any]] = {
        "provider_link_tpl": "https://{region_id}.console.aws.amazon.com/inspector/v2/home?region={region_id}#/findings/all",
    }
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("findingArn") >> F(AwsResource.id_from_arn),
        "name": S("title"),
        "mtime": S("updatedAt"),
        "arn": S("findingArn"),
        "aws_account_id": S("awsAccountId"),
        "code_vulnerability_details": S("codeVulnerabilityDetails")
        >> Bend(AwsInspectorCodeVulnerabilityDetails.mapping),
        "description": S("description"),
        "epss": S("epss", "score"),
        "exploit_available": S("exploitAvailable"),
        "exploitability_details": S("exploitabilityDetails", "lastKnownExploitAt"),
        "finding_arn": S("findingArn"),
        "first_observed_at": S("firstObservedAt"),
        "fix_available": S("fixAvailable"),
        "inspector_score": S("inspectorScore"),
        "inspector_score_details": S("inspectorScoreDetails") >> Bend(AwsInspectorInspectorScoreDetails.mapping),
        "last_observed_at": S("lastObservedAt"),
        "network_reachability_details": S("networkReachabilityDetails")
        >> Bend(AwsInspectorNetworkReachabilityDetails.mapping),
        "package_vulnerability_details": S("packageVulnerabilityDetails")
        >> Bend(AwsInspectorPackageVulnerabilityDetails.mapping),
        "remediation": S("remediation") >> Bend(AwsInspectorRemediation.mapping),
        "finding_resources": S("resources", default=[]) >> ForallBend(AwsInspectorResource.mapping),
        "finding_severity": S("severity"),
        "status": S("status"),
        "title": S("title"),
        "type": S("type"),
        "updated_at": S("updatedAt"),
    }
    aws_account_id: Optional[str] = field(default=None, metadata={"description": "The Amazon Web Services account ID associated with the finding."})  # fmt: skip
    code_vulnerability_details: Optional[AwsInspectorCodeVulnerabilityDetails] = field(default=None, metadata={"description": "Details about the code vulnerability identified in a Lambda function used to filter findings."})  # fmt: skip
    description: Optional[str] = field(default=None, metadata={"description": "The description of the finding."})  # fmt: skip
    epss: Optional[float] = field(default=None, metadata={"description": "The finding's EPSS score."})  # fmt: skip
    exploit_available: Optional[str] = field(default=None, metadata={"description": "If a finding discovered in your environment has an exploit available."})  # fmt: skip
    exploitability_details: Optional[datetime] = field(default=None, metadata={"description": "The details of an exploit available for a finding discovered in your environment."})  # fmt: skip
    finding_arn: Optional[str] = field(default=None, metadata={"description": "The Amazon Resource Number (ARN) of the finding."})  # fmt: skip
    first_observed_at: Optional[datetime] = field(default=None, metadata={"description": "The date and time that the finding was first observed."})  # fmt: skip
    fix_available: Optional[str] = field(default=None, metadata={"description": "Details on whether a fix is available through a version update. This value can be YES, NO, or PARTIAL. A PARTIAL fix means that some, but not all, of the packages identified in the finding have fixes available through updated versions."})  # fmt: skip
    inspector_score: Optional[float] = field(default=None, metadata={"description": "The Amazon Inspector score given to the finding."})  # fmt: skip
    inspector_score_details: Optional[AwsInspectorInspectorScoreDetails] = field(default=None, metadata={"description": "An object that contains details of the Amazon Inspector score."})  # fmt: skip
    last_observed_at: Optional[datetime] = field(default=None, metadata={"description": "The date and time the finding was last observed. This timestamp for this field remains unchanged until a finding is updated."})  # fmt: skip
    network_reachability_details: Optional[AwsInspectorNetworkReachabilityDetails] = field(default=None, metadata={"description": "An object that contains the details of a network reachability finding."})  # fmt: skip
    package_vulnerability_details: Optional[AwsInspectorPackageVulnerabilityDetails] = field(default=None, metadata={"description": "An object that contains the details of a package vulnerability finding."})  # fmt: skip
    remediation: Optional[AwsInspectorRemediation] = field(default=None, metadata={"description": "An object that contains the details about how to remediate a finding."})  # fmt: skip
    finding_resources: Optional[List[AwsInspectorResource]] = field(factory=list, metadata={"description": "Contains information on the resources involved in a finding. The resource value determines the valid values for type in your request. For more information, see Finding types in the Amazon Inspector user guide."})  # fmt: skip
    finding_severity: Optional[str] = field(default=None, metadata={"description": "The severity of the finding. UNTRIAGED applies to PACKAGE_VULNERABILITY type findings that the vendor has not assigned a severity yet. For more information, see Severity levels for findings in the Amazon Inspector user guide."})  # fmt: skip
    status: Optional[str] = field(default=None, metadata={"description": "The status of the finding."})  # fmt: skip
    title: Optional[str] = field(default=None, metadata={"description": "The title of the finding."})  # fmt: skip
    type: Optional[str] = field(default=None, metadata={"description": "The type of the finding. The type value determines the valid values for resource in your request. For more information, see Finding types in the Amazon Inspector user guide."})  # fmt: skip
    updated_at: Optional[datetime] = field(default=None, metadata={"description": "The date and time the finding was last updated at."})  # fmt: skip

    @staticmethod
    def set_findings(builder: GraphBuilder, resource_to_set: AwsResource, to_check: str = "id") -> None:
        """
        Set the assessment findings for the resource based on its ID or ARN.
        """
        if not isinstance(resource_to_set, AwsResource):
            return

        id_or_arn = ""

        if to_check == "arn":
            if not resource_to_set.arn:
                return
            id_or_arn = resource_to_set.arn
        elif to_check == "id":
            id_or_arn = resource_to_set.id
        else:
            return
        provider_findings = builder._assessment_findings.get(
            ("inspector", resource_to_set.region().id, resource_to_set.__class__.__name__), {}
        ).get(id_or_arn, [])
        if provider_findings:
            # Set the findings in the resource's _assessments dictionary
            resource_to_set._assessments.append(Assessment("inspector", provider_findings))

    def parse_finding(self, source: Json) -> Finding:
        severity_mapping = {
            "INFORMATIONAL": Severity.info,
            "LOW": Severity.low,
            "MEDIUM": Severity.medium,
            "HIGH": Severity.high,
            "CRITICAL": Severity.critical,
        }
        finding_title = self.safe_name
        if not self.finding_severity:
            finding_severity = Severity.medium
        else:
            finding_severity = severity_mapping.get(self.finding_severity, Severity.medium)
        description = self.description
        remidiation = ""
        if self.remediation and self.remediation.recommendation:
            remidiation = self.remediation.recommendation.text or ""
        updated_at = self.updated_at
        details = source.get("packageVulnerabilityDetails", {}) | source.get("codeVulnerabilityDetails", {})
        return Finding(finding_title, finding_severity, description, remidiation, updated_at, details)

    @classmethod
    def collect_resources(cls, builder: GraphBuilder) -> None:
        def check_type_and_adjust_id(
            class_type: Optional[str], class_id: Optional[str]
        ) -> Tuple[Optional[str], Optional[str]]:
            # to avoid circular import, defined here
            from fix_plugin_aws.resource.ec2 import AwsEc2Instance
            from fix_plugin_aws.resource.ecr import AwsEcrRepository
            from fix_plugin_aws.resource.lambda_ import AwsLambdaFunction

            if not class_id or not class_type:
                return None, None
            match class_type:
                case "AWS_LAMBDA_FUNCTION":
                    # remove lambda's version from arn
                    lambda_arn = class_id.rsplit(":", 1)[0]
                    return AwsLambdaFunction.__name__, lambda_arn
                case "AWS_EC2_INSTANCE":
                    return AwsEc2Instance.__name__, class_id
                case "AWS_ECR_REPOSITORY":
                    return AwsEcrRepository.__name__, class_id
                case _:
                    return None, None

        # Default behavior: in case the class has an ApiSpec, call the api and call collect.
        log.debug(f"Collecting {cls.__name__} in region {builder.region.name}")
        if spec := cls.api_spec:
            try:
                for item in builder.client.list(
                    aws_service=spec.service,
                    action=spec.api_action,
                    result_name=spec.result_property,
                    expected_errors=spec.expected_errors,
                    filterCriteria={"awsAccountId": [{"comparison": "EQUALS", "value": f"{builder.account.id}"}]},
                ):
                    if finding := AwsInspectorFinding.from_api(item, builder):
                        if finding_resources := finding.finding_resources:
                            for fr in finding_resources:
                                class_name, class_id = check_type_and_adjust_id(fr.type, fr.id)
                                if class_name and class_id:
                                    adjusted_finding = finding.parse_finding(item)
                                    builder.add_finding(
                                        "inspector", class_name, fr.region or "global", class_id, adjusted_finding
                                    )

            except Boto3Error as e:
                msg = f"Error while collecting {cls.__name__} in region {builder.region.name}: {e}"
                builder.core_feedback.error(msg, log)
                raise
            except Exception as e:
                msg = f"Error while collecting {cls.__name__} in region {builder.region.name}: {e}"
                builder.core_feedback.info(msg, log)
                raise


resources: List[Type[AwsResource]] = [AwsInspectorFinding]
