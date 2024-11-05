import logging
from datetime import datetime
from functools import partial
from typing import ClassVar, Dict, Optional, List, Tuple, Type, Any

from attrs import define, field
from boto3.exceptions import Boto3Error

from fix_plugin_aws.resource.base import AwsResource, AwsApiSpec, GraphBuilder
from fix_plugin_aws.resource.ec2 import AwsEc2Instance
from fix_plugin_aws.resource.ecr import AwsEcrRepository
from fix_plugin_aws.resource.lambda_ import AwsLambdaFunction
from fixlib.baseresources import SEVERITY_MAPPING, PhantomBaseResource, Severity, Finding
from fixlib.json_bender import Bender, S, ForallBend, Bend, F
from fixlib.types import Json

log = logging.getLogger("fix.plugins.aws")
service_name = "inspector2"

amazon_inspector = "amazon_inspector"


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
class AwsInspectorResource:
    kind: ClassVar[str] = "aws_inspector_resource"
    mapping: ClassVar[Dict[str, Bender]] = {
        # "details": S("details") # not used
        "id": S("id"),
        "partition": S("partition"),
        "region": S("region"),
        "type": S("type"),
    }
    id: Optional[str] = field(default=None, metadata={"description": "The ID of the resource."})  # fmt: skip
    partition: Optional[str] = field(default=None, metadata={"description": "The partition of the resource."})  # fmt: skip
    region: Optional[str] = field(default=None, metadata={"description": "The Amazon Web Services Region the impacted resource is located in."})  # fmt: skip
    type: Optional[str] = field(default=None, metadata={"description": "The type of resource."})  # fmt: skip


@define(eq=False, slots=False)
class AwsInspectorFinding(AwsResource, PhantomBaseResource):
    kind: ClassVar[str] = "aws_inspector_finding"
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec(service_name, "list-findings")
    _model_export: ClassVar[bool] = False  # do not export this class, since there will be no instances of it
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("findingArn") >> F(AwsResource.id_from_arn),
        "name": S("title"),
        "mtime": S("updatedAt"),
        "arn": S("findingArn"),
        "aws_account_id": S("awsAccountId"),
        "description": S("description"),
        "epss": S("epss", "score"),
        "exploit_available": S("exploitAvailable"),
        "exploitability_details": S("exploitabilityDetails", "lastKnownExploitAt"),
        "finding_arn": S("findingArn"),
        "first_observed_at": S("firstObservedAt"),
        "fix_available": S("fixAvailable"),
        "inspector_score": S("inspectorScore"),
        "last_observed_at": S("lastObservedAt"),
        "remediation": S("remediation") >> Bend(AwsInspectorRemediation.mapping),
        "finding_resources": S("resources", default=[]) >> ForallBend(AwsInspectorResource.mapping),
        "finding_severity": S("severity"),
        "status": S("status"),
        "title": S("title"),
        "type": S("type"),
        "updated_at": S("updatedAt"),
        # available but not used properties:
        # "inspector_score_details": S("inspectorScoreDetails")
        # "code_vulnerability_details": S("codeVulnerabilityDetails")
        # "network_reachability_details": S("networkReachabilityDetails")
        # "package_vulnerability_details": S("packageVulnerabilityDetails")
    }
    aws_account_id: Optional[str] = field(default=None, metadata={"description": "The Amazon Web Services account ID associated with the finding."})  # fmt: skip
    description: Optional[str] = field(default=None, metadata={"description": "The description of the finding."})  # fmt: skip
    epss: Optional[float] = field(default=None, metadata={"description": "The finding's EPSS score."})  # fmt: skip
    exploit_available: Optional[str] = field(default=None, metadata={"description": "If a finding discovered in your environment has an exploit available."})  # fmt: skip
    exploitability_details: Optional[datetime] = field(default=None, metadata={"description": "The details of an exploit available for a finding discovered in your environment."})  # fmt: skip
    finding_arn: Optional[str] = field(default=None, metadata={"description": "The Amazon Resource Number (ARN) of the finding."})  # fmt: skip
    first_observed_at: Optional[datetime] = field(default=None, metadata={"description": "The date and time that the finding was first observed."})  # fmt: skip
    fix_available: Optional[str] = field(default=None, metadata={"description": "Details on whether a fix is available through a version update. This value can be YES, NO, or PARTIAL. A PARTIAL fix means that some, but not all, of the packages identified in the finding have fixes available through updated versions."})  # fmt: skip
    inspector_score: Optional[float] = field(default=None, metadata={"description": "The Amazon Inspector score given to the finding."})  # fmt: skip
    last_observed_at: Optional[datetime] = field(default=None, metadata={"description": "The date and time the finding was last observed. This timestamp for this field remains unchanged until a finding is updated."})  # fmt: skip
    remediation: Optional[AwsInspectorRemediation] = field(default=None, metadata={"description": "An object that contains the details about how to remediate a finding."})  # fmt: skip
    finding_resources: Optional[List[AwsInspectorResource]] = field(factory=list, metadata={"description": "Contains information on the resources involved in a finding. The resource value determines the valid values for type in your request. For more information, see Finding types in the Amazon Inspector user guide."})  # fmt: skip
    finding_severity: Optional[str] = field(default=None, metadata={"description": "The severity of the finding. UNTRIAGED applies to PACKAGE_VULNERABILITY type findings that the vendor has not assigned a severity yet. For more information, see Severity levels for findings in the Amazon Inspector user guide."})  # fmt: skip
    status: Optional[str] = field(default=None, metadata={"description": "The status of the finding."})  # fmt: skip
    title: Optional[str] = field(default=None, metadata={"description": "The title of the finding."})  # fmt: skip
    type: Optional[str] = field(default=None, metadata={"description": "The type of the finding. The type value determines the valid values for resource in your request. For more information, see Finding types in the Amazon Inspector user guide."})  # fmt: skip
    updated_at: Optional[datetime] = field(default=None, metadata={"description": "The date and time the finding was last updated at."})  # fmt: skip

    def parse_finding(self, source: Json) -> Finding:
        finding_title = self.safe_name
        if not self.finding_severity:
            finding_severity = Severity.medium
        else:
            finding_severity = SEVERITY_MAPPING.get(self.finding_severity, Severity.medium)
        description = self.description
        remediation = ""
        if self.remediation and self.remediation.recommendation:
            remediation = self.remediation.recommendation.text or ""
        updated_at = self.updated_at
        details = source.get("packageVulnerabilityDetails", {}) | source.get("codeVulnerabilityDetails", {})
        return Finding(finding_title, finding_severity, description, remediation, updated_at, details)

    @classmethod
    def collect_resources(cls, builder: GraphBuilder) -> None:
        def check_type_and_adjust_id(
            class_type: Optional[str], resource_id: Optional[str]
        ) -> Tuple[Optional[Type[Any]], Optional[Dict[str, Any]]]:
            if not resource_id or not class_type:
                return None, None
            match class_type:
                case "AWS_LAMBDA_FUNCTION":
                    # remove lambda's version from arn
                    lambda_arn = resource_id.rsplit(":", 1)[0]
                    return AwsLambdaFunction, {"arn": lambda_arn}
                case "AWS_EC2_INSTANCE":
                    return AwsEc2Instance, {"id": resource_id}
                case "AWS_ECR_REPOSITORY":
                    return AwsEcrRepository, {"id": resource_id, "_region": builder.region}
                case _:
                    return None, None

        def add_finding(
            provider: str, finding: Finding, clazz: Optional[Type[AwsResource]] = None, **node: Any
        ) -> None:
            if resource := builder.node(clazz=clazz, **node):
                resource.add_finding(provider, finding)

        # Default behavior: in case the class has an ApiSpec, call the api and call collect.
        log.debug(f"Collecting {cls.__name__} in region {builder.region.name}")
        try:
            for item in builder.client.list(
                aws_service=service_name,
                action="list-findings",
                result_name="findings",
                expected_errors=["AccessDeniedException"],
                filterCriteria={"awsAccountId": [{"comparison": "EQUALS", "value": f"{builder.account.id}"}]},
            ):
                if finding := AwsInspectorFinding.from_api(item, builder):
                    for fr in finding.finding_resources or []:
                        clazz, res_filter = check_type_and_adjust_id(fr.type, fr.id)
                        if clazz and res_filter:
                            # append the finding when all resources have been collected
                            builder.after_collect_actions.append(
                                partial(
                                    add_finding,
                                    amazon_inspector,
                                    finding.parse_finding(item),
                                    clazz,
                                    **res_filter,
                                )
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
