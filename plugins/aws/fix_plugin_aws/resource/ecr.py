import json
import logging
from typing import ClassVar, Dict, Optional, List, Type, Any

from attrs import define, field
from boto3.exceptions import Boto3Error

from fix_plugin_aws.resource.base import AwsResource, AwsApiSpec, GraphBuilder
from fix_plugin_aws.utils import ToDict
from fixlib.json import sort_json
from fixlib.json_bender import Bender, S, Bend
from fixlib.types import Json

service_name = "ecr"
log = logging.getLogger("fix.plugins.aws")


@define(eq=False, slots=False)
class AwsEcrEncryptionConfiguration:
    kind: ClassVar[str] = "aws_ecr_encryption_configuration"
    mapping: ClassVar[Dict[str, Bender]] = {"encryption_type": S("encryptionType"), "kms_key": S("kmsKey")}
    encryption_type: Optional[str] = field(default=None, metadata={"description": "The encryption type to use. If you use the KMS encryption type, the contents of the repository will be encrypted using server-side encryption with Key Management Service key stored in KMS. When you use KMS to encrypt your data, you can either use the default Amazon Web Services managed KMS key for Amazon ECR, or specify your own KMS key, which you already created. For more information, see Protecting data using server-side encryption with an KMS key stored in Key Management Service (SSE-KMS) in the Amazon Simple Storage Service Console Developer Guide. If you use the AES256 encryption type, Amazon ECR uses server-side encryption with Amazon S3-managed encryption keys which encrypts the images in the repository using an AES-256 encryption algorithm. For more information, see Protecting data using server-side encryption with Amazon S3-managed encryption keys (SSE-S3) in the Amazon Simple Storage Service Console Developer Guide."})  # fmt: skip
    kms_key: Optional[str] = field(default=None, metadata={"description": "If you use the KMS encryption type, specify the KMS key to use for encryption. The alias, key ID, or full ARN of the KMS key can be specified. The key must exist in the same Region as the repository. If no key is specified, the default Amazon Web Services managed KMS key for Amazon ECR will be used."})  # fmt: skip


@define(eq=False, slots=False)
class AwsEcrRepository(AwsResource):
    kind: ClassVar[str] = "aws_ecr_repository"
    kind_display: ClassVar[str] = "AWS ECR Repository"
    kind_description: ClassVar[str] = "An AWS Elastic Container Registry (ECR) Repository is used for storing, managing, and deploying Docker container images in a secure, scalable, and private environment on AWS."  # fmt: skip
    aws_metadata: ClassVar[Dict[str, Any]] = {"provider_link_tpl": "https://{region_id}.console.aws.amazon.com/ecr/repositories/{name}?region={region}", "arn_tpl": "arn:{partition}:ecr:{region}:{account}:repository/{name}"}  # fmt: skip
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec("ecr", "describe-repositories", "repositories")
    public_spec: ClassVar[AwsApiSpec] = AwsApiSpec("ecr-public", "describe-repositories", "repositories")
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("repositoryName"),
        "tags": S("Tags", default=[]) >> ToDict(),
        "name": S("repositoryName"),
        "ctime": S("createdAt"),
        "repository_arn": S("repositoryArn"),
        "registry_id": S("registryId"),
        "repository_uri": S("repositoryUri"),
        "image_tag_mutability": S("imageTagMutability"),
        "image_scan_on_push": S("imageScanningConfiguration", "scanOnPush"),
        "encryption_configuration": S("encryptionConfiguration") >> Bend(AwsEcrEncryptionConfiguration.mapping),
    }
    repository_arn: Optional[str] = field(default=None, metadata={"description": "The Amazon Resource Name (ARN) that identifies the repository. The ARN contains the arn:aws:ecr namespace, followed by the region of the repository, Amazon Web Services account ID of the repository owner, repository namespace, and repository name. For example, arn:aws:ecr:region:012345678910:repository-namespace/repository-name."})  # fmt: skip
    registry_id: Optional[str] = field(default=None, metadata={"description": "The Amazon Web Services account ID associated with the registry that contains the repository."})  # fmt: skip
    repository_uri: Optional[str] = field(default=None, metadata={"description": "The URI for the repository. You can use this URI for container image push and pull operations."})  # fmt: skip
    image_tag_mutability: Optional[str] = field(default=None, metadata={"description": "The tag mutability setting for the repository."})  # fmt: skip
    image_scan_on_push: Optional[bool] = field(default=None, metadata={"description": "The image is scanned on every push."})  # fmt: skip
    encryption_configuration: Optional[AwsEcrEncryptionConfiguration] = field(default=None, metadata={"description": "The encryption configuration for the repository. This determines how the contents of your repository are encrypted at rest."})  # fmt: skip
    repository_visibility: Optional[str] = field(default=None, metadata={"description": "The repository is either public or private."})  # fmt: skip
    lifecycle_policy: Optional[Json] = field(default=None, metadata={"description": "The repository lifecycle policy."})  # fmt: skip

    @classmethod
    def collect_resources(cls, builder: GraphBuilder) -> None:
        def fetch_lifecycle_policy(repository: AwsEcrRepository) -> None:
            with builder.suppress(f"{service_name}.get-lifecycle-policy"):
                if policy := builder.client.get(
                    service_name,
                    "get-lifecycle-policy",
                    repositoryName=repository.name,
                    expected_errors=["LifecyclePolicyNotFoundException"],
                ):
                    repository.lifecycle_policy = sort_json(json.loads(policy["lifecyclePolicyText"]), sort_list=True)

        def collect(visibility: str, spec: AwsApiSpec) -> None:
            try:
                kwargs = spec.parameter or {}
                items = builder.client.list(
                    aws_service=spec.service,
                    action=spec.api_action,
                    result_name=spec.result_property,
                    expected_errors=spec.expected_errors,
                    **kwargs,
                )
                for js in items:
                    if instance := cls.from_api(js, builder):
                        instance.repository_visibility = visibility
                        builder.submit_work(service_name, fetch_lifecycle_policy, instance)
                        builder.add_node(instance, js)
            except Boto3Error as e:
                msg = f"Error while collecting {cls.__name__} in region {builder.region.name}: {e}"
                builder.core_feedback.error(msg, log)
                raise
            except Exception as e:
                msg = f"Error while collecting {cls.__name__} in region {builder.region.name}: {e}"
                builder.core_feedback.info(msg, log)
                raise

        # collect private and public repositories
        if builder.region.name == "global":
            collect("public", cls.public_spec)
        else:
            collect("private", cls.api_spec)

    @classmethod
    def called_collect_apis(cls) -> List[AwsApiSpec]:
        return [cls.api_spec, cls.public_spec, AwsApiSpec("ecr", "get-lifecycle-policy", None)]


# @define(eq=False, slots=False)
# class AwsEcrImageIdentifier:
#     kind: ClassVar[str] = "aws_ecr_image_identifier"
#     mapping: ClassVar[Dict[str, Bender]] = {"image_digest": S("imageDigest"), "image_tag": S("imageTag")}
#     image_digest: Optional[str] = field(default=None, metadata={"description": "The sha256 digest of the image manifest."})  # fmt: skip
#     image_tag: Optional[str] = field(default=None, metadata={"description": "The tag used for the image."})  # fmt: skip
#
#
# @define(eq=False, slots=False)
# class AwsEcrImage(AwsResource):
#     kind: ClassVar[str] = "aws_ecr_image"
#     api_spec: ClassVar[AwsApiSpec] = AwsApiSpec("ecr", "describe-images", "images")
#     mapping: ClassVar[Dict[str, Bender]] = {
#         "id": S("id"),
#         "tags": S("Tags", default=[]) >> ToDict(),
#         "name": S("Tags", default=[]) >> TagsValue("Name"),
#         "registry_id": S("registryId"),
#         "repository_name": S("repositoryName"),
#         "image_id": S("imageId") >> Bend(AwsEcrImageIdentifier.mapping),
#         "image_manifest": S("imageManifest"),
#         "image_manifest_media_type": S("imageManifestMediaType"),
#     }
#     registry_id: Optional[str] = field(default=None, metadata={"description": "The Amazon Web Services account ID associated with the registry containing the image."})  # fmt: skip
#     repository_name: Optional[str] = field(default=None, metadata={"description": "The name of the repository associated with the image."})  # fmt: skip
#     image_id: Optional[AwsEcrImageIdentifier] = field(default=None, metadata={"description": "An object containing the image tag and image digest associated with an image."})  # fmt: skip
#     image_manifest: Optional[str] = field(default=None, metadata={"description": "The image manifest associated with the image."})  # fmt: skip
#     image_manifest_media_type: Optional[str] = field(default=None, metadata={"description": "The manifest media type of the image."})  # fmt: skip


resources: List[Type[AwsResource]] = [AwsEcrRepository]
global_resources: List[Type[AwsResource]] = [AwsEcrRepository]
