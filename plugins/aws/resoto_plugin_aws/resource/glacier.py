from typing import ClassVar, Dict, List, Optional, Type

from attrs import define, field

from resoto_plugin_aws.aws_client import AwsClient
from resoto_plugin_aws.resource.base import AwsApiSpec, AwsResource, GraphBuilder
from resoto_plugin_aws.resource.kms import AwsKmsKey
from resoto_plugin_aws.resource.sns import AwsSnsTopic
from resotolib.baseresources import EdgeType, ModelReference
from resotolib.json_bender import S, Bend, Bender, ForallBend
from resotolib.types import Json


@define(eq=False, slots=False)
class AwsGlacierInventoryRetrievalParameters:
    kind: ClassVar[str] = "aws_glacier_job_inventory_retrieval_parameters"
    mapping: ClassVar[Dict[str, Bender]] = {
        "output_format": S("Format"),
        "start_date": S("StartDate"),
        "end_date": S("EndDate"),
        "limit": S("Limit"),
    }
    output_format: str = field(default=None)
    start_date: str = field(default=None)
    end_date: str = field(default=None)
    limit: str = field(default=None)


@define(eq=False, slots=False)
class AwsGlacierSelectParameters:
    kind: ClassVar[str] = "aws_glacier_job_select_parameters"
    mapping: ClassVar[Dict[str, Bender]] = {
        "input_serialization": S("InputSerialization"),
        "expression_type": S("ExpressionType"),
        "expression": S("Expression"),
        "output_serialization": S("OutputSerialization"),
    }
    input_serialization: Dict[str, Dict[str, str]] = field(default=None)
    expression_type: str = field(default=None)
    expression: str = field(default=None)
    output_serialization: Dict[str, Dict[str, str]] = field(default=None)


@define(eq=False, slots=False)
class AwsGlacierBucketEncryption:
    kind: ClassVar[str] = "aws_glacier_bucket_encryption"
    mapping: ClassVar[Dict[str, Bender]] = {
        "encryption_type": S("EncryptionType"),
        "kms_key_id": S("KMSKeyId"),
        "kms_context": S("KMSContext"),
    }
    encryption_type: str = field(default=None)
    kms_key_id: str = field(default=None)
    kms_context: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsGlacierAcl:
    kind: ClassVar[str] = "aws_glacier_acl"
    mapping: ClassVar[Dict[str, Bender]] = {
        "grantee": S("Grantee"),
        "permission": S("Permission"),
    }
    grantee: Dict[str, str] = field(default=None)
    permission: str = field(default=None)


@define(eq=False, slots=False)
class AwsGlacierJobBucket:
    kind: ClassVar[str] = "aws_glacier_job_bucket"
    mapping: ClassVar[Dict[str, Bender]] = {
        "bucket_name": S("BucketName"),
        "prefix": S("Prefix"),
        "encryption": S("Encryption") >> Bend(AwsGlacierBucketEncryption.mapping),
        "canned_acl": S("CannedACL"),
        "access_control_list": S("AccessControlList") >> ForallBend(AwsGlacierAcl.mapping),
        "tagging": S("Tagging"),
        "user_metadata": S("UserMetadata"),
        "storage_class": S("StorageClass"),
    }
    bucket_name: str = field(default=None)
    prefix: str = field(default=None)
    encryption: AwsGlacierBucketEncryption = field(default=None)
    access_control_list: List[AwsGlacierAcl] = field(default=None)
    tagging: Optional[Dict[str, str]] = field(default=None)
    user_metadata: Dict[str, str] = field(default=None)
    storage_class: str = field(default=None)


@define(eq=False, slots=False)
class AwsGlacierJobOutputLocation:
    kind: ClassVar[str] = "aws_glacier_job_output_location"
    mapping: ClassVar[Dict[str, Bender]] = {
        "s3": S("S3") >> Bend(AwsGlacierJobBucket.mapping),
    }
    s3: AwsGlacierJobBucket = field(default=None)


@define(eq=False, slots=False)
class AwsGlacierJob(AwsResource):
    kind: ClassVar[str] = "aws_glacier_job"
    reference_kinds: ClassVar[ModelReference] = {
        "predecessors": {
            "delete": ["aws_kms_key"],
        },
        "successors": {"default": ["aws_kms_key"]},
    }
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("JobId"),
        "name": S("JobId"),
        "ctime": S("CreationDate"),
        "vault_arn": S("VaultARN"),
        "description": S("JobDescription"),
        "glacier_job_action": S("Action"),
        "glacier_job_archive_id": S("ArchiveId"),
        "glacier_job_vault_arn": S("VaultARN"),
        "glacier_job_completed": S("Completed"),
        "glacier_job_status_code": S("StatusCode"),
        "glacier_job_status_message": S("StatusMessage"),
        "glacier_job_archive_size_in_bytes": S("ArchiveSizeInBytes"),
        "glacier_job_inventory_size_in_bytes": S("InventorySizeInBytes"),
        "glacier_job_sns_topic": S("SNSTopic"),
        "glacier_job_completion_date": S("CompletionDate"),
        "glacier_job_sha256_tree_hash": S("SHA256TreeHash"),
        "glacier_job_archive_sha256_tree_hash": S("ArchiveSHA256TreeHash"),
        "glacier_job_retrieval_byte_range": S("RetrievalByteRange"),
        "glacier_job_tier": S("Tier"),
        "glacier_job_inventory_retrieval_parameters": S("InventoryRetrievalParameters")
        >> Bend(AwsGlacierInventoryRetrievalParameters.mapping),
        "glacier_job_output_path": S("JobOutputPath"),
        "glacier_job_select_parameters": S("SelectParameters") >> Bend(AwsGlacierSelectParameters.mapping),
        "glacier_job_output_location": S("OutputLocation") >> Bend(AwsGlacierJobOutputLocation.mapping),
    }
    description: Optional[str] = field(default=None)
    glacier_job_action: str = field(default=None)
    glacier_job_archive_id: Optional[str] = field(default=None)
    glacier_job_vault_arn: Optional[str] = field(default=None)
    glacier_job_completed: bool = field(default=None)
    glacier_job_status_code: str = field(default=None)
    glacier_job_status_message: str = field(default=None)
    glacier_job_archive_size_in_bytes: Optional[int] = field(default=None)
    glacier_job_inventory_size_in_bytes: Optional[int] = field(default=None)
    glacier_job_sns_topic: str = field(default=None)
    glacier_job_completion_date: Optional[str] = field(default=None)
    glacier_job_sha256_tree_hash: Optional[str] = field(default=None)
    glacier_job_archive_sha256_tree_hash: Optional[str] = field(default=None)
    glacier_job_retrieval_byte_range: Optional[str] = field(default=None)
    glacier_job_tier: str = field(default=None)
    glacier_job_inventory_retrieval_parameters: Optional[AwsGlacierInventoryRetrievalParameters] = field(default=None)
    glacier_job_output_path: str = field(default=None)
    glacier_job_select_parameters: Optional[AwsGlacierSelectParameters] = field(default=None)
    glacier_job_output_location: Optional[AwsGlacierJobOutputLocation] = field(default=None)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if self.glacier_job_output_location:
            builder.dependant_node(
                self,
                clazz=AwsKmsKey,
                id=AwsKmsKey.normalise_id(self.glacier_job_output_location.s3.encryption.kms_key_id),
            )
        if self.glacier_job_sns_topic:
            builder.add_edge(self, clazz=AwsSnsTopic, arn=self.glacier_job_sns_topic)


@define(eq=False, slots=False)
class AwsGlacierVault(AwsResource):
    kind: ClassVar[str] = "aws_glacier_vault"
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec("glacier", "list-vaults", "VaultList")
    reference_kinds: ClassVar[ModelReference] = {
        "successors": {
            "default": ["aws_glacier_job"],
        }
    }
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("VaultName"),
        "name": S("VaultName"),
        "ctime": S("CreationDate"),
        "arn": S("VaultARN"),
        "glacier_last_inventory_date": S("LastInventoryDate"),
        "glacier_number_of_archives": S("NumberOfArchives"),
        "glacier_size_in_bytes": S("SizeInBytes"),
    }
    glacier_last_inventory_date: Optional[str] = field(default=None)
    glacier_number_of_archives: Optional[int] = field(default=None)
    glacier_size_in_bytes: Optional[int] = field(default=None)

    @classmethod
    def called_collect_apis(cls) -> List[AwsApiSpec]:
        return [
            cls.api_spec,
            AwsApiSpec(cls.api_spec.service, "list-tags-for-vault"),
            AwsApiSpec(cls.api_spec.service, "list-jobs"),
        ]

    @classmethod
    def collect(cls: Type[AwsResource], json: List[Json], builder: GraphBuilder) -> None:
        def add_tags(vault: AwsGlacierVault) -> None:
            tags = builder.client.get("glacier", "list-tags-for-vault", "Tags", vaultName=vault.name)
            if tags:
                vault.tags = tags

        for vault in json:
            vault_instance = cls.from_api(vault)
            builder.add_node(vault_instance, vault)
            builder.submit_work(add_tags, vault_instance)
            for job in builder.client.list("glacier", "list-jobs", "JobList", vaultName=vault_instance.name):
                job_instance = AwsGlacierJob.from_api(job)
                builder.add_node(job_instance, job)
                builder.add_edge(vault_instance, EdgeType.default, node=job_instance)

    def update_resource_tag(self, client: AwsClient, key: str, value: str) -> bool:
        client.call(
            aws_service="glacier", action="add-tags-to-vault", result_name=None, vaultName=self.name, Tags={key: value}
        )
        return True

    def delete_resource_tag(self, client: AwsClient, key: str) -> bool:
        client.call(
            aws_service="glacier", action="remove-tags-from-vault", result_name=None, vaultName=self.name, TagKeys=[key]
        )
        return True

    def delete_resource(self, client: AwsClient) -> bool:
        client.call(aws_service="glacier", action="delete-vault", result_name=None, vaultName=self.name)
        return True

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return [
            AwsApiSpec("glacier", "add-tags-to-vault"),
            AwsApiSpec("glacier", "remove-tags-from-vault"),
            AwsApiSpec("glacier", "delete-vault"),
        ]


resources: List[Type[AwsResource]] = [AwsGlacierVault, AwsGlacierJob]
