import json
from typing import ClassVar, Dict, List, Optional, Type, Any

from attrs import define, field

from fix_plugin_aws.aws_client import AwsClient
from fix_plugin_aws.resource.base import AwsApiSpec, AwsResource, GraphBuilder
from fix_plugin_aws.resource.kms import AwsKmsKey
from fix_plugin_aws.resource.sns import AwsSnsTopic
from fixlib.baseresources import EdgeType, ModelReference
from fixlib.graph import Graph
from fixlib.json import sort_json
from fixlib.json_bender import S, Bend, Bender, ForallBend
from fixlib.types import Json

service_name = "glacier"


@define(eq=False, slots=False)
class AwsGlacierInventoryRetrievalParameters:
    kind: ClassVar[str] = "aws_glacier_job_inventory_retrieval_parameters"
    kind_display: ClassVar[str] = "AWS Glacier Job Inventory Retrieval Parameters"
    kind_description: ClassVar[str] = (
        "Retrieval parameters for inventory jobs in Amazon Glacier service that allow"
        " users to access metadata about their Glacier vault inventory."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "output_format": S("Format"),
        "start_date": S("StartDate"),
        "end_date": S("EndDate"),
        "limit": S("Limit"),
    }
    output_format: Optional[str] = field(default=None)
    start_date: Optional[str] = field(default=None)
    end_date: Optional[str] = field(default=None)
    limit: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsGlacierSelectParameters:
    kind: ClassVar[str] = "aws_glacier_job_select_parameters"
    kind_display: ClassVar[str] = "AWS Glacier Job Select Parameters"
    kind_description: ClassVar[str] = (
        "The AWS Glacier Job Select Parameters are used to configure data retrieval jobs in Amazon Glacier,"
        " allowing you to define the format of the input data, the type of queries, the query expressions"
        " themselves, and the format of the output data."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "input_serialization": S("InputSerialization"),
        "expression_type": S("ExpressionType"),
        "expression": S("Expression"),
        "output_serialization": S("OutputSerialization"),
    }
    input_serialization: Optional[Dict[str, Dict[str, str]]] = field(default=None)
    expression_type: Optional[str] = field(default=None)
    expression: Optional[str] = field(default=None)
    output_serialization: Optional[Dict[str, Dict[str, str]]] = field(default=None)


@define(eq=False, slots=False)
class AwsGlacierBucketEncryption:
    kind: ClassVar[str] = "aws_glacier_bucket_encryption"
    kind_display: ClassVar[str] = "AWS Glacier Bucket Encryption"
    kind_description: ClassVar[str] = (
        "The AWS Glacier Bucket Encryption settings define the method and keys used to secure data in an Amazon"
        " Glacier storage bucket, providing options for server-side encryption and specifying the use of AWS"
        " Key Management Service (KMS) keys where applicable."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "encryption_type": S("EncryptionType"),
        "kms_key_id": S("KMSKeyId"),
        "kms_context": S("KMSContext"),
    }
    encryption_type: Optional[str] = field(default=None)
    kms_key_id: Optional[str] = field(default=None)
    kms_context: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsGlacierAcl:
    kind: ClassVar[str] = "aws_glacier_acl"
    kind_display: ClassVar[str] = "AWS Glacier ACL"
    kind_description: ClassVar[str] = (
        "AWS Glacier ACL is an access control feature in Amazon Glacier that allows"
        " users to manage permissions for their Glacier vaults and archives."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "grantee": S("Grantee"),
        "permission": S("Permission"),
    }
    grantee: Optional[Dict[str, str]] = field(default=None)
    permission: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsGlacierJobBucket:
    kind: ClassVar[str] = "aws_glacier_job_bucket"
    kind_display: ClassVar[str] = "AWS Glacier Job Bucket"
    kind_description: ClassVar[str] = (
        "The AWS Glacier Job Bucket is a setting for defining where and how the output of a"
        " data retrieval job from Amazon Glacier is stored and managed in Amazon S3."
    )
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
    bucket_name: Optional[str] = field(default=None)
    prefix: Optional[str] = field(default=None)
    encryption: Optional[AwsGlacierBucketEncryption] = field(default=None)
    access_control_list: Optional[List[AwsGlacierAcl]] = field(default=None)
    tagging: Optional[Dict[str, str]] = field(default=None)
    user_metadata: Optional[Dict[str, str]] = field(default=None)
    storage_class: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsGlacierJobOutputLocation:
    kind: ClassVar[str] = "aws_glacier_job_output_location"
    kind_display: ClassVar[str] = "AWS Glacier Job Output Location"
    kind_description: ClassVar[str] = (
        "The AWS Glacier Job Output Location refers to the destination where the"
        " output of an AWS Glacier job is stored."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "s3": S("S3") >> Bend(AwsGlacierJobBucket.mapping),
    }
    s3: Optional[AwsGlacierJobBucket] = field(default=None)


@define(eq=False, slots=False)
class AwsGlacierJob(AwsResource):
    kind: ClassVar[str] = "aws_glacier_job"
    kind_display: ClassVar[str] = "AWS Glacier Job"
    aws_metadata: ClassVar[Dict[str, Any]] = {"arn_tpl": "arn:{partition}:glacier:{region}:{account}:job/{id}"}  # fmt: skip
    kind_description: ClassVar[str] = (
        "AWS Glacier Jobs are used to manage and execute operations on data stored in"
        " Amazon S3 Glacier, such as data retrieval or inventory retrieval."
    )
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
    glacier_job_action: Optional[str] = field(default=None)
    glacier_job_archive_id: Optional[str] = field(default=None)
    glacier_job_vault_arn: Optional[str] = field(default=None)
    glacier_job_completed: Optional[bool] = field(default=None)
    glacier_job_status_code: Optional[str] = field(default=None)
    glacier_job_status_message: Optional[str] = field(default=None)
    glacier_job_archive_size_in_bytes: Optional[int] = field(default=None)
    glacier_job_inventory_size_in_bytes: Optional[int] = field(default=None)
    glacier_job_sns_topic: Optional[str] = field(default=None)
    glacier_job_completion_date: Optional[str] = field(default=None)
    glacier_job_sha256_tree_hash: Optional[str] = field(default=None)
    glacier_job_archive_sha256_tree_hash: Optional[str] = field(default=None)
    glacier_job_retrieval_byte_range: Optional[str] = field(default=None)
    glacier_job_tier: Optional[str] = field(default=None)
    glacier_job_inventory_retrieval_parameters: Optional[AwsGlacierInventoryRetrievalParameters] = field(default=None)
    glacier_job_output_path: Optional[str] = field(default=None)
    glacier_job_select_parameters: Optional[AwsGlacierSelectParameters] = field(default=None)
    glacier_job_output_location: Optional[AwsGlacierJobOutputLocation] = field(default=None)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        # noinspection PyUnboundLocalVariable
        if (o := self.glacier_job_output_location) and (s3 := o.s3) and (e := s3.encryption) and (kid := e.kms_key_id):
            builder.dependant_node(self, clazz=AwsKmsKey, id=AwsKmsKey.normalise_id(kid))
        if self.glacier_job_sns_topic:
            builder.add_edge(self, clazz=AwsSnsTopic, arn=self.glacier_job_sns_topic)

    @classmethod
    def service_name(cls) -> str:
        return service_name


@define(eq=False, slots=False)
class AwsGlacierVault(AwsResource):
    kind: ClassVar[str] = "aws_glacier_vault"
    kind_display: ClassVar[str] = "AWS Glacier Vault"
    aws_metadata: ClassVar[Dict[str, Any]] = {"provider_link_tpl": "https://{region_id}.console.aws.amazon.com/glacier/home?region={region}#/vault/{name}/view/properties", "arn_tpl": "arn:{partition}:glacier:{region}:{account}:vault/{name}"}  # fmt: skip
    kind_description: ClassVar[str] = (
        "AWS Glacier Vaults are used for long term data archiving and backup,"
        " providing a secure and durable storage solution with low cost."
    )
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec(service_name, "list-vaults", "VaultList")
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
    glacier_access_policy: Optional[Json] = field(default=None)

    @classmethod
    def called_collect_apis(cls) -> List[AwsApiSpec]:
        return [
            cls.api_spec,
            AwsApiSpec(cls.api_spec.service, "list-tags-for-vault"),
            AwsApiSpec(cls.api_spec.service, "list-jobs"),
        ]

    @classmethod
    def collect(cls: Type[AwsResource], source: List[Json], builder: GraphBuilder) -> None:
        def add_tags(vault: AwsGlacierVault) -> None:
            tags = builder.client.get(service_name, "list-tags-for-vault", "Tags", vaultName=vault.name)
            if tags:
                vault.tags = tags

        def access_policy(vault: AwsGlacierVault) -> None:
            response = builder.client.get(
                service_name,
                "get-vault-access-policy",
                "policy",
                vaultName=vault.name,
                expected_errors=["ResourceNotFoundException"],
            )
            if response and (policy_string := response.get("Policy")):
                vault.glacier_access_policy = sort_json(json.loads(policy_string), sort_list=True)

        for vault in source:
            if vault_instance := cls.from_api(vault, builder):
                builder.add_node(vault_instance, vault)
                builder.submit_work(service_name, add_tags, vault_instance)
                builder.submit_work(service_name, access_policy, vault_instance)
                for job in builder.client.list(service_name, "list-jobs", "JobList", vaultName=vault_instance.name):
                    if job_instance := AwsGlacierJob.from_api(job, builder):
                        builder.add_node(job_instance, job)
                        builder.add_edge(vault_instance, EdgeType.default, node=job_instance)

    def update_resource_tag(self, client: AwsClient, key: str, value: str) -> bool:
        client.call(
            aws_service=service_name,
            action="add-tags-to-vault",
            result_name=None,
            vaultName=self.name,
            Tags={key: value},
        )
        return True

    def delete_resource_tag(self, client: AwsClient, key: str) -> bool:
        client.call(
            aws_service=service_name,
            action="remove-tags-from-vault",
            result_name=None,
            vaultName=self.name,
            TagKeys=[key],
        )
        return True

    def delete_resource(self, client: AwsClient, graph: Graph) -> bool:
        client.call(aws_service=service_name, action="delete-vault", result_name=None, vaultName=self.name)
        return True

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return [
            AwsApiSpec(service_name, "add-tags-to-vault"),
            AwsApiSpec(service_name, "remove-tags-from-vault"),
            AwsApiSpec(service_name, "delete-vault"),
        ]


resources: List[Type[AwsResource]] = [AwsGlacierVault, AwsGlacierJob]
