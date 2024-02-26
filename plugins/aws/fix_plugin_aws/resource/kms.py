import json
from typing import ClassVar, Dict, List, Optional, Type, Any
from attrs import define, field
from fix_plugin_aws.aws_client import AwsClient
from fix_plugin_aws.resource.base import AwsResource, AwsApiSpec, GraphBuilder
from fixlib.baseresources import BaseAccessKey
from fix_plugin_aws.utils import ToDict
from fixlib.graph import Graph
from fixlib.json import sort_json
from fixlib.json_bender import Bend, Bender, S, ForallBend, bend
from fixlib.types import Json

service_name = "kms"


@define(eq=False, slots=False)
class AwsKmsMultiRegionPrimaryKey:
    kind: ClassVar[str] = "aws_kms_multiregion_primary_key"
    kind_display: ClassVar[str] = "AWS KMS Multiregion Primary Key"
    kind_description: ClassVar[str] = (
        "The AWS KMS Multi-Region Primary Key setting specifies the main encryption key and its associated"
        " AWS region in a multi-region key setup, which is used to encrypt and decrypt data across"
        " different geographic locations."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"arn": S("Arn"), "region": S("Region")}
    arn: Optional[str] = field(default=None)
    region: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsKmsMultiRegionReplicaKey:
    kind: ClassVar[str] = "aws_kms_multiregion_replica_key"
    kind_display: ClassVar[str] = "AWS KMS Multi-Region Replica Key"
    kind_description: ClassVar[str] = (
        "The AWS KMS Multi-Region Replica Key is part of a multi-region key configuration that serves as a"
        " secondary copy of the primary encryption key, residing in a different AWS region to support"
        " cross-regional failover and localized encryption operations."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"arn": S("Arn"), "region": S("Region")}
    arn: Optional[str] = field(default=None)
    region: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsKmsMultiRegionConfig:
    kind: ClassVar[str] = "aws_kms_multiregion_config"
    kind_display: ClassVar[str] = "AWS KMS Multi-Region Config"
    kind_description: ClassVar[str] = (
        "The AWS KMS Multi-Region Config allows for the creation and management of AWS KMS keys that"
        " are replicated across multiple AWS regions, enabling a centralized encryption key strategy"
        " with regional redundancies for improved availability and latency."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "multi_region_key_type": S("MultiRegionKeyType"),
        "primary_key": S("PrimaryKey") >> Bend(AwsKmsMultiRegionPrimaryKey.mapping),
        "replica_keys": S("ReplicaKeys", default=[]) >> ForallBend(AwsKmsMultiRegionReplicaKey.mapping),
    }
    multi_region_key_type: Optional[str] = field(default=None)
    primary_key: Optional[AwsKmsMultiRegionPrimaryKey] = field(default=None)
    replica_keys: List[AwsKmsMultiRegionReplicaKey] = field(factory=list)


@define(eq=False, slots=False)
class AwsKmsKey(AwsResource, BaseAccessKey):
    kind: ClassVar[str] = "aws_kms_key"
    kind_display: ClassVar[str] = "AWS KMS Key"
    aws_metadata: ClassVar[Dict[str, Any]] = {"provider_link_tpl": "https://{region_id}.console.aws.amazon.com/kms/home?region={region}#/kms/keys/{id}", "arn_tpl": "arn:{partition}:kms:{region}:{account}:key/{id}"}  # fmt: skip
    kind_description: ClassVar[str] = (
        "AWS KMS (Key Management Service) Key is a managed service that allows you to"
        " create and control the encryption keys used to encrypt your data stored on"
        " various AWS services and applications."
    )
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec(service_name, "list-keys", "Keys")
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("KeyId"),
        "name": S("KeyId"),
        "ctime": S("CreationDate"),
        "arn": S("Arn"),
        "access_key_status": S("KeyState"),
        "kms_aws_account_id": S("AWSAccountId"),
        "kms_enabled": S("Enabled"),
        "kms_description": S("Description"),
        "kms_key_usage": S("KeyUsage"),
        "kms_origin": S("Origin"),
        "kms_key_manager": S("KeyManager"),
        "kms_customer_master_key_spec": S("CustomerMasterKeySpec"),
        "kms_key_spec": S("KeySpec"),
        "kms_encryption_algorithms": S("EncryptionAlgorithms", default=[]),
        "kms_multi_region": S("MultiRegion"),
        "kms_deletion_date": S("DeletionDate"),
        "kms_valid_to": S("ValidTo"),
        "kms_custom_key_store_id": S("CustomKeyStoreId"),
        "kms_cloud_hsm_cluster_id": S("CloudHsmClusterId"),
        "kms_expiration_model": S("ExpirationModel"),
        "kms_signing_algorithms": S("SigningAlgorithms", default=[]),
        "kms_multiregion_configuration": S("MultiRegionConfiguration") >> Bend(AwsKmsMultiRegionConfig.mapping),
        "kms_pending_deletion_window_in_days": S("PendingDeletionWindowInDays"),
        "kms_mac_algorithms": S("MacAlgorithms", default=[]),
    }

    kms_aws_account_id: Optional[str] = field(default=None)
    kms_enabled: Optional[bool] = field(default=None)
    kms_description: Optional[str] = field(default=None)
    kms_key_usage: Optional[str] = field(default=None)
    kms_origin: Optional[str] = field(default=None)
    kms_key_manager: Optional[str] = field(default=None)
    kms_customer_master_key_spec: Optional[str] = field(default=None)
    kms_key_spec: Optional[str] = field(default=None)
    kms_encryption_algorithms: List[str] = field(factory=list)
    kms_multi_region: Optional[bool] = field(default=None)
    kms_deletion_date: Optional[str] = field(default=None)
    kms_valid_to: Optional[str] = field(default=None)
    kms_custom_key_store_id: Optional[str] = field(default=None)
    kms_cloud_hsm_cluster_id: Optional[str] = field(default=None)
    kms_expiration_model: Optional[str] = field(default=None)
    kms_signing_algorithms: List[str] = field(factory=list)
    kms_multiregion_configuration: Optional[AwsKmsMultiRegionConfig] = field(default=None)
    kms_pending_deletion_window_in_days: Optional[int] = field(default=None)
    kms_mac_algorithms: List[str] = field(factory=list)
    kms_key_rotation_enabled: Optional[bool] = field(default=None)
    kms_key_policy: Optional[Json] = field(default=None)

    @classmethod
    def called_collect_apis(cls) -> List[AwsApiSpec]:
        return [
            cls.api_spec,
            AwsApiSpec(service_name, "describe-key"),
            AwsApiSpec(service_name, "list-resource-tags"),
            AwsApiSpec(service_name, "get-key-policy"),
            AwsApiSpec(service_name, "get-key-rotation-status"),
        ]

    @classmethod
    def collect(cls: Type[AwsResource], js_list: List[Json], builder: GraphBuilder) -> None:
        def add_instance(key: Dict[str, str]) -> None:
            key_metadata = builder.client.get(
                service_name, "describe-key", result_name="KeyMetadata", KeyId=key["KeyId"]
            )
            if key_metadata is not None:
                if instance := AwsKmsKey.from_api(key_metadata, builder):
                    builder.add_node(instance, key_metadata)
                    builder.submit_work(service_name, add_tags, instance)
                    builder.submit_work(service_name, fetch_key_policy, instance)
                    if instance.kms_key_manager == "CUSTOMER" and instance.access_key_status == "Enabled":
                        builder.submit_work(service_name, add_rotation_status, instance)

        def fetch_key_policy(key: AwsKmsKey) -> None:
            with builder.suppress(f"{service_name}.get-key-policy"):
                key_policy: Optional[str] = builder.client.get(  # type: ignore
                    service_name,
                    "get-key-policy",
                    result_name="Policy",
                    KeyId=key.id,
                    PolicyName="default",
                    expected_errors=["NotFoundException"],
                )
                if key_policy is not None:
                    key.kms_key_policy = sort_json(json.loads(key_policy), sort_list=True)

        def add_rotation_status(key: AwsKmsKey) -> None:
            with builder.suppress(f"{service_name}.get-key-rotation-status"):
                key.kms_key_rotation_enabled = builder.client.get(  # type: ignore
                    service_name, "get-key-rotation-status", result_name="KeyRotationEnabled", KeyId=key.id
                )

        def add_tags(key: AwsKmsKey) -> None:
            tags = builder.client.list(
                service_name,
                "list-resource-tags",
                result_name="Tags",
                expected_errors=["AccessDeniedException"],
                KeyId=key.id,
            )
            if tags:
                key.tags = bend(ToDict(key="TagKey", value="TagValue"), tags)

        for js in js_list:
            builder.submit_work(service_name, add_instance, js)

    def update_resource_tag(self, client: AwsClient, key: str, value: str) -> bool:
        client.call(
            aws_service=service_name,
            action="tag-resource",
            result_name=None,
            KeyId=self.id,
            Tags=[{"TagKey": key, "TagValue": value}],
        )
        return True

    def delete_resource_tag(self, client: AwsClient, key: str) -> bool:
        client.call(aws_service=service_name, action="untag-resource", result_name=None, KeyId=self.id, TagKeys=[key])
        return True

    def delete_resource(self, client: AwsClient, graph: Graph) -> bool:
        if self.access_key_status == "Disabled":
            client.call(
                aws_service=service_name,
                action="schedule-key-deletion",
                result_name=None,
                KeyId=self.id,
                PendingWindowInDays=7,
            )
            return True
        if self.access_key_status == "PendingDeletion":
            return True

        client.call(
            aws_service=service_name,
            action="disable-key",
            result_name=None,
            KeyId=self.id,
            expected_errors=["NotFoundException"],
        )
        return True

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return [
            AwsApiSpec(service_name, "tag-resource"),
            AwsApiSpec(service_name, "untag-resource"),
            AwsApiSpec(service_name, "schedule-key-deletion"),
            AwsApiSpec(service_name, "disable-key"),
        ]

    @staticmethod
    def normalise_id(identifier: str) -> str:
        if identifier.startswith("arn:"):
            # format: "arn:aws:kms:region:account-id:key/id"
            return identifier.rsplit("/", 1)[-1]
        else:
            return identifier


resources: List[Type[AwsResource]] = [AwsKmsKey]
