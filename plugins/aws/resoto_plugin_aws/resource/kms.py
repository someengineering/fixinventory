from typing import ClassVar, Dict, List, Optional, Type
from attrs import define, field
from resoto_plugin_aws.aws_client import AwsClient
from resoto_plugin_aws.resource.base import AwsResource, AwsApiSpec, GraphBuilder
from resotolib.baseresources import BaseAccessKey
from resoto_plugin_aws.utils import ToDict
from resotolib.json_bender import Bend, Bender, S, ForallBend, bend
from resotolib.types import Json


@define(eq=False, slots=False)
class AwsKmsMultiRegionPrimaryKey:
    kind: ClassVar[str] = "aws_kms_multiregion_primary_key"
    mapping: ClassVar[Dict[str, Bender]] = {"arn": S("Arn"), "region": S("Region")}
    arn: Optional[str] = field(default=None)
    region: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsKmsMultiRegionReplicaKey:
    kind: ClassVar[str] = "aws_kms_multiregion_replica_key"
    mapping: ClassVar[Dict[str, Bender]] = {"arn": S("Arn"), "region": S("Region")}
    arn: Optional[str] = field(default=None)
    region: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsKmsMultiRegionConfig:
    kind: ClassVar[str] = "aws_kms_multiregion_config"
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
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec("kms", "list-keys", "Keys")
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

    kms_aws_account_id: str = field(default=None)
    kms_enabled: bool = field(default=None)
    kms_description: str = field(default=None)
    kms_key_usage: str = field(default=None)
    kms_origin: str = field(default=None)
    kms_key_manager: str = field(default=None)
    kms_customer_master_key_spec: str = field(default=None)
    kms_key_spec: str = field(default=None)
    kms_encryption_algorithms: List[str] = field(factory=list)
    kms_multi_region: bool = field(default=None)
    kms_deletion_date: Optional[str] = field(default=None)
    kms_valid_to: Optional[str] = field(default=None)
    kms_custom_key_store_id: Optional[str] = field(default=None)
    kms_cloud_hsm_cluster_id: Optional[str] = field(default=None)
    kms_expiration_model: Optional[str] = field(default=None)
    kms_signing_algorithms: List[str] = field(factory=list)
    kms_multiregion_configuration: Optional[AwsKmsMultiRegionConfig] = field(default=None)
    kms_pending_deletion_window_in_days: Optional[int] = field(default=None)
    kms_mac_algorithms: List[str] = field(factory=list)

    @classmethod
    def called_collect_apis(cls) -> List[AwsApiSpec]:
        return [cls.api_spec, AwsApiSpec("kms", "describe-key"), AwsApiSpec("kms", "list-resource-tags")]

    @classmethod
    def collect(cls: Type[AwsResource], json: List[Json], builder: GraphBuilder) -> None:
        def add_instance(key: Dict[str, str]) -> None:
            key_metadata = builder.client.get("kms", "describe-key", result_name="KeyMetadata", KeyId=key["KeyId"])
            if key_metadata is not None:
                instance = cls.from_api(key_metadata)
                builder.add_node(instance)
                builder.submit_work(add_tags, instance)

        def add_tags(key: AwsKmsKey) -> None:
            tags = builder.client.list(
                "kms", "list-resource-tags", result_name="Tags", expected_errors=["AccessDeniedException"], KeyId=key.id
            )
            if tags:
                key.tags = bend(ToDict(key="TagKey", value="TagValue"), tags)

        for js in json:
            add_instance(js)

    def update_resource_tag(self, client: AwsClient, key: str, value: str) -> bool:
        client.call(
            aws_service="kms",
            action="tag-resource",
            result_name=None,
            KeyId=self.id,
            Tags=[{"TagKey": key, "TagValue": value}],
        )
        return True

    def delete_resource_tag(self, client: AwsClient, key: str) -> bool:
        client.call(aws_service="kms", action="untag-resource", result_name=None, KeyId=self.id, TagKeys=[key])
        return True

    def delete_resource(self, client: AwsClient) -> bool:
        if self.access_key_status == "Disabled":
            client.call(
                aws_service="kms",
                action="schedule-key-deletion",
                result_name=None,
                KeyId=self.id,
                PendingWindowInDays=7,
            )
            return True
        if self.access_key_status == "PendingDeletion":
            return True

        client.call(aws_service="kms", action="disable-key", result_name=None, KeyId=self.id)
        return True

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return [
            AwsApiSpec("kms", "tag-resource"),
            AwsApiSpec("kms", "untag-resource"),
            AwsApiSpec("kms", "schedule-key-deletion"),
            AwsApiSpec("kms", "disable-key"),
        ]

    @staticmethod
    def normalise_id(identifier: str) -> str:
        if identifier.startswith("arn:"):
            # format: "arn:aws:kms:region:account-id:key/id"
            return identifier.rsplit("/", 1)[-1]
        else:
            return identifier


resources: List[Type[AwsResource]] = [AwsKmsKey]
