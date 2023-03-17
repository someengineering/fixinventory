from typing import Optional, ClassVar, Dict, List, Type

import math
from attr import field, define

from resoto_plugin_aws.aws_client import AwsClient
from resoto_plugin_aws.resource.base import AwsApiSpec, GraphBuilder, AwsResource
from resoto_plugin_aws.resource.kms import AwsKmsKey
from resoto_plugin_aws.utils import ToDict
from resotolib.baseresources import ModelReference, BaseNetworkShare
from resotolib.graph import Graph
from resotolib.json_bender import Bender, S, F, Bend
from resotolib.types import Json

service_name = "efs"


class EfsTaggable:
    def update_resource_tag(self, client: AwsClient, key: str, value: str) -> bool:
        client.call(
            aws_service=service_name,
            action="tag-resource",
            result_name=None,
            resourceId=self.id,  # type: ignore
            tags={key: value},
        )
        return True

    def delete_resource_tag(self, client: AwsClient, key: str) -> bool:
        client.call(
            aws_service=service_name,
            action="untag-resource",
            result_name=None,
            resourceId=self.id,  # type: ignore
            tagKeys=[key],
        )
        return True

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return [
            AwsApiSpec(service_name, "tag-resource", override_iam_permission="elasticfilesystem:TagResource"),
            AwsApiSpec(service_name, "untag-resource", override_iam_permission="elasticfilesystem:UntagResource"),
        ]


@define(eq=False, slots=False)
class AwsEfsMountTarget(AwsResource):
    kind: ClassVar[str] = "aws_efs_mount_target"
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("MountTargetId"),
        "owner_id": S("OwnerId"),
        "life_cycle_state": S("LifeCycleState"),
        "ip_address": S("IpAddress"),
        "availability_zone_name": S("AvailabilityZoneName"),
    }
    reference_kinds: ClassVar[ModelReference] = {"predecessors": {"default": ["aws_ec2_network_interface"]}}
    owner_id: Optional[str] = field(default=None)
    life_cycle_state: Optional[str] = field(default=None)
    ip_address: Optional[str] = field(default=None)
    availability_zone_name: Optional[str] = field(default=None)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if nic_id := source.get("NetworkInterfaceId"):
            builder.dependant_node(self, reverse=True, kind="aws_ec2_network_interface", id=nic_id)


@define(eq=False, slots=False)
class AwsEfsFileSystem(EfsTaggable, AwsResource, BaseNetworkShare):
    kind: ClassVar[str] = "aws_efs_file_system"
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec(
        service_name,
        "describe-file-systems",
        "FileSystems",
        override_iam_permission="elasticfilesystem:DescribeFileSystems",
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("FileSystemId"),
        "tags": S("Tags", default=[]) >> ToDict(),
        "name": S("Name"),
        "ctime": S("CreationTime"),
        "owner_id": S("OwnerId"),
        "creation_token": S("CreationToken"),
        "arn": S("FileSystemArn"),
        "share_status": S("LifeCycleState"),
        "share_size": S("SizeInBytes", "Value") >> F(lambda x: math.ceil(x / 1024**3)),
        "share_encrypted": S("Encrypted"),
        "share_throughput": S("ProvisionedThroughputInMibps") >> F(lambda x: x * 1024**2),
        "provisioned_throughput_in_mibps": S("ProvisionedThroughputInMibps"),
        "number_of_mount_targets": S("NumberOfMountTargets"),
        "performance_mode": S("PerformanceMode"),
        "throughput_mode": S("ThroughputMode"),
        "availability_zone_name": S("AvailabilityZoneName"),
    }
    reference_kinds: ClassVar[ModelReference] = {"successors": {"default": ["aws_kms_key"]}}
    owner_id: Optional[str] = field(default=None)
    creation_token: Optional[str] = field(default=None)
    number_of_mount_targets: Optional[int] = field(default=None)
    performance_mode: Optional[str] = field(default=None)
    throughput_mode: Optional[str] = field(default=None)
    provisioned_throughput_in_mibps: Optional[float] = field(default=None)
    availability_zone_name: Optional[str] = field(default=None)

    @classmethod
    def called_collect_apis(cls) -> List[AwsApiSpec]:
        return [
            cls.api_spec,
            AwsApiSpec(
                service_name, "describe-mount-targets", override_iam_permission="elasticfilesystem:DescribeMountTargets"
            ),
        ]

    @classmethod
    def collect(cls: Type[AwsResource], json: List[Json], builder: GraphBuilder) -> None:
        def collect_mount_points(fs: AwsEfsFileSystem) -> None:
            for mt_raw in builder.client.list(
                service_name, "describe-mount-targets", "MountTargets", FileSystemId=fs.id
            ):
                mt = AwsEfsMountTarget.from_api(mt_raw)
                builder.add_node(mt, mt_raw)
                builder.add_edge(fs, node=mt)

        for js in json:
            instance = cls.from_api(js)
            builder.add_node(instance, js)
            builder.submit_work(service_name, collect_mount_points, instance)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if kms_key_id := source.get("KmsKeyId"):
            builder.dependant_node(from_node=self, clazz=AwsKmsKey, id=AwsKmsKey.normalise_id(kms_key_id))

    def delete_resource(self, client: AwsClient, graph: Graph) -> bool:
        client.call(service_name, "delete-file-system", FileSystemId=self.id)
        return True

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return [
            AwsApiSpec(service_name, "delete-file-system", override_iam_permission="elasticfilesystem:DeleteFileSystem")
        ]


@define(eq=False, slots=False)
class AwsEfsPosixUser:
    kind: ClassVar[str] = "aws_efs_posix_user"
    mapping: ClassVar[Dict[str, Bender]] = {
        "uid": S("Uid"),
        "gid": S("Gid"),
        "secondary_gids": S("SecondaryGids", default=[]),
    }
    uid: Optional[int] = field(default=None)
    gid: Optional[int] = field(default=None)
    secondary_gids: List[int] = field(factory=list)


@define(eq=False, slots=False)
class AwsEfsCreationInfo:
    kind: ClassVar[str] = "aws_efs_creation_info"
    mapping: ClassVar[Dict[str, Bender]] = {
        "owner_uid": S("OwnerUid"),
        "owner_gid": S("OwnerGid"),
        "permissions": S("Permissions"),
    }
    owner_uid: Optional[int] = field(default=None)
    owner_gid: Optional[int] = field(default=None)
    permissions: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsEfsRootDirectory:
    kind: ClassVar[str] = "aws_efs_root_directory"
    mapping: ClassVar[Dict[str, Bender]] = {
        "path": S("Path"),
        "creation_info": S("CreationInfo") >> Bend(AwsEfsCreationInfo.mapping),
    }
    path: Optional[str] = field(default=None)
    creation_info: Optional[AwsEfsCreationInfo] = field(default=None)


@define(eq=False, slots=False)
class AwsEfsAccessPoint(AwsResource, EfsTaggable):
    kind: ClassVar[str] = "aws_efs_access_point"
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec(
        service_name,
        "describe-access-points",
        "AccessPoints",
        override_iam_permission="elasticfilesystem:DescribeAccessPoints",
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("AccessPointId"),
        "tags": S("Tags", default=[]) >> ToDict(),
        "name": S("Name"),
        "client_token": S("ClientToken"),
        "arn": S("AccessPointArn"),
        "posix_user": S("PosixUser") >> Bend(AwsEfsPosixUser.mapping),
        "root_directory": S("RootDirectory") >> Bend(AwsEfsRootDirectory.mapping),
        "owner_id": S("OwnerId"),
        "life_cycle_state": S("LifeCycleState"),
    }
    reference_kinds: ClassVar[ModelReference] = {"predecessors": {"default": ["aws_efs_file_system"]}}
    client_token: Optional[str] = field(default=None)
    posix_user: Optional[AwsEfsPosixUser] = field(default=None)
    root_directory: Optional[AwsEfsRootDirectory] = field(default=None)
    owner_id: Optional[str] = field(default=None)
    life_cycle_state: Optional[str] = field(default=None)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if fs_id := source.get("FileSystemId"):
            builder.dependant_node(
                from_node=self, reverse=True, delete_same_as_default=True, clazz=AwsEfsFileSystem, id=fs_id
            )


resources: List[Type[AwsResource]] = [AwsEfsFileSystem, AwsEfsAccessPoint]
