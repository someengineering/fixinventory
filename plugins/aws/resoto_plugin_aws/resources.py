import time
import copy
from datetime import date
from enum import Enum, auto
from resotolib.baseresources import *
from resotolib.graph import Graph
from resotolib.utils import make_valid_timestamp
from .utils import aws_client, aws_resource
from typing import ClassVar, Any
from dataclasses import dataclass
from resotolib.logger import log


default_ctime = make_valid_timestamp(date(2006, 3, 19))  # AWS public launch date


# derived from https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-template-resource-type-ref.html
@dataclass(eq=False)
class AWSAccount(BaseAccount):
    kind: ClassVar[str] = "aws_account"
    successor_kinds: ClassVar[Dict[str, List[str]]] = {
        "default": ["aws_region"],
        "delete": [],
    }

    account_alias: Optional[str] = ""
    role: Optional[str] = None
    users: Optional[int] = 0
    groups: Optional[int] = 0
    account_mfa_enabled: Optional[int] = 0
    account_access_keys_present: Optional[int] = 0
    account_signing_certificates_present: Optional[int] = 0
    mfa_devices: Optional[int] = 0
    mfa_devices_in_use: Optional[int] = 0
    policies: Optional[int] = 0
    policy_versions_in_use: Optional[int] = 0
    global_endpoint_token_version: Optional[int] = 0
    server_certificates: Optional[int] = 0
    minimum_password_length: Optional[int] = None
    require_symbols: Optional[bool] = None
    require_numbers: Optional[bool] = None
    require_uppercase_characters: Optional[bool] = None
    require_lowercase_characters: Optional[bool] = None
    allow_users_to_change_password: Optional[bool] = None
    expire_passwords: Optional[bool] = None
    max_password_age: Optional[int] = 0
    password_reuse_prevention: Optional[int] = 0
    hard_expiry: Optional[bool] = None

    def delete(self, graph) -> bool:
        return False


@dataclass(eq=False)
class AWSRegion(BaseRegion):
    kind: ClassVar[str] = "aws_region"
    successor_kinds: ClassVar[Dict[str, List[str]]] = {
        "default": [
            "aws_vpc_quota",
            "aws_vpc_peering_connection",
            "aws_vpc_endpoint",
            "aws_vpc",
            "aws_s3_bucket_quota",
            "aws_s3_bucket",
            "aws_rds_instance",
            "aws_iam_server_certificate_quota",
            "aws_iam_server_certificate",
            "aws_iam_role",
            "aws_iam_policy",
            "aws_iam_instance_profile",
            "aws_iam_group",
            "aws_elb_quota",
            "aws_elb",
            "aws_eks_cluster",
            "aws_ec2_volume_type",
            "aws_ec2_volume",
            "aws_iam_user",
            "aws_ec2_subnet",
            "aws_ec2_snapshot",
            "aws_ec2_security_group",
            "aws_ec2_route_table",
            "aws_ec2_network_interface",
            "aws_ec2_network_acl",
            "aws_ec2_nat_gateway",
            "aws_ec2_keypair",
            "aws_ec2_internet_gateway_quota",
            "aws_ec2_internet_gateway",
            "aws_ec2_instance_type",
            "aws_ec2_instance_quota",
            "aws_ec2_instance",
            "aws_ec2_elastic_ip",
            "aws_cloudwatch_alarm",
            "aws_cloudformation_stack",
            "aws_autoscaling_group",
            "aws_alb_target_group",
            "aws_alb_quota",
            "aws_alb",
        ],
        "delete": [],
    }
    ctime: Optional[datetime] = default_ctime

    def delete(self, graph) -> bool:
        return False


@dataclass(eq=False)
class AWSResource:
    kind: ClassVar[str] = "aws_resource"
    arn: Optional[str] = None

    def delete(self, graph) -> bool:
        return False


@dataclass(eq=False)
class AWSEC2InstanceType(AWSResource, BaseInstanceType):
    kind: ClassVar[str] = "aws_ec2_instance_type"
    successor_kinds: ClassVar[Dict[str, List[str]]] = {
        "default": ["aws_ec2_instance"],
        "delete": [],
    }


@dataclass(eq=False)
class AWSEC2InstanceQuota(AWSResource, BaseInstanceQuota):
    kind: ClassVar[str] = "aws_ec2_instance_quota"
    successor_kinds: ClassVar[Dict[str, List[str]]] = {
        "default": ["aws_ec2_instance_type"],
        "delete": [],
    }


@dataclass(eq=False)
class AWSEC2Instance(AWSResource, BaseInstance):
    kind: ClassVar[str] = "aws_ec2_instance"
    successor_kinds: ClassVar[Dict[str, List[str]]] = {
        "default": [
            "aws_ec2_volume",
            "aws_ec2_network_interface",
            "aws_ec2_keypair",
            "aws_ec2_elastic_ip",
            "aws_cloudwatch_alarm",
        ],
        "delete": ["aws_elb", "aws_autoscaling_group", "aws_alb_target_group"],
    }

    instance_status_map: ClassVar[Dict[str, InstanceStatus]] = {
        "pending": InstanceStatus.BUSY,
        "running": InstanceStatus.RUNNING,
        "shutting-down": InstanceStatus.BUSY,
        "terminated": InstanceStatus.TERMINATED,
        "stopping": InstanceStatus.BUSY,
        "stopped": InstanceStatus.STOPPED,
        "busy": InstanceStatus.BUSY,
    }

    def _instance_status_setter(self, value: str) -> None:
        self._instance_status = self.instance_status_map.get(
            value, InstanceStatus.UNKNOWN
        )
        if self._instance_status == InstanceStatus.TERMINATED:
            self._cleaned = True

    def delete(self, graph: Graph) -> bool:
        if self.instance_status == InstanceStatus.TERMINATED.value:
            log.debug(
                (
                    f"AWS EC2 Instance {self.dname} in"
                    f" account {self.account(graph).dname}"
                    f" region {self.region(graph).name}"
                    " is already terminated"
                )
            )
            self.log("Instance is already terminated")
            return True
        ec2 = aws_resource(self, "ec2", graph)
        instance = ec2.Instance(self.id)
        instance.terminate()
        return True

    def update_tag(self, key, value) -> bool:
        ec2 = aws_resource(self, "ec2")
        instance = ec2.Instance(self.id)
        instance.create_tags(Tags=[{"Key": key, "Value": value}])
        return True

    def delete_tag(self, key) -> bool:
        ec2 = aws_resource(self, "ec2")
        instance = ec2.Instance(self.id)
        instance.delete_tags(Tags=[{"Key": key}])
        return True


AWSEC2Instance.instance_status = property(
    AWSEC2Instance._instance_status_getter, AWSEC2Instance._instance_status_setter
)


@dataclass(eq=False)
class AWSEC2KeyPair(AWSResource, BaseKeyPair):
    kind: ClassVar[str] = "aws_ec2_keypair"
    successor_kinds: ClassVar[Dict[str, List[str]]] = {
        "default": [],
        "delete": ["aws_ec2_instance"],
    }

    def delete(self, graph: Graph) -> bool:
        ec2 = aws_client(self, "ec2", graph)
        ec2.delete_key_pair(KeyName=self.name)
        return True

    def update_tag(self, key, value) -> bool:
        ec2 = aws_client(self, "ec2")
        ec2.create_tags(Resources=[self.id], Tags=[{"Key": key, "Value": value}])
        return True

    def delete_tag(self, key) -> bool:
        ec2 = aws_client(self, "ec2")
        ec2.delete_tags(Resources=[self.id], Tags=[{"Key": key}])
        return True


@dataclass(eq=False)
class AWSEC2VolumeType(AWSResource, BaseVolumeType):
    kind: ClassVar[str] = "aws_ec2_volume_type"
    successor_kinds: ClassVar[Dict[str, List[str]]] = {
        "default": ["aws_ec2_volume"],
        "delete": [],
    }


@dataclass(eq=False)
class AWSEC2Volume(AWSResource, BaseVolume):
    kind: ClassVar[str] = "aws_ec2_volume"
    successor_kinds: ClassVar[Dict[str, List[str]]] = {
        "default": ["aws_ec2_snapshot"],
        "delete": ["aws_ec2_instance"],
    }

    volume_kms_key_id: Optional[str] = None
    volume_multi_attach_enabled: Optional[bool] = None
    volume_outpost_arn: Optional[str] = None
    volume_snapshot_id: Optional[str] = None

    volume_status_map: ClassVar[Dict[str, VolumeStatus]] = {
        "creating": VolumeStatus.BUSY,
        "available": VolumeStatus.AVAILABLE,
        "in-use": VolumeStatus.IN_USE,
        "deleting": VolumeStatus.BUSY,
        "deleted": VolumeStatus.DELETED,
        "error": VolumeStatus.ERROR,
        "busy": VolumeStatus.BUSY,
    }

    def _volume_status_setter(self, value: str) -> None:
        self._volume_status = self.volume_status_map.get(value, VolumeStatus.UNKNOWN)

    def delete(
        self,
        graph: Graph,
        snapshot_before_delete: bool = False,
        snapshot_timeout: int = 3600,
    ) -> bool:
        ec2 = aws_resource(self, "ec2", graph)
        volume = ec2.Volume(self.id)
        if snapshot_before_delete or self.snapshot_before_delete:
            log_msg = "Creating snapshot before deletion"
            self.log(log_msg)
            log.debug(f"{log_msg} of {self.kind} {self.dname}")
            snapshot = volume.create_snapshot(
                Description=f"resoto created snapshot for volume {self.id}",
                TagSpecifications=[
                    {
                        "ResourceType": "snapshot",
                        "Tags": [
                            {"Key": "Name", "Value": f"CK snap of {self.id}"},
                            {"Key": "owner", "Value": "resoto"},
                        ],
                    },
                ],
            )
            start_utime = time.time()
            while snapshot.state == "pending":
                if time.time() > start_utime + snapshot_timeout:
                    raise TimeoutError(
                        (
                            f"AWS EC2 Volume Snapshot {self.dname} tag update timed out after "
                            f"{snapshot_timeout} seconds with status {snapshot.state} ({snapshot.state_message})"
                        )
                    )
                time.sleep(10)
                log.debug(
                    (
                        f"Waiting for snapshot {snapshot.id} to finish before deletion of "
                        f"{self.kind} {self.dname} - progress {snapshot.progress}"
                    )
                )
                snapshot = ec2.Snapshot(snapshot.id)
            if snapshot.state != "completed":
                log_msg = f"Failed to create snapshot - status {snapshot.state} ({snapshot.state_message})"
                self.log(log_msg)
                log.error(
                    (
                        f"{log_msg} for {self.kind} {self.dname} in "
                        f"account {self.account(graph).dname} region {self.region(graph).name}"
                    )
                )
                return False
        volume.delete()
        return True

    def update_tag(self, key, value) -> bool:
        ec2 = aws_resource(self, "ec2")
        volume = ec2.Volume(self.id)
        volume.create_tags(Tags=[{"Key": key, "Value": value}])
        return True

    def delete_tag(self, key) -> bool:
        ec2 = aws_client(self, "ec2")
        ec2.delete_tags(Resources=[self.id], Tags=[{"Key": key}])
        return True


AWSEC2Volume.volume_status = property(
    AWSEC2Volume._volume_status_getter, AWSEC2Volume._volume_status_setter
)


@dataclass(eq=False)
class AWSEC2Snapshot(AWSResource, BaseSnapshot):
    kind: ClassVar[str] = "aws_ec2_snapshot"

    def delete(self, graph: Graph) -> bool:
        ec2 = aws_resource(self, "ec2", graph)
        snapshot = ec2.Snapshot(self.id)
        snapshot.delete()
        return True

    def update_tag(self, key, value) -> bool:
        ec2 = aws_client(self, "ec2")
        ec2.create_tags(Resources=[self.id], Tags=[{"Key": key, "Value": value}])
        return True

    def delete_tag(self, key) -> bool:
        ec2 = aws_client(self, "ec2")
        ec2.delete_tags(Resources=[self.id], Tags=[{"Key": key}])
        return True


@dataclass(eq=False)
class AWSEC2Subnet(AWSResource, BaseSubnet):
    kind: ClassVar[str] = "aws_ec2_subnet"
    successor_kinds: ClassVar[Dict[str, List[str]]] = {
        "default": [
            "aws_vpc_endpoint",
            "aws_rds_instance",
            "aws_elb",
            "aws_ec2_network_interface",
            "aws_ec2_network_acl",
            "aws_ec2_nat_gateway",
            "aws_alb",
        ],
        "delete": [
            "aws_vpc_endpoint",
            "aws_rds_instance",
            "aws_elb",
            "aws_ec2_network_interface",
            "aws_alb",
        ],
    }

    def delete(self, graph: Graph) -> bool:
        ec2 = aws_resource(self, "ec2", graph)
        subnet = ec2.Subnet(self.id)
        subnet.delete()
        return True

    def update_tag(self, key, value) -> bool:
        ec2 = aws_client(self, "ec2")
        ec2.create_tags(Resources=[self.id], Tags=[{"Key": key, "Value": value}])
        return True

    def delete_tag(self, key) -> bool:
        ec2 = aws_client(self, "ec2")
        ec2.delete_tags(Resources=[self.id], Tags=[{"Key": key}])
        return True


@dataclass(eq=False)
class AWSEC2ElasticIP(AWSResource, BaseIPAddress):
    kind: ClassVar[str] = "aws_ec2_elastic_ip"
    successor_kinds: ClassVar[Dict[str, List[str]]] = {
        "default": [],
        "delete": ["aws_ec2_network_interface", "aws_ec2_instance"],
    }

    instance_id: Optional[str] = None
    public_ip: Optional[str] = None
    allocation_id: Optional[str] = None
    association_id: Optional[str] = None
    domain: Optional[str] = None
    network_interface_id: Optional[str] = None
    network_interface_owner_id: Optional[str] = None
    private_ip_address: Optional[str] = None

    def pre_delete(self, graph: Graph) -> bool:
        if self.association_id is not None:
            ec2 = aws_client(self, "ec2", graph=graph)
            ec2.disassociate_address(AssociationId=self.association_id)
        else:
            log.debug(f"No association for {self.rtdname}")
        return True

    def delete(self, graph: Graph) -> bool:
        ec2 = aws_client(self, "ec2", graph=graph)
        ec2.release_address(AllocationId=self.allocation_id)
        return True

    def update_tag(self, key, value) -> bool:
        ec2 = aws_client(self, "ec2")
        ec2.create_tags(Resources=[self.id], Tags=[{"Key": key, "Value": value}])
        return True

    def delete_tag(self, key) -> bool:
        ec2 = aws_client(self, "ec2")
        ec2.delete_tags(Resources=[self.id], Tags=[{"Key": key}])
        return True


@dataclass(eq=False)
class AWSVPC(AWSResource, BaseNetwork):
    kind: ClassVar[str] = "aws_vpc"
    successor_kinds: ClassVar[Dict[str, List[str]]] = {
        "default": [
            "aws_vpc_peering_connection",
            "aws_vpc_endpoint",
            "aws_rds_instance",
            "aws_elb",
            "aws_ec2_subnet",
            "aws_ec2_security_group",
            "aws_ec2_route_table",
            "aws_ec2_network_interface",
            "aws_ec2_network_acl",
            "aws_ec2_nat_gateway",
            "aws_ec2_internet_gateway",
            "aws_alb_target_group",
        ],
        "delete": [
            "aws_vpc_peering_connection",
            "aws_vpc_endpoint",
            "aws_rds_instance",
            "aws_elb",
            "aws_ec2_subnet",
            "aws_ec2_security_group",
            "aws_ec2_route_table",
            "aws_ec2_network_interface",
            "aws_ec2_network_acl",
            "aws_ec2_nat_gateway",
            "aws_ec2_internet_gateway",
            "aws_alb_target_group",
        ],
    }
    is_default: bool = False

    def delete(self, graph: Graph) -> bool:
        if self.is_default:
            log_msg = (
                f"Not removing the default VPC {self.id} - aborting delete request"
            )
            log.debug(log_msg)
            self.log(log_msg)
            return False

        ec2 = aws_resource(self, "ec2", graph)
        vpc = ec2.Vpc(self.id)
        vpc.delete()
        return True

    def update_tag(self, key, value) -> bool:
        ec2 = aws_resource(self, "ec2")
        vpc = ec2.Vpc(self.id)
        vpc.create_tags(Tags=[{"Key": key, "Value": value}])
        return True

    def delete_tag(self, key) -> bool:
        ec2 = aws_client(self, "ec2")
        ec2.delete_tags(Resources=[self.id], Tags=[{"Key": key}])
        return True


@dataclass(eq=False)
class AWSVPCQuota(AWSResource, BaseNetworkQuota):
    kind: ClassVar[str] = "aws_vpc_quota"
    successor_kinds: ClassVar[Dict[str, List[str]]] = {
        "default": ["aws_vpc"],
        "delete": [],
    }


@dataclass(eq=False)
class AWSS3Bucket(AWSResource, BaseBucket):
    kind: ClassVar[str] = "aws_s3_bucket"

    def delete(self, graph: Graph) -> bool:
        s3 = aws_resource(self, "s3", graph)
        bucket = s3.Bucket(self.name)
        bucket.objects.delete()
        bucket.delete()
        return True


@dataclass(eq=False)
class AWSS3BucketQuota(AWSResource, BaseBucketQuota):
    kind: ClassVar[str] = "aws_s3_bucket_quota"
    successor_kinds: ClassVar[Dict[str, List[str]]] = {
        "default": ["aws_s3_bucket"],
        "delete": [],
    }


@dataclass(eq=False)
class AWSELB(AWSResource, BaseLoadBalancer):
    kind: ClassVar[str] = "aws_elb"
    successor_kinds: ClassVar[Dict[str, List[str]]] = {
        "default": ["aws_ec2_instance"],
        "delete": [],
    }

    def delete(self, graph: Graph) -> bool:
        client = aws_client(self, "elb", graph)
        _ = client.delete_load_balancer(LoadBalancerName=self.name)
        # todo: parse result
        return True

    def update_tag(self, key, value) -> bool:
        client = aws_client(self, "elb")
        client.add_tags(
            LoadBalancerNames=[self.name], Tags=[{"Key": key, "Value": value}]
        )
        return True

    def delete_tag(self, key) -> bool:
        client = aws_client(self, "elb")
        client.remove_tags(LoadBalancerNames=[self.name], Tags=[{"Key": key}])
        return True


@dataclass(eq=False)
class AWSALB(AWSResource, BaseLoadBalancer):
    kind: ClassVar[str] = "aws_alb"
    successor_kinds: ClassVar[Dict[str, List[str]]] = {
        "default": ["aws_iam_server_certificate", "aws_alb_target_group"],
        "delete": [],
    }

    def delete(self, graph: Graph) -> bool:
        client = aws_client(self, "elbv2", graph)
        _ = client.delete_load_balancer(LoadBalancerArn=self.arn)
        # todo: block until loadbalancer is gone
        return True

    def update_tag(self, key, value) -> bool:
        client = aws_client(self, "elbv2")
        client.add_tags(ResourceArns=[self.arn], Tags=[{"Key": key, "Value": value}])
        return True

    def delete_tag(self, key) -> bool:
        client = aws_client(self, "elbv2")
        client.remove_tags(ResourceArns=[self.arn], TagKeys=[key])
        return True


@dataclass(eq=False)
class AWSALBTargetGroup(AWSResource, BaseResource):
    kind: ClassVar[str] = "aws_alb_target_group"
    successor_kinds: ClassVar[Dict[str, List[str]]] = {
        "default": ["aws_ec2_instance"],
        "delete": ["aws_alb"],
    }

    target_type: str = ""

    def delete(self, graph: Graph) -> bool:
        client = aws_client(self, "elbv2", graph)
        _ = client.delete_target_group(TargetGroupArn=self.arn)
        # todo: parse result
        return True

    def update_tag(self, key, value) -> bool:
        client = aws_client(self, "elbv2")
        client.add_tags(ResourceArns=[self.arn], Tags=[{"Key": key, "Value": value}])
        return True

    def delete_tag(self, key) -> bool:
        client = aws_client(self, "elbv2")
        client.remove_tags(ResourceArns=[self.arn], TagKeys=[key])
        return True


@dataclass(eq=False)
class AWSELBQuota(AWSResource, BaseLoadBalancerQuota):
    kind: ClassVar[str] = "aws_elb_quota"
    successor_kinds: ClassVar[Dict[str, List[str]]] = {
        "default": ["aws_elb"],
        "delete": [],
    }


@dataclass(eq=False)
class AWSALBQuota(AWSResource, BaseLoadBalancerQuota):
    kind: ClassVar[str] = "aws_alb_quota"
    successor_kinds: ClassVar[Dict[str, List[str]]] = {
        "default": ["aws_alb"],
        "delete": [],
    }


@dataclass(eq=False)
class AWSEC2InternetGateway(AWSResource, BaseGateway):
    kind: ClassVar[str] = "aws_ec2_internet_gateway"

    def pre_delete(self, graph: Graph) -> bool:
        ec2 = aws_resource(self, "ec2", graph)
        internet_gateway = ec2.InternetGateway(self.id)
        for predecessor in self.predecessors(graph, edge_type=EdgeType.delete):
            if isinstance(predecessor, AWSVPC):
                log_msg = f"Detaching {predecessor.kind} {predecessor.dname}"
                self.log(log_msg)
                log.debug(f"{log_msg} for deletion of {self.kind} {self.dname}")
                internet_gateway.detach_from_vpc(VpcId=predecessor.id)
        return True

    def delete(self, graph: Graph) -> bool:
        ec2 = aws_resource(self, "ec2", graph)
        internet_gateway = ec2.InternetGateway(self.id)
        internet_gateway.delete()
        return True

    def update_tag(self, key, value) -> bool:
        ec2 = aws_client(self, "ec2")
        ec2.create_tags(Resources=[self.id], Tags=[{"Key": key, "Value": value}])
        return True

    def delete_tag(self, key) -> bool:
        ec2 = aws_client(self, "ec2")
        ec2.delete_tags(Resources=[self.id], Tags=[{"Key": key}])
        return True


@dataclass(eq=False)
class AWSEC2NATGateway(AWSResource, BaseGateway):
    kind: ClassVar[str] = "aws_ec2_nat_gateway"
    successor_kinds: ClassVar[Dict[str, List[str]]] = {
        "default": ["aws_ec2_network_interface"],
        "delete": [],
    }

    nat_gateway_status: str = ""

    def delete(self, graph: Graph) -> bool:
        ec2 = aws_client(self, "ec2", graph)
        ec2.delete_nat_gateway(NatGatewayId=self.id)
        return True

    def update_tag(self, key, value) -> bool:
        ec2 = aws_client(self, "ec2")
        ec2.create_tags(Resources=[self.id], Tags=[{"Key": key, "Value": value}])
        return True

    def delete_tag(self, key) -> bool:
        ec2 = aws_client(self, "ec2")
        ec2.delete_tags(Resources=[self.id], Tags=[{"Key": key}])
        return True


@dataclass(eq=False)
class AWSEC2InternetGatewayQuota(AWSResource, BaseGatewayQuota):
    kind: ClassVar[str] = "aws_ec2_internet_gateway_quota"
    successor_kinds: ClassVar[Dict[str, List[str]]] = {
        "default": ["aws_ec2_internet_gateway"],
        "delete": [],
    }


@dataclass(eq=False)
class AWSEC2SecurityGroup(AWSResource, BaseSecurityGroup):
    kind: ClassVar[str] = "aws_ec2_security_group"
    successor_kinds: ClassVar[Dict[str, List[str]]] = {
        "default": [
            "aws_vpc_endpoint",
            "aws_rds_instance",
            "aws_elb",
            "aws_ec2_network_interface",
        ],
        "delete": ["aws_vpc_endpoint", "aws_rds_instance"],
    }

    def pre_delete(self, graph: Graph) -> bool:
        ec2 = aws_resource(self, "ec2", graph)
        security_group = ec2.SecurityGroup(self.id)
        remove_ingress = []
        remove_egress = []

        for permission in security_group.ip_permissions:
            if (
                "UserIdGroupPairs" in permission
                and len(permission["UserIdGroupPairs"]) > 0
            ):
                p = copy.deepcopy(permission)
                remove_ingress.append(p)
                log.debug(
                    f"Adding incoming permission {p} of {self.kind} {self.dname} to removal list"
                )

        for permission in security_group.ip_permissions_egress:
            if (
                "UserIdGroupPairs" in permission
                and len(permission["UserIdGroupPairs"]) > 0
            ):
                p = copy.deepcopy(permission)
                remove_egress.append(p)
                log.debug(
                    f"Adding outgoing permission {p} of {self.kind} {self.dname} to removal list"
                )

        if len(remove_ingress) > 0:
            security_group.revoke_ingress(IpPermissions=remove_ingress)

        if len(remove_egress) > 0:
            security_group.revoke_egress(IpPermissions=remove_egress)

        return True

    def delete(self, graph: Graph) -> bool:
        ec2 = aws_resource(self, "ec2", graph)
        security_group = ec2.SecurityGroup(self.id)
        security_group.delete()
        return True

    def update_tag(self, key, value) -> bool:
        ec2 = aws_client(self, "ec2")
        ec2.create_tags(Resources=[self.id], Tags=[{"Key": key, "Value": value}])
        return True

    def delete_tag(self, key) -> bool:
        ec2 = aws_client(self, "ec2")
        ec2.delete_tags(Resources=[self.id], Tags=[{"Key": key}])
        return True


@dataclass(eq=False)
class AWSEC2RouteTable(AWSResource, BaseRoutingTable):
    kind: ClassVar[str] = "aws_ec2_route_table"
    successor_kinds: ClassVar[Dict[str, List[str]]] = {
        "default": ["aws_vpc_endpoint"],
        "delete": ["aws_vpc_endpoint"],
    }

    def pre_delete(self, graph: Graph) -> bool:
        ec2 = aws_resource(self, "ec2", graph)
        rt = ec2.RouteTable(self.id)
        for rta in rt.associations:
            if not rta.main:
                log_msg = f"Deleting route table association {rta.id}"
                self.log(log_msg)
                log.debug(f"{log_msg} for cleanup of {self.kind} {self.dname}")
                rta.delete()
        return True

    def delete(self, graph: Graph) -> bool:
        ec2 = aws_resource(self, "ec2", graph)
        rt = ec2.RouteTable(self.id)
        rt.delete()
        return True

    def update_tag(self, key, value) -> bool:
        ec2 = aws_client(self, "ec2")
        ec2.create_tags(Resources=[self.id], Tags=[{"Key": key, "Value": value}])
        return True

    def delete_tag(self, key) -> bool:
        ec2 = aws_client(self, "ec2")
        ec2.delete_tags(Resources=[self.id], Tags=[{"Key": key}])
        return True


@dataclass(eq=False)
class AWSVPCPeeringConnection(AWSResource, BasePeeringConnection):
    kind: ClassVar[str] = "aws_vpc_peering_connection"
    vpc_peering_connection_status: str = ""

    def delete(self, graph: Graph) -> bool:
        ec2 = aws_client(self, "ec2", graph)
        ec2.delete_vpc_peering_connection(VpcPeeringConnectionId=self.id)
        return True

    def update_tag(self, key, value) -> bool:
        ec2 = aws_client(self, "ec2")
        ec2.create_tags(Resources=[self.id], Tags=[{"Key": key, "Value": value}])
        return True

    def delete_tag(self, key) -> bool:
        ec2 = aws_client(self, "ec2")
        ec2.delete_tags(Resources=[self.id], Tags=[{"Key": key}])
        return True


@dataclass(eq=False)
class AWSVPCEndpoint(AWSResource, BaseEndpoint):
    kind: ClassVar[str] = "aws_vpc_endpoint"
    successor_kinds: ClassVar[Dict[str, List[str]]] = {
        "default": ["aws_ec2_network_interface"],
        "delete": [],
    }
    vpc_endpoint_type: str = ""
    vpc_endpoint_status: str = ""

    def delete(self, graph: Graph) -> bool:
        ec2 = aws_client(self, "ec2", graph)
        ec2.delete_vpc_endpoints(VpcEndpointIds=[self.id])
        return True

    def update_tag(self, key, value) -> bool:
        ec2 = aws_client(self, "ec2")
        ec2.create_tags(Resources=[self.id], Tags=[{"Key": key, "Value": value}])
        return True

    def delete_tag(self, key) -> bool:
        ec2 = aws_client(self, "ec2")
        ec2.delete_tags(Resources=[self.id], Tags=[{"Key": key}])
        return True


@dataclass(eq=False)
class AWSEC2NetworkAcl(AWSResource, BaseNetworkAcl):
    kind: ClassVar[str] = "aws_ec2_network_acl"
    successor_kinds: ClassVar[Dict[str, List[str]]] = {
        "default": [],
        "delete": ["aws_ec2_subnet"],
    }
    is_default: bool = False

    def delete(self, graph: Graph) -> bool:
        ec2 = aws_client(self, "ec2", graph)
        ec2.delete_network_acl(NetworkAclId=self.id)
        return True

    def update_tag(self, key, value) -> bool:
        ec2 = aws_client(self, "ec2")
        ec2.create_tags(Resources=[self.id], Tags=[{"Key": key, "Value": value}])
        return True

    def delete_tag(self, key) -> bool:
        ec2 = aws_client(self, "ec2")
        ec2.delete_tags(Resources=[self.id], Tags=[{"Key": key}])
        return True


@dataclass(eq=False)
class AWSEC2NetworkInterface(AWSResource, BaseNetworkInterface):
    kind: ClassVar[str] = "aws_ec2_network_interface"
    successor_kinds: ClassVar[Dict[str, List[str]]] = {
        "default": ["aws_ec2_elastic_ip"],
        "delete": ["aws_vpc_endpoint", "aws_ec2_nat_gateway", "aws_ec2_instance"],
    }

    def delete(self, graph: Graph) -> bool:
        ec2 = aws_resource(self, "ec2", graph)
        network_interface = ec2.NetworkInterface(self.id)
        network_interface.delete()
        return True

    def update_tag(self, key, value) -> bool:
        ec2 = aws_client(self, "ec2")
        ec2.create_tags(Resources=[self.id], Tags=[{"Key": key, "Value": value}])
        return True

    def delete_tag(self, key) -> bool:
        ec2 = aws_client(self, "ec2")
        ec2.delete_tags(Resources=[self.id], Tags=[{"Key": key}])
        return True


@dataclass(eq=False)
class AWSRDSInstance(AWSResource, BaseDatabase):
    kind: ClassVar[str] = "aws_rds_instance"
    volume_kms_key_id: Optional[str] = None


@dataclass(eq=False)
class AWSIAMUser(AWSResource, BaseUser):
    kind: ClassVar[str] = "aws_iam_user"
    successor_kinds: ClassVar[Dict[str, List[str]]] = {
        "default": ["aws_iam_access_key"],
        "delete": ["aws_iam_policy"],
    }
    user_policies: List = field(default_factory=list)

    def pre_delete(self, graph: Graph) -> bool:
        iam = aws_resource(self, "iam", graph)
        user = iam.User(self.name)
        for successor in self.successors(graph, edge_type=EdgeType.delete):
            if isinstance(successor, AWSIAMPolicy):
                log_msg = f"Detaching {successor.rtdname}"
                self.log(log_msg)
                log.debug(f"{log_msg} for deletion of {self.rtdname}")
                user.detach_policy(PolicyArn=successor.arn)

        iam = aws_client(self, "iam", graph)
        for user_policy in self.user_policies:
            log_msg = f"Deleting inline policy {user_policy}"
            self.log(log_msg)
            log.debug(f"{log_msg} for deletion of {self.rtdname}")
            iam.delete_user_policy(
                UserName=self.name,
                PolicyName=user_policy,
            )
        return True

    def delete(self, graph: Graph) -> bool:
        iam = aws_resource(self, "iam", graph)
        user = iam.User(self.name)
        user.delete()
        return True


@dataclass(eq=False)
class AWSIAMGroup(AWSResource, BaseGroup):
    kind: ClassVar[str] = "aws_iam_group"
    successor_kinds: ClassVar[Dict[str, List[str]]] = {
        "default": ["aws_iam_user"],
        "delete": ["aws_iam_policy"],
    }
    group_policies: List = field(default_factory=list)

    def pre_delete(self, graph: Graph) -> bool:
        iam = aws_resource(self, "iam", graph)
        group = iam.Group(self.name)
        for successor in self.successors(graph, edge_type=EdgeType.delete):
            if isinstance(successor, AWSIAMPolicy):
                log_msg = f"Detaching {successor.rtdname}"
                self.log(log_msg)
                log.debug(f"{log_msg} for deletion of {self.rtdname}")
                group.detach_policy(PolicyArn=successor.arn)

        iam = aws_client(self, "iam", graph)
        for group_policy in self.group_policies:
            log_msg = f"Deleting inline policy {group_policy}"
            self.log(log_msg)
            log.debug(f"{log_msg} for deletion of {self.rtdname}")
            iam.delete_group_policy(
                GroupName=self.name,
                PolicyName=group_policy,
            )
        return True

    def delete(self, graph: Graph) -> bool:
        iam = aws_resource(self, "iam", graph)
        group = iam.Group(self.name)
        group.delete()
        return True


@dataclass(eq=False)
class AWSIAMRole(AWSResource, BaseRole):
    kind: ClassVar[str] = "aws_iam_role"
    successor_kinds: ClassVar[Dict[str, List[str]]] = {
        "default": ["aws_iam_policy", "aws_iam_instance_profile"],
        "delete": ["aws_iam_policy", "aws_iam_instance_profile", "aws_eks_cluster"],
    }

    role_policies: List = field(default_factory=list)

    def pre_delete(self, graph: Graph) -> bool:
        iam = aws_resource(self, "iam", graph)
        role = iam.Role(self.name)
        for successor in self.successors(graph, edge_type=EdgeType.delete):
            if isinstance(successor, AWSIAMPolicy):
                log_msg = f"Detaching {successor.rtdname}"
                self.log(log_msg)
                log.debug(f"{log_msg} for deletion of {self.rtdname}")
                role.detach_policy(PolicyArn=successor.arn)

        iam = aws_client(self, "iam", graph)
        for role_policy in self.role_policies:
            log_msg = f"Deleting inline policy {role_policy}"
            self.log(log_msg)
            log.debug(f"{log_msg} for deletion of {self.rtdname}")
            iam.delete_role_policy(
                RoleName=self.name,
                PolicyName=role_policy,
            )
        return True

    def delete(self, graph: Graph) -> bool:
        iam = aws_resource(self, "iam", graph)
        role = iam.Role(self.name)
        role.delete()
        return True


@dataclass(eq=False)
class AWSIAMPolicy(AWSResource, BasePolicy):
    kind: ClassVar[str] = "aws_iam_policy"
    successor_kinds: ClassVar[Dict[str, List[str]]] = {
        "default": ["aws_iam_user", "aws_iam_group"],
        "delete": [],
    }

    def delete(self, graph: Graph) -> bool:
        iam = aws_resource(self, "iam", graph)
        policy = iam.Policy(self.arn)
        policy.delete()
        return True


@dataclass(eq=False)
class AWSIAMInstanceProfile(AWSResource, BaseInstanceProfile):
    kind: ClassVar[str] = "aws_iam_instance_profile"
    successor_kinds: ClassVar[Dict[str, List[str]]] = {
        "default": ["aws_ec2_instance"],
        "delete": [],
    }

    def pre_delete(self, graph: Graph) -> bool:
        iam = aws_resource(self, "iam", graph)
        instance_profile = iam.InstanceProfile(self.name)
        for predecessor in self.predecessors(graph, edge_type=EdgeType.delete):
            if isinstance(predecessor, AWSIAMRole):
                log_msg = f"Detaching {predecessor.rtdname}"
                self.log(log_msg)
                log.debug(f"{log_msg} for deletion of {self.rtdname}")
                instance_profile.remove_role(RoleName=predecessor.name)
        return True

    def delete(self, graph: Graph) -> bool:
        iam = aws_resource(self, "iam", graph)
        instance_profile = iam.InstanceProfile(self.name)
        instance_profile.delete()
        return True


@dataclass(eq=False)
class AWSIAMAccessKey(AWSResource, BaseAccessKey):
    kind: ClassVar[str] = "aws_iam_access_key"

    user_name: Optional[str] = None
    access_key_last_used_region: Optional[str] = None
    access_key_last_used_service_name: Optional[str] = None

    def delete(self, graph: Graph) -> bool:
        iam = aws_resource(self, "iam", graph)
        access_key = iam.AccessKey(self.user_name, self.id)
        access_key.delete()
        return True


@dataclass(eq=False)
class AWSIAMServerCertificate(AWSResource, BaseCertificate):
    kind: ClassVar[str] = "aws_iam_server_certificate"
    successor_kinds: ClassVar[Dict[str, List[str]]] = {
        "default": [],
        "delete": ["aws_alb"],
    }
    path: str = None

    def delete(self, graph: Graph) -> bool:
        iam = aws_resource(self, "iam", graph)
        certificate = iam.ServerCertificate(self.name)
        certificate.delete()
        return True


@dataclass(eq=False)
class AWSIAMServerCertificateQuota(AWSResource, BaseCertificateQuota):
    kind: ClassVar[str] = "aws_iam_server_certificate_quota"
    successor_kinds: ClassVar[Dict[str, List[str]]] = {
        "default": ["aws_iam_server_certificate"],
        "delete": [],
    }


@dataclass(eq=False)
class AWSCloudFormationStack(AWSResource, BaseStack):
    kind: ClassVar[str] = "aws_cloudformation_stack"

    def delete(self, graph: Graph) -> bool:
        cf = aws_resource(self, "cloudformation", graph)
        stack = cf.Stack(self.name)
        stack.delete()
        return True

    class ModificationMode(Enum):
        """Defines Tag modification mode"""

        UPDATE = auto()
        DELETE = auto()

    def update_tag(self, key, value) -> bool:
        return self._modify_tag(
            key, value, mode=AWSCloudFormationStack.ModificationMode.UPDATE
        )

    def delete_tag(self, key) -> bool:
        return self._modify_tag(
            key, mode=AWSCloudFormationStack.ModificationMode.DELETE
        )

    def _modify_tag(self, key, value=None, mode=None, wait=False) -> bool:
        tags = dict(self.tags)
        if mode == AWSCloudFormationStack.ModificationMode.DELETE:
            if not self.tags.get(key):
                raise KeyError(key)
            del tags[key]
        elif mode == AWSCloudFormationStack.ModificationMode.UPDATE:
            if self.tags.get(key) == value:
                return True
            tags.update({key: value})
        else:
            return False

        cf = aws_resource(self, "cloudformation")
        stack = cf.Stack(self.name)
        stack = self.wait_for_completion(stack, cf)
        response = stack.update(
            Capabilities=["CAPABILITY_NAMED_IAM"],
            UsePreviousTemplate=True,
            Tags=[{"Key": label, "Value": value} for label, value in tags.items()],
            Parameters=[
                {"ParameterKey": parameter, "UsePreviousValue": True}
                for parameter in self.stack_parameters.keys()
            ],
        )
        if response.get("ResponseMetadata", {}).get("HTTPStatusCode", 0) != 200:
            raise RuntimeError(
                f"Error updating AWS Cloudformation Stack {self.dname} for {mode.name} of tag {key}"
            )
        if wait:
            self.wait_for_completion(stack, cf)
        self.tags = tags
        return True

    def wait_for_completion(self, stack, cloudformation_resource, timeout=300):
        start_utime = time.time()
        while stack.stack_status.endswith("_IN_PROGRESS"):
            if time.time() > start_utime + timeout:
                raise TimeoutError(
                    (
                        f"AWS Cloudformation Stack {self.dname} tag update timed out "
                        f"after {timeout} seconds with status {stack.stack_status}"
                    )
                )
            time.sleep(5)
            stack = cloudformation_resource.Stack(stack.name)
        return stack


@dataclass(eq=False)
class AWSEKSCluster(AWSResource, BaseResource):
    kind: ClassVar[str] = "aws_eks_cluster"
    successor_kinds: ClassVar[Dict[str, List[str]]] = {
        "default": ["aws_iam_role", "aws_eks_nodegroup"],
        "delete": ["aws_eks_nodegroup"],
    }
    cluster_status: str = ""
    cluster_endpoint: str = ""

    def delete(self, graph: Graph) -> bool:
        eks = aws_client(self, "eks", graph)
        eks.delete_cluster(name=self.name)
        return True

    def update_tag(self, key, value) -> bool:
        eks = aws_client(self, "eks")
        eks.tag_resource(resourceArn=self.arn, tags={key: value})
        return True

    def delete_tag(self, key) -> bool:
        eks = aws_client(self, "eks")
        eks.untag_resource(resourceArn=self.arn, tagKeys=[key])
        return True


@dataclass(eq=False)
class AWSEKSNodegroup(AWSResource, BaseResource):
    kind: ClassVar[str] = "aws_eks_nodegroup"
    successor_kinds: ClassVar[Dict[str, List[str]]] = {
        "default": ["aws_autoscaling_group"],
        "delete": [],
    }

    cluster_name: str = ""
    nodegroup_status: str = ""

    def delete(self, graph: Graph) -> bool:
        eks = aws_client(self, "eks", graph)
        eks.delete_nodegroup(clusterName=self.cluster_name, nodegroupName=self.name)
        return True

    def update_tag(self, key, value) -> bool:
        eks = aws_client(self, "eks")
        eks.tag_resource(resourceArn=self.arn, tags={key: value})
        return True

    def delete_tag(self, key) -> bool:
        eks = aws_client(self, "eks")
        eks.untag_resource(resourceArn=self.arn, tagKeys=[key])
        return True


@dataclass(eq=False)
class AWSAutoScalingGroup(AWSResource, BaseAutoScalingGroup):
    kind: ClassVar[str] = "aws_autoscaling_group"
    successor_kinds: ClassVar[Dict[str, List[str]]] = {
        "default": ["aws_ec2_instance"],
        "delete": ["aws_eks_nodegroup"],
    }

    def delete(self, graph: Graph, force_delete: bool = True) -> bool:
        client = aws_client(self, "autoscaling", graph)
        client.delete_auto_scaling_group(
            AutoScalingGroupName=self.name, ForceDelete=force_delete
        )
        return True

    def update_tag(self, key, value) -> bool:
        client = aws_client(self, "autoscaling")
        client.create_or_update_tags(
            Tags=[
                {
                    "ResourceId": self.name,
                    "ResourceType": "auto-scaling-group",
                    "Key": key,
                    "Value": value,
                    "PropagateAtLaunch": True,
                }
            ]
        )
        return True

    def delete_tag(self, key) -> bool:
        client = aws_client(self, "autoscaling")
        client.delete_tags(
            Tags=[
                {
                    "ResourceId": self.name,
                    "ResourceType": "auto-scaling-group",
                    "Key": key,
                    "Value": self.tags[key],
                    "PropagateAtLaunch": True,
                }
            ]
        )
        return True


@dataclass(eq=False)
class AWSCloudwatchAlarm(AWSResource, BaseResource):
    kind: ClassVar[str] = "aws_cloudwatch_alarm"
    successor_kinds: ClassVar[Dict[str, List[str]]] = {
        "default": [],
        "delete": ["aws_ec2_instance"],
    }

    actions_enabled: bool = False
    alarm_description: Optional[str] = None
    alarm_actions: Optional[List] = field(default_factory=list)
    comparison_operator: Optional[str] = None
    dimensions: Optional[List] = field(default_factory=list)
    evaluation_periods: Optional[int] = 0
    insufficient_data_actions: Optional[List] = field(default_factory=list)
    metric_name: Optional[str] = None
    namespace: Optional[str] = None
    ok_actions: Optional[List] = field(default_factory=list)
    period: Optional[int] = 0
    state_value: Optional[str] = None
    statistic: Optional[str] = None
    threshold: Optional[float] = 0.0

    def delete(self, graph: Graph) -> bool:
        cloudwatch = aws_resource(self, "cloudwatch", graph)
        alarm = cloudwatch.Alarm(self.name)
        alarm.delete()
        return True

    def update_tag(self, key, value) -> bool:
        client = aws_client(self, "cloudwatch")
        client.tag_resource(ResourceARN=self.arn, Tags=[{"Key": key, "Value": value}])
        return True

    def delete_tag(self, key) -> bool:
        client = aws_client(self, "cloudwatch")
        client.untag_resource(ResourceARN=self.arn, TagKeys=[key])
        return True


@dataclass(eq=False)
class AWSCloudFormationStackSet(AWSResource, BaseResource):
    kind: ClassVar[str] = "aws_cloudformation_stack_set"
    description: Optional[str] = None
    stack_set_status: Optional[str] = None
    stack_set_parameters: Dict = field(default_factory=dict)
    stack_set_capabilities: Optional[List[str]] = field(default_factory=list)
    stack_set_administration_role_arn: Optional[str] = None
    stack_set_execution_role_name: Optional[str] = None
    stack_set_drift_detection_details: Optional[Dict[str, Any]] = field(
        default_factory=dict
    )
    stack_set_last_drift_check_timestamp: Optional[datetime] = None
    stack_set_auto_deployment: Optional[Dict[str, bool]] = field(default_factory=dict)
    stack_set_permission_model: Optional[str] = None
    stack_set_organizational_unit_ids: Optional[List[str]] = field(default_factory=list)
    stack_set_managed_execution_active: Optional[bool] = None

    def delete(self, graph: Graph) -> bool:
        cf = aws_client(self, "cloudformation", graph)
        cf.delete_stack_set(StackSetName=self.name)
        return True

    class ModificationMode(Enum):
        """Defines Tag modification mode"""

        UPDATE = auto()
        DELETE = auto()

    def update_tag(self, key, value) -> bool:
        return self._modify_tag(
            key, value, mode=AWSCloudFormationStackSet.ModificationMode.UPDATE
        )

    def delete_tag(self, key) -> bool:
        return self._modify_tag(
            key, mode=AWSCloudFormationStackSet.ModificationMode.DELETE
        )

    def _modify_tag(self, key, value=None, mode=None) -> bool:
        tags = dict(self.tags)
        if mode == AWSCloudFormationStackSet.ModificationMode.DELETE:
            if not self.tags.get(key):
                raise KeyError(key)
            del tags[key]
        elif mode == AWSCloudFormationStackSet.ModificationMode.UPDATE:
            if self.tags.get(key) == value:
                return True
            tags.update({key: value})
        else:
            return False

        cf = aws_client(self, "cloudformation")
        response = cf.update_stack_set(
            StackSetName=self.name,
            Capabilities=["CAPABILITY_NAMED_IAM"],
            UsePreviousTemplate=True,
            Tags=[{"Key": label, "Value": value} for label, value in tags.items()],
            Parameters=[
                {"ParameterKey": parameter, "UsePreviousValue": True}
                for parameter in self.stack_set_parameters.keys()
            ],
        )
        if response.get("ResponseMetadata", {}).get("HTTPStatusCode", 0) != 200:
            raise RuntimeError(
                "Error updating AWS Cloudformation Stack Set"
                f" {self.dname} for {mode.name} of tag {key}"
            )
        self.tags = tags
        return True
