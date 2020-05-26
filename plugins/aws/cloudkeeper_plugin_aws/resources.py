import time
import logging
from datetime import date
from enum import Enum, auto
from cloudkeeper.baseresources import *
from cloudkeeper.utils import make_valid_timestamp
from .utils import aws_session


default_ctime = make_valid_timestamp(date(2006, 3, 19))    # AWS public launch date
log = logging.getLogger('cloudkeeper.' + __name__)


# derived from https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-template-resource-type-ref.html
class AWSAccount(BaseAccount):
    resource_type = 'aws_account'

    def __init__(self, *args, role: str = None, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.role = role


class AWSRegion(BaseRegion):
    resource_type = 'aws_region'

    def __init__(self, *args, role: str = None, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.ctime = default_ctime


class AWSResource:
    def __init__(self, *args, arn: str = None, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.arn = arn


class AWSEC2InstanceType(AWSResource, BaseInstanceType):
    resource_type = "aws_ec2_instance_type"


class AWSEC2InstanceQuota(AWSResource, BaseInstanceQuota):
    resource_type = "aws_ec2_instance_quota"


class AWSEC2Instance(AWSResource, BaseInstance):
    resource_type = "aws_ec2_instance"

    def delete(self, account: AWSAccount, region: AWSRegion) -> bool:
        if self.instance_status == 'terminated':
            log.error(f'AWS EC2 Instance {self.id} in account {account.name} region {region.name} is already terminated')
            return False
        ec2 = aws_session(account.id, account.role).resource('ec2', region_name=region.id)
        instance = ec2.Instance(self.id)
        instance.terminate()
        return True

    def update_tag(self, key, value) -> bool:
        ec2 = aws_session(self.account().id, self.account().role).resource('ec2', region_name=self.region().id)
        instance = ec2.Instance(self.id)
        instance.create_tags(Tags=[{'Key': key, 'Value': value}])
        return True

    def delete_tag(self, key) -> bool:
        ec2 = aws_session(self.account().id, self.account().role).resource('ec2', region_name=self.region().id)
        instance = ec2.Instance(self.id)
        instance.delete_tags(Tags=[{'Key': key}])
        return True


class AWSEC2KeyPair(AWSResource, BaseKeyPair):
    resource_type = "aws_ec2_keypair"

    def delete(self, account: AWSAccount, region: AWSRegion) -> bool:
        ec2 = aws_session(account.id, account.role).client('ec2', region_name=region.id)
        ec2.delete_key_pair(KeyName=self.name)
        return True

    def update_tag(self, key, value) -> bool:
        ec2 = aws_session(self.account().id, self.account().role).client('ec2', region_name=self.region().id)
        ec2.create_tags(Resources=[self.id], Tags=[{'Key': key, 'Value': value}])
        return True

    def delete_tag(self, key) -> bool:
        ec2 = aws_session(self.account().id, self.account().role).client('ec2', region_name=self.region().id)
        ec2.delete_tags(
            Resources=[self.id],
            Tags=[{'Key': key}]
        )
        return True


class AWSEC2VolumeType(AWSResource, BaseVolumeType):
    resource_type = "aws_ec2_volume_type"


class AWSEC2Volume(AWSResource, BaseVolume):
    resource_type = "aws_ec2_volume"

    def delete(self, account: AWSAccount, region: AWSRegion) -> bool:
        ec2 = aws_session(account.id, account.role).resource('ec2', region_name=region.id)
        volume = ec2.Volume(self.id)
        volume.delete()
        return True

    def update_tag(self, key, value) -> bool:
        ec2 = aws_session(self.account().id, self.account().role).resource('ec2', region_name=self.region().id)
        volume = ec2.Volume(self.id)
        volume.create_tags(Tags=[{'Key': key, 'Value': value}])
        return True

    def delete_tag(self, key) -> bool:
        ec2 = aws_session(self.account().id, self.account().role).client('ec2', region_name=self.region().id)
        ec2.delete_tags(
            Resources=[self.id],
            Tags=[{'Key': key}]
        )
        return True


class AWSEC2Subnet(AWSResource, BaseSubnet):
    resource_type = "aws_ec2_subnet"

    def delete(self, account: AWSAccount, region: AWSRegion) -> bool:
        ec2 = aws_session(account.id, account.role).resource('ec2', region_name=region.id)
        subnet = ec2.Subnet(self.id)
        subnet.delete()
        return True

    def update_tag(self, key, value) -> bool:
        ec2 = aws_session(self.account().id, self.account().role).client('ec2', region_name=self.region().id)
        ec2.create_tags(Resources=[self.id], Tags=[{'Key': key, 'Value': value}])
        return True

    def delete_tag(self, key) -> bool:
        ec2 = aws_session(self.account().id, self.account().role).client('ec2', region_name=self.region().id)
        ec2.delete_tags(
            Resources=[self.id],
            Tags=[{'Key': key}]
        )
        return True


class AWSVPC(AWSResource, BaseNetwork):
    resource_type = "aws_vpc"

    def __init__(self, *args, is_default: bool = False, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.is_default = is_default

    def delete(self, account: AWSAccount, region: AWSRegion) -> bool:
        if self.is_default:
            log_msg = f'Not removing the default VPC {self.id} - aborting delete request'
            log.debug(log_msg)
            self.log(log_msg)
            return False

        ec2 = aws_session(account.id, account.role).resource('ec2', region_name=region.id)
        vpc = ec2.Vpc(self.id)
        vpc.delete()
        return True

    def update_tag(self, key, value) -> bool:
        ec2 = aws_session(self.account().id, self.account().role).resource('ec2', region_name=self.region().id)
        vpc = ec2.Vpc(self.id)
        vpc.create_tags(Tags=[{'Key': key, 'Value': value}])
        return True

    def delete_tag(self, key) -> bool:
        ec2 = aws_session(self.account().id, self.account().role).client('ec2', region_name=self.region().id)
        ec2.delete_tags(
            Resources=[self.id],
            Tags=[{'Key': key}]
        )
        return True


class AWSVPCQuota(AWSResource, BaseNetworkQuota):
    resource_type = "aws_vpc_quota"


class AWSS3Bucket(AWSResource, BaseBucket):
    resource_type = "aws_s3_bucket"

    def delete(self, account: AWSAccount, region: AWSRegion) -> bool:
        s3 = aws_session(account.id, account.role).resource('s3', region_name=region.id)
        bucket = s3.Bucket(self.name)
        bucket.objects.delete()
        bucket.delete()
        return True


class AWSS3BucketQuota(AWSResource, BaseBucketQuota):
    resource_type = "aws_s3_bucket_quota"


class AWSELB(AWSResource, BaseLoadBalancer):
    resource_type = "aws_elb"

    def delete(self, account: AWSAccount, region: AWSRegion) -> bool:
        client = aws_session(account.id, account.role).client('elb', region_name=region.id)
        _ = client.delete_load_balancer(LoadBalancerName=self.name)
        # todo: parse result
        return True

    def update_tag(self, key, value) -> bool:
        client = aws_session(self.account().id, self.account().role).client('elb', region_name=self.region().id)
        client.add_tags(
            LoadBalancerNames=[self.name],
            Tags=[{'Key': key, 'Value': value}]
        )
        return True

    def delete_tag(self, key) -> bool:
        client = aws_session(self.account().id, self.account().role).client('elb', region_name=self.region().id)
        client.remove_tags(
            LoadBalancerNames=[self.name],
            Tags=[{'Key': key}]
        )
        return True


class AWSALB(AWSResource, BaseLoadBalancer):
    resource_type = "aws_alb"

    def delete(self, account: AWSAccount, region: AWSRegion) -> bool:
        client = aws_session(account.id, account.role).client('elbv2', region_name=region.id)
        _ = client.delete_load_balancer(LoadBalancerArn=self.arn)
        # todo: block until loadbalancer is gone
        return True

    def update_tag(self, key, value) -> bool:
        client = aws_session(self.account().id, self.account().role).client('elbv2', region_name=self.region().id)
        client.add_tags(
            ResourceArns=[self.arn],
            Tags=[{'Key': key, 'Value': value}]
        )
        return True

    def delete_tag(self, key) -> bool:
        client = aws_session(self.account().id, self.account().role).client('elbv2', region_name=self.region().id)
        client.remove_tags(
            ResourceArns=[self.arn],
            TagKeys=[key]
        )
        return True


class AWSALBTargetGroup(AWSResource, BaseResource):
    resource_type = 'aws_alb_target_group'

    metrics_description = {
        'aws_alb_target_groups_total': {'help': 'Number of AWS ALB Target Groups', 'labels': ['cloud', 'account', 'region']},
        'cleaned_aws_alb_target_groups_total': {'help': 'Cleaned number of AWS ALB Target Groups', 'labels': ['cloud', 'account', 'region']},
    }

    def __init__(self, *args, role: str = None, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.target_type = ''

    def metrics(self, graph) -> Dict:
        self._metrics['aws_alb_target_groups_total'][(self.cloud(graph).name, self.account(graph).name, self.region(graph).name)] = 1
        if self._cleaned:
            self._metrics['cleaned_aws_alb_target_groups_total'][(self.cloud(graph).name, self.account(graph).name, self.region(graph).name)] = 1
        return self._metrics

    def delete(self, account: AWSAccount, region: AWSRegion) -> bool:
        client = aws_session(account.id, account.role).client('elbv2', region_name=region.id)
        _ = client.delete_target_group(TargetGroupArn=self.arn)
        # todo: parse result
        return True

    def update_tag(self, key, value) -> bool:
        client = aws_session(self.account().id, self.account().role).client('elbv2', region_name=self.region().id)
        client.add_tags(
            ResourceArns=[self.arn],
            Tags=[{'Key': key, 'Value': value}]
        )
        return True

    def delete_tag(self, key) -> bool:
        client = aws_session(self.account().id, self.account().role).client('elbv2', region_name=self.region().id)
        client.remove_tags(
            ResourceArns=[self.arn],
            TagKeys=[key]
        )
        return True


class AWSELBQuota(AWSResource, BaseLoadBalancerQuota):
    resource_type = "aws_elb_quota"


class AWSALBQuota(AWSResource, BaseLoadBalancerQuota):
    resource_type = "aws_alb_quota"


class AWSEC2InternetGateway(AWSResource, BaseGateway):
    resource_type = "aws_ec2_internet_gateway"

    def delete(self, account: AWSAccount, region: AWSRegion) -> bool:
        ec2 = aws_session(account.id, account.role).resource('ec2', region_name=region.id)
        internet_gateway = ec2.InternetGateway(self.id)
        internet_gateway.delete()
        return True

    def update_tag(self, key, value) -> bool:
        ec2 = aws_session(self.account().id, self.account().role).client('ec2', region_name=self.region().id)
        ec2.create_tags(Resources=[self.id], Tags=[{'Key': key, 'Value': value}])
        return True

    def delete_tag(self, key) -> bool:
        ec2 = aws_session(self.account().id, self.account().role).client('ec2', region_name=self.region().id)
        ec2.delete_tags(
            Resources=[self.id],
            Tags=[{'Key': key}]
        )
        return True


class AWSEC2NATGateway(AWSResource, BaseGateway):
    resource_type = "aws_ec2_nat_gateway"

    def delete(self, account: AWSAccount, region: AWSRegion) -> bool:
        ec2 = aws_session(account.id, account.role).client('ec2', region_name=region.id)
        ec2.delete_nat_gateway(NatGatewayId=self.id)
        return True

    def update_tag(self, key, value) -> bool:
        ec2 = aws_session(self.account().id, self.account().role).client('ec2', region_name=self.region().id)
        ec2.create_tags(Resources=[self.id], Tags=[{'Key': key, 'Value': value}])
        return True

    def delete_tag(self, key) -> bool:
        ec2 = aws_session(self.account().id, self.account().role).client('ec2', region_name=self.region().id)
        ec2.delete_tags(
            Resources=[self.id],
            Tags=[{'Key': key}]
        )
        return True


class AWSEC2InternetGatewayQuota(AWSResource, BaseGatewayQuota):
    resource_type = "aws_ec2_internet_gateway_quota"


class AWSEC2SecurityGroup(AWSResource, BaseSecurityGroup):
    resource_type = "aws_ec2_security_group"

    def delete(self, account: AWSAccount, region: AWSRegion) -> bool:
        ec2 = aws_session(account.id, account.role).resource('ec2', region_name=region.id)
        security_group = ec2.SecurityGroup(self.id)
        security_group.delete()
        return True

    def update_tag(self, key, value) -> bool:
        ec2 = aws_session(self.account().id, self.account().role).client('ec2', region_name=self.region().id)
        ec2.create_tags(Resources=[self.id], Tags=[{'Key': key, 'Value': value}])
        return True

    def delete_tag(self, key) -> bool:
        ec2 = aws_session(self.account().id, self.account().role).client('ec2', region_name=self.region().id)
        ec2.delete_tags(
            Resources=[self.id],
            Tags=[{'Key': key}]
        )
        return True


class AWSEC2RouteTable(AWSResource, BaseRoutingTable):
    resource_type = "aws_ec2_route_table"

    def delete(self, account: AWSAccount, region: AWSRegion) -> bool:
        ec2 = aws_session(account.id, account.role).client('ec2', region_name=region.id)
        ec2.delete_route_table(RouteTableId=self.id)
        return True

    def update_tag(self, key, value) -> bool:
        ec2 = aws_session(self.account().id, self.account().role).client('ec2', region_name=self.region().id)
        ec2.create_tags(Resources=[self.id], Tags=[{'Key': key, 'Value': value}])
        return True

    def delete_tag(self, key) -> bool:
        ec2 = aws_session(self.account().id, self.account().role).client('ec2', region_name=self.region().id)
        ec2.delete_tags(
            Resources=[self.id],
            Tags=[{'Key': key}]
        )
        return True

class AWSEC2NetworkAcl(AWSResource, BaseNetworkAcl):
    resource_type = "aws_ec2_network_acl"

    def __init__(self, *args, is_default: bool = False, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.is_default = is_default

    def delete(self, account: AWSAccount, region: AWSRegion) -> bool:
        ec2 = aws_session(account.id, account.role).client('ec2', region_name=region.id)
        ec2.delete_network_acl(NetworkAclId=self.id)
        return True

    def update_tag(self, key, value) -> bool:
        ec2 = aws_session(self.account().id, self.account().role).client('ec2', region_name=self.region().id)
        ec2.create_tags(Resources=[self.id], Tags=[{'Key': key, 'Value': value}])
        return True

    def delete_tag(self, key) -> bool:
        ec2 = aws_session(self.account().id, self.account().role).client('ec2', region_name=self.region().id)
        ec2.delete_tags(
            Resources=[self.id],
            Tags=[{'Key': key}]
        )
        return True


class AWSEC2NetworkInterface(AWSResource, BaseNetworkInterface):
    resource_type = "aws_ec2_network_interface"

    def delete(self, account: AWSAccount, region: AWSRegion) -> bool:
        ec2 = aws_session(account.id, account.role).resource('ec2', region_name=region.id)
        network_interface = ec2.NetworkInterface(self.id)
        network_interface.delete()
        return True

    def update_tag(self, key, value) -> bool:
        ec2 = aws_session(self.account().id, self.account().role).client('ec2', region_name=self.region().id)
        ec2.create_tags(Resources=[self.id], Tags=[{'Key': key, 'Value': value}])
        return True

    def delete_tag(self, key) -> bool:
        ec2 = aws_session(self.account().id, self.account().role).client('ec2', region_name=self.region().id)
        ec2.delete_tags(
            Resources=[self.id],
            Tags=[{'Key': key}]
        )
        return True


class AWSRDSInstance(AWSResource, BaseDatabase):
    resource_type = "aws_rds_instance"


class AWSIAMUser(AWSResource, BaseUser):
    resource_type = "aws_iam_user"

    def delete(self, account: AWSAccount, region: AWSRegion) -> bool:
        iam = aws_session(account.id, account.role).resource('iam', region_name=region.id)
        user = iam.User(self.name)
        user.delete()
        return True


class AWSIAMGroup(AWSResource, BaseGroup):
    resource_type = "aws_iam_group"

    def delete(self, account: AWSAccount, region: AWSRegion) -> bool:
        iam = aws_session(account.id, account.role).resource('iam', region_name=region.id)
        group = iam.Group(self.name)
        group.delete()
        return True


class AWSIAMRole(AWSResource, BaseRole):
    resource_type = "aws_iam_role"

    def delete(self, account: AWSAccount, region: AWSRegion) -> bool:
        iam = aws_session(account.id, account.role).resource('iam', region_name=region.id)
        role = iam.Role(self.name)
        role.delete()
        return True


class AWSIAMPolicy(AWSResource, BasePolicy):
    resource_type = "aws_iam_policy"

    def delete(self, account: AWSAccount, region: AWSRegion) -> bool:
        iam = aws_session(account.id, account.role).resource('iam', region_name=region.id)
        policy = iam.Policy(self.arn)
        policy.delete()
        return True


class AWSIAMInstanceProfile(AWSResource, BaseInstanceProfile):
    resource_type = "aws_iam_instance_profile"

    def delete(self, account: AWSAccount, region: AWSRegion) -> bool:
        iam = aws_session(account.id, account.role).resource('iam', region_name=region.id)
        instance_profile = iam.InstanceProfile(self.name)
        instance_profile.delete()
        return True


class AWSIAMAccessKey(AWSResource, BaseAccessKey):
    resource_type = "aws_iam_access_key"

    def __init__(self, *args, user_name: str = None, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.user_name = user_name

    def delete(self, account: AWSAccount, region: AWSRegion) -> bool:
        iam = aws_session(account.id, account.role).resource('iam', region_name=region.id)
        access_key = iam.AccessKey(self.user_name, self.id)
        access_key.delete()
        return True


class AWSIAMServerCertificate(AWSResource, BaseCertificate):
    resource_type = "aws_iam_server_certificate"

    def __init__(self, *args, path: str = None, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.path = path

    def delete(self, account: AWSAccount, region: AWSRegion) -> bool:
        iam = aws_session(account.id, account.role).resource('iam', region_name=region.id)
        certificate = iam.ServerCertificate(self.name)
        certificate.delete()
        return True


class AWSIAMServerCertificateQuota(AWSResource, BaseCertificateQuota):
    resource_type = "aws_iam_server_certificate_quota"


class AWSCloudFormationStack(AWSResource, BaseStack):
    resource_type = "aws_cloudformation_stack"

    def delete(self, account, region) -> bool:
        cf = aws_session(account.id, account.role).resource('cloudformation', region_name=region.id)
        stack = cf.Stack(self.name)
        stack.delete()
        return True

    class ModificationMode(Enum):
        """Defines Tag modification mode
        """
        UPDATE = auto()
        DELETE = auto()

    def update_tag(self, key, value) -> bool:
        return self._modify_tag(key, value, mode=AWSCloudFormationStack.ModificationMode.UPDATE)

    def delete_tag(self, key) -> bool:
        return self._modify_tag(key, mode=AWSCloudFormationStack.ModificationMode.DELETE)

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

        cf = aws_session(self.account().id, self.account().role).resource('cloudformation', region_name=self.region().id)
        stack = cf.Stack(self.name)
        stack = self.wait_for_completion(stack, cf)
        response = stack.update(
            Capabilities=['CAPABILITY_NAMED_IAM'],
            UsePreviousTemplate=True,
            Tags=[{'Key': label, 'Value': value} for label, value in tags.items()],
            Parameters=[{'ParameterKey': parameter, 'UsePreviousValue': True} for parameter in self.stack_parameters.keys()]
        )
        if response.get('ResponseMetadata', {}).get('HTTPStatusCode', 0) != 200:
            raise RuntimeError(f'Error updating AWS Cloudformation Stack {self.name} for {mode.name} of tag {key}')
        if wait:
            self.wait_for_completion(stack, cf)
        self.tags = tags
        return True

    def wait_for_completion(self, stack, cloudformation_resource, timeout=300):
        start_utime = time.time()
        while stack.stack_status.endswith('_IN_PROGRESS'):
            if time.time() > start_utime + timeout:
                raise TimeoutError(f'Stack {stack.name} tag update timed out after {timeout} seconds with status {stack.stack_status}')
            time.sleep(5)
            stack = cloudformation_resource.Stack(stack.name)
        return stack


class AWSEKSCluster(AWSResource, BaseResource):
    resource_type = 'aws_eks_cluster'

    metrics_description = {
        'aws_eks_clusters_total': {'help': 'Number of AWS EKS Clusters', 'labels': ['cloud', 'account', 'region']},
        'cleaned_aws_eks_clusters_total': {'help': 'Cleaned number of AWS EKS Clusters', 'labels': ['cloud', 'account', 'region']},
    }

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.cluster_status = ''
        self.cluster_endpoint = ''

    def metrics(self, graph) -> Dict:
        self._metrics['aws_eks_clusters_total'][(self.cloud(graph).name, self.account(graph).name, self.region(graph).name)] = 1
        if self._cleaned:
            self._metrics['cleaned_aws_eks_clusters_total'][(self.cloud(graph).name, self.account(graph).name, self.region(graph).name)] = 1
        return self._metrics

    def delete(self, account: AWSAccount, region: AWSRegion) -> bool:
        eks = aws_session(account.id, account.role).client('eks', region_name=region.id)
        eks.delete_cluster(name=self.name)
        return True

    def update_tag(self, key, value) -> bool:
        eks = aws_session(self.account().id, self.account().role).client('eks', region_name=self.region().id)
        eks.tag_resource(
            resourceArn=self.arn,
            tags={key: value}
        )
        return True

    def delete_tag(self, key) -> bool:
        eks = aws_session(self.account().id, self.account().role).client('eks', region_name=self.region().id)
        eks.untag_resource(
            resourceArn=self.arn,
            tagKeys=[key]
        )
        return True


class AWSEKSNodegroup(AWSResource, BaseResource):
    resource_type = 'aws_eks_nodegroup'

    metrics_description = {
        'aws_eks_nodegroups_total': {'help': 'Number of AWS EKS Nodegroups', 'labels': ['cloud', 'account', 'region']},
        'cleaned_aws_eks_nodegroups_total': {'help': 'Cleaned number of AWS EKS Nodegroups', 'labels': ['cloud', 'account', 'region']},
    }

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.cluster_name = ''
        self.nodegroup_status = ''

    def metrics(self, graph) -> Dict:
        self._metrics['aws_eks_nodegroups_total'][(self.cloud(graph).name, self.account(graph).name, self.region(graph).name)] = 1
        if self._cleaned:
            self._metrics['cleaned_aws_eks_nodegroups_total'][(self.cloud(graph).name, self.account(graph).name, self.region(graph).name)] = 1
        return self._metrics

    def delete(self, account: AWSAccount, region: AWSRegion) -> bool:
        eks = aws_session(account.id, account.role).client('eks', region_name=region.id)
        eks.delete_nodegroup(clusterName=self.cluster_name, nodegroupName=self.name)
        return True

    def update_tag(self, key, value) -> bool:
        eks = aws_session(self.account().id, self.account().role).client('eks', region_name=self.region().id)
        eks.tag_resource(
            resourceArn=self.arn,
            tags={key: value}
        )
        return True

    def delete_tag(self, key) -> bool:
        eks = aws_session(self.account().id, self.account().role).client('eks', region_name=self.region().id)
        eks.untag_resource(
            resourceArn=self.arn,
            tagKeys=[key]
        )
        return True


class AWSAutoScalingGroup(AWSResource, BaseAutoScalingGroup):
    resource_type = 'aws_autoscaling_group'

    def delete(self, account: AWSAccount, region: AWSRegion, force_delete=True) -> bool:
        client = aws_session(account.id, account.role).client('autoscaling', region_name=region.id)
        client.delete_auto_scaling_group(AutoScalingGroupName=self.name, ForceDelete=force_delete)
        return True

    def update_tag(self, key, value) -> bool:
        client = aws_session(self.account().id, self.account().role).client('autoscaling', region_name=self.region().id)
        client.create_or_update_tags(
            Tags=[{
                'ResourceId': self.name,
                'ResourceType': 'auto-scaling-group',
                'Key': key,
                'Value': value,
                'PropagateAtLaunch': True
            }]
        )
        return True

    def delete_tag(self, key) -> bool:
        client = aws_session(self.account().id, self.account().role).client('autoscaling', region_name=self.region().id)
        client.delete_tags(
            Tags=[{
                'ResourceId': self.name,
                'ResourceType': 'auto-scaling-group',
                'Key': key,
                'Value': self.tags[key],
                'PropagateAtLaunch': True
            }]
        )
        return True
