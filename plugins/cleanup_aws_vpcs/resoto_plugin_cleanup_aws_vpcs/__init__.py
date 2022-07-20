from copy import deepcopy
from resotolib.baseresources import EdgeType
from resotolib.baseplugin import BaseActionPlugin
from resotolib.logger import log
from resotolib.core.search import CoreGraph
from resotolib.graph import Graph
from resoto_plugin_aws.resource.ec2 import (
    AwsEc2Vpc,
    AwsEc2VpcPeeringConnection,
    AwsEc2NetworkAcl,
    AwsEc2NetworkInterface,
    AwsEc2Subnet,
    AwsEc2SecurityGroup,
    AwsEc2InternetGateway,
    AwsEc2NatGateway,
    AwsEc2RouteTable,
    AwsEc2VpcEndpoint,
    AwsEc2Instance,
    AwsEc2ElasticIp,
)
from resoto_plugin_aws.resource.elb import AwsElb
from resoto_plugin_aws.resource.elbv2 import AwsAlb, AwsAlbTargetGroup
from resotolib.config import Config
from .config import CleanupAWSVPCsConfig
from typing import Dict


class CleanupAWSVPCsPlugin(BaseActionPlugin):
    action = "post_cleanup_plan"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.config = {}

    def bootstrap(self) -> bool:
        return Config.plugin_cleanup_aws_vpcs.enabled

    def do_action(self, data: Dict) -> None:
        Config.plugin_cleanup_aws_vpcs.validate(Config.plugin_cleanup_aws_vpcs)
        self.config = deepcopy(Config.plugin_cleanup_aws_vpcs.config)
        cg = CoreGraph(tls_data=self.tls_data)
        query = "is(aws_vpc) and /desired.clean == true and /metadata.cleaned == false <-default,delete[0:]delete->"
        graph = cg.graph(query)
        self.vpc_cleanup(graph)
        cg.patch_nodes(graph)

    def vpc_cleanup(self, graph: Graph):
        log.info("AWS VPC cleanup called")
        for node in graph.nodes:
            if node.protected or not node.clean or not isinstance(node, AwsEc2Vpc):
                continue

            cloud = node.cloud(graph)
            account = node.account(graph)
            region = node.region(graph)
            log_prefix = (
                f"Found AWS VPC {node.dname} in cloud {cloud.name} account {account.dname} "
                f"region {region.name} marked for cleanup."
            )

            if self.config and len(self.config) > 0:
                if cloud.id not in self.config or account.id not in self.config[cloud.id]:
                    log.debug((f"{log_prefix} Account not found in config - ignoring dependent resources."))
                    continue

            vpc_instances = [
                i
                for i in node.descendants(graph, edge_type=EdgeType.delete)
                if isinstance(i, AwsEc2Instance)
                and i.instance_status not in ("shutting-down", "terminated")
                and not i.clean
            ]
            if len(vpc_instances) > 0:
                log_msg = "VPC contains active EC2 instances - not cleaning VPC."
                log.debug(f"{log_prefix} {log_msg}")
                node.log(log_msg)
                node.clean = False
                continue

            log.debug(f"{log_prefix} Marking dependent resources for cleanup as well.")

            for descendant in node.descendants(graph, edge_type=EdgeType.delete):
                log.debug(f"Found descendant {descendant.rtdname} of VPC {node.dname}")
                if isinstance(
                    descendant,
                    (
                        AwsEc2VpcPeeringConnection,
                        AwsEc2NetworkAcl,
                        AwsEc2NetworkInterface,
                        AwsElb,
                        AwsAlb,
                        AwsAlbTargetGroup,
                        AwsEc2Subnet,
                        AwsEc2SecurityGroup,
                        AwsEc2InternetGateway,
                        AwsEc2NatGateway,
                        AwsEc2RouteTable,
                        AwsEc2VpcEndpoint,
                        AwsEc2ElasticIp,
                    ),
                ):
                    descendant.log(
                        (
                            f"Marking for cleanup because resource is a descendant of VPC {node.dname} "
                            f"which is set to be cleaned"
                        )
                    )
                    node.log(f"Marking {descendant.rtdname} for cleanup because resource is a descendant")
                    descendant.clean = True
                else:
                    if descendant.clean:
                        log.debug(
                            (
                                f"Descendant {descendant.rtdname} of VPC {node.dname} is not targeted but "
                                f"already marked for cleaning"
                            )
                        )
                    else:
                        log.error(
                            (
                                f"Descendant {descendant.rtdname} of VPC {node.dname} is not targeted and "
                                f"not marked for cleaning - VPC cleanup will likely fail"
                            )
                        )
                        node.log(
                            (
                                f"Descendant {descendant.rtdname} is not targeted and not marked for cleaning "
                                f"- cleanup will likely fail"
                            )
                        )

    @staticmethod
    def add_config(config: Config) -> None:
        config.add_config(CleanupAWSVPCsConfig)
