from resotolib.baseresources import EdgeType
import yaml
from resotolib.baseplugin import BaseActionPlugin
from resotolib.logging import log
from resotolib.core.query import CoreGraph
from resotolib.graph import Graph
from resoto_plugin_aws.resources import (
    AWSVPC,
    AWSVPCPeeringConnection,
    AWSEC2NetworkAcl,
    AWSEC2NetworkInterface,
    AWSELB,
    AWSALB,
    AWSALBTargetGroup,
    AWSEC2Subnet,
    AWSEC2SecurityGroup,
    AWSEC2InternetGateway,
    AWSEC2NATGateway,
    AWSEC2RouteTable,
    AWSVPCEndpoint,
    AWSEC2Instance,
    AWSEC2ElasticIP,
)
from resotolib.args import ArgumentParser
from typing import Dict


class CleanupAWSVPCsPlugin(BaseActionPlugin):
    action = "post_cleanup_plan"

    def __init__(self):
        super().__init__()

        self.config = {}
        if ArgumentParser.args.cleanup_aws_vpcs_config:
            self.config = CleanupAWSVPCsConfig(
                config_file=ArgumentParser.args.cleanup_aws_vpcs_config
            )
            self.config.read()  # initial read to ensure config format is valid

    def bootstrap(self) -> bool:
        return ArgumentParser.args.cleanup_aws_vpcs

    def do_action(self, data: Dict) -> None:
        cg = CoreGraph()

        query = "is(aws_vpc) and desired.clean == true and metadata.cleaned == false <-[0:]->"
        graph = cg.graph(query)
        self.vpc_cleanup(graph)
        cg.patch_nodes(graph)

    def vpc_cleanup(self, graph: Graph):
        log.info("AWS VPC cleanup called")
        for node in graph.nodes:
            if node.protected or not node.clean or not isinstance(node, AWSVPC):
                continue

            cloud = node.cloud(graph)
            account = node.account(graph)
            region = node.region(graph)
            log_prefix = (
                f"Found AWS VPC {node.dname} in cloud {cloud.name} account {account.dname} "
                f"region {region.name} marked for cleanup."
            )

            if len(self.config) > 0:
                if (
                    cloud.id not in self.config
                    or account.id not in self.config[cloud.id]
                ):
                    log.debug(
                        (
                            f"{log_prefix} Account not found in config - ignoring dependent resources."
                        )
                    )
                    continue

            vpc_instances = [
                i
                for i in node.descendants(graph, edge_type=EdgeType.delete)
                if isinstance(i, AWSEC2Instance)
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
                        AWSVPCPeeringConnection,
                        AWSEC2NetworkAcl,
                        AWSEC2NetworkInterface,
                        AWSELB,
                        AWSALB,
                        AWSALBTargetGroup,
                        AWSEC2Subnet,
                        AWSEC2SecurityGroup,
                        AWSEC2InternetGateway,
                        AWSEC2NATGateway,
                        AWSEC2RouteTable,
                        AWSVPCEndpoint,
                        AWSEC2ElasticIP,
                    ),
                ):
                    descendant.log(
                        (
                            f"Marking for cleanup because resource is a descendant of VPC {node.dname} "
                            f"which is set to be cleaned"
                        )
                    )
                    node.log(
                        f"Marking {descendant.rtdname} for cleanup because resource is a descendant"
                    )
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
    def add_args(arg_parser: ArgumentParser) -> None:
        arg_parser.add_argument(
            "--cleanup-aws-vpcs",
            help="Cleanup AWS VPCs (default: False)",
            dest="cleanup_aws_vpcs",
            action="store_true",
            default=False,
        )
        arg_parser.add_argument(
            "--cleanup-aws-vpcs-config",
            help="Path to Cleanup AWS VPCs Plugin Config",
            default=None,
            dest="cleanup_aws_vpcs_config",
        )


class CleanupAWSVPCsConfig(dict):
    def __init__(self, *args, config_file: str = None, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.config_file = config_file

    def read(self) -> bool:
        if not self.config_file:
            raise ValueError(
                "Attribute config_file is not set on CleanupAWSVPCsConfig() instance"
            )

        with open(self.config_file) as config_file:
            config = yaml.load(config_file, Loader=yaml.FullLoader)
        if self.validate(config):
            self.update(config)
            return True
        return False

    @staticmethod
    def validate(config) -> bool:
        if not isinstance(config, dict):
            raise ValueError("Config is no dict")

        for cloud_id, account_ids in config.items():
            if not isinstance(cloud_id, str):
                raise ValueError(f"Cloud ID {cloud_id} is no string")
            if not isinstance(account_ids, list):
                raise ValueError(f"Account IDs {account_ids} is no list")

            for account_id in account_ids:
                if not isinstance(account_id, str):
                    raise ValueError(f"Account ID {account_id} is no string")
        return True
