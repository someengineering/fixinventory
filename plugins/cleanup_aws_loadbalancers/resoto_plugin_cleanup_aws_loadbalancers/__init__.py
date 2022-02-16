from resotolib.baseplugin import BaseActionPlugin
from resotolib.baseresources import EdgeType
from resotolib.logging import log
from resotolib.core.query import CoreGraph
from resotolib.graph import Graph
from resoto_plugin_aws.resources import (
    AWSELB,
    AWSALB,
    AWSALBTargetGroup,
    AWSEC2Instance,
)
from resotolib.args import ArgumentParser
from resotolib.utils import parse_delta
from typing import Dict


class CleanupAWSLoadbalancersPlugin(BaseActionPlugin):
    action = "cleanup_plan"

    def __init__(self):
        super().__init__()

    def bootstrap(self) -> bool:
        if ArgumentParser.args.cleanup_aws_loadbalancers:
            try:
                self.age = parse_delta(
                    ArgumentParser.args.cleanup_aws_loadbalancers_age
                )
                log.debug(f"AWS Loadbalancer Cleanup Plugin Age {self.age}")
            except ValueError:
                log.exception(
                    f"Error while parsing AWS Loadbalancer "
                    f"Cleanup Age {ArgumentParser.args.cleanup_aws_loadbalancers_age}"
                )
            else:
                return True
        return False

    def do_action(self, data: Dict) -> None:
        cg = CoreGraph()

        query = 'is(["aws_elb", "aws_alb", "aws_alb_target_group"]) <-default,delete[0:]delete->'
        graph = cg.graph(query)
        self.loadbalancer_cleanup(graph)
        cg.patch_nodes(graph)

    def loadbalancer_cleanup(self, graph: Graph):
        log.info("AWS Loadbalancers Cleanup called")
        for node in graph.nodes:
            if (
                not isinstance(node, AWSELB)
                and not isinstance(node, AWSALB)
                and not isinstance(node, AWSALBTargetGroup)
            ):
                continue

            if node.age < self.age:
                continue

            if node.tags.get("expiration") == "never":
                continue

            cloud = node.cloud(graph)
            account = node.account(graph)
            region = node.region(graph)

            if (
                isinstance(node, AWSELB)
                and len(
                    [
                        i
                        for i in node.predecessors(graph, edge_type=EdgeType.delete)
                        if isinstance(i, AWSEC2Instance)
                        and i.instance_status != "terminated"
                    ]
                )
                == 0
                and len(node.backends) == 0
            ):
                log.debug(
                    (
                        f"Found orphaned AWS ELB {node.dname} in cloud {cloud.name} account {account.dname} "
                        f"region {region.name} with age {node.age} and no EC2 instances attached to it."
                    )
                )
                node.clean = True
            elif (
                isinstance(node, AWSALB)
                and len(
                    [
                        n
                        for n in node.predecessors(graph, edge_type=EdgeType.delete)
                        if isinstance(n, AWSALBTargetGroup)
                    ]
                )
                == 0
                and len(node.backends) == 0
            ):
                log.debug(
                    (
                        f"Found orphaned AWS ALB {node.dname} in cloud {cloud.name} account {account.dname} "
                        f"region {region.name} with age {node.age} and no Target Groups attached to it."
                    )
                )
                node.clean = True
            elif (
                isinstance(node, AWSALBTargetGroup)
                and len(list(node.successors(graph, edge_type=EdgeType.delete))) == 0
            ):
                log.debug(
                    (
                        f"Found orphaned AWS ALB Target Group {node.dname} in cloud {cloud.name} "
                        f"account {account.dname} region {region.name} with age {node.age}"
                    )
                )
                node.clean = True
            elif isinstance(node, AWSALB):
                cleanup_alb = True
                target_groups = [
                    n
                    for n in node.predecessors(graph, edge_type=EdgeType.delete)
                    if isinstance(n, AWSALBTargetGroup)
                ]

                if len(node.backends) > 0:
                    cleanup_alb = False

                for tg in target_groups:
                    if (
                        tg.target_type != "instance"
                        or tg.age < self.age
                        or len(
                            [
                                i
                                for i in tg.predecessors(
                                    graph, edge_type=EdgeType.delete
                                )
                                if isinstance(i, AWSEC2Instance)
                                and i.instance_status != "terminated"
                            ]
                        )
                        > 0
                    ):
                        cleanup_alb = False

                if cleanup_alb:
                    log.debug(
                        (
                            f"Found AWS ALB {node.dname} in cloud {cloud.name} account {account.dname} "
                            f"region {region.name} with age {node.age} and no EC2 instances attached "
                            f"to its {len(target_groups)} target groups."
                        )
                    )
                    for tg in target_groups:
                        tg.clean = True
                    node.clean = True

    @staticmethod
    def add_args(arg_parser: ArgumentParser) -> None:
        arg_parser.add_argument(
            "--cleanup-aws-loadbalancers",
            help="Cleanup unused AWS Loadbalancers (default: False)",
            dest="cleanup_aws_loadbalancers",
            action="store_true",
            default=False,
        )
        arg_parser.add_argument(
            "--cleanup-aws-loadbalancers-age",
            help="Cleanup unused AWS Loadbalancers Age (default: 7 days)",
            default="7 days",
            dest="cleanup_aws_loadbalancers_age",
        )
