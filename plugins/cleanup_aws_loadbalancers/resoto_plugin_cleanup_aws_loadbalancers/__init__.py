from resotolib.baseplugin import BaseActionPlugin
from resotolib.baseresources import EdgeType
from resotolib.logger import log
from resotolib.core.search import CoreGraph
from resotolib.graph import Graph
from resoto_plugin_aws.resource.elb import AwsElb
from resoto_plugin_aws.resource.elbv2 import AwsAlb, AwsAlbTargetGroup
from resoto_plugin_aws.resource.ec2 import AwsEc2Instance
from resotolib.config import Config
from .config import CleanupAWSLoadbalancersConfig
from resotolib.durations import parse_duration
from typing import Dict


class CleanupAWSLoadbalancersPlugin(BaseActionPlugin):
    action = "cleanup_plan"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.age = None
        if Config.plugin_cleanup_aws_loadbalancers.enabled:
            self.update_age()

    def bootstrap(self) -> bool:
        return Config.plugin_cleanup_aws_loadbalancers.enabled

    def do_action(self, data: Dict) -> None:
        self.update_age()
        cg = CoreGraph(tls_data=self.tls_data)
        query = 'is(["aws_elb", "aws_alb", "aws_alb_target_group"]) <-default,delete[0:]delete->'
        graph = cg.graph(query)
        self.loadbalancer_cleanup(graph)
        cg.patch_nodes(graph)

    def update_age(self) -> None:
        try:
            self.age = parse_duration(Config.plugin_cleanup_aws_loadbalancers.min_age)
            log.debug(f"Cleanup AWS Load balancers minimum age is {self.age}")
        except ValueError:
            log.error(
                "Error while parsing Cleanup AWS Load balancers minimum age"
                f" {Config.plugin_cleanup_aws_loadbalancers.min_age}"
            )
            raise

    def loadbalancer_cleanup(self, graph: Graph):
        log.info("AWS Loadbalancers Cleanup called")
        for node in graph.nodes:
            if (
                not isinstance(node, AwsElb)
                and not isinstance(node, AwsAlb)
                and not isinstance(node, AwsAlbTargetGroup)
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
                isinstance(node, AwsElb)
                and len(
                    [
                        i
                        for i in node.predecessors(graph, edge_type=EdgeType.delete)
                        if isinstance(i, AwsEc2Instance) and i.instance_status != "terminated"
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
                isinstance(node, AwsAlb)
                and len(
                    [n for n in node.predecessors(graph, edge_type=EdgeType.delete) if isinstance(n, AwsAlbTargetGroup)]
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
                isinstance(node, AwsAlbTargetGroup)
                and len(list(node.successors(graph, edge_type=EdgeType.delete))) == 0
            ):
                log.debug(
                    (
                        f"Found orphaned AWS ALB Target Group {node.dname} in cloud {cloud.name} "
                        f"account {account.dname} region {region.name} with age {node.age}"
                    )
                )
                node.clean = True
            elif isinstance(node, AwsAlb):
                cleanup_alb = True
                target_groups = [
                    n for n in node.predecessors(graph, edge_type=EdgeType.delete) if isinstance(n, AwsAlbTargetGroup)
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
                                for i in tg.predecessors(graph, edge_type=EdgeType.delete)
                                if isinstance(i, AwsEc2Instance) and i.instance_status != "terminated"
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
    def add_config(config: Config) -> None:
        config.add_config(CleanupAWSLoadbalancersConfig)
