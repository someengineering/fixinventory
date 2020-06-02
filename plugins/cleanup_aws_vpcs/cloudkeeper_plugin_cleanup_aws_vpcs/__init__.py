import logging
import threading
from cloudkeeper.baseplugin import BasePlugin
from cloudkeeper_plugin_aws.resources import (
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
)
from cloudkeeper.args import ArgumentParser
from cloudkeeper.event import (
    Event,
    EventType,
    add_event_listener,
    remove_event_listener,
)

log = logging.getLogger("cloudkeeper." + __name__)


class CleanupAWSVPCsPlugin(BasePlugin):
    def __init__(self):
        super().__init__()
        self.name = "cleanup_aws_vpcs"
        self.exit = threading.Event()
        if ArgumentParser.args.cleanup_aws_vpcs:
            add_event_listener(EventType.SHUTDOWN, self.shutdown)
            add_event_listener(
                EventType.CLEANUP_BEGIN, self.vpc_cleanup, blocking=True, timeout=3600,
            )
        else:
            self.exit.set()

    def __del__(self):
        remove_event_listener(EventType.CLEANUP_BEGIN, self.vpc_cleanup)
        remove_event_listener(EventType.SHUTDOWN, self.shutdown)

    def go(self):
        self.exit.wait()

    def vpc_cleanup(self, event: Event):
        graph = event.data
        log.info("AWS VPC cleanup called")
        with graph.lock.read_access:
            for node in graph.nodes:
                if not node.clean and not isinstance(node, AWSVPC) or node.protected:
                    continue

                cloud = node.cloud(graph)
                account = node.account(graph)
                region = node.region(graph)

                log.debug(
                    (
                        f"Found AWS VPC {node.id} in cloud {cloud.name} account {account.name} region {region.name}"
                        f" marked for cleanup. Marking dependent resources for cleanup as well."
                    )
                )
                for descendant in node.descendants(graph):
                    log.debug(
                        f"Found descendant {descendant.resource_type} {descendant.id} of VPC {node.id}"
                    )
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
                        ),
                    ):
                        descendant.clean = True
                    else:
                        log.error(
                            f"Descendant {descendant.resource_type} {descendant.id} of VPC {node.id} not marked for cleaning - VPC cleanup will likely fail"
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

    def shutdown(self, event: Event):
        log.debug(
            f"Received event {event.event_type} - shutting down AWS VPC Cleanup plugin"
        )
        self.exit.set()
