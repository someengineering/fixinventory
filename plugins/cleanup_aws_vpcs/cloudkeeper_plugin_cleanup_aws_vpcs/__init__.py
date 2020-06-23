import logging
import threading
import yaml
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

        self.config = {}
        if ArgumentParser.args.cleanup_aws_vpcs_config:
            self.config = CleanupAWSVPCsConfig(
                config_file=ArgumentParser.args.cleanup_aws_vpcs_config
            )
            self.config.read()  # initial read to ensure config format is valid

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
                if node.protected or not node.clean or not isinstance(node, AWSVPC):
                    continue

                cloud = node.cloud(graph)
                account = node.account(graph)
                region = node.region(graph)

                if len(self.config) > 0:
                    if (
                        cloud.id not in self.config
                        or account.id not in self.config[cloud.id]
                    ):
                        log.debug(
                            (
                                f"Found AWS VPC {node.dname} in cloud {cloud.name} account {account.dname} region {region.name}"
                                f" marked for cleanup. Account not found in config - ignoring dependent resources."
                            )
                        )
                        continue

                log.debug(
                    (
                        f"Found AWS VPC {node.dname} in cloud {cloud.name} account {account.dname} region {region.name}"
                        f" marked for cleanup. Marking dependent resources for cleanup as well."
                    )
                )
                for descendant in node.descendants(graph):
                    log.debug(
                        f"Found descendant {descendant.resource_type} {descendant.dname} of VPC {node.dname}"
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
                        if descendant.clean:
                            log.debug(
                                f"Descendant {descendant.resource_type} {descendant.dname} of VPC {node.dname} is not targeted but already marked for cleaning"
                            )
                        else:
                            log.error(
                                f"Descendant {descendant.resource_type} {descendant.dname} of VPC {node.dname} is not targeted and not marked for cleaning - VPC cleanup will likely fail"
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

    def shutdown(self, event: Event):
        log.debug(
            f"Received event {event.event_type} - shutting down AWS VPC Cleanup plugin"
        )
        self.exit.set()


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
