import yaml
from resotolib.baseplugin import BaseActionPlugin
from resotolib.core.query import CoreGraph
from resotolib.graph import Graph
from resoto_plugin_aws.resources import (
    AWSCloudwatchAlarm,
    AWSEC2Instance,
)
from resotolib.logging import log
from resotolib.args import ArgumentParser
from typing import Dict


class CleanupAWSAlarmsPlugin(BaseActionPlugin):
    action = "cleanup_plan"

    def __init__(self):
        super().__init__()

        self.config = {}
        if ArgumentParser.args.cleanup_aws_alarms_config:
            self.config = CleanupAWSAlarmsConfig(
                config_file=ArgumentParser.args.cleanup_aws_alarms_config
            )
            self.config.read()  # initial read to ensure config format is valid

    def bootstrap(self) -> bool:
        return ArgumentParser.args.cleanup_aws_alarms

    def do_action(self, data: Dict) -> None:
        cg = CoreGraph()

        query = "is(aws_cloudwatch_alarm) <-[0:]->"
        graph = cg.graph(query)
        self.alarm_cleanup(graph)
        cg.patch_nodes(graph)

    def alarm_cleanup(self, graph: Graph):
        log.info("AWS Cloudwatch Alarms cleanup called")
        for node in graph.nodes:
            if node.protected or not isinstance(node, AWSCloudwatchAlarm):
                continue

            cloud = node.cloud(graph)
            account = node.account(graph)
            region = node.region(graph)
            log_prefix = (
                f"Found {node.rtdname} in cloud {cloud.name} account {account.dname} "
                f"region {region.name}."
            )

            if len(self.config) > 0:
                if (
                    cloud.id not in self.config
                    or account.id not in self.config[cloud.id]
                ):
                    log.debug((f"{log_prefix} Account not found in config - ignoring."))
                    continue

            should_clean = False
            i = None
            log_msg = log_prefix
            for dimension in node.dimensions:
                if dimension.get("Name") == "InstanceId":
                    instance_id = dimension.get("Value")
                    i = graph.search_first_all(
                        {"kind": "aws_ec2_instance", "id": instance_id}
                    )
                    if isinstance(i, AWSEC2Instance) and i.instance_status not in (
                        "terminated"
                    ):
                        should_clean = False
                        break
                    else:
                        should_clean = True
                        log_msg += f" Referenced EC2 instance {instance_id} not found."

            if not should_clean:
                continue
            log.debug(f"{log_msg} - cleaning alarm")
            node.clean = True

    @staticmethod
    def add_args(arg_parser: ArgumentParser) -> None:
        arg_parser.add_argument(
            "--cleanup-aws-alarms",
            help="Cleanup AWS Cloudwatch Alarms (default: False)",
            dest="cleanup_aws_alarms",
            action="store_true",
            default=False,
        )
        arg_parser.add_argument(
            "--cleanup-aws-alarms-config",
            help="Path to Cleanup AWS Cloudwatch Alarms Plugin Config",
            default=None,
            dest="cleanup_aws_alarms_config",
        )


class CleanupAWSAlarmsConfig(dict):
    def __init__(self, *args, config_file: str = None, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.config_file = config_file

    def read(self) -> bool:
        if not self.config_file:
            raise ValueError(
                "Attribute config_file is not set on CleanupAWSAlarmsConfig() instance"
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
