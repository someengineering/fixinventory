from resotolib.baseplugin import BaseActionPlugin
from resotolib.core.search import CoreGraph
from resotolib.graph import Graph
from resoto_plugin_aws.resource.cloudwatch import AwsCloudwatchAlarm
from resoto_plugin_aws.resource.ec2 import AwsEc2Instance
from resotolib.logger import log
from resotolib.config import Config
from .config import CleanupAWSAlarmsConfig
from typing import Dict


class CleanupAWSAlarmsPlugin(BaseActionPlugin):
    action = "cleanup_plan"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.config = {}
        if Config.plugin_cleanup_aws_alarms.enabled:
            self.config = Config.plugin_cleanup_aws_alarms.config

    def bootstrap(self) -> bool:
        return Config.plugin_cleanup_aws_alarms.enabled

    def do_action(self, data: Dict) -> None:
        cg = CoreGraph(tls_data=self.tls_data)

        query = "is(aws_cloudwatch_alarm) <-default,delete[0:]delete->"
        graph = cg.graph(query)
        self.alarm_cleanup(graph)
        cg.patch_nodes(graph)

    def alarm_cleanup(self, graph: Graph):
        log.info("AWS Cloudwatch Alarms cleanup called")
        for node in graph.nodes:
            if node.protected or not isinstance(node, AwsCloudwatchAlarm):
                continue

            cloud = node.cloud(graph)
            account = node.account(graph)
            region = node.region(graph)
            log_prefix = f"Found {node.rtdname} in cloud {cloud.name} account {account.dname} " f"region {region.name}."

            if len(self.config) > 0:
                if cloud.id not in self.config or account.id not in self.config[cloud.id]:
                    log.debug((f"{log_prefix} Account not found in config - ignoring."))
                    continue

            should_clean = False
            i = None
            log_msg = log_prefix
            for dimension in node.dimensions:
                if dimension.get("Name") == "InstanceId":
                    instance_id = dimension.get("Value")
                    i = graph.search_first_all({"kind": "aws_ec2_instance", "id": instance_id})
                    if isinstance(i, AwsEc2Instance) and i.instance_status not in ("terminated"):
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
    def add_config(config: Config) -> None:
        config.add_config(CleanupAWSAlarmsConfig)
