from copy import deepcopy
from resotolib.logger import log
from resotolib.core.search import CoreGraph
from resotolib.baseplugin import BaseActionPlugin
from resotolib.core.model_export import node_from_dict
from resotolib.config import Config
from .config import ProtectorConfig
from typing import Dict


class ProtectorPlugin(BaseActionPlugin):
    action = "post_collect"

    def bootstrap(self) -> bool:
        return Config.plugin_protector.enabled

    def do_action(self, data: Dict) -> None:
        log.info("Protector called")
        Config.plugin_protector.validate(Config.plugin_protector)
        self.config = deepcopy(Config.plugin_protector.config)

        cg = CoreGraph(tls_data=self.tls_data)
        resource_parts = []
        for cloud_id, accounts in self.config.items():
            for account_id, regions in accounts.items():
                for region_id, kinds in regions.items():
                    for kind, resources in kinds.items():
                        for resource_id in resources:
                            log.debug(
                                f"Protecting {resource_id} of kind {kind} in"
                                f" region {region_id} account {account_id}"
                                f" cloud {cloud_id}"
                            )
                            resource_parts.append(
                                f'(/reported.id == "{resource_id}"'
                                f' and /reported.kind == "{kind}"'
                                f' and /ancestors.region.reported.id == "{region_id}"'
                                f' and /ancestors.cloud.reported.id == "{cloud_id}")'
                            )
        resource_part = " or ".join(resource_parts)
        command = f"search {resource_part} | protect"
        for node_data in cg.execute(command):
            node = node_from_dict(node_data)
            log.debug(f"Protected {node.rtdname}")

    @staticmethod
    def add_config(config: Config) -> None:
        config.add_config(ProtectorConfig)
