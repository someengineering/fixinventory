from cklib.logging import log
import yaml
from cklib.core.query import CoreGraph
from cklib.baseplugin import BaseActionPlugin
from cklib.graph.export import node_from_dict
from cklib.args import ArgumentParser
from typing import Dict


class ProtectSnowflakesPlugin(BaseActionPlugin):
    action = "post_collect"

    def __init__(self):
        super().__init__()
        if ArgumentParser.args.protect_snowflakes_config:
            self.config = ProtectSnowflakesConfig(
                config_file=ArgumentParser.args.protect_snowflakes_config
            )
            self.config.read()  # initial read to ensure config format is valid

    def bootstrap(self) -> bool:
        return ArgumentParser.args.protect_snowflakes_config is not None

    def do_action(self, data: Dict) -> None:
        log.info("Protect Snowflakes called")
        self.config.read()

        cg = CoreGraph()
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
                                f'(reported.id == "{resource_id}"'
                                f' and reported.kind == "{kind}"'
                                f' and metadata.ancestors.region.id == "{region_id}"'
                                f' and metadata.ancestors.cloud.id == "{cloud_id}")'
                            )
        resource_part = " or ".join(resource_parts)
        command = f"query {resource_part} | protect"
        for node_data in cg.execute(command):
            node = node_from_dict(node_data)
            log.debug(f"Protected {node.rtdname}")

    @staticmethod
    def add_args(arg_parser: ArgumentParser) -> None:
        arg_parser.add_argument(
            "--protect-snowflakes-config",
            help="Path to Protect Snowflakes Plugin Config",
            default=None,
            dest="protect_snowflakes_config",
        )


class ProtectSnowflakesConfig(dict):
    def __init__(self, *args, config_file: str = None, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.config_file = config_file

    def read(self) -> bool:
        if not self.config_file:
            raise ValueError(
                "Attribute config_file is not set on ProtectSnowflakesConfig() instance"
            )

        with open(self.config_file) as config_file:
            config = yaml.load(config_file, Loader=yaml.FullLoader)
        if self.validate(config):
            self.update(config)

    @staticmethod
    def validate(config) -> bool:
        if not isinstance(config, dict):
            raise ValueError("Config is no dict")

        for cloud_id, account_data in config.items():
            if not isinstance(cloud_id, str):
                raise ValueError(f"Cloud ID {cloud_id} is no string")
            if not isinstance(account_data, dict):
                raise ValueError(f"Account Data {account_data} is no dict")

            for account_id, region_data in account_data.items():
                if not isinstance(account_id, str):
                    raise ValueError(f"Account ID {account_id} is no string")
                if not isinstance(region_data, dict):
                    raise ValueError(f"Region Data {region_data} is no dict")

                for region_id, resource_data in region_data.items():
                    if not isinstance(region_id, str):
                        raise ValueError(f"Region ID {region_id} is no string")
                    if not isinstance(resource_data, dict):
                        raise ValueError(f"Resource Data {resource_data} is no dict")

                    for kind, resource_list in resource_data.items():
                        if not isinstance(kind, str):
                            raise ValueError(f"Resource Kind {kind} is no string")
                        if not isinstance(resource_list, list):
                            raise ValueError(
                                f"Resource List {resource_list} is no list"
                            )

                        for resource_id in resource_list:
                            if not isinstance(resource_id, str):
                                raise ValueError(
                                    f"Resource ID {resource_id} is no string"
                                )
        return True
