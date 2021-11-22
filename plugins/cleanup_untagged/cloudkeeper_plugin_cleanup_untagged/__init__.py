import inspect
import yaml
from cklib.baseplugin import BaseActionPlugin
from cklib.logging import log
from cklib.core.query import CoreGraph
from cklib.graph import Graph
from cklib.baseresources import *
from cklib.args import ArgumentParser
from cklib.utils import parse_delta
from typing import Dict


class CleanupUntaggedPlugin(BaseActionPlugin):
    action = "cleanup_plan"

    def __init__(self):
        super().__init__()
        if ArgumentParser.args.cleanup_untagged_config:
            self.config = CleanupUntaggedConfig(
                config_file=ArgumentParser.args.cleanup_untagged_config
            )
            self.config.read()  # initial read to ensure config format is valid

    def bootstrap(self) -> bool:
        return ArgumentParser.args.cleanup_untagged_config is not None

    def do_action(self, data: Dict) -> None:
        cg = CoreGraph()

        self.config.read()  # runtime read in case config file was updated since last run
        query = "is(resource) and age > 2h <-[0:]->"
        graph = cg.graph(query)
        self.vpc_cleanup(graph)
        cg.patch_nodes(graph)

    def cleanup_untagged(self, graph: Graph):
        log.debug("Cleanup Untagged called")
        
        for node in graph.nodes:
            cloud = node.cloud(graph)
            account = node.account(graph)
            region = node.region(graph)
            node_classes = [cls.__name__ for cls in inspect.getmro(node.__class__)]
            node_classes.remove("ABC")
            node_classes.remove("object")

            if (
                not isinstance(node, BaseResource)
                or isinstance(node, BaseCloud)
                or isinstance(node, BaseAccount)
                or isinstance(node, BaseRegion)
                or not isinstance(cloud, BaseCloud)
                or not isinstance(account, BaseAccount)
                or not isinstance(region, BaseRegion)
                or node.protected
                or node.phantom
                or cloud.id not in self.config["accounts"]
                or account.id not in self.config["accounts"][cloud.id]
                or node.age < self.config["accounts"][cloud.id][account.id]["age"]
                or set(node_classes).isdisjoint(self.config["classes"])
                or all(
                    (
                        tag in node.tags and len(node.tags[tag]) > 0
                        for tag in self.config["tags"]
                    )
                )
            ):
                continue

            log_msg = (
                f"Missing one or more of tags: {', '.join(self.config['tags'])} and age {node.age} is older "
                f"than threshold of {self.config['accounts'][cloud.id][account.id]['age']}"
            )
            log.error(
                (
                    f"Cleaning resource {node.rtdname} in cloud {cloud.name} "
                    f"account {account.dname} region {region.name}: {log_msg}"
                )
            )
            node.log(log_msg)
            node.clean = True

    @staticmethod
    def add_args(arg_parser: ArgumentParser) -> None:
        arg_parser.add_argument(
            "--cleanup-untagged-config",
            help="Path to Cleanup Untagged Plugin Config",
            default=None,
            dest="cleanup_untagged_config",
        )


class CleanupUntaggedConfig(dict):
    def __init__(self, *args, config_file: str = None, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.config_file = config_file

    def read(self) -> bool:
        if not self.config_file:
            log.error(
                "Attribute config_file is not set on CleanupUntaggedConfig() instance"
            )
            return False

        with open(self.config_file) as config_file:
            config = yaml.load(config_file, Loader=yaml.FullLoader)
        if self.validate(config):
            self.update(config)
        return True

    @staticmethod
    def validate(config) -> bool:
        required_sections = ["tags", "kinds", "accounts"]
        for section in required_sections:
            if section not in config:
                raise ValueError(f"Section '{section}' not found in config")

        if not isinstance(config["tags"], list) or len(config["tags"]) == 0:
            raise ValueError("Error in 'tags' section")

        if not isinstance(config["kinds"], list) or len(config["kinds"]) == 0:
            raise ValueError("Error in 'kinds' section")

        if not isinstance(config["accounts"], dict) or len(config["accounts"]) == 0:
            raise ValueError("Error in 'accounts' section")

        default_age = config.get("default", {}).get("age")
        if default_age is not None:
            default_age = parse_delta(default_age)

        for cloud_id, account in config["accounts"].items():
            for account_id, account_data in account.items():
                if "name" not in account_data:
                    raise ValueError(
                        f"Missing 'name' for account '{cloud_id}/{account_id}"
                    )
                if "age" in account_data:
                    account_data["age"] = parse_delta(account_data["age"])
                else:
                    if default_age is None:
                        raise ValueError(
                            f"Missing 'age' for account '{cloud_id}/{account_id}' and no default age defined'"
                        )
                    account_data["age"] = default_age
        return True
