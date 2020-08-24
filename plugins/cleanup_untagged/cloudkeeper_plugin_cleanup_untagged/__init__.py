import cloudkeeper.logging
import threading
import inspect
import yaml
from cloudkeeper.baseplugin import BasePlugin
from cloudkeeper.baseresources import *
from cloudkeeper.args import ArgumentParser
from cloudkeeper.event import (
    Event,
    EventType,
    add_event_listener,
    remove_event_listener,
)
from cloudkeeper.utils import parse_delta
from prometheus_client import Counter

log = cloudkeeper.logging.getLogger("cloudkeeper." + __name__)

metrics_cleanup_untagged = Counter(
    "cloudkeeper_plugin_cleanup_untagged_resources_total",
    "Cleanup Untagged Plugin Untagged Resources",
    ["cloud", "account", "region", "resource_type"],
)


class CleanupUntaggedPlugin(BasePlugin):
    def __init__(self):
        super().__init__()
        self.name = "cleanup_untagged"
        self.exit = threading.Event()
        if ArgumentParser.args.cleanup_untagged_config:
            self.config = CleanupUntaggedConfig(
                config_file=ArgumentParser.args.cleanup_untagged_config
            )
            self.config.read()  # initial read to ensure config format is valid
            add_event_listener(EventType.SHUTDOWN, self.shutdown)
            add_event_listener(
                EventType.CLEANUP_PLAN,
                self.cleanup_untagged,
                blocking=True,
                timeout=900,
            )
        else:
            self.exit.set()

    def __del__(self):
        remove_event_listener(EventType.CLEANUP_PLAN, self.cleanup_untagged)
        remove_event_listener(EventType.SHUTDOWN, self.shutdown)

    def go(self):
        self.exit.wait()

    def cleanup_untagged(self, event: Event):
        log.debug("Cleanup Untagged called")
        self.config.read()  # runtime read in case config file was updated since last run
        graph = event.data
        with graph.lock.read_access:
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

                metrics_cleanup_untagged.labels(
                    cloud=cloud.name,
                    account=account.name,
                    region=region.name,
                    resource_type=node.resource_type,
                ).inc()
                log_msg = (
                    f"Missing one or more of tags: {', '.join(self.config['tags'])} and age {node.age} is older "
                    f"than threshold of {self.config['accounts'][cloud.id][account.id]['age']}"
                )
                log.error(
                    (
                        f"Cleaning resource {node.resource_type} {node.dname} in cloud {cloud.name} "
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

    def shutdown(self, event: Event):
        log.debug(
            f"Received event {event.event_type} - shutting down Cleanup Untagged Plugin"
        )
        self.exit.set()


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
        required_sections = ["tags", "classes", "accounts"]
        for section in required_sections:
            if section not in config:
                raise ValueError(f"Section '{section}' not found in config")

        if not isinstance(config["tags"], list) or len(config["tags"]) == 0:
            raise ValueError("Error in 'tags' section")

        if not isinstance(config["classes"], list) or len(config["classes"]) == 0:
            raise ValueError("Error in 'classes' section")

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
