import cklib.logging
import threading
import inspect
from .config import TagValidatorConfig
from cklib.baseplugin import BasePlugin
from cklib.baseresources import *
from cklib.args import ArgumentParser
from cklib.graph import Graph
from cklib.event import (
    Event,
    EventType,
    add_event_listener,
    remove_event_listener,
)
from cklib.utils import parse_delta
from cloudkeeperV1.paralleltagger import ParallelTagger
from prometheus_client import Summary, Counter

log = cklib.logging.getLogger("cloudkeeper." + __name__)

metrics_tag_violations = Counter(
    "cloudkeeper_plugin_tagvalidator_tag_violations_total",
    "Tag Validator Plugin Tag Violations",
    ["cloud", "account", "region", "kind"],
)
metrics_validate_tags = Summary(
    "cloudkeeper_plugin_tagvalidator_validate_tags_seconds",
    "Tag Validator Plugin Time it took the validate_tags() method",
)


class TagValidatorPlugin(BasePlugin):
    def __init__(self):
        super().__init__()
        self.name = "tagvalidator"
        self.exit = threading.Event()
        self.run_lock = threading.Lock()
        if ArgumentParser.args.tagvalidator_config:
            self.config = TagValidatorConfig(ArgumentParser.args.tagvalidator_config)
            add_event_listener(EventType.SHUTDOWN, self.shutdown)
            add_event_listener(
                EventType.COLLECT_FINISH, self.tag_validator, blocking=True, timeout=900
            )
        else:
            self.exit.set()

    def __del__(self):
        remove_event_listener(EventType.COLLECT_FINISH, self.tag_validator)
        remove_event_listener(EventType.SHUTDOWN, self.shutdown)

    def go(self):
        self.exit.wait()

    def tag_validator(self, event: Event):
        if not self.run_lock.acquire(blocking=False):
            log.error("Tag Validator is already running")
            return

        graph = event.data
        log.info("Tag Validator called")
        try:
            self.validate_tags(graph)
        except Exception:
            raise
        finally:
            self.run_lock.release()

    @metrics_validate_tags.time()
    def validate_tags(self, graph: Graph):
        config = self.config.read_config()
        pt = ParallelTagger(self.name)
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
                ):
                    continue

                if cloud.id in config and account.id in config[cloud.id]:
                    class_config = {}
                    node_class = None
                    for node_class in node_classes:
                        node_class = node_class.lower()
                        if node_class in config[cloud.id][account.id]:
                            class_config = config[cloud.id][account.id][node_class]
                            break

                    for tag, tag_config in class_config.items():
                        if region.id in tag_config:
                            desired_value = tag_config[region.id]
                        elif "*" in tag_config:
                            desired_value = tag_config["*"]
                        else:
                            log.error(
                                (
                                    f"No tag config for node {node.dname} class {node_class} in account "
                                    f"{account.dname} cloud {cloud.id}"
                                )
                            )
                            continue

                        if tag in node.tags:
                            current_value = node.tags[tag]
                            log.debug(
                                (
                                    f"Found {node.rtdname} age {node.age} in cloud {cloud.name}"
                                    f" account {account.dname} region {region.name} with tag {tag}: {current_value}"
                                )
                            )

                            if desired_value == "never":
                                continue

                            if current_value == "never" and desired_value != "never":
                                log_msg = (
                                    f"Current value {current_value} is not allowed - "
                                    f"setting tag {tag} to desired value {desired_value}"
                                )
                                log.debug(log_msg)
                                set_tag(
                                    pt,
                                    node,
                                    tag,
                                    desired_value,
                                    log_msg,
                                    cloud,
                                    account,
                                    region,
                                )
                                continue

                            try:
                                current_value_td = parse_delta(current_value)
                            except ValueError:
                                log_msg = (
                                    f"Can't parse current value {current_value} - "
                                    f"setting tag {tag} to desired value {desired_value}"
                                )
                                log.error(log_msg)
                                set_tag(
                                    pt,
                                    node,
                                    tag,
                                    desired_value,
                                    log_msg,
                                    cloud,
                                    account,
                                    region,
                                )
                                continue

                            try:
                                desired_value_td = parse_delta(desired_value)
                            except (AssertionError, ValueError):
                                log.error(
                                    "Can't parse desired value {} into timedelta - skipping tag"
                                )
                                continue

                            if desired_value_td < current_value_td:
                                log_msg = (
                                    f"Current value {current_value} is larger than desired value {desired_value} - "
                                    f"setting tag {tag}"
                                )
                                log.debug(log_msg)
                                set_tag(
                                    pt,
                                    node,
                                    tag,
                                    desired_value,
                                    log_msg,
                                    cloud,
                                    account,
                                    region,
                                )
        pt.run()

    @staticmethod
    def add_args(arg_parser: ArgumentParser) -> None:
        arg_parser.add_argument(
            "--tagvalidator-config",
            help="Path to Tag Validator Config",
            default=None,
            dest="tagvalidator_config",
        )
        arg_parser.add_argument(
            "--tagvalidator-dry-run",
            help="Tag Validator Dry Run",
            dest="tagvalidator_dry_run",
            action="store_true",
            default=False,
        )

    def shutdown(self, event: Event):
        log.debug(
            f"Received event {event.event_type} - shutting down tag validator plugin"
        )
        self.exit.set()


def set_tag(
    pt: ParallelTagger,
    node: BaseResource,
    tag,
    value,
    log_msg: str,
    cloud: BaseCloud = None,
    account: BaseAccount = None,
    region: BaseRegion = None,
):
    pt_key = None
    if node and cloud and account and region:
        metrics_tag_violations.labels(
            cloud=cloud.name,
            account=account.dname,
            region=region.name,
            kind=node.kind,
        ).inc()
        pt_key = f"{cloud.id}-{account.id}-{region.id}"
    if ArgumentParser.args.tagvalidator_dry_run:
        log_msg = f"DRY RUN - ACTION NOT PERFORMED: {log_msg}"
        node.log(log_msg)
        log.debug(
            f"Tag Validator Dry Run - not setting {tag}: {value} for node {node.dname}"
        )
    else:
        node.log(log_msg)
        pt.add(node, tag, value, pt_key)
