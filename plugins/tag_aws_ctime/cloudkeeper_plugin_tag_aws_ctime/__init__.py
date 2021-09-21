import cklib.logging
import threading
from datetime import datetime, timezone
from cklib.graph import Graph
from cklib.baseplugin import BasePlugin
from cklib.baseresources import BaseCloud, BaseAccount, BaseRegion
from cloudkeeper_plugin_aws.resources import (
    AWSALBTargetGroup,
    AWSEC2KeyPair,
    AWSEC2NetworkAcl,
    AWSVPC,
)
from cloudkeeper.paralleltagger import ParallelTagger
from cklib.args import ArgumentParser
from cklib.event import (
    Event,
    EventType,
    add_event_listener,
    remove_event_listener,
)
from prometheus_client import Summary, Counter

log = cklib.logging.getLogger("cloudkeeper." + __name__)

metrics_ctime_tags = Counter(
    "cloudkeeper_plugin_tag_aws_ctime_tags_total",
    "Tag AWS ctime Plugin Number of ctime tags applied",
    ["cloud", "account", "region"],
)
metrics_tag_ctime = Summary(
    "cloudkeeper_plugin_tag_aws_ctime_tag_ctime_seconds",
    "Tag AWS ctime Plugin Time it took the tag_ctime() method",
)


class TagAWSCtimePlugin(BasePlugin):
    def __init__(self):
        super().__init__()
        self.name = "tag_aws_ctime"
        self.exit = threading.Event()
        self.run_lock = threading.Lock()
        if ArgumentParser.args.tag_aws_ctime:
            log.debug("AWS ctime Tagger plugin initializing")
            add_event_listener(EventType.SHUTDOWN, self.shutdown)
            add_event_listener(
                EventType.COLLECT_FINISH,
                self.aws_ctime_tagger,
                blocking=False,
                timeout=900,
            )
        else:
            self.exit.set()

    def __del__(self):
        remove_event_listener(EventType.COLLECT_FINISH, self.aws_ctime_tagger)
        remove_event_listener(EventType.SHUTDOWN, self.shutdown)

    def go(self):
        self.exit.wait()

    def aws_ctime_tagger(self, event: Event):
        if not self.run_lock.acquire(blocking=False):
            log.error("AWS ctime Tagger is already running")
            return

        graph = event.data
        log.info("AWS ctime Tagger called")
        try:
            self.tag_ctime(graph)
        except Exception:
            raise
        finally:
            self.run_lock.release()

    @metrics_tag_ctime.time()
    def tag_ctime(self, graph: Graph):
        now = datetime.utcnow().replace(tzinfo=timezone.utc).isoformat()
        pt = ParallelTagger(self.name)
        with graph.lock.read_access:
            for node in graph.nodes:
                if not isinstance(
                    node, (AWSALBTargetGroup, AWSEC2NetworkAcl, AWSEC2KeyPair, AWSVPC)
                ):
                    continue

                if "cloudkeeper:ctime" not in node.tags:
                    cloud = node.cloud(graph)
                    account = node.account(graph)
                    region = node.region(graph)
                    if (
                        not isinstance(cloud, BaseCloud)
                        or not isinstance(account, BaseAccount)
                        or not isinstance(region, BaseRegion)
                    ):
                        log.error(
                            (
                                f"Resource {node.rtdname} has no valid "
                                "cloud, account or region associated with it"
                            )
                        )
                        continue

                    log.debug(
                        (
                            f"Resource {node.rtdname} in cloud {cloud.name} account "
                            f"{account.dname} region {region.name} has no cloudkeeper:ctime tag "
                            f"- setting it because ctime is not available via the AWS API"
                        )
                    )
                    pt_key = f"{cloud.id}-{account.id}-{region.id}"
                    pt.add(node, "cloudkeeper:ctime", now, pt_key)
                    metrics_ctime_tags.labels(
                        cloud=cloud.name, account=account.dname, region=region.name
                    ).inc()
        pt.run()

    @staticmethod
    def add_args(arg_parser: ArgumentParser) -> None:
        arg_parser.add_argument(
            "--tag-aws-ctime",
            help="Tag AWS ctime (default: False)",
            dest="tag_aws_ctime",
            action="store_true",
            default=False,
        )

    def shutdown(self, event: Event):
        log.debug(
            f"Received event {event.event_type} - shutting down AWS ctime tagging plugin"
        )
        self.exit.set()
