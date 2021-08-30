import cloudkeeper.logging
import threading
from datetime import timedelta
from cloudkeeper.baseplugin import BasePlugin
from cloudkeeper.baseresources import BaseInstance, BaseVolume
from cloudkeeper.args import ArgumentParser
from cloudkeeper.utils import parse_delta
from cloudkeeper.event import (
    Event,
    EventType,
    add_event_listener,
    remove_event_listener,
)

log = cloudkeeper.logging.getLogger("cloudkeeper." + __name__)

age_ranges = ["30d", "7d", "1d", "12h", "8h", "4h", "2h", "1h"]
age_range_lookup = {}
for range in age_ranges:
    td = parse_delta(range)
    age_range_lookup[range] = td


def age_range(age: timedelta) -> str:
    for range in age_ranges:
        if age >= age_range_lookup.get(range, parse_delta(range)):
            return range
    return "0s"


class MetricsAgeRangePlugin(BasePlugin):
    def __init__(self):
        super().__init__()
        self.name = "metrics_age_range"
        self.exit = threading.Event()
        if ArgumentParser.args.metrics_age_range:
            add_event_listener(
                EventType.GENERATE_METRICS,
                self.generate_age_range_metrics,
                blocking=True,
            )
            add_event_listener(EventType.SHUTDOWN, self.shutdown)
        else:
            self.exit.set()

    def __del__(self):
        remove_event_listener(
            EventType.GENERATE_METRICS, self.generate_age_range_metrics
        )
        remove_event_listener(EventType.SHUTDOWN, self.shutdown)

    def go(self):
        self.exit.wait()

    @staticmethod
    def generate_age_range_metrics(event: Event):
        graph = event.data
        log.info("Generating Age Range Metrics")
        with graph.lock.read_access:
            for node in graph.nodes():
                node_age = getattr(node, "age", None)
                if not isinstance(node_age, timedelta):
                    continue
                node_age_range = age_range(node.age)

                metric_value = 1
                if isinstance(node, BaseInstance):
                    metric_name = "instances_age_range"
                    metric_help = "Age Range of Instances"
                    metric_labels = [
                        "cloud",
                        "account",
                        "region",
                        "type",
                        "status",
                        "age",
                    ]
                    metric_label_values = (
                        node.cloud(graph).name,
                        node.account(graph).dname,
                        node.region(graph).name,
                        node.instance_type,
                        node.instance_status,
                        node_age_range,
                    )
                    node.add_metric(
                        metric_name,
                        metric_value,
                        metric_help,
                        metric_labels,
                        metric_label_values,
                    )
                elif isinstance(node, BaseVolume):
                    metric_name = "volumes_age_range"
                    metric_help = "Age Range of Volumes"
                    metric_labels = [
                        "cloud",
                        "account",
                        "region",
                        "type",
                        "status",
                        "age",
                    ]
                    metric_label_values = (
                        node.cloud(graph).name,
                        node.account(graph).dname,
                        node.region(graph).name,
                        node.volume_type,
                        node.volume_status,
                        node_age_range,
                    )
                    node.add_metric(
                        metric_name,
                        metric_value,
                        metric_help,
                        metric_labels,
                        metric_label_values,
                    )
                else:
                    continue

                log.debug(
                    (
                        f"Adding metrics for {node.rtdname}, "
                        f"created {node.age} ago, age range {node_age_range}"
                    )
                )

    @staticmethod
    def add_args(arg_parser: ArgumentParser) -> None:
        arg_parser.add_argument(
            "--metrics-age-range",
            help="Metrics: Age Range (default: False)",
            default=False,
            dest="metrics_age_range",
            action="store_true",
        )

    def shutdown(self, event: Event):
        log.debug(
            f"Received event {event.event_type} - shutting down age range metrics plugin"
        )
        self.exit.set()
