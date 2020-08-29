import re
import cloudkeeper.logging
from cloudkeeper.args import ArgumentParser
from cloudkeeper.baseresources import *
from prometheus_client import Summary
from prometheus_client.core import GaugeMetricFamily
from collections import defaultdict
from typing import List, Tuple

log = cloudkeeper.logging.getLogger(__name__)

metrics_graph2metrics = Summary(
    "cloudkeeper_graph2metrics_seconds", "Time it took the graph2metrics() method"
)


class GraphCollector:
    """A Prometheus compatible Collector implementation"""

    def __init__(self, gc) -> None:
        self.gc = gc

    def collect(self):
        """collect() is being called whenever the /metrics endpoint is requested"""
        log.debug("GraphCollector generating metrics")
        metrics = self.gc.metrics

        for metric in metrics.values():
            yield metric


@metrics_graph2metrics.time()
def graph2metrics(graph):
    metrics = {}
    num = {}

    with graph.lock.read_access:
        for node in graph.nodes:
            if not isinstance(node, BaseResource):
                continue
            try:
                for metric, data in node.metrics_description.items():
                    if metric not in metrics:
                        metrics[metric] = GaugeMetricFamily(
                            f"cloudkeeper_{metric}",
                            data["help"],
                            labels=mlabels(data["labels"]),
                        )
                        num[metric] = defaultdict(lambda: 0)
                for metric, data in node.metrics(graph).items():
                    for labels, value in data.items():
                        if metric not in num:
                            log.error(
                                (
                                    f"Couldn't find metric {metric} in num when"
                                    f" processing node {node}"
                                )
                            )
                            continue
                        num[metric][mtags(labels, node)] += value
            except AttributeError:
                log.exception(f"Encountered invalid node in graph {node}")

        for metric in metrics:
            for labels, value in num[metric].items():
                metrics[metric].add_metric(labels, value)

    return metrics


# The mlabels() and mtags() functions are being used to dynamically add more labels
# to each metric. The idea here is that via a cli arg we can specify resource tags
# that should be exported as labels for each metric. This way we don't have to touch
# the code itself any time we want to add another metrics dimension. Instead we could
# just have a tag like 'project' and then use the '--tag-as-metrics-label project'
# argument to export another label based on the given tag.
def mlabels(labels: List) -> List:
    """Takes a list of labels and appends any cli arg specified tag names to it."""
    if ArgumentParser.args and ArgumentParser.args.metrics_tag_as_label:
        for tag in ArgumentParser.args.metrics_tag_as_label:
            labels.append(make_valid_label(tag))
    return labels


def mtags(labels: Tuple, node: BaseResource) -> Tuple:
    """Takes a tuple containing labels and adds any tags specified as cli args to it.

    Returns the extended tuple.
    """
    if not type(labels) is tuple:
        if type(labels) is list:
            labels = tuple(labels)
        else:
            labels = tuple([labels])
    ret = list(labels)
    if ArgumentParser.args and ArgumentParser.args.metrics_tag_as_label:
        for tag in ArgumentParser.args.metrics_tag_as_label:
            if tag in node.tags:
                tag_value = node.tags[tag]
                ret.append(tag_value)
            else:
                ret.append("")
    return tuple(ret)


def make_valid_label(label: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_]", "_", label)
