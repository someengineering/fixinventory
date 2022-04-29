from resotolib.logger import log


class Metrics:
    def __init__(self) -> None:
        self.live = {}
        self.staging = {}

    def swap(self) -> None:
        self.live = self.staging
        self.staging = {}


class GraphCollector:
    """A Prometheus compatible Collector implementation"""

    def __init__(self, metrics: Metrics) -> None:
        self.metrics = metrics

    def collect(self):
        """collect() is being called whenever the /metrics endpoint is requested"""
        log.debug("generating metrics")

        for metric in self.metrics.live.values():
            yield metric
