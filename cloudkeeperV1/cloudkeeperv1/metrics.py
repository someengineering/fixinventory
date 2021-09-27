from cklib.logging import log


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
