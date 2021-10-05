from prometheus_async.aio import time as prom_time
from prometheus_client import Histogram, Counter, Gauge

# All exported metrics are listed here
MethodDuration = Histogram("method_call_duration", "Duration of single method call", ["module", "name"])
RequestCount = Counter("requests_total", "Total Request Count", ["method", "endpoint", "http_status"])
RequestLatency = Histogram("request_latency_seconds", "Request latency", ["endpoint"])
RequestInProgress = Gauge("requests_in_progress_total", "Requests in progress", ["endpoint", "method"])


def timed(module: str, name: str):
    """
    Use this annotation on a method and measure the duration of the call.
    :param module: the name of the component.
    :param name: the name of the method to be measured.
    :return: the wrapped function
    """
    return prom_time(MethodDuration.labels(module=module, name=name))
