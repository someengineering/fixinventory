import time
from functools import wraps
from typing import Callable, Any, TypeVar, cast

from prometheus_client import Histogram, Counter, Gauge

# All exported metrics are listed here
Prefix = "resotocore_"
MethodDuration = Histogram(f"{Prefix}method_call_duration", "Duration of single method call", ["module", "name"])
RequestCount = Counter(f"{Prefix}requests_total", "Total Request Count", ["method", "endpoint", "http_status"])
RequestLatency = Histogram(f"{Prefix}request_latency_seconds", "Request latency", ["endpoint"])
RequestInProgress = Gauge(f"{Prefix}requests_in_progress_total", "Requests in progress", ["endpoint", "method"])

# Create a type that is bound to the underlying wrapped function
# This way all signature information is preserved!
DecoratedFn = TypeVar("DecoratedFn", bound=Callable[..., Any])


def perf_now() -> float:
    return time.perf_counter()


def timed(module: str, name: str, is_async: bool = True) -> Callable[[DecoratedFn], DecoratedFn]:
    """
    Use this annotation on a method and measure the duration of the call.
    :param module: the name of the component.
    :param name: the name of the method to be measured.
    :param is_async: set to false if the underlying method is not async
    :return: the wrapped function
    """
    metric = MethodDuration.labels(module=module, name=name)

    def sync_time_wrapper(fn: DecoratedFn) -> DecoratedFn:
        @wraps(fn)
        def async_time_decorated(*args: Any, **kwargs: Any) -> Any:
            start_time = perf_now()
            try:
                rv = fn(*args, **kwargs)
                return rv
            finally:
                metric.observe(perf_now() - start_time)

        return cast(DecoratedFn, async_time_decorated)

    def async_time_wrapper(fn: DecoratedFn) -> DecoratedFn:
        @wraps(fn)
        async def async_time_decorated(*args: Any, **kwargs: Any) -> Any:
            start_time = perf_now()
            try:
                rv = await fn(*args, **kwargs)
                return rv
            finally:
                metric.observe(perf_now() - start_time)

        return cast(DecoratedFn, async_time_decorated)

    return async_time_wrapper if is_async else sync_time_wrapper
