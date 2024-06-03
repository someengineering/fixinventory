import time
from functools import wraps
from typing import Optional, Any, TypeVar, Callable, cast


T = TypeVar("T", bound=Callable[..., Any])


def if_should_benchmark(method: T) -> T:
    @wraps(method)
    def wrapper(self: Any, *args: Any, **kwargs: Any) -> Any:
        if getattr(self, "should_benchmark", False):
            return method(self, *args, **kwargs)
        return None

    return cast(T, wrapper)


class Benchmark:
    def __init__(self, should_benchmark: bool = False) -> None:
        self.should_benchmark = should_benchmark
        self.request_started_at: Optional[float] = None
        self.first_byte_at: Optional[float] = None
        self.last_byte_at: Optional[float] = None
        self.time_to_first_byte: Optional[float] = None
        self.time_to_last_byte: Optional[float] = None

    @if_should_benchmark
    def request_sent(self) -> None:
        self.request_started_at = time.time()
        self.first_byte_at = None
        self.last_byte_at = None

    @if_should_benchmark
    def first_byte_received(self) -> None:
        self.first_byte_at = time.time()

    @if_should_benchmark
    def last_byte_received(self) -> None:
        self.last_byte_at = time.time()
        self.calculate_times()

    @if_should_benchmark
    def calculate_times(self) -> None:
        if not self.request_started_at or not self.first_byte_at or not self.last_byte_at:
            return
        self.time_to_first_byte = self.first_byte_at - self.request_started_at
        self.time_to_last_byte = self.last_byte_at - self.request_started_at

    @if_should_benchmark
    def print_results(self, print_fn: Callable[[str], None] = print) -> None:
        if self.time_to_first_byte is None or self.time_to_last_byte is None:
            print_fn("Timing data is incomplete.")
            return
        header = "┌─────────| Benchmark Results |─────────┐"
        footer = "└───────────────────────────────────────┘"
        text_width = len(header)
        time_to_first_byte_text = "│ Time to first byte: "
        time_to_last_byte_text = "│ Time to last byte: "
        time_to_first_byte = f"{self.time_to_first_byte * 1000:.1f} ms │"
        time_to_last_byte = f"{self.time_to_last_byte * 1000:.1f} ms │"
        padded_first_byte = time_to_first_byte.rjust(text_width - len(time_to_first_byte_text))
        padded_last_byte = time_to_last_byte.rjust(text_width - len(time_to_last_byte_text))

        message = (
            f"\n{header}\n{time_to_first_byte_text}{padded_first_byte}\n"
            f"{time_to_last_byte_text}{padded_last_byte}\n{footer}"
        )
        print_fn(message)
