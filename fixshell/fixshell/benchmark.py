import time
from functools import wraps
from typing import Optional, Any, TypeVar, Callable, cast, Mapping, Union
from fixlib.utils import iec_size_format


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
        self.query_stats: Optional[Mapping[str, Union[str, int, float]]] = None
        self.tty_columns: int = 80
        self.tty_rows: int = 20

    def set_tty_size(self, columns: int, rows: int) -> None:
        self.tty_columns = columns
        self.tty_rows = rows

    @if_should_benchmark
    def request_sent(self) -> None:
        self.request_started_at = time.time()
        self.first_byte_at = None
        self.last_byte_at = None
        self.query_stats = None

    @if_should_benchmark
    def first_byte_received(self) -> None:
        self.first_byte_at = time.time()

    @if_should_benchmark
    def last_byte_received(self, response_headers: Optional[Mapping[str, str]] = None) -> None:
        self.last_byte_at = time.time()
        self.calculate_times()
        if response_headers:
            self.query_stats = parse_metrics(response_headers.get("Query-Stats"))

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

        header_text = "Benchmark Results"
        header_inner = f"| {header_text} |"
        header_length = len(header_inner)
        side_length = (self.tty_columns - 2 - header_length) // 2
        header = f"┌{'─' * side_length}{header_inner}{'─' * (self.tty_columns - 2 - side_length - header_length)}┐"
        footer = f"└{'─' * (self.tty_columns - 2)}┘"

        data = {
            "Network first byte": f"{self.time_to_first_byte * 1000:.1f} ms",
            "Network last byte": f"{self.time_to_last_byte * 1000:.1f} ms",
        }
        if self.query_stats and len(self.query_stats) > 0:
            data.update(
                {
                    "Unbounded total matches": f"{self.query_stats.get('fullCount', 0)}",
                    "Documents filtered out": f"{self.query_stats.get('filtered', 0)}",
                    "Index-based document scans": f"{self.query_stats.get('scanned_index', 0)}",
                    "Full document scans": f"{self.query_stats.get('scanned_full', 0)}",
                    "Database execution time": f"{self.query_stats.get('execution_time', 0) * 1000:.1f} ms",
                    "Peak DB memory usage": f"{iec_size_format(float(self.query_stats.get('peak_memory_usage', 0.0)))}",
                    "Index lookup cursors created": f"{self.query_stats.get('cursorsCreated', 0)}",
                    "Existing cursors repurposed": f"{self.query_stats.get('cursorsRearmed', 0)}",
                    "Cache hits": f"{self.query_stats.get('cacheHits', 0)}",
                    "Cache misses": f"{self.query_stats.get('cacheMisses', 0)}",
                }
            )
        max_item_width = max(len(f"| {key}: {value} ") for key, value in data.items())
        columns = max(1, self.tty_columns // max_item_width)
        columns = min(columns, len(data))
        column_width = self.tty_columns // columns

        lines = []
        items = list(data.items())
        for i in range(0, len(items), columns):
            line = ""
            for j in range(columns):
                if i + j < len(items):
                    column_item = ""
                    if j > 0:
                        column_item += " "
                    key, value = items[i + j]
                    column_item += f"│ {key}: "
                    column_item += value.rjust(column_width - len(column_item) - 1)
                    line += column_item
                else:
                    line += " │".ljust(column_width - 1)
            line += "│".rjust(self.tty_columns - len(line))
            lines.append(line)

        message = f"\n{header}\n" + "\n".join(lines) + f"\n{footer}\n"
        print_fn(message)


def parse_metrics(input_string: Optional[str]) -> Mapping[str, Union[str, int, float]]:
    if not input_string or not str(input_string).strip():
        return {}

    key_value_pairs = [pair.strip() for pair in input_string.split(",")]
    result_dict = {}
    for pair in key_value_pairs:
        key, value = pair.split("=")
        try:
            converted_value: Union[int, float, str] = int(value)
        except ValueError:
            try:
                converted_value = float(value)
            except ValueError:
                converted_value = value
        result_dict[key] = converted_value
    return result_dict
