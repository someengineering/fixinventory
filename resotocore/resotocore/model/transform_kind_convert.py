from resotolib.durations import parse_duration, duration_str
from resotocore.util import utc, utc_str, from_utc


def datetime_before_now(duration_string: str) -> str:
    duration = parse_duration(duration_string)
    timestamp = utc() - duration
    return utc_str(timestamp)


def duration_until_now(at: str) -> str:
    timestamp = from_utc(at)
    duration = utc() - timestamp
    return duration_str(duration, precision=2)


converters = {"duration_to_datetime": (datetime_before_now, duration_until_now)}
