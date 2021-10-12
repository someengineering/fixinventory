from datetime import timedelta

from durations_nlp import Duration

from core.util import utc, utc_str, from_utc


def datetime_before_now(duration_string: str) -> str:
    duration = timedelta(seconds=Duration(duration_string).seconds)
    timestamp = utc() - duration
    return utc_str(timestamp)


def duration_until_now(at: str) -> str:
    timestamp = from_utc(at)
    duration = utc() - timestamp
    return f"{duration.seconds}s"


converters = {"duration_to_datetime": (datetime_before_now, duration_until_now)}
