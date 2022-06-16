from resotolib.durations import parse_duration, time_units
from resotocore.util import utc, utc_str, from_utc


def datetime_before_now(duration_string: str) -> str:
    duration = parse_duration(duration_string)
    timestamp = utc() - duration
    return utc_str(timestamp)


def duration_until_now(at: str) -> str:
    timestamp = from_utc(at)
    duration = utc() - timestamp
    seconds = duration.total_seconds()
    found = False
    count = 0
    result = ""
    for unit, _, factor in time_units:
        if unit:
            if seconds > factor:
                found = True
                num = int(seconds / factor)
                seconds = seconds - (num * factor)
                result += f"{num}{unit}"
            if found:
                count += 1
            # precision: we only use 2 units to describe the age.
            if count >= 2:
                break

    # in case the duration is less than one second
    return result if result else "0s"


converters = {"duration_to_datetime": (datetime_before_now, duration_until_now)}
