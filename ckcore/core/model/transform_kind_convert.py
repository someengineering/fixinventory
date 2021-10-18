from datetime import timedelta

from durations_nlp import Duration

from core.util import utc, utc_str, from_utc


def datetime_before_now(duration_string: str) -> str:
    duration = timedelta(seconds=Duration(duration_string).seconds)
    timestamp = utc() - duration
    return utc_str(timestamp)


unit_in_secs = {
    "y": 365 * 24 * 3600,
    "M": 31 * 24 * 3600,
    "w": 7 * 24 * 3600,
    "d": 24 * 3600,
    "h": 3600,
    "m": 60,
    "s": 1,
}


def duration_until_now(at: str) -> str:
    timestamp = from_utc(at)
    duration = utc() - timestamp
    seconds = duration.total_seconds()
    found = False
    count = 0
    result = ""
    for unit, factor in unit_in_secs.items():
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
