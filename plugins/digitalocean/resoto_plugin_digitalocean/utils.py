import resotolib.logging
from typing import Iterable, List, Union, Callable, Any, Dict
from datetime import datetime

log = resotolib.logging.getLogger("resoto." + __name__)


def get_result_data(result: Dict, value: Union[str, Callable]) -> Any:
    """Returns data from a GCP API call result dict.

    Args:
        result: Dict containing the result or a GCP API execute() call.
        value: Either directly the name of a key found in result or
            a callable like a lambda that finds the relevant data withing
            result.
    """
    data = None
    if callable(value):
        try:
            data = value(result)
        except Exception:
            log.exception(f"Exception while trying to fetch data calling {value}")
    elif value in result:
        data = result[value]
    return data

def iso2datetime(ts: str) -> datetime:
    if ts is None:
        return
    if ts.endswith("Z"):
        ts = ts[:-1] + "+00:00"
    if ts is not None:
        return datetime.fromisoformat(ts)

def region_slug_to_id(slug: str) -> str:
    return f"do:region:{slug}"