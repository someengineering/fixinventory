from datetime import datetime
from typing import Union, Callable, Any, Dict, Optional

import resotolib.logging

log = resotolib.logging.getLogger("resoto." + __name__)


def get_result_data(result: Dict, value: Union[str, Callable]) -> Any:
    """Returns data from a DO API call result dict.

    Args:
        result: Dict containing the result
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


def iso2datetime(ts: Optional[str]) -> Optional[datetime]:
    if ts is None:
        return
    if ts.endswith("Z"):
        ts = ts[:-1] + "+00:00"
    if ts is not None:
        return datetime.fromisoformat(ts)


def region_id(slug: str) -> str:
    return f"do:region:{slug}"


def project_id(value: str) -> str:
    return f"do:project:{value}"


def droplet_id(value: int) -> str:
    return f"do:droplet:{value}"


def kubernetes_id(value: str) -> str:
    return f"do:kubernetes:{value}"


def volume_id(value: int) -> str:
    return f"do:volume:{value}"


def vpc_id(value: str) -> str:
    return f"do:vpc:{value}"


def snapshot_id(value: int) -> str:
    return f"do:snapshot:{value}"


def loadbalancer_id(value: int) -> str:
    return f"do:loadbalancer:{value}"


def floatingip_id(value: str) -> str:
    return f"do:floatingip:{value}"


def database_id(value: str) -> str:
    return f"do:dbaas:{value}"


def image_id(value: str) -> str:
    return f"do:image:{value}"


def space_id(value: str) -> str:
    return f"do:space:{value}"


def app_id(value: str) -> str:
    return f"do:app:{value}"
