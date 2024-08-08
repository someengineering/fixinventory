import logging
from datetime import datetime
from typing import Callable, Dict, TypeVar, Any
from attr import frozen
import functools

from fixlib.baseresources import StatName, MetricName, MetricUnit
from fixlib.json_bender import F

T = TypeVar("T")
log = logging.getLogger("fix.plugins.azure")


def rgetattr(obj: Any, attr: str, *args: Any) -> Any:
    """
    Recursively retrieves the value from a nested class based on the provided attr path.
    """

    def _getattr(obj: Any, attr: str) -> Any:
        return getattr(obj, attr, *args)

    return functools.reduce(_getattr, [obj] + attr.split("."))


def rgetvalue(data: Dict[str, Any], key_path: str, default: Any = None) -> Any:
    """
    Recursively retrieves the value from a nested dictionary based on the provided key path.
    """
    keys = key_path.split(".")
    nested_value = data
    for key in keys:
        if isinstance(nested_value, Dict) and key in nested_value:
            nested_value = nested_value[key]
        else:
            return default
    return nested_value


def identity(x: T) -> T:
    return x


def case_insensitive_eq(left: T, right: T) -> bool:
    if isinstance(left, str) and isinstance(right, str):
        return left.lower() == right.lower()
    else:
        return left == right


def from_str_to_typed(config_type: str, value: str) -> Any:
    def set_bool(val: str) -> bool:
        if val.lower() == "on":
            return True
        return False

    type_mapping = {
        "Enumeration": lambda x: set_bool(x) if x.lower() in ["on", "off"] else str(x),
        "Integer": int,
        "Numeric": float,
        "Set": lambda x: [s.strip() for s in x.split(",")],
        "String": str,
        "Boolean": set_bool,
    }
    try:
        return type_mapping[config_type](value)  # type: ignore
    except Exception as e:
        log.warning(f"An error occured while typing value: {e}")
        return None


TimestampToIso = F(lambda x: datetime.fromtimestamp(x).isoformat())
NoneIfEmpty = F(lambda x: x if x else None)


@frozen(kw_only=True)
class MetricNormalization:
    metric_name: MetricName
    unit: MetricUnit
    stat_map: Dict[str, StatName] = {
        "minimum": StatName.min,
        "average": StatName.avg,
        "maximum": StatName.max,
    }
    normalize_value: Callable[[float], float] = identity
