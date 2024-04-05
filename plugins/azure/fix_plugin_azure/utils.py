from typing import Callable, Dict, TypeVar, Any
from attr import frozen
import functools

from fixlib.baseresources import StatName, MetricName, MetricUnit


T = TypeVar("T")


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
