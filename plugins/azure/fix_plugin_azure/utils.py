from typing import Callable, Dict, TypeVar, Any
from attr import frozen
import functools

from fixlib.baseresources import StatName, MetricName, MetricUnit


T = TypeVar("T")


def rgetattr(obj: Any, attr: str, *args: Any) -> Any:
    def _getattr(obj: Any, attr: str) -> Any:
        return getattr(obj, attr, *args)

    return functools.reduce(_getattr, [obj] + attr.split("."))


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
