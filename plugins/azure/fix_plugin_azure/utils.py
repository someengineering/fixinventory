from typing import Callable, Dict, TypeVar, Any
from attr import frozen
import functools


T = TypeVar("T")


def rgetattr(obj: Any, attr: str, *args: Any) -> Any:
    def _getattr(obj: Any, attr: str) -> Any:
        return getattr(obj, attr, *args)

    return functools.reduce(_getattr, [obj] + attr.split("."))


def identity(x: T) -> T:
    return x


@frozen(kw_only=True)
class MetricNormalization:
    name: str
    stat_map: Dict[str, str] = {
        "minimum": "min",
        "maximum": "max",
        "average": "avg",
        "total": "sum",
    }
    normalize_value: Callable[[float], float] = identity
