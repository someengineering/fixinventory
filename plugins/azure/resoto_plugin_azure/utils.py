from typing import Callable, Dict, TypeVar
from attr import frozen


T = TypeVar("T")


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
