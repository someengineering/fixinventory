from typing import Dict, Any, Type, Union

from resotolib.types import Json
from resotolib.units import parse
from jsonbender import Bender, bend


class Bend(Bender):
    def __init__(self, mappings: Dict[str, Bender], **kwargs):
        super().__init__(**kwargs)
        self._mappings = mappings

    def execute(self, value: Json) -> Any:
        return bend(self._mappings, value)


class MapValue(Bender):
    def __init__(self, lookup: Dict[str, Any], default: Any = None, **kwargs):
        super().__init__(**kwargs)
        self._lookup = lookup
        self._default = default

    def execute(self, value: str) -> Any:
        return self._lookup.get(value, self._default)


class StringToUnitNumber(Bender):
    def __init__(self, unit: str, expected: Type[Union[int, float]] = float, **kwargs):
        super().__init__(**kwargs)
        self._unit = unit
        self._expected = expected

    def execute(self, value: str) -> Union[int, float]:
        return self._expected(parse(value).to(self._unit))


class CPUCoresToNumber(Bender):
    def execute(self, source: str) -> float:
        return float(source[:-1]) / 1000 if source.endswith("m") else float(source)
