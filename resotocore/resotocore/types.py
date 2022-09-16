from typing import Any, Optional, Callable, Dict, Sequence, Union, Mapping, Literal

JsonElement = Union[Mapping[str, Any], Sequence[Any], int, float, bool, str, None]
JsonArray = Sequence[JsonElement]
# See discussion here: https://github.com/python/typing/issues/182
Json = Dict[str, Any]


ValidationResult = Optional[Any]
ValidationFn = Callable[[Any], ValidationResult]

EdgeType = Literal["default", "delete"]
