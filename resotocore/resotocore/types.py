from typing import Any, Optional, Callable, Dict, Sequence, Union, Mapping

JsonElement = Union[str, int, float, bool, None, Mapping[str, Any], Sequence[Any]]
JsonArray = Sequence[JsonElement]
# See discussion here: https://github.com/python/typing/issues/182
Json = Dict[str, Any]


ValidationResult = Optional[Any]
ValidationFn = Callable[[Any], ValidationResult]
