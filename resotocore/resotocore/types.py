from typing import Any, Optional, Callable, Union, Dict, Sequence, Mapping

Json = Dict[str, Any]

JsonArray = Sequence[Union[Mapping[str, Any], Sequence[Any], str, int, float, None]]
JsonElement = Union[Mapping[str, Any], Sequence[Any], str, int, float, bool, None]

ValidationResult = Optional[Any]
ValidationFn = Callable[[Any], ValidationResult]
