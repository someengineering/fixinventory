from typing import Dict, Any, Optional, Callable, Union

Json = Dict[str, Any]

JsonElement = Union[Json, str, int, float, bool, None]

ValidationResult = Optional[Any]
ValidationFn = Callable[[Any], ValidationResult]
