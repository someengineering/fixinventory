from typing import Any, Optional, Callable, Union

Json = dict[str, Any]

JsonElement = Union[Json, str, int, float, bool, None]

ValidationResult = Optional[Any]
ValidationFn = Callable[[Any], ValidationResult]
