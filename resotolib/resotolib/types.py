from typing import Dict, Any, Union, Mapping, Sequence, TypeVar, Callable, Any

# mypy does not support recursive type definitions
# See discussion here: https://github.com/python/typing/issues/182
Json = Dict[str, Any]
JsonElement = Union[str, int, float, bool, None, Mapping[str, Any], Sequence[Any]]
DecoratedFn = TypeVar("DecoratedFn", bound=Callable[..., Any])
