from typing import Any, Optional, Callable, Dict, Sequence, Union, Mapping, Literal

JsonElement = Union[
    Mapping[str, Any],
    Sequence[Union[Mapping[str, Any], Sequence[Any], str, int, float, bool, None]],
    str,
    int,
    float,
    bool,
    None,
]
JsonArray = Sequence[JsonElement]  # type: ignore
Json = Dict[str, Any]


ValidationResult = Optional[Any]
ValidationFn = Callable[[Any], ValidationResult]

EdgeType = Literal["default", "delete"]
