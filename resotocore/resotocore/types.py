from typing import Any, Optional, Callable, Dict, Sequence, Union, Mapping, Literal

# Ideally we would be able to define it like this:
# JsonElement = Union[ Mapping[str, JsonElement], Sequence[JsonElement], str, int, float, bool, None]
# Sadly python does not support recursive types yet, so we try to narrow it to:
JsonElement = Union[
    Mapping[str, Any],
    Sequence[Union[Mapping[str, Any], Sequence[Any], str, int, float, bool, None]],
    str,
    int,
    float,
    bool,
    None,
]
JsonArray = Sequence[JsonElement]
Json = Dict[str, Any]


ValidationResult = Optional[Any]
ValidationFn = Callable[[Any], ValidationResult]

EdgeType = Literal["default", "delete"]
