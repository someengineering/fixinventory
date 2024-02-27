from typing import Any, Optional, Callable, Dict, Sequence, Union, Mapping, Literal

from jsons import set_deserializer

# Ideally we would be able to define it like this:
# JsonElement = Union[ Mapping[str, JsonElement], Sequence[JsonElement], str, int, float, bool, None]
# Sadly python does not support recursive types yet, so we try to narrow it to:
JsonElement = Union[
    str,
    int,
    float,
    bool,
    None,
    Mapping[str, Any],
    Sequence[Union[Mapping[str, Any], Sequence[Any], str, int, float, bool, None]],
]
JsonArray = Sequence[JsonElement]
Json = Dict[str, Any]


ValidationResult = Optional[Any]
ValidationFn = Callable[[Any], ValidationResult]

EdgeType = Literal["default", "delete"]


# make sure jsons does not do something clever, when a json element needs to be parsed
# omitting this deserializer, will read a string into a list of characters etc.
def parse_js_element(elem: JsonElement, _: type = object, **kwargs: object) -> JsonElement:
    return elem


set_deserializer(parse_js_element, [str, int, float, bool, None])
