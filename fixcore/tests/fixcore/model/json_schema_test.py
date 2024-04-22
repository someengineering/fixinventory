from fixcore.model.json_schema import json_schema
from fixcore.model.model import Model


def test_schema(foo_model: Model) -> None:
    schema = json_schema(foo_model)
    # The resource is one of the possible 8 types
    assert len(schema["oneOf"]) == 8

    # base type - all properties are defined, additional properties are allowed
    assert schema["$defs"]["base"]["required"] == ["id", "kind"]
    assert schema["$defs"]["base"]["properties"].keys() == {"id", "kind", "ctime"}
    assert schema["$defs"]["base"]["additionalProperties"] is True

    # final resource type - all properties are defined, additional properties are not allowed
    assert schema["$defs"]["some_complex"]["required"] == []
    expected = {"id", "kind", "ctime", "cloud", "account", "parents", "children", "nested"}
    assert schema["$defs"]["some_complex"]["properties"].keys() == expected
    assert schema["$defs"]["some_complex"]["additionalProperties"] is False

    # simple types are defined
    assert schema["$defs"]["datetime"]["type"] == "string"
    assert schema["$defs"]["datetime"]["format"] == "date-time"
