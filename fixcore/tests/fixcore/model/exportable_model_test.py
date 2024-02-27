from fixcore.model.exportable_model import json_export_simple_schema
from fixcore.model.model import Model


def test_simple_model(person_model: Model) -> None:
    simple = {n["fqn"]: n for n in json_export_simple_schema(person_model)}
    assert len(simple) == 10
    address = simple["Address"]
    assert len(address["properties"]) == 7
    id = address["properties"]["id"]
    assert id["kind"]["type"] == "simple"
    tags = address["properties"]["tags"]
    assert tags["kind"]["type"] == "dictionary"
    assert tags["kind"]["key"]["fqn"] == "string"
    assert tags["kind"]["value"]["fqn"] == "string"
