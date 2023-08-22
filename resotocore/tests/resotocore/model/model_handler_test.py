import pytest

from resotocore.db.db_access import DbAccess
from resotocore.ids import GraphName
from resotocore.model.model_handler import ModelHandlerDB


@pytest.mark.asyncio
async def test_uml_generation(db_access: DbAccess) -> None:
    handler = ModelHandlerDB(db_access, "http://localhost:8000")
    image = await handler.uml_image(GraphName("ns"), "puml")
    assert image.startswith(b"@startuml")
    assert image.endswith(b"@enduml")
    assert b"class graph_root {\n**id**: string\n**name**: string\n**tags**: dictionary[string, string]\n}" in image
    image2 = await handler.uml_image(
        GraphName("ns"),
        "puml",
        with_inheritance=False,
        with_base_classes=True,
        with_subclasses=True,
        with_predecessors=True,
        with_successors=True,
        with_properties=False,
        link_classes=True,
        only_aggregate_roots=False,
        sort_props=False,
    )
    assert b"class graph_root [[#graph_root]] {\n\n}" in image2
