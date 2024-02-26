import pytest

from fixcore.db.db_access import DbAccess
from fixcore.ids import GraphName
from fixcore.model.model import Model, ComplexKind, predefined_kinds
from fixcore.model.model_handler import ModelHandlerDB


@pytest.mark.asyncio
async def test_update_delete(db_access: DbAccess, person_model: Model) -> None:
    # step 0: clean slate
    name = GraphName("ns")
    mdb = await db_access.get_graph_model_db(name)
    await mdb.wipe()
    pdk = len(predefined_kinds)
    handler = ModelHandlerDB(db_access, "http://localhost:8000")
    # step 1: put current model
    model = await handler.update_model(name, list(person_model.kinds.values()), True)
    assert len(model) == len(person_model)
    # step 2: update with only one kind
    boo = ComplexKind("boo", [], [])
    model = await handler.update_model(name, [boo], True)
    assert len(model) == pdk + 1
    assert len([a async for a in mdb.keys()]) == pdk + 1


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
