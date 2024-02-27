from fixcore.db.model import QueryModel, GraphUpdate
from fixcore.model.model import Model
from fixcore.query.model import Query


def test_query_model() -> None:
    model = QueryModel(Query.by("test"), Model.from_kinds([]), {"a": "1", "b": "True", "c": "false", "d": "true"})
    assert model.is_set("a")
    assert model.is_set("b")
    assert not model.is_set("c")
    assert model.is_set("d")


def test_graph_update() -> None:
    gu1 = GraphUpdate(1, 2, 3, 4, 5, 6)
    gu2 = GraphUpdate(6, 5, 4, 3, 2, 1)
    assert gu1.all_changes() == gu2.all_changes() == 21
    assert gu1 + gu2 == GraphUpdate(7, 7, 7, 7, 7, 7)
