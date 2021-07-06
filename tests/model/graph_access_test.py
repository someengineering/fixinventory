import collections
from datetime import date

import jsons
from networkx import DiGraph
from deepdiff import DeepDiff
from core.model.graph_access import GraphAccess, GraphBuilder
from tests.db.graphdb_test import Foo

FooTuple = collections.namedtuple("FooTuple", ["a", "b", "c", "d", "e", "f", "g"],
                                  defaults=["", 0, [], "foo", {"a": 12, "b": 32}, date.fromisoformat('2021-03-29'),
                                            1.234567])


def test_access_node():
    g = DiGraph()
    g.add_node(1, data=FooTuple(a="1"))
    access = GraphAccess(g)
    _, json, sha, _, _ = access.node(1)
    assert sha == 'ae15ce169cbf1048cf1da6bd537eb0259437c630d45b82ce2fb2321d0b3059cd'
    assert json == {'a': '1', 'b': 0, 'c': [], 'd': 'foo', 'e': {'a': 12, 'b': 32}, 'f': '2021-03-29', 'g': 1.234567}
    assert access.node(2) is None


def test_marshal_unmarshal():
    foo = Foo("12")
    name = type(foo).__name__
    clazz = globals()[name]
    js = jsons.dumps(foo)
    again = jsons.loads(js, cls=clazz)
    assert DeepDiff(foo, again, truncate_datetime='second') == {}
    assert 4 == 4


def test_content_hash():
    # the order of properties should not matter for the content hash
    g = DiGraph()
    g.add_node(1, data={"a": {"a": 1, "c": 2, "b": 3}, "c": 2, "b": 3, "d": "foo", "z": True})
    g.add_node(2, data={"z": True, "c": 2, "b": 3, "a": {"b": 3, "c": 2, "a": 1}, "d": "foo"})  # change the order

    access = GraphAccess(g)
    sha1 = access.node(1)[2]
    sha2 = access.node(2)[2]
    assert sha1 == sha2


def test_root():
    g = DiGraph()
    g.add_node(1, data=Foo("1"))
    g.add_node(2, data=Foo("2"))
    g.add_node(3, data=Foo("3"))
    g.add_edge(1, 2)
    g.add_edge(2, 3)
    access = GraphAccess(g)
    assert access.root() == 1


def test_not_visited():
    g = DiGraph()
    g.add_node(1, data=FooTuple(a="1"))
    g.add_node(2, data=FooTuple(a="2"))
    g.add_node(3, data=FooTuple(a="3"))
    g.add_node(4, data=FooTuple(a="4"))
    access = GraphAccess(g)
    access.node(1)
    access.node(3)
    not_visited = list(access.not_visited_nodes())
    assert len(not_visited) == 2
    assert not_visited[0][2] == "54307723f66f858dec826875ab2636bd83daec4f2ce2141347977f7efb07220d"
    assert not_visited[1][2] == "bfb6c25b89368ac7167226590f153a3c519d9a8200dcc6c18f75ffbc8673850c"


def test_edges():
    g = DiGraph()
    g.add_node(1, data=Foo("1"))
    g.add_node(2, data=Foo("2"))
    g.add_node(3, data=Foo("3"))
    g.add_node(4, data=Foo("4"))
    g.add_edge(1, 2)
    g.add_edge(1, 3)
    g.add_edge(2, 3)
    g.add_edge(2, 4)
    g.add_edge(3, 4)
    access = GraphAccess(g)
    assert list(access.edges) == [(1, 2), (1, 3), (2, 3), (2, 4), (3, 4)]
    assert access.has_edge(1, 2)
    assert not access.has_edge(1, 9)
    assert access.has_edge(2, 3)
    assert list(access.not_visited_edges()) == [(1, 3), (2, 4), (3, 4)]


def test_flatten():
    js = {"id": "blub", "d": "2021-06-18T10:31:34Z", "i": 0, "s": "hello", "a": [{"a": "one"}, {"b": "two"}]}
    flat = GraphBuilder.flatten(js)
    assert flat == "blub 2021-06-18T10:31:34Z 0 hello one two"
