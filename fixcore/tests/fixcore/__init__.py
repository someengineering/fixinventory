from typing import Optional

from networkx import MultiDiGraph

from tests.fixcore.db.graphdb_test import Foo, Bla
from fixcore.model.graph_access import EdgeTypes, GraphAccess
from fixcore.model.typed_model import to_js
from fixcore.types import EdgeType, Json, JsonElement


def create_graph(bla_text: str, width: int = 10) -> MultiDiGraph:
    graph = MultiDiGraph()

    def add_edge(from_node: str, to_node: str, edge_type: EdgeType = EdgeTypes.default) -> None:
        key = GraphAccess.edge_key(from_node, to_node, edge_type)
        graph.add_edge(from_node, to_node, key, edge_type=edge_type)

    def add_node(uid: str, kind: str, node: Optional[Json] = None, replace: bool = False) -> None:
        reported = {**(node if node else to_js(Foo(uid))), "kind": kind}
        refs = {"cloud_id": "collector", "account_id": "sub_root"} if kind not in ("graph_root", "cloud") else {}

        graph.add_node(
            uid,
            id=uid,
            kinds=[kind],
            reported=reported,
            desired={"node_id": uid},
            metadata={"node_id": uid, "replace": replace},
            ancestors={
                "cloud": {"reported": {"name": "collector", "id": "collector"}},
                "account": {"reported": {"name": "sub_root", "id": "sub_root"}},
            },
            refs=refs,
        )

    # root -> collector -> sub_root -> **rest
    add_node("root", "graph_root")
    add_node("collector", "cloud", replace=True)
    add_node("sub_root", "account")
    add_edge("root", "collector")
    add_edge("collector", "sub_root")

    for o in range(0, width):
        oid = str(o)
        add_node(oid, "foo")
        add_edge("sub_root", oid)
        for i in range(0, width):
            iid = f"{o}_{i}"
            add_node(iid, "bla", node=to_js(Bla(iid, name=bla_text)))
            add_edge(oid, iid)
            add_edge(iid, oid, EdgeTypes.delete)
    return graph
