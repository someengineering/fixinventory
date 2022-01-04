from typing import List, Optional, Set

from aiohttp import ClientSession
from networkx import MultiDiGraph

from core.db.model import GraphUpdate
from core.model.model import Model, Kind
from core.model.typed_model import from_js, to_js
from core.types import Json
from core.util import AccessJson


class ApiClient:
    """
    The ApiClient interacts with a running core instance via the REST interface.
    This client is used for testing purposes only.
    """

    def __init__(self, base_path: str, session: ClientSession):
        self.base_path = base_path
        self.session = session

    async def model(self) -> Model:
        async with self.session.get(self.base_path + "/model") as response:
            model_json = await response.json()
            model = Model.from_kinds([from_js(kind, Kind) for kind in model_json["kinds"].values()])  # type: ignore
            return model

    async def update_model(self, update: List[Kind]) -> Model:
        async with self.session.patch(self.base_path + "/model", json=to_js(update)) as response:
            model_json = await response.json()
            model = Model.from_kinds([from_js(kind, Kind) for kind in model_json["kinds"].values()])  # type: ignore
            return model

    async def list_graphs(self) -> Set[str]:
        async with self.session.get(self.base_path + f"/graph") as response:
            return set(await response.json())

    async def get_graph(self, name: str) -> Optional[AccessJson]:
        async with self.session.post(self.base_path + f"/graph/{name}") as response:
            return AccessJson(await response.json()) if response.status == 200 else None

    async def create_graph(self, name: str) -> AccessJson:
        async with self.session.post(self.base_path + f"/graph/{name}") as response:
            # root node
            return AccessJson(await response.json())

    async def delete_graph(self, name: str, truncate: bool = False) -> str:
        props = {"truncate": "true"} if truncate else {}
        async with self.session.delete(self.base_path + f"/graph/{name}", params=props) as response:
            # root node
            return await response.text()

    async def create_node(self, graph: str, parent_node_id: str, node_id: str, node: Json) -> AccessJson:
        async with self.session.post(
            self.base_path + f"/graph/{graph}/node/{node_id}/under/{parent_node_id}", json=node
        ) as response:
            if response.status == 200:
                return AccessJson(await response.json())
            else:
                raise AttributeError(await response.text())

    async def patch_node(self, graph: str, node_id: str, node: Json, section: Optional[str] = None) -> AccessJson:
        section_path = f"/section/{section}" if section else ""
        async with self.session.patch(
            self.base_path + f"/graph/{graph}/node/{node_id}{section_path}", json=node
        ) as response:
            if response.status == 200:
                return AccessJson(await response.json())
            else:
                raise AttributeError(await response.text())

    async def get_node(self, graph: str, node_id: str) -> AccessJson:
        async with self.session.get(self.base_path + f"/graph/{graph}/node/{node_id}") as response:
            if response.status == 200:
                return AccessJson(await response.json())
            else:
                raise AttributeError(await response.text())

    async def delete_node(self, graph: str, node_id: str) -> None:
        async with self.session.delete(self.base_path + f"/graph/{graph}/node/{node_id}") as response:
            if response.status == 204:
                return None
            else:
                raise AttributeError(await response.text())

    async def patch_nodes(self, graph: str, nodes: List[Json]) -> List[AccessJson]:
        async with self.session.patch(self.base_path + f"/graph/{graph}/nodes", json=nodes) as response:
            if response.status == 200:
                return AccessJson.wrap(await response.json(), None)  # type: ignore
            else:
                raise AttributeError(await response.text())

    async def merge_graph(self, graph: str, update: MultiDiGraph) -> GraphUpdate:
        ga: List[Json] = [{**node, "type": "node"} for _, node in update.nodes(data=True)]
        for from_node, to_node in update.edges():
            ga.append({"type": "edge", "from": from_node, "to": to_node})

        async with self.session.post(self.base_path + f"/graph/{graph}/merge", json=ga) as response:
            if response.status == 200:
                return from_js(await response.json(), GraphUpdate)
            else:
                raise AttributeError(await response.text())
