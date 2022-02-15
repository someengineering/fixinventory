from typing import List, Optional, Set, Tuple

from aiohttp import ClientSession
from networkx import MultiDiGraph

from core.cli.model import ParsedCommands, ParsedCommand
from core.config import ConfigEntity
from core.db import EstimatedQueryCost
from core.db.model import GraphUpdate
from core.model.model import Model, Kind
from core.model.typed_model import from_js, to_js
from core.task.model import Subscriber, Subscription
from core.types import Json, JsonElement
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
                return AccessJson.wrap_list(await response.json())
            else:
                raise AttributeError(await response.text())

    @staticmethod
    def graph_to_json(graph: MultiDiGraph) -> List[Json]:
        ga: List[Json] = [{**node, "type": "node"} for _, node in graph.nodes(data=True)]
        for from_node, to_node, data in graph.edges(data=True):
            ga.append({"type": "edge", "from": from_node, "to": to_node, "edge_type": data["edge_type"]})
        return ga

    async def merge_graph(self, graph: str, update: MultiDiGraph) -> GraphUpdate:
        js = self.graph_to_json(update)
        async with self.session.post(self.base_path + f"/graph/{graph}/merge", json=js) as r:
            if r.status == 200:
                return from_js(await r.json(), GraphUpdate)
            else:
                raise AttributeError(await r.text())

    async def add_to_batch(
        self, graph: str, update: MultiDiGraph, batch_id: Optional[str] = None
    ) -> Tuple[str, GraphUpdate]:
        js = self.graph_to_json(update)
        props = {"batch_id": batch_id} if batch_id else None
        async with self.session.post(self.base_path + f"/graph/{graph}/batch/merge", json=js, params=props) as r:
            if r.status == 200:
                return r.headers["BatchId"], from_js(await r.json(), GraphUpdate)
            else:
                raise AttributeError(await r.text())

    async def list_batches(self, graph: str) -> List[AccessJson]:
        async with self.session.get(self.base_path + f"/graph/{graph}/batch") as r:
            if r.status == 200:
                return AccessJson.wrap_list(await r.json())
            else:
                raise AttributeError(await r.text())

    async def commit_batch(self, graph: str, batch_id: str) -> None:
        async with self.session.post(self.base_path + f"/graph/{graph}/batch/{batch_id}") as r:
            if r.status == 200:
                return None
            else:
                raise AttributeError(await r.text())

    async def abort_batch(self, graph: str, batch_id: str) -> None:
        async with self.session.delete(self.base_path + f"/graph/{graph}/batch/{batch_id}") as r:
            if r.status == 200:
                return None
            else:
                raise AttributeError(await r.text())

    async def query_graph_raw(self, graph: str, query: str) -> AccessJson:
        async with self.session.post(self.base_path + f"/graph/{graph}/query/raw", data=query) as r:
            if r.status == 200:
                return AccessJson.wrap_object(await r.json())
            else:
                raise AttributeError(await r.text())

    async def query_graph_explain(self, graph: str, query: str) -> EstimatedQueryCost:
        async with self.session.post(self.base_path + f"/graph/{graph}/query/explain", data=query) as r:
            if r.status == 200:
                return from_js(await r.json(), EstimatedQueryCost)
            else:
                raise AttributeError(await r.text())

    async def query_list(self, graph: str, query: str) -> List[AccessJson]:
        async with self.session.post(self.base_path + f"/graph/{graph}/query/list", data=query) as r:
            if r.status == 200:
                return AccessJson.wrap_list(await r.json())
            else:
                raise AttributeError(await r.text())

    async def query_graph(self, graph: str, query: str) -> List[AccessJson]:
        async with self.session.post(self.base_path + f"/graph/{graph}/query/graph", data=query) as r:
            if r.status == 200:
                return AccessJson.wrap_list(await r.json())
            else:
                raise AttributeError(await r.text())

    async def query_aggregate(self, graph: str, query: str) -> List[AccessJson]:
        async with self.session.post(self.base_path + f"/graph/{graph}/query/aggregate", data=query) as r:
            if r.status == 200:
                return AccessJson.wrap_list(await r.json())
            else:
                raise AttributeError(await r.text())

    async def search(self, graph: str, term: str) -> List[AccessJson]:
        async with self.session.get(self.base_path + f"/graph/{graph}/search", params={"term": term}) as r:
            if r.status == 200:
                return AccessJson.wrap_list(await r.json())
            else:
                raise AttributeError(await r.text())

    async def subscribers(self) -> List[Subscriber]:
        async with self.session.get(self.base_path + f"/subscribers") as r:
            if r.status == 200:
                return from_js(await r.json(), List[Subscriber])
            else:
                raise AttributeError(await r.text())

    async def subscribers_for_event(self, event_type: str) -> List[Subscriber]:
        async with self.session.get(self.base_path + f"/subscribers/for/{event_type}") as r:
            if r.status == 200:
                return from_js(await r.json(), List[Subscriber])
            else:
                raise AttributeError(await r.text())

    async def subscriber(self, uid: str) -> Optional[Subscriber]:
        async with self.session.get(self.base_path + f"/subscriber/{uid}") as r:
            if r.status == 200:
                return from_js(await r.json(), Subscriber)
            else:
                return None

    async def update_subscriber(self, uid: str, subscriptions: List[Subscription]) -> Optional[Subscriber]:
        async with self.session.put(self.base_path + f"/subscriber/{uid}", json=to_js(subscriptions)) as r:
            if r.status == 200:
                return from_js(await r.json(), Subscriber)
            else:
                raise AttributeError(await r.text())

    async def add_subscription(self, uid: str, subscription: Subscription) -> Subscriber:
        props = {
            "timeout": str(int(subscription.timeout.total_seconds())),
            "wait_for_completion": str(subscription.wait_for_completion),
        }
        async with self.session.post(
            self.base_path + f"/subscriber/{uid}/{subscription.message_type}", params=props
        ) as r:
            if r.status == 200:
                return from_js(await r.json(), Subscriber)
            else:
                raise AttributeError(await r.text())

    async def delete_subscription(self, uid: str, subscription: Subscription) -> Subscriber:
        async with self.session.delete(self.base_path + f"/subscriber/{uid}/{subscription.message_type}") as r:
            if r.status == 200:
                return from_js(await r.json(), Subscriber)
            else:
                raise AttributeError(await r.text())

    async def delete_subscriber(self, uid: str) -> None:
        async with self.session.delete(self.base_path + f"/subscriber/{uid}") as r:
            if r.status == 204:
                return None
            else:
                raise AttributeError(await r.text())

    async def cli_evaluate(self, graph: str, command: str, **env: str) -> List[Tuple[ParsedCommands, List[AccessJson]]]:
        props = {"graph": graph, "section": "reported", **env}
        async with self.session.post(self.base_path + f"/cli/evaluate", data=command, params=props) as r:
            if r.status == 200:
                return [
                    (
                        ParsedCommands(from_js(json["parsed"], List[ParsedCommand]), json["env"]),
                        AccessJson.wrap(json["execute"]),
                    )
                    for json in await r.json()
                ]
            else:
                raise AttributeError(await r.text())

    async def cli_execute(self, graph: str, command: str, **env: str) -> List[JsonElement]:
        props = {"graph": graph, "section": "reported", **env}
        async with self.session.post(self.base_path + f"/cli/execute", data=command, params=props) as r:
            if r.status == 200:
                return AccessJson.wrap_list(await r.json())  # type: ignore
            else:
                raise AttributeError(await r.text())

    async def cli_info(self) -> AccessJson:
        async with self.session.get(self.base_path + f"/cli/info") as r:
            if r.status == 200:
                return AccessJson.wrap_object(await r.json())
            else:
                raise AttributeError(await r.text())

    async def configs(self) -> List[ConfigEntity]:
        async with self.session.get(self.base_path + f"/configs") as r:
            if r.status == 200:
                return [ConfigEntity(cid, config) for cid, config in (await r.json()).items()]
            else:
                raise AttributeError(await r.text())

    async def config(self, config_id: str) -> AccessJson:
        async with self.session.get(self.base_path + f"/config/{config_id}") as r:
            if r.status == 200:
                return AccessJson.wrap_object(await r.json())
            else:
                raise AttributeError(await r.text())

    async def patch_config(self, config_id: str, json: Json) -> AccessJson:
        async with self.session.patch(self.base_path + f"/config/{config_id}", json=json) as r:
            if r.status == 200:
                return AccessJson.wrap_object(await r.json())
            else:
                raise AttributeError(await r.text())

    async def delete_config(self, config_id: str) -> None:
        async with self.session.delete(self.base_path + f"/config/{config_id}") as r:
            if r.status == 204:
                return None
            else:
                raise AttributeError(await r.text())

    async def ping(self) -> str:
        async with self.session.get(self.base_path + f"/system/ping") as r:
            if r.status == 200:
                return await r.text()
            else:
                raise AttributeError(await r.text())

    async def ready(self) -> str:
        async with self.session.get(self.base_path + f"/system/ready") as r:
            if r.status == 200:
                return await r.text()
            else:
                raise AttributeError(await r.text())
