import asyncio
import json
import logging
import string
from functools import partial
from random import SystemRandom
from typing import List, Union, AsyncGenerator, Callable, Awaitable, Any

from aiohttp import web, WSMsgType, WSMessage
from aiohttp.web_exceptions import HTTPRedirection
from aiohttp.web_request import Request
from aiohttp.web_response import StreamResponse
from aiohttp_swagger3 import SwaggerFile, SwaggerUiSettings
from networkx import DiGraph
from networkx.readwrite import cytoscape_data

from core import feature
from core.db.db_access import DbAccess
from core.db.model import QueryModel
from core.error import NotFoundError
from core.event_bus import EventBus
from core.model.graph_access import GraphBuilder
from core.model.model import Kind, Model
from core.types import Json
from core.model.model_handler import ModelHandler
from core.model.typed_model import to_js, from_js
from core.query.query_parser import parse_query

log = logging.getLogger(__name__)
Section = Union[str, List[str]]
RequestHandler = Callable[[Request], Awaitable[StreamResponse]]


class Api:

    def __init__(self, db: DbAccess, model_handler: ModelHandler, event_bus: EventBus):
        self.db = db
        self.model_handler = model_handler
        self.event_bus = event_bus
        self.app = web.Application(middlewares=[self.error_handler])
        r = "reported"
        d = "desired"
        rd = [r, d]
        SwaggerFile(
            self.app,
            spec_file="./static/api-doc.yaml",
            swagger_ui_settings=SwaggerUiSettings(path="/api-doc", layout="BaseLayout", docExpansion="none"),
        )
        self.app.add_routes([
            # Model operations
            web.get("/model", self.get_model),
            web.get("/model/uml", self.model_uml),
            web.patch("/model", self.update_model),
            # CRUD Graph operations
            web.get("/graph", self.list_graphs),
            web.get("/graph/{graph_id}", partial(self.get_node, r)),
            web.post("/graph/{graph_id}", self.create_graph),
            web.delete("/graph/{graph_id}", self.wipe),
            # Reported section of the graph
            web.get("/graph/{graph_id}/reported/search", self.search_graph),
            web.post("/graph/{graph_id}/reported/node/{node_id}/under/{parent_node_id}", self.create_node),
            web.get("/graph/{graph_id}/reported/node/{node_id}", partial(self.get_node, r)),
            web.patch("/graph/{graph_id}/reported/node/{node_id}", partial(self.update_node, r, r)),
            web.delete("/graph/{graph_id}/reported/node/{node_id}", self.delete_node),
            web.put("/graph/{graph_id}/reported/sub_graph/{parent_node_id}", self.update_sub_graph),
            web.post("/graph/{graph_id}/reported/batch/sub_graph/{parent_node_id}", self.update_sub_graph_batch),
            web.get("/graph/{graph_id}/reported/batch", self.list_batches),
            web.post("/graph/{graph_id}/reported/batch/{batch_id}", self.commit_batch),
            web.delete("/graph/{graph_id}/reported/batch/{batch_id}", self.abort_batch),
            web.post("/graph/{graph_id}/reported/query", partial(self.query, r, r)),
            web.post("/graph/{graph_id}/reported/query/raw", partial(self.raw, r, r)),
            web.post("/graph/{graph_id}/reported/query/explain", partial(self.explain, r)),
            web.post("/graph/{graph_id}/reported/query/list", partial(self.query_list, r, r)),
            web.post("/graph/{graph_id}/reported/query/graph", partial(self.query_graph_stream, r, r)),
            # Desired section of the graph
            web.get("/graph/{graph_id}/desired/node/{node_id}", partial(self.get_node, rd)),
            web.patch("/graph/{graph_id}/desired/node/{node_id}", partial(self.update_node, d, rd)),
            web.post("/graph/{graph_id}/desired/query", partial(self.query, d, rd)),
            web.post("/graph/{graph_id}/desired/query/raw", partial(self.raw, d, rd)),
            web.post("/graph/{graph_id}/desired/query/explain", partial(self.explain, d, rd)),
            web.post("/graph/{graph_id}/desired/query/list", partial(self.query_list, d, rd)),
            web.post("/graph/{graph_id}/desired/query/graph", partial(self.query_graph_stream, d, rd)),
            # Event operations
            web.get("/events", self.handle_events),  # type: ignore
            # Serve static filed
            web.get("", self.redirect_to_ui),
            web.static('/static', './static/'),
        ])

    async def redirect_to_ui(self, request: Request) -> StreamResponse:
        raise web.HTTPFound('/static/index.html')

    async def handle_events(self, request: Request) -> None:
        show = request.query["show"].split(",") if "show" in request.query else ["*"]
        ws = web.WebSocketResponse()
        await ws.prepare(request)

        async def receive() -> None:
            async for msg in ws:
                try:
                    if isinstance(msg, WSMessage) and msg.type == WSMsgType.TEXT and len(msg.data.strip()) > 0:
                        log.info(f"Incoming message: type={msg.type} data={msg.data} extra={msg.extra}")
                        js = json.loads(msg.data)
                        if "name" in js and "event" in js:
                            await self.event_bus.emit(js["name"], js["event"])
                        else:
                            raise AttributeError(f"Expected event but got: {msg}")
                except BaseException:
                    # do not allow any exception - it will destroy the async fiber and cleanup
                    await ws.close()

        async def send() -> None:
            try:
                with self.event_bus.subscribe(show) as events:
                    while True:
                        event = await events.get()
                        await ws.send_str(json.dumps(event) + "\n")
            except BaseException:
                # do not allow any exception - it will destroy the async fiber and cleanup
                await ws.close()

        await asyncio.gather(asyncio.create_task(receive()), asyncio.create_task(send()))

    async def model_uml(self, request: Request) -> StreamResponse:
        show = request.query["show"].split(",") if "show" in request.query else None
        result = await self.model_handler.uml_image(show)
        response = web.StreamResponse()
        response.headers['Content-Type'] = 'image/svg+xml'
        await response.prepare(request)
        await response.write_eof(result)
        return response

    async def get_model(self, _: Request) -> StreamResponse:
        md = await self.model_handler.load_model()
        return web.json_response(to_js(md))

    async def update_model(self, request: Request) -> StreamResponse:
        js = await request.json()
        kinds: List[Kind] = from_js(js, List[Kind])  # type: ignore
        model = await self.model_handler.update_model(kinds)
        return web.json_response(to_js(model))

    async def get_node(self, section: str, request: Request) -> StreamResponse:
        graph_id = request.match_info.get('graph_id', 'ns')
        node_id = request.match_info.get('node_id', 'root')
        graph = self.db.get_graph_db(graph_id)
        node = await graph.get_node(node_id, section)
        if node is None:
            return web.HTTPNotFound(text=f"No such node with id {node_id} in graph {graph_id}")
        else:
            return web.json_response(node)

    async def create_node(self, request: Request) -> StreamResponse:
        graph_id = request.match_info.get('graph_id', 'ns')
        node_id = request.match_info.get('node_id', 'some_existing')
        parent_node_id = request.match_info.get('parent_node_id', 'root')
        graph = self.db.get_graph_db(graph_id)
        item = await request.json()
        md = await self.model_handler.load_model()
        node = await graph.create_node(md, node_id, item, parent_node_id)
        return web.json_response(node)

    async def update_node(self, section: str, result_section: Section, request: Request) -> StreamResponse:
        graph_id = request.match_info.get('graph_id', 'ns')
        node_id = request.match_info.get('node_id', 'some_existing')
        graph = self.db.get_graph_db(graph_id)
        patch = await request.json()
        md = await self.model_handler.load_model()
        node = await graph.update_node(md, section, result_section, node_id, patch)
        return web.json_response(node)

    async def delete_node(self, request: Request) -> StreamResponse:
        graph_id = request.match_info.get('graph_id', 'ns')
        node_id = request.match_info.get('node_id', 'some_existing')
        if node_id == "root":
            raise AttributeError("Root node can not be deleted!")
        graph = self.db.get_graph_db(graph_id)
        await graph.delete_node(node_id)
        return web.HTTPNoContent()

    async def list_graphs(self, _: Request) -> StreamResponse:
        return web.json_response(await self.db.list_graphs())

    async def create_graph(self, request: Request) -> StreamResponse:
        graph_id = request.match_info.get('graph_id', 'ns')
        graph = await self.db.create_graph(graph_id)
        root = await graph.get_node("root", "reported")
        return web.json_response(root)

    async def update_sub_graph(self, request: Request) -> StreamResponse:
        log.info("Received put_sub_graph request")
        md = await self.model_handler.load_model()
        graph = await self.read_graph(request, md)
        under_node_id = request.match_info.get('parent_node_id', 'root')
        graph_db = self.db.get_graph_db(request.match_info.get('graph_id', 'ns'))
        info = await graph_db.update_sub_graph(md, graph, under_node_id)
        return web.json_response(to_js(info))

    async def update_sub_graph_batch(self, request: Request) -> StreamResponse:
        log.info("Received put_sub_graph_batch request")
        md = await self.model_handler.load_model()
        graph = await self.read_graph(request, md)
        under_node_id = request.match_info.get('parent_node_id', 'root')
        graph_db = self.db.get_graph_db(request.match_info.get('graph_id', 'ns'))
        rnd = ''.join(SystemRandom().choice(string.ascii_letters) for _ in range(12))
        batch_id = request.query.get('batch_id', rnd)
        info = await graph_db.update_sub_graph(md, graph, under_node_id, batch_id)
        return web.json_response(to_js(info), headers={"BatchId": batch_id})

    async def list_batches(self, request: Request) -> StreamResponse:
        graph_db = self.db.get_graph_db(request.match_info.get('graph_id', 'ns'))
        batch_updates = await graph_db.list_in_progress_batch_updates()
        return web.json_response(batch_updates)

    async def commit_batch(self, request: Request) -> StreamResponse:
        graph_db = self.db.get_graph_db(request.match_info.get('graph_id', 'ns'))
        batch_id = request.match_info.get('batch_id', 'some_existing')
        await graph_db.commit_batch_update(batch_id)
        return web.HTTPOk(body="Batch committed.")

    async def abort_batch(self, request: Request) -> StreamResponse:
        graph_db = self.db.get_graph_db(request.match_info.get('graph_id', 'ns'))
        batch_id = request.match_info.get('batch_id', 'some_existing')
        await graph_db.abort_batch_update(batch_id)
        return web.HTTPOk(body="Batch aborted.")

    async def raw(self, query_section: str, request: Request) -> StreamResponse:
        query_string = await request.text()
        graph_db = self.db.get_graph_db(request.match_info.get('graph_id', 'ns'))
        m = await self.model_handler.load_model()
        q = parse_query(query_string)
        query, bind_vars = graph_db.to_query(QueryModel(q, m, query_section))
        return web.json_response({"query": query, "bind_vars": bind_vars})

    async def explain(self, query_section: str, request: Request) -> StreamResponse:
        query_string = await request.text()
        graph_db = self.db.get_graph_db(request.match_info.get('graph_id', 'ns'))
        q = parse_query(query_string)
        m = await self.model_handler.load_model()
        result = await graph_db.explain(QueryModel(q, m, query_section))
        return web.json_response(result)

    async def search_graph(self, request: Request) -> StreamResponse:
        if not feature.DB_SEARCH:
            raise AttributeError("This feature is not enabled!")
        if "term" not in request.query:
            raise AttributeError("Expect query parameter term to be defined!")
        query_string = request.query.get("term", "")
        limit = int(request.query.get("limit", "10"))
        graph_db = self.db.get_graph_db(request.match_info.get('graph_id', 'ns'))
        result = graph_db.search(query_string, limit)
        # noinspection PyTypeChecker
        return await self.stream_response_from_gen(request, (to_js(a) async for a in result))

    async def query_list(self, query_section: str, result_section: Section, request: Request) -> StreamResponse:
        query_string = await request.text()
        graph_db = self.db.get_graph_db(request.match_info.get('graph_id', 'ns'))
        q = parse_query(query_string)
        m = await self.model_handler.load_model()
        result = graph_db.query_list(QueryModel(q, m, query_section, result_section))
        # noinspection PyTypeChecker
        return await self.stream_response_from_gen(request, (to_js(a) async for a in result))

    async def cytoscape(self, query_section: str, result_section: Section, request: Request) -> StreamResponse:
        query_string = await request.text()
        graph_db = self.db.get_graph_db(request.match_info.get('graph_id', 'ns'))
        q = parse_query(query_string)
        m = await self.model_handler.load_model()
        result = await graph_db.query_graph(QueryModel(q, m, query_section, result_section))
        node_link_data = cytoscape_data(result)
        return web.json_response(node_link_data)

    async def query_graph_stream(self, query_section: str, result_section: Section, request: Request) -> StreamResponse:
        query_string = await request.text()
        q = parse_query(query_string)
        m = await self.model_handler.load_model()
        graph_db = self.db.get_graph_db(request.match_info.get('graph_id', 'ns'))
        gen = graph_db.query_graph_gen(QueryModel(q, m, query_section, result_section))
        # noinspection PyTypeChecker
        return await self.stream_response_from_gen(request, (item async for _, item in gen))

    async def query(self, query_section: str, result_section: Section, request: Request) -> StreamResponse:
        if request.headers.get("format") == "cytoscape":
            return await self.cytoscape(query_section, result_section, request)
        if request.headers.get("format") == "graph":
            return await self.query_graph_stream(query_section, result_section, request)
        elif request.headers.get("format") == "list":
            return await self.query_list(query_section, result_section, request)
        else:
            return web.HTTPPreconditionFailed(text="Define format header. `format: [graph|list|cytoscape]`")

    async def wipe(self, request: Request) -> StreamResponse:
        graph_id = request.match_info.get('graph_id', 'ns')
        if "truncate" in request.query:
            await self.db.get_graph_db(graph_id).wipe()
            return web.HTTPOk(body="Graph truncated.")
        else:
            await self.db.delete_graph(graph_id)
            return web.HTTPOk(body="Graph deleted.")

    @staticmethod
    async def read_graph(request: Request, md: Model) -> DiGraph:
        async def stream_to_graph() -> DiGraph:
            builder = GraphBuilder(md)
            async for line in request.content:
                if len(line.strip()) == 0:
                    continue
                builder.add_node(json.loads(line))
            log.info("Graph read into memory")
            return builder.graph

        async def json_to_graph() -> DiGraph:
            json_array = await request.json()
            log.info("Json read into memory")
            builder = GraphBuilder(md)
            if isinstance(json_array, list):
                for doc in json_array:
                    builder.add_node(doc)
            log.info("Graph read into memory")
            return builder.graph

        if request.content_type == "application/json":
            return await json_to_graph()
        elif request.content_type == "application/x-ndjson":
            return await stream_to_graph()
        else:
            raise AttributeError("Can not read graph. Currently supported formats: json and ndjson!")

    @staticmethod
    async def stream_response_from_gen(request: Request, gen: AsyncGenerator[Json, None]) -> StreamResponse:
        async def respond_json() -> StreamResponse:
            response = web.StreamResponse(status=200, headers={'Content-Type': 'application/json'})
            await response.prepare(request)
            await response.write("[".encode("utf-8"))
            first = True
            async for item in gen:
                js = json.dumps(to_js(item))
                sep = "," if not first else ""
                await response.write(f"{sep}\n{js}".encode("utf-8"))
                first = False
            await response.write_eof("]".encode("utf-8"))
            return response

        async def respond_ndjson() -> StreamResponse:
            response = web.StreamResponse(status=200, headers={'Content-Type': 'application/x-ndjson'})
            await response.prepare(request)
            async for item in gen:
                js = json.dumps(to_js(item))
                await response.write(f"{js}\n".encode("utf-8"))
            await response.write_eof()
            return response

        if request.headers.get("accept") == "application/x-ndjson":
            return await respond_ndjson()
        else:
            return await respond_json()

    @staticmethod
    async def error_handler(_: Any, handler: RequestHandler) -> RequestHandler:
        async def middleware_handler(request: Request) -> StreamResponse:
            try:
                response = await handler(request)
                return response
            except HTTPRedirection as e:
                # redirects are implemented as exceptions in aiohttp for whatever reason...
                raise e
            except NotFoundError as e:
                kind = type(e).__name__
                message = f"Error: {kind}\nMessage: {str(e)}"
                log.info(f'Request {request} has failed with exception: {message}', exc_info=e)
                return web.HTTPNotFound(text=message)
            except Exception as e:
                kind = type(e).__name__
                content = e.message if hasattr(e, 'message') else str(e)  # type: ignore
                message = f"Error: {kind}\nMessage: {content}"
                log.warning(f'Request {request} has failed with exception: {message}', exc_info=e)
                return web.HTTPBadRequest(text=message)

        return middleware_handler
