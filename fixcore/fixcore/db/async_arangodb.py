from __future__ import annotations

import logging
import re
from contextlib import asynccontextmanager
from numbers import Number
from typing import (
    Optional,
    MutableMapping,
    Sequence,
    Union,
    Any,
    Dict,
    List,
    Callable,
    AsyncIterator,
    Set,
    AsyncContextManager,
    Awaitable,
)

from arango import ArangoServerError, CursorNextError
from arango.collection import StandardCollection, VertexCollection, EdgeCollection
from arango.cursor import Cursor
from arango.database import StandardDatabase, Database, TransactionDatabase
from arango.graph import Graph
from arango.typings import Json, Jsons

from fixcore.async_extensions import run_async
from fixcore.error import QueryTookToLongError
from fixcore.util import identity
from fixcore.ids import GraphName

log = logging.getLogger(__name__)


class AsyncCursor(AsyncIterator[Any]):
    def __init__(
        self,
        cursor: Cursor,
        *,
        query: str,
        bind_vars: Optional[Json] = None,
        trafo: Optional[Callable[[Json], Optional[Any]]] = None,
        flatten_nodes_and_edges: bool = False,
    ):
        self.query = query
        self.bind_vars = bind_vars
        self.cursor = cursor
        self.visited_node: Set[str] = set()
        self.visited_edge: Set[str] = set()
        self.deferred_edges: List[Json] = []
        self.cursor_exhausted = False
        self.trafo: Callable[[Json], Optional[Any]] = trafo if trafo else identity  # type: ignore
        self.vt_len: Optional[int] = None
        self.on_hold: Optional[Json] = None
        self.get_next: Callable[[], Awaitable[Optional[Json]]] = (
            self.next_filtered if flatten_nodes_and_edges else self.next_element
        )

    async def __anext__(self) -> Any:
        # if there is an on-hold element: unset and return it
        # background: a graph node contains vertex and edge information.
        # since this method can only return one element at a time, the edge is put on-hold for vertex+edge data.
        if self.on_hold:
            res = self.on_hold
            self.on_hold = None
            return res
        elif self.cursor_exhausted:
            return await self.next_deferred_edge()
        else:
            try:
                while True:
                    element = await self.get_next()
                    if element is not None:
                        return element
            except StopAsyncIteration:
                # iterator exhausted: all elements have been processed. Now yield all deferred edges.
                self.cursor_exhausted = True
                return await self.next_deferred_edge()

    def close(self) -> None:
        if stats := self.cursor.statistics():
            log.debug(f"Query {self.query} with bind_vars {self.bind_vars} took {stats}")
        self.cursor.close(ignore_missing=True)

    def count(self) -> Optional[int]:
        return self.cursor.count()

    def full_count(self) -> Optional[int]:
        return stats.get("fullCount") if (stats := self.cursor.statistics()) else None

    async def next_element(self) -> Optional[Json]:
        element = await self.next_from_db()
        return self.trafo(element)

    async def next_filtered(self) -> Optional[Json]:
        element = await self.next_from_db()
        vertex: Optional[Json] = None
        edge = None
        try:
            _key = element["_key"]
            if _key not in self.visited_node:
                self.visited_node.add(_key)
                vertex = self.trafo(element)

            from_id = element.get("_from")
            to_id = element.get("_to")
            link_id = element.get("_link_id")
            if from_id is not None and to_id is not None and link_id is not None:
                if link_id not in self.visited_edge:
                    self.visited_edge.add(link_id)
                    if not self.vt_len:
                        self.vt_len = len(re.sub("/.*$", "", from_id)) + 1
                    edge = {
                        "type": "edge",
                        # example: vertex_name/node_id -> node_id
                        "from": from_id[self.vt_len :],  # noqa: E203
                        # example: vertex_name/node_id -> node_id
                        "to": to_id[self.vt_len :],  # noqa: E203
                        # example: vertex_name_default/edge_id -> default
                        "edge_type": re.sub("/.*$", "", link_id[self.vt_len :]),  # noqa: E203
                    }
                    # make sure that both nodes of the edge have been visited already
                    if from_id not in self.visited_node or to_id not in self.visited_node:
                        self.deferred_edges.append(edge)
                        edge = None
            # if the vertex is not returned: return the edge
            # otherwise return the vertex and remember the edge
            if vertex:
                self.on_hold = edge
                return vertex
            else:
                return edge
        except Exception as ex:
            log.warning(f"Could not read element {element}: {ex}. Ignore.")
        return None

    async def next_from_db(self) -> Json:
        try:
            if self.cursor.empty():
                if not self.cursor.has_more():
                    raise StopAsyncIteration
                # next batch is fetched in separate thread
                await run_async(self.cursor.fetch)
            res: Json = self.cursor.pop()
            return res
        except CursorNextError as ex:
            log.error(f"Cursor does not exist any longer. Query: {self.query} with bind_vars: {self.bind_vars}")
            raise QueryTookToLongError("Cursor does not exist any longer, since the query ran for too long.") from ex

    async def next_deferred_edge(self) -> Json:
        try:
            while True:
                e = self.deferred_edges.pop()
                if e["from"] in self.visited_node and e["to"] in self.visited_node:
                    return e
        except IndexError as ex:
            raise StopAsyncIteration from ex


class AsyncCursorContext(AsyncContextManager[AsyncCursor]):
    def __init__(self, cursor: AsyncCursor):
        self.cursor = cursor

    async def __aenter__(self) -> AsyncCursor:
        return self.cursor

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.cursor.close()


class AsyncArangoDBBase:
    def __init__(self, db: Database):
        self.db = db

    async def aql_cursor(
        self,
        query: str,
        trafo: Optional[Callable[[Json], Optional[Any]]] = None,
        flatten_nodes_and_edges: Optional[bool] = None,
        count: bool = False,
        batch_size: Optional[int] = None,
        ttl: Optional[Number] = None,
        bind_vars: Optional[Dict[str, Any]] = None,
        full_count: Optional[bool] = None,
        max_plans: Optional[int] = None,
        optimizer_rules: Optional[Sequence[str]] = None,
        cache: Optional[bool] = None,
        memory_limit: int = 0,
        fail_on_warning: Optional[bool] = None,
        profile: Optional[bool] = None,
        max_transaction_size: Optional[int] = None,
        max_warning_count: Optional[int] = None,
        intermediate_commit_count: Optional[int] = None,
        intermediate_commit_size: Optional[int] = None,
        satellite_sync_wait: Optional[int] = None,
        stream: Optional[bool] = None,
        skip_inaccessible_cols: Optional[bool] = None,
        max_runtime: Optional[Number] = None,
    ) -> AsyncCursorContext:
        cursor: Cursor = await run_async(
            self.db.aql.execute,  # type: ignore
            query,
            count,
            batch_size,
            ttl,
            bind_vars,
            full_count,
            max_plans,
            optimizer_rules,
            cache,
            memory_limit,
            fail_on_warning,
            profile,
            max_transaction_size,
            max_warning_count,
            intermediate_commit_count,
            intermediate_commit_size,
            satellite_sync_wait,
            stream,
            skip_inaccessible_cols,
            max_runtime,
        )
        return AsyncCursorContext(
            AsyncCursor(
                cursor,
                trafo=trafo,
                flatten_nodes_and_edges=flatten_nodes_and_edges or False,
                query=query,
                bind_vars=bind_vars,
            )
        )

    async def aql(
        self,
        query: str,
        count: bool = False,
        batch_size: Optional[int] = None,
        ttl: Optional[Number] = None,
        bind_vars: Optional[Dict[str, Any]] = None,
        full_count: Optional[bool] = None,
        max_plans: Optional[int] = None,
        optimizer_rules: Optional[Sequence[str]] = None,
        cache: Optional[bool] = None,
        memory_limit: int = 0,
        fail_on_warning: Optional[bool] = None,
        profile: Optional[bool] = None,
        max_transaction_size: Optional[int] = None,
        max_warning_count: Optional[int] = None,
        intermediate_commit_count: Optional[int] = None,
        intermediate_commit_size: Optional[int] = None,
        satellite_sync_wait: Optional[int] = None,
        stream: Optional[bool] = None,
        skip_inaccessible_cols: Optional[bool] = None,
        max_runtime: Optional[Number] = None,
    ) -> Cursor:
        return await run_async(
            self.db.aql.execute,  # type: ignore
            query,
            count,
            batch_size,
            ttl,
            bind_vars,
            full_count,
            max_plans,
            optimizer_rules,
            cache,
            memory_limit,
            fail_on_warning,
            profile,
            max_transaction_size,
            max_warning_count,
            intermediate_commit_count,
            intermediate_commit_size,
            satellite_sync_wait,
            stream,
            skip_inaccessible_cols,
            max_runtime,
        )

    async def explain(
        self,
        query: str,
        all_plans: bool = False,
        max_plans: Optional[int] = None,
        opt_rules: Optional[Sequence[str]] = None,
        bind_vars: Optional[MutableMapping[str, str]] = None,
    ) -> Union[Json, Jsons]:
        return await run_async(self.db.aql.explain, query, all_plans, max_plans, opt_rules, bind_vars)  # type: ignore

    async def execute_transaction(
        self,
        command: str,
        params: Optional[Json] = None,
        read: Optional[Sequence[str]] = None,
        write: Optional[Sequence[str]] = None,
        sync: Optional[bool] = None,
        timeout: Optional[Number] = None,
        max_size: Optional[int] = None,
        allow_implicit: Optional[bool] = None,
        intermediate_commit_count: Optional[int] = None,
        intermediate_commit_size: Optional[int] = None,
    ) -> Any:
        return await run_async(
            self.db.execute_transaction,
            command,
            params,
            read,
            write,
            sync,
            timeout,
            max_size,
            allow_implicit,
            intermediate_commit_count,
            intermediate_commit_size,
        )

    async def get(
        self,
        collection: str,
        document: Union[str, Json],
        rev: Optional[str] = None,
        check_rev: bool = True,
    ) -> Optional[Json]:
        return await run_async(self.db.collection(collection).get, document, rev, check_rev)  # type: ignore

    async def insert(
        self,
        collection: str,
        document: Json,
        return_new: bool = False,
        sync: Optional[bool] = None,
        silent: bool = False,
        overwrite: bool = False,
        return_old: bool = False,
        overwrite_mode: Optional[str] = None,
        keep_none: Optional[bool] = None,
        merge: Optional[bool] = None,
    ) -> Union[bool, Json]:
        return await run_async(
            self.db.insert_document,  # type: ignore
            collection,
            document,
            return_new,
            sync,
            silent,
            overwrite,
            return_old,
            overwrite_mode,
            keep_none,
            merge,
        )

    async def update(
        self,
        collection: str,
        document: Json,
        check_rev: bool = True,
        merge: bool = True,
        keep_none: bool = True,
        return_new: bool = False,
        return_old: bool = False,
        sync: Optional[bool] = None,
        silent: bool = False,
    ) -> Json:
        return await run_async(
            self.db.collection(collection).update,  # type: ignore
            document,
            check_rev,
            merge,
            keep_none,
            return_new,
            return_old,
            sync,
            silent,
        )

    async def delete(
        self,
        collection: str,
        document: Union[str, Json],
        rev: Optional[str] = None,
        check_rev: bool = True,
        ignore_missing: bool = False,
        return_old: bool = False,
        sync: Optional[bool] = None,
        silent: bool = False,
    ) -> Union[bool, Json]:
        return await run_async(
            self.db.collection(collection).delete,  # type: ignore
            document,
            rev,
            check_rev,
            ignore_missing,
            return_old,
            sync,
            silent,
        )

    async def all(self, collection: str, skip: Optional[int] = None, limit: Optional[int] = None) -> Cursor:
        return await run_async(self.db.collection(collection).all, skip, limit)  # type: ignore

    async def keys(self, collection: str) -> Cursor:
        return await run_async(self.db.collection(collection).keys)  # type: ignore

    async def count(self, collection: str) -> int:
        return await run_async(self.db.collection(collection).count)  # type: ignore

    async def insert_many(
        self,
        collection: str,
        documents: Sequence[Json],
        return_new: bool = False,
        sync: Optional[bool] = None,
        silent: bool = False,
        overwrite: bool = False,
        return_old: bool = False,
    ) -> Union[bool, List[Union[Json, ArangoServerError]]]:
        fn = self.db.collection(collection).insert_many
        return await run_async(fn, documents, return_new, sync, silent, overwrite, return_old)  # type: ignore

    async def update_many(
        self,
        collection: str,
        documents: Sequence[Json],
        check_rev: bool = True,
        merge: bool = True,
        keep_none: bool = True,
        return_new: bool = False,
        return_old: bool = False,
        sync: Optional[bool] = None,
        silent: bool = False,
    ) -> Union[bool, List[Union[Json, ArangoServerError]]]:
        fn = self.db.collection(collection).update_many
        return await run_async(
            fn, documents, check_rev, merge, keep_none, return_new, return_old, sync, silent  # type: ignore
        )

    async def delete_many(
        self,
        collection: str,
        documents: Sequence[Json],
        return_old: bool = False,
        check_rev: bool = True,
        sync: Optional[bool] = None,
        silent: bool = False,
    ) -> Union[bool, List[Union[Json, ArangoServerError]]]:
        fn = self.db.collection(collection).delete_many
        return await run_async(fn, documents, return_old, check_rev, sync, silent)  # type: ignore

    async def has_collection(self, name: str) -> bool:
        return await run_async(self.db.has_collection, name)  # type: ignore

    async def create_collection(
        self,
        name: str,
        sync: bool = False,
        system: bool = False,
        edge: bool = False,
        user_keys: bool = True,
        key_increment: Optional[int] = None,
        key_offset: Optional[int] = None,
        key_generator: str = "traditional",
        shard_fields: Optional[Sequence[str]] = None,
        shard_count: Optional[int] = None,
        replication_factor: Optional[int] = None,
        shard_like: Optional[str] = None,
        sync_replication: Optional[bool] = None,
        enforce_replication_factor: Optional[bool] = None,
        sharding_strategy: Optional[str] = None,
        smart_join_attribute: Optional[str] = None,
        write_concern: Optional[int] = None,
        schema: Optional[Json] = None,
    ) -> StandardCollection:
        return await run_async(
            self.db.create_collection,  # type: ignore
            name,
            sync,
            system,
            edge,
            user_keys,
            key_increment,
            key_offset,
            key_generator,
            shard_fields,
            shard_count,
            replication_factor,
            shard_like,
            sync_replication,
            enforce_replication_factor,
            sharding_strategy,
            smart_join_attribute,
            write_concern,
            schema,
        )

    async def delete_collection(self, name: str, ignore_missing: bool = False, system: Optional[bool] = None) -> bool:
        return await run_async(self.db.delete_collection, name, ignore_missing, system)  # type: ignore

    def collection(self, name: str) -> StandardCollection:
        return self.db.collection(name)

    async def truncate(self, collection: str) -> bool:
        return await run_async(self.db.collection(collection).truncate)  # type: ignore

    async def delete_vertex(
        self,
        graph: GraphName,
        vertex: Json,
        rev: Optional[str] = None,
        check_rev: bool = True,
        ignore_missing: bool = False,
        sync: Optional[bool] = None,
    ) -> Union[bool, Json]:
        return await run_async(
            self.db.graph(graph).delete_vertex, vertex, rev, check_rev, ignore_missing, sync  # type: ignore
        )

    async def has_graph(self, name: GraphName) -> bool:
        return await run_async(self.db.has_graph, name)  # type: ignore

    async def create_graph(
        self,
        name: str,
        edge_definitions: Optional[Sequence[Json]] = None,
        orphan_collections: Optional[Sequence[str]] = None,
        smart: Optional[bool] = None,
        smart_field: Optional[str] = None,
        shard_count: Optional[int] = None,
    ) -> Graph:
        log.info(f"Create graph {name}.")
        return await run_async(
            self.db.create_graph,  # type: ignore
            name,
            edge_definitions,
            orphan_collections,
            smart,
            smart_field,
            shard_count,
        )

    def graph(self, name: str) -> Graph:
        return self.db.graph(name)

    async def has_vertex_collection(self, graph: GraphName, name: str) -> bool:
        return await run_async(self.db.graph(graph).has_vertex_collection, name)  # type: ignore

    async def create_vertex_collection(self, graph: GraphName, name: str) -> VertexCollection:
        log.info(f"Create vertex collection {name} for graph {graph}")
        return await run_async(self.db.graph(graph).create_vertex_collection, name)  # type: ignore

    async def has_edge_definition(self, graph: GraphName, name: str) -> bool:
        return await run_async(self.db.graph(graph).has_edge_definition, name)  # type: ignore

    async def create_edge_definition(
        self,
        graph: GraphName,
        edge_collection: str,
        from_vertex_collections: Sequence[str],
        to_vertex_collections: Sequence[str],
    ) -> EdgeCollection:
        log.info(f"Create edge collection {edge_collection} for graph {graph}")
        return await run_async(
            self.db.graph(graph).create_edge_definition,  # type: ignore
            edge_collection,
            from_vertex_collections,
            to_vertex_collections,
        )

    async def views(self) -> Jsons:
        return await run_async(self.db.views)  # type: ignore

    async def create_view(self, name: str, view_type: str, properties: Optional[Json]) -> Json:
        log.info(f"Create view {name}")
        return await run_async(self.db.create_view, name, view_type, properties)  # type: ignore


class AsyncArangoDB(AsyncArangoDBBase):
    def __init__(self, db: StandardDatabase):
        super().__init__(db)
        self.db: StandardDatabase = db

    @asynccontextmanager
    async def begin_transaction(
        self,
        read: Union[str, Sequence[str], None] = None,
        write: Union[str, Sequence[str], None] = None,
        exclusive: Union[str, Sequence[str], None] = None,
        sync: Optional[bool] = None,
        allow_implicit: Optional[bool] = None,
        lock_timeout: Optional[int] = None,
        max_size: Optional[int] = None,
    ) -> AsyncIterator[AsyncArangoTransactionDB]:
        tx = await run_async(
            self.db.begin_transaction, read, write, exclusive, sync, allow_implicit, lock_timeout, max_size
        )
        atx = AsyncArangoTransactionDB(tx)
        try:
            yield atx
        except Exception as ex:
            await atx.abort_transaction()
            raise ex
        await atx.commit_transaction()


class AsyncArangoTransactionDB(AsyncArangoDBBase):
    def __init__(self, db: TransactionDatabase):
        super().__init__(db)
        self.db: TransactionDatabase = db

    async def commit_transaction(self) -> bool:
        return await run_async(self.db.commit_transaction)

    async def abort_transaction(self) -> bool:
        return await run_async(self.db.abort_transaction)
