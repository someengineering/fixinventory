from __future__ import annotations

from contextlib import asynccontextmanager
from numbers import Number
from typing import Optional, MutableMapping, Sequence, Union, Any, AsyncGenerator, Dict, List

from arango import ArangoServerError
from arango.collection import StandardCollection, VertexCollection, EdgeCollection
from arango.cursor import Cursor
from arango.database import StandardDatabase, Database, TransactionDatabase
from arango.graph import Graph
from arango.typings import Json, Jsons

from core.async_extensions import run_async
from core.metrics import timed


class AsyncArangoDBBase:
    def __init__(self, db: Database):
        self.db = db

    @timed("arango", "aql")
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
        # TODO: remove the 2 lines once this fix: https://github.com/arangodb/arangodb/pull/14801 is released
        opt = ["-reduce-extraction-to-projection"]
        optimizer_rules = list(optimizer_rules) + opt if optimizer_rules else opt
        return await run_async(
            self.db.aql.execute,
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

    @timed("arango", "explain")
    async def explain(
        self,
        query: str,
        all_plans: bool = False,
        max_plans: Optional[int] = None,
        opt_rules: Optional[Sequence[str]] = None,
        bind_vars: Optional[MutableMapping[str, str]] = None,
    ) -> Union[Json, Jsons]:
        return await run_async(self.db.aql.explain, query, all_plans, max_plans, opt_rules, bind_vars)

    @timed("arango", "execute_transaction")
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

    @timed("arango", "get")
    async def get(
        self,
        collection: str,
        document: Union[str, Json],
        rev: Optional[str] = None,
        check_rev: bool = True,
    ) -> Optional[Json]:
        return await run_async(self.db.collection(collection).get, document, rev, check_rev)

    @timed("arango", "insert")
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
            self.db.insert_document,
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

    @timed("arango", "update")
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
            self.db.collection(collection).update,
            document,
            check_rev,
            merge,
            keep_none,
            return_new,
            return_old,
            sync,
            silent,
        )

    @timed("arango", "delete")
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
            self.db.collection(collection).delete, document, rev, check_rev, ignore_missing, return_old, sync, silent
        )

    @timed("arango", "all")
    async def all(self, collection: str, skip: Optional[int] = None, limit: Optional[int] = None) -> Cursor:
        return await run_async(self.db.collection(collection).all, skip, limit)

    @timed("arango", "insert_many")
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

    @timed("arango", "update_many")
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
        return await run_async(  # type: ignore
            fn, documents, check_rev, merge, keep_none, return_new, return_old, sync, silent
        )

    @timed("arango", "delete_many")
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
            self.db.create_collection,
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
        graph: str,
        vertex: Json,
        rev: Optional[str] = None,
        check_rev: bool = True,
        ignore_missing: bool = False,
        sync: Optional[bool] = None,
    ) -> Union[bool, Json]:
        return await run_async(self.db.graph(graph).delete_vertex, vertex, rev, check_rev, ignore_missing, sync)

    async def has_graph(self, name: str) -> bool:
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
        return await run_async(
            self.db.create_graph, name, edge_definitions, orphan_collections, smart, smart_field, shard_count
        )

    def graph(self, name: str) -> Graph:
        return self.db.graph(name)

    async def has_vertex_collection(self, graph: str, name: str) -> bool:
        return await run_async(self.db.graph(graph).has_vertex_collection, name)  # type: ignore

    async def create_vertex_collection(self, graph: str, name: str) -> VertexCollection:
        return await run_async(self.db.graph(graph).create_vertex_collection, name)

    async def has_edge_definition(self, graph: str, name: str) -> bool:
        return await run_async(self.db.graph(graph).has_edge_definition, name)  # type: ignore

    async def create_edge_definition(
        self,
        graph: str,
        edge_collection: str,
        from_vertex_collections: Sequence[str],
        to_vertex_collections: Sequence[str],
    ) -> EdgeCollection:
        return await run_async(
            self.db.graph(graph).create_edge_definition, edge_collection, from_vertex_collections, to_vertex_collections
        )

    async def views(self) -> Jsons:
        return await run_async(self.db.views)

    async def create_view(self, name: str, view_type: str, properties: Optional[Json]) -> Json:
        return await run_async(self.db.create_view, name, view_type, properties)


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
    ) -> AsyncGenerator[AsyncArangoTransactionDB, None]:
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
        return await run_async(self.db.commit_transaction)  # type: ignore

    async def abort_transaction(self) -> bool:
        return await run_async(self.db.abort_transaction)  # type: ignore
