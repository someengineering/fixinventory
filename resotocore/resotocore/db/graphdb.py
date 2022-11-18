import asyncio
import logging
import uuid
from abc import ABC, abstractmethod
from collections import defaultdict
from datetime import datetime, timedelta
from enum import Enum
from functools import partial
from numbers import Number
from typing import DefaultDict, Optional, Callable, AsyncGenerator, Any, Iterable, Dict, List, Tuple, TypeVar, cast

from arango import AnalyzerGetError
from arango.collection import VertexCollection, StandardCollection, EdgeCollection
from arango.graph import Graph
from arango.typings import Json
from attr import evolve
from networkx import MultiDiGraph

from resotocore.analytics import CoreEvent, AnalyticsEventSender
from resotocore.core_config import GraphUpdateConfig
from resotocore.db import arango_query, EstimatedSearchCost
from resotocore.db.arango_query import fulltext_delimiter
from resotocore.db.async_arangodb import AsyncArangoDB, AsyncArangoTransactionDB, AsyncArangoDBBase, AsyncCursorContext
from resotocore.db.model import GraphUpdate, QueryModel
from resotocore.error import InvalidBatchUpdate, ConflictingChangeInProgress, NoSuchChangeError, OptimisticLockingFailed
from resotocore.model.adjust_node import AdjustNode
from resotocore.model.graph_access import GraphAccess, GraphBuilder, EdgeTypes, Section
from resotocore.model.model import Model, ComplexKind, TransformKind
from resotocore.model.resolve_in_graph import NodePath, GraphResolver
from resotocore.query.model import Query, FulltextTerm, MergeTerm, P
from resotocore.types import JsonElement, EdgeType
from resotocore.util import first, value_in_path_get, utc_str, uuid_str, value_in_path, json_hash, set_value_in_path
from resotocore.ids import NodeId

log = logging.getLogger(__name__)


class HistoryChange(Enum):
    node_created = "node_created"
    node_updated = "node_updated"
    node_deleted = "node_deleted"


class GraphDB(ABC):
    @property
    @abstractmethod
    def name(self) -> str:
        pass

    @abstractmethod
    async def get_node(self, model: Model, node_id: NodeId) -> Optional[Json]:
        pass

    @abstractmethod
    async def create_node(self, model: Model, node_id: NodeId, data: Json, under_node_id: NodeId) -> Json:
        pass

    @abstractmethod
    async def update_deferred_edges(self, edges: List[Tuple[NodeId, NodeId, str]], ts: datetime) -> Tuple[int, int]:
        pass

    @abstractmethod
    async def update_node(
        self, model: Model, node_id: NodeId, patch_or_replace: Json, replace: bool, section: Optional[str]
    ) -> Json:
        pass

    @abstractmethod
    def update_nodes(
        self, model: Model, patches_by_id: Dict[NodeId, Json], **kwargs: Any
    ) -> AsyncGenerator[Json, None]:
        pass

    @abstractmethod
    def update_nodes_desired(
        self, model: Model, patch: Json, node_ids: List[NodeId], **kwargs: Any
    ) -> AsyncGenerator[Json, None]:
        pass

    @abstractmethod
    def update_nodes_metadata(
        self, model: Model, patch: Json, node_ids: List[NodeId], **kwargs: Any
    ) -> AsyncGenerator[Json, None]:
        pass

    @abstractmethod
    async def delete_node(self, node_id: NodeId) -> None:
        pass

    @abstractmethod
    async def merge_graph(
        self, graph_to_merge: MultiDiGraph, model: Model, maybe_change_id: Optional[str] = None, is_batch: bool = False
    ) -> Tuple[List[str], GraphUpdate]:
        pass

    @abstractmethod
    async def list_in_progress_updates(self) -> List[Json]:
        pass

    @abstractmethod
    async def commit_batch_update(self, batch_id: str) -> None:
        pass

    @abstractmethod
    async def abort_update(self, batch_id: str) -> None:
        pass

    @abstractmethod
    async def search_list(
        self, query: QueryModel, with_count: bool = False, timeout: Optional[timedelta] = None, **kwargs: Any
    ) -> AsyncCursorContext:
        pass

    @abstractmethod
    async def search_history(
        self,
        query: QueryModel,
        change: Optional[HistoryChange] = None,
        before: Optional[datetime] = None,
        after: Optional[datetime] = None,
        with_count: bool = False,
        timeout: Optional[timedelta] = None,
        **kwargs: Any,
    ) -> AsyncCursorContext:
        pass

    @abstractmethod
    async def search_graph_gen(
        self, query: QueryModel, with_count: bool = False, timeout: Optional[timedelta] = None
    ) -> AsyncCursorContext:
        pass

    @abstractmethod
    async def search_graph(self, query: QueryModel) -> MultiDiGraph:
        pass

    @abstractmethod
    async def search_aggregation(self, query: QueryModel) -> AsyncCursorContext:
        pass

    @abstractmethod
    async def explain(self, query: QueryModel, with_edges: bool = False) -> EstimatedSearchCost:
        pass

    @abstractmethod
    async def wipe(self) -> None:
        pass

    @abstractmethod
    async def to_query(self, query_model: QueryModel, with_edges: bool = False) -> Tuple[str, Json]:
        pass

    @abstractmethod
    async def create_update_schema(self) -> None:
        pass


class ArangoGraphDB(GraphDB):
    def __init__(self, db: AsyncArangoDB, name: str, adjust_node: AdjustNode, config: GraphUpdateConfig) -> None:
        super().__init__()
        self._name = name
        self.node_adjuster = adjust_node
        self.vertex_name = name
        self.in_progress = f"{name}_in_progress"
        self.node_history = f"{name}_node_history"
        self.db = db
        self.config = config

    @property
    def name(self) -> str:
        return self._name

    def edge_collection(self, edge_type: EdgeType) -> str:
        return f"{self.name}_{edge_type}"

    async def get_node(self, model: Model, node_id: NodeId) -> Optional[Json]:
        node = await self.by_id(node_id)
        return self.document_to_instance_fn(model)(node) if node is not None else None

    async def create_node(self, model: Model, node_id: NodeId, data: Json, under_node_id: NodeId) -> Json:
        graph = GraphBuilder(model)
        graph.add_node(node_id, data)
        graph.add_edge(under_node_id, node_id, EdgeTypes.default)
        access = GraphAccess(graph.graph, node_id, {under_node_id})
        _, node_inserts, _, _ = self.prepare_nodes(access, [], model)
        _, edge_inserts, _ = self.prepare_edges(access, [], EdgeTypes.default)
        assert len(node_inserts) == 1
        assert len(edge_inserts) == 1
        edge_collection = self.edge_collection(EdgeTypes.default)
        async with self.db.begin_transaction(write=[self.vertex_name, edge_collection]) as tx:
            result: Json = await tx.insert(self.vertex_name, node_inserts[0], return_new=True)
            await tx.insert(edge_collection, edge_inserts[0])
            trafo = self.document_to_instance_fn(model)
            return trafo(result["new"])

    async def update_deferred_edges(self, edges: List[Tuple[NodeId, NodeId, str]], ts: datetime) -> Tuple[int, int]:

        default_edges: List[Json] = []
        delete_edges: List[Json] = []

        for from_node, to_node, edge_type in edges:
            json_node = self.edge_to_json(from_node, to_node, None)
            json_node["outer_edge_ts"] = utc_str(ts)  # must be kept in sync with an index
            if edge_type == EdgeTypes.default:
                default_edges.append(json_node)
            else:
                delete_edges.append(json_node)

        def deletion_query(edge_collection: str) -> str:
            return f"""
            FOR edge IN {edge_collection}
                FILTER edge.outer_edge_ts != null &&  edge.outer_edge_ts < "{utc_str(ts)}"
                REMOVE edge in {edge_collection}
            """

        updated_edges = 0
        deleted_edges = 0

        if default_edges:
            edge_collection = self.edge_collection(EdgeTypes.default)
            async with self.db.begin_transaction(write=[edge_collection]) as tx:
                await tx.insert_many(edge_collection, default_edges, overwrite=True)
                updated_edges += len(default_edges)
                query = deletion_query(edge_collection)
                with await tx.aql(query, count=True) as cursor:
                    deleted_edges += cursor.count() or 0

        if delete_edges:
            edge_collection = self.edge_collection(EdgeTypes.delete)
            async with self.db.begin_transaction(write=[edge_collection]) as tx:
                await tx.insert_many(edge_collection, delete_edges, overwrite=True)
                updated_edges += len(delete_edges)
                query = deletion_query(edge_collection)
                with await tx.aql(query, count=True) as cursor:
                    deleted_edges += cursor.count() or 0

        return updated_edges, deleted_edges

    async def update_node(
        self, model: Model, node_id: NodeId, patch_or_replace: Json, replace: bool, section: Optional[str]
    ) -> Json:
        return await self.update_node_with(self.db, model, node_id, patch_or_replace, replace, section)

    async def update_node_with(
        self,
        db: AsyncArangoDBBase,
        model: Model,
        node_id: NodeId,
        patch_or_replace: Json,
        replace: bool,
        section: Optional[str],
    ) -> Json:
        node = await self.by_id_with(db, node_id)
        if node is None:
            raise AttributeError(f"No document found with this id: {node_id}")
        if "revision" in patch_or_replace and patch_or_replace["revision"] != node["_rev"]:
            raise OptimisticLockingFailed(node_id)

        updated = node.copy()
        if section:
            existing_section = node.get(section)
            existing_section = existing_section if existing_section else {}
            updated[section] = patch_or_replace if replace else {**existing_section, **patch_or_replace}
        else:
            for sect in Section.content_ordered:
                if sect in patch_or_replace:
                    existing_section = node.get(sect)
                    existing_section = existing_section if existing_section else {}
                    updated[sect] = (
                        patch_or_replace[sect] if replace else {**existing_section, **patch_or_replace[sect]}
                    )

        # Only the reported section is defined by the model and can be coerced
        kind = model[updated[Section.reported]]
        coerced = kind.check_valid(updated[Section.reported])
        updated[Section.reported] = coerced if coerced is not None else updated[Section.reported]

        # call adjuster on resulting node
        ctime = value_in_path_get(node, NodePath.reported_ctime, utc_str())
        adjusted = self.adjust_node(model, GraphAccess.dump_direct(node_id, updated, kind, recompute=True), ctime)
        update = {"_key": node["_key"], "hash": adjusted["hash"], "kinds": adjusted["kinds"], "flat": adjusted["flat"]}
        # copy relevant sections into update node
        for sec in [section] if section else Section.content_ordered:
            if sec in adjusted:
                update[sec] = adjusted[sec]

        result = await db.update(self.vertex_name, update, return_new=True, merge=not replace)
        trafo = self.document_to_instance_fn(model)
        return trafo(result["new"])

    async def update_nodes(
        self, model: Model, patches_by_id: Dict[NodeId, Json], **kwargs: Any
    ) -> AsyncGenerator[Json, None]:
        log.info(f"Update nodes called with {len(patches_by_id)} updates.")
        # collect all sections to be deleted
        deletes: Dict[str, List[str]] = defaultdict(list)
        delete_sections = [Section.desired, Section.metadata]
        # group patches by changes: single desired or metadata changes can be executed via special purpose methods.
        updates: Dict[str, Json] = {}
        updated_nodes: Dict[str, List[NodeId]] = defaultdict(list)
        for uid, patch_js in patches_by_id.items():
            # filter out delete operation
            for section in delete_sections:
                if section in patch_js and patch_js[section] is None:
                    deletes[section].append(uid)
                    del patch_js[section]
            # filter out empty changes (== noop patches)
            for section in Section.content_ordered:
                if section in patch_js and patch_js[section] == {}:
                    del patch_js[section]
            # all remaining changes are updates
            if patch_js:
                hashed = json_hash(patch_js)
                updates[hashed] = patch_js
                updated_nodes[hashed].append(uid)

        # all changes are executed inside a transaction: either all changes are successful or none
        async with self.db.begin_transaction(read=[self.vertex_name], write=[self.vertex_name]) as tx:

            async def update_node_multi(js: Json, node_ids: List[NodeId]) -> AsyncGenerator[Json, None]:
                for node_id in node_ids:
                    log.debug(f"Update node: change={js} on {node_id}")
                    single_update = await self.update_node_with(tx, model, node_id, js, False, None)
                    yield single_update

            for section, ids in deletes.items():
                log.debug(f"Delete section {section} for ids: {ids}")
                async for res in self.delete_nodes_section_with(tx, model, section, ids):
                    yield res

            for change_id, change in updates.items():
                items = updated_nodes[change_id]
                if len(change) == 1 and Section.desired in change:
                    log.debug(f"Update desired many: change={change} on {items}")
                    patch = change[Section.desired]
                    result = self.update_nodes_section_with(tx, model, Section.desired, patch, items)
                elif len(change) == 1 and Section.metadata in change:
                    log.debug(f"Update metadata many: change={change} on {items}")
                    patch = change[Section.metadata]
                    result = self.update_nodes_section_with(tx, model, Section.metadata, patch, items)
                else:
                    result = update_node_multi(change, items)
                async for res in result:
                    yield res

    def update_nodes_desired(
        self, model: Model, patch: Json, node_ids: List[NodeId], **kwargs: Any
    ) -> AsyncGenerator[Json, None]:
        return self.update_nodes_section_with(self.db, model, Section.desired, patch, node_ids)

    def update_nodes_metadata(
        self, model: Model, patch: Json, node_ids: List[NodeId], **kwargs: Any
    ) -> AsyncGenerator[Json, None]:
        return self.update_nodes_section_with(self.db, model, Section.metadata, patch, node_ids)

    async def delete_nodes_section_with(
        self, db: AsyncArangoDBBase, model: Model, section: str, node_ids: List[str]
    ) -> AsyncGenerator[Json, None]:
        bind_var = {"node_ids": node_ids}
        trafo = self.document_to_instance_fn(model)
        with await db.aql(query=self.query_delete_desired_metadata_many(section), bind_vars=bind_var) as cursor:
            for element in cursor:
                yield trafo(element)

    async def update_nodes_section_with(
        self, db: AsyncArangoDBBase, model: Model, section: str, patch: Json, node_ids: List[NodeId]
    ) -> AsyncGenerator[Json, None]:
        bind_var = {"patch": patch, "node_ids": node_ids}
        trafo = self.document_to_instance_fn(model)
        with await db.aql(query=self.query_update_desired_metadata_many(section), bind_vars=bind_var) as cursor:
            for element in cursor:
                yield trafo(element)

    async def delete_node(self, node_id: NodeId) -> None:
        with await self.db.aql(query=self.query_count_direct_children(), bind_vars={"rid": node_id}) as cursor:
            count = cursor.next()
            if count > 0:
                raise AttributeError(f"Can not delete node, since it has {count} child(ren)!")

        with await self.db.aql(query=self.query_node_by_id(), bind_vars={"rid": node_id}) as cursor:
            if not cursor.empty():
                await self.db.delete_vertex(self.name, cursor.next())
            else:
                return None

    async def by_id(self, node_id: NodeId) -> Optional[Json]:
        return await self.by_id_with(self.db, node_id)

    async def by_id_with(self, db: AsyncArangoDBBase, node_id: NodeId) -> Optional[Json]:
        with await db.aql(query=self.query_node_by_id(), bind_vars={"rid": node_id}) as cursor:
            return cursor.next() if not cursor.empty() else None

    async def search_list(
        self, query: QueryModel, with_count: bool = False, timeout: Optional[timedelta] = None, **kwargs: Any
    ) -> AsyncCursorContext:
        assert query.query.aggregate is None, "Given query is an aggregation function. Use the appropriate endpoint!"
        q_string, bind = await self.to_query(query)
        return await self.db.aql_cursor(
            query=q_string,
            trafo=self.document_to_instance_fn(query.model, query.query),
            count=with_count,
            bind_vars=bind,
            batch_size=10000,
            ttl=cast(Number, int(timeout.total_seconds())) if timeout else None,
        )

    async def search_history(
        self,
        query: QueryModel,
        change: Optional[HistoryChange] = None,
        before: Optional[datetime] = None,
        after: Optional[datetime] = None,
        with_count: bool = False,
        timeout: Optional[timedelta] = None,
        **kwargs: Any,
    ) -> AsyncCursorContext:
        more_than_one = len(query.query.parts) > 1
        has_invalid_terms = any(query.query.find_terms(lambda t: isinstance(t, (FulltextTerm, MergeTerm))))
        has_navigation = any(p.navigation for p in query.query.parts)
        if more_than_one and has_invalid_terms or has_navigation:
            raise AttributeError("Fulltext, merge terms and navigation is not supported in history queries!")
        # adjust query
        term = query.query.current_part.term
        if change:
            term = term.and_term(P.single("change").eq(change.value))
        if after:
            term = term.and_term(P.single("changed_at").gt(utc_str(after)))
        if before:
            term = term.and_term(P.single("changed_at").lt(utc_str(before)))
        query = QueryModel(evolve(query.query, parts=[evolve(query.query.current_part, term=term)]), query.model)
        q_string, bind = arango_query.to_query(self, query, from_collection=self.node_history)
        trafo = (
            None
            if query.query.aggregate
            else self.document_to_instance_fn(
                query.model, query.query, ["change", "changed_at", "created", "updated", "deleted"]
            )
        )
        ttl = cast(Number, int(timeout.total_seconds())) if timeout else None
        return await self.db.aql_cursor(
            query=q_string, trafo=trafo, count=with_count, bind_vars=bind, batch_size=10000, ttl=ttl
        )

    async def search_graph_gen(
        self, query: QueryModel, with_count: bool = False, timeout: Optional[timedelta] = None
    ) -> AsyncCursorContext:
        assert query.query.aggregate is None, "Given query is an aggregation function. Use the appropriate endpoint!"
        query_string, bind = await self.to_query(query, with_edges=True)
        return await self.db.aql_cursor(
            query=query_string,
            trafo=self.document_to_instance_fn(query.model, query.query),
            bind_vars=bind,
            count=with_count,
            batch_size=10000,
            ttl=cast(Number, int(timeout.total_seconds())) if timeout else None,
        )

    async def search_graph(self, query: QueryModel) -> MultiDiGraph:
        async with await self.search_graph_gen(query) as cursor:
            graph = MultiDiGraph()
            async for item in cursor:
                if "from" in item and "to" in item and "edge_type" in item:
                    key = GraphAccess.edge_key(item["from"], item["to"], item["edge_type"])
                    graph.add_edge(key.from_node, key.to_node, key, edge_type=key.edge_type)
                elif "id" in item:
                    graph.add_node(item["id"], **item)
            return graph

    async def search_aggregation(self, query: QueryModel) -> AsyncCursorContext:
        q_string, bind = await self.to_query(query)
        assert query.query.aggregate is not None, "Given query has no aggregation section"
        return await self.db.aql_cursor(query=q_string, bind_vars=bind)

    async def explain(self, query: QueryModel, with_edges: bool = False) -> EstimatedSearchCost:
        return await arango_query.query_cost(self, query, with_edges)

    async def wipe(self) -> None:
        await self.db.truncate(self.vertex_name)
        for edge_type in EdgeTypes.all:
            await self.db.truncate(self.edge_collection(edge_type))
        await self.insert_genesis_data()

    @staticmethod
    def document_to_instance_fn(
        model: Model, query: Optional[Query] = None, additional_root_props: Optional[List[str]] = None
    ) -> Callable[[Json], Optional[Json]]:
        def props(doc: Json, result: Json, definition: Iterable[str]) -> None:
            for prop in definition:
                if prop in doc and doc[prop]:
                    result[prop] = doc[prop]

        def synth_props(doc: Json, result: Json) -> None:
            reported_in = doc[Section.reported]
            kind = model.get(reported_in)
            if isinstance(kind, ComplexKind):
                reported_out = result[Section.reported]
                for synth in kind.synthetic_props():
                    if isinstance(synth.kind, TransformKind) and synth.prop.synthetic:
                        source_value = value_in_path(reported_in, synth.prop.synthetic.path)
                        if source_value:
                            reported_out[synth.prop.name] = synth.kind.transform(source_value)

        def render_prop(doc: Json, root_level: bool) -> Json:
            if Section.reported in doc or Section.desired in doc or Section.metadata in doc:
                # side note: the dictionary remembers insertion order
                # this order is also used to render the output (e.g. yaml property order)
                result = {"id": doc["_key"], "type": "node"}
                if "_rev" in doc:
                    result["revision"] = doc["_rev"]
                props(doc, result, Section.content)
                if root_level:
                    props(doc, result, Section.lookup_sections_ordered)
                    if additional_root_props:
                        props(doc, result, additional_root_props)
                synth_props(doc, result)
                return result
            else:
                return doc

        def render_merge_results(doc: Json, result: Json, q: Query) -> Json:
            for mq in q.merge_query_by_name:
                merged = value_in_path(doc, mq.name)
                if merged:
                    if mq.only_first and isinstance(merged, dict):
                        rendered = render_merge_results(merged, render_prop(merged, False), mq.query)
                        set_value_in_path(rendered, mq.name, result)
                    elif isinstance(merged, list):
                        rendered = [render_merge_results(elem, render_prop(elem, False), mq.query) for elem in merged]
                        set_value_in_path(rendered, mq.name, result)
            return result

        def merge_results(doc: Json) -> Optional[Json]:
            rendered = render_prop(doc, True)
            if query:
                render_merge_results(doc, rendered, query)
            return rendered

        return merge_results

    async def list_in_progress_updates(self) -> List[Json]:
        with await self.db.aql(self.query_active_updates()) as cursor:
            return list(cursor)

    async def get_tmp_collection(self, change_id: str, create: bool = True) -> StandardCollection:
        id_part = str(uuid.uuid5(uuid.NAMESPACE_DNS, change_id)).replace("-", "")
        temp_name = f"{self.vertex_name}_temp_{id_part}"
        if await self.db.has_collection(temp_name):
            return self.db.collection(temp_name)
        elif create:
            temp = await self.db.create_collection(temp_name, replication_factor=1)
            temp.add_persistent_index(["action"])
            return temp
        else:
            raise NoSuchChangeError(change_id)

    async def move_temp_to_proper(self, change_id: str, temp_name: str) -> None:
        change_key = str(uuid.uuid5(uuid.NAMESPACE_DNS, change_id))
        log.info(f"Move temp->proper data: change_id={change_id}, change_key={change_key}, temp_name={temp_name}")
        edge_inserts = [
            f'for e in {temp_name} filter e.action=="edge_insert" and e.edge_type=="{a}" '
            f'insert e.data in {self.edge_collection(a)} OPTIONS {{overwriteMode: "replace"}}'
            for a in EdgeTypes.all
        ]
        edge_deletes = [
            f'for e in {temp_name} filter e.action=="edge_delete" and e.edge_type=="{a}" '
            f"remove e.data in {self.edge_collection(a)}"
            for a in EdgeTypes.all
        ]
        history_updates = [
            f'for e in {temp_name} filter e.action=="node_created" insert MERGE({{change: e.action, changed_at: e.data.created}}, UNSET(e.data, "_key", "flat", "hash")) in {self.node_history}',  # noqa: E501
            f'for e in {temp_name} filter e.action=="node_updated" insert MERGE({{change: e.action, changed_at: e.data.updated}}, UNSET(e.data, "_key", "flat", "hash")) in {self.node_history}',  # noqa: E501
            f'for e in {temp_name} filter e.action=="node_deleted" let node = Document(CONCAT("{self.vertex_name}/", e.data._key)) insert MERGE({{change: "node_deleted", deleted: e.data.deleted, changed_at: e.data.deleted}}, UNSET(node, "_key", "_id", "_rev", "flat", "hash")) in {self.node_history}',  # noqa: E501
        ]
        updates = ";\n".join(
            map(
                lambda aql: f"db._createStatement({{ query: `{aql}` }}).execute()",
                (history_updates if self.config.keep_history else [])
                + [
                    f'for e in {temp_name} filter e.action=="node_created" insert e.data in {self.vertex_name}'
                    ' OPTIONS{overwriteMode: "replace"}',
                    f'for e in {temp_name} filter e.action=="node_updated" update e.data in {self.vertex_name}'
                    " OPTIONS {mergeObjects: false}",
                    f'for e in {temp_name} filter e.action=="node_deleted" remove e.data in {self.vertex_name}',
                ]
                + edge_inserts
                + edge_deletes
                + [f'remove {{_key: "{change_key}"}} in {self.in_progress}'],
            )
        )
        await self.db.execute_transaction(
            f'function () {{\nvar db=require("@arangodb").db;\n{updates}\n}}',
            read=[temp_name],
            write=[self.edge_collection(a) for a in EdgeTypes.all]
            + [self.vertex_name, self.in_progress, self.node_history],
        )
        log.info(f"Move temp->proper data: change_id={change_id} done.")

    async def mark_update(
        self, root_node_ids: List[str], parent_node_ids: List[str], change_id: str, is_batch: bool
    ) -> None:
        async with self.db.begin_transaction(read=[self.in_progress], write=[self.in_progress]) as tx:
            existing = next(await tx.aql(self.query_active_change(), bind_vars={"root_node_ids": root_node_ids}), None)
            if existing is not None:
                other = existing["change"]
                raise InvalidBatchUpdate() if change_id == other else ConflictingChangeInProgress(other)
            await tx.insert(
                self.in_progress,
                {
                    "_key": str(uuid.uuid5(uuid.NAMESPACE_DNS, change_id)),
                    "root_node_ids": list(root_node_ids),
                    "parent_node_ids": list(parent_node_ids),
                    "change": change_id,
                    "created": utc_str(),
                    "is_batch": is_batch,
                },
            )

    async def refresh_marked_update(self, change_id: str) -> None:
        with await self.db.aql(self.update_active_change(), bind_vars={"change": change_id}):
            return None

    async def delete_marked_update(self, change_id: str, tx: Optional[AsyncArangoTransactionDB] = None) -> None:
        db = tx if tx else self.db
        doc = {"_key": str(uuid.uuid5(uuid.NAMESPACE_DNS, change_id))}
        await db.delete(self.in_progress, doc, ignore_missing=True)

    def adjust_node(self, model: Model, json: Json, created_at: Any) -> Json:
        reported = json[Section.reported]
        # preserve ctime in reported: if it is not set, use the creation time of the object
        if not reported.get("ctime", None):
            kind = model[reported]
            if isinstance(kind, ComplexKind) and "ctime" in kind:
                reported["ctime"] = created_at

        # adjuster has the option to manipulate the resulting json
        return self.node_adjuster.adjust(json)

    def prepare_nodes(
        self, access: GraphAccess, node_cursor: Iterable[Json], model: Model
    ) -> Tuple[GraphUpdate, List[Json], List[Json], List[Json]]:
        log.info(f"Prepare nodes for subgraph {access.root()}")
        info = GraphUpdate()
        resource_inserts: List[Json] = []
        resource_updates: List[Json] = []
        resource_deletes: List[Json] = []

        optional_properties = [*Section.all_ordered, "refs", "kinds", "flat", "hash"]

        def insert_node(node: Json) -> None:
            elem = self.adjust_node(model, node, access.at_json)
            js_doc: Json = {"_key": elem["id"], "created": access.at_json, "updated": access.at_json}
            for prop in optional_properties:
                value = node.get(prop, None)
                if value:
                    js_doc[prop] = value
            resource_inserts.append(js_doc)
            info.nodes_created += 1

        def update_or_delete_node(node: Json) -> None:
            key = node["_key"]
            hash_string = node["hash"]
            elem = access.node(key)
            if elem is None:
                # node is in db, but not in the graph any longer: delete node
                resource_deletes.append({"_key": key, "deleted": access.at_json})
                info.nodes_deleted += 1
            elif elem["hash"] != hash_string:
                # node is in db and in the graph, content is different
                adjusted: Json = self.adjust_node(model, elem, node["created"])
                js = {"_key": key, "created": node["created"], "updated": access.at_json}
                for prop in optional_properties:
                    value = adjusted.get(prop, None)
                    if value:
                        js[prop] = value
                resource_updates.append(js)
                info.nodes_updated += 1

        for doc in node_cursor:
            update_or_delete_node(doc)

        for not_visited in access.not_visited_nodes():
            insert_node(not_visited)
        return info, resource_inserts, resource_updates, resource_deletes

    def edge_to_json(self, from_node: str, to_node: str, refs: Optional[Dict[str, str]]) -> Json:
        key = self.db_edge_key(from_node, to_node)
        js = {
            "_key": key,
            "_from": f"{self.vertex_name}/{from_node}",
            "_to": f"{self.vertex_name}/{to_node}",
            "refs": refs,
        }
        return js

    def prepare_edges(
        self, access: GraphAccess, edge_cursor: Iterable[Json], edge_type: EdgeType
    ) -> Tuple[GraphUpdate, List[Json], List[Json]]:
        log.info(f"Prepare edges of type {edge_type} for subgraph {access.root()}")
        info = GraphUpdate()
        edges_inserts: List[Json] = []
        edges_deletes: List[Json] = []

        def insert_edge(from_node: str, to_node: str) -> None:
            # Take the refs with the lower number of entries (or none):
            # Lower number of entries means closer to the root.
            # Ownership is maintained as self-contained subgraph.
            # A relationship from a sub-graph root to a node closer to the graph root, is not considered
            # part of the sub-graph root, but the parent graph.
            to_refs = access.nodes[to_node].get("refs")
            from_refs = access.nodes[from_node].get("refs")
            refs = (to_refs if len(to_refs) < len(from_refs) else from_refs) if to_refs and from_refs else None

            js = self.edge_to_json(from_node, to_node, refs)
            edges_inserts.append(js)
            info.edges_created += 1

        def update_edge(edge: Json) -> None:
            from_node = edge["_from"].split("/")[1]  # vertex/id
            to_node = edge["_to"].split("/")[1]  # vertex/id
            if not access.has_edge(from_node, to_node, edge_type):
                edges_deletes.append(edge)
                info.edges_deleted += 1

        for doc in edge_cursor:
            update_edge(doc)

        for edge_from, edge_to in access.not_visited_edges(edge_type):
            insert_edge(edge_from, edge_to)

        return info, edges_inserts, edges_deletes

    async def merge_graph(
        self, graph_to_merge: MultiDiGraph, model: Model, maybe_change_id: Optional[str] = None, is_batch: bool = False
    ) -> Tuple[List[str], GraphUpdate]:
        change_id = maybe_change_id if maybe_change_id else uuid_str()

        async def prepare_graph(
            sub: GraphAccess, node_query: Tuple[str, Json], edge_query: Callable[[EdgeType], Tuple[str, Json]]
        ) -> Tuple[
            GraphUpdate, List[Json], List[Json], List[Json], Dict[EdgeType, List[Json]], Dict[EdgeType, List[Json]]
        ]:
            graph_info = GraphUpdate()
            # check all nodes for this subgraph
            query, bind = node_query
            log.debug(f"Query for nodes: {sub.root()}")
            with await self.db.aql(query, bind_vars=bind, batch_size=50000) as node_cursor:
                node_info, ni, nu, nd = self.prepare_nodes(sub, node_cursor, model)
                graph_info += node_info

            # check all edges in all relevant edge-collections
            edge_inserts: DefaultDict[EdgeType, List[Json]] = defaultdict(list)
            edge_deletes: DefaultDict[EdgeType, List[Json]] = defaultdict(list)
            for edge_type in EdgeTypes.all:
                query, bind = edge_query(edge_type)
                log.debug(f"Query for edges of type {edge_type}: {sub.root()}")
                with await self.db.aql(query, bind_vars=bind, batch_size=50000) as ec:
                    edge_info, gei, ged = self.prepare_edges(sub, ec, edge_type)
                    graph_info += edge_info
                    edge_inserts[edge_type] = gei
                    edge_deletes[edge_type] = ged
            return graph_info, ni, nu, nd, edge_inserts, edge_deletes

        roots, parent, graphs = GraphAccess.merge_graphs(graph_to_merge)
        logging.info(f"merge_graph {len(roots)} merge nodes found. change_id={change_id}, is_batch={is_batch}.")

        def parent_edges(edge_type: EdgeType) -> Tuple[str, Json]:
            edge_ids = [self.db_edge_key(f, t) for f, t, et in parent.g.edges(data="edge_type") if et == edge_type]
            return self.query_update_edges_by_ids(edge_type), {"ids": edge_ids}

        def merge_edges(merge_node: str, merge_node_kind: str, edge_type: EdgeType) -> Tuple[str, Json]:
            return self.query_update_edges(edge_type, merge_node_kind), {"update_id": merge_node}

        K = TypeVar("K")  # noqa: N806
        V = TypeVar("V")  # noqa: N806

        def combine_dict(left: Dict[K, List[V]], right: Dict[K, List[V]]) -> Dict[K, List[V]]:
            result = dict(left)
            for key, right_values in right.items():
                left_values = left.get(key)
                result[key] = left_values + right_values if left_values else right_values
            return result

        # this will throw an exception, in case of a conflicting update (--> outside try block)
        log.debug("Mark all parent nodes for this update to avoid conflicting changes")
        await self.mark_update(roots, list(parent.nodes), change_id, is_batch)
        try:
            parents_nodes = self.query_update_nodes_by_ids(), {"ids": list(parent.g.nodes)}
            info, nis, nus, nds, eis, eds = await prepare_graph(parent, parents_nodes, parent_edges)
            for num, (root, graph) in enumerate(graphs):
                root_kind = GraphResolver.resolved_kind(graph_to_merge.nodes[root])
                if root_kind:
                    log.info(f"Update subgraph: root={root} ({root_kind}, {num+1} of {len(roots)})")
                    node_query = self.query_update_nodes(root_kind), {"update_id": root}
                    edge_query = partial(merge_edges, root, root_kind)

                    i, ni, nu, nd, ei, ed = await prepare_graph(graph, node_query, edge_query)
                    info += i
                    nis += ni
                    nus += nu
                    nds += nd
                    eis = combine_dict(eis, ei)
                    eds = combine_dict(eds, ed)
                else:
                    # Already checked in GraphAccess - only here as safeguard.
                    raise AttributeError(f"Kind of update root {root} is not a pre-resolved and can not be used!")

            log.debug(f"Update prepared: {info}. Going to persist the changes.")
            await self.refresh_marked_update(change_id)
            await self.persist_update(change_id, is_batch, info, nis, nus, nds, eis, eds)
            return roots, info
        except Exception as ex:
            await self.delete_marked_update(change_id)
            raise ex

    async def persist_update(
        self,
        change_id: str,
        is_batch: bool,
        info: GraphUpdate,
        resource_inserts: List[Json],
        resource_updates: List[Json],
        resource_deletes: List[Json],
        edge_inserts: Dict[EdgeType, List[Json]],
        edge_deletes: Dict[EdgeType, List[Json]],
    ) -> None:
        async def execute_many_async(
            async_fn: Callable[[str, List[Json]], Any], name: str, array: List[Json], **kwargs: Any
        ) -> None:
            if array:
                async_fn_with_args = partial(async_fn, **kwargs) if kwargs else async_fn
                result = await async_fn_with_args(name, array)  # type: ignore
                ex: Optional[Exception] = first(lambda x: isinstance(x, Exception), result)
                if ex:
                    raise ex  # pylint: disable=raising-bad-type

        async def trafo_many(
            async_fn: Callable[[str, List[Json]], Any], name: str, array: List[Json], template: Json
        ) -> None:
            # update the array in place to not create another intermediate array
            for idx, item in enumerate(array):
                entry = template.copy()
                entry["data"] = item
                array[idx] = entry
            await execute_many_async(async_fn, name, array)

        async def store_to_tmp_collection(temp: StandardCollection) -> None:
            tmp = temp.name
            ri = trafo_many(self.db.insert_many, tmp, resource_inserts, {"action": "node_created"})
            ru = trafo_many(self.db.insert_many, tmp, resource_updates, {"action": "node_updated"})
            rd = trafo_many(self.db.insert_many, tmp, resource_deletes, {"action": "node_deleted"})
            edge_i = [
                trafo_many(self.db.insert_many, tmp, inserts, {"action": "edge_insert", "edge_type": tpe})
                for tpe, inserts in edge_inserts.items()
            ]
            edge_u = [
                trafo_many(self.db.insert_many, tmp, deletes, {"action": "edge_delete", "edge_type": tpe})
                for tpe, deletes in edge_deletes.items()
            ]
            await asyncio.gather(*([ri, ru, rd] + edge_i + edge_u))

        async def update_via_temp_collection() -> None:
            temp = await self.get_tmp_collection(change_id)
            log.debug(f"Store change in temp collection {temp.name}")
            try:
                await store_to_tmp_collection(temp)
                await self.move_temp_to_proper(change_id, temp.name)
            finally:
                log.debug(f"Delete temp collection {temp.name}")
                await self.db.delete_collection(temp.name)

        async def update_batch() -> None:
            temp = await self.get_tmp_collection(change_id)
            log.info(f"Batch update: use temp collection {temp.name}")
            await store_to_tmp_collection(temp)

        if is_batch:
            await update_batch()
            await self.refresh_marked_update(change_id)
        else:
            await update_via_temp_collection()
        log.debug("Persist update done.")

    async def commit_batch_update(self, batch_id: str) -> None:
        temp_table = await self.get_tmp_collection(batch_id, False)
        await self.move_temp_to_proper(batch_id, temp_table.name)
        await self.db.delete_collection(temp_table.name)

    async def abort_update(self, batch_id: str) -> None:
        try:
            temp_table = await self.get_tmp_collection(batch_id, False)
            await self.db.delete_collection(temp_table.name)
        except NoSuchChangeError:
            pass
        await self.delete_marked_update(batch_id)

    async def to_query(self, query_model: QueryModel, with_edges: bool = False) -> Tuple[str, Json]:
        return arango_query.to_query(self, query_model, with_edges)

    async def insert_genesis_data(self) -> None:
        root_data = {"kind": "graph_root", "name": "root"}
        sha = GraphBuilder.content_hash(root_data)
        root_node = {"_key": "root", "id": "root", Section.reported: root_data, "kinds": ["graph_root"], "hash": sha}
        try:
            await self.db.insert(self.vertex_name, root_node)
        except Exception:
            # ignore if the root not is already created
            return None

    async def create_update_schema(self) -> None:
        db = self.db

        async def create_update_graph(
            graph_name: str, vertex_name: str, edge_name: str
        ) -> Tuple[Graph, VertexCollection, EdgeCollection]:
            graph = db.graph(graph_name) if await db.has_graph(graph_name) else await db.create_graph(graph_name)
            vertex_collection = (
                graph.vertex_collection(vertex_name)
                if await db.has_vertex_collection(graph_name, vertex_name)
                else await db.create_vertex_collection(graph_name, vertex_name)
            )
            edge_collection = (
                graph.edge_collection(edge_name)
                if await db.has_edge_definition(graph_name, edge_name)
                else await db.create_edge_definition(graph_name, edge_name, [vertex_name], [vertex_name])
            )
            return graph, vertex_collection, edge_collection

        def create_update_collection_indexes(
            nodes: VertexCollection, progress: StandardCollection, node_history: StandardCollection
        ) -> None:
            # node indexes ------
            node_idxes = {idx["name"]: idx for idx in nodes.indexes()}
            # this index will hold all the necessary data to query for an update (index only query)
            if "update_nodes_ref_id" not in node_idxes:
                log.info(f"Add index update_nodes_ref_id on {nodes.name}")
                nodes.add_persistent_index(
                    # if _key would be defined as first property, the optimizer would use it in case
                    # a simple id() query would be executed.
                    ["refs.cloud_id", "refs.account_id", "refs.region_id", "hash", "created", "_key"],
                    sparse=False,
                    name="update_nodes_ref_id",
                )

            if "kinds_id_name_ctime" not in node_idxes:
                nodes.add_persistent_index(
                    ["kinds[*]", "reported.id", "reported.name", "reported.ctime"],
                    sparse=False,
                    name="kinds_id_name_ctime",
                )
            # progress indexes ------
            progress_idxes = {idx["name"]: idx for idx in progress.indexes()}
            if "parent_nodes" not in progress_idxes:
                log.info(f"Add index parent_nodes on {progress.name}")
                progress.add_persistent_index(["parent_nodes[*]"], name="parent_nodes")
            if "root_nodes" not in progress_idxes:
                log.info(f"Add index root_nodes on {progress.name}")
                progress.add_persistent_index(["root_nodes[*]"], name="root_nodes")
            # history indexes ------
            node_history_indexes = {idx["name"]: idx for idx in node_history.indexes()}
            if "history_access" not in node_history_indexes:
                node_history.add_persistent_index(
                    ["change", "changed_at", "kinds[*]", "reported.id", "reported.name", "reported.ctime"],
                    sparse=False,
                    name="history_access",
                )
            if "ttl_index" not in node_history_indexes:
                node_history.add_ttl_index(["changed"], int(timedelta(days=14).total_seconds()), name="ttl_index")

        def create_update_edge_indexes(edges: EdgeCollection) -> None:
            edge_idxes = {idx["name"]: idx for idx in edges.indexes()}
            # this index will hold all the necessary data to query for an update (index only query)
            if "update_edges_ref_id" not in edge_idxes:
                log.info(f"Add index update_edges_ref_id on {edges.name}")
                edges.add_persistent_index(
                    ["_key", "_from", "_to", "refs.cloud_id", "refs.account_id", "refs.region_id"],
                    sparse=False,
                    name="update_edges_ref_id",
                )
            outer_edge_ts_index_name = "outer_edge_timestamp_index"
            if outer_edge_ts_index_name not in edge_idxes:
                log.info(f"Add index {outer_edge_ts_index_name} on {edges.name}")
                edges.add_persistent_index(["outer_edge_ts"], sparse=True, name=outer_edge_ts_index_name)

        async def create_collection(name: str) -> StandardCollection:
            return db.collection(name) if await db.has_collection(name) else await db.create_collection(name)

        async def create_update_views(nodes: VertexCollection) -> None:
            name = f"search_{nodes.name}"
            prop = "flat"  # only the flat property is indexes

            # make sure the delimited analyzer exists
            try:
                db.db.analyzer("delimited")
            except AnalyzerGetError:
                db.db.create_analyzer(
                    "delimited",
                    "pipeline",
                    {
                        "pipeline": [
                            # lower case (leaving accents as is)
                            {"type": "norm", "properties": {"locale": "en_US.utf-8", "accent": True, "case": "lower"}},
                            # split the input
                            *[{"type": "delimiter", "properties": {"delimiter": a}} for a in fulltext_delimiter],
                            # remove empty strings
                            {"type": "stopwords", "properties": {"stopwords": [""], "hex": False}},
                        ]
                    },
                    ["frequency", "norm", "position"],
                )

            views = {view["name"]: view for view in await db.views()}
            if name not in views:
                log.info(f"Create view {name}")
                await db.create_view(
                    name,
                    "arangosearch",
                    {
                        "links": {nodes.name: {"fields": {prop: {"analyzers": ["delimited"]}}}},
                        "primarySort": [{"field": prop, "direction": "desc"}],
                        "inBackground": True,  # note: this setting only applies when the view is created
                    },
                )

        for edge_type in EdgeTypes.all:
            edge_type_name = self.edge_collection(edge_type)
            await create_update_graph(self.name, self.vertex_name, edge_type_name)

        vertex = db.graph(self.name).vertex_collection(self.vertex_name)
        in_progress = await create_collection(self.in_progress)
        node_history_collection = await create_collection(self.node_history)
        create_update_collection_indexes(vertex, in_progress, node_history_collection)
        for edge_type in EdgeTypes.all:
            edge_collection = db.graph(self.name).edge_collection(self.edge_collection(edge_type))
            create_update_edge_indexes(edge_collection)

        await create_update_views(vertex)
        await self.insert_genesis_data()

    @staticmethod
    def db_edge_key(from_node: str, to_node: str) -> str:
        return str(uuid.uuid5(uuid.NAMESPACE_DNS, f"{from_node}:{to_node}"))

    # parameter: rid
    # return: the complete document
    def query_node_by_id(self) -> str:
        return f"""
      FOR resource in {self.vertex_name}
      FILTER resource._key==@rid
      LIMIT 1
      RETURN resource
      """

    def query_update_nodes(self, merge_node_kind: str) -> str:
        return f"""
        FOR a IN {self.vertex_name}
        FILTER a.refs.{merge_node_kind}_id==@update_id
        RETURN {{_key: a._key, hash:a.hash, created:a.created}}
        """

    def query_update_edges(self, edge_type: EdgeType, merge_node_kind: str) -> str:
        collection = self.edge_collection(edge_type)
        return f"""
        FOR a IN {collection}
        FILTER a.refs.{merge_node_kind}_id==@update_id
        RETURN {{_key: a._key, _from: a._from, _to: a._to}}
        """

    def query_update_nodes_by_ids(self) -> str:
        return f"""
        FOR a IN {self.vertex_name}
        FILTER a._key IN @ids
        RETURN {{_key: a._key, hash:a.hash, created:a.created}}
        """

    def query_update_edges_by_ids(self, edge_type: EdgeType) -> str:
        collection = self.edge_collection(edge_type)
        return f"""
        FOR a IN {collection}
        FILTER a._key in @ids
        RETURN {{_key: a._key, _from: a._from, _to: a._to}}
        """

    def query_update_parent_linked(self) -> str:
        return f"""
        FOR a IN {self.edge_collection(EdgeTypes.default)}
        FILTER a._from==@from and a._to==@to
        RETURN true
        """

    def query_update_desired_metadata_many(self, section: str) -> str:
        return f"""
        FOR a IN {self.vertex_name}
        FILTER a._key in @node_ids
        UPDATE a with {{ "{section}": @patch }} IN {self.vertex_name}
        RETURN NEW
        """

    def query_delete_desired_metadata_many(self, section: str) -> str:
        return f"""
        FOR a IN {self.vertex_name}
        FILTER a._key in @node_ids
        REPLACE a with UNSET(a, "{section}") IN {self.vertex_name}
        RETURN NEW
        """

    def query_count_direct_children(self) -> str:
        return f"""
        FOR pn in {self.vertex_name} FILTER pn._key==@rid LIMIT 1
        FOR c IN 1..1 OUTBOUND pn {self.edge_collection(EdgeTypes.default)} COLLECT WITH COUNT INTO length
        RETURN length
        """

    def query_active_updates(self) -> str:
        return f"""
        FOR c IN {self.in_progress}
        RETURN {{id: c.change, created: c.created, affected_nodes: c.root_node_ids, is_batch: c.is_batch}}
        """

    def query_active_change(self) -> str:
        return f"""
        FOR change IN {self.in_progress}
        FILTER @root_node_ids any in change.parent_node_ids OR @root_node_ids any in change.root_node_ids
        RETURN change
        """

    def update_active_change(self) -> str:
        return f"""
        FOR d in {self.in_progress}
        FILTER d.change == @change
        UPDATE d WITH {{created: DATE_ISO8601(DATE_NOW())}} in {self.in_progress}
        """


class EventGraphDB(GraphDB):
    def __init__(self, real: ArangoGraphDB, event_sender: AnalyticsEventSender):
        self.real = real
        self.event_sender = event_sender
        self.graph_name = real.name

    @property
    def name(self) -> str:
        return self.real.name

    async def get_node(self, model: Model, node_id: NodeId) -> Optional[Json]:
        return await self.real.get_node(model, node_id)

    async def create_node(self, model: Model, node_id: NodeId, data: Json, under_node_id: NodeId) -> Json:
        result = await self.real.create_node(model, node_id, data, under_node_id)
        await self.event_sender.core_event(CoreEvent.NodeCreated, {"graph": self.graph_name})
        return result

    async def update_deferred_edges(self, edges: List[Tuple[NodeId, NodeId, str]], ts: datetime) -> Tuple[int, int]:
        updated, deleted = await self.real.update_deferred_edges(edges, ts)
        await self.event_sender.core_event(CoreEvent.DeferredEdgesUpdated, updated=updated, deleted=deleted)
        return updated, deleted

    async def update_node(
        self, model: Model, node_id: NodeId, patch_or_replace: Json, replace: bool, section: Optional[str]
    ) -> Json:
        result = await self.real.update_node(model, node_id, patch_or_replace, replace, section)
        await self.event_sender.core_event(CoreEvent.NodeUpdated, {"graph": self.graph_name, "section": section})
        return result

    async def delete_node(self, node_id: NodeId) -> None:
        await self.real.delete_node(node_id)
        await self.event_sender.core_event(CoreEvent.NodeDeleted, {"graph": self.graph_name})

    def update_nodes(
        self, model: Model, patches_by_id: Dict[NodeId, Json], **kwargs: Any
    ) -> AsyncGenerator[Json, None]:
        return self.real.update_nodes(model, patches_by_id, **kwargs)

    async def update_nodes_desired(
        self, model: Model, patch: Json, node_ids: List[NodeId], **kwargs: Any
    ) -> AsyncGenerator[Json, None]:
        result = self.real.update_nodes_desired(model, patch, node_ids, **kwargs)
        await self.event_sender.core_event(
            CoreEvent.NodesDesiredUpdated, {"graph": self.graph_name}, updated=len(node_ids)
        )
        async for a in result:
            yield a

    async def update_nodes_metadata(
        self, model: Model, patch: Json, node_ids: List[NodeId], **kwargs: Any
    ) -> AsyncGenerator[Json, None]:
        result = self.real.update_nodes_metadata(model, patch, node_ids, **kwargs)
        await self.event_sender.core_event(
            CoreEvent.NodesMetadataUpdated, {"graph": self.graph_name}, updated=len(node_ids)
        )
        async for a in result:
            yield a

    async def merge_graph(
        self, graph_to_merge: MultiDiGraph, model: Model, maybe_change_id: Optional[str] = None, is_batch: bool = False
    ) -> Tuple[List[str], GraphUpdate]:
        roots, info = await self.real.merge_graph(graph_to_merge, model, maybe_change_id, is_batch)
        root_counter: Dict[str, int] = {}
        for root in roots:
            root_node = graph_to_merge.nodes[root]
            rep_id = value_in_path_get(root_node, NodePath.reported_id, root)
            root_counter[f"node_count_{rep_id}.total"] = value_in_path_get(root_node, NodePath.descendant_count, 0)
            summary: Dict[str, int] = value_in_path_get(root_node, NodePath.descendant_summary, {})
            for nd_name, nd_count in summary.items():
                root_counter[f"node_count_{rep_id}.{nd_name}"] = nd_count

        # Filter the cloud nodes and get the name
        provider_names = [
            value_in_path_get(data, NodePath.reported_name, node_id)
            for node_id, data in graph_to_merge.nodes(data=True)
            if "cloud" in data.get("kinds", [])
        ]
        event_data: Dict[str, JsonElement] = {"graph": self.graph_name, "providers": provider_names, "batch": is_batch}

        kind = CoreEvent.BatchUpdateGraphMerged if is_batch else CoreEvent.GraphMerged
        await self.event_sender.core_event(
            kind,
            event_data,
            nodes=len(graph_to_merge.nodes),
            edges=len(graph_to_merge.edges),
            updated_roots=len(roots),
            updated=info.all_changes(),
            nodes_updated=info.nodes_updated,
            nodes_deleted=info.nodes_deleted,
            nodes_created=info.nodes_created,
            edges_created=info.edges_created,
            edges_updated=info.edges_updated,
            edges_deleted=info.edges_deleted,
            **root_counter,
        )
        return roots, info

    async def list_in_progress_updates(self) -> List[Json]:
        return await self.real.list_in_progress_updates()

    async def commit_batch_update(self, batch_id: str) -> None:
        info = first(lambda x: x["id"] == batch_id, await self.real.list_in_progress_updates())
        await self.real.commit_batch_update(batch_id)
        await self.event_sender.core_event(CoreEvent.BatchUpdateCommitted, {"graph": self.graph_name, "batch": info})

    async def abort_update(self, batch_id: str) -> None:
        info = first(lambda x: x["id"] == batch_id, await self.real.list_in_progress_updates())
        await self.real.abort_update(batch_id)
        await self.event_sender.core_event(CoreEvent.BatchUpdateAborted, {"graph": self.graph_name, "batch": info})

    async def search_list(
        self, query: QueryModel, with_count: bool = False, timeout: Optional[timedelta] = None, **kwargs: Any
    ) -> AsyncCursorContext:
        counters, context = query.query.analytics()
        await self.event_sender.core_event(CoreEvent.Query, context, **counters)
        return await self.real.search_list(query, with_count, timeout, **kwargs)

    async def search_history(
        self,
        query: QueryModel,
        change: Optional[HistoryChange] = None,
        before: Optional[datetime] = None,
        after: Optional[datetime] = None,
        with_count: bool = False,
        timeout: Optional[timedelta] = None,
        **kwargs: Any,
    ) -> AsyncCursorContext:
        counters, context = query.query.analytics()
        await self.event_sender.core_event(CoreEvent.HistoryQuery, context, **counters)
        return await self.real.search_history(query, change, before, after, with_count, timeout, **kwargs)

    async def search_graph_gen(
        self, query: QueryModel, with_count: bool = False, timeout: Optional[timedelta] = None
    ) -> AsyncCursorContext:
        counters, context = query.query.analytics()
        await self.event_sender.core_event(CoreEvent.Query, context, **counters)
        return await self.real.search_graph_gen(query, with_count, timeout)

    async def search_aggregation(self, query: QueryModel) -> AsyncCursorContext:
        counters, context = query.query.analytics()
        await self.event_sender.core_event(CoreEvent.Query, context, **counters)
        return await self.real.search_aggregation(query)

    async def search_graph(self, query: QueryModel) -> MultiDiGraph:
        counters, context = query.query.analytics()
        await self.event_sender.core_event(CoreEvent.Query, context, **counters)
        return await self.real.search_graph(query)

    async def explain(self, query: QueryModel, with_edges: bool = False) -> EstimatedSearchCost:
        return await self.real.explain(query)

    async def wipe(self) -> None:
        await self.real.wipe()
        await self.event_sender.core_event(CoreEvent.GraphDBWiped, {"graph": self.graph_name})

    async def to_query(self, query_model: QueryModel, with_edges: bool = False) -> Tuple[str, Json]:
        return await self.real.to_query(query_model, with_edges)

    async def create_update_schema(self) -> None:
        await self.real.create_update_schema()
