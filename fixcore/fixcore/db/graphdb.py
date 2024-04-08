import asyncio
import logging
import uuid
from abc import ABC, abstractmethod
from collections import defaultdict
from datetime import datetime, timedelta
from enum import Enum
from functools import partial
from numbers import Number
from textwrap import dedent
from typing import (
    DefaultDict,
    Optional,
    Callable,
    AsyncGenerator,
    Any,
    Iterable,
    Dict,
    List,
    Tuple,
    TypeVar,
    cast,
    AsyncIterator,
    Literal,
    Union,
)

from aiostream import stream, pipe
from arango import AnalyzerGetError
from arango.collection import VertexCollection, StandardCollection, EdgeCollection
from arango.graph import Graph
from arango.typings import Json
from attr import evolve
from networkx import MultiDiGraph

from fixcore.analytics import CoreEvent, AnalyticsEventSender
from fixcore.async_extensions import run_async
from fixcore.core_config import GraphUpdateConfig
from fixcore.db import arango_query, EstimatedSearchCost
from fixcore.db.arango_query import fulltext_delimiter
from fixcore.db.async_arangodb import AsyncArangoDB, AsyncArangoTransactionDB, AsyncArangoDBBase, AsyncCursorContext
from fixcore.db.model import GraphUpdate, QueryModel
from fixcore.db.usagedb import resource_usage_db
from fixcore.error import InvalidBatchUpdate, ConflictingChangeInProgress, NoSuchChangeError, OptimisticLockingFailed
from fixcore.ids import NodeId, GraphName
from fixcore.model.adjust_node import AdjustNode
from fixcore.model.graph_access import GraphAccess, GraphBuilder, EdgeTypes, Section
from fixcore.model.model import (
    Model,
    ComplexKind,
    TransformKind,
    ResolvedPropertyPath,
    UsageDatapoint,
    synthetic_metadata_kinds,
)
from fixcore.model.resolve_in_graph import NodePath, GraphResolver, ResolveProp
from fixcore.model.typed_model import to_js, from_js
from fixcore.query.model import Query, FulltextTerm, MergeTerm, P, Predicate
from fixcore.report import ReportSeverity, SecurityIssue
from fixcore.types import JsonElement, EdgeType
from fixcore.util import (
    first,
    value_in_path_get,
    utc_str,
    uuid_str,
    value_in_path,
    json_hash,
    set_value_in_path,
    if_set,
)

log = logging.getLogger(__name__)


class HistoryChange(Enum):
    node_created = "node_created"  # when the resource is created
    node_updated = "node_updated"  # when the resource is updated
    node_deleted = "node_deleted"  # when the resource is deleted
    node_vulnerable = "node_vulnerable"  # when the resource fails one or more security checks (after being compliant)
    node_compliant = "node_compliant"  # when the resource passes all security checks (after being vulnerable)


class GraphDB(ABC):
    @property
    @abstractmethod
    def name(self) -> GraphName:
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
    async def update_security_section(
        self,
        report_run_id: str,
        iterator: AsyncIterator[Tuple[NodeId, List[SecurityIssue]]],
        model: Model,
        accounts: Optional[List[str]] = None,
    ) -> Tuple[int, int]:
        pass

    @abstractmethod
    async def delete_node(self, node_id: NodeId, model: Model, keep_history: bool = False) -> None:
        pass

    @abstractmethod
    async def merge_graph(
        self,
        graph_to_merge: MultiDiGraph,
        model: Model,
        maybe_change_id: Optional[str] = None,
        is_batch: bool = False,
        update_history: bool = True,
        preserve_parent_structure: bool = False,
    ) -> Tuple[List[str], GraphUpdate]:
        pass

    @abstractmethod
    async def list_in_progress_updates(self) -> List[Json]:
        pass

    @abstractmethod
    async def commit_batch_update(self, batch_id: str, update_history: bool = True) -> None:
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
        changes: Optional[List[HistoryChange]] = None,
        before: Optional[datetime] = None,
        after: Optional[datetime] = None,
        with_count: bool = False,
        timeout: Optional[timedelta] = None,
        **kwargs: Any,
    ) -> AsyncCursorContext:
        pass

    @abstractmethod
    async def list_possible_values(
        self,
        query: QueryModel,
        path_or_predicate: Union[str, Predicate],
        part: Literal["attributes", "values"],
        limit: Optional[int] = None,
        skip: Optional[int] = None,
        with_count: bool = False,
        timeout: Optional[timedelta] = None,
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
    async def search_aggregation(
        self, query: QueryModel, with_count: bool = False, timeout: Optional[timedelta] = None
    ) -> AsyncCursorContext:
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

    @abstractmethod
    async def copy_graph(self, to_graph: GraphName, to_snapshot: bool = False) -> "GraphDB":
        pass

    @abstractmethod
    async def insert_usage_data(self, data: List[UsageDatapoint]) -> None:
        pass

    @abstractmethod
    def graph_vertex_name(self) -> str:
        pass

    @abstractmethod
    def graph_usage_collection_nane(self) -> str:
        pass

    @abstractmethod
    def edge_collection(self, edge_type: EdgeType) -> str:
        pass


class ArangoGraphDB(GraphDB):
    def __init__(self, db: AsyncArangoDB, name: GraphName, adjust_node: AdjustNode, config: GraphUpdateConfig) -> None:
        super().__init__()
        self._name = name
        self.node_adjuster = adjust_node
        self.vertex_name = name
        self.in_progress = f"{name}_in_progress"
        self.node_history = f"{name}_node_history"
        self.usage_db = resource_usage_db(db, f"{name}_usage")
        self.db = db
        self.config = config

    @property
    def name(self) -> GraphName:
        return self._name

    def graph_vertex_name(self) -> str:
        return self.vertex_name

    def graph_usage_collection_nane(self) -> str:
        return self.usage_db.collection_name

    def edge_collection(self, edge_type: EdgeType) -> str:
        return f"{self.name}_{edge_type}"

    async def get_node(self, model: Model, node_id: NodeId) -> Optional[Json]:
        node = await self.by_id(node_id)
        return self.document_to_instance_fn(model)(node) if node is not None else None

    async def create_node(self, model: Model, node_id: NodeId, data: Json, under_node_id: NodeId) -> Json:
        log.info(f"Create node: node_id={node_id}, under_node_id={under_node_id}, data={data}")
        graph = GraphBuilder(model, uuid_str())
        graph.add_node(node_id, data)
        graph.add_edge(under_node_id, node_id, EdgeTypes.default)
        access = GraphAccess(graph.graph, node_id, {under_node_id})
        _, node_inserts, _, _ = self.prepare_nodes(access, [], model)
        _, edge_inserts, _ = self.prepare_edges(access, [], EdgeTypes.default)
        assert len(node_inserts) == 1
        assert len(edge_inserts) == 1
        edge_collection = self.edge_collection(EdgeTypes.default)
        async with self.db.begin_transaction(write=[self.vertex_name, edge_collection]) as tx:
            result: Json = await tx.insert(self.vertex_name, node_inserts[0], return_new=True)  # type: ignore
            await tx.insert(edge_collection, edge_inserts[0])
            trafo = self.document_to_instance_fn(model)
            return trafo(result["new"])

    async def update_deferred_edges(self, edges: List[Tuple[NodeId, NodeId, str]], ts: datetime) -> Tuple[int, int]:
        log.info(f"Update {len(edges)} deferred edges.")
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
        log.info(f"Update node with node_id={node_id}, section={section}, replace={replace}, update={patch_or_replace}")
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
        adjusted = self.adjust_node(
            model, GraphAccess.dump_direct(node_id, updated, kind, recompute=True), ctime, utc_str()
        )
        update = {"_key": node["_key"], "hash": adjusted["hash"], "kinds": adjusted["kinds"], "flat": adjusted["flat"]}
        # copy relevant sections into update node
        for sec in [section] if section else Section.content_ordered:
            if sec in adjusted:
                update[sec] = adjusted[sec]

        async def update_resolved_property(id_prop: ResolveProp, patch: Json, history: bool) -> None:
            log.info(f"Update resolved property: {id_prop.to}={patch} for node_id={node_id}")
            async with await self.db.aql_cursor(
                query=self.update_resolved(id_prop, history), bind_vars={"node_id": node_id, "patch": patch}
            ) as crs:
                async for el in crs:
                    part = self.node_history if history else self.vertex_name
                    log.info(f"Updated resolved property in {part}: {el} elements changed.")

        # update resolved properties in vertex and history collection
        if (ra := GraphResolver.resolve_ancestor_for(update)) and (rid := ra.resolves_id()):
            changes: Json = {}
            for prop in ra.resolved_props():
                if value_in_path(node, prop.extract_path) != (nv := value_in_path(update, prop.extract_path)):
                    set_value_in_path(nv, prop.to_path, changes)
            if changes:
                await update_resolved_property(rid, changes, False)
                await update_resolved_property(rid, changes, True)

        # update in database
        result = await self.db.update(self.vertex_name, update, return_new=True, merge=not replace)
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
        log.info(f"Update nodes section: section={section}, patch={patch} on {len(node_ids)} nodes.")
        to_delete = [k for k, v in patch.items() if v is None]
        update = {k: v for k, v in patch.items() if v is not None}
        bind_var = {"patch": update, "delete": to_delete, "node_ids": node_ids}
        trafo = self.document_to_instance_fn(model)
        with await db.aql(query=self.query_update_desired_metadata_many(section), bind_vars=bind_var) as cursor:
            for element in cursor:
                yield trafo(element)

    async def delete_node(self, node_id: NodeId, model: Model, keep_history: bool = False) -> None:
        log.info(f"Delete node {node_id}, keep_history={keep_history}")

        async def delete_children(element: Json) -> None:
            with await self.db.aql(query=self.query_count_direct_children(), bind_vars={"rid": node_id}) as cursor:
                count = cursor.next()
                if count > 0:
                    # Merge a graph with a single node -> logic will remove all children.
                    # Note: this will only work for nodes that are resolved (cloud, account, region, zone...)
                    builder = GraphBuilder(model, node_id)
                    builder.add_node(node_id, reported=element[Section.reported], replace=True)
                    await self.merge_graph(builder.graph, model, node_id, update_history=keep_history)

        async def delete_history(element: Json) -> None:
            # if this element is a resolved kind, we will delete all nodes from history with a reference to this kind
            if (kd := GraphResolver.resolved_kind(element)) and (ref := GraphResolver.resolved_ancestors.get(kd)):
                q = f"FOR doc IN `{self.node_history}` FILTER doc.{ref} == @node_id REMOVE doc IN `{self.node_history}`"
                with await self.db.aql(query=q, bind_vars={"node_id": node_id}):
                    pass

        if node := await self.by_id(node_id):
            await delete_children(node)
            if not keep_history:
                await delete_history(node)
            await self.db.delete_vertex(self.name, {"_id": node["_id"]})

    async def update_security_section(
        self,
        report_run_id: str,
        iterator: AsyncIterator[Tuple[NodeId, List[SecurityIssue]]],
        model: Model,
        accounts: Optional[List[str]] = None,
    ) -> Tuple[int, int]:  # inserted, updated
        accounts_list = accounts or []
        log.info(f"Update security section. run_id={report_run_id} for accounts={accounts_list}")
        temp_collection = await self.get_tmp_collection(report_run_id)
        now = utc_str()
        nodes_vulnerable_new = 0
        nodes_vulnerable_updated = 0

        def read_checks(issues: List[Json]) -> Dict[str, SecurityIssue]:
            result: Dict[str, SecurityIssue] = {}
            for check in issues:
                issue = from_js(check, SecurityIssue)
                if issue.check in result:
                    result[issue.check].benchmarks.update(issue.benchmarks)
                else:
                    result[issue.check] = issue
            return result

        def update_security_section(
            existing_issues: List[Json], actual_issues: List[SecurityIssue]
        ) -> Tuple[List[Json], HistoryChange, ReportSeverity, bool, Json]:
            existing = read_checks(existing_issues)
            updated: Dict[str, SecurityIssue] = {}  # check id -> issue
            diff_compliant: List[Json] = []
            diff_vulnerable: List[Json] = []
            # use this loop to merge actual issues with the same check
            for issue in actual_issues:
                if same_check := updated.get(issue.check):
                    same_check.benchmarks |= issue.benchmarks
                else:
                    updated[issue.check] = issue
            # now compare the updated with the existing issues
            for key, issue in updated.items():
                if same_check := existing.get(key):
                    vulnerable_diff, compliant_diff = same_check.diff(issue)
                    if vulnerable_diff or compliant_diff:
                        if_set(vulnerable_diff, lambda x: diff_vulnerable.append(x.to_json()))
                        if_set(compliant_diff, lambda x: diff_compliant.append(x.to_json()))
                        same_check.severity = issue.severity
                        same_check.benchmarks = issue.benchmarks
                    updated[key] = same_check
                else:
                    issue.opened_at = now
                    diff_vulnerable.append(issue.to_json())
            # deleted issues are compliant
            diff_compliant.extend(v.to_json() for k, v in existing.items() if k not in updated)
            # the node severity is the highest severity of all issues
            previous = max((a.severity for a in existing.values()), default=ReportSeverity.info)
            severity = max((a.severity for a in updated.values()), default=ReportSeverity.info)
            # the node is still vulnerable: the change marks either improvement or worsening
            change = (
                HistoryChange.node_compliant
                # better #1: severity is lower, #2: severity is the same, but less issues
                if (severity < previous or (severity == previous and len(existing) > len(updated)))
                else HistoryChange.node_vulnerable
            )
            diff: Json = {
                HistoryChange.node_compliant.value: diff_compliant,
                HistoryChange.node_vulnerable.value: diff_vulnerable,
            }
            if existing:
                diff["previous"] = previous.value
            changed = bool(diff_compliant or diff_vulnerable)
            return [a.to_json() for a in updated.values()], change, severity, changed, diff

        async def update_chunk(chunk: Dict[NodeId, List[SecurityIssue]]) -> None:
            nonlocal nodes_vulnerable_new, nodes_vulnerable_updated
            async with await self.search_list(
                QueryModel(Query.by(P.with_id(list(chunk.keys()))), model), no_trafo=True
            ) as ctx:
                nodes_to_insert = []
                async for node in ctx:
                    node_id = NodeId(node.pop("_key", ""))
                    node["id"] = node_id  # store the id in the id column (not _key)
                    existing: List[Json] = value_in_path_get(node, NodePath.security_issues, [])
                    updated, change, severity, changed, diff = update_security_section(existing, chunk.get(node_id, []))
                    security_section = dict(
                        issues=updated,
                        opened_at=value_in_path_get(node, NodePath.security_opened_at, now),
                        reopen_counter=value_in_path_get(node, NodePath.security_reopen_counter, -1),
                        run_id=report_run_id,
                        has_issues=True,
                        severity=severity.value,
                    )
                    node["security"] = security_section
                    node["changed_at"] = now
                    if not existing:  # no issues before, but now
                        nodes_vulnerable_new += 1
                        security_section["opened_at"] = now
                        security_section["reopen_counter"] = security_section["reopen_counter"] + 1  # type: ignore
                        node["change"] = "node_vulnerable"
                        node["diff"] = diff
                        nodes_to_insert.append(dict(action="node_vulnerable", node_id=node_id, data=node))
                    elif changed:
                        nodes_vulnerable_updated += 1
                        nodes_to_insert.append(dict(action="node_vulnerable", node_id=node_id, data=node))
                        node["change"] = change.value
                        node["diff"] = diff
                    else:  # no change
                        nodes_to_insert.append(dict(action="mark", node_id=node_id, run_id=report_run_id))
                # note: we can not detect deleted nodes here -> since we marked all new/existing nodes, we can detect deleted nodes in the next step # noqa
                await run_async(temp_collection.insert_many, nodes_to_insert, silent=True)

        async def move_security_temp_to_proper() -> None:
            temp_name = temp_collection.name
            accounts_quoted = ",".join(f'"{acc}"' for acc in accounts_list)
            account_filter = f"and e.ancestors.account.reported.id in [{accounts_quoted}]" if accounts else ""
            aql_updates = [
                # Select all new or updated vulnerable nodes. Insert into history and update vertex.
                f'for e in {temp_name} filter e.action=="node_vulnerable" insert e.data in {self.node_history} update {{_key: e.node_id, security: e.data.security}} in {self.vertex_name} OPTIONS {{mergeObjects: false}}',  # noqa
                # Update security.run_id for all items with the same security issues
                # Mark all nodes in the graph from the nodes in the temp collection.
                f'for e in {temp_name} filter e.action=="mark" update {{_key: e.node_id, security: {{run_id: e.run_id}}}} in {self.vertex_name} OPTIONS {{mergeObjects: true}}',  # Noqa
                # All unmarked nodes in the graph are compliant again.
                # Add history entry and update vertex.
                f'for e in {self.vertex_name} filter e.security.run_id!=null and e.security.run_id!="{report_run_id}" {account_filter} '  # noqa: E501
                f'insert MERGE(UNSET(e, "_key", "_id", "_rev", "flat", "hash"), {{id: e._key, change: "{HistoryChange.node_compliant.value}", changed_at: "{now}", diff:{{previous: e.security.severity, node_compliant:e.security.issues}}, security: {{has_issues:false, run_id:"{report_run_id}", reopen_counter:e.security.reopen_counter, opened_at:e.security.opened_at, closed_at: "{now}"}}}}) in {self.node_history} '  # noqa: E501
                f'update {{_key: e._key, security: {{reopen_counter: e.security.reopen_counter, closed_at: "{now}"}}}} in {self.vertex_name} OPTIONS {{mergeObjects: false}}',  # noqa: E501
            ]
            updates = ";\n".join(map(lambda aql: f"db._createStatement({{ query: `{aql}` }}).execute()", aql_updates))
            await self.db.execute_transaction(
                f'function () {{\nvar db=require("@arangodb").db;\n{updates}\n}}',
                read=[temp_name],
                write=[self.vertex_name, self.node_history],
            )
            log.info("Latest security update available.")

        try:
            # stream updates to the temp collection
            async with (stream.iterate(iterator) | pipe.chunks(1000)).stream() as streamer:
                async for part in streamer:
                    await update_chunk(dict(part))
            # move temp collection to proper and history collection
            await move_security_temp_to_proper()
        finally:
            await self.db.delete_collection(temp_collection.name)
        if nodes_vulnerable_updated or nodes_vulnerable_new:
            log.info(f"Security section updated: {nodes_vulnerable_new} new, {nodes_vulnerable_updated} updated")
        return nodes_vulnerable_new, nodes_vulnerable_updated

    async def by_id(self, node_id: NodeId) -> Optional[Json]:
        return await self.by_id_with(self.db, node_id)

    async def by_id_with(self, db: AsyncArangoDBBase, node_id: NodeId) -> Optional[Json]:
        with await db.aql(query=self.query_node_by_id(), bind_vars={"rid": node_id}) as cursor:
            return cursor.next() if not cursor.empty() else None

    async def list_possible_values(
        self,
        query: QueryModel,
        path_or_predicate: Union[str, Predicate],
        part: Literal["attributes", "values"],
        limit: Optional[int] = None,
        skip: Optional[int] = None,
        with_count: bool = False,
        timeout: Optional[timedelta] = None,
    ) -> AsyncCursorContext:
        q_string, bind = arango_query.possible_values(self, query, path_or_predicate, part, limit, skip)
        return await self.db.aql_cursor(
            query=q_string,
            count=with_count,
            full_count=with_count,
            bind_vars=bind,
            batch_size=10000,
            ttl=cast(Number, int(timeout.total_seconds())) if timeout else None,
        )

    async def search_list(
        self, query: QueryModel, with_count: bool = False, timeout: Optional[timedelta] = None, **kwargs: Any
    ) -> AsyncCursorContext:
        assert query.query.aggregate is None, "Given query is an aggregation function. Use the appropriate endpoint!"
        q_string, bind = await self.to_query(query)
        return await self.db.aql_cursor(
            query=q_string,
            trafo=None if kwargs.get("no_trafo") else self.document_to_instance_fn(query.model, query),
            flatten_nodes_and_edges=True,
            count=with_count,
            full_count=with_count,
            bind_vars=bind,
            batch_size=10000,
            ttl=cast(Number, int(timeout.total_seconds())) if timeout else None,
        )

    async def search_history(
        self,
        query: QueryModel,
        changes: Optional[List[HistoryChange]] = None,
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
        if changes:
            term = term.and_term(P.single("change").is_in([c.value for c in changes]))
        if after:
            term = term.and_term(P.single("changed_at").gt(utc_str(after)))
        if before:
            term = term.and_term(P.single("changed_at").lt(utc_str(before)))
        query = QueryModel(evolve(query.query, parts=[evolve(query.query.current_part, term=term)]), query.model)
        q_string, bind = arango_query.to_query(self, query, from_collection=self.node_history, id_column="id")
        trafo = (
            None
            if query.query.aggregate
            else self.document_to_instance_fn(
                query.model,
                query,
                ["change", "changed_at", "before", "diff"],
                id_column="id",
            )
        )
        ttl = cast(Number, int(timeout.total_seconds())) if timeout else None
        return await self.db.aql_cursor(
            query=q_string,
            trafo=trafo,
            count=with_count,
            full_count=with_count,
            bind_vars=bind,
            batch_size=10000,
            ttl=ttl,
        )

    async def search_graph_gen(
        self, query: QueryModel, with_count: bool = False, timeout: Optional[timedelta] = None
    ) -> AsyncCursorContext:
        assert query.query.aggregate is None, "Given query is an aggregation function. Use the appropriate endpoint!"
        query_string, bind = await self.to_query(query, with_edges=True)
        return await self.db.aql_cursor(
            query=query_string,
            trafo=self.document_to_instance_fn(query.model, query),
            flatten_nodes_and_edges=True,
            bind_vars=bind,
            count=with_count,
            full_count=with_count,
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

    async def search_aggregation(
        self, query: QueryModel, with_count: bool = False, timeout: Optional[timedelta] = None
    ) -> AsyncCursorContext:
        q_string, bind = await self.to_query(query)
        assert query.query.aggregate is not None, "Given query has no aggregation section"
        return await self.db.aql_cursor(
            query=q_string,
            bind_vars=bind,
            count=with_count,
            full_count=with_count,
            ttl=cast(Number, int(timeout.total_seconds())) if timeout else None,
        )

    async def explain(self, query: QueryModel, with_edges: bool = False) -> EstimatedSearchCost:
        return await arango_query.query_cost(self, query, with_edges)

    async def wipe(self) -> None:
        await self.db.truncate(self.vertex_name)
        for edge_type in EdgeTypes.all:
            await self.db.truncate(self.edge_collection(edge_type))
        await self.insert_genesis_data()

    @staticmethod
    def document_to_instance_fn(
        model: Model,
        query: Optional[QueryModel] = None,
        additional_root_props: Optional[List[str]] = None,
        id_column: str = "_key",
    ) -> Callable[[Json], Json]:
        synthetic_metadata = model.predefined_synthetic_props(synthetic_metadata_kinds)
        with_kinds = query and query.is_set("with-kind")

        def props(doc: Json, result: Json, definition: Iterable[str]) -> None:
            for prop in definition:
                if prop in doc and doc[prop]:
                    result[prop] = doc[prop]

        def synth_props(
            doc: Json, result: Json, section: str, synthetic_properties: List[ResolvedPropertyPath]
        ) -> None:
            if (section_in := doc.get(section)) and (section_out := result.get(section)):
                for synth in synthetic_properties:
                    if isinstance(synth.kind, TransformKind) and synth.prop.synthetic:
                        source_value = value_in_path(section_in, synth.prop.synthetic.path)
                        if source_value:
                            section_out[synth.prop.name] = synth.kind.transform(source_value)

        def render_prop(doc: Json, root_level: bool) -> Json:
            if Section.reported in doc or Section.desired in doc or Section.metadata in doc:
                # side note: the dictionary remembers insertion order
                # this order is also used to render the output (e.g. yaml property order)
                result = {"id": doc[id_column], "type": "node"}
                if "_rev" in doc:
                    result["revision"] = doc["_rev"]
                props(doc, result, Section.content_ordered)
                kind = model.get(doc[Section.reported])
                if root_level:
                    props(doc, result, Section.lookup_sections_ordered)
                    if additional_root_props:
                        props(doc, result, additional_root_props)
                    if with_kinds and kind is not None:
                        result["kind"] = to_js(kind)
                if isinstance(kind, ComplexKind):
                    synth_props(doc, result, Section.reported, kind.synthetic_props())
                    synth_props(doc, result, Section.metadata, synthetic_metadata)
                return result
            else:
                return doc

        def render_merge_results(doc: Json, result: Json, q: Query) -> Json:
            for mq in q.merge_query_by_name:
                merged = value_in_path(doc, mq.name)
                if merged:
                    if mq.only_first and isinstance(merged, dict):
                        rd = render_merge_results(merged, render_prop(merged, False), mq.query)
                        set_value_in_path(rd, mq.name, result)
                    elif isinstance(merged, list):
                        rl = [render_merge_results(elem, render_prop(elem, False), mq.query) for elem in merged]
                        set_value_in_path(rl, mq.name, result)
            return result

        def merge_results(doc: Json) -> Json:
            rendered = render_prop(doc, True)
            if query:
                render_merge_results(doc, rendered, query.query)
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

    async def move_temp_to_proper(self, change_id: str, temp_name: str, update_history: bool = True) -> None:
        change_key = str(uuid.uuid5(uuid.NAMESPACE_DNS, change_id))
        log.info(f"Move temp->proper data: change_id={change_id}, change_key={change_key}, temp_name={temp_name}")
        edge_inserts = [
            f'for e in {temp_name} filter e.action=="edge_insert" and e.edge_type=="{a}" '
            f'insert e.data in {self.edge_collection(a)} OPTIONS {{overwriteMode: "replace"}}'
            for a in EdgeTypes.all
        ]
        edge_deletes = [
            f'for e in {temp_name} filter e.action=="edge_delete" and e.edge_type=="{a}" '
            f"remove e.data in {self.edge_collection(a)} OPTIONS {{ ignoreErrors: true }}"
            for a in EdgeTypes.all
        ]
        history_updates = [
            f'for e in {temp_name} filter e.action=="node_created" and e.data.history==true insert MERGE({{id: e.data._key, change: e.action, changed_at: e.data.created}}, UNSET(e.data, "_key", "flat", "hash", "hist_hash", "history")) in {self.node_history}',  # noqa: E501
            f'for e in {temp_name} filter e.action=="node_updated" and e.data.history==true let node = Document(CONCAT("{self.vertex_name}/", e.data._key)) insert MERGE({{id: e.data._key, change: e.action, changed_at: e.data.updated, before: node.reported}}, UNSET(e.data, "_key", "flat", "hash", "hist_hash", "history")) in {self.node_history}',  # noqa: E501
            f'for e in {temp_name} filter e.action=="node_deleted" and e.data.history==true let node = Document(CONCAT("{self.vertex_name}/", e.data._key)) insert MERGE({{id: node._key, change: "node_deleted", deleted: e.data.deleted, changed_at: e.data.deleted}}, UNSET(node, "_key", "_id", "_rev", "flat", "hash", "hist_hash", "history")) in {self.node_history}',  # noqa: E501
        ]
        usage_updates = [
            f'for u in {self.usage_db.collection_name} filter u.change_id=="{change_id}" update {{_key: u.id}} with {{ usage: MERGE(u.v, {{ start: DATE_ISO8601(u.at*1000), duration: "1h" }}) }} in {self.vertex_name} options {{ mergeObjects: false }}'  # noqa: E501
        ]
        updates = ";\n".join(
            map(
                lambda aql: f"db._createStatement({{ query: `{aql}` }}).execute()",
                (history_updates if self.config.keep_history and update_history else [])
                + [
                    f'for e in {temp_name} filter e.action=="node_created" insert UNSET(e.data, "history") in {self.vertex_name} OPTIONS{{overwriteMode: "replace"}}',  # noqa: E501
                    f'for e in {temp_name} filter e.action=="node_updated" let node = Document(CONCAT("{self.vertex_name}/", e.data._key)) update MERGE(UNSET(e.data, "history"), {{metadata: MERGE(NOT_NULL(node.metadata, {{}}), NOT_NULL(e.data.metadata, {{}}))}}) in {self.vertex_name} OPTIONS {{mergeObjects: false}}',  # noqa: E501
                    f'for e in {temp_name} filter e.action=="node_deleted" remove UNSET(e.data, "history") in {self.vertex_name} OPTIONS {{ ignoreErrors: true }}',  # noqa: E501
                ]
                + edge_inserts
                + edge_deletes
                + usage_updates
                + [f'remove {{_key: "{change_key}"}} in {self.in_progress}'],
            )
        )
        cmd = f'function () {{\nvar db=require("@arangodb").db;\n{updates}\n}}'
        await self.db.execute_transaction(
            command=cmd,
            read=[temp_name, self.usage_db.collection_name],
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

    def adjust_node(
        self, model: Model, json: Json, created_at: str, updated_at: str, *, mtime_from_ctime: bool = False
    ) -> Json:
        reported = json[Section.reported]
        # preserve ctime in reported: if it is not set, use the creation time of the object
        if not reported.get("ctime", None):
            kind = model[reported]
            if isinstance(kind, ComplexKind) and "ctime" in kind:
                reported["ctime"] = created_at
        # if no mtime is reported, we set updated_at as modification time
        if not reported.get("mtime", None):
            kind = model[reported]
            if isinstance(kind, ComplexKind) and "mtime" in kind:
                reported["mtime"] = reported.get("ctime", updated_at) if mtime_from_ctime else updated_at

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

        optional_properties = [*Section.all_ordered, "refs", "kinds", "flat", "hash", "hist_hash"]

        def insert_node(node: Json) -> None:
            elem = self.adjust_node(model, node, access.at_json, access.at_json, mtime_from_ctime=True)
            js_doc: Json = {"_key": elem["id"], "created": access.at_json, "updated": access.at_json, "history": True}
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
                resource_deletes.append({"_key": key, "deleted": access.at_json, "history": True})
                info.nodes_deleted += 1
            elif elem["hash"] != hash_string:
                # node is in db and in the graph, content is different
                adjusted: Json = self.adjust_node(model, elem, node["created"], access.at_json)
                history = elem.get("hist_hash") != node.get("hist_hash")
                js = {"_key": key, "created": node["created"], "updated": access.at_json, "history": history}
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
        self,
        graph_to_merge: MultiDiGraph,
        model: Model,
        maybe_change_id: Optional[str] = None,
        is_batch: bool = False,
        update_history: bool = True,
        preserve_parent_structure: bool = False,
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
        log.info(f"merge_graph {len(roots)} merge nodes found. change_id={change_id}, is_batch={is_batch}.")

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

            def parent_edges(edge_type: EdgeType) -> Tuple[str, Json]:
                edge_ids = [self.db_edge_key(f, t) for f, t, et in parent.g.edges(data="edge_type") if et == edge_type]
                return self.edges_by_ids_and_until_replace_node(edge_type, preserve_parent_structure, parent, edge_ids)

            parents_nodes = self.nodes_by_ids_and_until_replace_node(preserve_parent_structure, parent)
            info, nis, nus, nds, eis, eds = await prepare_graph(parent, parents_nodes, parent_edges)
            for num, (root, graph) in enumerate(graphs):
                root_kind = GraphResolver.resolved_kind(graph_to_merge.nodes[root])
                if root_kind:
                    # noinspection PyTypeChecker
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
            await self.persist_update(change_id, is_batch, info, nis, nus, nds, eis, eds, update_history)
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
        update_history: bool,
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
                await self.move_temp_to_proper(change_id, temp.name, update_history)
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

    async def commit_batch_update(self, batch_id: str, update_history: bool = True) -> None:
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

    async def create_update_schema(self, init_with_data: bool = True, to_snapshot: bool = False) -> None:
        db = self.db

        async def create_update_graph(
            graph_name: GraphName, vertex_name: str, edge_name: str
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

        def create_node_indexes(nodes: VertexCollection) -> None:
            node_idxes = {idx["name"]: idx for idx in cast(List[Json], nodes.indexes())}
            # old update node index: remove if still exists
            if "update_nodes_ref_id" in node_idxes:
                nodes.delete_index("update_nodes_ref_id")

            # this index will hold all the necessary data to query for an update (index only query)
            if "update_nodes" not in node_idxes:
                log.info(f"Add index update_nodes on {nodes.name}")
                nodes.add_persistent_index(
                    # if _key was defined as first property, the optimizer would use it in case
                    # a simple id() query would be executed.
                    ["refs.cloud_id", "refs.account_id", "refs.region_id", "hash", "hist_hash", "created", "_key"],
                    sparse=False,
                    name="update_nodes",
                )

            if "kinds_id_name_ctime" not in node_idxes:
                nodes.add_persistent_index(
                    ["kinds[*]", "reported.id", "reported.name", "reported.ctime"],
                    sparse=False,
                    name="kinds_id_name_ctime",
                )

            if "security_overview" not in node_idxes:
                nodes.add_persistent_index(
                    fields=["security.run_id", "security.has_issues", "security.opened_at", "security.severity"],
                    sparse=True,
                    name="security_overview",
                )

        def create_update_collection_indexes(progress: StandardCollection, node_history: StandardCollection) -> None:
            # progress indexes ------
            progress_idxes = {idx["name"]: idx for idx in cast(List[Json], progress.indexes())}
            if "parent_nodes" not in progress_idxes:
                log.info(f"Add index parent_nodes on {progress.name}")
                progress.add_persistent_index(["parent_nodes[*]"], name="parent_nodes")
            if "root_nodes" not in progress_idxes:
                log.info(f"Add index root_nodes on {progress.name}")
                progress.add_persistent_index(["root_nodes[*]"], name="root_nodes")
            # history indexes ------
            nh_idx = {idx["name"]: idx for idx in cast(List[Json], node_history.indexes())}
            if "history_access" not in nh_idx:
                node_history.add_persistent_index(
                    ["id", "change", "changed_at", "kinds[*]", "reported.id", "reported.name", "reported.ctime"],
                    sparse=False,
                    name="history_access",
                )
            ttl_secs = self.config.keep_history_for_days * (24 * 60 * 60)  # days to seconds
            if "ttl_index" in nh_idx:
                node_history.delete_index("ttl_index")
            if "history_ttl" not in nh_idx or value_in_path(nh_idx, ["history_ttl", "expiry_time"]) != ttl_secs:
                if "history_ttl" in nh_idx:
                    node_history.delete_index("history_ttl")
                node_history.add_ttl_index(["changed_at"], ttl_secs, name="history_ttl")

        def create_update_edge_indexes(edges: EdgeCollection) -> None:
            edge_idxes = {idx["name"]: idx for idx in cast(List[Json], edges.indexes())}
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

        if to_snapshot:
            # since the snapshots are immutable, we don't in_progress or node_history collections
            # we only create the indexes on the vertex collection
            create_node_indexes(vertex)
        else:
            in_progress = await create_collection(self.in_progress)
            node_history_collection = await create_collection(self.node_history)
            await run_async(create_node_indexes, vertex)
            await run_async(create_update_collection_indexes, in_progress, node_history_collection)
            await self.usage_db.create_update_schema()

        for edge_type in EdgeTypes.all:
            edge_collection = db.graph(self.name).edge_collection(self.edge_collection(edge_type))
            await run_async(create_update_edge_indexes, edge_collection)

        await create_update_views(vertex)
        if init_with_data:
            await self.insert_genesis_data()

    async def copy_graph(self, to_graph: GraphName, to_snapshot: bool = False) -> GraphDB:
        if await self.db.has_graph(to_graph):
            raise ValueError(f"Graph {to_graph} already exists")

        new_graph_db = ArangoGraphDB(db=self.db, name=to_graph, adjust_node=self.node_adjuster, config=self.config)

        # collection creation can't be a part of a transaction so we do that first
        # we simply reuse the existing create_update_schema method but do not insert any genesis data
        async def create_new_collections(new_db: ArangoGraphDB, to_snapshot: bool) -> None:
            await new_db.create_update_schema(init_with_data=False, to_snapshot=to_snapshot)

        # we want to have a consistent snapshot view of the graph
        async def copy_data() -> None:
            read: List[str] = [self.vertex_name]
            write: List[str] = [new_graph_db.vertex_name]
            queries = [f"FOR v IN `{self.vertex_name}` INSERT v INTO `{new_graph_db.vertex_name}`"]
            if not to_snapshot:  # no history for snapshots
                read.append(self.node_history)
                write.append(new_graph_db.node_history)
                queries.append(f"FOR v IN `{self.node_history}` INSERT v INTO `{new_graph_db.node_history}`")
            for et in EdgeTypes.all:
                new_vertex = new_graph_db.vertex_name
                read.append(self.edge_collection(et))
                write.append(new_graph_db.edge_collection(et))
                queries.append(
                    f"FOR edge IN `{self.edge_collection(et)}` "
                    f"LET from = CONCAT('{new_vertex}', '/', PARSE_IDENTIFIER(edge._from)['key']) "
                    f"LET to = CONCAT('{new_vertex}', '/', PARSE_IDENTIFIER(edge._to)['key']) "
                    f"INSERT MERGE(edge, {{_from: from, _to: to}}) INTO `{new_graph_db.edge_collection(et)}`"
                )

            q_str = "\n".join([f'db._query(query="{q}");' for q in queries])
            tx = f""" function () {{ const db = require('@arangodb').db; {q_str} }}"""
            await self.db.execute_transaction(tx, read=read, write=write)

        await create_new_collections(new_graph_db, to_snapshot=to_snapshot)
        await copy_data()

        return cast(GraphDB, new_graph_db)

    async def insert_usage_data(self, data: List[UsageDatapoint]) -> None:
        if self.name.startswith("snapshot"):
            raise ValueError("Cannot insert usage data into a snapshot graph")
        await self.usage_db.update_many(data)

    @staticmethod
    def db_edge_key(from_node: str, to_node: str) -> str:
        return str(uuid.uuid5(uuid.NAMESPACE_DNS, f"{from_node}:{to_node}"))

    # parameter: rid
    # return: the complete document
    def query_node_by_id(self) -> str:
        return f"""
      FOR resource in `{self.vertex_name}`
      FILTER resource._key==@rid
      LIMIT 1
      RETURN resource
      """

    def query_update_nodes(self, merge_node_kind: str) -> str:
        return f"""
        FOR a IN `{self.vertex_name}`
        FILTER a.refs.{merge_node_kind}_id==@update_id
        RETURN {{_key: a._key, hash:a.hash, hist_hash:a.hist_hash, created:a.created}}
        """

    def query_update_edges(self, edge_type: EdgeType, merge_node_kind: str) -> str:
        collection = self.edge_collection(edge_type)
        return f"""
        FOR a IN `{collection}`
        FILTER a.refs.{merge_node_kind}_id==@update_id
        RETURN {{_key: a._key, _from: a._from, _to: a._to}}
        """

    def query_update_parent_linked(self) -> str:
        return f"""
        FOR a IN `{self.edge_collection(EdgeTypes.default)}`
        FILTER a._from==@from and a._to==@to
        RETURN true
        """

    def query_update_desired_metadata_many(self, section: str) -> str:
        return f"""
        FOR a IN `{self.vertex_name}`
        FILTER a._key in @node_ids
        LET merged_section = MERGE(UNSET(NOT_NULL(a.{section}, {{}}), @delete), @patch)
        UPDATE a with {{ "{section}": merged_section}} IN `{self.vertex_name}`
        OPTIONS {{mergeObjects: false}}
        RETURN NEW
        """

    def query_delete_desired_metadata_many(self, section: str) -> str:
        return f"""
        FOR a IN `{self.vertex_name}`
        FILTER a._key in @node_ids
        REPLACE a with UNSET(a, "{section}") IN `{self.vertex_name}`
        RETURN NEW
        """

    def query_count_direct_children(self) -> str:
        return f"""
        FOR pn in `{self.vertex_name}` FILTER pn._key==@rid LIMIT 1
        FOR c IN 1..1 OUTBOUND pn {self.edge_collection(EdgeTypes.default)} COLLECT WITH COUNT INTO length
        RETURN length
        """

    def query_active_updates(self) -> str:
        return f"""
        FOR c IN `{self.in_progress}`
        RETURN {{id: c.change, created: c.created, affected_nodes: c.root_node_ids, is_batch: c.is_batch}}
        """  # noqa: E501

    def query_active_change(self) -> str:
        return f"""
        FOR change IN `{self.in_progress}`
        FILTER @root_node_ids any in change.parent_node_ids OR @root_node_ids any in change.root_node_ids
        RETURN change
        """

    def update_active_change(self) -> str:
        return f"""
        FOR d in `{self.in_progress}`
        FILTER d.change == @change
        UPDATE d WITH {{created: DATE_ISO8601(DATE_NOW())}} in `{self.in_progress}`
        """  # noqa: E501

    def update_resolved(
        self,
        prop: ResolveProp,
        history: bool = False,
    ) -> str:
        coll = self.node_history if history else self.vertex_name
        return dedent(
            f"""
            FOR d in `{coll}` FILTER d.{prop.to}==@node_id
            UPDATE d WITH @patch in `{coll}`
            COLLECT WITH COUNT INTO count
            RETURN count
            """
        )

    def nodes_by_ids_and_until_replace_node(
        self, preserve_parent_structure: bool, access: GraphAccess
    ) -> Tuple[str, Json]:
        query_update_nodes_by_ids = (
            f"FOR a IN `{self.vertex_name}` "
            "FILTER a._key IN @ids RETURN {_key: a._key, hash:a.hash, hist_hash:a.hist_hash, created:a.created}"
        )
        bind_vars: Json = {"ids": list(access.g.nodes)}
        if preserve_parent_structure:
            cloud_id = access.cloud_node_id()
            assert cloud_id is not None, "When parent structure should be preserved, a cloud node is required!"
            bind_vars["node_id"] = cloud_id
            filter_section = " AND ".join(f"'{kind}' not in node.kinds" for kind in GraphResolver.resolved_ancestors)
            nodes_until_replace_node = f"""
            FOR cloud_node in `{self.vertex_name}` FILTER cloud_node._key == @node_id
            FOR node IN 0..100 OUTBOUND cloud_node
            `{self.edge_collection(EdgeTypes.default)}`
            PRUNE node.metadata["replace"] == true
            OPTIONS {{ bfs: true, uniqueVertices: 'global' }}
            FILTER {filter_section}
            RETURN {{_key: node._key, hash: node.hash, hist_hash:node.hist_hash, created: node.created}}
            """

            statement = f"""
            LET nodes_by_ids = ({query_update_nodes_by_ids})
            LET nodes_until_replace = ({nodes_until_replace_node})
            LET all_of_them = UNION_DISTINCT(nodes_by_ids, nodes_until_replace)
            FOR n IN all_of_them RETURN n
            """
            return statement, bind_vars
        else:
            return query_update_nodes_by_ids, bind_vars

    def edges_by_ids_and_until_replace_node(
        self, edge_type: EdgeType, preserve_parent_structure: bool, access: GraphAccess, edge_ids: List[str]
    ) -> Tuple[str, Json]:
        collection = self.edge_collection(edge_type)
        bind_vars: Json = {"ids": edge_ids}
        query_update_edges_by_ids = (
            f"FOR a IN `{collection}` FILTER a._key in @ids RETURN {{_key: a._key, _from: a._from, _to: a._to}}"
        )
        if preserve_parent_structure:
            cloud_id = access.cloud_node_id()
            assert cloud_id is not None, "When parent structure should be preserved, a cloud node is required!"
            bind_vars["node_id"] = cloud_id
            filter_section = " AND ".join(f"'{kind}' not in node.kinds" for kind in GraphResolver.resolved_ancestors)
            edges_until_replace_node = f"""
            FOR cloud_node in `{self.vertex_name}` FILTER cloud_node._key == @node_id
            FOR node, edge IN 0..100 OUTBOUND cloud_node `{self.edge_collection(edge_type)}`
            PRUNE node.metadata["replace"] == true
            OPTIONS {{ bfs: true, uniqueVertices: 'global' }}
            FILTER {filter_section}
            RETURN {{_key: edge._key, _from: edge._from, _to: edge._to}}
            """
            statement = f"""
            LET edges_by_ids = ({query_update_edges_by_ids})
            LET edges_until_replace = ({edges_until_replace_node})
            LET all_of_them = UNION_DISTINCT(edges_by_ids, edges_until_replace)
            FOR e IN all_of_them RETURN e
            """
            return statement, bind_vars
        else:
            return query_update_edges_by_ids, bind_vars


class EventGraphDB(GraphDB):
    def __init__(self, real: ArangoGraphDB, event_sender: AnalyticsEventSender):
        self.real = real
        self.event_sender = event_sender
        self.graph_name = real.name

    @property
    def name(self) -> GraphName:
        return self.real.name

    @property
    def vertex_name(self) -> str:
        return self.real.vertex_name

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

    async def delete_node(self, node_id: NodeId, model: Model, keep_history: bool = False) -> None:
        await self.real.delete_node(node_id, model, keep_history)
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

    async def update_security_section(
        self,
        report_run_id: str,
        iterator: AsyncIterator[Tuple[NodeId, List[SecurityIssue]]],
        model: Model,
        accounts: Optional[List[str]] = None,
    ) -> Tuple[int, int]:
        return await self.real.update_security_section(report_run_id, iterator, model, accounts)

    async def merge_graph(
        self,
        graph_to_merge: MultiDiGraph,
        model: Model,
        maybe_change_id: Optional[str] = None,
        is_batch: bool = False,
        update_history: bool = True,
        preserve_parent_structure: bool = False,
    ) -> Tuple[List[str], GraphUpdate]:
        roots, info = await self.real.merge_graph(
            graph_to_merge, model, maybe_change_id, is_batch, update_history, preserve_parent_structure
        )
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

    async def commit_batch_update(self, batch_id: str, update_history: bool = True) -> None:
        info = first(lambda x: x["id"] == batch_id, await self.real.list_in_progress_updates())
        await self.real.commit_batch_update(batch_id, update_history)
        await self.event_sender.core_event(CoreEvent.BatchUpdateCommitted, {"graph": self.graph_name, "batch": info})

    async def abort_update(self, batch_id: str) -> None:
        info = first(lambda x: x["id"] == batch_id, await self.real.list_in_progress_updates())
        await self.real.abort_update(batch_id)
        await self.event_sender.core_event(CoreEvent.BatchUpdateAborted, {"graph": self.graph_name, "batch": info})

    async def list_possible_values(
        self,
        query: QueryModel,
        path_or_predicate: Union[str, Predicate],
        part: Literal["attributes", "values"],
        limit: Optional[int] = None,
        skip: Optional[int] = None,
        with_count: bool = False,
        timeout: Optional[timedelta] = None,
    ) -> AsyncCursorContext:
        return await self.real.list_possible_values(query, path_or_predicate, part, limit, skip, with_count, timeout)

    async def search_list(
        self, query: QueryModel, with_count: bool = False, timeout: Optional[timedelta] = None, **kwargs: Any
    ) -> AsyncCursorContext:
        return await self.real.search_list(query, with_count, timeout, **kwargs)

    async def search_history(
        self,
        query: QueryModel,
        changes: Optional[List[HistoryChange]] = None,
        before: Optional[datetime] = None,
        after: Optional[datetime] = None,
        with_count: bool = False,
        timeout: Optional[timedelta] = None,
        **kwargs: Any,
    ) -> AsyncCursorContext:
        counters, context = query.query.analytics()
        await self.event_sender.core_event(CoreEvent.HistoryQuery, context, **counters)
        return await self.real.search_history(query, changes, before, after, with_count, timeout, **kwargs)

    async def search_graph_gen(
        self, query: QueryModel, with_count: bool = False, timeout: Optional[timedelta] = None
    ) -> AsyncCursorContext:
        return await self.real.search_graph_gen(query, with_count, timeout)

    async def search_aggregation(
        self, query: QueryModel, with_count: bool = False, timeout: Optional[timedelta] = None
    ) -> AsyncCursorContext:
        return await self.real.search_aggregation(query, with_count, timeout)

    async def search_graph(self, query: QueryModel) -> MultiDiGraph:
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

    async def copy_graph(self, to_graph: GraphName, to_snapshot: bool = False) -> GraphDB:
        await self.event_sender.core_event(
            CoreEvent.GraphCopied,
            {"graph": self.graph_name, "to_graph": to_graph},
        )
        return await self.real.copy_graph(to_graph, to_snapshot=to_snapshot)

    async def insert_usage_data(self, data: List[UsageDatapoint]) -> None:
        await self.real.insert_usage_data(data)

    def graph_vertex_name(self) -> str:
        return self.real.graph_vertex_name()

    def graph_usage_collection_nane(self) -> str:
        return self.real.graph_usage_collection_nane()

    def edge_collection(self, edge_type: EdgeType) -> str:
        return self.real.edge_collection(edge_type)
