import json
import logging
import re
from collections import defaultdict
from datetime import datetime, timedelta
from textwrap import dedent
from typing import Union, List, Tuple, Any, Optional, Dict, Literal, Collection

from arango.typings import Json
from attrs import evolve

from fixcore.constants import less_greater_then_operations as lgt_ops, arangodb_matches_null_ops
from fixcore.db import EstimatedSearchCost, EstimatedQueryCostRating as Rating
from fixcore.db.arangodb_functions import as_arangodb_function
from fixcore.db.model import QueryModel
from fixcore.model.graph_access import Section, Direction
from fixcore.model.model import SyntheticProperty, ResolvedPropertyPath
from fixcore.model.resolve_in_graph import GraphResolver
from fixcore.query.model import (
    Predicate,
    IsTerm,
    Part,
    Term,
    CombinedTerm,
    FunctionTerm,
    Navigation,
    IdTerm,
    Aggregate,
    AllTerm,
    AggregateFunction,
    Sort,
    WithClause,
    AggregateVariableName,
    AggregateVariableCombined,
    NotTerm,
    MergeTerm,
    MergeQuery,
    Query,
    SortOrder,
    FulltextTerm,
    Limit,
    ContextTerm,
    WithUsage,
)
from fixcore.util import set_value_in_path, exist, utc_str
from fixlib.durations import duration_str

log = logging.getLogger(__name__)

# Those words are keywords in aql and need to be "escaped"
escape_aql_parts = {
    "collect",
    "filter",
    "for",
    "insert",
    "let",
    "limit",
    "remove",
    "replace",
    "return",
    "search",
    "sort",
    "update",
    "upsert",
    "window",
    "with",
}

allowed_first_merge_part = Part(AllTerm())
unset_props = json.dumps(["flat"])
# This list of delimiter is also used in the arango delimiter index.
# In case the definition is changed, also the index needs to change!
fulltext_delimiter = [" ", "_", "-", "@", ":", "/", "."]
fulltext_delimiter_regexp = re.compile("[" + "".join(re.escape(a) for a in fulltext_delimiter) + "]+")

# All resolved ancestors attributes have to be treated explicitly.
# Queries with /ancestors.kind.xxx have to be treated as merge query parameters.

array_marker = re.compile(r"\[]|\[\*]")
array_marker_in_path_regexp = re.compile(r"(?:\[]|\[\*])(?=[.])")


class ArangoQueryContext:
    def __init__(self) -> None:
        self.counters: Dict[str, int] = defaultdict(lambda: 0)
        self.bind_vars: Dict[str, Any] = {}

    def next_counter(self, name: str) -> int:
        count = self.counters[name]
        self.counters[name] = count + 1
        return count

    def next_crs(self, name: str = "m") -> str:
        return f"{name}{self.next_counter(name)}"

    def next_bind_var_name(self) -> str:
        return f'b{self.next_counter("bind_vars")}'

    def add_bind_var(self, value: Any) -> str:
        bvn = self.next_bind_var_name()
        self.bind_vars[bvn] = value
        return bvn


def to_query(
    db: Any,
    query_model: QueryModel,
    with_edges: bool = False,
    from_collection: Optional[str] = None,
    id_column: str = "_key",
) -> Tuple[str, Json]:
    ctx = ArangoQueryContext()
    query = query_model.query
    start = from_collection or f"`{db.graph_vertex_name()}`"
    cursor, query_str = query_string(db, query, query_model, start, with_edges, ctx, id_column=id_column)
    last_limit = f" LIMIT {ll.offset}, {ll.length}" if (ll := query.current_part.limit) else ""
    return f"""{query_str} FOR result in {cursor}{last_limit} RETURN UNSET(result, {unset_props})""", ctx.bind_vars


def query_string(
    db: Any,
    query: Query,
    query_model: QueryModel,
    start_cursor: str,
    with_edges: bool,
    ctx: ArangoQueryContext,
    *,
    outer_merge: Optional[str] = None,
    id_column: str = "_key",
) -> Tuple[str, str]:
    # Note: the parts are maintained in reverse order
    query_parts = query.parts[::-1]
    model = query_model.model

    def prop_name_kind(
        path: str, context_path: Optional[str] = None
    ) -> Tuple[str, ResolvedPropertyPath, Optional[str]]:  # prop_name, prop, merge_name
        local_path = f"{context_path}.{path}" if context_path else path
        resolved, merge_name = query_model.prop_kind(local_path)

        def synthetic_path(synth: SyntheticProperty) -> str:
            before, after = local_path.rsplit(resolved.prop.name, 1)
            return f'{before}{".".join(synth.path)}{after}'

        def escape_part(path_part: str) -> str:
            return f"`{path_part}`" if path_part.lower() in escape_aql_parts else path_part

        prop_name = synthetic_path(resolved.prop.synthetic) if resolved.prop.synthetic else local_path

        # remove the context from the path
        if context_path and prop_name.startswith(context_path):
            prop_name = prop_name[len(context_path) + 1 :]
        # make sure the path does not contain any aql keywords
        prop_name = ".".join(escape_part(pn) for pn in prop_name.split("."))

        return prop_name, resolved, merge_name

    def aggregate(in_cursor: str, a: Aggregate) -> Tuple[str, str]:
        cursor_lookup: Dict[Tuple[str, ...], str] = {}
        nested_function_lookup: Dict[AggregateFunction, str] = {}
        nested = {name for agg in a.group_by for name in agg.all_names() if array_marker.search(name)}
        # If we have a nested array, we need to unfold the array and create a new for loop for each array access.
        if nested:
            cursor = ctx.next_crs("agg")
            for_loop = f"for {cursor} in {in_cursor}"
            internals = []
            for ag in nested:
                inner_crsr = cursor
                ars = [a.lstrip(".") for a in array_marker.split(ag)]
                ar_parts = []
                for ar in ars[0:-1]:
                    ar_parts.append(ar)
                    if existing_nested := cursor_lookup.get(tuple(ar_parts)):
                        inner_crsr = existing_nested
                        continue
                    nxt_crs = ctx.next_crs("pre")
                    cursor_lookup[tuple(ar_parts)] = nxt_crs
                    for_loop += f" FOR {nxt_crs} IN APPEND(TO_ARRAY({inner_crsr}.{ar}), {{_internal: true}})"
                    internals.append(f"{nxt_crs}._internal!=true")
                    inner_crsr = nxt_crs
            for_loop += f" FILTER {' AND '.join(internals)}"
        else:
            cursor = ctx.next_crs("agg")
            for_loop = f"for {cursor} in {in_cursor}"

        # the property needs to be accessed from the correct cursor
        def prop_for(name: str) -> str:
            ars = [a.lstrip(".") for a in array_marker.split(name)]
            if len(ars) == 1:  # no array access
                return f"{cursor}.{name}"
            else:  # array access
                if ars[-1] == "":  # last part is array
                    return cursor_lookup[tuple(ars[0:-1])]
                else:
                    return f"{cursor_lookup[tuple(ars[0:-1])]}.{ars[-1]}"

        # the function needs to be accessed from the correct cursor or from a let expression
        def function_value_for(fn: AggregateFunction, name: str) -> str:
            ars = [a.lstrip(".") for a in array_marker_in_path_regexp.split(name)]
            if len(ars) == 1:  # no array access
                return f"{cursor}.{fn.name}"
            elif tuple(ars[0:-1]) in cursor_lookup:  # array access with a related group variable
                return f"{cursor_lookup[tuple(ars[0:-1])]}.{ars[-1]}"
            else:  # array access without a related group variable -> let expression
                return nested_function_lookup[fn]

        # compute the correct cursor name for the given variable
        def var_name(n: Union[AggregateVariableName, AggregateVariableCombined]) -> str:
            def comb_name(cb: Union[str, AggregateVariableName]) -> str:
                return f'"{cb}"' if isinstance(cb, str) else prop_for(cb.name)

            return (
                prop_for(n.name)
                if isinstance(n, AggregateVariableName)
                else f'CONCAT({",".join(comb_name(cp) for cp in n.parts)})'
            )

        # compute the correct function term for the given function
        def func_term(fn: AggregateFunction) -> str:
            name = function_value_for(fn, fn.name) if isinstance(fn.name, str) else str(fn.name)
            return f"{name} {fn.combined_ops()}" if fn.ops else name

        # if the function accesses an array, we need to handle this specially
        # - in case the property name is also used in the group by, we can simply use the variable cursor
        # - if not we need to create a separate let expression before the collect statement
        #   inside the collect / aggregate we can refer to the let expression
        # - if only a part of property name is used, use the last known cursor.
        #   example: a[*].c in var and a[*].b[*].d in group -> use the a[*] cursor
        def unfold_array_func_term(fn: AggregateFunction) -> Optional[str]:
            if isinstance(fn.name, int):
                return None
            ars = [a.lstrip(".") for a in array_marker_in_path_regexp.split(fn.name)]
            if len(ars) == 1:
                return None
            # array access without a related group variable.
            res = ctx.next_crs("agg_let")
            nested_function_lookup[fn] = res
            pre = ""
            current = cursor
            car = []
            for ar in ars[0:-1]:
                car.append(ar)
                tcar = tuple(car)
                if tcar in cursor_lookup:
                    current = cursor_lookup[tcar]
                    continue
                nxt_crs = ctx.next_crs("inner")
                pre += f" FOR {nxt_crs} IN TO_ARRAY({current}.{ar})"
                current = nxt_crs
            return f"LET {res} = {fn.function}({pre} RETURN {current}.{ars[-1]})"

        variables = ", ".join(f"var_{num}={var_name(v.name)}" for num, v in enumerate(a.group_by))
        agg_vars = ", ".join(f'"{v.get_as_name()}": var_{num}' for num, v in enumerate(a.group_by))
        array_functions = " ".join((af for af in (unfold_array_func_term(f) for f in a.group_func) if af is not None))
        funcs = ", ".join(f"fn_{num}={f.function}({func_term(f)})" for num, f in enumerate(a.group_func))
        agg_funcs = ", ".join(f'"{f.get_as_name()}": fn_{num}' for num, f in enumerate(a.group_func))
        group_result = f'"group":{{{agg_vars}}},' if a.group_by else ""
        aggregate_term = f"collect {variables} aggregate {funcs}"
        return_result = f"{{{group_result} {agg_funcs}}}"
        return "aggregated", f"LET aggregated = ({for_loop} {array_functions} {aggregate_term} RETURN {return_result})"

    def predicate(
        cursor: str, p: Predicate, context_path: Optional[str] = None
    ) -> Tuple[Optional[str], str, Optional[str]]:
        pre = ""
        extra = ""
        path = p.name

        # handle that the final property is an array: a.b.c[*]
        if "filter" in p.args:
            arr_filter = p.args["filter"]
            extra = f" {arr_filter} "
            if p.name.endswith("[*]"):
                path = p.name
            elif p.name.endswith("[]"):
                path = f"{p.name[:-2]}[*]"
            else:
                path = f"{p.name}[*]"
        elif p.name.endswith("[*]"):
            extra = " any "
            path = p.name
        elif p.name.endswith("[]"):
            extra = " any "
            path = p.name.replace("[]", "[*]")

        prop_name, prop, _ = prop_name_kind(path, context_path)

        # nested prop access needs to be unfolded via separate for loops: a.b[*].c[*].d
        ars = [a.lstrip(".") for a in array_marker_in_path_regexp.split(prop_name)]
        ars_stmts = []
        prop_name = ars.pop()
        for ar in ars:
            nxt_crs = ctx.next_crs("pre")
            ars_stmts.append(f"{nxt_crs}._internal!=true")
            # append an internal element to make sure this for loop always yields at least one result
            # this value will be filtered out explicitly later on.
            # example: group_ip_permissions[*].{ip_ranges[*].cidr_ip="0.0.0.0/0" or ipv6_ranges[*].cidr_ipv6="::/0"}
            # if there are no cidr_ip or cidr_ipv6 ranges, the nested for loops will not yield any results
            # the or condition will not be evaluated and the result will be empty
            # to avoid this, we add an internal element to the result set and filter it out later on
            pre += f" FOR {nxt_crs} IN APPEND(TO_ARRAY({cursor}.{ar}), {{_internal: true}})"
            cursor = nxt_crs

        bvn = ctx.next_bind_var_name()
        op = lgt_ops[p.op] if prop.simple_kind.reverse_order and p.op in lgt_ops else p.op
        if op in ["in", "not in"] and isinstance(p.value, list):
            ctx.bind_vars[bvn] = [prop.kind.coerce(a, array_creation=False) for a in p.value]
        else:
            ctx.bind_vars[bvn] = prop.kind.coerce(p.value, array_creation=False)
        var_name = f"{cursor}.{prop_name}"
        if op == "=~":  # use regex_test to do case-insensitive matching
            p_term = f"REGEX_TEST({var_name}, @{bvn}, true)"
        else:
            p_term = f"{var_name}{extra} {op} @{bvn}"
        post = " AND ".join(ars_stmts) if ars_stmts else None
        # null check is required, since x<anything evaluates to true if x is null!
        return pre, f"({var_name}!=null and {p_term})" if op in arangodb_matches_null_ops else p_term, post

    def context_term(
        cursor: str, aep: ContextTerm, context_path: Optional[str] = None
    ) -> Tuple[Optional[str], str, Optional[str]]:
        predicate_statement = ""
        filter_statement = ""
        post_stmts = []
        path_cursor = cursor
        context_path = f"{context_path}.{aep.name}" if context_path else aep.name
        # unfold only, if random access is required
        if "[]" in aep.name or "[*]" in aep.name:
            spath = array_marker.split(aep.name)
            # in case the array is defined on the last property, it can be ignored
            if spath[-1] == "":
                spath = spath[:-1]
            for ar in [a.lstrip(".") for a in spath]:
                nxt_crs = ctx.next_crs("pre")
                # see predicate for explanation
                post_stmts.append(f"{nxt_crs}._internal!=true")
                predicate_statement += f" FOR {nxt_crs} IN APPEND(TO_ARRAY({path_cursor}.{ar}), {{_internal: true}})"
                path_cursor = nxt_crs
            ps, fs, pss = term(path_cursor, aep.term, context_path)
        else:
            # no unfolding required, just use the current cursor
            # move the context path into the variable name, do not use any local path for rendering
            # (a.b.{c=1 and d=2}) ==> (a.b.c=1 and a.b.d=2)
            ps, fs, pss = term(path_cursor, aep.term.change_variable(lambda x: f"{context_path}.{x}"))
        if ps:
            predicate_statement += ps
        if pss:
            post_stmts.append(pss)
        if fs:
            filter_statement += fs
        post = " AND ".join(post_stmts) if post_stmts else None
        return predicate_statement, filter_statement, post

    def with_id(cursor: str, t: IdTerm) -> str:
        bvn = ctx.next_bind_var_name()
        if len(t.ids) == 1:
            ctx.bind_vars[bvn] = t.ids[0]
            return f"{cursor}.{id_column} == @{bvn}"
        else:
            ctx.bind_vars[bvn] = t.ids
            return f"{cursor}.{id_column} in @{bvn}"

    def is_term(cursor: str, t: IsTerm) -> str:
        is_results = []
        for kind in t.kinds:
            if kind not in model:
                raise AttributeError(f"Given kind does not exist: {kind}")
            bvn = ctx.next_bind_var_name()
            ctx.bind_vars[bvn] = kind
            is_results.append(f"@{bvn} IN {cursor}.kinds")
        is_result = " or ".join(is_results)
        return is_result if len(is_results) == 1 else f"({is_result})"

    def fulltext_term(cursor: str, t: FulltextTerm) -> str:
        # This fulltext filter can not take advantage of the fulltext search index.
        # Instead, we filter the resulting entry to match a regular expression derived from the term.
        # The flat property is used via a regexp search.
        bvn = ctx.next_bind_var_name()
        dl = fulltext_delimiter_regexp
        ctx.bind_vars[bvn] = dl.pattern.join(f"{re.escape(w)}" for w in dl.split(t.text))
        return f"REGEX_TEST({cursor}.flat, @{bvn}, true)"

    def not_term(
        cursor: str, t: NotTerm, context_path: Optional[str] = None
    ) -> Tuple[Optional[str], str, Optional[str]]:
        pre, term_string, post = term(cursor, t.term, context_path)
        return pre, f"NOT ({term_string})", post

    def term(
        cursor: str, ab_term: Term, context_path: Optional[str] = None
    ) -> Tuple[Optional[str], str, Optional[str]]:
        if isinstance(ab_term, AllTerm):
            return None, "true", None
        if isinstance(ab_term, Predicate):
            return predicate(cursor, ab_term, context_path)
        if isinstance(ab_term, ContextTerm):
            return context_term(cursor, ab_term, context_path)
        elif isinstance(ab_term, FunctionTerm):
            return None, as_arangodb_function(cursor, ctx.bind_vars, ab_term, query_model), None
        elif isinstance(ab_term, IdTerm):
            return None, with_id(cursor, ab_term), None
        elif isinstance(ab_term, IsTerm):
            return None, is_term(cursor, ab_term), None
        elif isinstance(ab_term, NotTerm):
            return not_term(cursor, ab_term, context_path)
        elif isinstance(ab_term, FulltextTerm):
            return None, fulltext_term(cursor, ab_term), None
        elif isinstance(ab_term, CombinedTerm):
            pre_left, left, post_left = term(cursor, ab_term.left, context_path)
            pre_right, right, post_right = term(cursor, ab_term.right, context_path)
            pre = pre_left + " " + pre_right if pre_left and pre_right else pre_left if pre_left else pre_right
            post = (
                post_left + " AND " + post_right if post_left and post_right else post_left if post_left else post_right
            )
            return pre, f"({left}) {ab_term.op} ({right})", post
        else:
            raise AttributeError(f"Do not understand: {ab_term}")

    def merge(cursor: str, merge_queries: List[MergeQuery]) -> Tuple[str, str]:  # cursor, query
        result_cursor = ctx.next_crs("merge_result")
        merge_cursor = ctx.next_crs()
        merge_result = f"LET {result_cursor} = (FOR {merge_cursor} in {cursor} "
        merge_parts: Json = {}

        def add_merge_query(mq: MergeQuery, part_result: str) -> None:
            nonlocal merge_result
            # make sure the sub query is valid
            f = mq.query.parts[-1]
            assert (
                f.term == AllTerm() and not f.sort and not f.limit and not f.with_clause and not f.tag
            ), "Merge query needs to start with navigation!"
            merge_crsr = ctx.next_crs("merge_part")
            # make sure the limit only yields one element
            mg_crs, mg_query = query_string(
                db,
                mq.query,
                query_model,
                merge_cursor,
                with_edges,
                ctx,
                outer_merge=merge_crsr,
                id_column=id_column,
            )
            if mq.only_first:
                merge_result += (
                    f"LET {part_result}=FIRST({mg_query} FOR r in {mg_crs} LIMIT 1 RETURN UNSET(r, {unset_props}))"
                )
            else:
                merge_result += (
                    f"LET {part_result}=({mg_query} FOR r in {mg_crs} RETURN DISTINCT UNSET(r, {unset_props}))"
                )

        # check if this query points to an already resolved value
        # Currently only resolved ancestors are taken into account:
        # <-[1:]- is(cloud|account|region|zone)
        # noinspection PyUnresolvedReferences
        def is_already_resolved(q: Query) -> Optional[str]:
            def check_is(t: IsTerm) -> Optional[str]:
                for kind in t.kinds:
                    if kind in GraphResolver.resolved_ancestors:
                        return kind
                return None

            # noinspection PyTypeChecker
            return (
                check_is(q.parts[0].term)
                if (
                    len(q.parts) == 2
                    and not q.aggregate
                    and q.parts[1].navigation
                    and q.parts[1].navigation.direction == "in"
                    and q.parts[1].navigation.until > 1
                    and isinstance(q.parts[0].term, IsTerm)
                )
                else None
            )

        for mq_in in merge_queries:
            part_res = ctx.next_crs("part_res")
            resolved = is_already_resolved(mq_in.query)
            if resolved:
                merge_result += (
                    f'LET {part_res} = DOCUMENT("{db.graph_vertex_name()}", {merge_cursor}.refs.{resolved}_id)'
                )
            else:
                add_merge_query(mq_in, part_res)
            set_value_in_path(part_res, mq_in.name, merge_parts)

        def merge_part_result(d: Json) -> str:
            vals = [f"{k}: {merge_part_result(v)}" if isinstance(v, dict) else f"{k}: {v}" for k, v in d.items()]
            return "{" + ", ".join(vals) + "}"

        final_merge = f"RETURN MERGE_RECURSIVE({merge_cursor}, {merge_part_result(merge_parts)}))"
        return result_cursor, f"{merge_result} {final_merge}"

    def part(p: Part, in_cursor: str, part_idx: int) -> Tuple[Part, str, str, str]:
        query_part = ""
        filtered_out = ""
        last_part = len(query.parts) == (part_idx + 1)

        def filter_statement(current_cursor: str, part_term: Term, limit: Optional[Limit]) -> str:
            if isinstance(part_term, AllTerm) and limit is None and not p.sort:
                return current_cursor
            nonlocal query_part, filtered_out
            crsr = ctx.next_crs()
            filtered_out = ctx.next_crs("filter")
            md = f"NOT_NULL({crsr}.metadata, {{}})"
            limited = f" LIMIT {limit.offset}, {limit.length} " if limit else " "
            pre, term_string, post = term(crsr, part_term)
            pre_string = " " + pre if pre else ""
            post_string = f" AND ({post})" if post else ""
            for_stmt = f"FOR {crsr} in {current_cursor}{pre_string} FILTER {term_string}{post_string}"
            # in case nested properties get unfolded, we need to make the list distinct again
            if pre:
                nested_distinct = ctx.next_crs("nested_distinct")
                for_stmt = f"LET {nested_distinct} = ({for_stmt} RETURN DISTINCT {crsr})"
                crsr = ctx.next_crs()
                sort_by = sort(crsr, p.sort) if p.sort else " "
                for_stmt = f"{for_stmt} FOR {crsr} in {nested_distinct}{sort_by}{limited}"
            else:
                sort_by = sort(crsr, p.sort) if p.sort else " "
                for_stmt = f"{for_stmt}{sort_by}{limited}"
            f_res = f'MERGE({crsr}, {{metadata:MERGE({md}, {{"query_tag": "{p.tag}"}})}})' if p.tag else crsr
            return_stmt = f"RETURN {f_res}"
            reverse = "REVERSE" if p.reverse_result else ""
            query_part += f"LET {filtered_out} = {reverse}({for_stmt}{return_stmt})"
            return filtered_out

        def with_usage(in_crsr: str, usage: WithUsage, term: Term, limit: Optional[Limit]) -> str:
            nonlocal query_part

            # split the term and create a filter statement for everything before the usage predicates
            before_term, after_term = term.split_by_usage()

            # the limit is applied here, when the after term does not filter at all
            after_filter_cursor = filter_statement(in_crsr, before_term, limit=limit if after_term.is_all else None)

            # add the usage predicates
            usage_crs = ctx.next_crs("with_usage")
            start = ctx.next_bind_var_name()
            end = ctx.next_bind_var_name()
            start_s = ctx.next_bind_var_name()
            duration = ctx.next_bind_var_name()
            start_time = usage.start_from_now()
            end_time = usage.end_from_now()
            ctx.bind_vars[start] = start_time.timestamp()
            ctx.bind_vars[end] = end_time.timestamp()
            ctx.bind_vars[start_s] = utc_str(start_time)
            ctx.bind_vars[duration] = duration_str(end_time - start_time)
            avgs = []
            merges = []
            for mn in usage.metrics:
                avgs.append(f"{mn}_min = MIN(m.v.{mn}.min), {mn}_avg = AVG(m.v.{mn}.avg), {mn}_max = MAX(m.v.{mn}.max)")
                merges.append(f"{mn}: {{min: {mn}_min, avg: {mn}_avg, max: {mn}_max}}")
            query_part += dedent(
                f"""
                let {usage_crs} = (
                    for r in {after_filter_cursor}
                        let resource=r
                        let resource_usage = first(
                            for m in {db.graph_usage_collection_nane()}
                            filter m.at>=@{start} and m.at<=@{end} and m.id==r._key
                            collect aggregate {", ".join(avgs)}, count = sum(1)
                            return {{usage:{{{",".join(merges)},entries:count,start:@{start_s},duration:@{duration}}}}}
                        )
                        return resource_usage.usage.entries ? merge(resource, resource_usage) : resource
                )
                """
            )

            # finally apply the filter that includes the usage predicates
            return filter_statement(usage_crs, after_term, limit)

        def with_clause(in_crsr: str, clause: WithClause, limit: Optional[Limit]) -> str:
            nonlocal query_part
            # this is the general structure of the with_clause that is created
            #
            # FOR cloud in foo FILTER @0 in cloud.kinds
            #    FOR account IN 0..1 OUTBOUND cloud foo_default
            #    OPTIONS { bfs: true, uniqueVertices: 'global' }
            #    FILTER (cloud._key==account._key) or (@1 in account.kinds)
            #        FOR region in 0..1 OUTBOUND account foo_default
            #        OPTIONS { bfs: true, uniqueVertices: 'global' }
            #         FILTER (cloud._key==region._key) or (@2 in region.kinds)
            #             FOR zone in 0..1 OUTBOUND region foo_default
            #             OPTIONS { bfs: true, uniqueVertices: 'global' }
            #             FILTER (cloud._key==zone._key) or (@3 in zone.kinds)
            #         COLLECT l4_cloud = cloud, l4_account=account, l4_region=region WITH COUNT INTO counter3
            #         FILTER (l4_cloud._key==l4_region._key) or (counter3>=0)
            #     COLLECT l3_cloud = l4_cloud, l3_account=l4_account WITH COUNT INTO counter2
            #     FILTER (l3_cloud._key==l3_account._key) or (counter2>=0) // ==2 regions
            # COLLECT l2_cloud = l3_cloud WITH COUNT INTO counter1
            # FILTER (counter1>=0) //counter is +1 since the node itself is always bypassed
            # RETURN ({cloud: l2_cloud._key, count:counter1})
            current = ctx.next_counter("with_clause")

            def cursor_in(depth: int) -> str:
                return f"c{current}_{depth}"

            l0crsr = cursor_in(0)

            def traversal_filter(cl: WithClause, in_crs: str, depth: int) -> str:
                nav = cl.navigation
                crsr = cursor_in(depth)
                direction = "OUTBOUND" if nav.direction == Direction.outbound else "INBOUND"
                unique = "uniqueEdges: 'path'" if with_edges else "uniqueVertices: 'global'"
                pre, term_string, post = term(crsr, cl.term) if cl.term else (None, "true", None)
                pre_string = " " + pre if pre else ""
                post_string = f" AND ({post})" if post else ""
                filter_clause = f"({term_string})"
                inner = traversal_filter(cl.with_clause, crsr, depth + 1) if cl.with_clause else ""
                filter_root = f"({l0crsr}._key=={crsr}._key) or " if depth > 0 else ""
                edge_type_traversals = f", {direction} ".join(f"`{db.edge_collection(et)}`" for et in nav.edge_types)
                return (
                    f"FOR {crsr} IN 0..{nav.until} {direction} {in_crs} "
                    f"{edge_type_traversals} OPTIONS {{ bfs: true, {unique} }} "
                    f"{pre_string} FILTER {filter_root}{filter_clause}{post_string} "
                ) + inner

            def collect_filter(cl: WithClause, depth: int) -> str:
                fltr = cl.with_filter
                if cl.with_clause:
                    collects = ", ".join(f"l{depth-1}_l{i}_res=l{depth}_l{i}_res" for i in range(0, depth))
                else:
                    collects = ", ".join(f"l{depth-1}_l{i}_res={cursor_in(i)}" for i in range(0, depth))

                if depth == 1:
                    # note: the traversal starts from 0 (only 0 and 1 is allowed)
                    # when we start from 1: increase the count by one to not count the start node
                    # when we start from 0: the start node is expected in the count already
                    filter_term = f"FILTER counter1{fltr.op}{fltr.num + cl.navigation.start}"
                else:
                    root_key = f"l{depth-1}_l0_res._key==l{depth-1}_l{depth-1}_res._key"
                    filter_term = f"FILTER ({root_key}) or (counter{depth}{fltr.op}{fltr.num})"

                inner = collect_filter(cl.with_clause, depth + 1) if cl.with_clause else ""
                return inner + f"COLLECT {collects} WITH COUNT INTO counter{depth} {filter_term} "

            out = ctx.next_crs()

            limited = f" LIMIT {limit.offset}, {limit.length} " if limit else " "
            query_part += (
                f"LET {out} =( FOR {l0crsr} in {in_crsr} "
                + traversal_filter(clause, l0crsr, 1)
                + collect_filter(clause, 1)
                + limited
                + "RETURN l0_l0_res) "
            )
            return out

        def inout(in_crsr: str, start: int, until: int, edge_type: str, direction: str) -> str:
            nonlocal query_part
            in_c = ctx.next_crs("io_in")
            out = ctx.next_crs("io_out")
            out_crsr = ctx.next_crs("io_crs")
            link = ctx.next_crs("io_link")
            unique = "uniqueEdges: 'path'" if with_edges else "uniqueVertices: 'global'"
            link_str = f", {link}" if with_edges else ""
            dir_bound = "OUTBOUND" if direction == Direction.outbound else "INBOUND"
            inout_result = (
                f"MERGE({out_crsr}, {{_from:{link}._from, _to:{link}._to, _link_id:{link}._id}})"
                if with_edges
                else out_crsr
            )
            if outer_merge and part_idx == 0:
                graph_cursor = in_crsr
                outer_for = ""
            else:
                graph_cursor = in_c
                outer_for = f"FOR {in_c} in {in_crsr} "

            query_part += (
                f"LET {out} =({outer_for}"
                f"FOR {out_crsr}{link_str} IN {start}..{until} {dir_bound} {graph_cursor} "
                f"`{db.edge_collection(edge_type)}` OPTIONS {{ bfs: true, {unique} }} "
                f"RETURN DISTINCT {inout_result}) "
            )
            return out

        def navigation(in_crsr: str, nav: Navigation) -> str:
            nonlocal query_part
            all_walks = []
            if nav.direction == Direction.any:
                for et in nav.edge_types:
                    all_walks.append(inout(in_crsr, nav.start, nav.until, et, Direction.inbound))
                for et in nav.maybe_two_directional_outbound_edge_type or nav.edge_types:
                    all_walks.append(inout(in_crsr, nav.start, nav.until, et, Direction.outbound))
            else:
                for et in nav.edge_types:
                    all_walks.append(inout(in_crsr, nav.start, nav.until, et, nav.direction))

            if len(all_walks) == 1:
                return all_walks[0]
            else:
                nav_crsr = ctx.next_crs()
                all_walks_combined = ",".join(all_walks)
                query_part += f"LET {nav_crsr} = UNION_DISTINCT({all_walks_combined})"
                return nav_crsr

        # Skip the limit in case of
        # - with clause: the limit is applied in the with clause
        # - last part: the limit is applied in the outermost for loop
        filter_limit = p.limit if (p.with_clause is None and not last_part) else None
        cursor = in_cursor
        part_term = p.term
        if isinstance(p.term, MergeTerm):
            # only allow a limit in the prefilter, if there is no post filter
            pre_limit = filter_limit if (p.term.post_filter is None or p.term.post_filter.is_all) else None
            filter_cursor = filter_statement(cursor, p.term.pre_filter, pre_limit)
            cursor, merge_part = merge(filter_cursor, p.term.merge)
            query_part += merge_part
            # always do the post filter in case of sort or limit
            part_term = p.term.post_filter if p.term.post_filter else AllTerm()
        if p.with_usage and len(p.with_usage.metrics) > 0:
            # filter is applied in the with usage
            cursor = with_usage(cursor, p.with_usage, part_term, filter_limit)
        else:
            cursor = filter_statement(cursor, part_term, filter_limit)

        # See filter_limit documentation above
        with_clause_limit = p.limit if not last_part else None
        cursor = with_clause(cursor, p.with_clause, with_clause_limit) if p.with_clause else cursor
        cursor = navigation(cursor, p.navigation) if p.navigation else cursor
        return p, cursor, filtered_out, query_part

    def sort(cursor: str, so: List[Sort]) -> str:
        def single_sort(single: Sort) -> str:
            prop_name, resolved, _ = prop_name_kind(single.name)
            order = SortOrder.reverse(single.order) if resolved.simple_kind.reverse_order else single.order
            return f"{cursor}.{prop_name} {order}"

        sorts = ", ".join(single_sort(s) for s in so)
        return f" SORT {sorts} "

    def fulltext(ft_part: Term, filter_term: Term) -> Tuple[str, str]:
        # The fulltext index only understands not, combine and fulltext
        def ft_term(cursor: str, ab_term: Term) -> str:
            if isinstance(ab_term, NotTerm):
                return f"NOT ({ft_term(cursor, ab_term.term)})"
            elif isinstance(ab_term, FulltextTerm):
                bvn = ctx.next_bind_var_name()
                ctx.bind_vars[bvn] = ab_term.text
                # the fulltext index is based on the flat property. The full text term is tokenized.
                return f"PHRASE({cursor}.flat, @{bvn})"
            elif isinstance(ab_term, CombinedTerm):
                left = ft_term(cursor, ab_term.left)
                right = ft_term(cursor, ab_term.right)
                return f"({left}) {ab_term.op} ({right})"
            else:
                raise AttributeError(f"Do not understand: {ab_term}")

        # Since fulltext filtering is handled separately, we replace the remaining filter term in the first part
        query_parts[0] = evolve(query_parts[0], term=filter_term)
        crs = ctx.next_crs()
        doc = f"search_{db.graph_vertex_name()}"
        ftt = ft_term("ft", ft_part)
        q = f"LET {crs}=(FOR ft in {doc} SEARCH ANALYZER({ftt}, 'delimited') SORT BM25(ft) DESC RETURN ft)"
        return q, crs

    parts = []
    ft, remaining = fulltext_term_combine(query_parts[0].term)
    fulltext_part, crsr = fulltext(ft, remaining) if ft else ("", start_cursor)
    for idx, p in enumerate(query_parts):
        part_tuple = part(p, crsr, idx)
        parts.append(part_tuple)
        crsr = part_tuple[1]

    query_str = fulltext_part + " ".join(p[3] for p in parts)
    resulting_cursor = crsr
    nxt = ctx.next_crs()
    if query.aggregate:  # return aggregate
        resulting_cursor, aggregation = aggregate(resulting_cursor, query.aggregate)
        query_str += aggregation
        # if the last part has a sort order, we use it here again
        if query.current_part.sort:
            sort_by = sort("res", query.current_part.sort)
            query_str += f" LET {nxt} = (FOR res in {resulting_cursor}{sort_by} RETURN res)"
            resulting_cursor = nxt
    else:  # return results
        # return all tagged commands (last result is "tagged" automatically)
        tagged = {out for part, _, out, _ in parts if part.tag}
        if tagged:
            tagged_union = f'UNION({",".join(tagged)},{resulting_cursor})'
            query_str += f" LET {nxt} = (FOR res in {tagged_union} RETURN res)"
            resulting_cursor = nxt
    return resulting_cursor, query_str


def possible_values(
    db: Any,
    query: QueryModel,
    path_or_predicate: Union[str, Predicate],
    detail: Literal["attributes", "values"],
    limit: Optional[int] = None,
    skip: Optional[int] = None,
) -> Tuple[str, Json]:
    path = path_or_predicate if isinstance(path_or_predicate, str) else path_or_predicate.name
    start = f"`{db.graph_vertex_name()}`"
    ctx = ArangoQueryContext()
    cursor, query_str = query_string(db, query.query, query, start, False, ctx, id_column="_key")

    # iterate over the result
    let_cursor = ctx.next_crs()
    query_str += f" LET {let_cursor} = ("
    next_cursor = ctx.next_crs()
    query_str += f" FOR {next_cursor} in {cursor}"
    cursor = next_cursor

    # expand array paths
    ars = [a.lstrip(".") for a in array_marker_in_path_regexp.split(path)]
    prop_name = None if path.endswith("[]") or path.endswith("[*]") else ars.pop()
    for ar in ars:
        nxt_crs = ctx.next_crs()
        query_str += f" FOR {nxt_crs} IN TO_ARRAY({cursor}.{ar})"
        cursor = nxt_crs
    access_path = f"{cursor}.{prop_name}" if prop_name is not None else cursor

    # access the detail
    if detail == "attributes":
        cursor = ctx.next_crs()
        query_str += (
            f" FILTER IS_OBJECT({access_path}) FOR {cursor} IN ATTRIBUTES({access_path}, true) RETURN {cursor})"
        )
    elif detail == "values":
        query_str += f" RETURN {access_path})"
    else:
        raise AttributeError(f"Unknown detail: {detail}")

    # result stream of matching entries: filter and sort
    sorted_let = ctx.next_crs()
    next_cursor = ctx.next_crs()
    query_str += f" LET {sorted_let} = (FOR {next_cursor} IN {let_cursor} FILTER {next_cursor}!=null"
    cursor = next_cursor
    if isinstance(path_or_predicate, Predicate):
        p: Predicate = path_or_predicate
        bvn = f'b{ctx.next_counter("bind_vars")}'
        prop = query.model.property_by_path(Section.without_section(p.name))
        pk = prop.kind
        op = lgt_ops[p.op] if prop.simple_kind.reverse_order and p.op in lgt_ops else p.op
        ctx.bind_vars[bvn] = [pk.coerce(a) for a in p.value] if isinstance(p.value, list) else pk.coerce(p.value)
        if op == "=~":  # use regex_test to do case-insensitive matching
            query_str += f" FILTER REGEX_TEST({cursor}, @{bvn}, true)"
        else:
            query_str += f" FILTER {cursor} {op} @{bvn}"
    query_str += f" RETURN DISTINCT {cursor})"
    cursor = sorted_let
    next_cursor = ctx.next_crs()
    query_str += f"FOR {next_cursor} IN {cursor} SORT {next_cursor} ASC"
    if limit:
        query_str += f" LIMIT {skip if skip else 0}, {limit}"
    query_str += f" RETURN {next_cursor}"
    return query_str, ctx.bind_vars


def create_time_series(
    query_model: QueryModel, db: Any, time_series_collection: str, time_series: str, at: int
) -> Tuple[str, Json]:
    query = query_model.query
    ctx = ArangoQueryContext()
    start = f"`{db.graph_vertex_name()}`"
    cursor, query_str = query_string(db, query, query_model, start, False, ctx)
    next_crs = ctx.next_crs()
    at_bvn = ctx.add_bind_var(at)
    ts_bvn = ctx.add_bind_var(time_series)
    insert = (
        query_str + f" for {next_crs} in {cursor} insert MERGE({next_crs}, {{at:@{at_bvn}, ts:@{ts_bvn}}})"
        f" into `{time_series_collection}` collect with count into length return length"
    )
    return insert, ctx.bind_vars


def load_time_series(
    time_series_collection: str,
    time_series: str,
    start: datetime,
    end: datetime,
    granularity: timedelta,
    group_aggregation: Literal["avg", "sum", "min", "max"] = "avg",
    group_by: Optional[Collection[str]] = None,
    group_filter: Optional[List[Predicate]] = None,
) -> Tuple[str, Json]:
    ctx = ArangoQueryContext()
    bv_name = ctx.add_bind_var(time_series)
    bv_start = ctx.add_bind_var(int(start.timestamp()))
    bv_end = ctx.add_bind_var(int(end.timestamp()))

    query = f"FOR d in `{time_series_collection}` FILTER d.ts==@{bv_name} AND d.at>=@{bv_start} AND d.at<@{bv_end}"
    if group_filter:
        parts = []
        for f in group_filter:
            bv = ctx.add_bind_var(f.value)
            parts.append(f"d.group.{f.name}{f.op}@{bv}")
        query += f" FILTER {' AND '.join(parts)}"
    time_slot = ctx.next_crs()
    slotter = int(granularity.total_seconds())
    gran = ctx.add_bind_var(slotter)
    offset = start.timestamp() - ((start.timestamp() // slotter) * slotter)
    # slot the time by averaging each single group
    query += f" LET {time_slot} = (FLOOR(d.at / @{gran}) * @{gran}) + @{ctx.add_bind_var(offset)}"
    query += f" COLLECT group_slot={time_slot}, complete_group=d.group"
    query += " AGGREGATE slot_avg = AVG(d.v)"
    query += " RETURN {at: group_slot, group: complete_group, v: slot_avg}"

    # short circuit: no additional grouping and aggregation is avg
    if group_by is None and group_aggregation == "avg":
        return query, ctx.bind_vars  # already the correct query

    # create the groups to collect
    slotted = ctx.next_crs()
    collect = ["group_slot=d.at"]
    group = ""
    if group_by is None:
        collect.append("complete_group=d.group")
        group = "group: complete_group,"
    elif len(group_by) == 0:
        pass  # no other groups
    else:
        parts = []
        for g in group_by:
            collect.append(f"group_{g}=d.group.{g}")
            parts.append(f"{g}: group_{g}")
        group = f"group: {{ {', '.join(parts)} }},"

    query = f"LET {slotted} = ( {query} )\n"
    query += f" FOR d in {slotted} COLLECT {', '.join(collect)}"
    query += f" AGGREGATE agg_val={group_aggregation}(d.v)"
    query += f" SORT group_slot RETURN {{at: group_slot,{group} v: agg_val}}"
    return query, ctx.bind_vars


async def query_cost(graph_db: Any, model: QueryModel, with_edges: bool) -> EstimatedSearchCost:
    q_string, bind = to_query(graph_db, model, with_edges=with_edges)
    nr_nodes = await graph_db.db.count(graph_db.vertex_name)
    plan = await graph_db.db.explain(query=q_string, bind_vars=bind)
    full_collection_scan = exist(lambda node: node["type"] == "EnumerateCollectionNode", plan["nodes"])
    estimated_cost = int(plan["estimatedCost"])
    estimated_items = int(plan["estimatedNrItems"])
    # If the number of returned items is small, most of the computation happens on the db side
    # A higher factor (==estimated cost) is acceptable in this case.
    factor = 20 if estimated_items < 3 else 2.1
    # max upper bound, if the number of nodes is very small
    ratio = estimated_cost / max(10000, nr_nodes * factor)
    # the best rating is complex, if a full collection scan is required.
    best = Rating.complex if full_collection_scan else Rating.simple
    rating = best if ratio < 0.2 else (Rating.complex if ratio < 1 else Rating.bad)
    return EstimatedSearchCost(estimated_cost, estimated_items, nr_nodes, full_collection_scan, rating)


def fulltext_term_combine(term_in: Term) -> Tuple[Optional[Term], Term]:
    """
    Split the term of this part into the independent fulltext term and the remaining part of the term.
    Logic: self.term ~=logical_equivalent=~ fulltext & remaining
    :return: a term that can utilize the fulltext search index and a "normal" filter term.
    """

    def combine_fulltext(term: Term) -> Tuple[Term, Term]:
        if not term.contains_term_type(FulltextTerm):
            return AllTerm(), term
        elif isinstance(term, FulltextTerm):
            return term, AllTerm()
        elif isinstance(term, CombinedTerm):
            if (
                (term.left.contains_term_type(FulltextTerm) or term.right.contains_term_type(FulltextTerm))
                and term.op == "or"
                and term.find_term(lambda x: not isinstance(x, FulltextTerm) and not isinstance(x, CombinedTerm))
            ):
                # This term can not utilize the search index!
                return AllTerm(), term
            left = isinstance(term.left, FulltextTerm)
            right = isinstance(term.right, FulltextTerm)
            if left and right:
                return term, AllTerm()
            elif left:
                ft, remaining = combine_fulltext(term.right)
                return ft.combine(term.op, term.left), remaining
            elif right:
                ft, remaining = combine_fulltext(term.left)
                return ft.combine(term.op, term.right), remaining
            else:
                lf, remaining_left = combine_fulltext(term.right)
                rf, remaining_right = combine_fulltext(term.left)
                return lf.combine(term.op, rf), remaining_left.combine(term.op, remaining_right)
        elif isinstance(term, NotTerm):
            ft, remaining = combine_fulltext(term.term)
            return NotTerm(ft), remaining if isinstance(remaining, AllTerm) else NotTerm(remaining)
        elif isinstance(term, MergeTerm):
            ft, remaining = combine_fulltext(term.pre_filter)
            return ft, evolve(term, pre_filter=remaining)
        else:
            raise AttributeError(f"Can not handle term of type: {type(term)} ({term})")

    fulltext, new_term = combine_fulltext(term_in)
    return (None, term_in) if isinstance(fulltext, AllTerm) else (fulltext, new_term)
