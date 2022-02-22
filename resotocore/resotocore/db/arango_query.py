import json
import logging
import re
from collections import defaultdict
from dataclasses import replace
from typing import Union, List, Tuple, Any, Optional, Dict, Set

from arango.typings import Json

from resotocore.constants import less_greater_then_operations as lgt_ops, arangodb_matches_null_ops
from resotocore.db import EstimatedSearchCost, EstimatedQueryCostRating as Rating
from resotocore.db.arangodb_functions import as_arangodb_function
from resotocore.db.model import QueryModel
from resotocore.model.graph_access import EdgeType, Section, Direction
from resotocore.model.model import SyntheticProperty, ResolvedProperty
from resotocore.model.resolve_in_graph import GraphResolver
from resotocore.query.model import (
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
)
from resotocore.query.query_parser import merge_ancestors_parser
from resotocore.util import first, set_value_in_path, exist

log = logging.getLogger(__name__)

allowed_first_merge_part = Part(AllTerm())
unset_props = json.dumps(["flat"])
# This list of delimiter is also used in the arango delimiter index.
# In case the definition is changed, also the index needs to change!
fulltext_delimiter = [" ", "_", "-", "@", ":", "/", "."]
fulltext_delimiter_regexp = re.compile("[" + "".join(re.escape(a) for a in fulltext_delimiter) + "]+")


def to_query(db: Any, query_model: QueryModel, with_edges: bool = False) -> Tuple[str, Json]:
    count: Dict[str, int] = defaultdict(lambda: 0)
    query = query_model.query
    bind_vars: Json = {}
    cursor, query_str = query_string(db, query, query_model, db.vertex_name, with_edges, bind_vars, count)
    return f"""{query_str} FOR result in {cursor} RETURN UNSET(result, {unset_props})""", bind_vars


def query_string(
    db: Any,
    query: Query,
    query_model: QueryModel,
    start_cursor: str,
    with_edges: bool,
    bind_vars: Json,
    counters: Dict[str, int],
    outer_merge: Optional[str] = None,
) -> Tuple[str, str]:
    # Note: the parts are maintained in reverse order
    query_parts = query.parts[::-1]
    model = query_model.model
    merge_names: Set[str] = query_model.query.merge_names
    mw = query.preamble.get("merge_with_ancestors")
    merge_with: List[str] = re.split("\\s*,\\s*", str(mw)) if mw else []

    def next_counter(name: str) -> int:
        count = counters[name]
        counters[name] = count + 1
        return count

    def next_crs(name: str = "m") -> str:
        return f"{name}{next_counter(name)}"

    def next_bind_var_name() -> str:
        return f'b{next_counter("bind_vars")}'

    def prop_name_kind(path: str) -> Tuple[str, ResolvedProperty, Optional[str]]:  # prop_name, prop, merge_name
        merge_name = first(lambda name: path.startswith(name + "."), merge_names)
        # remove merge_name and section part (if existent) from the path
        lookup = Section.without_section(path[len(merge_name) + 1 :] if merge_name else path)  # noqa: E203
        resolved = model.property_by_path(lookup)

        def synthetic_path(synth: SyntheticProperty) -> str:
            before, after = path.rsplit(resolved.prop.name, 1)
            return f'{before}{".".join(synth.path)}{after}'

        prop_name = synthetic_path(resolved.prop.synthetic) if resolved.prop.synthetic else path

        return prop_name, resolved, merge_name

    def aggregate(in_cursor: str, a: Aggregate) -> Tuple[str, str]:
        cursor = next_crs("agg")

        def var_name(n: Union[AggregateVariableName, AggregateVariableCombined]) -> str:
            def comb_name(cb: Union[str, AggregateVariableName]) -> str:
                return f'"{cb}"' if isinstance(cb, str) else f"{cursor}.{cb.name}"

            return (
                f"{cursor}.{n.name}"
                if isinstance(n, AggregateVariableName)
                else f'CONCAT({",".join(comb_name(cp) for cp in n.parts)})'
            )

        def func_term(fn: AggregateFunction) -> str:
            name = f"{cursor}.{fn.name}" if isinstance(fn.name, str) else str(fn.name)
            return f"{name} {fn.combined_ops()}" if fn.ops else name

        variables = ", ".join(f"var_{num}={var_name(v.name)}" for num, v in enumerate(a.group_by))
        funcs = ", ".join(f"fn_{num}={f.function}({func_term(f)})" for num, f in enumerate(a.group_func))
        agg_vars = ", ".join(f'"{v.get_as_name()}": var_{num}' for num, v in enumerate(a.group_by))
        agg_funcs = ", ".join(f'"{f.get_as_name()}": fn_{num}' for num, f in enumerate(a.group_func))
        group_result = f'"group":{{{agg_vars}}},' if a.group_by else ""
        aggregate_term = f"collect {variables} aggregate {funcs}"
        return_result = f"{{{group_result} {agg_funcs}}}"
        return (
            "aggregated",
            f"LET aggregated = (for {cursor} in {in_cursor} {aggregate_term} RETURN {return_result})",
        )

    def predicate(cursor: str, p: Predicate) -> str:
        extra = ""
        path = p.name

        # handle that property is an array
        if "filter" in p.args:
            arr_filter = p.args["filter"]
            extra = f" {arr_filter} "
            path = f"{p.name}[]"
        elif "[*]" in p.name:
            extra = " any " if "[*]" in p.name else " "
            path = p.name.replace("[*]", "[]")

        prop_name, prop, merge_name = prop_name_kind(path)
        bvn = next_bind_var_name()
        op = lgt_ops[p.op] if prop.kind.reverse_order and p.op in lgt_ops else p.op
        if op in ["in", "not in"] and isinstance(p.value, list):
            bind_vars[bvn] = [prop.kind.coerce(a) for a in p.value]
        else:
            bind_vars[bvn] = prop.kind.coerce(p.value)
        # in case of section: add the section if the predicate does not belong to a merge attribute
        var_name = f"{cursor}.{prop_name}" if merge_name else f"{cursor}.{prop_name}"
        p_term = f"{var_name}{extra} {op} @{bvn}"
        # null check is required, since x<anything evaluates to true if x is null!
        return f"({var_name}!=null and {p_term})" if op in arangodb_matches_null_ops else p_term

    def with_id(cursor: str, t: IdTerm) -> str:
        bvn = next_bind_var_name()
        bind_vars[bvn] = t.id
        return f"{cursor}._key == @{bvn}"

    def is_term(cursor: str, t: IsTerm) -> str:
        is_results = []
        for kind in t.kinds:
            if kind not in model:
                raise AttributeError(f"Given kind does not exist: {kind}")
            bvn = next_bind_var_name()
            bind_vars[bvn] = kind
            is_results.append(f"@{bvn} IN {cursor}.kinds")
        is_result = " or ".join(is_results)
        return is_result if len(is_results) == 1 else f"({is_result})"

    def fulltext_term(cursor: str, t: FulltextTerm) -> str:
        # This fulltext filter can not take advantage of the fulltext search index.
        # Instead, we filter the resulting entry for an occurrence of at least one word in the term.
        # The flat property is used via a regexp search.
        bvn = next_bind_var_name()
        dl = fulltext_delimiter_regexp
        bind_vars[bvn] = dl.pattern.join(f"{re.escape(w)}" for w in dl.split(t.text))
        return f"REGEX_TEST({cursor}.flat, @{bvn}, true)"

    def not_term(cursor: str, t: NotTerm) -> str:
        return f"NOT ({term(cursor, t.term)})"

    def term(cursor: str, ab_term: Term) -> str:
        if isinstance(ab_term, AllTerm):
            return "true"
        if isinstance(ab_term, Predicate):
            return predicate(cursor, ab_term)
        elif isinstance(ab_term, FunctionTerm):
            return as_arangodb_function(cursor, bind_vars, ab_term, query_model)
        elif isinstance(ab_term, IdTerm):
            return with_id(cursor, ab_term)
        elif isinstance(ab_term, IsTerm):
            return is_term(cursor, ab_term)
        elif isinstance(ab_term, NotTerm):
            return not_term(cursor, ab_term)
        elif isinstance(ab_term, FulltextTerm):
            return fulltext_term(cursor, ab_term)
        elif isinstance(ab_term, CombinedTerm):
            left = term(cursor, ab_term.left)
            right = term(cursor, ab_term.right)
            return f"({left}) {ab_term.op} ({right})"
        else:
            raise AttributeError(f"Do not understand: {ab_term}")

    def merge(cursor: str, merge_queries: List[MergeQuery]) -> Tuple[str, str]:  # cursor, query
        result_cursor = next_crs("merge_result")
        merge_cursor = next_crs()
        merge_result = f"LET {result_cursor} = (FOR {merge_cursor} in {cursor} "
        merge_parts: Json = {}

        def add_merge_query(mq: MergeQuery, part_result: str) -> None:
            nonlocal merge_result
            # make sure the sub query is valid
            f = mq.query.parts[-1]
            assert (
                f.term == AllTerm() and not f.sort and not f.limit and not f.with_clause and not f.tag
            ), "Merge query needs to start with navigation!"
            merge_crsr = next_crs("merge_part")
            # make sure the limit only yields one element
            mg_crs, mg_query = query_string(
                db, mq.query, query_model, merge_cursor, with_edges, bind_vars, counters, merge_crsr
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
            part_res = next_crs("part_res")
            resolved = is_already_resolved(mq_in.query)
            if resolved:
                merge_result += f'LET {part_res} = DOCUMENT("{db.vertex_name}", {merge_cursor}.refs.{resolved}_id)'
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

        def filter_statement(current_cursor: str, part_term: Term) -> str:
            if isinstance(part_term, AllTerm) and p.limit is None and not p.sort:
                return current_cursor
            nonlocal query_part, filtered_out
            crsr = next_crs()
            filtered_out = next_crs("filter")
            md = f"NOT_NULL({crsr}.metadata, {{}})"
            f_res = f'MERGE({crsr}, {{metadata:MERGE({md}, {{"query_tag": "{p.tag}"}})}})' if p.tag else crsr
            limited = f" LIMIT {p.limit} " if p.limit else " "
            sort_by = sort(crsr, p.sort) if p.sort else " "
            for_stmt = f"FOR {crsr} in {current_cursor} FILTER {term(crsr, part_term)}{sort_by}{limited}"
            return_stmt = f"RETURN {f_res}"
            query_part += f"LET {filtered_out} = ({for_stmt}{return_stmt})"
            return filtered_out

        def with_clause(in_crsr: str, clause: WithClause) -> str:
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
            current = next_counter("with_clause")

            def cursor_in(depth: int) -> str:
                return f"c{current}_{depth}"

            l0crsr = cursor_in(0)

            def traversal_filter(cl: WithClause, in_crs: str, depth: int) -> str:
                nav = cl.navigation
                crsr = cursor_in(depth)
                direction = "OUTBOUND" if nav.direction == Direction.outbound else "INBOUND"
                unique = "uniqueEdges: 'path'" if with_edges else "uniqueVertices: 'global'"
                filter_clause = f"({term(crsr, cl.term)})" if cl.term else "true"
                inner = traversal_filter(cl.with_clause, crsr, depth + 1) if cl.with_clause else ""
                filter_root = f"({l0crsr}._key=={crsr}._key) or " if depth > 0 else ""
                edge_type_traversals = f", {direction} ".join(db.edge_collection(et) for et in nav.edge_types)
                return (
                    f"FOR {crsr} IN 0..{nav.until} {direction} {in_crs} "
                    f"{edge_type_traversals} OPTIONS {{ bfs: true, {unique} }} "
                    f"FILTER {filter_root}{filter_clause} "
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

            out = next_crs()

            query_part += (
                f"LET {out} =( FOR {l0crsr} in {in_crsr} "
                + traversal_filter(clause, l0crsr, 1)
                + collect_filter(clause, 1)
                + "RETURN l0_l0_res) "
            )
            return out

        def inout(in_crsr: str, start: int, until: int, edge_type: str, direction: str) -> str:
            nonlocal query_part
            in_c = next_crs("io_in")
            out = next_crs("io_out")
            out_crsr = next_crs("io_crs")
            link = next_crs("io_link")
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
                f"{db.edge_collection(edge_type)} OPTIONS {{ bfs: true, {unique} }} "
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
                nav_crsr = next_crs()
                all_walks_combined = ",".join(all_walks)
                query_part += f"LET {nav_crsr} = UNION_DISTINCT({all_walks_combined})"
                return nav_crsr

        if isinstance(p.term, MergeTerm):
            filter_cursor = filter_statement(in_cursor, p.term.pre_filter)
            cursor, merge_part = merge(filter_cursor, p.term.merge)
            query_part += merge_part
            post = p.term.post_filter if p.term.post_filter else AllTerm()
            # always do the post filter in case of sort or limit
            cursor = filter_statement(cursor, post)
        else:
            cursor = filter_statement(in_cursor, p.term)
        cursor = with_clause(cursor, p.with_clause) if p.with_clause else cursor
        cursor = navigation(cursor, p.navigation) if p.navigation else cursor
        return p, cursor, filtered_out, query_part

    def merge_ancestors(cursor: str, part_str: str, ancestor_names: List[str]) -> Tuple[str, str]:
        ancestors: List[Tuple[str, str]] = [merge_ancestors_parser.parse(p) for p in ancestor_names]
        m_parts = [f"FOR node in {cursor} "]

        # filter out resolved ancestors: all remaining ancestors need to be looked up in hierarchy
        to_resolve = [(nr, p_as) for nr, p_as in ancestors if nr not in GraphResolver.resolved_ancestors]
        if to_resolve:
            merge_stop_at = next_bind_var_name()
            merge_ancestor_nodes = next_bind_var_name()
            bind_vars[merge_stop_at] = to_resolve[0][0]
            bind_vars[merge_ancestor_nodes] = [tr[0] for tr in to_resolve]
            m_parts.append(
                "LET ancestor_nodes = ("
                + f"FOR p IN 1..1000 INBOUND node {db.edge_collection(EdgeType.default)} "
                + f"PRUNE @{merge_stop_at} in p.kinds "
                + "OPTIONS {order: 'bfs', uniqueVertices: 'global'} "
                + f"FILTER p.kinds any in @{merge_ancestor_nodes} RETURN p)"
            )
            for tr, _ in to_resolve:
                bv = next_bind_var_name()
                bind_vars[bv] = tr
                m_parts.append(f"""LET {tr} = FIRST(FOR p IN ancestor_nodes FILTER @{bv} IN p.kinds RETURN p)""")

        # all resolved ancestors can be looked up directly
        for tr, _ in ancestors:
            if tr in GraphResolver.resolved_ancestors:
                m_parts.append(f'LET {tr} = DOCUMENT("{db.vertex_name}", node.refs.{tr}_id)')

        result_parts = []
        for section in Section.content_ordered:
            ancestor_result = "{" + ",".join([f"{p[1]}: {p[0]}.{section}" for p in ancestors]) + "}"
            result_parts.append(f"{section}: MERGE(NOT_NULL(node.{section},{{}}), {ancestor_result})")

        m_parts.append("RETURN MERGE(node, {" + ", ".join(result_parts) + "})")
        return "merge_with_ancestor", part_str + f' LET merge_with_ancestor = ({" ".join(m_parts)})'

    def sort(cursor: str, so: List[Sort]) -> str:
        def single_sort(single: Sort) -> str:
            prop_name, resolved, merge_name = prop_name_kind(single.name)
            # in case of section: add the section if the predicate does not belong to a merge attribute
            var_name = f"{cursor}.{prop_name}" if merge_name else f"{cursor}.{prop_name}"
            order = SortOrder.reverse(single.order) if resolved.kind.reverse_order else single.order
            return f"{var_name} {order}"

        sorts = ", ".join(single_sort(s) for s in so)
        return f" SORT {sorts} "

    def fulltext(ft_part: Term, filter_term: Term) -> Tuple[str, str]:
        # The fulltext index only understands not, combine and fulltext
        def ft_term(cursor: str, ab_term: Term) -> str:
            if isinstance(ab_term, NotTerm):
                return f"NOT ({ft_term(cursor, ab_term.term)})"
            elif isinstance(ab_term, FulltextTerm):
                bvn = next_bind_var_name()
                bind_vars[bvn] = ab_term.text
                # the fulltext index is based on the flat property. The full text term is tokenized.
                return f"PHRASE({cursor}.flat, @{bvn})"
            elif isinstance(ab_term, CombinedTerm):
                left = ft_term(cursor, ab_term.left)
                right = ft_term(cursor, ab_term.right)
                return f"({left}) {ab_term.op} ({right})"
            else:
                raise AttributeError(f"Do not understand: {ab_term}")

        # Since fulltext filtering is handled separately, we replace the remaining filter term in the first part
        query_parts[0] = replace(query_parts[0], term=filter_term)
        crs = next_crs()
        doc = f"search_{db.vertex_name}"
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

    all_parts = fulltext_part + " ".join(p[3] for p in parts)
    resulting_cursor, query_str = merge_ancestors(crsr, all_parts, merge_with) if merge_with else (crsr, all_parts)
    nxt = next_crs()
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
            return ft, replace(term, pre_filter=remaining)
        else:
            raise AttributeError(f"Can not handle term of type: {type(term)} ({term})")

    fulltext, new_term = combine_fulltext(term_in)
    return (None, term_in) if isinstance(fulltext, AllTerm) else (fulltext, new_term)
