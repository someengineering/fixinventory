import logging
import re
from typing import Union, List, Tuple, Any, Iterator

from arango.typings import Json

from core.constants import less_greater_then_operations as lgt_ops, arangodb_matches_null_ops
from core.db.arangodb_functions import as_arangodb_function
from core.db.model import QueryModel
from core.model.graph_access import EdgeType, Section
from core.model.model import SyntheticProperty
from core.model.resolve_in_graph import GraphResolver
from core.query.model import (
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
)
from core.query.query_parser import merge_ancestors_parser
from core.util import count_iterator

log = logging.getLogger(__name__)


def to_query(db: Any, query_model: QueryModel, with_edges: bool = False) -> Tuple[str, Json]:
    count = count_iterator()
    bind_vars: Json = {}
    cursor, query_str = query_string(db, query_model.query, query_model, db.vertex_name, with_edges, bind_vars, count)
    return f"""{query_str} FOR result in {cursor} RETURN result""", bind_vars


def query_string(
    db: Any,
    query: Query,
    query_model: QueryModel,
    start_cursor: str,
    with_edges: bool,
    bind_vars: Json,
    count: Iterator[int],
) -> Tuple[str, str]:
    model = query_model.model
    section_dot = f"{query_model.query_section}." if query_model.query_section else ""
    mw = query.preamble.get("merge_with_ancestors")
    merge_with: List[str] = re.split("\\s*,\\s*", str(mw)) if mw else []

    def next_crs() -> str:
        return f"n{next(count)}"

    def next_bind_var_name() -> str:
        return f"b{next(count)}"

    def aggregate(in_cursor: str, a: Aggregate) -> Tuple[str, str]:
        cursor = next_crs()

        def var_name(n: Union[AggregateVariableName, AggregateVariableCombined]) -> str:
            def comb_name(cb: Union[str, AggregateVariableName]) -> str:
                return f'"{cb}"' if isinstance(cb, str) else f"{cursor}.{section_dot}{cb.name}"

            return (
                f"{cursor}.{section_dot}{n.name}"
                if isinstance(n, AggregateVariableName)
                else f'CONCAT({",".join(comb_name(cp) for cp in n.parts)})'
            )

        def func_term(fn: AggregateFunction) -> str:
            name = f"{cursor}.{section_dot}{fn.name}" if isinstance(fn.name, str) else str(fn.name)
            return f"{name} {fn.combined_ops()}" if fn.ops else name

        vs = {str(v.name): f"var_{num}" for num, v in enumerate(a.group_by)}
        fs = {v.name: f"fn_{num}" for num, v in enumerate(a.group_func)}
        variables = ", ".join(f"{vs[str(v.name)]}={var_name(v.name)}" for v in a.group_by)
        funcs = ", ".join(f"{fs[v.name]}={v.function}({func_term(v)})" for v in a.group_func)
        agg_vars = ", ".join(f'"{v.get_as_name()}": {vs[str(v.name)]}' for v in a.group_by)
        agg_funcs = ", ".join(f'"{f.get_as_name()}": {fs[f.name]}' for f in a.group_func)
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
        if "array" in p.args:
            arr_filter = p.args["filter"] if "filter" in p.args else "any"
            extra = f" {arr_filter} "
            path = f"{p.name}[]"
        elif "[*]" in p.name:
            extra = " any " if "[*]" in p.name else " "
            path = p.name.replace("[*]", "[]")

        bvn = next_bind_var_name()
        # if no section is given, the path is prefixed by the section: remove the section
        lookup = path if query_model.query_section else Section.without_section(path)
        prop = model.property_by_path(lookup)

        def synthetic_path(synth: SyntheticProperty) -> str:
            before, after = p.name.rsplit(prop.prop.name, 1)
            return f'{before}{".".join(synth.path)}{after}'

        op = lgt_ops[p.op] if prop.kind.reverse_order and p.op in lgt_ops else p.op
        if op in ["in", "not in"] and isinstance(p.value, list):
            bind_vars[bvn] = [prop.kind.coerce(a) for a in p.value]
        else:
            bind_vars[bvn] = prop.kind.coerce(p.value)
        prop_name = synthetic_path(prop.prop.synthetic) if prop.prop.synthetic else p.name
        var_name = f"{cursor}.{section_dot}{prop_name}"
        p_term = f"{var_name}{extra} {op} @{bvn}"
        # null check is required, since x<anything evaluates to true if x is null!
        return f"({var_name}!=null and {p_term})" if op in arangodb_matches_null_ops else p_term

    def with_id(cursor: str, t: IdTerm) -> str:
        bvn = next_bind_var_name()
        bind_vars[bvn] = t.id
        return f"{cursor}._key == @{bvn}"

    def is_instance(cursor: str, t: IsTerm) -> str:
        if t.kind not in model:
            raise AttributeError(f"Given kind does not exist: {t.kind}")
        bvn = next_bind_var_name()
        bind_vars[bvn] = t.kind
        return f"@{bvn} IN {cursor}.kinds"

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
            return is_instance(cursor, ab_term)
        elif isinstance(ab_term, NotTerm):
            return not_term(cursor, ab_term)
        elif isinstance(ab_term, CombinedTerm):
            left = term(cursor, ab_term.left)
            right = term(cursor, ab_term.right)
            return f"({left}) {ab_term.op} ({right})"
        else:
            raise AttributeError(f"Do not understand: {ab_term}")

    def merge(cursor: str, merge_queries: List[MergeQuery]) -> Tuple[str, str]:  # cursor, query
        merge_name = f"merge{next(count)}"
        merge_result = ""
        merge_parts = []
        for q in merge_queries:
            merge_crsr = next_crs()
            inter_crsr = next_crs()
            # make sure the limit only yields one element
            mg_crs, mg_query = query_string(
                db, q.query.with_limit(1), query_model, cursor, with_edges, bind_vars, count
            )
            merge_result += f"LET {merge_crsr}=({mg_query} FOR {inter_crsr} in {mg_crs} RETURN {inter_crsr})"
            merge_parts.append(f"{q.name}: FIRST({merge_crsr})")

        result_crs = next_crs()
        final_merge = f'FOR {result_crs} IN {cursor} RETURN MERGE({result_crs}, {{{", ".join(merge_parts)}}})'
        return merge_name, f"LET {merge_name}=({merge_result} {final_merge})"

    def part(p: Part, in_cursor: str) -> Tuple[Part, str, str, str]:
        query_part = ""
        filtered_out = ""

        def filter_statement(current_cursor: str, part_term: Term) -> str:
            nonlocal query_part, filtered_out
            crsr = next_crs()
            filtered_out = next_crs()
            md = f"NOT_NULL({crsr}.metadata, {{}})"
            f_res = f'MERGE({crsr}, {{metadata:MERGE({md}, {{"query_tag": "{p.tag}"}})}})' if p.tag else crsr
            limited = f" LIMIT {p.limit} " if p.limit else " "
            sort_by = sort(crsr, p.sort, section_dot) if p.sort else " "
            for_stmt = f"FOR {crsr} in {current_cursor} FILTER {term(crsr, part_term)}{sort_by}{limited}RETURN {f_res}"
            query_part += f"LET {filtered_out} = ({for_stmt})"
            print(f"filter: LET {filtered_out} = ({for_stmt})")
            return filtered_out

        def with_clause(in_crsr: str, clause: WithClause) -> str:
            nonlocal query_part
            # this is the general structure of the with_clause that is created
            #
            # FOR cloud in foo FILTER @0 in cloud.kinds
            #    FOR account IN 0..1 OUTBOUND cloud foo_dependency
            #    OPTIONS { bfs: true, uniqueVertices: 'global' }
            #    FILTER (cloud._key==account._key) or (@1 in account.kinds)
            #        FOR region in 0..1 OUTBOUND account foo_dependency
            #        OPTIONS { bfs: true, uniqueVertices: 'global' }
            #         FILTER (cloud._key==region._key) or (@2 in region.kinds)
            #             FOR zone in 0..1 OUTBOUND region foo_dependency
            #             OPTIONS { bfs: true, uniqueVertices: 'global' }
            #             FILTER (cloud._key==zone._key) or (@3 in zone.kinds)
            #         COLLECT l4_cloud = cloud, l4_account=account, l4_region=region WITH COUNT INTO counter3
            #         FILTER (l4_cloud._key==l4_region._key) or (counter3>=0)
            #     COLLECT l3_cloud = l4_cloud, l3_account=l4_account WITH COUNT INTO counter2
            #     FILTER (l3_cloud._key==l3_account._key) or (counter2>=0) // ==2 regions
            # COLLECT l2_cloud = l3_cloud WITH COUNT INTO counter1
            # FILTER (counter1>=0) //counter is +1 since the node itself is always bypassed
            # RETURN ({cloud: l2_cloud._key, count:counter1})
            current = next(count)

            def cursor_in(depth: int) -> str:
                return f"c{current}_{depth}"

            l0crsr = cursor_in(0)

            def traversal_filter(cl: WithClause, in_crs: str, depth: int) -> str:
                nav = cl.navigation
                crsr = cursor_in(depth)
                direction = "OUTBOUND" if nav.direction == "out" else "INBOUND"
                unique = "uniqueEdges: 'path'" if with_edges else "uniqueVertices: 'global'"
                filter_clause = f"({term(crsr, cl.term)})" if cl.term else "true"
                inner = traversal_filter(cl.with_clause, crsr, depth + 1) if cl.with_clause else ""
                filter_root = f"({l0crsr}._key=={crsr}._key) or " if depth > 0 else ""
                return (
                    f"FOR {crsr} IN 0..{nav.until} {direction} {in_crs} "
                    f"{db.edge_collection(nav.edge_type)} OPTIONS {{ bfs: true, {unique} }} "
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
            in_c = next_crs()
            out = next_crs()
            out_crsr = next_crs()
            link = next_crs()
            unique = "uniqueEdges: 'path'" if with_edges else "uniqueVertices: 'global'"
            dir_bound = "OUTBOUND" if direction == "out" else "INBOUND"
            inout_result = f"MERGE({out_crsr}, {{_from:{link}._from, _to:{link}._to}})" if with_edges else out_crsr
            query_part += (
                f"LET {out} =( FOR {in_c} in {in_crsr} "
                f"FOR {out_crsr}, {link} IN {start}..{until} {dir_bound} {in_c} "
                f"{db.edge_collection(edge_type)} OPTIONS {{ bfs: true, {unique} }} "
                f"RETURN DISTINCT {inout_result}) "
            )
            return out

        def navigation(in_crsr: str, nav: Navigation) -> str:
            nonlocal query_part
            if nav.direction == "inout":
                # traverse to root
                to_in = inout(in_crsr, nav.start, nav.until, nav.edge_type, "in")
                # traverse to leaf (in case of 0: use 1 to not have the current element twice)
                to_out = inout(in_crsr, max(1, nav.start), nav.until, nav.edge_type, "out")
                nav_crsr = next_crs()
                query_part += f"LET {nav_crsr} = UNION({to_in}, {to_out})"
                return nav_crsr
            else:
                return inout(in_crsr, nav.start, nav.until, nav.edge_type, nav.direction)

        if isinstance(p.term, MergeTerm):
            filter_cursor = filter_statement(in_cursor, p.term.pre_filter)
            cursor, merge_part = merge(filter_cursor, p.term.merge)
            query_part += merge_part
            if p.term.post_filter:
                cursor = filter_statement(cursor, p.term.post_filter)
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
        for section in Section.all:
            ancestor_result = "{" + ",".join([f"{p[1]}: {p[0]}.{section}" for p in ancestors]) + "}"
            result_parts.append(f"{section}: MERGE(NOT_NULL(node.{section},{{}}), {ancestor_result})")

        m_parts.append("RETURN MERGE(node, {" + ", ".join(result_parts) + "})")
        return "merge_with_ancestor", part_str + f' LET merge_with_ancestor = ({" ".join(m_parts)})'

    def sort(cursor: str, so: List[Sort], sect_dot: str) -> str:
        sorts = ", ".join(f"{cursor}.{sect_dot}{s.name} {s.order}" for s in so)
        return f" SORT {sorts} "

    parts = []
    crsr = start_cursor
    for p in reversed(query.parts):
        part_tuple = part(p, crsr)
        parts.append(part_tuple)
        crsr = part_tuple[1]

    all_parts = " ".join(p[3] for p in parts)
    resulting_cursor, query_str = merge_ancestors(crsr, all_parts, merge_with) if merge_with else (crsr, all_parts)
    nxt = next_crs()
    if query.aggregate:  # return aggregate
        resulting_cursor, aggregation = aggregate(resulting_cursor, query.aggregate)
        query_str += aggregation
        # if the last part has a sort order, we use it here again
        if query.current_part.sort:
            sort_by = sort("res", query.current_part.sort, "")
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
