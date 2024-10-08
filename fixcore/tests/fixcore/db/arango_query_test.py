from datetime import timedelta, datetime
from functools import partial
from typing import Tuple, Any

import pytest

from fixcore.db import EstimatedSearchCost, EstimatedQueryCostRating
from fixcore.db.arango_query import (
    graph_query as graph_query_direct,
    query_cost,
    fulltext_term_combine,
    possible_values,
    load_time_series,
    history_query,
    TranslateRegexpToLike,
)
from fixcore.db.graphdb import GraphDB
from fixcore.db.model import QueryModel
from fixcore.model.model import Model
from fixcore.query.model import Query, Sort, P
from fixcore.query.query_parser import parse_query, predicate_term
from fixcore.types import Json


graph_query = partial(graph_query_direct, consistent=True)
view_query = partial(graph_query_direct, consistent=False)


def test_sort_order_for_synthetic_prop(foo_model: Model, graph_db: GraphDB) -> None:
    def check_sort_in_query(q: Query, expected_sort: str) -> None:
        query_str, _ = graph_query(graph_db, QueryModel(q, foo_model))
        assert f"SORT {expected_sort}" in query_str, f"Expected {expected_sort} in {query_str}"

    check_sort_in_query(Query.by("foo").add_sort(Sort("reported.age")), "m0.reported.ctime desc")
    check_sort_in_query(Query.by("foo").add_sort(Sort("some.age")), "m0.some.age asc")
    check_sort_in_query(Query.by("foo").add_sort(Sort("reported.ctime")), "m0.reported.ctime asc")
    check_sort_in_query(Query.by("foo").add_sort(Sort("metadata.expired")), "m0.metadata.expired asc")


@pytest.mark.asyncio
async def test_query_cost(foo_model: Model, graph_db: GraphDB) -> None:
    async def cost(query_str: str) -> EstimatedSearchCost:
        query = parse_query(query_str)
        return await query_cost(graph_db, QueryModel(query, foo_model), False)

    c1 = await cost("aggregate(sum(1) as count):is(base) sort count asc")
    assert c1.full_collection_scan is False
    assert c1.rating is EstimatedQueryCostRating.simple

    c2 = await cost("is(base) sort count asc")
    assert c2.full_collection_scan is False
    assert c2.rating is EstimatedQueryCostRating.simple

    c3 = await cost("all sort reported.name asc")
    assert c3.full_collection_scan is False
    assert c3.rating is EstimatedQueryCostRating.simple

    c4 = await cost("all {parents: <-[0:]-} sort reported.name asc")
    assert c4.full_collection_scan is False
    assert c4.rating is EstimatedQueryCostRating.bad


async def test_id_term(foo_model: Model, graph_db: GraphDB) -> None:
    q, _ = await graph_db.to_query(QueryModel(Query.by(P.with_id("1234")), foo_model))
    assert "m0._key == @b0" in q
    q, _ = await graph_db.to_query(QueryModel(Query.by(P.with_id(["1", "2", "3"])), foo_model))
    assert "m0._key in @b0" in q
    q, _ = history_query(graph_db, QueryModel(Query.by(P.with_id(["1", "2", "3"])), foo_model))
    assert "m0.id in @b0" in q


def test_fulltext_term() -> None:
    part = parse_query('(a>0 and ("foo" and (b>1 and c>2 and "d")))').parts[0]
    ft, remaining = fulltext_term_combine(part.term)
    assert str(remaining) == "((b > 1 and c > 2) and a > 0)"
    assert str(ft) == '("d" and "foo")'
    # there are 2 fulltext terms or combined with something else
    ft, remaining = fulltext_term_combine(parse_query('(a>0 and "b") or ("c" and "d")').parts[0].term)
    assert ft is None  # fulltext index can not be utilized
    ft, remaining = fulltext_term_combine(parse_query('a>0 {c: <--} "fulltext"').parts[0].term)
    assert ft is None  # fulltext index can not be utilized
    ft, remaining = fulltext_term_combine(parse_query('a>0 {c: <-- "fulltext" }').parts[0].term)
    assert ft is None  # fulltext index can not be utilized
    ft, remaining = fulltext_term_combine(parse_query('"a" and "b" or "c" and "d"').parts[0].term)
    assert str(ft) == '((("a" and "b") or "c") and "d")'


def test_fulltext_index_query(foo_model: Model, graph_db: GraphDB) -> None:
    def query_string(query: str) -> str:
        query_str, _ = graph_query(graph_db, QueryModel(parse_query(query), foo_model))
        return query_str

    single_ft_index = (
        "LET m0=(FOR ft in ns_view SEARCH ANALYZER(PHRASE(ft.flat, @b0), 'delimited') RETURN ft) "
        'FOR result in m0 RETURN UNSET(result, ["flat"])'
    )
    assert query_string('"a"') == single_ft_index
    assert query_string('"some other fulltext string"') == single_ft_index
    # and/or is combined correctly
    assert (
        "ANALYZER((((PHRASE(ft.flat, @b0)) and (PHRASE(ft.flat, @b1))) or "
        "(PHRASE(ft.flat, @b2))) and (PHRASE(ft.flat, @b3)), 'delimited')"
    ) in query_string('"a" and "b" or "c" and "d"')


def test_ancestors_kind_lookup(foo_model: Model, graph_db: GraphDB) -> None:
    # 1234 is coerced to a string
    _, bv = graph_query(graph_db, QueryModel(parse_query("ancestors.account.reported.name==1234"), foo_model))
    assert bv["b0"] == "1234"


def test_escape_property_path(foo_model: Model, graph_db: GraphDB) -> None:
    raw = "metadata.replace.with.filter.sort.bla==true"
    query = graph_query(graph_db, QueryModel(parse_query(raw), foo_model))[0]
    # aql keywords are escaped with backslashes
    assert "m0.metadata.`replace`.`with`.`filter`.`sort`.bla" in query


def test_with_query_with_limit(foo_model: Model, graph_db: GraphDB) -> None:
    query = "is(foo) with(empty, -->) limit 2"
    query_str, _ = graph_query(graph_db, QueryModel(parse_query(query), foo_model))
    # make sure, there is no limit in the filter statement
    assert "LET filter0 = (FOR m0 in `ns` FILTER @b0 IN m0.kinds  RETURN m0)" in query_str
    # the limit is not applied to the with statement, but on the final for loop
    assert "LIMIT 0, 2 RETURN" in query_str


def test_context(foo_model: Model, graph_db: GraphDB) -> None:
    query = 'is(foo) and nested[*].{name=true and inner[*].{name=true}} and parents[*].{some_int="23"}'
    aql, bind_vars = graph_query(graph_db, QueryModel(parse_query(query).on_section("reported"), foo_model))
    # query unfolds all nested loops
    assert aql == (
        "LET filter0 = (LET nested_distinct0 = (FOR m0 in `ns`  "
        "FOR pre0 IN APPEND(TO_ARRAY(m0.reported.nested), {_internal: true}) "
        "FOR pre1 IN APPEND(TO_ARRAY(pre0.inner), {_internal: true})  "
        "FOR pre2 IN APPEND(TO_ARRAY(m0.reported.parents), {_internal: true}) "
        "FILTER ((@b0 IN m0.kinds) and ((pre0.name == @b1) and (pre1.name == @b2))) and (pre2.some_int == @b3) AND "
        "((pre0._internal!=true AND pre1._internal!=true and pre2._internal!=true)) "
        "RETURN DISTINCT m0) "
        "FOR m1 in nested_distinct0  RETURN m1) "
        'FOR result in filter0 RETURN UNSET(result, ["flat"])'
    )
    # coercing works correctly for context terms
    assert bind_vars["b1"] == "true"  # true is coerced to a string
    assert bind_vars["b2"] == "true"  # inner true is coerced to a string
    assert bind_vars["b3"] == 23  # 23 is coerced to an int

    query = 'is(foo) and not nested[*].{name=true and not inner[*].{name=true}} and not parents[*].{some_int="23"}'
    aql, bind_vars = graph_query(graph_db, QueryModel(parse_query(query).on_section("reported"), foo_model))
    assert aql == (
        "LET filter0 = (LET nested_distinct0 = (FOR m0 in `ns`  "
        "FOR pre0 IN APPEND(TO_ARRAY(m0.reported.nested), {_internal: true}) "
        "FOR pre1 IN APPEND(TO_ARRAY(pre0.inner), {_internal: true})  "
        "FOR pre2 IN APPEND(TO_ARRAY(m0.reported.parents), {_internal: true}) "
        "FILTER ((@b0 IN m0.kinds) and (NOT ((pre0.name == @b1) and (NOT (pre1.name == @b2))))) and "
        "(NOT (pre2.some_int == @b3)) AND "
        "((pre0._internal!=true AND pre1._internal!=true and pre2._internal!=true)) "
        "RETURN DISTINCT m0) "
        "FOR m1 in nested_distinct0  RETURN m1) "
        'FOR result in filter0 RETURN UNSET(result, ["flat"])'
    )

    # fixed index works as well
    query = "is(foo) and inner[1].{name=true and inner[0].name==true}"
    aql, bind_vars = graph_query(graph_db, QueryModel(parse_query(query).on_section("reported"), foo_model))
    assert aql == (
        "LET filter0 = (FOR m0 in `ns` FILTER (@b0 IN m0.kinds) and "
        "((m0.reported.inner[1].name == @b1) and (m0.reported.inner[1].inner[0].name == @b2))  RETURN m0) "
        'FOR result in filter0 RETURN UNSET(result, ["flat"])'
    )


def test_usage(foo_model: Model, graph_db: GraphDB) -> None:
    q, _ = graph_query(graph_db, QueryModel(parse_query("with_usage(3w, cpu, mem) is(foo)"), foo_model))
    assert q == (
        "LET filter0 = (FOR m0 in `ns` FILTER @b0 IN m0.kinds  RETURN m0)\n"
        "let with_usage0 = (\n"
        "    for r in filter0\n"
        "        let resource=r\n"
        "        let resource_usage = first(\n"
        "            for m in ns_usage\n"
        "            filter m.at>=@b1 and m.at<=@b2 and m.id==r._key\n"
        "            collect aggregate cpu_min = MIN(m.v.cpu.min), cpu_avg = AVG(m.v.cpu.avg), cpu_max = MAX(m.v.cpu.max), mem_min = MIN(m.v.mem.min), mem_avg = AVG(m.v.mem.avg), mem_max = MAX(m.v.mem.max), count = sum(1)\n"  # noqa: E501
        "            return {usage:{cpu: {min: cpu_min, avg: cpu_avg, max: cpu_max},mem: {min: mem_min, avg: mem_avg, max: mem_max},entries:count,start:@b3,duration:@b4}}\n"  # noqa: E501
        "        )\n"
        "        return resource_usage.usage.entries ? merge(resource, resource_usage) : resource\n"
        ")\n"
        ' FOR result in with_usage0 RETURN UNSET(result, ["flat"])'
    )


def test_aggregation(foo_model: Model, graph_db: GraphDB) -> None:
    q, _ = graph_query(graph_db, QueryModel(parse_query("aggregate(name: max(num)): is(foo)"), foo_model))
    assert "collect var_0=agg0.name aggregate fn_0=max(agg0.num)" in q
    # aggregate vars get expanded
    q, _ = graph_query(graph_db, QueryModel(parse_query("aggregate(name, a[*].b[*].c: max(num)): is(foo)"), foo_model))
    assert (
        "for agg0 in filter0 FOR pre0 IN APPEND(TO_ARRAY(agg0.a), {_internal: true}) "
        "FOR pre1 IN APPEND(TO_ARRAY(pre0.b), {_internal: true}) "
        "FILTER pre0._internal!=true AND pre1._internal!=true  "
        "collect var_0=agg0.name, var_1=pre1.c "
        "aggregate fn_0=max(agg0.num) "
        'RETURN {"group":{"name": var_0, "c": var_1}, "max_of_num": fn_0}' in q
    )
    q, _ = graph_query(
        graph_db,
        QueryModel(parse_query("aggregate(name: max(num), min(a[*].x), sum(a[*].b[*].d)): is(foo)"), foo_model),
    )
    # no expansion on the main level, but expansion in subqueries (let expressions)
    assert (
        "for agg0 in filter0 "
        "LET agg_let0 = min( FOR inner0 IN TO_ARRAY(agg0.a) RETURN inner0.x) "
        "LET agg_let1 = sum( FOR inner1 IN TO_ARRAY(agg0.a) FOR inner2 IN TO_ARRAY(inner1.b) RETURN inner2.d) "
        "collect var_0=agg0.name "
        "aggregate fn_0=max(agg0.num), fn_1=min(agg_let0), fn_2=sum(agg_let1) "
        'RETURN {"group":{"name": var_0}, "max_of_num": fn_0, '
        '"min_of_a_x": fn_1, "sum_of_a_b_d": fn_2}' in q
    )
    q, _ = graph_query(
        graph_db,
        QueryModel(parse_query("aggregate(name, a[*].c: max(num), min(a[*].x), sum(a[*].b[*].d)): is(foo)"), foo_model),
    )
    assert (
        "for agg0 in filter0 FOR pre0 IN APPEND(TO_ARRAY(agg0.a), {_internal: true}) "
        "FILTER pre0._internal!=true "
        "LET agg_let0 = min( RETURN pre0.x) "
        "LET agg_let1 = sum( FOR inner0 IN TO_ARRAY(pre0.b) RETURN inner0.d) "
        "collect var_0=agg0.name, var_1=pre0.c "
        "aggregate fn_0=max(agg0.num), fn_1=min(pre0.x), fn_2=sum(agg_let1) "
        'RETURN {"group":{"name": var_0, "c": var_1}, "max_of_num": fn_0, '
        '"min_of_a_x": fn_1, "sum_of_a_b_d": fn_2}' in q
    )
    q, _ = graph_query(graph_db, QueryModel(parse_query("aggregate(name, a[*].b[*]: max(num)): is(foo)"), foo_model))
    assert (
        "for agg0 in filter0 "
        "FOR pre0 IN APPEND(TO_ARRAY(agg0.a), {_internal: true}) "
        "FOR pre1 IN APPEND(TO_ARRAY(pre0.b), {_internal: true}) "
        "FILTER pre0._internal!=true AND pre1._internal!=true  "
        "collect var_0=agg0.name, var_1=pre1 "
        'aggregate fn_0=max(agg0.num) RETURN {"group":{"name": var_0, "b[*]": var_1}, "max_of_num": fn_0}) '
        'FOR result in aggregated RETURN UNSET(result, ["flat"])'
    ) in q


def test_possible_values(foo_model: Model, graph_db: GraphDB) -> None:
    # attributes: simple path
    model = QueryModel(parse_query("is(foo)"), foo_model)
    pv, bv = possible_values(graph_db, model, "reported.tags", "attributes")
    assert pv == (
        "LET filter0 = (FOR m0 in `ns` FILTER @b0 IN m0.kinds  RETURN m0) "  # query
        "LET m2 = ( FOR m3 in filter0 FILTER IS_OBJECT(m3.reported.tags) "  # make sure that the property is an object
        "FOR m4 IN ATTRIBUTES(m3.reported.tags, true) RETURN m4) "  # iterate over all properties of the object path
        "LET m5 = (FOR m6 IN m2 FILTER m6!=null RETURN DISTINCT m6)"  # filter null, distinct
        "FOR m7 IN m5 SORT m7 ASC RETURN m7"
    )  # sort and return
    assert bv == {"b0": "foo"}
    # attributes: predicate
    tags_with_a = predicate_term.parse('reported.tags =~ "^a.*"')
    pv, bv = possible_values(graph_db, model, tags_with_a, "attributes")
    assert pv == (
        "LET filter0 = (FOR m0 in `ns` FILTER @b0 IN m0.kinds  RETURN m0) "
        "LET m2 = ( FOR m3 in filter0 FILTER IS_OBJECT(m3.reported.tags) "
        "FOR m4 IN ATTRIBUTES(m3.reported.tags, true) RETURN m4) "
        "LET m5 = (FOR m6 IN m2 FILTER m6!=null FILTER REGEX_TEST(m6, @b1, true) "  # filter by null and regex
        "RETURN DISTINCT m6)FOR m7 IN m5 SORT m7 ASC RETURN m7"
    )

    assert bv == {"b0": "foo", "b1": "^a.*"}
    # attributes: predicate over array value
    pred = predicate_term.parse("reported.pod_spec.containers[*].security_context.run_as_user not in [1000, 10001]")
    pv, bv = possible_values(graph_db, model, pred, "attributes")
    assert pv == (
        "LET filter0 = (FOR m0 in `ns` FILTER @b0 IN m0.kinds  RETURN m0) "
        "LET m2 = ( FOR m3 in filter0 FOR m4 IN TO_ARRAY(m3.reported.pod_spec.containers) "  # expand nested arrays
        "FILTER IS_OBJECT(m4.security_context.run_as_user) "
        "FOR m5 IN ATTRIBUTES(m4.security_context.run_as_user, true) RETURN m5) "
        "LET m6 = (FOR m7 IN m2 FILTER m7!=null FILTER m7 not in @b1 RETURN DISTINCT m7)"
        "FOR m8 IN m6 SORT m8 ASC RETURN m8"
    )
    assert bv == {"b0": "foo", "b1": [1000, 10001]}
    # attributes: array as last element
    pv, bv = possible_values(graph_db, model, "reported.pod_spec.containers[*]", "attributes")
    assert pv == (
        "LET filter0 = (FOR m0 in `ns` FILTER @b0 IN m0.kinds  RETURN m0) "
        "LET m2 = ( FOR m3 in filter0 FOR m4 IN TO_ARRAY(m3.reported.pod_spec.containers[*]) "
        "FILTER IS_OBJECT(m4) FOR m5 IN ATTRIBUTES(m4, true) RETURN m5) "
        "LET m6 = (FOR m7 IN m2 FILTER m7!=null RETURN DISTINCT m7)"
        "FOR m8 IN m6 SORT m8 ASC RETURN m8"
    )
    # values: simple path
    pv, bv = possible_values(graph_db, model, "reported.tags.test", "values")
    assert pv == (
        "LET filter0 = (FOR m0 in `ns` FILTER @b0 IN m0.kinds  RETURN m0) "  # query
        "LET m2 = ( FOR m3 in filter0 RETURN m3.reported.tags.test) "  # select the property value
        "LET m4 = (FOR m5 IN m2 FILTER m5!=null RETURN DISTINCT m5)"  # filter null,  distinct
        "FOR m6 IN m4 SORT m6 ASC RETURN m6"
    )  # sort and return
    assert bv == {"b0": "foo"}
    # values: predicate
    pv, bv = possible_values(graph_db, model, tags_with_a, "values")
    assert pv == (
        "LET filter0 = (FOR m0 in `ns` FILTER @b0 IN m0.kinds  RETURN m0) "
        "LET m2 = ( FOR m3 in filter0 RETURN m3.reported.tags) "
        "LET m4 = (FOR m5 IN m2 FILTER m5!=null FILTER REGEX_TEST(m5, @b1, true) RETURN DISTINCT m5)"  # filter by null and regex
        "FOR m6 IN m4 SORT m6 ASC RETURN m6"
    )
    assert bv == {"b0": "foo", "b1": "^a.*"}
    # values: predicate over array value
    pv, bv = possible_values(graph_db, model, pred, "attributes")
    assert pv == (
        "LET filter0 = (FOR m0 in `ns` FILTER @b0 IN m0.kinds  RETURN m0) "
        "LET m2 = ( FOR m3 in filter0 FOR m4 IN TO_ARRAY(m3.reported.pod_spec.containers) "  # expand nested arrays
        "FILTER IS_OBJECT(m4.security_context.run_as_user) "
        "FOR m5 IN ATTRIBUTES(m4.security_context.run_as_user, true) RETURN m5) "
        "LET m6 = (FOR m7 IN m2 FILTER m7!=null FILTER m7 not in @b1 RETURN DISTINCT m7)"
        "FOR m8 IN m6 SORT m8 ASC RETURN m8"
    )
    assert bv == {"b0": "foo", "b1": [1000, 10001]}
    # limit the result
    pv, bv = possible_values(graph_db, model, "reported.tags", "values", limit=10)
    assert pv.endswith("SORT m6 ASC LIMIT 0, 10 RETURN m6")
    # skip and limit the result
    pv, bv = possible_values(graph_db, model, "reported.tags", "values", limit=10, skip=20)
    assert pv.endswith("SORT m6 ASC LIMIT 20, 10 RETURN m6")


def test_load_time_series() -> None:
    now = datetime.fromtimestamp(1700000000)
    one_hour = timedelta(hours=1)
    # group_by=[] --> no group by any value
    q, bv = load_time_series("ts", "foo", now - (24 * one_hour), now, one_hour, group_by=[])
    assert (
        q == "LET m1 = ( FOR d in `ts` FILTER d.ts==@b0 AND d.at>=@b1 AND d.at<@b2 "
        "LET m0 = (FLOOR((d.at + @b4) / @b3) * @b3) - @b4 "
        "COLLECT group_slot=m0, complete_group=d.group "
        "AGGREGATE slot_avg = AVG(d.v) "
        "RETURN {at: group_slot, group: complete_group, v: slot_avg} )\n "
        "FOR d in m1 COLLECT group_slot=d.at AGGREGATE agg_val=avg(d.v) "
        "SORT group_slot RETURN {at: group_slot, v: agg_val}"
    )
    assert bv == {"b0": "foo", "b1": 1699913600, "b2": 1700000000, "b3": 3600, "b4": 2800}
    # no group by defined --> group by all values
    q, bv = load_time_series("ts", "foo", now - (24 * one_hour), now, one_hour)
    assert (
        q == "FOR d in `ts` FILTER d.ts==@b0 AND d.at>=@b1 AND d.at<@b2 "
        "LET m0 = (FLOOR((d.at + @b4) / @b3) * @b3) - @b4 "
        "COLLECT group_slot=m0, complete_group=d.group "
        "AGGREGATE slot_avg = AVG(d.v) "
        "RETURN {at: group_slot, group: complete_group, v: slot_avg}"
    )
    assert bv == {"b0": "foo", "b1": 1699913600, "b2": 1700000000, "b3": 3600, "b4": 2800}
    # group by specific group variables
    q, bv = load_time_series("ts", "foo", now - (24 * one_hour), now, one_hour, group_by=["a", "b"])
    assert (
        q == "LET m1 = ( FOR d in `ts` FILTER d.ts==@b0 AND d.at>=@b1 AND d.at<@b2 "
        "LET m0 = (FLOOR((d.at + @b4) / @b3) * @b3) - @b4 "
        "COLLECT group_slot=m0, complete_group=d.group "
        "AGGREGATE slot_avg = AVG(d.v) "
        "RETURN {at: group_slot, group: complete_group, v: slot_avg} )\n "
        "FOR d in m1 "
        "COLLECT group_slot=d.at, group_a=d.group.a, group_b=d.group.b "
        "AGGREGATE agg_val=avg(d.v) "
        "SORT group_slot RETURN {at: group_slot,group: { a: group_a, b: group_b }, v: agg_val}"
    )
    assert bv == {"b0": "foo", "b1": 1699913600, "b2": 1700000000, "b3": 3600, "b4": 2800}
    # group by specific group variables and filter by group variables
    q, bv = load_time_series(
        "ts", "foo", now - (24 * one_hour), now, one_hour, group_by=["a", "b"], group_filter=[P("a").eq("a")]
    )
    assert (
        q == "LET m1 = ( FOR d in `ts` FILTER d.ts==@b0 AND d.at>=@b1 AND d.at<@b2 FILTER d.group.a == @b3 "
        "LET m0 = (FLOOR((d.at + @b5) / @b4) * @b4) - @b5 "
        "COLLECT group_slot=m0, complete_group=d.group "
        "AGGREGATE slot_avg = AVG(d.v) RETURN {at: group_slot, group: complete_group, v: slot_avg} )\n "
        "FOR d in m1 "
        "COLLECT group_slot=d.at, group_a=d.group.a, group_b=d.group.b "
        "AGGREGATE agg_val=avg(d.v) "
        "SORT group_slot RETURN {at: group_slot,group: { a: group_a, b: group_b }, v: agg_val}"
    )
    assert bv == {"b0": "foo", "b1": 1699913600, "b2": 1700000000, "b3": "a", "b4": 3600, "b5": 2800}
    # use avg-factor
    q, _ = load_time_series("ts", "foo", now - (24 * one_hour), now, one_hour, avg_factor=1000)
    assert "slot_avg = AVG(d.v / @b" in q  # factor divides average
    assert "v: slot_avg * @b" in q  # factor multiplies result


def test_view(foo_model: Model, graph_db: GraphDB) -> None:
    def assert_view(query: str, expected: str, **kwargs: Any) -> Tuple[str, Json]:
        q, bv = view_query(graph_db, QueryModel(parse_query(query), foo_model))
        assert expected in q
        for k, v in kwargs.items():
            assert bv[k] == v
        return q, bv

    # all reads plain from the view: no search and no filter
    assert_view("all", 'FOR result in `ns_view` RETURN UNSET(result, ["flat"])')

    # read only from view
    assert_view("is(foo)", "SEARCH v0.kinds == @b0 RETURN v0)  FOR result in view0")

    # read only from view via phrase
    assert_view('"test"',
                'LET view0 = (FOR v0 in `ns_view` SEARCH ANALYZER(PHRASE(v0.flat, @b0), "delimited") SORT BM25(v0) DESC RETURN v0)  FOR result in view0 RETURN UNSET(result, ["flat"])')  # fmt: skip

    # read only from view via property
    assert_view("name==123", "SEARCH v0.name == @b0 RETURN v0)  FOR result in view0")

    # Handle empty string
    assert_view("name==null", "SEARCH NOT EXISTS(v0.name) RETURN v0)  FOR result in view0 RETURN")

    # Handle empty string
    assert_view("name!=null", "SEARCH EXISTS(v0.name) RETURN v0)  FOR result in view0 RETURN")

    # g is of type array. the view cannot distinguish between null and empty array, so we need to filter afterward
    assert_view("g==null", "SEARCH NOT EXISTS(v0.g) RETURN v0) LET filter0 = (FOR m0 in view0 FILTER m0.g == @b0 ")  # fmt: skip

    # g is of type array. the view cannot distinguish between null and empty array, so we need to filter afterward
    # Optimisation note: in this case we could remove the filter when in [null, []] is used
    assert_view("g in [null, []]", "SEARCH NOT EXISTS(v0.g) RETURN v0) LET filter0 = (FOR m0 in view0 FILTER m0.g in @b0  RETURN m0)")  # fmt: skip

    # g is of type array. the view cannot distinguish between null and empty array, so we need to filter afterward
    assert_view("g not in [null, []]", "SEARCH EXISTS(v0.g) RETURN v0) LET filter0 = (FOR m0 in view0 FILTER (m0.g!=null and m0.g not in @b0)")  # fmt: skip

    # g is of type array. the view cannot distinguish between null and empty array, so we need to filter afterward
    assert_view("g!=null", "SEARCH EXISTS(v0.g) RETURN v0) LET filter0 = (FOR m0 in view0 FILTER m0.g != @b0")  # fmt: skip

    # < operator needs an exists check
    assert_view("name<test", "SEARCH (EXISTS(v0.name) and v0.name < @b0) RETURN v0")

    # > operator does not need an existence check
    assert_view("name>test", "SEARCH v0.name > @b0 RETURN v0")
    _, bv = assert_view('name in [12, true, false, "test"]', "SEARCH v0.name in @b0 RETURN v0")
    assert bv["b0"] == ["12", "true", "false", "test"]  # 12, true, false is coerced to string

    # the view is not able to compare arrays -> use view with IN operator and filter afterwards
    assert_view("g==[1,2,3]", "SEARCH v0.g IN @b0 RETURN v0) LET filter0 = (FOR m0 in view0 FILTER m0.g == @b1  RETURN m0)")  # fmt: skip
    # asking for a specific element in an array can leverage the view
    assert_view("g[*]==1", "SEARCH v0.g == @b0 RETURN v0")
    assert_view("g[*] in [1,2,3]", "SEARCH v0.g in @b0 RETURN v0)  FOR result in view0")
    # use like instead of regex
    if TranslateRegexpToLike:
        assert_view('name=~"^123"', "SEARCH v0.name LIKE @b0", b0="123%")
        assert_view('name=~"^.*123$"', "SEARCH v0.name LIKE @b0", b0="%123")
        assert_view('name=~".*123$"', "SEARCH v0.name LIKE @b0", b0="%123")
        assert_view('name=~"^123$"', "SEARCH v0.name LIKE @b0", b0="123")
        assert_view('name=~"^%1%2%.*3%$"', "SEARCH v0.name LIKE @b0", b0="\\%1\\%2\\%%3\\%")
        assert_view('name=~"^...$"', "SEARCH v0.name LIKE @b0", b0="___")

    # cannot use like since regex cannot be expressed as glob. needs filter
    assert_view('name=~"123[0-9]+"',
                'LET filter0 = (FOR m0 in `ns_view` FILTER (m0.name!=null and REGEX_TEST(m0.name, @b0, true))  RETURN m0) FOR result in filter0 RETURN UNSET(result, ["flat"])')  # fmt: skip
    # use search to select the documents, but needs filter for array handling
    assert_view("name[*].foo[*].bla=12",
                'LET view0 = (FOR v0 in `ns_view` SEARCH v0.name.foo.bla == @b0 RETURN v0)  FOR result in view0 RETURN UNSET(result, ["flat"])')  # fmt: skip
    assert_view('is("aws_ec2_instance") and "deleteme" and reported.instance_placement.tenancy == "default"',
                'LET view0 = (FOR v0 in `ns_view` SEARCH ((v0.kinds == @b0 and ANALYZER(PHRASE(v0.flat, @b1), "delimited")) and v0.reported.instance_placement.tenancy == @b2) SORT BM25(v0) DESC RETURN v0)  FOR result in view0 RETURN UNSET(result, ["flat"])')  # fmt: skip
