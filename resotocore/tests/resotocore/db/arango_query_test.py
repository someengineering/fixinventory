import pytest

from resotocore.db import EstimatedSearchCost, EstimatedQueryCostRating
from resotocore.db.arango_query import to_query, query_cost, fulltext_term_combine
from resotocore.db.graphdb import GraphDB
from resotocore.db.model import QueryModel
from resotocore.model.model import Model
from resotocore.query.model import Query, Sort
from resotocore.query.query_parser import parse_query


def test_sort_order_for_synthetic_prop(foo_model: Model, graph_db: GraphDB) -> None:
    def check_sort_in_query(q: Query, expected_sort: str) -> None:
        query_str, _ = to_query(graph_db, QueryModel(q, foo_model))
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
    assert c3.full_collection_scan is True
    assert c3.rating is EstimatedQueryCostRating.complex

    c4 = await cost("all {parents: <-[0:]-} sort reported.name asc")
    assert c4.full_collection_scan is True
    assert c4.rating is EstimatedQueryCostRating.bad


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
        query_str, _ = to_query(graph_db, QueryModel(parse_query(query), foo_model))
        return query_str

    single_ft_index = (
        "LET m0=(FOR ft in search_ns SEARCH ANALYZER(PHRASE(ft.flat, @b0), 'delimited') "
        "SORT BM25(ft) DESC RETURN ft) "
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
    query = "ancestors.account.reported.name==1234"
    assert to_query(graph_db, QueryModel(parse_query(query), foo_model))[1] == {"b0": "1234"}


def test_escape_property_path(foo_model: Model, graph_db: GraphDB) -> None:
    raw = "metadata.replace.with.filter.sort.bla==true"
    query = to_query(graph_db, QueryModel(parse_query(raw), foo_model))[0]
    # aql keywords are escaped with backslashes
    assert "m0.metadata.`replace`.`with`.`filter`.`sort`.bla" in query


def test_with_query_with_limit(foo_model: Model, graph_db: GraphDB) -> None:
    query = "is(foo) with(empty, -->) limit 2"
    query_str, _ = to_query(graph_db, QueryModel(parse_query(query), foo_model))
    # make sure, there is no limit in the filter statement
    assert "LET filter0 = (FOR m0 in `ns` FILTER @b0 IN m0.kinds  RETURN m0)" in query_str
    # make sure the limit is applied to the with statement
    assert "FILTER counter1==1  LIMIT 0, 2 RETURN l0_l0_res" in query_str


def test_context(foo_model: Model, graph_db: GraphDB) -> None:
    query = 'is(foo) and nested[*].{name=true and inner[*].{name=true}} and parents[*].{some_int="23"}'
    aql, bind_vars = to_query(graph_db, QueryModel(parse_query(query).on_section("reported"), foo_model))
    # query unfolds all nested loops
    assert aql == (
        "LET filter0 = (LET nested_distinct0 = (FOR m0 in `ns`  FOR pre0 IN TO_ARRAY(m0.reported.nested) "
        "FOR pre1 IN TO_ARRAY(pre0.inner)  "
        "FOR pre2 IN TO_ARRAY(m0.reported.parents) "
        "FILTER ((@b0 IN m0.kinds) and ((pre0.name == @b1) and (pre1.name == @b2))) and (pre2.some_int == @b3) "
        "RETURN DISTINCT m0) FOR m1 in nested_distinct0  "
        'RETURN m1) FOR result in filter0 RETURN UNSET(result, ["flat"])'
    )
    # coercing works correctly for context terms
    assert bind_vars["b1"] == "true"  # true is coerced to a string
    assert bind_vars["b2"] == "true"  # inner true is coerced to a string
    assert bind_vars["b3"] == 23  # 23 is coerced to an int

    # fixed index works as well
    query = "is(foo) and inner[1].{name=true and inner[0].name==true}"
    aql, bind_vars = to_query(graph_db, QueryModel(parse_query(query).on_section("reported"), foo_model))
    assert aql == (
        "LET filter0 = (FOR m0 in `ns` FILTER (@b0 IN m0.kinds) and "
        "((m0.reported.inner[1].name == @b1) and (m0.reported.inner[1].inner[0].name == @b2))  RETURN m0) "
        'FOR result in filter0 RETURN UNSET(result, ["flat"])'
    )


def test_usage(foo_model: Model, graph_db: GraphDB) -> None:
    q, b = to_query(graph_db, QueryModel(parse_query("with_usage(3w, cpu, mem) is(foo)"), foo_model))
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
