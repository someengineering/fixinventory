import pytest
from pytest import fixture

from core.query.template_expander import InMemoryTemplateExpander, render_template


@fixture
def expander() -> InMemoryTemplateExpander:
    return InMemoryTemplateExpander()


@pytest.mark.asyncio
async def test_simple_expand(expander) -> None:
    expander.templates["foo"] = "Hey {{name}} - this is {{noun}}"
    expander.templates["bla"] = "One, two, {{t3}}"
    expander.templates["bar"] = "Heureka"
    result, expands = await expander.render(
        "Test: expand(foo, name=bart, noun=crazy). expand(bla, t3=jiffy). expand(bar)"
    )
    assert result == "Test: Hey bart - this is crazy. One, two, jiffy. Heureka"
    assert len(expands) == 3
    assert expands[0].template == "foo"
    assert expands[0].props == dict(name="bart", noun="crazy")
    assert expands[1].template == "bla"
    assert expands[1].props == dict(t3="jiffy")
    assert expands[2].template == "bar"
    assert expands[2].props == {}


@pytest.mark.asyncio
async def test_query_expand(expander) -> None:
    expander.templates["unused_load_balancer"] = (
        "is(aws_alb) and age>{{age}} and backends==[] "
        'with(empty, <-- is(aws_alb_target_group) and target_type=="instance" and age>{{age}} '
        'with(empty, <-- is(aws_ec2_instance) and instance_status!="terminated"))'
        " <-[0:1]- is(aws_alb_target_group) or is(aws_alb)"
    )
    result, expands = await expander.render("query expand(unused_load_balancer, age=7d)")
    print(result)


def test_render_simple() -> None:
    attrs = {"foo": "123", "list": ["a", "b", "c"]}
    res = render_template("query foo={{foo}} and test in {{list}}", attrs)
    assert res == 'query foo=123 and test in ["a", "b", "c"]'


def test_render_list() -> None:
    attrs = {"is": ["alb", "elb"]}
    res = render_template("query {{#is.with_index}}{{^first}} or {{/first}}is({{value}}){{/is.with_index}}", attrs)
    assert res == "query is(alb) or is(elb)"


def test_render_filter() -> None:
    attrs = {"foo": "123", "filter": 32}
    template = "query foo={{foo.parens}}{{#filter}} and some.other.prop == {{filter}}{{/filter}}"
    res = render_template(template, attrs)
    assert res == 'query foo="123" and some.other.prop == 32'
    attrs2 = {"foo": "123"}
    res = render_template(template, attrs2)
    assert res == 'query foo="123"'
