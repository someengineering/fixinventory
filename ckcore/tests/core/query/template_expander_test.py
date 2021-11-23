import pytest
from pytest import fixture

from core.error import NoSuchTemplateError
from core.query import Template
from core.query.template_expander import InMemoryTemplateExpander, render_template


@fixture
def expander() -> InMemoryTemplateExpander:
    return InMemoryTemplateExpander()


@pytest.mark.asyncio
async def test_simple_expand(expander: InMemoryTemplateExpander) -> None:
    templates = [
        Template("foo", "Hey {{name}} - this is {{noun}}"),
        Template("bla", "One, two, {{t3}}"),
        Template("bar", "Heureka"),
    ]
    for t in templates:
        expander.templates[t.name] = t
    result, expands = await expander.expand(
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
async def test_query_expand(expander: InMemoryTemplateExpander) -> None:
    expander.templates["albs"] = Template("albs", "is(aws_alb) and age>{{older_than}}")
    result, expands = await expander.expand("query expand(albs, older_than=7d)")
    assert result == "query is(aws_alb) and age>7d"


@pytest.mark.asyncio
async def test_non_existent_template_expand(expander: InMemoryTemplateExpander) -> None:
    with pytest.raises(NoSuchTemplateError, match="does_not_exist"):
        await expander.expand("query expand(does_not_exist)")


def test_render_simple() -> None:
    attrs = {"foo": "123", "list": ["a", "b", "c"]}
    res = render_template("query foo={{foo}} and test in {{list}}", attrs)
    assert res == 'query foo=123 and test in ["a", "b", "c"]'
    # fallback properties are used if the original list does not contain the value
    res2 = render_template("query foo={{foo}} and test in {{list}}", {}, [attrs])
    assert res2 == 'query foo=123 and test in ["a", "b", "c"]'


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
