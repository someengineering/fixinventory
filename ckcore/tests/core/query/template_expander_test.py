from typing import Dict, Optional, List

import pytest
from pytest import fixture

from core.error import NoSuchTemplateError
from core.query.model import Template
from core.query.template_expander import render_template, TemplateExpanderBase, TemplateExpander
from core.types import Json


class InMemoryTemplateExpander(TemplateExpanderBase):
    def __init__(self) -> None:
        self.templates: Dict[str, Template] = {}
        self.props: Json = {}

    async def put_template(self, template: Template) -> None:
        self.templates[template.name] = template

    async def delete_template(self, name: str) -> None:
        self.templates.pop(name, None)

    async def get_template(self, name: str) -> Optional[Template]:
        return self.templates.get(name)

    async def list_templates(self) -> List[Template]:
        return list(self.templates.values())

    def default_props(self) -> Optional[Json]:
        return self.props


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
async def test_expand(expander: TemplateExpander) -> None:
    await expander.put_template(Template("albs", "is(aws_alb) and age>{{older_than}}"))
    result, expands = await expander.expand("query expand(albs, older_than=7d)")
    assert result == "query is(aws_alb) and age>7d"
    with pytest.raises(NoSuchTemplateError, match="does_not_exist"):
        await expander.expand("query expand(does_not_exist)")


@pytest.mark.asyncio
async def test_add_update_delete_get_list(expander: TemplateExpander) -> None:
    await expander.put_template(Template("albs", "is(aws_alb) and age>{{older_than}}"))
    result = await expander.get_template("albs")
    assert result and result.name == "albs" and result.template == "is(aws_alb) and age>{{older_than}}"
    assert len(await expander.list_templates()) == 1
    await expander.put_template(Template("albs", "is(aws_alb) and age>{{old}} limit 3"))
    assert (await expander.get_template("albs")).template == "is(aws_alb) and age>{{old}} limit 3"  # type: ignore
    await expander.delete_template("albs")
    assert len(await expander.list_templates()) == 0


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
