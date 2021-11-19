from core.query.templater import render_template


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
