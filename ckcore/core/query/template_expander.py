import functools
import json
from abc import abstractmethod
from typing import Any, Generator, ByteString, Union, Iterable
from typing import Dict, Tuple
from typing import List
from typing import Optional

from parsy import string, Parser, regex, any_char
from ustache import default_getter, default_virtuals, render

from core.error import NoSuchTemplateError
from core.parse_util import (
    double_quote_dp,
    single_quote_dp,
    double_quoted_string_part_or_esc_dp,
    single_quoted_string_part_or_esc_dp,
    make_parser,
    lparen_p,
    literal_p,
    comma_p,
    colon_p,
    json_object_p,
    rparen_dp,
    equals_p,
    json_value_p,
)
from core.query import Expandable, TemplateExpander, Template, query_parser
from core.query.model import Query
from core.types import Json
from core.util import identity


class TemplateExpanderBase(TemplateExpander):
    """
    Base expander functionality which implements the expanding functionality
    and leaves the storage functionality to the subsequent classes.
    """

    async def parse_query(self, to_parse: str) -> Query:
        expanded, _ = await self.expand(to_parse)
        return query_parser.parse_query(expanded)

    async def expand(self, maybe_expandable: str) -> Tuple[str, List[Expandable]]:
        parts = string_with_expands.parse(maybe_expandable)
        expands = [exp for exp in parts if isinstance(exp, Expandable)]
        if expands:
            result = ""
            for part in parts:
                result += await self.expand_part(part) if isinstance(part, Expandable) else part
            return result, expands
        else:
            # nothing to expand
            return maybe_expandable, expands

    async def expand_part(self, expand: Expandable) -> str:
        tpl = await self.template(expand.template)
        if tpl:
            return self.render(tpl, expand.props)
        else:
            raise NoSuchTemplateError(expand.template)

    def render(self, template: str, properties: Json) -> str:
        dp = self.default_props()
        return render_template(template, properties, [dp] if dp else ())

    @abstractmethod
    def default_props(self) -> Optional[Json]:
        pass

    @abstractmethod
    async def template(self, name: str) -> Optional[str]:
        pass


class InMemoryTemplateExpander(TemplateExpanderBase):
    def __init__(self) -> None:
        self.templates: Dict[str, Template] = {}
        self.props: Json = {}

    async def template(self, name: str) -> Optional[str]:
        return self.templates[name].template if name in self.templates else None

    async def add_template(self, template: Template) -> None:
        if template.name in self.templates:
            raise AttributeError("Template with this name already exists!")
        self.templates[template.name] = template

    async def delete_template(self, name: str) -> None:
        self.templates.pop(name, None)

    async def get_template(self, name: str) -> Optional[Template]:
        return self.templates.get(name)

    async def list_templates(self) -> List[Template]:
        return list(self.templates.values())

    def default_props(self) -> Optional[Json]:
        return self.props


def render_template(template: str, props: Json, more_props: Iterable[Json] = ()) -> str:
    """
    Render given provided template with given property values.
    :param template: the template string.
    :param props: the properties to populate.
    :param more_props: additional property maps
    :return: the rendered template string.
    """

    def with_index(result: Any) -> Any:
        def item(lst: List[Any], idx: int, i: Any) -> Any:
            itm = i
            if not isinstance(i, dict):
                itm = {"value": i}
            itm["index"] = idx
            if idx == 0:
                itm["first"] = True
            if idx == len(lst) - 1:
                itm["last"] = True
            return itm

        if isinstance(result, list):
            result = [item(result, idx, a) for idx, a in enumerate(result)]
        return result

    def json_stringify(data: Any, text: bool = False) -> Generator[Union[bytes, ByteString], None, None]:
        if isinstance(data, ByteString) and not text:
            yield data
        elif isinstance(data, str):
            yield data.encode()
        elif isinstance(data, (list, dict)):
            yield json.dumps(data).encode()
        else:
            yield f"{data}".encode()

    getter = functools.partial(
        default_getter,
        virtuals={
            **default_virtuals,
            "with_index": with_index,
            "parens": lambda s: f'"{s}"',
        },
    )
    # noinspection PyTypeChecker
    return render(  # type: ignore
        template,
        props,
        scopes=more_props,
        escape=identity,
        stringify=json_stringify,
        getter=getter,
    )


@make_parser
def tpl_key_value_parser() -> Parser:
    key = yield literal_p
    yield equals_p
    value = yield json_value_p
    return key, value


# double quoted string is maintained with quotes: "foo" -> "foo"
double_quoted_string = double_quote_dp + double_quoted_string_part_or_esc_dp + double_quote_dp
# single quoted string is parsed without surrounding quotes: 'foo' -> 'foo'
single_quoted_string = single_quote_dp + single_quoted_string_part_or_esc_dp + single_quote_dp
expand_fn = string("expand")
not_expand_or_paren = regex("(?:(?!(?:(?:expand\\()|[\"'])).)+")
tpl_props_p = (json_object_p | tpl_key_value_parser.sep_by(comma_p, min=1).map(dict)).optional()


@make_parser
def expand_fn_parser() -> Parser:
    yield expand_fn
    yield lparen_p
    template_name = yield literal_p
    yield (comma_p | colon_p).optional()
    props = yield tpl_props_p
    yield rparen_dp
    return Expandable(template_name, props if props else {})


# a command are tokens until EOF or pipe
string_with_expands = (
    double_quoted_string | single_quoted_string | expand_fn_parser | not_expand_or_paren | any_char
).at_least(1)
