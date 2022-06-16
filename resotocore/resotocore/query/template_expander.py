import functools
import json
from abc import abstractmethod
from typing import Any, ByteString, Union, Iterable, Tuple, List, Optional, cast

from parsy import string, Parser, regex, any_char
from ustache import default_getter, default_virtuals, render, PropertyGetter, TagsTuple, default_tags

from resotolib.parse_util import (
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

from resotocore.db.templatedb import TemplateEntityDb
from resotocore.error import NoSuchTemplateError
from resotocore.query import query_parser, QueryParser
from resotocore.query.model import Query, Expandable, Template
from resotocore.types import Json
from resotocore.util import identity, duration, utc, utc_str


class TemplateExpander(QueryParser):
    """
    TemplateExpander is able to maintain (crud) a set of templates
    as well as expanding strings which might contain expandable sections that refer to templates
    in the templates library.
    """

    @abstractmethod
    async def expand(self, maybe_expandable: str) -> Tuple[str, List[Expandable]]:
        """
        Expand the given string, which might contain expandable sections.
        All expandable sections get expanded and replaced in the string.
        If there are no expandable sections, the string is returned as is.

        If there are expandable sections, where the related template does not exist,
        an exception is thrown.

        :param maybe_expandable: a string which might contain expandable sections.
        :return: A string with all expandable sections expanded.
        :raises: NoSuchTemplateError if the related template of an expandable section does not exist.
        """

    @abstractmethod
    def render(self, template: str, properties: Json) -> str:
        """
        Render a given template with given properties.
        :param template: the template to render.
        :param properties: the properties used to define the template properties.
        :return: the fully rendered string without any template parameters.
        """

    @abstractmethod
    async def put_template(self, template: Template) -> None:
        """
        Put a named template to the template library.
        :param template: the template to put.
        :return: None.
        """

    @abstractmethod
    async def delete_template(self, name: str) -> None:
        """
        Delete a with given name from the template library.
        :param name: the name of the template to delete.
        :return: None.
        """

    @abstractmethod
    async def get_template(self, name: str) -> Optional[Template]:
        """
        Return the template with the given name.
        :param name: the name of the template.
        :return: the template with the given name if the template exists otherwise None.
        """

    @abstractmethod
    async def list_templates(self) -> List[Template]:
        """
        List all available templates in the system.
        :return: all templates in the system.
        """


class TemplateExpanderBase(TemplateExpander):
    """
    Base expander functionality which implements the expanding functionality
    and leaves the storage functionality to the subsequent classes.
    """

    async def parse_query(
        self, to_parse: str, on_section: Optional[str], *, omit_section_expansion: bool = False, **env: str
    ) -> Query:
        expanded, _ = await self.expand(to_parse)
        result = query_parser.parse_query(expanded, **env)
        return result if omit_section_expansion else result.on_section(on_section)

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
        tpl = await self.get_template(expand.template)
        if tpl:
            return self.render(tpl.template, expand.props)
        else:
            raise NoSuchTemplateError(expand.template)

    def render(self, template: str, properties: Json) -> str:
        dp = self.default_props()
        return render_template(template, properties, [dp] if dp else ())

    @abstractmethod
    def default_props(self) -> Optional[Json]:
        pass


class DBTemplateExpander(TemplateExpanderBase):
    """
    Template expander, which maintains the templates in the database.
    """

    def __init__(self, db: TemplateEntityDb) -> None:
        self.db = db

    def default_props(self) -> Optional[Json]:
        return None

    async def put_template(self, template: Template) -> None:
        await self.db.update(template)

    async def delete_template(self, name: str) -> None:
        await self.db.delete(name)

    async def get_template(self, name: str) -> Optional[Template]:
        return await self.db.get(name)

    async def list_templates(self) -> List[Template]:
        return [t async for t in self.db.all()]


class VirtualFunctions:
    """
    Virtual functions that can be used on template parameters.
    """

    @staticmethod
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

    @staticmethod
    def parens(result: Any) -> str:
        return f'"{result}"'

    @staticmethod
    def from_now(result: str) -> str:
        return utc_str(utc() + duration(result))


# noinspection PyTypeChecker
getter: PropertyGetter = functools.partial(
    default_getter,
    virtuals={
        **default_virtuals,
        "with_index": VirtualFunctions.with_index,
        "parens": VirtualFunctions.parens,
        "from_now": VirtualFunctions.from_now,
    },
)


def render_template(template: str, props: Json, more_props: Iterable[Json] = (), tags: TagsTuple = default_tags) -> str:
    """
    Render given provided template with given property values.
    :param template: the template string.
    :param props: the properties to populate.
    :param more_props: additional property maps
    :param tags: the tags to identify the template
    :return: the rendered template string.
    """

    def json_stringify(data: Any, text: bool = False) -> Union[bytes, ByteString]:
        if isinstance(data, ByteString) and not text:
            return data
        elif isinstance(data, str):
            return data.encode()
        elif isinstance(data, (list, dict)):
            return json.dumps(data).encode()
        else:
            return f"{data}".encode()

    rendered = render(
        template, props, scopes=more_props, escape=identity, stringify=json_stringify, getter=getter, tags=tags
    )
    return cast(str, rendered)


@make_parser
def tpl_key_value_parser() -> Parser:
    key = yield literal_p
    yield equals_p
    value = yield json_value_p
    return key, value


# double-quoted string is maintained with quotes: "foo" -> "foo"
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
