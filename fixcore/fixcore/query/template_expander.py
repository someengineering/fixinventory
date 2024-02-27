import functools
import json
import re
from abc import abstractmethod
from typing import Any, Union, Iterable, Tuple, List, Optional, cast, Dict

from parsy import string, Parser, regex, any_char
from ustache import default_getter, default_virtuals, render, PropertyGetter, TagsTuple, default_tags

from fixcore.error import NoSuchTemplateError
from fixcore.query import query_parser, QueryParser
from fixcore.query.model import Query, Expandable, Template, PathRoot
from fixcore.types import Json
from fixcore.util import identity, duration, utc, utc_str
from fixlib.parse_util import (
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


class TemplateExpander(QueryParser):
    """
    TemplateExpander is able to maintain (crud) a set of templates
    as well as expanding strings which might contain expandable sections that refer to templates
    in the template library.
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


# Replace abbreviated predicate names with actual names
PredicateNameAdditions = {
    # shortcut for selecting any attribute on cloud/account/region/zone: cloud.id=123
    "(cloud[.]).*": "/ancestors.cloud.reported.",
    "(account[.]).*": "/ancestors.account.reported.",
    "(region[.]).*": "/ancestors.region.reported.",
    "(zone[.]).*": "/ancestors.zone.reported.",
    "(usage[.]).*": "/usage.",
    # shortcut for selecting by name on cloud/account/region/zone: cloud=aws
    "(cloud)": "/ancestors.cloud.reported.name",
    "(account)": "/ancestors.account.reported.name",
    "(region)": "/ancestors.region.reported.name",
    "(zone)": "/ancestors.zone.reported.name",
}


class TemplateExpanderBase(TemplateExpander):
    """
    Base expander functionality which implements the expanding functionality
    and leaves the storage functionality to the subsequent classes.
    """

    @staticmethod
    def change_well_known_names(name: str) -> str:
        for pattern, addition in PredicateNameAdditions.items():
            if match := re.fullmatch(pattern, name):
                res = addition + name[len(match.group(1)) :]
                return res
        return name

    async def parse_query(
        self,
        to_parse: str,
        on_section: Optional[str],
        *,
        omit_section_expansion: bool = False,
        env: Optional[Dict[str, str]] = None,
    ) -> Query:
        # if the query starts with the term "search " then we parse it as command line
        if to_parse.strip().startswith("search "):
            in_section = PathRoot if omit_section_expansion else on_section or PathRoot
            to_parse = await self.parse_query_from_command_line(to_parse, in_section, env=env)
            omit_section_expansion = True  # already done
        rendered = self.render(to_parse, env) if env else to_parse
        expanded, _ = await self.expand(rendered)
        result = query_parser.parse_query(expanded, env)
        result = result.change_variable(self.change_well_known_names)
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

    @abstractmethod
    async def parse_query_from_command_line(
        self, to_parse: str, on_section: str, env: Optional[Dict[str, str]] = None
    ) -> str:
        pass


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

    @staticmethod
    def ago(result: str) -> str:
        return utc_str(utc() - duration(result))

    @staticmethod
    def as_list(result: Any) -> List[Any]:
        if isinstance(result, list):
            return result
        elif isinstance(result, dict):
            return [{"key": k, "value": v} for k, v in result.items()]
        else:
            return [result]


# noinspection PyTypeChecker
getter: PropertyGetter = functools.partial(
    default_getter,
    virtuals={
        **default_virtuals,
        "with_index": VirtualFunctions.with_index,
        "parens": VirtualFunctions.parens,
        "from_now": VirtualFunctions.from_now,
        "ago": VirtualFunctions.ago,
        "as_list": VirtualFunctions.as_list,
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

    def json_stringify(data: Any, text: bool = False) -> Union[bytes, bytearray]:
        if isinstance(data, (bytes, bytearray)) and not text:
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
