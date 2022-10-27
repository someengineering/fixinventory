import pathlib
import re
from abc import ABC
from attrs import define, field
from re import Pattern
from math import floor
from shutil import get_terminal_size
from typing import Iterable, Optional, List, Dict, Union, Tuple, Callable, Any

import jsons
from prompt_toolkit import PromptSession as PTSession
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
from prompt_toolkit.completion import (
    Completer,
    CompleteEvent,
    Completion,
    WordCompleter,
    NestedCompleter,
    merge_completers,
    PathCompleter,
    FuzzyCompleter,
)
from prompt_toolkit.document import Document
from prompt_toolkit.history import FileHistory
from prompt_toolkit.styles import Style
from resotoclient.async_client import ResotoClient
from resotoclient.models import Property

from resotolib.logger import log


def cut_document_remaining(document: Document, span: Tuple[int, int]) -> Document:
    remaining = document.text_before_cursor[span[0] : span[1]]
    return Document(
        remaining,
        cursor_position=document.cursor_position - (len(document.text) - len(remaining)),
    )


def cut_document_last(document: Document, last_part: str) -> Document:
    text = document.text_before_cursor
    if last_part in text:
        left, right = document.text_before_cursor.rsplit(last_part, 1)
        right_stripped = right.lstrip()
        return Document(
            right_stripped,
            cursor_position=document.cursor_position - len(left) - len(last_part) - (len(right) - len(right_stripped)),
        )
    else:
        return document


@define
class ArgInfo:
    name: Optional[str]
    expects_value: bool = False
    possible_values: List[str] = field(factory=list)
    can_occur_multiple_times: bool = False
    value_hint: Optional[str] = None
    help_text: Optional[str] = None
    option_group: Optional[str] = None


# ArgsInfo = Union[Dict[str, Union["ArgsInfo", List[ArgInfo]]], List[ArgInfo]]
# mypy does not support recursive type aliases: define 3 levels as maximum here
ArgsInfo = Union[
    Dict[
        str,
        Union[
            Dict[str, Union[Dict[str, Union[Any, List[ArgInfo]]], List[ArgInfo]]],
            List[ArgInfo],
        ],
    ],
    List[ArgInfo],
]


@define
class CommandInfo:
    name: str
    args: ArgsInfo = field(factory=dict)  # type: ignore
    source: bool = True
    info: str = ""
    help: str = ""


@define
class ArgCompleter(Completer):
    arg: ArgInfo
    completer: Optional[Completer]

    def get_completions(self, document: Document, complete_event: CompleteEvent) -> Iterable[Completion]:
        if self.completer:
            return self.completer.get_completions(document, complete_event)
        else:
            return []


@define
class CommandCompleter(Completer):
    cmd: CommandInfo
    completer: Optional[Completer]

    def get_completions(self, document: Document, complete_event: CompleteEvent) -> Iterable[Completion]:
        if self.completer:
            return self.completer.get_completions(document, complete_event)
        else:
            return []


class FuzzyWordCompleter(Completer):
    def __init__(
        self,
        words: List[str],
        display_dict: Optional[Dict[str, str]] = None,
        meta_dict: Optional[Dict[str, str]] = None,
    ) -> None:
        self.words = words
        self.WORD = True
        self.word_completer = WordCompleter(
            words=self.words,
            WORD=self.WORD,
            display_dict=display_dict,
            meta_dict=meta_dict,
        )
        self.fuzzy_completer = FuzzyCompleter(self.word_completer, WORD=self.WORD)

    def get_completions(self, document: Document, complete_event: CompleteEvent) -> Iterable[Completion]:
        return self.fuzzy_completer.get_completions(document, complete_event)

    def get_completions_filtered(
        self,
        document: Document,
        complete_event: CompleteEvent,
        predicate: Callable[[Completion], bool],
    ) -> Iterable[Completion]:
        for v in self.get_completions(document, complete_event):
            if predicate(v):
                yield v

    def get_completions_without(
        self, document: Document, complete_event: CompleteEvent, **filter_values: bool
    ) -> Iterable[Completion]:
        return self.get_completions_filtered(document, complete_event, lambda v: not filter_values.get(v.text, False))


re_nav_block = r"[a-zA-Z0-9]*(?:\[[0-9:]+\])?[a-zA-Z0-9]*"
re_navigation = re.compile(f"-{re_nav_block}->|<-{re_nav_block}-|<-{re_nav_block}->")

re_start_query = re.compile(r"^\s*(/?[A-Za-z0-9_.]*)$")
re_inside_is = re.compile(".*is\\(([^)]*)$")
re_json_value = r'(?:"[^"]*")|(?:\[[^\\]+\])|(?:\{[^}]+\})|(?:[A-Za-z0-9_\-:/.]+)'

re_partial_and_or = r"|a|an|and|o|or|-|<|-|-\[|--|<-|<-\[|s|so|sor|sort|l|li|lim|limi|limit"
re_param = "/?[A-Za-z_][A-Za-z0-9_\\-.\\[\\]]*"
re_op = "==|=|!=|<|>|<=|>=|=~|~|!~|\\s+in\\s+|\\s+not in\\s+"
re_fulltext = r'(?:"[^"]*")'

# match and/or
re_after_bracket = re.compile(f".*\\)\\s+({re_partial_and_or})$")
# noinspection RegExpUnnecessaryNonCapturingGroup
re_after_param_filter = re.compile(f".*{re_param}\\s*(?:{re_op})\\s*(?:{re_json_value})\\s({re_partial_and_or})$")
# noinspection RegExpUnnecessaryNonCapturingGroup
re_after_fulltext = re.compile(f".*(?:{re_fulltext})\\s*({re_partial_and_or})$")
re_after_sort_limit = re.compile(
    f".*(?:sort\\s+\\S+\\s(?:asc|desc)?|limit\\s+\\d+(?:,\\s*\\d+)?)\\s*({re_partial_and_or})$"
)
re_sort_attribute = re.compile(r".*sort\s+(\S*)$")
re_sort_order = re.compile(r".*sort\s+\S+\s+(\S*)$")

re_param_start = re.compile(r"(?:\s*|.*and\s+|.*or\s+)(/?[\w\-\[\]_.*]*)$")
re_slash_reported = re.compile(r"/reported.(\S*)$")
re_ancestor_descendant_kind = re.compile(r"(?:/ancestors.|/descendants.)([^.]*)$")
re_ancestor_descendant_section = re.compile(r"(?:/ancestors.|/descendants.)[\w\d_-]+[.]([^.]*)$")
re_ancestor_descendant_reported = re.compile(r"(?:/ancestors.|/descendants.)[\w\d_-]+[.]reported[.](\S*)$")
re_parm = "/?[A-Za-z0-9_\\-.\\[\\]*]*"
re_first_word = re.compile(f"^\\s*({re_parm})$")
re_second_word = re.compile(f"^\\s*{re_parm}\\s+(\\w*)$")
re_third_word = re.compile(f"^\\s*{re_parm}\\s+\\w+\\s+(\\w*)$")
re_after_third_word = re.compile(f"^\\s*{re_parm}\\s+\\w+\\s+\\w+\\s*(\\w*)$")
re_inside_function = re.compile(r".*\w+\(([^)]*)$")
re_fn = r"\w+\([^)]+\)"
re_second_word_after_fn = re.compile(f"^\\s*{re_fn}\\s*(\\w*)$")
re_third_word_after_fn = re.compile(f"^\\s*{re_fn}\\s+\\w+\\s*(\\w*)$")
re_after_third_word_fn = re.compile(f"^\\s*{re_fn}\\s+\\w+\\s+\\w+\\s*(\\w*)$")
re_after_bracket_start = re.compile(r"(?:|.*\s+)\((\w*)$")


class DocumentExtension:
    def __init__(self, document: Document, part_splitter: Optional[Pattern[str]] = None) -> None:
        self.document = document
        self.text = document.text_before_cursor
        self.parts = part_splitter.split(self.text) if part_splitter else [self.text]
        self.last = self.parts[-1].lstrip() if self.parts else ""
        self.last_words = self.last.split()
        self.last_word = self.word_at(-1)

    def cut_text(self, span: Tuple[int, int]) -> Document:
        return cut_document_remaining(self.document, span)

    def cut_last(self, span: Tuple[int, int]) -> Document:
        return cut_document_remaining(self.last_doc(), span)

    def last_doc(self) -> Document:
        return Document(self.last, self.document.cursor_position - (len(self.text) - len(self.last)))

    def word_at(self, idx: int) -> str:
        return self.last_words[idx] if abs(idx) <= len(self.last_words) else ""


class AbstractSearchCompleter(Completer, ABC):
    def __init__(self, kinds: List[str], props: List[str]):
        self.kinds = kinds
        self.props = props
        self.prop_lookup = set(props)
        ops = ["=", "!=", ">", "<", "<=", ">=", "~", "!~", "in"]
        self.ops_lookup = set(ops)
        self.kind_completer = FuzzyWordCompleter(kinds, meta_dict={p: "kind" for p in kinds})
        self.property_names_completer = FuzzyWordCompleter(
            props + ["/ancestors", "/reported", "/desired", "/metadata", "/descendants"],
            meta_dict=(
                {
                    "/reported": "absolute path in reported section",
                    "/desired": "absolute path in desired section",
                    "/metadata": "absolute path in metadata section",
                    "/ancestors": "ancestor properties",
                    "/descendants": "descendant properties",
                    **{p: "property" for p in self.props},
                }
            ),
        )
        self.start_completer = FuzzyWordCompleter(
            ['"', "is(", "/ancestors"] + props + ["/reported", "/desired", "/metadata", "/descendants", "all"],
            meta_dict=(
                {
                    '"': 'full text search. e.g. "test"',
                    "is(": "matches elements of defined kind",
                    "all": "matches all elements",
                    "/reported": "absolute path in reported section",
                    "/desired": "absolute path in desired section",
                    "/metadata": "absolute path in metadata section",
                    "/ancestors": "filter ancestor properties",
                    "/descendants": "filter descendant properties",
                    **{p: "filter property" for p in self.props},
                }
            ),
        )
        self.ops_completer = FuzzyWordCompleter(ops)
        self.and_or_completer = FuzzyWordCompleter(
            [
                "and",
                "or",
                "sort",
                "limit",
                "-->",
                "<--",
                "-[0:1]->",
                "<-[0:1]-",
                "-[0:]->",
                "<-[0:]-",
                "<-[0:]->",
            ],
            meta_dict={
                "and": "combine next term with and",
                "or": "combine next term with or",
                "sort": "sort results based on property",
                "limit": "limit results by offset and number",
                "-->": "traverse outbound one hop",
                "<--": "traverse inbound one hop",
                "-[0:1]->": "outbound one hop with current node",
                "<-[0:1]-": "inbound one hop with current node",
                "-[0:]->": "outbound to all leaves",
                "<-[0:]-": "inbound until the root",
                "<-[0:]->": "any reachable node from here",
            },
        )
        self.value_completer = HintCompleter("<value>", "like 123, test, 12days, true, false, null, [1,2,3], {a:1}")
        self.limit_completer = HintCompleter("<num>", "Number of elements with optional offset. e.g. 23 or 12, 23")
        self.sort_order_completer = FuzzyWordCompleter(["asc", "desc"])
        self.section_completer = FuzzyWordCompleter(["reported", "desired", "metadata"])

    def property_path_completions(
        self, completer: Completer, doc: Document, complete_event: CompleteEvent
    ) -> Iterable[Completion]:
        all_completions = list(completer.get_completions(doc, complete_event))
        # reduce the list to the next dot, in case there are too many suggestions
        if len(all_completions) > 10:
            dl = len(doc.text_before_cursor)
            reduced = [a for a in all_completions if "." not in a.text[dl:]]
            all_completions = reduced if reduced else all_completions
        return all_completions

    def property_completions(
        self,
        doc: Document,
        ext: DocumentExtension,
        complete_event: CompleteEvent,
        start_with: Completer,
    ) -> Iterable[Completion]:
        if kind := re_ancestor_descendant_kind.match(ext.last_word):
            pd = cut_document_remaining(doc, kind.span(1))
            return self.kind_completer.get_completions(pd, complete_event)
        elif section := re_ancestor_descendant_section.match(ext.last_word):
            pd = cut_document_remaining(doc, section.span(1))
            return self.section_completer.get_completions(pd, complete_event)
        elif section := re_ancestor_descendant_reported.match(ext.last_word):
            pd = cut_document_remaining(doc, section.span(1))
            return self.property_path_completions(self.property_names_completer, pd, complete_event)
        elif reported := re_slash_reported.match(ext.last_word):
            pd = cut_document_remaining(doc, reported.span(1))
            return self.property_path_completions(self.property_names_completer, pd, complete_event)
        else:
            return self.property_path_completions(start_with, doc, complete_event)


class KindCompleter(AbstractSearchCompleter):
    def get_completions(self, document: Document, complete_event: CompleteEvent) -> Iterable[Completion]:
        return self.kind_completer.get_completions(document, complete_event)


class SearchCompleter(AbstractSearchCompleter):
    def get_completions(self, document: Document, complete_event: CompleteEvent) -> Iterable[Completion]:
        ext = DocumentExtension(document, re_navigation)
        have_sort = " sort " in ext.last
        have_limit = " limit " in ext.last

        if in_start := re_start_query.match(ext.last):
            doc = ext.cut_last(in_start.span(1))
            return self.property_completions(doc, ext, complete_event, self.start_completer)
        elif parm := re_param_start.match(ext.text):
            doc = ext.cut_text(parm.span(1))
            return self.property_completions(doc, ext, complete_event, self.start_completer)
        elif bracket := re_after_bracket_start.match(ext.text):
            doc = ext.cut_text(bracket.span(1))
            return self.property_completions(doc, ext, complete_event, self.start_completer)
        elif in_is := re_inside_is.match(ext.text):
            doc = ext.cut_text(in_is.span(1))
            return self.kind_completer.get_completions(doc, complete_event)
        elif after := re_after_bracket.match(ext.last):
            doc = ext.cut_last(after.span(1))
            return self.and_or_completer.get_completions(doc, complete_event)
        elif after := re_after_fulltext.match(ext.last):
            doc = ext.cut_last(after.span(1))
            return self.and_or_completer.get_completions(doc, complete_event)
        elif after := re_sort_attribute.match(ext.last):
            doc = ext.cut_last(after.span(1))
            return self.property_completions(doc, ext, complete_event, self.property_names_completer)
        elif after := re_sort_order.match(ext.last):  # sort order
            doc = ext.cut_last(after.span(1))
            return self.sort_order_completer.get_completions(doc, complete_event)
        elif ext.last_word == "limit":
            doc = cut_document_last(document, ext.last_word)
            return self.limit_completer.get_completions(doc, complete_event)
        elif after := re_after_sort_limit.match(ext.last):
            doc = cut_document_remaining(document, after.span(1))
            return self.and_or_completer.get_completions_without(
                doc,
                complete_event,
                **{
                    "sort": have_sort | have_limit,
                    "limit": have_limit,
                    "and": have_sort | have_limit,
                    "or": have_sort | have_limit,
                },
            )
        elif after := re_after_param_filter.match(ext.last):
            doc = ext.cut_last(after.span(1))
            return self.and_or_completer.get_completions(doc, complete_event)
        elif (ext.last_word in self.prop_lookup or ext.last_word.startswith("/")) and not have_sort:
            doc = cut_document_last(document, ext.last_word)
            return self.ops_completer.get_completions(doc, complete_event)
        elif ext.last_word in self.ops_lookup:
            doc = cut_document_last(document, ext.last_word)
            return self.value_completer.get_completions(doc, complete_event)
        else:
            return []


class AggregateCompleter(AbstractSearchCompleter):
    def __init__(self, kinds: List[str], props: List[str]) -> None:
        super().__init__(kinds, props)
        self.aggregate_fns = ["sum(", "min(", "max(", "avg("]
        self.aggregate_fn_completer = FuzzyWordCompleter(
            self.aggregate_fns,
            meta_dict={
                "sum(": "sum over all occurrences",
                "min(": "use the smallest occurrence",
                "max(": "use the biggest occurrence",
                "avg(": "average over all occurrences",
            },
        )
        self.as_completer = FuzzyWordCompleter(["as"], meta_dict=({"as": "rename this result"}))
        self.colon_completer = FuzzyWordCompleter(
            [":"],
            meta_dict=({":": "to define functions for this group"}),
        )
        self.comma_var_completer = FuzzyWordCompleter(
            [","],
            meta_dict=({",": "define another group variable"}),
        )
        self.comma_fn_completer = FuzzyWordCompleter(
            [","],
            meta_dict=({",": "define another group function"}),
        )
        self.props_completer = FuzzyWordCompleter(
            props + ["/ancestors", "/reported", "/desired", "/metadata", "/descendants"],
            meta_dict=(
                {
                    "/reported": "absolute path in reported section",
                    "/desired": "absolute path in desired section",
                    "/metadata": "absolute path in metadata section",
                    "/ancestors": "on ancestor properties",
                    "/descendants": "on descendant properties",
                    **{p: "aggregate property" for p in self.props},
                }
            ),
        )
        self.group_with_value_completer = merge_completers(
            [HintCompleter("1", "Static value to count", "1"), self.props_completer]
        )
        self.group_after_name = merge_completers([self.as_completer, self.colon_completer, self.comma_var_completer])
        self.fn_after_name = merge_completers([self.as_completer, self.comma_fn_completer])
        self.after_group = merge_completers([self.comma_var_completer, self.colon_completer])
        self.after_fn_completer = merge_completers([self.as_completer, self.comma_fn_completer])
        self.hint_completer = HintCompleter(
            "Example",
            "aggregation example",
            "kind, volume_type as type: sum(volume_size) as volume_size",
        )
        self.with_hint_completer = merge_completers(
            [self.hint_completer, self.props_completer, self.aggregate_fn_completer]
        )
        self.value_hint_completer = HintCompleter("<name>", "name of this result")

    def group_completion(self, document: Document, complete_event: CompleteEvent) -> Iterable[Completion]:
        ext = DocumentExtension(document, re.compile(r"\s*,\s*"))
        if first := re_first_word.match(ext.last):
            doc = ext.cut_last(first.span(1))
            return self.property_completions(doc, ext, complete_event, self.props_completer)
        elif second := re_second_word.match(ext.last):
            doc = ext.cut_last(second.span(1))
            return self.group_after_name.get_completions(doc, complete_event)
        elif third := re_third_word.match(ext.last):
            doc = ext.cut_last(third.span(1))
            return self.value_hint_completer.get_completions(doc, complete_event)
        elif after := re_after_third_word.match(ext.last):
            doc = ext.cut_last(after.span(1))
            return self.after_group.get_completions(doc, complete_event)
        else:
            return []

    def fn_completion(self, document: Document, complete_event: CompleteEvent) -> Iterable[Completion]:
        ext = DocumentExtension(cut_document_last(document, ":"), re.compile(r"\s*,\s*"))
        if first := re_first_word.match(ext.last):
            doc = ext.cut_last(first.span(1))
            return self.aggregate_fn_completer.get_completions(doc, complete_event)
        elif in_fn := re_inside_function.match(ext.last):
            doc = ext.cut_last(in_fn.span(1))
            return self.group_with_value_completer.get_completions(doc, complete_event)
        elif second := re_second_word_after_fn.match(ext.last):
            doc = ext.cut_last(second.span(1))
            return self.fn_after_name.get_completions(doc, complete_event)
        elif third := re_third_word_after_fn.match(ext.last):
            doc = ext.cut_last(third.span(1))
            return self.value_hint_completer.get_completions(doc, complete_event)
        elif after := re_after_third_word_fn.match(ext.last):
            doc = ext.cut_last(after.span(1))
            return self.comma_fn_completer.get_completions(doc, complete_event)
        else:
            return []

    def get_completions(self, document: Document, complete_event: CompleteEvent) -> Iterable[Completion]:
        text = document.text_before_cursor
        in_functions = ":" in text or any(a for a in self.aggregate_fns if a in text)
        if text.strip() == "":
            return self.with_hint_completer.get_completions(document, complete_event)
        elif in_functions:
            return self.fn_completion(document, complete_event)
        else:
            return self.group_completion(document, complete_event)


class PropertyCompleter(AbstractSearchCompleter):
    def get_completions(self, document: Document, complete_event: CompleteEvent) -> Iterable[Completion]:
        ext = DocumentExtension(document)
        return self.property_completions(document, ext, complete_event, self.property_names_completer)


class PropertyListCompleter(AggregateCompleter):
    # Inherit from aggregate completer only, since the grouping completer
    # already implements everything we need.
    def __init__(self, kinds: List[str], props: List[str], with_as: bool = True) -> None:
        super().__init__(kinds, props)
        self.comma_var_completer = FuzzyWordCompleter(
            [","],
            meta_dict=({",": "define another variable"}),
        )
        self.props_completer = self.property_names_completer
        self.group_after_name = (
            merge_completers([self.as_completer, self.comma_var_completer]) if with_as else self.comma_var_completer
        )
        self.after_group = self.comma_var_completer

    def get_completions(self, document: Document, complete_event: CompleteEvent) -> Iterable[Completion]:
        return self.group_completion(document, complete_event)


class HintCompleter(Completer):
    def __init__(self, hint: str, meta: Optional[str] = None, value: str = " ") -> None:
        self.value = value
        self.cpl = WordCompleter([value], meta_dict={value: meta}, display_dict={value: hint}, WORD=True)

    def get_completions(self, document: Document, complete_event: CompleteEvent) -> Iterable[Completion]:
        # Only show a hint once at the start
        if self.value == " " and document.text_before_cursor.strip() != "":
            return []
        else:
            return self.cpl.get_completions(document, complete_event)


class ArgsCompleter(Completer):
    def __init__(self, args: List[ArgCompleter]):
        direct: List[ArgCompleter] = []
        opts: List[ArgCompleter] = []
        for x in args:
            (direct if x.arg.name is None else opts).append(x)
        self.direct = direct
        self.args: Dict[str, ArgCompleter] = {arg.arg.name: arg for arg in opts if arg.arg.name is not None}
        self.value_lookup: Dict[str, ArgCompleter] = {v: a for a in args for v in a.arg.possible_values}
        self.options_completer = FuzzyWordCompleter(
            list(self.args.keys()),
            meta_dict={
                arg: complete.arg.help_text for arg, complete in self.args.items() if complete.arg.help_text is not None
            },
        )

    def inside_option(self, parts: List[str]) -> Optional[ArgCompleter]:
        for idx, part in enumerate(reversed(parts)):
            if (parm := self.args.get(part)) is not None:
                return parm if parm.arg.expects_value and idx < 2 else None
        return None

    def get_completions(self, document: Document, complete_event: CompleteEvent) -> Iterable[Completion]:
        text = document.text_before_cursor
        parts = text.strip().split()
        maybe = self.inside_option(parts)

        # eat all options: remaining parts can be completed eventually
        adapted = text
        for arg in self.args.values():
            val_pattern = "\\s+\\S+\\s+" if arg.arg.expects_value else "\\s*"
            adapted = re.sub(f"\\s*{arg.arg.name}{val_pattern}", "", adapted)
        doc = Document(
            adapted,
            cursor_position=document.cursor_position - (len(text) - len(adapted)),
        )

        # look at the last word to see if an option is started
        adapted_stripped = adapted.lstrip()
        sp = adapted_stripped.rsplit(maxsplit=1)
        last = sp[-1] if len(sp) > 1 else adapted_stripped
        start_arg = last.strip() != "" and any(a.arg.name.startswith(last) for a in self.args.values() if a.arg.name)

        def direct_completers() -> Completer:
            def allowed_arg(arg_info: ArgInfo) -> bool:
                group = arg_info.option_group
                return group is None or not any(
                    a.arg.name in parts for a in self.args.values() if a.arg.option_group == group
                )

            d = [a.completer for a in self.direct if a.completer if allowed_arg(a.arg)]
            return merge_completers(d)

        def allowed(completion: Completion) -> bool:
            txt = completion.text
            # has this parameter been specified before?
            already_defined = txt in parts and txt in self.args and not self.args[txt].arg.can_occur_multiple_times

            # is this a possible value, where another value is already defined?
            another_value_defined = False
            if txt in self.value_lookup:
                another_value_defined = any(v for v in self.value_lookup[txt].arg.possible_values if v in parts)

            # another option group defined
            ag = self.args.get(completion.text)
            option_group_defined = False
            if group := ag.arg.option_group if ag else None:
                option_group_defined = any(
                    a.arg.name in parts for a in self.args.values() if a.arg.option_group == group
                )

            # if we come here: this is a valid completion
            return False if already_defined or another_value_defined or option_group_defined else True

        # either there is no option or an option has been started
        if adapted_stripped == "" or start_arg:
            last_doc = Document(
                last,
                cursor_position=document.cursor_position - (len(document.text) - len(last)),
            )
            direct = direct_completers().get_completions(doc, complete_event)
            opts = self.options_completer.get_completions(last_doc, complete_event)
            return [c for c in opts if allowed(c)] + list(direct)
            # inside an option
        elif maybe is not None and maybe.arg.name is not None:
            # suggest the arg values
            doc = cut_document_last(doc, maybe.arg.name)
            return maybe.get_completions(doc, complete_event)
            # no option started and not inside any option: assume a direct completion
        else:
            return direct_completers().get_completions(doc, complete_event)


class CommandLineCompleter(Completer):
    def __init__(self, commands: List[CommandInfo], completers: List[CommandCompleter]):
        self.commands = commands
        self.command_completers = {c.cmd.name: c for c in completers}
        self.source_completer = FuzzyWordCompleter([c.name for c in commands if c.source])
        self.flow_completer = FuzzyWordCompleter([c.name for c in commands if not c.source])

    def find_current_command(self, document: Document) -> Optional[Tuple[CommandCompleter, str]]:
        parts = document.text_before_cursor.lstrip().split(maxsplit=1)
        if parts and (command := self.command_completers.get(parts[0])) is not None:
            args = parts[1] if len(parts) == 2 else ""
            return command, args
        return None

    def get_completions(self, document: Document, complete_event: CompleteEvent) -> Iterable[Completion]:
        text = document.text_before_cursor.lstrip()

        adapted = document
        if ";" in text:
            left, right = document.text_before_cursor.rsplit(";", 1)
            adapted = Document(right, document.cursor_position - len(left) - 1)

        if "|" in adapted.text_before_cursor:
            left, right = adapted.text_before_cursor.rsplit("|", 1)
            adapted = Document(right, document.cursor_position - len(left) - 1)

        if not text.endswith((";", "|")):  # enforce a space after ; or |
            maybe = self.find_current_command(adapted)
            if maybe is not None:
                completer, arg = maybe
                doc = Document(arg, len(arg))
                return completer.get_completions(doc, complete_event)
            elif ";" in text or "|" in text:
                return self.flow_completer.get_completions(adapted, complete_event)
            else:
                return self.source_completer.get_completions(adapted, complete_event)
        else:
            return []

    @staticmethod
    def create_completer(cmds: List[CommandInfo], kinds: List[str], props: List[str]) -> "CommandLineCompleter":
        def arg_completer(arg: ArgInfo) -> Optional[Completer]:
            if arg.possible_values:
                meta = {a: arg.help_text for a in arg.possible_values} if arg.help_text is not None else None
                return FuzzyWordCompleter(arg.possible_values, meta_dict=meta)
            elif arg.value_hint == "file":
                return PathCompleter()
            elif arg.value_hint == "kind":
                return KindCompleter(kinds, props)
            elif arg.value_hint == "property":
                return PropertyCompleter(kinds, props)
            elif arg.value_hint == "property_list_plain":
                return PropertyListCompleter(kinds, props, with_as=False)
            elif arg.value_hint == "property_list_with_as":
                return PropertyListCompleter(kinds, props, with_as=True)
            elif arg.value_hint == "command":
                meta = {cmd.name: "command" for cmd in cmds}
                return FuzzyWordCompleter([cmd.name for cmd in cmds], meta_dict=meta)
            elif arg.value_hint == "search":
                return SearchCompleter(kinds, props)
            elif arg.value_hint == "aggregate":
                return AggregateCompleter(kinds, props)
            elif arg.help_text:
                return HintCompleter("<value>", arg.help_text)
            else:
                return HintCompleter("<value>")

        def arg_value_completer(arg: ArgInfo) -> ArgCompleter:
            return ArgCompleter(arg, arg_completer(arg))

        def command_completer(cmd: CommandInfo) -> Optional[Completer]:
            def walk_commands(sub_commands: Dict[str, Union["ArgsInfo", List[ArgInfo]]]) -> Completer:
                return NestedCompleter.from_nested_dict(
                    {
                        sub_cmd: ArgsCompleter([arg_value_completer(arg) for arg in options])
                        if isinstance(options, list)
                        else walk_commands(options)
                        for sub_cmd, options in sub_commands.items()
                    }
                )

            if isinstance(cmd.args, list):
                return ArgsCompleter([arg_value_completer(arg) for arg in cmd.args])
            elif isinstance(cmd.args, dict):
                return walk_commands(cmd.args)
            else:
                return None

        cmd_completer = [CommandCompleter(cmd, command_completer(cmd)) for cmd in cmds]
        return CommandLineCompleter(cmds, cmd_completer)


class SafeCompleter(Completer):
    """
    This completer ensures, that the underlying completer will always return "something"
    prompt_toolkit does not handle empty completions very well.
    """

    def __init__(self, completer: Completer) -> None:
        self.completer = completer

    def get_completions(self, document: Document, complete_event: CompleteEvent) -> Iterable[Completion]:
        try:
            result = self.completer.get_completions(document, complete_event)
            return [] if result is None else result
        except Exception as ex:
            log.warning(f"Error in completer: {ex}", exc_info=ex)
            return []


class PromptSession:

    style = Style.from_dict(
        {
            "green": "#00ff00",
            "red": "#ff0000",
            "prompt": "#C724B1",
        }
    )

    prompt_message = [("class:prompt", "> ")]

    def __init__(
        self,
        cmds: List[CommandInfo],
        kinds: List[str],
        props: List[str],
        history_file: str = str(pathlib.Path.home() / ".resotoshell_history"),
    ):
        history = FileHistory(history_file)
        _, tty_rows = get_terminal_size(fallback=(80, 25))
        reserved_row_ratio = 1 / 4
        min_reserved_rows = 4
        max_reserved_rows = 12
        reserved_space_for_menu = max(min_reserved_rows, min(floor(tty_rows * reserved_row_ratio), max_reserved_rows))
        self.completer = CommandLineCompleter.create_completer(cmds, kinds, props)
        self.session: PTSession[str] = PTSession(history=history, reserve_space_for_menu=reserved_space_for_menu)

    async def prompt(self) -> str:
        return await self.session.prompt_async(
            self.prompt_message,  # type: ignore
            completer=SafeCompleter(self.completer),
            complete_while_typing=True,
            style=self.style,
            auto_suggest=AutoSuggestFromHistory(),
        )


async def core_metadata(
    client: ResotoClient,
) -> Tuple[List[CommandInfo], List[str], List[str]]:

    try:
        log.debug("Fetching core metadata..")
        model = await client.model()

        def path(p: Property) -> List[str]:
            kind = p.kind
            name = p.name
            result = [name]
            if p.kind.endswith("[]"):
                kind = kind[:-2]
                name += "[*]"
                result.append(name)

            kd = model.kinds.get(kind)
            if kd is not None and kd.properties:
                result.extend(name + "." + pp for prop in kd.properties for pp in path(prop))
            return result

        aggregate_roots = {
            k: v for k, v in model.kinds.items() if getattr(v, "aggregate_root", True) and v.properties is not None
        }

        known_props = {p for v in aggregate_roots.values() for prop in v.properties or [] for p in path(prop)}
        info = await client.cli_info()
        cmds = [jsons.load(cmd, CommandInfo) for cmd in info.get("commands", [])]
        return cmds, sorted(aggregate_roots.keys()), sorted(known_props)
    except Exception as ex:
        log.warning(
            f"Can not load metadata from core: {ex}. No suggestions as fallback.",
            exc_info=ex,
        )
        return [], [], []
