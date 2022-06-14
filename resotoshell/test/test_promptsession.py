import re
from typing import Set

from prompt_toolkit.completion import (
    Completer,
    CompleteEvent,
    WordCompleter,
    NestedCompleter,
)
from prompt_toolkit.document import Document

from resotoshell.promptsession import (
    CommandLineCompleter,
    SearchCompleter,
    DocumentExtension,
    AggregateCompleter,
    PropertyListCompleter,
    CommandInfo,
    ArgInfo,
)

known_kinds = ["account", "instance", "instance_type", "network"]
known_props = [
    "age",
    "instance_memory",
    "instance_status",
    "some.nested.prop",
    "some.nested.other.prop",
    "some.nested.array[*].other[*].prop.foo",
]
known_commands = [
    CommandInfo("aggregate", source=False, args=[ArgInfo(None, True, value_hint="aggregate")]),
    CommandInfo(
        "ancestors",
        args=[
            ArgInfo("--with-origin", help_text="include the origin in the output"),
            ArgInfo(None, True, ["default", "delete"], help_text="edge type"),
        ],
        source=False,
    ),
    CommandInfo(
        "certificate",
        args={
            "create": [
                ArgInfo("--common-name", True, help_text="Common name like: example.com"),
                ArgInfo(
                    "--dns-names",
                    True,
                    help_text="List of other dns names: example.org example.io",
                ),
                ArgInfo(
                    "--ip-addresses",
                    True,
                    help_text="List of ip addresses: 1.2.3.4 2.3.4.5",
                ),
            ],
        },
    ),
    CommandInfo(
        "configs",
        args={
            "list": [],
            "set": [
                ArgInfo(None, expects_value=True, help_text="<config_id> <key>=<value>"),
            ],
            "show": [ArgInfo(None, expects_value=True, help_text="<config_id> e.g. resoto.core")],
            "edit": [
                ArgInfo(None, expects_value=True, help_text="<config_id> e.g. resoto.core"),
            ],
            "update": [
                ArgInfo(
                    None,
                    expects_value=True,
                    help_text="<config_id> /path/to/config.yaml",
                ),
            ],
            "delete": [
                ArgInfo(None, expects_value=True, help_text="<config_id> e.g. resoto.core"),
            ],
        },
    ),
    CommandInfo(
        "count",
        [
            ArgInfo(
                None,
                expects_value=True,
                help_text="optional property to count",
                value_hint="property",
            )
        ],
        source=False,
    ),
    CommandInfo(
        "list",
        [
            ArgInfo("--csv", help_text="format", option_group="format"),
            ArgInfo("--markdown", help_text="format", option_group="format"),
            ArgInfo(
                None,
                expects_value=True,
                help_text="the list of properties, comma separated",
                value_hint="property_list_with_as",
            ),
        ],
        source=False,
    ),
    CommandInfo(
        "search",
        args=[
            ArgInfo("--with-edges", help_text="include edges in the output"),
            ArgInfo(None, True, value_hint="search"),
        ],
    ),
]


def complete(part: str, completer: Completer, return_meta: bool = False) -> Set[str]:
    return {
        a.display_meta_text if return_meta else a.text
        for a in completer.get_completions(Document(part, len(part)), CompleteEvent())
    }


def test_doc_ext() -> None:
    d = Document("Sentence 1. Things I want to say", 32)
    ext = DocumentExtension(d, re.compile(r"\s*[.]\s*"))
    assert ext.last_doc() == Document("Things I want to say", 20)


def test_complete_command() -> None:
    n = CommandLineCompleter.create_completer(known_commands, [], [])

    # source commands
    assert len(complete("", n)) == 3
    assert complete("c", n) == {"certificate", "configs", "search"}
    assert complete("ce", n) == {"certificate"}

    # flow commands
    assert len(complete("search all | ", n)) == 4
    assert complete("search all | c", n) == {"ancestors", "count"}


def test_property() -> None:
    n = SearchCompleter(known_kinds, known_props)
    # /ancestors.xxx handling
    assert complete("/anc", n) == {"/ancestors"}
    assert len(complete("/ancestors.", n)) == len(known_kinds)
    assert complete("/ancestors.account.", n) == {"reported", "desired", "metadata"}
    assert len(complete("/ancestors.account.reported.", n)) >= len(known_props)
    assert complete("is(volume) and /anc", n) == {"/ancestors"}
    assert len(complete("is(volume) and /ancestors.", n)) == len(known_kinds)
    assert complete("is(volume) and /ancestors.account.", n) == {
        "reported",
        "desired",
        "metadata",
    }
    assert len(complete("is(volume) and /ancestors.account.reported.", n)) >= len(known_props)
    # /reported handling
    assert complete("/repo", n) == {"/reported"}
    assert len(complete("/reported.", n)) >= len(known_props)

    assert complete("some.nested.", n) == {
        "some.nested.array[*].other[*].prop.foo",
        "some.nested.other.prop",
        "some.nested.prop",
    }
    assert complete("some.nested.array[", n) == {"some.nested.array[*].other[*].prop.foo"}


def test_property_list() -> None:
    n = PropertyListCompleter(known_kinds, known_props)
    assert complete("/anc", n) == {"/ancestors"}
    assert complete("foo, /anc", n) == {"/ancestors"}
    assert complete("foo as bla, /anc", n) == {"/ancestors"}
    assert complete("foo as bla, ins", n) == {"instance_memory", "instance_status"}
    assert len(complete("foo as ", n)) == 1  # suggest name


def test_search() -> None:
    n = SearchCompleter(known_kinds, known_props)
    assert len(complete("", n)) > len(known_props)
    assert "is(" in complete("i", n)

    # show possible kinds in is()
    assert len(complete("is(", n)) == len(known_kinds)

    # show possible combinations after is()
    assert {"and", "or"} <= complete("is(foo) ", n)

    # show possible props for filter expression
    assert len(complete("is(instance) and ", n)) > len(known_props)
    assert len(complete("is(instance) or ", n)) > len(known_props)

    # show possible operators for filter expression
    assert {">", "<", "=", "!=", ">=", "<="} <= complete("is(instance) or age ", n)

    # show possible operators for filter expression
    assert complete("is(instance) or age >= ", n, True) == {"like 123, test, 12days, true, false, null, [1,2,3], {a:1}"}

    # suggest sort and limit after filter
    # show possible operators for filter expression
    assert {"sort", "limit"} <= complete("is(instance) or age >= 12d ", n)

    # show all properties for sorting
    assert len(complete("is(instance) or age >= 12d sort ", n)) >= len(known_props)

    # show sort order after the property
    assert {"asc", "desc"} <= complete("is(instance) or age >= 12d sort foo ", n)

    # do not suggest sort again, but limit
    assert "sort" not in complete("is(instance) or age >= 12d sort foo asc ", n)
    assert "limit" in complete("is(instance) or age >= 12d sort foo asc ", n)

    # suggest traverse operators after limit
    assert {"<--", "-->"} <= complete("is(instance) or age >= 12d sort foo limit 23, 12 ", n)

    # suggest filter expression after traverse
    assert {"is(", "all"} <= complete("is(instance) or age >= 12d sort foo limit 23, 12 --> ", n)
    assert {"is(", "all"} <= complete("(", n)


def test_aggregate() -> None:
    n = AggregateCompleter(known_kinds, known_props)
    # show all  possible properties (+ example etc)
    assert len(complete("", n)) >= len(known_props)
    # after the group
    assert {"as", ":", ","} <= complete("name ", n)
    # define a name for the group
    assert complete("name as ", n, True) == {"name of this result"}
    # after a complete group
    assert {":", ","} <= complete("name as bla ", n)
    assert "as" not in complete("name as bla ", n)
    # expect the next group var
    assert len(complete("name, ", n)) >= len(known_props)
    # works the same for multiple group vars
    assert {"as", ":", ","} <= complete("name, foo ", n)

    # show possible functions
    assert {"sum(", "min("} <= complete("name: ", n)
    # show all properties + static values
    assert len(complete("name: sum(", n)) >= len(known_props)
    # suggest to name this function
    assert {"as", ","} <= complete("name: sum(1)", n)
    # after named function, only comma is allowed
    assert complete("name: sum(1) as bla ", n) == {","}
    assert complete("name: sum(1) as bla, min(foo) as foo ", n) == {","}

    # start with function
    assert len(complete("sum(", n)) >= len(known_props)
    assert complete("sum(foo) as ", n, True) == {"name of this result"}
    assert {"sum(", "min("} <= complete("sum(foo) as foo,", n)


def test_complete_option() -> None:
    n = CommandLineCompleter.create_completer(known_commands, known_kinds, known_props)
    assert complete("ancestors ", n) == {
        "--with-origin",
        "default",
        "delete",
    }
    # show all options
    assert complete("ancestors --with-origin ", n) == {"default", "delete"}
    # once a direct value is supplied, no other option is shown
    assert complete("ancestors default ", n) == set()
    # once a direct value is supplied, no other option is shown
    assert complete("ancestors --with-origin default ", n) == set()
    assert complete("ancestors -", n) == {"--with-origin"}
    assert complete("configs ", n) == {
        "list",
        "set",
        "show",
        "edit",
        "update",
        "delete",
    }
    assert complete("configs show ", n, True) == {"<config_id> e.g. resoto.core"}
    assert complete("certificate create --common-name ", n, True) == {"Common name like: example.com"}
    assert "--common-name" not in complete("certificate create --common-name example.com ", n)
    assert complete("configs show ", n, True) == {"<config_id> e.g. resoto.core"}
    assert {"--markdown", "--csv"} <= complete("search all | list ", n)
    assert len(complete("search all | list ", n)) >= len(known_props)

    # nothing is suggested when the hint has been provided
    assert complete("echo hello ", n) == set()


def test_complete_word() -> None:
    w = WordCompleter(["aaa", "bbb", "ccc"])
    assert complete("", w) == {"aaa", "bbb", "ccc"}
    assert complete("a", w) == {"aaa"}

    n = NestedCompleter.from_nested_dict(
        {
            "aggregate": WordCompleter(["avg", "sum", "count"]),
            "ancestors": {
                "--with-origin": None,
                "default": {"foo": {"bla": {"bar"}}},
                "delete": None,
            },
        }
    )
    assert complete("", n) == {"aggregate", "ancestors"}

    # nested
    assert complete("anc", n) == {"ancestors"}
    assert complete("ancestors ", n) == {"--with-origin", "default", "delete"}
    assert complete("ancestors --", n) == {"--with-origin"}
    assert complete("ancestors default foo ", n) == {"bla"}
    assert complete("ancestors default foo bla ", n) == {"bar"}

    # words
    assert complete("aggregate ", n) == {"avg", "sum", "count"}
    assert complete("aggregate a", n) == {"avg"}
