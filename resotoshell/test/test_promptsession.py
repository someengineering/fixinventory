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
    known_commands,
    SearchCompleter,
    known_kinds,
    known_props,
)


def complete(part: str, completer: Completer, return_display: bool = False) -> Set[str]:
    return {
        a.display[0][1] if return_display else a.text
        for a in completer.get_completions(Document(part, len(part)), CompleteEvent())
    }


def test_complete_command() -> None:
    n = CommandLineCompleter.create_completer(known_commands, [], [])

    # source commands
    assert len(complete("", n)) == 13
    assert complete("c", n) == {"certificate", "configs", "echo", "search"}
    assert complete("ce", n) == {"certificate"}

    # flow commands
    assert len(complete("search all | ", n)) == 22
    assert {"chunk", "clean", "count"} <= complete("search all | c", n)
    assert complete("search all | cl", n) == {"clean"}


def test_search() -> None:
    n = SearchCompleter(known_kinds, known_props)
    assert len(complete("", n, True)) > len(known_props)
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
    assert complete("is(instance) or age >= ", n, True) == {
        "Value like 123, test, 12days, true, false, null, [1,2,3], {a:1}"
    }

    # suggest sort and limit after filter
    # show possible operators for filter expression
    assert {"sort", "limit"} <= complete("is(instance) or age >= 12d ", n)

    # show all properties for sorting
    assert len(complete("is(instance) or age >= 12d sort ", n)) == len(known_props)

    # show sort order after the property
    assert {"asc", "desc"} <= complete("is(instance) or age >= 12d sort foo ", n)

    # do not suggest sort again, but limit
    assert "sort" not in complete("is(instance) or age >= 12d sort foo asc ", n)
    assert "limit" in complete("is(instance) or age >= 12d sort foo asc ", n)

    # suggest traverse operators after limit
    assert {"<--", "-->"} <= complete(
        "is(instance) or age >= 12d sort foo limit 23, 12 ", n
    )

    # suggest filter expression after traverse
    assert {"is(", "all"} <= complete(
        "is(instance) or age >= 12d sort foo limit 23, 12 --> ", n
    )


def test_complete_option() -> None:
    n = CommandLineCompleter.create_completer(known_commands, [], [])
    assert complete("ancestors ", n) == {
        "--with-origin",
        "default",
        "delete",
    }
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

    assert complete("certificate create --common-name ", n, True) == {
        "Common name like: example.com"
    }

    assert complete("configs show ", n, True) == {"<config_id> e.g. resoto.core"}

    assert complete("search all | list ", n, True) == {
        "--markdown",
        "the list of properties, comma separated",
        "--csv",
    }


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
