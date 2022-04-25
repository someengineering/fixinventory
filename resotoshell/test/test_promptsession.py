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
    assert complete("", n, True) == {
        "is(kind): matches elements of defined kind",
        "all: matches all elements",
    }
    assert complete("i", n, True) == {"is(kind): matches elements of defined kind"}
    assert len(complete("is(", n)) == len(known_kinds)
    assert len(complete("is(instance) and ", n)) == len(known_props)
    assert len(complete("is(instance) or ", n)) == len(known_props)


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
