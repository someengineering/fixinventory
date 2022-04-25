from typing import List

from prompt_toolkit.completion import (
    Completer,
    CompleteEvent,
    WordCompleter,
    NestedCompleter,
)
from prompt_toolkit.document import Document

from resotoshell.promptsession import (
    ResotoCompleter,
    known_commands,
)


def complete(part: str, completer: Completer, return_display: bool = True) -> List[str]:
    return [
        a.display[0][1] if return_display else a.text
        for a in completer.get_completions(Document(part, len(part)), CompleteEvent())
    ]


def test_complete_command() -> None:
    n = ResotoCompleter(*known_commands)

    # source commands
    assert len(complete("", n)) == 12
    assert complete("c", n) == ["certificate", "configs"]
    assert complete("ce", n) == ["certificate"]

    # flow commands
    assert len(complete("search all | ", n)) == 22
    assert complete("search all | c", n) == ["chunk", "clean", "count"]
    assert complete("search all | cl", n) == ["clean"]


def test_complete_option() -> None:
    n = ResotoCompleter(*known_commands)
    assert complete("ancestors ", n) == [
        "--with-origin",
        "default: (edge type)",
        "delete: (edge type)",
    ]
    assert complete("ancestors -", n) == ["--with-origin"]
    assert complete("configs ", n) == [
        "list",
        "set",
        "show",
        "edit",
        "update",
        "delete",
    ]
    assert complete("configs show ", n) == ["<config_id> e.g. resoto.core"]

    assert complete("certificate create --common-name ", n, True) == [
        "Common name like: example.com"
    ]

    assert complete("configs show ", n) == ["<config_id> e.g. resoto.core"]


def test_complete_word() -> None:
    w = WordCompleter(["aaa", "bbb", "ccc"])
    assert complete("", w) == ["aaa", "bbb", "ccc"]
    assert complete("a", w) == ["aaa"]

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
    assert complete("", n) == ["aggregate", "ancestors"]

    # nested
    assert complete("anc", n) == ["ancestors"]
    assert complete("ancestors ", n) == ["--with-origin", "default", "delete"]
    assert complete("ancestors --", n) == ["--with-origin"]
    assert complete("ancestors default foo ", n) == ["bla"]
    assert complete("ancestors default foo bla ", n) == ["bar"]

    # words
    assert complete("aggregate ", n) == ["avg", "sum", "count"]
    assert complete("aggregate a", n) == ["avg"]
