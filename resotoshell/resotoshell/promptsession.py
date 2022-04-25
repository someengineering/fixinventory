import pathlib
from dataclasses import dataclass, field
from typing import Iterable, Optional, List, Dict, Union

from prompt_toolkit import PromptSession as PTSession
from prompt_toolkit.completion import (
    Completer,
    CompleteEvent,
    Completion,
    WordCompleter,
    NestedCompleter,
    merge_completers,
    PathCompleter,
)
from prompt_toolkit.document import Document
from prompt_toolkit.history import FileHistory
from prompt_toolkit.styles import Style


def cut_document(document: Document, last_part: str) -> Document:
    left, right = document.text_before_cursor.rsplit(last_part, 1)
    right_stripped = right.lstrip()
    return Document(
        right_stripped,
        cursor_position=document.cursor_position
        - len(left)
        - len(last_part)
        - (len(right) - len(right_stripped)),
    )


@dataclass
class OptionParameterInfo:
    name: Optional[str]
    expects_value: bool = False
    possible_values: List[str] = field(default_factory=list)
    can_occur_multiple_times: bool = False
    value_hint: Optional[str] = None
    help_text: Optional[str] = None
    completer: Optional[Completer] = None

    def __post_init__(self) -> None:
        if not self.expects_value:
            self.completer = None
        if self.possible_values:
            hp = (
                {p: f"{p}: ({self.help_text})" for p in self.possible_values}
                if self.help_text
                else None
            )
            self.completer = WordCompleter(
                self.possible_values, display_dict=hp, WORD=True
            )
        elif self.value_hint == "file":
            self.completer = PathCompleter()
        elif self.help_text:
            self.completer = ExampleCompleter(self.help_text)


SubCommands = Dict[str, Union["SubCommands", List[OptionParameterInfo]]]


@dataclass
class CommandInfo:
    name: str
    options: List[OptionParameterInfo] = field(default_factory=list)
    sub_commands: SubCommands = field(default_factory=dict)
    source: bool = True
    completer: Optional[Completer] = None

    def __post_init__(self) -> None:
        assert self.options != self.sub_commands
        if self.options:
            self.completer = OptionParamCompleter(*self.options)

        def walk_commands(sub_commands: SubCommands) -> Completer:
            return NestedCompleter.from_nested_dict(
                {
                    sub_cmd: OptionParamCompleter(*options)
                    if isinstance(options, list)
                    else walk_commands(options)
                    for sub_cmd, options in sub_commands.items()
                }
            )

        if self.sub_commands:
            self.completer = walk_commands(self.sub_commands)


class ExampleCompleter(Completer):
    def __init__(self, *examples: str):
        self.examples = examples

    def get_completions(
        self, document: Document, complete_event: CompleteEvent
    ) -> Iterable[Completion]:
        # only provide one example
        if document.text_before_cursor == "":
            for example in self.examples:
                yield Completion(" ", start_position=0, display=example)


class OptionParamCompleter(Completer):
    def __init__(self, *params: OptionParameterInfo):
        direct, opts = [], []
        for x in params:
            (direct if x.name is None else opts).append(x)

        self.params: Dict[str, OptionParameterInfo] = {
            param.name: param for param in opts
        }

        # this completer completes new options as well as direct values
        self.completer = merge_completers(
            [
                WordCompleter(list(self.params.keys()), WORD=True),
                *[a.completer for a in direct],
            ]
        )
        self.value_lookup: Dict[str, OptionParameterInfo] = {
            v: a for a in params for v in a.possible_values
        }

    def inside_option(self, parts: List[str]) -> Optional[OptionParameterInfo]:
        for idx, part in enumerate(reversed(parts)):
            if (parm := self.params.get(part)) is not None:
                return parm if parm.expects_value and idx < 2 else None

    def get_completions(
        self, document: Document, complete_event: CompleteEvent
    ) -> Iterable[Completion]:
        parts = document.text_before_cursor.strip().split()
        maybe = self.inside_option(parts)
        if maybe is None:

            def allowed(completion: Completion) -> bool:
                txt = completion.text
                # has this parameter been specified before?
                if (
                    txt in parts
                    and txt in self.params
                    and not self.params[txt].can_occur_multiple_times
                ):
                    return False
                # is this a possible value, where another value is already defined?
                if txt in self.value_lookup:
                    return not any(
                        v for v in self.value_lookup[txt].possible_values if v in parts
                    )
                # if we come here: this is a valid completion
                return True

            return filter(
                allowed, self.completer.get_completions(document, complete_event)
            )
        else:
            # suggest the option values
            doc = cut_document(document, maybe.name)
            return maybe.completer.get_completions(doc, complete_event)


class ResotoCompleter(Completer):
    def __init__(self, *commands: CommandInfo):
        self.commands: Dict[str, CommandInfo] = {
            command.name: command for command in commands
        }
        self.source_completer = WordCompleter(
            [c.name for c in commands if c.source], WORD=True
        )
        self.flow_completer = WordCompleter(
            [c.name for c in commands if not c.source], WORD=True
        )

    def find_current_command(self, document: Document) -> Optional[CommandInfo]:
        parts = document.text_before_cursor.strip().split()
        for part in reversed(parts):
            if (command := self.commands.get(part)) is not None:
                return command

    def get_completions(
        self, document: Document, complete_event: CompleteEvent
    ) -> Iterable[Completion]:
        text = document.text_before_cursor.lstrip()

        adapted = document
        if ";" in text:
            left, right = document.text.rsplit(";", 1)
            adapted = Document(right, document.cursor_position - len(left) - 1)
        elif "|" in text:
            left, right = document.text.rsplit("|", 1)
            adapted = Document(right, document.cursor_position - len(left) - 1)

        if not text.endswith((";", "|")):  # enforce a space after ; or |
            maybe = self.find_current_command(adapted)
            if maybe is not None:
                doc = cut_document(document, maybe.name)
                return maybe.completer.get_completions(doc, complete_event)
            elif ";" in text or "|" in text:
                return self.flow_completer.get_completions(adapted, complete_event)
            else:
                return self.source_completer.get_completions(adapted, complete_event)


known_commands = [
    CommandInfo("aggregate", source=False),
    CommandInfo(
        "ancestors",
        options=[
            OptionParameterInfo("--with-origin"),
            OptionParameterInfo(
                None, True, ["default", "delete"], help_text="edge type"
            ),
        ],
        source=False,
    ),
    CommandInfo(
        "certificate",
        sub_commands={
            "create": [
                OptionParameterInfo(
                    "--common-name", True, help_text="Common name like: example.com"
                ),
                OptionParameterInfo(
                    "--dns-names",
                    True,
                    help_text="List of other dns names: example.org example.io",
                ),
                OptionParameterInfo(
                    "--ip-addresses",
                    True,
                    help_text="List of ip addresses: 1.2.3.4 2.3.4.5",
                ),
            ],
            "delete": [],
        },
    ),
    CommandInfo(
        "configs",
        sub_commands={
            "list": [],
            "set": [
                OptionParameterInfo(
                    None, expects_value=True, help_text="<config_id> <key>=<value>"
                ),
            ],
            "show": [
                OptionParameterInfo(
                    None, expects_value=True, help_text="<config_id> e.g. resoto.core"
                )
            ],
            "edit": [
                OptionParameterInfo(
                    None, expects_value=True, help_text="<config_id> <key>=<value>"
                ),
            ],
            "update": [
                OptionParameterInfo(
                    None,
                    expects_value=True,
                    help_text="<config_id> /path/to/config.yaml",
                ),
            ],
            "delete": [
                OptionParameterInfo(
                    None, expects_value=True, help_text="<config_id> <key>=<value>"
                ),
            ],
        },
    ),
    CommandInfo(
        "chunk",
        [
            OptionParameterInfo(
                None, expects_value=True, help_text="number of elements in the chunk"
            )
        ],
        source=False,
    ),
    CommandInfo(
        "clean",
        [
            OptionParameterInfo(
                None, expects_value=True, help_text="optional reason for cleaning"
            )
        ],
        source=False,
    ),
    CommandInfo(
        "count",
        [
            OptionParameterInfo(
                None, expects_value=True, help_text="optional property to count"
            )
        ],
        source=False,
    ),
    CommandInfo(
        "descendants",
        options=[
            OptionParameterInfo("--with-origin"),
            OptionParameterInfo(
                None, True, ["default", "delete"], help_text="edge type"
            ),
        ],
        source=False,
    ),
    CommandInfo("dump", source=False),
    CommandInfo(
        "echo",
        [OptionParameterInfo(None, expects_value=True, help_text="the text to echo")],
    ),
    CommandInfo("env"),
    CommandInfo("flatten", source=False),
    CommandInfo(
        "format",
        [
            OptionParameterInfo(
                None,
                possible_values=[
                    "--json",
                    "--ndjson",
                    "--text",
                    "--cytoscape",
                    "--graphml",
                    "--dot",
                ],
            ),
            OptionParameterInfo(
                None,
                expects_value=True,
                help_text="format definition with {} placeholders.",
            ),
        ],
        source=False,
    ),
    CommandInfo(
        "head",
        options=[
            OptionParameterInfo(
                None, True, help_text="the number of elements to return. e.g. -10"
            ),
        ],
        source=False,
    ),
    CommandInfo(
        "http",
        [
            OptionParameterInfo("--compress"),
            OptionParameterInfo("--timeout", expects_value=True),
            OptionParameterInfo("--no-ssl-verify"),
            OptionParameterInfo("--no-body"),
            OptionParameterInfo("--nr-of-retries", expects_value=True),
            OptionParameterInfo(
                None,
                expects_value=True,
                help_text="<method> <url> <headers> <query_params>",
            ),
        ],
        source=False,
    ),
    CommandInfo(
        "jobs",
        sub_commands={
            "add": [
                OptionParameterInfo("--id", expects_value=True),
                OptionParameterInfo("--schedule", expects_value=True),
                OptionParameterInfo("--wait-for-event", expects_value=True),
                OptionParameterInfo("--timeout", expects_value=True),
                OptionParameterInfo(None, help_text="<command> to run"),
            ],
            "show": [
                OptionParameterInfo(None, help_text="<job-id>"),
            ],
            "list": [],
            "update": [
                OptionParameterInfo(None, help_text="<job-id>"),
                OptionParameterInfo("--schedule", expects_value=True),
                OptionParameterInfo("--wait-for-event", expects_value=True),
            ],
            "delete": [
                OptionParameterInfo(None, help_text="<job-id>"),
            ],
            "activate": [
                OptionParameterInfo(None, help_text="<job-id>"),
            ],
            "deactivate": [
                OptionParameterInfo(None, help_text="<job-id>"),
            ],
            "run": [
                OptionParameterInfo(None, help_text="<job-id>"),
            ],
            "running": [],
        },
    ),
    CommandInfo(
        "json",
        [
            OptionParameterInfo(None, expects_value=True, help_text="json expression."),
        ],
    ),
    CommandInfo(
        "jq",
        [
            OptionParameterInfo("--no-rewrite"),
            OptionParameterInfo(None, expects_value=True, help_text="the text to echo"),
        ],
        source=False,
    ),
    CommandInfo(
        "kinds",
        [
            OptionParameterInfo("-p", expects_value=True),
            OptionParameterInfo(
                None, expects_value=True, help_text="the name of the kind"
            ),
        ],
    ),
    CommandInfo(
        "list",
        [
            OptionParameterInfo(
                None, possible_values=["--csv", "--markdown"], help_text="format"
            ),
            OptionParameterInfo(
                None,
                expects_value=True,
                help_text="the list of properties, comma separated",
            ),
        ],
        source=False,
    ),
    CommandInfo(
        "predecessors",
        options=[
            OptionParameterInfo("--with-origin"),
            OptionParameterInfo(
                None, True, ["default", "delete"], help_text="edge type"
            ),
        ],
        source=False,
    ),
    CommandInfo("protect", source=False),
    CommandInfo("search"),
    CommandInfo(
        "set_desired",
        options=[
            OptionParameterInfo(None, True, help_text="<prop>=<value>"),
        ],
        source=False,
    ),
    CommandInfo(
        "set_metadata",
        options=[
            OptionParameterInfo(None, True, help_text="<prop>=<value>"),
        ],
        source=False,
    ),
    CommandInfo(
        "sleep",
        options=[
            OptionParameterInfo(None, True, help_text="time to sleep in seconds"),
        ],
    ),
    CommandInfo(
        "successors",
        options=[
            OptionParameterInfo("--with-origin"),
            OptionParameterInfo(
                None, True, ["default", "delete"], help_text="edge type"
            ),
        ],
        source=False,
    ),
    CommandInfo(
        "system",
        sub_commands={
            "backup": {
                "create": [
                    OptionParameterInfo(
                        None,
                        expects_value=True,
                        help_text="The name of the backup file.",
                        value_hint="file",
                    ),
                ],
                "restore": [
                    OptionParameterInfo(
                        None,
                        expects_value=True,
                        help_text="The name of the local backup file to upload.",
                        value_hint="file",
                    ),
                ],
            },
            "info": [],
        },
    ),
    CommandInfo(
        "tag",
        sub_commands={
            "update": [
                OptionParameterInfo("--nowait"),
                OptionParameterInfo(
                    None,
                    expects_value=True,
                    help_text="<tag-name> <tag-value>",
                ),
            ],
            "delete": [
                OptionParameterInfo("--nowait"),
                OptionParameterInfo(
                    None,
                    expects_value=True,
                    help_text="<tag-name>",
                ),
            ],
        },
        source=False,
    ),
    CommandInfo(
        "tail",
        options=[
            OptionParameterInfo(
                None, True, help_text="the number of elements to return. e.g. -10"
            ),
        ],
        source=False,
    ),
    CommandInfo(
        "templates",
        sub_commands={
            "add": [
                OptionParameterInfo(
                    None,
                    expects_value=True,
                    help_text="<name> <template>",
                ),
            ],
            "delete": [
                OptionParameterInfo(
                    None,
                    expects_value=True,
                    help_text="<name>",
                ),
            ],
            "test": [
                OptionParameterInfo(
                    None,
                    expects_value=True,
                    help_text="<key1>=<value1>, ..., <keyN>=<valueN> <template>",
                ),
            ],
            "update": [
                OptionParameterInfo(
                    None,
                    expects_value=True,
                    help_text="<name> <template>",
                ),
            ],
        },
    ),
    CommandInfo("unique", source=False),
    CommandInfo(
        "workflows",
        sub_commands={
            "show": [
                OptionParameterInfo(None, help_text="<workflow-id>"),
            ],
            "list": [],
            "run": [
                OptionParameterInfo(None, help_text="<workflow-id>"),
            ],
            "running": [],
        },
    ),
    CommandInfo(
        "write",
        [
            OptionParameterInfo(
                None, value_hint="file", help_text="<filename> to write to"
            )
        ],
        source=False,
    ),
]


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
        self, history_file: str = str(pathlib.Path.home() / ".resotoshell_history")
    ):
        history = FileHistory(history_file)
        self.completer = ResotoCompleter(*known_commands)
        self.session = PTSession(history=history)

    def prompt(self) -> str:
        try:
            return self.session.prompt(
                self.prompt_message,
                completer=self.completer,
                complete_while_typing=True,
                style=self.style,
                # auto_suggest=AutoSuggestFromHistory(),
            )
        except (TypeError, AttributeError) as ex:
            raise KeyboardInterrupt from ex
