import threading
import inspect
import re
import pathlib
import ast
import time
import calendar
import yaml
from cklib.logging import log
from typing import Iterable, Tuple, Any, List
from collections import deque
from itertools import islice
from functools import lru_cache, partial

try:
    from tzlocal import get_localzone
except ImportError:
    pass
from datetime import datetime, timedelta, timezone, date
from distutils.util import strtobool
from collections import defaultdict
from prompt_toolkit import PromptSession
from prompt_toolkit.history import FileHistory
from prompt_toolkit.completion import WordCompleter
from prompt_toolkit.shortcuts import button_dialog
from cklib.baseresources import BaseResource
from cklib.pluginloader import PluginLoader, PluginType
from cklib.graph import (
    Graph,
    GraphContainer,
    graph2pickle,
)
from cklib.args import ArgumentParser
from cklib.event import (
    dispatch_event,
    Event,
    EventType,
    add_event_listener,
    list_event_listeners,
)
from cklib.utils import (
    parse_delta,
    make_valid_timestamp,
    split_esc,
    fmt_json,
    resource2dict,
)
from cklib.cleaner import Cleaner


class Cli(threading.Thread):
    """The cloudkeeper CLI"""

    def __init__(self, gc: GraphContainer, scheduler) -> None:
        super().__init__()
        self.name = "cli"
        self.exit = threading.Event()
        self.gc = gc
        self.scheduler = scheduler
        self.__run = not ArgumentParser.args.no_cli
        self.clipboard = Clipboard()

        for action in ArgumentParser.args.cli_actions:
            register_cli_action(action)

        read_cli_actions_config()
        add_event_listener(EventType.SHUTDOWN, self.shutdown)

    def run(self) -> None:
        session = completer = None
        if self.__run:
            history = None
            if ArgumentParser.args.cli_history:
                history = FileHistory(ArgumentParser.args.cli_history)
            session = PromptSession(history=history)
            completer = WordCompleter(
                CliHandler(self.gc.graph, clipboard=self.clipboard).valid_commands
            )

        while self.__run:
            try:
                cli_input = session.prompt("> ", completer=completer)
                if cli_input == "":
                    continue

                ch = CliHandler(
                    self.gc.graph, scheduler=self.scheduler, clipboard=self.clipboard
                )
                for item in ch.evaluate_cli_input(cli_input):
                    print(item)

            except KeyboardInterrupt:
                pass
            except EOFError:
                CliHandler.quit("Keyboard Shutdown")
            except (RuntimeError, ValueError) as e:
                log.error(e)
            except Exception:
                log.exception("Caught unhandled exception while processing CLI command")
        self.exit.wait()

    def shutdown(self, event: Event) -> None:
        log.debug(f"Received signal to shut down cli thread {event.event_type}")
        self.__run = False
        self.exit.set()

    @staticmethod
    def add_args(arg_parser: ArgumentParser) -> None:
        arg_parser.add_argument(
            "--no-cli",
            help="Don't run the CLI thread",
            dest="no_cli",
            action="store_true",
            default=False,
        )
        arg_parser.add_argument(
            "--register-cli-action",
            help="Register a CLI Action (Format: event:command)",
            dest="cli_actions",
            type=str,
            default=[],
            nargs="+",
        )
        arg_parser.add_argument(
            "--cli-actions-config",
            help="Path to CLI Actions config",
            dest="cli_actions_config",
            type=str,
            default=None,
        )
        default_history_file = pathlib.Path.home() / ".cloudkeeper_history"
        cli_history_default = None
        if default_history_file.exists():
            cli_history_default = str(default_history_file)
        arg_parser.add_argument(
            "--cli-history",
            help=(
                "Path to CLI history file"
                " (default: None or ~/.cloudkeeper_history if exists)"
            ),
            dest="cli_history",
            type=str,
            default=cli_history_default,
        )


class Clipboard:
    def __init__(self) -> None:
        self.__data = []

    def clear(self):
        self.data = []

    @property
    def data(self) -> List:
        return self.__data

    @data.setter
    def data(self, value) -> None:
        self.__data = value


class CliHandler:
    def __init__(
        self, graph: Graph, scheduler=None, clipboard: Clipboard = None
    ) -> None:
        self.graph = graph
        self.scheduler = scheduler
        self.commands = {}
        cli_plugins = [
            Plugin(graph, scheduler, clipboard)
            for Plugin in PluginLoader().plugins(PluginType.CLI)
        ]

        for f, m in inspect.getmembers(self, predicate=inspect.ismethod):
            if f.startswith("cmd_"):
                self.commands[f[4:]] = m

        for cli_plugin in cli_plugins:
            for f, m in inspect.getmembers(cli_plugin, predicate=inspect.ismethod):
                if f.startswith("cmd_"):
                    self.commands[f[4:]] = m

        self.valid_commands = sorted(self.commands.keys())
        if clipboard is None:
            clipboard = Clipboard()
        self.clipboard = clipboard

    def evaluate_cli_input(self, cli_input: str) -> Iterable:
        cli_input = replace_placeholder(cli_input)
        for cmd_chain in split_esc(cli_input, ";"):
            cmds = (cmd.strip() for cmd in split_esc(cmd_chain, "|"))
            with self.graph.lock.read_access:
                items = self.graph.nodes()
                for cmd in cmds:
                    args = ""
                    if " " in cmd:
                        cmd, args = cmd.split(" ", 1)
                    if cmd in self.commands:
                        items = self.commands[cmd](items, args)
                    else:
                        items = (f"Unknown command: {cmd}",)
                        break
                for item in items:
                    yield item

    @staticmethod
    def quit(reason=None):
        dispatch_event(
            Event(EventType.SHUTDOWN, {"reason": reason, "emergency": False})
        )

    match_actions = {
        ">": lambda x, y: x > y,
        "<": lambda x, y: x < y,
        "=": lambda x, y: x == y,
        "~": lambda x, y: bool(re.search(str(y), str(x))),
        "has": lambda x, y: y in x,
    }

    def cmd_match(self, items: Iterable, args: str) -> Iterable:
        """Usage: | match [not] <attribute> <operator> <value> |

        Matches resources whose attribute matches a value.

        Valid operators are:
          > greather than
          < less than
          = equal to
          ~ regex match
          has value is contained in attribute
        """
        attr, action, value = None, None, None
        negate_match = False
        if args.startswith("not "):
            negate_match = True
            args = args[4:]
        for action in self.match_actions.keys():
            if action in args:
                pos = args.index(action)
                if pos == 0 or pos == len(args) - 1:
                    raise RuntimeError(
                        f"Can't have {action} at the beginning or end of match"
                    )
                attr, value = args.split(action, 1)
                attr = attr.strip()
                value = value.strip()
                break

        if not attr or not action or not value:
            raise RuntimeError(f"Invalid match {args}")

        for item in items:
            item_attr = self.get_item_attr(item, attr)
            if item_attr is None:
                continue
            # We convert value for every resource even though
            # chances are that types for same attributes are the
            # same across all resource types.
            match_item_attr = item_attr
            match_value = value
            if isinstance(item_attr, timedelta):
                match_value = parse_delta(value)
            elif isinstance(item_attr, datetime):
                match_value = make_valid_timestamp(datetime.fromisoformat(value))
            elif isinstance(item_attr, bool):
                match_value = strtobool(value)
            elif isinstance(item_attr, int):
                if str(value).isnumeric():
                    match_value = int(value)
                else:
                    match_item_attr, match_value = str(item_attr), str(value)
            elif isinstance(item_attr, float):
                if not bool(re.search("[^0-9.]", str(value))):
                    match_value = float(value)
                else:
                    match_item_attr, match_value = str(item_attr), str(value)
            elif isinstance(item_attr, complex):
                if not bool(re.search("[^0-9.]", str(value))):
                    match_value = complex(value)
                else:
                    match_item_attr, match_value = str(item_attr), str(value)

            if (
                not negate_match
                and self.match_actions[action](match_item_attr, match_value)
            ) or (
                negate_match
                and not self.match_actions[action](match_item_attr, match_value)
            ):
                yield item

    def cmd_grep(self, items: Iterable, args: str) -> Iterable:
        """Usage: | grep <str> |

        Grep <str> in the input strings.
        """
        if len(args) == 0:
            raise RuntimeError("grep requires an argument")

        for item in items:
            if args in str(item):
                yield item

    def cmd_quit(self, items: Iterable, args: str) -> Iterable:
        """Usage: quit

        Quit cloudkeeper.
        """
        self.quit("Shutdown requested by CLI input")
        return ()

    def cmd_clipboard(self, items: Iterable, args: str) -> Iterable:
        """Usage: | clipboard <copy|append|paste|clear> [passthrough] |

        Copy/paste input to/from CLI clipboard.
        Optional `passthrough` arg will pass any input items through
        to the next CLI command.
        """
        cmd = args
        arg = None
        if " " in args:
            cmd, arg = args.split(" ", 1)

        if cmd in ("copy", "append"):
            if cmd == "copy":
                self.clipboard.clear()
            for item in items:
                self.clipboard.data.append(item)
                if arg == "passthrough":
                    yield item
        elif cmd == "paste":
            yield from self.clipboard.data
            if arg == "passthrough":
                yield from items
        elif cmd == "clear":
            self.clipboard.clear()
            if arg == "passthrough":
                yield from items
        else:
            yield "Unknown clipboard command. See `help clipboard`."

    def cmd_collect(self, items: Iterable, args: str) -> Iterable:
        """Usage: collect

        Perform a collect run.
        """
        dispatch_event(Event(EventType.START_COLLECT))
        return ()

    def cmd_delete(self, items: Iterable, args: str) -> Iterable:
        """Usage: | delete [--yes] |

        Calls the cleanup method on all resources.
        Won't ask for confirmation if --yes is provided.

        WARNING: THIS WILL IMMEDIATELY DELETE ALL INPUT RESOURCES
        """
        for item in items:
            if not isinstance(item, BaseResource):
                raise RuntimeError(
                    f"Item {item} is not a valid resource - deletion failed"
                )
            if args == "--yes":
                confirm_delete = True
            else:
                confirm_delete = button_dialog(
                    title=f"Delete {item.name}",
                    text=f"Really delete {item.name}?",
                    buttons=[("Yes", True), ("No", False), ("Abort", None)],
                ).run()

            if confirm_delete is None:
                break
            elif confirm_delete is True:
                item.pre_cleanup(self.graph)
                item.cleanup(self.graph)
            yield item

    def cmd_dump(self, items: Iterable, args: str) -> Iterable:
        """Usage: | dump [--json] [--private]

        Dumps details about the resources.
        Optionally dump them as one JSON object.
        Beware that dumping large datasets as JSON requires
        the entire dataset to be in memory.

        If --private is given private resource attributes
        (those starting with _) will be included in the dump.
        """
        dump_json = False
        json_out = []
        args = args.split(" ")
        if "--json" in args:
            dump_json = True
        exclude_private = "--private" not in args

        for item in items:
            if not isinstance(item, BaseResource):
                raise RuntimeError(
                    f"Item {item} is not a valid resource - dumping failed"
                )
            out = resource2dict(item, exclude_private, self.graph)
            if dump_json:
                json_out.append(out)
            else:
                yield ("---\n" + yaml.dump(out, Dumper=yaml.Dumper).strip())
        if dump_json:
            yield (fmt_json(json_out))

    def cmd_tag(self, items: Iterable, args: str) -> Iterable:
        """Usage: | tag <update|delete> key [value]

        Sets, updates or deletes a tag.

        WARNING: THIS WILL SET/UPDATE/DELETE A RESOURCE TAG IN THE CLOUD
        """
        cmd = str(args).split(" ", 2)
        if len(cmd) < 2:
            raise RuntimeError("Invalid number of arguments for tag command")
        action = cmd[0]
        key = cmd[1]
        value = None
        if len(cmd) == 3:
            value = cmd[2]
        for item in items:
            if not isinstance(item, BaseResource):
                raise RuntimeError(
                    f"Item {item} is not a valid resource - tag update failed"
                )
            if action == "update" and value is not None:
                item.tags[key] = value
                yield item
            elif action == "delete":
                del item.tags[key]
                yield item
            else:
                raise RuntimeError(f"Invalid tag action {action} or empty value")

    def cmd_count(self, items: Iterable, args: str) -> Iterable:
        """Usage: | count [attribute]

        Counts the number of items.
        Optionally counts by attribute.
        """
        attr = args
        counter = defaultdict(int)
        total = 0
        total_matched = 0
        total_unmatched = 0

        for item in items:
            total += 1
            if attr:
                item_attr = self.get_item_attr(item, attr)
                if item_attr is None:
                    continue
                counter[str(item_attr)] += 1
                total_matched += 1
        total_unmatched = total - total_matched
        for attribute, count in sorted(counter.items(), key=lambda x: x[1]):
            yield f"{attribute}: {count}"

        if attr:
            yield f"total matched: {total_matched}"
            yield f"total unmatched: {total_unmatched}"
        yield f"total: {total}"

    def cmd_tail(self, items: Iterable, args: str) -> Iterable:
        """Usage: | tail <num> |

        Returns the last num lines.
        """
        num = int(args) if len(args) > 0 else 10
        if num < 0:
            num *= -1
        return deque(items, num)

    def cmd_head(self, items: Iterable, args: str) -> Iterable:
        """Usage: | head <num> |

        Returns the first num lines.
        """
        num = int(args) if len(args) > 0 else 10
        if num < 0:
            num *= -1
        return islice(items, num)

    def cmd_help(self, items: Iterable, args: str) -> Iterable:
        """Usage: help <command>

        Show help text for a command.
        """
        extra_doc = ""
        if args == "":
            args = "help"
            valid_commands = "\n    ".join(self.valid_commands)
            placeholder_help = inspect.getdoc(replace_placeholder)
            extra_doc = f"""\n
{placeholder_help}

Valid commands are:
    {valid_commands}

Note that you can pipe commands using the pipe character (|)
and chain multipe commands using the semicolon (;).
            """
        if args in self.commands:
            doc = inspect.getdoc(self.commands[args])
            if doc is None:
                doc = f"Command {args} has no help text."
        else:
            doc = f"Unknown command: {args}"
        doc += extra_doc
        return (doc,)

    def cmd_predecessors(self, items: Iterable, args: str) -> Iterable:
        """Usage: | predecessors [--with-origin] |

        List a resource's predecessors in the graph.
        Predecessors are a resource's parents.

        If --with-origin is specified the origin resource(s) will also be output.
        """
        return self.relatives(items, "predecessors", args)

    def cmd_successors(self, items: Iterable, args: str) -> Iterable:
        """Usage: | successors [--with-origin] |

        List a resource's successors in the graph.
        Successors are a resource's children.

        If --with-origin is specified the origin resource(s) will also be output.
        """
        return self.relatives(items, "successors", args)

    def cmd_ancestors(self, items: Iterable, args: str) -> Iterable:
        """Usage: | ancestors [--with-origin] |

        List a resource's ancestors in the graph.
        Ancestors are a resource's parents and their parents
        and their parents and so on.

        If --with-origin is specified the origin resource(s) will also be output.
        """
        return self.relatives(items, "ancestors", args)

    def cmd_descendants(self, items: Iterable, args: str) -> Iterable:
        """Usage: | descendants [--with-origin] |

        List a resource's descendants in the graph.
        Descendants are a resource's children and their children
        and their children and so on.

        If --with-origin is specified the origin resource(s) will also be output.
        """
        return self.relatives(items, "descendants", args)

    def relatives(self, nodes: Iterable, group: str, args: str) -> Iterable:
        """Return a group of relatives for any given list of nodes"""
        output_origin_node = args == "--with-origin"

        for node in nodes:
            if output_origin_node:
                yield node
            if not isinstance(node, BaseResource):
                raise RuntimeError(f"Node {node} is not a valid resource")
            yield from getattr(node, group)(self.graph)

    def cmd_tee(self, items: Iterable, args: str) -> Iterable:
        """Usage: | tee [-a] <filename> |

        Write input to file.
        Optionally use -a to append to filename.
        """
        mode = "w"
        filename = args
        if args.startswith("-a "):
            mode = "a"
            _, filename = args.split(" ", 1)

        with open(filename, mode) as outfile:
            for item in items:
                outfile.write(f"{item}\n")
                yield item

    def cmd_format(self, items: Iterable, args: str) -> Iterable:
        """Usage: | format "{attr}: {attr.name}" |

        String format the output.
        Any resource attribute returned in the dump output can be used.
        If a resource is missing a referenced attribute an empty string will
        be printed instead.

        Example:
            > match kind = gcp_instance |
              format {name} {instance_cores} {instance_memory/1024}

        See
            https://docs.python.org/3.8/library/string.html#formatspec
        for more on the Python Format Specification Mini-Language.
        """
        for item in items:
            if not isinstance(item, BaseResource):
                raise RuntimeError(
                    f"Item {item} is not a valid resource - dumping failed"
                )
            fmt = defaultdict(str)
            out = resource2dict(item, exclude_private=False, graph=self.graph)
            out["resource"] = item
            fmt.update(out)
            fmt_item = args.format_map(fmt)
            yield fmt_item

    def cmd_write(self, items: Iterable, args: str) -> Iterable:
        """Usage: | write [-a] <filename>

        Write input to file.
        Optionally use -a to append to filename.
        """
        i = 0
        mode = "w"
        str_mode = "Writing"
        filename = args
        if args.startswith("-a "):
            mode = "a"
            str_mode = "Appending"
            _, filename = args.split(" ", 1)

        with open(filename, mode) as outfile:
            yield f"{str_mode} data to {filename}."
            for item in items:
                outfile.write(f"{item}\n")
                i += 1
        yield f"Write of {i} item{'' if i == 1 else 's'} complete."

    def cmd_sort(self, items: Iterable, args: str, reverse: bool = False) -> Iterable:
        """Usage: | sort [attribute] |

        Sort input alphabetically.
        Optionally sort by attribute.
        """
        attr = args

        def getsortkey(item):
            if len(attr) == 0:
                return item
            attr_value = self.get_item_attr(item, attr)
            if attr_value is None:
                raise ValueError(f"Item {item} has no attribute {attr}")
            return attr_value

        yield from sorted(list(items), key=getsortkey, reverse=reverse)

    def cmd_rsort(self, items: Iterable, args: str, reverse: bool = False) -> Iterable:
        """Usage: | rsort [attribute] |

        Sort input alphabetically in reverse order.
        Optionally sort by attribute.
        """
        return self.cmd_sort(items, args, reverse=True)

    def cmd_backup(self, items: Iterable, args: str) -> Iterable:
        """Usage: backup <filename>

        Create a backup of the graph.
        """
        filename = args
        with open(filename, "wb") as outfile:
            yield (f"Writing Graph backup to {filename}")
            outfile.write(graph2pickle(self.graph))
        yield ("done")

    def cmd_clean(self, items: Iterable, args: str) -> Iterable:
        """Usage: | clean |

        Flag a resource for cleaning.

        WARNING: THIS WILL FLAG RESOURCES FOR CLEANUP (DELAYED DELETION)
        """
        for item in items:
            if not isinstance(item, BaseResource):
                raise RuntimeError(
                    f"Item {item} is not a valid resource - cleanup flagging failed"
                )
            item.clean = True
            yield item

    def cmd_set(self, items: Iterable, args: str) -> Iterable:
        """Usage: | set <attribute> <value> |

        Set an attribute to a value.
        Only returns items whose attribute was successfully modified.
        """
        attribute, value = args.split(" ", 1)
        for item in items:
            if not isinstance(item, BaseResource):
                raise RuntimeError(
                    f"Item {item} is not a valid resource - setting attribute failed"
                )
            if hasattr(item, attribute):
                type_attr = type(getattr(item, attribute))
                try:
                    converted = type_attr(ast.literal_eval(value))
                except ValueError:
                    log.exception(
                        (
                            "An error occurred when trying to cast value"
                            f" '{value}' to {type_attr}"
                        )
                    )
                else:
                    setattr(item, attribute, converted)
                    yield item

    def cmd_protect(self, items: Iterable, args: str) -> Iterable:
        """Usage: | protect |

        Burn a resource's protection fuse so it won't be deleted
        or otherwise modified in the future.

        WARNING: THIS WILL ONLY PROTECT RESOURCES IN YOUR LOCAL INSTANCE OF THE GRAPH
        """
        for item in items:
            if not isinstance(item, BaseResource):
                raise RuntimeError(
                    f"Item {item} is not a valid resource - can't burn protection fuse"
                )
            item.protected = True
            yield item

    def cmd_cleanup(self, items: Iterable, args: str) -> Iterable:
        """Usage: cleanup

        Perform a resource cleanup.

        WARNING: THIS WILL IMMEDIATELY DELETE ALL RESOURCES FLAGGED FOR CLEANUP
        """
        yield "Beginning cleanup"
        resource_cleaner = Cleaner(self.graph)
        resource_cleaner.cleanup()
        yield "Cleanup finished"

    def cmd_print(self, items: Iterable, args: str) -> Iterable:
        """Usage: | print [attribute] |

        Prints all input items.
        Optionally print an input items attribute.
        """
        for item in items:
            if args and isinstance(item, BaseResource):
                item_attr = self.get_item_attr(item, args)
                if item_attr is None:
                    continue
                print(item_attr)
                yield item
            else:
                print(item)
                yield item

    def cmd_log(self, items: Iterable, args: str) -> Iterable:
        """Usage: | log [loglevel] |

        Send input to logger.
        """
        log_level = args if len(args) > 0 else "info"
        logger = getattr(log, log_level, None)
        if logger is None or not callable(logger):
            raise ValueError(f"Unknown log level: {log_level}")

        for item in items:
            logger(item)
            yield item

    def cmd_uniq(self, items: Iterable, args: str) -> Iterable:
        """Usage: | uniq |

        Deduplicate input.
        """
        seen = {}
        for item in items:
            if seen.get(item) is None:
                seen[item] = True
                yield item

    def cmd_has(self, items: Iterable, args: str) -> Iterable:
        """Usage: | has [not] <attribute> |

        List resources that do or don't have an attribute
        and that attribute has a value.
        """
        attr = args
        negate_match = False
        if attr.startswith("not "):
            negate_match = True
            attr = attr[4:]

        if len(attr) == 0:
            raise RuntimeError("has requires an attribute name")

        for item in items:
            item_attr = self.get_item_attr(item, attr)
            if (not negate_match and item_attr is not None) or (
                negate_match and item_attr is None
            ):
                yield item

    def cmd_sleep(self, items: Iterable, args: str) -> Iterable:
        """Usage: | sleep [pipe] <seconds> |

        Sleep for the specified number of seconds.
        If pipe is specified sleep will pipe through all input items.
        """
        pipe = False
        if args.startswith("pipe "):
            pipe = True
            args = args[5:]

        seconds = args
        if len(seconds) == 0 or bool(re.search("[^0-9.]", str(seconds))):
            raise ValueError("invalid number of seconds")

        seconds = float(seconds)
        time.sleep(seconds)

        if pipe:
            yield from items

    def cmd_register(self, items: Iterable, args: str) -> Iterable:
        """Usage: register <event>:<cli command>

        Register a CLI command with an event.
        """
        if len(args) == 0:
            yield "register takes an event and cli command as argument"
        else:
            yield "Registering CLI action"
            if register_cli_action(args):
                yield "success"
            else:
                yield "failed"

    def cmd_date(self, items: Iterable, args: str) -> Iterable:
        """Usage: date

        Show the current date and time in iso format.
        """
        tz = get_localzone()
        yield tz.localize(datetime.now()).isoformat()

    def cmd_utcdate(self, items: Iterable, args: str) -> Iterable:
        """Usage: utcdate

        Show the current UTC date and time in iso format.
        """
        yield datetime.utcnow().replace(tzinfo=timezone.utc).isoformat()

    def cmd_echo(self, items: Iterable, args: str) -> Iterable:
        """Usage: echo [string]

        Echo a string to the console.

        Can be used for testing string substitution.
        E.g. echo @TODAY@
        """
        yield args

    def cmd_listeners(self, items: Iterable, args: str) -> Iterable:
        """Usage: listeners

        List all registered event listeners.
        """
        yield from list_event_listeners()

    def cmd_jobs(self, items: Iterable, args: str) -> Iterable:
        """Usage: jobs

        Return a list of scheduled jobs
        """
        if self.scheduler is None:
            raise RuntimeError("No scheduler given")
        yield from self.scheduler.get_jobs()

    def cmd_add_job(self, items: Iterable, args: str) -> Iterable:
        """Usage: add_job <schedule> [event]:<cli command>

        Add a scheduled job in cron format.
            field          allowed values
            -----          --------------
            minute         0–59
            hour           0–23
            day of month   1–31
            month          1–12
            day of week    0-6 or mon,tue,wed,thu,fri,sat,sun

        Example:
            Count EC2 Instances every three hours
            > add_job 0 */3 * * * match kind = aws_ec2_instance \\| count
        """
        if self.scheduler is None:
            raise RuntimeError("No scheduler given")
        job = self.scheduler.add_job(args)
        yield f"job id: {job.id}"

    def cmd_remove_job(self, items: Iterable, args: str) -> Iterable:
        """Usage: remove_job <job-id>

        Remove a scheduled job.
        """
        if self.scheduler is None:
            raise RuntimeError("No scheduler given")

        if len(args) == 0:
            yield "remove_job takes a job id as argument"
        else:
            if self.scheduler.remove_job(args):
                yield "success"
            else:
                yield "failed"

    def get_item_attr(self, item: BaseResource, attr: str) -> Any:
        return_length = False
        if attr.startswith("len:"):
            return_length = True
            attr = attr[4:]
        attr, attr_key, attr_attr = get_attr_key(attr)
        item_attr = getattr(item, attr, None)

        if (
            attr
            in (
                "cloud",
                "account",
                "region",
                "zone",
                "location",
            )
            and callable(item_attr)
        ):
            item_attr = item_attr(self.graph)
        elif (
            attr
            in (
                "predecessors",
                "successors",
                "ancestors",
                "descendants",
            )
            and callable(item_attr)
        ):
            item_attr = list(item_attr(self.graph))
        if item_attr is not None and not callable(item_attr):
            if attr_key is not None and isinstance(item_attr, dict):
                item_attr = item_attr.get(attr_key)
            elif (
                attr_key is not None
                and isinstance(item_attr, (list, tuple, set))
                and isint(attr_key)
            ):
                attr_key = int(attr_key)
                if isinstance(item_attr, set):
                    item_attr = tuple(item_attr)
                if (
                    attr_key >= 0
                    and attr_key < len(item_attr)
                    or attr_key < 0
                    and attr_key * -1 <= len(item_attr)
                ):
                    item_attr = item_attr[attr_key]
                else:
                    item_attr = None
        if attr_attr is not None:
            item_attr = self.get_item_attr(item_attr, attr_attr)
        if return_length:
            if isinstance(item_attr, (list, dict, str, tuple, set, bytes, frozenset)):
                item_attr = len(item_attr)
            else:
                item_attr = None
        return item_attr


def isint(s):
    try:
        int(s)
    except ValueError:
        return False
    else:
        return True


@lru_cache()
def get_attr_key(attr: str) -> Tuple:
    attr_key = None
    attr_attr = None
    if "." in attr:
        dot_pos = attr.index(".")
        attr_attr = attr[dot_pos + 1 :]
        attr = attr[:dot_pos]
    if "[" in attr and "]" in attr:
        open_bracket_pos = attr.index("[")
        close_bracket_pos = attr.index("]")
        if open_bracket_pos < close_bracket_pos - 1:
            attr_key = attr[open_bracket_pos + 1 : close_bracket_pos]
            attr = attr[:open_bracket_pos]
    return (attr, attr_key, attr_attr)


def register_cli_action(action: str, one_shot: bool = False) -> bool:
    if ":" not in action:
        log.error(f"Invalid CLI action {action}")
        return False
    event, command = action.split(":", 1)
    event = event.strip()
    command = command.strip()
    if event.startswith("1"):
        one_shot = True
        event = event[1:]
    for e in EventType:
        if event == e.name.lower():
            f = partial(cli_event_handler, command)
            return add_event_listener(e, f, blocking=True, one_shot=one_shot)
    else:
        log.error(f"Invalid event type {event}")
    return False


def read_cli_actions_config(config_file: str = None) -> None:
    if config_file is None:
        if not ArgumentParser.args.cli_actions_config:
            return
        config_file = ArgumentParser.args.cli_actions_config

    log.debug(f"Reading CLI actions configuration file {config_file}")
    try:
        with open(config_file, "r") as fp:
            for line in fp:
                line = line.strip()
                if not line.startswith("#") and len(line) > 0:
                    register_cli_action(line)
    except Exception:
        log.exception(f"Failed to read scheduler configuration file {config_file}")


def cli_event_handler(cli_input: str, event: Event = None, graph: Graph = None) -> None:
    if graph is None and event:
        log.info(
            f"Received event {event.event_type.name}, running command: {cli_input}"
        )
        graph = event.data
    try:
        ch = CliHandler(graph)
        for item in ch.evaluate_cli_input(cli_input):
            log.info(item)
    except (RuntimeError, ValueError) as e:
        log.error(e)
    except Exception:
        log.exception("Caught unhandled exception while processing CLI command")


def replace_placeholder(cli_input: str) -> str:
    """
    Valid placeholder strings in commands are:
        @UTC@       -> '2020-04-21T11:30:22.331346+00:00'
        @NOW@       -> '2020-04-21T13:48:25.420230+02:00'
        @TODAY@     -> '2020-04-21'
        @YEAR@      -> '2020'
        @MONTH@     -> '04'
        @DAY@       -> '21'
        @TIME@      -> '11:47:55'
        @HOUR@      -> '11'
        @MINUTE@    -> '47'
        @SECOND@    -> '55'
        @TZ@        -> 'CEST'
        @TZ_OFFSET@ -> '+0200'
        @MONDAY@    -> '2020-04-27'
        @TUESDAY@   -> '2020-04-21'
        @WEDNESDAY@ -> '2020-04-22'
        @THURSDAY@  -> '2020-04-23'
        @FRIDAY@    -> '2020-04-24'
        @SATURDAY@  -> '2020-04-25'
        @SUNDAY@    -> '2020-04-26'
    """
    t = date.today()
    utc = datetime.utcnow().replace(tzinfo=timezone.utc).isoformat()
    try:
        n = get_localzone().localize(datetime.now())
    except Exception:
        n = utc
    now = n.isoformat()
    today = t.strftime("%Y-%m-%d")
    year = t.strftime("%Y")
    month = t.strftime("%m")
    day = t.strftime("%d")
    time = n.strftime("%H:%M:%S")
    hour = n.strftime("%H")
    minute = n.strftime("%M")
    second = n.strftime("%S")
    tz_offset = n.strftime("%z")
    tz = n.strftime("%Z")
    monday = (t + timedelta((calendar.MONDAY - t.weekday()) % 7)).isoformat()
    tuesday = (t + timedelta((calendar.TUESDAY - t.weekday()) % 7)).isoformat()
    wednesday = (t + timedelta((calendar.WEDNESDAY - t.weekday()) % 7)).isoformat()
    thursday = (t + timedelta((calendar.THURSDAY - t.weekday()) % 7)).isoformat()
    friday = (t + timedelta((calendar.FRIDAY - t.weekday()) % 7)).isoformat()
    saturday = (t + timedelta((calendar.SATURDAY - t.weekday()) % 7)).isoformat()
    sunday = (t + timedelta((calendar.SUNDAY - t.weekday()) % 7)).isoformat()

    cli_input = cli_input.replace("@UTC@", utc)
    cli_input = cli_input.replace("@NOW@", now)
    cli_input = cli_input.replace("@TODAY@", today)
    cli_input = cli_input.replace("@YEAR@", year)
    cli_input = cli_input.replace("@MONTH@", month)
    cli_input = cli_input.replace("@DAY@", day)
    cli_input = cli_input.replace("@TIME@", time)
    cli_input = cli_input.replace("@HOUR@", hour)
    cli_input = cli_input.replace("@MINUTE@", minute)
    cli_input = cli_input.replace("@SECOND@", second)
    cli_input = cli_input.replace("@TZ_OFFSET@", tz_offset)
    cli_input = cli_input.replace("@TZ@", tz)
    cli_input = cli_input.replace("@MONDAY@", monday)
    cli_input = cli_input.replace("@TUESDAY@", tuesday)
    cli_input = cli_input.replace("@WEDNESDAY@", wednesday)
    cli_input = cli_input.replace("@THURSDAY@", thursday)
    cli_input = cli_input.replace("@FRIDAY@", friday)
    cli_input = cli_input.replace("@SATURDAY@", saturday)
    cli_input = cli_input.replace("@SUNDAY@", sunday)

    return cli_input
