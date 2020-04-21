import threading
import logging
import inspect
import re
import time
import calendar
from typing import Iterable, Tuple, Any
from collections import deque
from itertools import islice
from functools import lru_cache, partial
from tzlocal import get_localzone
from datetime import datetime, timedelta, timezone, date
from distutils.util import strtobool
from collections import defaultdict
from prompt_toolkit import PromptSession
from prompt_toolkit.completion import WordCompleter
from prompt_toolkit.shortcuts import button_dialog
from cloudkeeper.baseresources import BaseResource
from cloudkeeper.graph import Graph, GraphContainer, get_resource_attributes, graph2pickle
from cloudkeeper.args import ArgumentParser
from cloudkeeper.event import dispatch_event, Event, EventType, add_event_listener, remove_event_listener
from cloudkeeper.utils import parse_delta, make_valid_timestamp, split_esc
from cloudkeeper.cleaner import Cleaner
from pprint import pformat


log = logging.getLogger(__name__)


class Cli(threading.Thread):
    """The cloudkeeper CLI
    """
    def __init__(self, gc: GraphContainer, scheduler) -> None:
        super().__init__()
        self.name = 'cli'
        self.exit = threading.Event()
        self.gc = gc
        self.scheduler = scheduler
        self.__run = not ArgumentParser.args.no_cli

        for action in ArgumentParser.args.cli_actions:
            register_cli_action(action)

        add_event_listener(EventType.SHUTDOWN, self.shutdown)

    def __del__(self):
        remove_event_listener(EventType.SHUTDOWN, self.shutdown)

    def run(self) -> None:
        if self.__run:
            session = PromptSession()
            completer = WordCompleter(CliHandler(self.gc.graph).valid_commands)

        while self.__run:
            try:
                cli_input = session.prompt('> ', completer=completer)
                if cli_input == '':
                    continue

                ch = CliHandler(self.gc.graph, self.scheduler)
                for item in ch.evaluate_cli_input(cli_input):
                    print(item)

            except KeyboardInterrupt:
                pass
            except EOFError:
                CliHandler.quit('Keyboard Shutdown')
            except (RuntimeError, ValueError) as e:
                log.error(e)
            except Exception:
                log.exception('Caught unhandled exception while processing CLI command')
        self.exit.wait()

    def shutdown(self, event: Event) -> None:
        log.debug(f'Received signal to shut down cli thread {event.event_type}')
        self.__run = False
        self.exit.set()

    @staticmethod
    def add_args(arg_parser: ArgumentParser) -> None:
        arg_parser.add_argument('--no-cli', help="Don't run the CLI thread", dest='no_cli', action='store_true', default=False)
        arg_parser.add_argument('--register-cli-action', help='Register a CLI Action (Format: event:command)', dest='cli_actions', type=str, default=[], nargs='+')


class CliHandler:
    def __init__(self, graph: Graph, scheduler=None) -> None:
        self.graph = graph
        self.scheduler = scheduler
        self.valid_commands = sorted([f[4:] for f, _ in inspect.getmembers(self.__class__, predicate=inspect.isfunction) if f.startswith('cmd_')])

    def evaluate_cli_input(self, cli_input: str) -> Iterable:
        cli_input = replace_placeholder(cli_input)
        for cmd_chain in split_esc(cli_input, ';'):
            cmds = (cmd.strip() for cmd in split_esc(cmd_chain, '|'))
            with self.graph.lock.read_access:
                items = self.graph.nodes()
                for cmd in cmds:
                    args = ''
                    if ' ' in cmd:
                        cmd, args = cmd.split(' ', 1)
                    method = f'cmd_{cmd}'
                    if hasattr(self, method):
                        items = getattr(self, method)(items, args)
                    else:
                        items = (f'Unknown command: {cmd}',)
                        break
                for item in items:
                    yield item

    @staticmethod
    def quit(reason=None):
        dispatch_event(Event(EventType.SHUTDOWN, {'reason': reason, 'emergency': False}))

    match_actions = {
        '>': lambda x, y: x > y,
        '<': lambda x, y: x < y,
        '=': lambda x, y: x == y,
        '~': lambda x, y: bool(re.search(str(y), str(x)))
    }

    def cmd_match(self, items: Iterable, args: str) -> Iterable:
        '''Usage: | match [not] <attribute> <operator> <value>

        Matches resources whose attribute matches a value.

        Valid operators are:
          > greather than
          < less than
          = equal to
          ~ regex match
        '''
        attr, action, value = None, None, None
        negate_match = False
        if args.startswith('not '):
            negate_match = True
            args = args[4:]
        for action in self.match_actions.keys():
            if action in args:
                pos = args.index(action)
                if pos == 0 or pos == len(args) - 1:
                    raise RuntimeError(f"Can't have {action} at the beginning or end of match")
                attr, value = args.split(action, 1)
                attr = attr.strip()
                value = value.strip()
                break

        if not attr or not action or not value:
            raise RuntimeError(f'Invalid match {args}')

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
                if not bool(re.search('[^0-9.]', str(value))):
                    match_value = float(value)
                else:
                    match_item_attr, match_value = str(item_attr), str(value)
            elif isinstance(item_attr, complex):
                if not bool(re.search('[^0-9.]', str(value))):
                    match_value = complex(value)
                else:
                    match_item_attr, match_value = str(item_attr), str(value)

            if (not negate_match and self.match_actions[action](match_item_attr, match_value)) or (
                    negate_match and not self.match_actions[action](match_item_attr, match_value)):
                yield item

    def cmd_grep(self, items: Iterable, args: str) -> Iterable:
        '''Usage: | grep <str>

        Grep <str> in the input strings.
        '''
        if len(args) == 0:
            raise RuntimeError('grep requires an argument')

        for item in items:
            if args in str(item):
                yield item

    def cmd_quit(self, items: Iterable, args: str) -> Iterable:
        '''Usage: quit

        Quit cloudkeeper.
        '''
        self.quit('Shutdown requested by CLI input')
        return ()

    def cmd_procinfo(self, items: Iterable, args: str) -> Iterable:
        '''Usage: procinfo

        Show information about running threads.
        '''
        yield 'Threads'
        for thread in threading.enumerate():
            yield f'\t{thread.name}: {thread}'

    def cmd_collect(self, items: Iterable, args: str) -> Iterable:
        '''Usage: collect

        Perform a collect run.
        '''
        dispatch_event(Event(EventType.START_COLLECT))
        return ()

    def cmd_delete(self, items: Iterable, args: str) -> Iterable:
        '''Usage: | delete [--yes]

        Calls the cleanup method on all resources.
        Won't ask for confirmation if --yes is provided.

        WARNING: THIS WILL IMMEDIATELY DELETE ALL INPUT RESOURCES
        '''
        for item in items:
            if not isinstance(item, BaseResource):
                raise RuntimeError(f'Item {item} is not a valid resource - deletion failed')
            if args == '--yes':
                confirm_delete = True
            else:
                confirm_delete = button_dialog(
                    title=f'Delete {item.name}',
                    text=f'Really delete {item.name}?',
                    buttons=[
                        ('Yes', True),
                        ('No', False),
                        ('Abort', None)
                    ],
                ).run()

            if confirm_delete is None:
                break
            elif confirm_delete is True:
                item.cleanup(self.graph)
            yield item

    def cmd_dump(self, items: Iterable, args: str) -> Iterable:
        '''Usage: | dump

        Dumps details about the resources.
        '''
        for item in items:
            if not isinstance(item, BaseResource):
                raise RuntimeError(f'Item {item} is not a valid resource - dumping failed')
            yield('Object Dump:')
            yield(pformat(get_resource_attributes(item)))
            yield('Object Log:')
            yield(pformat(item.event_log))

    def cmd_tag(self, items: Iterable, args: str) -> Iterable:
        '''Usage: | tag <update|delete> key [value]

        Sets, updates or deletes a tag.

        WARNING: THIS WILL SET/UPDATE/DELETE A RESOURCE TAG IN THE CLOUD
        '''
        cmd = str(args).split(' ', 2)
        if len(cmd) < 2:
            raise RuntimeError(f'Invalid number of arguments for tag command')
        action = cmd[0]
        key = cmd[1]
        value = None
        if len(cmd) == 3:
            value = cmd[2]
        for item in items:
            if not isinstance(item, BaseResource):
                raise RuntimeError(f'Item {item} is not a valid resource - tag update failed')
            if action == 'update' and value is not None:
                item.tags[key] = value
                yield item
            elif action == 'delete':
                del(item.tags[key])
                yield item
            else:
                raise RuntimeError(f'Invalid tag action {action} or empty value')

    def cmd_count(self, items: Iterable, args: str) -> Iterable:
        '''Usage: | count [attribute]

        Counts the number of items.
        Optionally counts by attribute.
        '''
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
            yield f'{attribute}: {count}'

        if attr:
            yield f'total matched: {total_matched}'
            yield f'total unmatched: {total_unmatched}'
        yield f'total: {total}'

    def cmd_tail(self, items: Iterable, args: str) -> Iterable:
        '''Usage: | tail <num>

        Returns the last num lines.
        '''
        num = int(args) if len(args) > 0 else 10
        if num < 0:
            num *= -1
        return deque(items, num)

    def cmd_head(self, items: Iterable, args: str) -> Iterable:
        '''Usage: | head <num>

        Returns the first num lines.
        '''
        num = int(args) if len(args) > 0 else 10
        if num < 0:
            num *= -1
        return islice(items, num)

    def cmd_help(self, items: Iterable, args: str) -> Iterable:
        '''Usage: help <command>

        Show help text for a command.
        '''
        extra_doc = ''
        if args == '':
            args = 'help'
            valid_commands = "\n    ".join(self.valid_commands)
            placeholder_help = inspect.getdoc(replace_placeholder)
            extra_doc = f'''\n
{placeholder_help}

Valid commands are:
    {valid_commands}

Note that you can pipe commands using the pipe character (|)
and chain multipe commands using the semicolon (;).
            '''
        method = f'cmd_{args}'
        if hasattr(self, method):
            f = getattr(self, method)
            doc = inspect.getdoc(f)
            if doc is None:
                doc = f'Command {args} has no help text.'
        else:
            doc = f'Unknown command: {args}'
        doc += extra_doc
        return (doc,)

    def cmd_predecessors(self, items: Iterable, args: str) -> Iterable:
        '''Usage: | predecessors [--with-origin]

        List a resource's predecessors in the graph.
        Predecessors are a resource's parents.

        If --with-origin is specified the origin resource(s) will also be output.
        '''
        return self.relatives(items, 'predecessors', args)

    def cmd_successors(self, items: Iterable, args: str) -> Iterable:
        '''Usage: | successors [--with-origin]

        List a resource's successors in the graph.
        Successors are a resource's children.

        If --with-origin is specified the origin resource(s) will also be output.
        '''
        return self.relatives(items, 'successors', args)

    def cmd_ancestors(self, items: Iterable, args: str) -> Iterable:
        '''Usage: | ancestors [--with-origin]

        List a resource's ancestors in the graph.
        Ancestors are a resource's parents and their parents
        and their parents and so on.

        If --with-origin is specified the origin resource(s) will also be output.
        '''
        return self.relatives(items, 'ancestors', args)

    def cmd_descendants(self, items: Iterable, args: str) -> Iterable:
        '''Usage: | descendants [--with-origin]

        List a resource's descendants in the graph.
        Descendants are a resource's children and their children
        and their children and so on.

        If --with-origin is specified the origin resource(s) will also be output.
        '''
        return self.relatives(items, 'descendants', args)

    def relatives(self, nodes: Iterable, group: str, args: str) -> Iterable:
        '''Return a group of relatives for any given list of nodes
        '''
        output_origin_node = True if args == '--with-origin' else False

        for node in nodes:
            if output_origin_node:
                yield node
            if not isinstance(node, BaseResource):
                raise RuntimeError(f'Node {node} is not a valid resource')
            yield from getattr(node, group)(self.graph)

    def cmd_tee(self, items: Iterable, args: str) -> Iterable:
        '''Usage: | tee [-a] <filename>

        Write input to file.
        Optionally use -a to append to filename.
        '''
        mode = 'w'
        filename = args
        if args.startswith('-a '):
            mode = 'a'
            _, filename = args.split(' ', 1)

        with open(filename, mode) as outfile:
            for item in items:
                outfile.write(f'{item}\n')
                yield item

    def cmd_sort(self, items: Iterable, args: str, reverse: bool = False) -> Iterable:
        '''Usage: | sort [attribute]

        Sort input alphabetically.
        Optionally sort by attribute.
        '''
        attr = args

        def getsortkey(item):
            if len(attr) == 0:
                return item
            attr_value = self.get_item_attr(item, attr)
            if attr_value is None:
                raise ValueError(f'Item {item} has no attribute {attr}')
            return attr_value

        yield from sorted(list(items), key=getsortkey, reverse=reverse)

    def cmd_rsort(self, items: Iterable, args: str, reverse: bool = False) -> Iterable:
        '''Usage: | rsort [attribute]

        Sort input alphabetically in reverse order.
        Optionally sort by attribute.
        '''
        return self.cmd_sort(items, args, reverse=True)

    def cmd_backup(self, items: Iterable, args: str) -> Iterable:
        '''Usage: backup <filename>

        Create a backup of the graph.
        '''
        filename = args
        with open(filename, 'wb') as outfile:
            yield(f'Writing Graph backup to {filename}')
            outfile.write(graph2pickle(self.graph))
        yield('done')

    def cmd_clean(self, items: Iterable, args: str) -> Iterable:
        '''Usage: | clean

        Flag a resource for cleaning.

        WARNING: THIS WILL FLAG RESOURCES FOR CLEANUP (DELAYED DELETION)
        '''
        for item in items:
            if not isinstance(item, BaseResource):
                raise RuntimeError(f'Item {item} is not a valid resource - cleanup flagging failed')
            item.clean = True
            yield item

    def cmd_protect(self, items: Iterable, args: str) -> Iterable:
        '''Usage: | protect

        Burn a resource's protection fuse so it won't be deleted
        or otherwise modified in the future.

        WARNING: THIS WILL ONLY PROTECT RESOURCES IN YOUR LOCAL INSTANCE OF THE GRAPH
        '''
        for item in items:
            if not isinstance(item, BaseResource):
                raise RuntimeError(f"Item {item} is not a valid resource - can't burn protection fuse")
            item.protected = True
            yield item

    def cmd_cleanup(self, items: Iterable, args: str) -> Iterable:
        '''Usage: cleanup

        Perform a resource cleanup.

        WARNING: THIS WILL IMMEDIATELY DELETE ALL RESOURCES FLAGGED FOR CLEANUP
        '''
        yield 'Beginning cleanup'
        resource_cleaner = Cleaner(self.graph)
        resource_cleaner.cleanup()
        yield 'Cleanup finished'

    def cmd_print(self, items: Iterable, args: str) -> Iterable:
        '''Usage: | print

        Prints all input items.
        '''
        for item in items:
            print(item)
            yield item

    def cmd_log(self, items: Iterable, args: str) -> Iterable:
        '''Usage: | log [loglevel]

        Send input to logger.
        '''
        log_level = args if len(args) > 0 else 'info'
        logger = getattr(log, log_level, None)
        if logger is None or not callable(logger):
            raise ValueError(f'Unknown log level: {log_level}')

        for item in items:
            logger(item)
            yield item

    def cmd_uniq(self, items: Iterable, args: str) -> Iterable:
        '''Usage: | uniq

        Deduplicate input.
        '''
        seen = {}
        for item in items:
            if seen.get(item) is None:
                seen[item] = True
                yield item

    def cmd_has(self, items: Iterable, args: str) -> Iterable:
        '''Usage: | has [not] <attribute>

        List resources that do or don't have an attribute
        and that attribute has a value.
        '''
        attr = args
        negate_match = False
        if attr.startswith('not '):
            negate_match = True
            attr = attr[4:]

        if len(attr) == 0:
            raise RuntimeError('has requires an attribute name')

        for item in items:
            item_attr = self.get_item_attr(item, attr)
            if (not negate_match and item_attr is not None) or (negate_match and item_attr is None):
                yield item

    def cmd_sleep(self, items: Iterable, args: str) -> Iterable:
        '''Usage: | sleep [pipe] <seconds>

        Sleep for the specified number of seconds.
        If pipe is specified sleep will pipe through all input items.
        '''
        pipe = False
        if args.startswith('pipe '):
            pipe = True
            args = args[5:]

        seconds = args
        if len(seconds) == 0 or bool(re.search('[^0-9.]', str(seconds))):
            raise ValueError('invalid number of seconds')

        seconds = float(seconds)
        time.sleep(seconds)

        if pipe:
            yield from items

    def cmd_register(self, items: Iterable, args: str) -> Iterable:
        '''Usage: register <event>:<cli command>

        Register a CLI command with an event.
        '''
        if len(args) == 0:
            yield 'register takes an event and cli command as argument'
        else:
            yield 'Registering CLI action'
            if register_cli_action(args):
                yield 'success'
            else:
                yield 'failed'

    def cmd_date(self, items: Iterable, args: str) -> Iterable:
        '''Usage: date

        Show the current date and time in iso format.
        '''
        tz = get_localzone()
        yield tz.localize(datetime.now()).isoformat()

    def cmd_utcdate(self, items: Iterable, args: str) -> Iterable:
        '''Usage: utcdate

        Show the current UTC date and time in iso format.
        '''
        yield datetime.utcnow().replace(tzinfo=timezone.utc).isoformat()

    def cmd_echo(self, items: Iterable, args: str) -> Iterable:
        '''Usage: echo [string]

        Echo a string to the console.

        Can be used for testing string substitution.
        E.g. echo @TODAY@
        '''
        yield args

    def cmd_jobs(self, items: Iterable, args: str) -> Iterable:
        '''Usage: jobs

        Return a list of scheduled jobs
        '''
        if self.scheduler is None:
            raise RuntimeError('No scheduler given')
        yield from self.scheduler.get_jobs()

    def cmd_add_job(self, items: Iterable, args: str) -> Iterable:
        '''Usage: add_job <schedule> [event]:<cli command>

        Add a scheduled job in cron format.
            field          allowed values
            -----          --------------
            minute         0–59
            hour           0–23
            day of month   1–31
            month          1–12
            day of week    0–7

        Example:
            Count EC2 Instances every three hours
            > add_job 0 */3 * * * match resource_type = aws_ec2_instance \\| count
        '''
        if self.scheduler is None:
            raise RuntimeError('No scheduler given')
        job = self.scheduler.add_job(args)
        yield f'job id: {job.id}'

    def cmd_remove_job(self, items: Iterable, args: str) -> Iterable:
        '''Usage: remove_job <job-id>

        Remove a scheduled job.
        '''
        if self.scheduler is None:
            raise RuntimeError('No scheduler given')

        if len(args) == 0:
            yield 'remove_job takes a job id as argument'
        else:
            if self.scheduler.remove_job(args):
                yield 'success'
            else:
                yield 'failed'

    def get_item_attr(self, item: BaseResource, attr: str) -> Any:
        attr, attr_key, attr_attr = get_attr_key(attr)
        item_attr = getattr(item, attr, None)
        if attr in ['cloud', 'account', 'region'] and callable(item_attr):
            item_attr = item_attr(self.graph)
        if item_attr is not None and not callable(item_attr):
            if attr_key is not None and isinstance(item_attr, dict):
                item_attr = item_attr.get(attr_key)
        if attr_attr is not None:
            item_attr = getattr(item_attr, attr_attr, None)
        return item_attr


@lru_cache()
def get_attr_key(attr: str) -> Tuple:
    attr_key = None
    attr_attr = None
    if '.' in attr:
        dot_pos = attr.index('.')
        attr_attr = attr[dot_pos + 1:]
        attr = attr[:dot_pos]
    if '[' in attr and ']' in attr:
        open_bracket_pos = attr.index('[')
        close_bracket_pos = attr.index(']')
        if open_bracket_pos < close_bracket_pos - 1:
            attr_key = attr[open_bracket_pos + 1:close_bracket_pos]
            attr = attr[:open_bracket_pos]
    return (attr, attr_key, attr_attr)


def register_cli_action(action: str, one_shot: bool = False) -> bool:
    if ':' not in action:
        log.error(f'Invalid CLI action {action}')
        return False
    event, command = action.split(':', 1)
    event = event.strip()
    command = command.strip()
    if event.startswith('1'):
        one_shot = True
        event = event[1:]
    for e in EventType:
        if event == e.name.lower():
            f = partial(cli_event_handler, command)
            return add_event_listener(e, f, blocking=True, one_shot=one_shot)
    else:
        log.error(f'Invalid event type {event}')
    return False


def cli_event_handler(cli_input: str, event: Event = None, graph: Graph = None) -> None:
    if graph is None and event:
        log.info(f'Received event {event.event_type.name}, running command: {cli_input}')
        graph = event.data
    try:
        ch = CliHandler(graph)
        for item in ch.evaluate_cli_input(cli_input):
            log.info(item)
    except (RuntimeError, ValueError) as e:
        log.error(e)
    except Exception:
        log.exception('Caught unhandled exception while processing CLI command')


def replace_placeholder(cli_input: str) -> str:
    '''
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
    '''
    t = date.today()
    n = get_localzone().localize(datetime.now())
    utc = datetime.utcnow().replace(tzinfo=timezone.utc).isoformat()
    now = n.isoformat()
    today = t.strftime('%Y-%m-%d')
    year = t.strftime('%Y')
    month = t.strftime('%m')
    day = t.strftime('%d')
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

    cli_input = cli_input.replace('@UTC@', utc)
    cli_input = cli_input.replace('@NOW@', now)
    cli_input = cli_input.replace('@TODAY@', today)
    cli_input = cli_input.replace('@YEAR@', year)
    cli_input = cli_input.replace('@MONTH@', month)
    cli_input = cli_input.replace('@DAY@', day)
    cli_input = cli_input.replace('@TIME@', time)
    cli_input = cli_input.replace('@HOUR@', hour)
    cli_input = cli_input.replace('@MINUTE@', minute)
    cli_input = cli_input.replace('@SECOND@', second)
    cli_input = cli_input.replace('@TZ_OFFSET@', tz_offset)
    cli_input = cli_input.replace('@TZ@', tz)
    cli_input = cli_input.replace('@MONDAY@', monday)
    cli_input = cli_input.replace('@TUESDAY@', tuesday)
    cli_input = cli_input.replace('@WEDNESDAY@', wednesday)
    cli_input = cli_input.replace('@THURSDAY@', thursday)
    cli_input = cli_input.replace('@FRIDAY@', friday)
    cli_input = cli_input.replace('@SATURDAY@', saturday)
    cli_input = cli_input.replace('@SUNDAY@', sunday)

    return cli_input
