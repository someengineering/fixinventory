import threading
import logging
import re
import os
import gc as garbage_collector
import resource
import time
import json
import ipaddress
from functools import wraps
from pprint import pformat
from pympler import asizeof
from typing import Dict, List
from datetime import date, datetime, timezone, timedelta
from ctypes import CDLL
from signal import Signals, SIGKILL

log = logging.getLogger(__name__)
PR_SET_PDEATHSIG = 1


class RWLock:
    """Synchronization object used in a solution of so-called second
    readers-writers problem. In this problem, many readers can simultaneously
    access a share, and a writer has an exclusive access to this share.
    Additionally, the following constraints should be met:
    1) no reader should be kept waiting if the share is currently opened for
        reading unless a writer is also waiting for the share,
    2) no writer should be kept waiting for the share longer than absolutely
        necessary.

    The implementation is based on [1, secs. 4.2.2, 4.2.6, 4.2.7]
    with a modification -- adding an additional lock (C{self.__readers_queue})
    -- in accordance with [2].

    Sources:
    [1] A.B. Downey: "The little book of semaphores", Version 2.1.5, 2008
    [2] P.J. Courtois, F. Heymans, D.L. Parnas:
        "Concurrent Control with 'Readers' and 'Writers'",
        Communications of the ACM, 1971 (via [3])
    [3] http://en.wikipedia.org/wiki/Readers-writers_problem

    This code is a derivative of the code from ActiveState Code service at:
    http://code.activestate.com/recipes/577803-reader-writer-lock-with-priority-for-writers
    and is licensed under the MIT license.
    """

    def __init__(self):
        self.__read_switch = _LightSwitch()
        self.__write_switch = _LightSwitch()
        self.__no_readers = threading.Lock()
        self.__no_writers = threading.Lock()
        self.__readers_queue = threading.Lock()
        """A lock giving an even higher priority to the writer in certain
        cases (see [2] for a discussion)"""

        class _ReadAccess:
            def __init__(self, rwlock: RWLock):
                self.rwlock = rwlock

            def __enter__(self):
                self.rwlock.reader_acquire()
                return self.rwlock

            def __exit__(self, typ, value, tb):
                self.rwlock.reader_release()
        self.read_access = _ReadAccess(self)

        class _WriteAccess:
            def __init__(self, rwlock: RWLock):
                self.rwlock = rwlock

            def __enter__(self):
                self.rwlock.writer_acquire()
                return self.rwlock

            def __exit__(self, typ, value, tb):
                self.rwlock.writer_release()
        self.write_access = _WriteAccess(self)

    def reader_acquire(self):
        self.__readers_queue.acquire()
        self.__no_readers.acquire()
        self.__read_switch.acquire(self.__no_writers)
        self.__no_readers.release()
        self.__readers_queue.release()

    def reader_release(self):
        self.__read_switch.release(self.__no_writers)

    def writer_acquire(self):
        self.__write_switch.acquire(self.__no_readers)
        self.__no_writers.acquire()

    def writer_release(self):
        self.__no_writers.release()
        self.__write_switch.release(self.__no_readers)


class _LightSwitch:
    """An auxiliary "light switch"-like object. The first thread turns on the
    "switch", the last one turns it off (see [1, sec. 4.2.2] for details)."""

    def __init__(self):
        self.__counter = 0
        self.__mutex = threading.Lock()

    def acquire(self, lock):
        self.__mutex.acquire()
        self.__counter += 1
        if self.__counter == 1:
            lock.acquire()
        self.__mutex.release()

    def release(self, lock):
        self.__mutex.acquire()
        self.__counter -= 1
        if self.__counter == 0:
            lock.release()
        self.__mutex.release()


def make_valid_timestamp(timestamp: datetime) -> datetime:
    if not isinstance(timestamp, datetime) and isinstance(timestamp, date):
        timestamp = datetime.combine(timestamp, datetime.min.time()).replace(tzinfo=timezone.utc)
    elif isinstance(timestamp, datetime) and timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=timezone.utc)
    elif isinstance(timestamp, datetime):
        pass
    else:
        timestamp = datetime.utcnow().replace(tzinfo=timezone.utc)
    return timestamp


def delta_to_str(delta: timedelta) -> str:
    """Convert a timedelta to a string format which is reversable.
    Takes a datetime.timedelta object and converts it into a string
    that is parseable by parse_delta
    """
    # NOTE: Rounds up to nearest minute)
    units = [('m', 60), ('h', 60), ('d', 24), ('w', 7)]

    remaining = delta.total_seconds()

    delta_str = ''

    negative = remaining < 0

    def add_negative():
        return '-' + delta_str if negative else delta_str

    # Only handle things in the future for simplicity in testing.
    if negative:
        remaining = -remaining

    # Print 0 minutes as the base case.
    if remaining == 0:
        return '0m'

    for i in range(0, len(units)):
        _, count = units[i]

        remainder = int(remaining % count)
        remaining = int(remaining // count)

        # Round up the first unit (seconds) into minutes.
        if i == 0:
            if remainder > 0:
                remaining += 1
        else:
            assert i > 0
            if remainder != 0:
                delta_str = "{}{}{}".format(remainder, units[i - 1][0], delta_str)

        # No need to go further / captured it all, so long as we've printed at
        # least minutes.
        if remaining == 0 and i > 0:
            return add_negative()

    # Print the last unit with all the remaining count.
    delta_str = "{}{}{}".format(remaining, units[-1][0], delta_str)

    return add_negative()


def parse_delta(delta: str) -> timedelta:
    """Parse a timedelta string format into a python timedelta object.
    Takes a delta string like that constructed in delta_to_str and converts
    it into a datetime.timedelta object
    """
    assert delta != 'never'
    possible_args = ['weeks', 'days', 'hours', 'minutes']

    # Find all the <count> <unit> patterns, expand the count + units to build a timedelta.
    chunk_regex = r'(\d+)\s*(\D+)\s*'
    kwargs = {}
    for count, unit in re.findall(chunk_regex, delta, re.I):
        unit = unit.strip()
        int_count = int(count)
        found_unit = False
        # match so that units can be given as single letters instead of whole words
        for arg in possible_args:
            if arg.startswith(unit):
                kwargs[arg] = int_count
                found_unit = True
                break

        if not found_unit:
            raise ValueError(f"Unknown unit '{unit}' when parsing '{delta}'")

    if len(kwargs) == 0:
        raise ValueError(f"Unable to parse '{delta}'")

    return timedelta(**kwargs)


def chunks(items: List, n: int) -> List:
    """Split a list of items into multiple lists of size n and yield each chunk
    """
    for i in range(0, len(items), n):
        yield items[i:i + n]


def split_esc(s, delim):
    """Split with support for delimiter escaping

    Via: https://stackoverflow.com/a/29107566
    """
    i, res, buf = 0, [], ''
    while True:
        j, e = s.find(delim, i), 0
        if j < 0:  # end reached
            return res + [buf + s[i:]]  # add remainder
        while j - e and s[j - e - 1] == '\\':
            e += 1  # number of escapes
        d = e // 2  # number of double escapes
        if e != d * 2:  # odd number of escapes
            buf += s[i:j - d - 1] + s[j]  # add the escaped char
            i = j + 1  # and skip it
            continue  # add more to buf
        res.append(buf + s[i:j - d])
        i, buf = j + len(delim), ''  # start after delim


def get_stats(graph=None) -> Dict:
    try:
        stats = {
            'maxrss_self_bytes': resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * 1024,
            'maxrss_children_bytes': resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss * 1024,
            'active_threads': threading.active_count(),
            'thread_names': [thread.name for thread in threading.enumerate()],
            'graph_size_bytes': asizeof.asizeof(graph),
            'garbage_collector': garbage_collector.get_stats(),
            'process': get_all_process_info()
        }
        stats['graph_size_human_readable'] = iec_size_format(stats['graph_size_bytes']),
        stats['maxrss_self_human_readable'] = iec_size_format(stats['maxrss_self_bytes']),
        stats['maxrss_children_human_readable'] = iec_size_format(stats['maxrss_children_bytes']),
    except Exception:
        log.exception('Error while trying to get stats')
        return {}
    else:
        return stats


def get_all_process_info(pid: int = None, proc: str = '/proc') -> Dict:
    if pid is None:
        pid = os.getpid()
    process_info = {}
    process_info['parent'] = {pid: get_process_info(pid)}
    process_info['parent'][pid]['file_descriptors'] = get_file_descriptor_info(pid, proc)
    process_info['children'] = get_child_process_info(pid, proc)
    for pid in process_info['children']:
        process_info['children'][pid]['file_descriptors'] = get_file_descriptor_info(pid, proc)
    return process_info


def get_child_process_info(parent_pid: int = None, proc: str = '/proc') -> Dict:
    if parent_pid is None:
        parent_pid = os.getpid()
    child_process_info = {}
    for pid in get_pid_list(proc):
        process_info = get_process_info(pid)
        if process_info.get('PPid') == str(parent_pid):
            child_process_info[pid] = dict(process_info)
    return child_process_info


def get_pid_list(proc: str = '/proc') -> List:
    pids = []
    for entry in os.listdir(proc):
        try:
            if os.path.isdir(os.path.join(proc, entry)) and entry.isdigit():
                pids.append(int(entry))
        except (PermissionError, FileNotFoundError):
            pass
    return pids


def get_process_info(pid: int = None, proc: str = '/proc') -> Dict:
    if pid is None:
        pid = os.getpid()
    process_info = {}
    try:
        with open(os.path.join(proc, str(pid), 'status'), 'r') as status:
            for line in status:
                k, v = line.split(':', 1)
                v = re.sub('[ \t]+', ' ', v.strip())
                process_info[k.lower()] = v
        for limit_name in ('NOFILE', 'NPROC'):
            process_info[f'RLIMIT_{limit_name}'.lower()] = resource.getrlimit(getattr(resource, f'RLIMIT_{limit_name}'))
    except (PermissionError, FileNotFoundError):
        pass
    return process_info


def get_file_descriptor_info(pid: int = None, proc: str = '/proc') -> Dict:
    if pid is None:
        pid = os.getpid()
    pid = str(pid)
    file_descriptor_info = {}
    try:
        for entry in os.listdir(os.path.join(proc, pid, 'fd')):
            file_descriptor_info[entry] = {}
            entry_path = os.path.join(proc, pid, 'fd', entry)
            if os.path.islink(entry_path):
                target = os.readlink(entry_path)
                file_descriptor_info[entry]['target'] = target
    except (PermissionError, FileNotFoundError):
        pass
    return file_descriptor_info


def log_stats(graph=None, garbage_collector_stats: bool = False) -> None:
    stats = get_stats(graph)
    try:
        log.debug(f"Stats: max rss self: {stats['maxrss_self_human_readable']}, children: {stats['maxrss_children_human_readable']}, active threads {stats['active_threads']}: {', '.join([thread for thread in stats['thread_names']])}")
        if graph:
            log.debug(f"Graph Stats: {stats['graph_size_human_readable']}")
        if garbage_collector_stats:
            gc_stats = " | ".join([f"Gen {i}: collections {data.get('collections')}, collected {data.get('collected')}, uncollectable {data.get('uncollectable')}" for i, data in enumerate(stats['garbage_collector'])])
            log.debug(f'Garbage Collector Stats: {gc_stats}')
    except Exception:
        log.exception('Error while trying to log stats')


# via https://stackoverflow.com/a/1094933
def iec_size_format(byte_size: int) -> str:
    for unit in ['B', 'KiB', 'MiB', 'GiB', 'TiB', 'PiB', 'EiB', 'ZiB']:
        if abs(byte_size) < 1024.0:
            return f'{byte_size:.2f} {unit}'
        byte_size /= 1024.0
    return f'{byte_size:.2f} YiB'


def json_default(o):
    if hasattr(o, 'to_json'):
        return o.to_json()
    elif isinstance(o, (date, datetime)):
        return o.isoformat()
    elif isinstance(o, Exception):
        return pformat(o)
    raise TypeError(f'Object of type {o.__class__.__name__} is not JSON serializable')


def signal_on_parent_exit(signal: Signals = SIGKILL) -> bool:
    log.debug(f"Setting PR_SET_PDEATHSIG to {signal.name} for current process")
    try:
        libc = CDLL('libc.so.6')
        res = libc.prctl(PR_SET_PDEATHSIG, signal)
    except Exception:
        log.exception("An error occured when trying to set PR_SET_PDEATHSIG")
    else:
        return res == 0
    return False


def log_runtime(f):
    @wraps(f)
    def timer(*args, **kwargs):
        start = time.time()
        ret = f(*args, **kwargs)
        runtime = time.time() - start
        args_str = ', '.join([repr(arg) for arg in args])
        kwargs_str = ', '.join([f"{k}={repr(v)}" for k, v in kwargs.items()])
        if len(args) > 0 and len(kwargs) > 0:
            args_str += ', '
        log.debug(f"Runtime of {f.__name__}({args_str}{kwargs_str}): {runtime:.3f} seconds")
        return ret
    return timer


def fmt_json(value) -> str:
    return json.dumps(value, default=json_default, skipkeys=True, indent=4, separators=(',', ': '), sort_keys=True)
