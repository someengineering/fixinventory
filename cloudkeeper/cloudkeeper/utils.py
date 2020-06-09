import threading
import logging
import re
import gc as garbage_collector
import resource
from pympler import asizeof
from typing import List
from datetime import date, datetime, timezone, timedelta


log = logging.getLogger(__name__)


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


def log_stats(gc=None, garbage_collector_stats: bool = False) -> None:
    try:
        maxrss = iec_size_format(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * 1024)
        log.debug(f'Stats: max rss {maxrss}, active threads {threading.active_count()}: {", ".join([thread.name for thread in threading.enumerate()])}')
        if gc:
            log.debug((
                f'Graph Stats:'
                f' container {iec_size_format(asizeof.asizeof(gc))}'
                f', graph {iec_size_format(asizeof.asizeof(gc.graph))}'
                f', pickle {iec_size_format(asizeof.asizeof(gc.pickle))}'
            ))
        if garbage_collector_stats:
            gc_stats = " | ".join([f"Gen {i}: collections {data.get('collections')}, collected {data.get('collected')}, uncollectable {data.get('uncollectable')}" for i, data in enumerate(garbage_collector.get_stats())])
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
