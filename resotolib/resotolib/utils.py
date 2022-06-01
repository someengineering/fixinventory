import string
import threading
import hashlib
import socket
import re
import os
import gc as garbage_collector
import sys
import random
import pkg_resources

if sys.platform == "linux":
    import resource
import time
import json
import requests
from resotolib.logger import log
from functools import wraps
from tarfile import TarFile, TarInfo
from pprint import pformat
from typing import Any, Callable, Dict, List, Tuple, Optional
from datetime import date, datetime, timezone, timedelta

try:
    from psutil import cpu_count
except ImportError:
    from os import cpu_count


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

    This code is a derivative of the code from ActiveState Code service at: http://
    code.activestate.com/recipes/577803-reader-writer-lock-with-priority-for-writers
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


def rnd_str(str_len: int = 10) -> str:
    return "".join(random.choice(string.ascii_uppercase + string.digits) for _ in range(str_len))


def make_valid_timestamp(timestamp: datetime) -> Optional[datetime]:
    if not isinstance(timestamp, datetime) and isinstance(timestamp, date):
        timestamp = datetime.combine(timestamp, datetime.min.time()).replace(tzinfo=timezone.utc)
    elif isinstance(timestamp, datetime) and timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=timezone.utc)
    elif isinstance(timestamp, datetime):
        pass
    else:
        timestamp = None
    return timestamp


def str2timedelta(td: str) -> timedelta:
    if "day" in td:
        m = re.match(
            r"(?P<days>[-\d]+) day[s]*, (?P<hours>\d+):(?P<minutes>\d+):(?P<seconds>\d[\.\d+]*)",
            td,
        )
    else:
        m = re.match(r"(?P<hours>\d+):(?P<minutes>\d+):(?P<seconds>\d[\.\d+]*)", td)
    args = {key: float(val) for key, val in m.groupdict().items()}
    return timedelta(**args)


def str2timezone(tz: str) -> timezone:
    mult = 1
    if not tz.startswith("UTC") or len(tz) != 9:
        raise ValueError(f"Invalid timezone string {tz}")
    if tz[3] == "-":
        mult = -1
    hours = int(tz[4:6]) * mult
    minutes = int(tz[7:9])
    return timezone(offset=timedelta(hours=hours, minutes=minutes))


def delta_to_str(delta: timedelta) -> str:
    """Convert a timedelta to a string format which is reversable.
    Takes a datetime.timedelta object and converts it into a string
    that is parseable by parse_delta
    """
    # NOTE: Rounds up to nearest minute)
    units = [("m", 60), ("h", 60), ("d", 24), ("w", 7)]

    remaining = delta.total_seconds()

    delta_str = ""

    negative = remaining < 0

    def add_negative():
        return "-" + delta_str if negative else delta_str

    # Only handle things in the future for simplicity in testing.
    if negative:
        remaining = -remaining

    # Print 0 minutes as the base case.
    if remaining == 0:
        return "0m"

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
    assert delta != "never"
    possible_args = ["weeks", "days", "hours", "minutes"]

    # Find all the <count> <unit> patterns, expand the count + units to build a
    # timedelta.
    chunk_regex = r"(\d+)\s*(\D+)\s*"
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
    """Split a list of items into multiple lists of size n and yield each chunk"""
    for s in range(0, len(items), n):
        e = s + n
        yield items[s:e]


def split_esc(s, delim):
    """Split with support for delimiter escaping

    Via: https://stackoverflow.com/a/29107566
    """
    i, res, buf = 0, [], ""
    while True:
        j, e = s.find(delim, i), 0
        if j < 0:  # end reached
            return res + [buf + s[i:]]  # add remainder
        while j - e and s[j - e - 1] == "\\":
            e += 1  # number of escapes
        d = e // 2  # number of double escapes
        if e != d * 2:  # odd number of escapes
            buf += s[i : j - d - 1] + s[j]  # add the escaped char
            i = j + 1  # and skip it
            continue  # add more to buf
        res.append(buf + s[i : j - d])
        i, buf = j + len(delim), ""  # start after delim


def get_stats(graph=None) -> Dict:
    try:
        stats = {
            "active_threads": threading.active_count(),
            "thread_names": [thread.name for thread in threading.enumerate()],
            "garbage_collector": garbage_collector.get_stats(),
            "process": get_all_process_info(),
        }
        if sys.platform == "linux":
            stats.update(
                {
                    "maxrss_parent_bytes": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * 1024,
                    "maxrss_children_bytes": resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss * 1024,
                }
            )
        else:
            stats.update({"maxrss_parent_bytes": 0, "maxrss_children_bytes": 0})
        stats["maxrss_total_bytes"] = stats["maxrss_parent_bytes"] + stats["maxrss_children_bytes"]
        num_fds_parent = stats["process"].get("parent", {}).get("num_file_descriptors", 0)
        num_fds_children = sum([v["num_file_descriptors"] for v in stats["process"].get("children", {}).values()])
        stats.update(
            {
                "maxrss_parent_human_readable": iec_size_format(stats["maxrss_parent_bytes"]),
                "maxrss_children_human_readable": iec_size_format(stats["maxrss_children_bytes"]),
                "maxrss_total_human_readable": iec_size_format(stats["maxrss_total_bytes"]),
                "num_fds_parent": num_fds_parent,
                "num_fds_children": num_fds_children,
                "num_fds_total": num_fds_parent + num_fds_children,
            }
        )
    except Exception:
        log.exception("Error while trying to get stats")
        return {}
    else:
        return stats


def get_all_process_info(pid: int = None, proc: str = "/proc") -> Dict:
    if sys.platform != "linux":
        return {}
    if pid is None:
        pid = os.getpid()
    process_info = {}
    process_info["parent"] = get_process_info(pid)
    process_info["parent"]["file_descriptors"] = get_file_descriptor_info(pid, proc)
    process_info["parent"]["num_file_descriptors"] = len(process_info["parent"]["file_descriptors"])
    process_info["children"] = get_child_process_info(pid, proc)
    for pid in process_info["children"]:
        process_info["children"][pid]["file_descriptors"] = get_file_descriptor_info(pid, proc)
        process_info["children"][pid]["num_file_descriptors"] = len(process_info["children"][pid]["file_descriptors"])
    return process_info


def get_child_process_info(parent_pid: int = None, proc: str = "/proc") -> Dict:
    if sys.platform != "linux":
        return {}
    if parent_pid is None:
        parent_pid = os.getpid()
    child_process_info = {}
    for pid in get_pid_list(proc):
        process_info = get_process_info(pid)
        if process_info.get("ppid") == str(parent_pid):
            child_process_info[pid] = dict(process_info)
    return child_process_info


def get_pid_list(proc: str = "/proc") -> List:
    if sys.platform != "linux":
        return []
    pids = []
    for entry in os.listdir(proc):
        try:
            if os.path.isdir(os.path.join(proc, entry)) and entry.isdigit():
                pids.append(int(entry))
        except (PermissionError, FileNotFoundError):
            pass
    return pids


def get_process_info(pid: int = None, proc: str = "/proc") -> Dict:
    if sys.platform != "linux":
        return {}
    if pid is None:
        pid = os.getpid()
    process_info = {}
    try:
        with open(os.path.join(proc, str(pid), "status"), "r") as status:
            for line in status:
                k, v = line.split(":", 1)
                v = re.sub("[ \t]+", " ", v.strip())
                process_info[k.lower()] = v
        for limit_name in ("NOFILE", "NPROC"):
            process_info[f"RLIMIT_{limit_name}".lower()] = resource.getrlimit(getattr(resource, f"RLIMIT_{limit_name}"))
    except (PermissionError, FileNotFoundError):
        pass
    return process_info


def get_file_descriptor_info(pid: int = None, proc: str = "/proc") -> Dict:
    if sys.platform != "linux":
        return {}
    if pid is None:
        pid = os.getpid()
    pid = str(pid)
    file_descriptor_info = {}
    try:
        for entry in os.listdir(os.path.join(proc, pid, "fd")):
            entry_path = os.path.join(proc, pid, "fd", entry)
            if os.path.islink(entry_path):
                file_descriptor_info[entry] = {}
                target = os.readlink(entry_path)
                file_descriptor_info[entry]["target"] = target
    except (PermissionError, FileNotFoundError):
        pass
    return file_descriptor_info


def log_stats(graph=None, garbage_collector_stats: bool = False) -> None:
    stats = get_stats(graph)
    try:
        log.debug(
            f"Stats: max rss parent: {stats['maxrss_parent_human_readable']},"
            f" children: {stats['maxrss_children_human_readable']},"
            f" fds: {stats['num_fds_total']}/"
            f"{stats['process'].get('parent', {}).get('rlimit_nofile', [0])[0]}"
            f" active threads {stats['active_threads']}:"
            f" {', '.join([thread for thread in stats['thread_names']])}"
        )
        if graph:
            log.debug(f"Graph Stats: {stats['graph_size_human_readable']}")
        if garbage_collector_stats:
            gc_stats = " | ".join(
                [
                    (
                        f"Gen {i}: collections {data.get('collections')}, "
                        f"collected {data.get('collected')}, "
                        f"uncollectable {data.get('uncollectable')}"
                    )
                    for i, data in enumerate(stats["garbage_collector"])
                ]
            )
            log.debug(f"Garbage Collector Stats: {gc_stats}")
    except Exception:
        log.exception("Error while trying to log stats")


# via https://stackoverflow.com/a/1094933
def iec_size_format(byte_size: int) -> str:
    for unit in ["B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB", "ZiB"]:
        if abs(byte_size) < 1024.0:
            return f"{byte_size:.2f} {unit}"
        byte_size /= 1024.0
    return f"{byte_size:.2f} YiB"


# via https://stackoverflow.com/a/44873382
def sha256sum(filename: str, buffer_size: int = 128 * 1024) -> str:
    h = hashlib.sha256()
    buffer = bytearray(buffer_size)
    buffer_view = memoryview(buffer)
    with open(filename, "rb", buffering=0) as f:
        while True:
            n = f.readinto(buffer_view)
            if not n:
                break
            h.update(buffer_view[:n])
    return h.hexdigest()


def json_default(o):
    if hasattr(o, "to_json"):
        return o.to_json()
    elif isinstance(o, (date, datetime)):
        return o.isoformat()
    elif isinstance(o, Exception):
        return pformat(o)
    raise TypeError(f"Object of type {o.__class__.__name__} is not JSON serializable")


def log_runtime(f):
    @wraps(f)
    def timer(*args, **kwargs):
        start = time.time()
        ret = f(*args, **kwargs)
        runtime = time.time() - start
        args_str = ", ".join([repr(arg) for arg in args])
        kwargs_str = ", ".join([f"{k}={repr(v)}" for k, v in kwargs.items()])
        if len(args) > 0 and len(kwargs) > 0:
            args_str += ", "
        log.debug(f"Runtime of {f.__name__}({args_str}{kwargs_str}): {runtime:.3f} seconds")
        return ret

    return timer


def except_log_and_pass(do_raise: Optional[Tuple] = None):
    if do_raise is None:
        do_raise = ()

    def acallable(f):
        @wraps(f)
        def catch_and_log(*args, **kwargs):
            try:
                return f(*args, **kwargs)
            except do_raise:
                raise
            except Exception:
                args_str = ", ".join([repr(arg) for arg in args])
                kwargs_str = ", ".join([f"{k}={repr(v)}" for k, v in kwargs.items()])
                if len(args) > 0 and len(kwargs) > 0:
                    args_str += ", "
                log.exception(f"Caught exception in {f.__name__}({args_str}{kwargs_str})")

        return catch_and_log

    return acallable


def fmt_json(value) -> str:
    return json.dumps(
        value,
        default=json_default,
        skipkeys=True,
        indent=4,
        separators=(",", ": "),
        sort_keys=True,
    )


def increase_limits() -> None:
    if sys.platform != "linux":
        return
    for limit_name in ("RLIMIT_NOFILE", "RLIMIT_NPROC"):
        soft_limit, hard_limit = resource.getrlimit(getattr(resource, limit_name))
        log.debug(f"Current {limit_name} soft: {soft_limit} hard: {hard_limit}")
        try:
            if soft_limit < hard_limit:
                log.debug(f"Increasing {limit_name} {soft_limit} -> {hard_limit}")
                resource.setrlimit(getattr(resource, limit_name), (hard_limit, hard_limit))
        except (ValueError):
            log.error(f"Failed to increase {limit_name} {soft_limit} -> {hard_limit}")


resource_attributes_blacklist = ["event_log"]


def get_resource_attributes(resource, exclude_private: bool = True, keep_data_structures: bool = False) -> Dict:
    attributes = dict(resource.__dict__)
    attributes["kind"] = resource.kind

    for attr_name in dir(resource):
        if exclude_private and attr_name.startswith("_"):
            continue
        attr_type = getattr(type(resource), attr_name, None)
        if isinstance(attr_type, property):
            attributes[attr_name] = getattr(resource, attr_name, None)
    attributes["tags"] = dict(attributes.pop("_tags"))

    remove_keys = []
    add_keys = {}

    for key, value in attributes.items():
        if exclude_private and str(key).startswith("_") or str(key) in resource_attributes_blacklist:
            remove_keys.append(key)
        elif isinstance(value, (list, tuple, set)) and not keep_data_structures:
            remove_keys.append(key)
            for i, v in enumerate(value):
                if v is not None:
                    add_keys[key + "[" + str(i) + "]"] = v
        elif isinstance(value, dict) and not keep_data_structures:
            remove_keys.append(key)
            for k, v in value.items():
                if v is not None:
                    add_keys[key + "['" + k + "']"] = v
        elif isinstance(value, (date, datetime, timedelta)):
            attributes[key] = str(value)
        elif value is None:
            remove_keys.append(key)
        elif not isinstance(
            value,
            (
                str,
                int,
                float,
                complex,
                list,
                tuple,
                range,
                dict,
                set,
                frozenset,
                bool,
                bytes,
                bytearray,
                memoryview,
            ),
        ):
            remove_keys.append(key)

    for key in remove_keys:
        attributes.pop(key)
    attributes.update(add_keys)

    return attributes


def resource2dict(item, exclude_private=True, graph=None) -> Dict:
    out = get_resource_attributes(item, exclude_private=exclude_private, keep_data_structures=True)
    cloud = item.cloud(graph)
    account = item.account(graph)
    region = item.region(graph)
    location = item.location(graph)
    zone = item.zone(graph)
    out["cloud_id"] = cloud.id
    out["account_id"] = account.id
    out["region_id"] = region.id
    out["location_id"] = location.id
    out["zone_id"] = zone.id
    out["cloud_name"] = cloud.name
    out["account_name"] = account.name
    out["region_name"] = region.name
    out["location_name"] = location.name
    out["zone_name"] = zone.name
    out["event_log"] = item.event_log
    out["predecessors"] = [i.chksum for i in item.predecessors(graph)]
    out["successors"] = [i.chksum for i in item.successors(graph)]
    return out


def type_str(o):
    cls = o.__class__
    module = cls.__module__
    if module == "builtins":
        return cls.__qualname__
    return module + "." + cls.__qualname__


class defaultlist(list):  # noqa: N801
    def __init__(self, func: Callable) -> None:
        self._func = func

    def _fill(self, index: int) -> None:
        while len(self) <= index:
            self.append(self._func())

    def __setitem__(self, index: int, value: Any) -> None:
        self._fill(index)
        list.__setitem__(self, index, value)

    def __getitem__(self, index: int) -> Any:
        self._fill(index)
        return list.__getitem__(self, index)


class ResourceChanges:
    def __init__(self, node) -> None:
        self.node = node
        self.reported = set()
        self.desired = set()
        self.metadata = set()
        self.changed = False

    def add(self, property: str) -> None:
        if property in ("tags"):
            self.reported.add(property)
        elif property in ("clean"):
            self.desired.add(property)
        elif property in ("cleaned", "protected"):
            self.metadata.add(property)
        elif property == "log":
            pass
        else:
            raise ValueError(f"Unknown property {property}")
        self.changed = True

    def get(self) -> Dict:
        changes = {}
        for section in ("reported", "desired", "metadata"):
            for attribute in getattr(self, section, []):
                if section not in changes:
                    changes[section] = {}
                try:
                    changes[section][attribute] = getattr(self.node, attribute)
                except AttributeError:
                    log.error(f"Resource {self.node.rtdname} has no attribute {attribute}")
        if len(self.node.event_log) > 0:
            if "metadata" not in changes:
                changes[section] = {}
            changes["metadata"]["event_log"] = self.node.str_event_log
        return changes


def get_local_ip_addresses(
    *,
    include_loopback: bool = True,
    san_ip_addresses: Optional[List[str]] = None,
    connect_to_ips: Optional[List[str]] = None,
) -> List[str]:
    ips = set()
    if connect_to_ips is None:
        connect_to_ips = ["8.8.8.8", "2001:4860:4860::8888"]
    if include_loopback:
        ips.add("127.0.0.1")
        ips.add("::1")

    try:
        local_address = socket.gethostbyname(socket.gethostname())
    except Exception:
        pass
    else:
        ips.add(local_address)

    for dst_ip in connect_to_ips:
        try:
            af_inet = socket.AF_INET6 if ":" in dst_ip else socket.AF_INET
            s = socket.socket(af_inet, socket.SOCK_DGRAM)
            s.connect((dst_ip, 53))
            local_address = s.getsockname()[0]
        except Exception:
            pass
        else:
            ips.add(local_address)

    if isinstance(san_ip_addresses, list):
        ips.update(san_ip_addresses)
    return list(ips)


def get_local_hostnames(
    *,
    include_loopback: bool = True,
    san_ip_addresses: Optional[List[str]] = None,
    san_dns_names: Optional[List[str]] = None,
    connect_to_ips: Optional[List[str]] = None,
) -> List[str]:
    hostnames = set()
    if include_loopback:
        hostnames.add("localhost")

    try:
        local_hostname = socket.gethostname()
    except Exception:
        pass
    else:
        hostnames.add(local_hostname)

    for ip in get_local_ip_addresses(
        include_loopback=include_loopback,
        connect_to_ips=connect_to_ips,
        san_ip_addresses=san_ip_addresses,
    ):
        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except Exception:
            pass
        else:
            hostnames.add(hostname)

    if isinstance(san_dns_names, list):
        hostnames.update(san_dns_names)
    return list(hostnames)


def ordinal(num: int) -> str:
    suffix = "tsnrhtdd"[(num // 10 % 10 != 1) * (num % 10 < 4) * num % 10 :: 4]
    return f"{num}{suffix}"


def num_default_threads(num_min_threads: int = 4) -> int:
    count = num_min_threads
    try:
        # try to get the number of usable cores first
        count = len(os.sched_getaffinity(0))
    except AttributeError:
        try:
            count = cpu_count()
        except Exception:
            pass
    if not isinstance(count, int):
        count = num_min_threads
    return max(count, num_min_threads)


# via vmware/pyvcloud/vcd/utils.py
def _badpath(path: str, base: str) -> bool:
    # joinpath will ignore base if path is absolute
    return not os.path.realpath(os.path.abspath(os.path.join(base, path))).startswith(base)


def _badlink(info: TarInfo, base: str) -> bool:
    # Links are interpreted relative to the directory containing the link
    tip = os.path.realpath(os.path.abspath(os.path.join(base, os.path.dirname(info.name))))
    return _badpath(info.linkname, base=tip)


def component_version(component: str = "resotolib") -> str:
    return pkg_resources.get_distribution(component).version


def update_check(
    package_name: str = "resotolib",
    current_version: Optional[str] = None,
    no_prerelease: bool = True,
    github_project: str = "someengineering/resoto",
) -> Optional[str]:
    """Check for new Resoto releases.

    :param package_name: The name of the Python package to retrieve the version number for.
    :param current_version: Alternatively define a version number to check against.
    :param no_prerelease: If True, only stable releases will be considered.
    :param github_project: The name of the GitHub project to check for new releases.
    :return: None if no new release was found or an info string if a new release was found.
    """
    if current_version is None:
        current_version = component_version(package_name)

    # We are assuming that there is a stable release within the first 100 releases returned.
    # If that is not the case need to implement paging.
    releases_uri = f"https://api.github.com/repos/{github_project}/releases?per_page=100"
    headers = {"Accept": "application/vnd.github.v3+json"}
    releases_response = requests.get(releases_uri, headers=headers)
    if releases_response.status_code != 200:
        raise RuntimeError(f"Unable to get releases from {releases_uri}:" f" {releases_response.status_code}")
    latest_version = None
    latest_version_ctime = None
    for release in releases_response.json():
        release_tag = release["tag_name"]
        release_date = make_valid_timestamp(datetime.strptime(release["published_at"], "%Y-%m-%dT%H:%M:%SZ"))
        if not no_prerelease or not pkg_resources.parse_version(release_tag).is_prerelease:
            latest_version = release_tag
            latest_version_ctime = release_date
            break

    if latest_version is None:
        release_kind = "stable " if no_prerelease else ""
        raise RuntimeError(f"Unable to find a {release_kind}release for {github_project}")

    # If the current version is equal or newer than the remote version return None
    if pkg_resources.parse_version(current_version) >= pkg_resources.parse_version(latest_version):
        return None

    msg = f"Current version {current_version} is out of date. Latest version is {latest_version}!"

    current_release_uri = f"https://api.github.com/repos/someengineering/resoto/releases/tags/{current_version}"
    current_release_response = requests.get(current_release_uri, headers=headers)
    if current_release_response.status_code == 200:
        current_version_ctime = make_valid_timestamp(
            datetime.strptime(current_release_response.json()["published_at"], "%Y-%m-%dT%H:%M:%SZ")
        )
        current_version_age = latest_version_ctime - current_version_ctime
        msg = (
            f"Current version {current_version} is {current_version_age.days} days out of date."
            f" Latest version is {latest_version}!"
        )

    return msg


def safe_members_in_tarfile(tarfile: TarFile) -> List:
    base = os.path.realpath(os.path.abspath((".")))
    basename = os.path.basename(tarfile.name)
    result = []
    for tar_info in tarfile.getmembers():
        if _badpath(tar_info.name, base):
            log.error(f"Error in {basename}, {tar_info.name} is blocked: illegal path")
        elif tar_info.issym() and _badlink(tar_info, base):
            log.error(f"Error in {basename}, {tar_info.name} is blocked:" f" symlink to {tar_info.linkname}")
        elif tar_info.islnk() and _badlink(tar_info, base):
            log.error(f"Error in {basename}, {tar_info.name} is blocked:" f" hard link to {tar_info.linkname}")
        else:
            result.append(tar_info)
    return result


def rrdata_as_dict(record_type: str, record_data: str) -> Dict:
    record_type = record_type.upper()
    rrdata = {}
    record_elements = []
    if record_type not in ("TXT"):
        record_data = " ".join(
            "".join([line.split(";")[0] for line in record_data.splitlines()]).replace("(", "").replace(")", "").split()
        )
    if record_type in ("SOA", "MX", "SRV", "CAA"):
        record_elements = record_data.split(" ")

    rrdata["record_value"] = record_data

    if record_type in ("A", "AAAA", "CNAME", "NS", "PTR"):
        pass
    elif record_type in ("TXT"):
        if record_data[0] == '"' and record_data[-1] == '"':
            record_data = record_data[1:-1]
        merge_pattern = '" "'
        merge_pattern_deletions = 0
        merge_pattern_offsets = [m.start() for m in re.finditer(merge_pattern, record_data)]
        for offset in merge_pattern_offsets:
            offset = offset - merge_pattern_deletions * len(merge_pattern)
            if record_data[offset - 1] == "\\":
                continue
            record_data = record_data[0:offset] + record_data[offset + len(merge_pattern) :]
            merge_pattern_deletions += 1

        rrdata["record_value"] = record_data
    elif record_type in ("SOA"):
        rrdata["record_value"] = record_data
        if len(record_elements) != 7:
            raise ValueError(f"Invalid SOA record {record_data}")
        rrdata["record_mname"] = record_elements[0]
        rrdata["record_rname"] = record_elements[1]
        rrdata["record_serial"] = int(record_elements[2])
        rrdata["record_refresh"] = int(record_elements[3])
        rrdata["record_retry"] = int(record_elements[4])
        rrdata["record_expire"] = int(record_elements[5])
        rrdata["record_minimum"] = int(record_elements[6])
    elif record_type in ("MX"):
        if len(record_elements) != 2:
            raise ValueError(f"Invalid MX record {record_data}")
        rrdata["record_priority"] = int(record_elements[0])
        rrdata["record_value"] = record_elements[1]
    elif record_type in ("SRV"):
        if len(record_elements) != 4:
            raise ValueError(f"Invalid SRV record {record_data}")
        rrdata["record_priority"] = int(record_elements[0])
        rrdata["record_weight"] = int(record_elements[1])
        rrdata["record_port"] = int(record_elements[2])
        rrdata["record_value"] = record_elements[3]
    elif record_type in ("CAA"):
        if len(record_elements) != 3:
            raise ValueError(f"Invalid CAA record {record_data}")
        rrdata["record_flags"] = int(record_elements[0])
        rrdata["record_tag"] = record_elements[1]
        rrdata["record_value"] = record_elements[2]

    return rrdata
