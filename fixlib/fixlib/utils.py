import hashlib
import os
import random
import re
import socket
import string
import sys
import time
from argparse import ArgumentParser
from contextlib import closing
from copy import deepcopy
from datetime import date, datetime, timezone, timedelta
from functools import wraps, cached_property
from tarfile import TarFile, TarInfo
from typing import (
    Dict,
    List,
    Tuple,
    Optional,
    NoReturn,
    Any,
    Mapping,
    Union,
    Callable,
    cast,
    Iterator,
    TypeVar,
    Sequence,
)
from zoneinfo import ZoneInfo

import select
from frozendict import frozendict
from tzlocal import get_localzone_name

from fixlib.logger import log
from fixlib.types import DecoratedFn, JsonElement

T = TypeVar("T")
UTC_Date_Format = "%Y-%m-%dT%H:%M:%SZ"


def rnd_str(str_len: int = 10) -> str:
    return "".join(random.choice(string.ascii_uppercase + string.digits) for _ in range(str_len))


def utc() -> datetime:
    return datetime.now(timezone.utc)


def utc_str(dto: Optional[datetime] = None) -> str:
    dt = dto if dto is not None else utc()
    if dt.tzinfo is not None and dt.tzname() != "UTC":
        offset = dt.tzinfo.utcoffset(dt)
        if offset is not None and offset.total_seconds() != 0:
            dt = (dt - offset).replace(tzinfo=timezone.utc)
    return dt.strftime(UTC_Date_Format)


def parse_utc(date_string: str) -> datetime:
    dt = datetime.fromisoformat(date_string)
    if (
        not dt.tzinfo
        or dt.tzinfo.utcoffset(None) is None
        or dt.tzinfo.utcoffset(None).total_seconds() != 0  # type: ignore
    ):
        dt = dt.astimezone(timezone.utc)
    return dt


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


def get_local_tzinfo() -> ZoneInfo:
    zone_name = get_localzone_name()
    if zone_name is None:
        zone_name = "Etc/UTC"
    return ZoneInfo(zone_name)


def chunks(items: List[T], n: int) -> Iterator[List[T]]:
    """Split a list of items into multiple lists of size n and yield each chunk"""
    for s in range(0, len(items), n):
        e = s + n
        yield items[s:e]


def unset_cached_properties(obj: Any) -> None:
    """
    Reset all cached properties of an object.
    Successive calls to the property will recompute the value.
    :param obj: the object with cached properties.
    """
    cls = obj.__class__
    for a in dir(obj):
        attr_a = getattr(cls, a, cls)
        if isinstance(attr_a, cached_property):
            obj.__dict__.pop(attr_a.attrname, None)


# via https://stackoverflow.com/a/1094933
def iec_size_format(byte_size: float) -> str:
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


def log_runtime(f: DecoratedFn) -> DecoratedFn:
    @wraps(f)
    def timer(*args: Any, **kwargs: Any) -> Any:
        start = time.time()
        ret = f(*args, **kwargs)
        runtime = time.time() - start
        args_str = ", ".join([repr(arg) for arg in args])
        kwargs_str = ", ".join([f"{k}={repr(v)}" for k, v in kwargs.items()])
        if len(args) > 0 and len(kwargs) > 0:
            args_str += ", "
        log.debug(f"Runtime of {f.__name__}({args_str}{kwargs_str}): {runtime:.3f} seconds")
        return ret

    return timer  # type: ignore


def except_log_and_pass(do_raise: Optional[Tuple[Any]] = None) -> Callable[..., Any]:
    do_raise_tuple = do_raise if do_raise is not None else ()

    def acallable(f: Callable[..., Any]) -> Callable[..., Any]:
        @wraps(f)
        def catch_and_log(*args: Any, **kwargs: Any) -> Any:
            try:
                return f(*args, **kwargs)
            except do_raise_tuple:
                raise
            except Exception:
                args_str = ", ".join([repr(arg) for arg in args])
                kwargs_str = ", ".join([f"{k}={repr(v)}" for k, v in kwargs.items()])
                if len(args) > 0 and len(kwargs) > 0:
                    args_str += ", "
                log.exception(f"Caught exception in {f.__name__}({args_str}{kwargs_str})")

        return catch_and_log

    return acallable


resource_attributes_blacklist = ["event_log"]


def get_resource_attributes(
    resource: Any, exclude_private: bool = True, keep_data_structures: bool = False
) -> Dict[str, Any]:
    attributes = dict(resource.__dict__)
    attributes["kind"] = resource.kind

    for attr_name in dir(resource):
        if exclude_private and attr_name.startswith("_"):
            continue
        attr_type = getattr(type(resource), attr_name, None)
        if isinstance(attr_type, property):
            attributes[attr_name] = getattr(resource, attr_name, None)

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


def type_str(o: Any) -> str:
    cls = o.__class__
    module = str(cls.__module__)
    if module == "builtins":
        return str(cls.__qualname__)
    return module + "." + str(cls.__qualname__)


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
            with socket.socket(af_inet, socket.SOCK_DGRAM) as s:
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


def safe_members_in_tarfile(tarfile: TarFile) -> List[Any]:
    # via vmware/pyvcloud/vcd/utils.py
    def badpath(path: str, base: str) -> bool:
        # joinpath will ignore base if path is absolute
        return not os.path.realpath(os.path.abspath(os.path.join(base, path))).startswith(base)

    def badlink(info: TarInfo, base: str) -> bool:
        # Links are interpreted relative to the directory containing the link
        tip = os.path.realpath(os.path.abspath(os.path.join(base, os.path.dirname(info.name))))
        return badpath(info.linkname, base=tip)

    base = os.path.realpath(os.path.abspath((".")))
    basename = os.path.basename(tarfile.name)  # type: ignore
    result = []
    for tar_info in tarfile.getmembers():
        if badpath(tar_info.name, base):
            log.error(f"Error in {basename}, {tar_info.name} is blocked: illegal path")
        elif tar_info.issym() and badlink(tar_info, base):
            log.error(f"Error in {basename}, {tar_info.name} is blocked:" f" symlink to {tar_info.linkname}")
        elif tar_info.islnk() and badlink(tar_info, base):
            log.error(f"Error in {basename}, {tar_info.name} is blocked:" f" hard link to {tar_info.linkname}")
        else:
            result.append(tar_info)
    return result


def rrdata_as_dict(record_type: str, record_data: str) -> Dict[str, Any]:
    record_type = record_type.upper()
    rrdata: Dict[str, Any] = {}
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


class NoExitArgumentParser(ArgumentParser):
    def error(self, message: str) -> NoReturn:
        raise AttributeError(f"Could not parse arguments: {message}")

    def exit(self, status: int = 0, message: Optional[str] = None) -> NoReturn:
        msg = message if message else "unknown"
        raise AttributeError(f"Could not parse arguments: {msg}")


env_var_substitution_pattern = re.compile(r"\$\((\w+)\)")


def is_env_var_string(obj: Any) -> bool:
    is_string = isinstance(obj, str)
    if not is_string:
        return False
    has_env_var = re.search(env_var_substitution_pattern, obj) is not None
    return has_env_var


def replace_env_vars(elem: JsonElement, environment: Mapping[str, str], keep_unresolved: bool = True) -> JsonElement:
    # a special marker to avoid removing nulls
    class UnresolvedEnvVar:
        pass

    # no need to have many instances of this
    Unresolved = UnresolvedEnvVar()

    def replace_env_vars_helper(
        elem: JsonElement, environment: Mapping[str, str], keep_unresolved: bool, path: List[Union[str, int]]
    ) -> Union[JsonElement, UnresolvedEnvVar]:
        if isinstance(elem, dict):
            replaced_dict = {
                k: replace_env_vars_helper(v, environment, keep_unresolved, path + [k]) for k, v in elem.items()
            }
            without_unresolved_dict = {k: v for k, v in replaced_dict.items() if v is not Unresolved}
            return without_unresolved_dict
        elif isinstance(elem, list):
            replaced_list = [
                replace_env_vars_helper(v, environment, keep_unresolved, path + [i]) for i, v, in enumerate(elem)
            ]
            without_unresolved_list = [v for v in replaced_list if v is not Unresolved]
            return without_unresolved_list
        elif isinstance(elem, str):
            str_value = elem
            for match in re.finditer(env_var_substitution_pattern, elem):
                env_var_name = match.group(1)
                if env_var_found := environment.get(env_var_name):
                    str_value = str_value.replace(match.group(0), env_var_found)
                elif keep_unresolved:
                    pass
                else:
                    conf_path = ""

                    for idx, part in enumerate(path):
                        if idx == 0:
                            conf_path += str(part)
                        else:
                            conf_path += f"[{part}]" if isinstance(part, int) else f".{part}"
                    message = f"The environment variable `{env_var_name}` is not defined "
                    message += "in configuration at path {conf_path}. "
                    message += f"Please set the environment variable `{env_var_name}` or adjust the configuration. "
                    message += "You can also use the --override option to override the config value."
                    log.warning(f"Environment variable substitution failed: {message}")

                    return Unresolved

            return str_value
        elif isinstance(elem, UnresolvedEnvVar):
            # let's not leak that outside
            return None
        else:
            return elem

    replaced = replace_env_vars_helper(elem, environment, keep_unresolved, [])
    if isinstance(replaced, UnresolvedEnvVar):
        return None
    else:
        return replaced


def merge_json_elements(
    existing: JsonElement,
    update: JsonElement,
    merge_strategy: Callable[[JsonElement, JsonElement], JsonElement] = lambda existing_val, update_val: update_val,
) -> JsonElement:
    """
    Merges two JsonElements accorting to merge strategy.
    By default recursively traverses Dicts and prefers the new value
    """
    if isinstance(existing, dict) and isinstance(update, dict):
        output = deepcopy(existing)
        for update_key, update_value in update.items():
            existing_value = existing.get(update_key)
            if isinstance(update_value, dict) and isinstance(existing_value, dict):
                output[update_key] = merge_strategy(
                    existing_value, merge_json_elements(existing_value, update_value, merge_strategy)
                )
            else:
                merge_result = merge_strategy(existing_value, deepcopy(update_value))
                if merge_result is not None:
                    output[update_key] = merge_result

    else:
        return merge_strategy(existing, deepcopy(update))

    return output


def drop_deleted_attributes(to_be_cleaned: JsonElement, reference: JsonElement) -> JsonElement:
    """Removes all attributes from the to_be_cleaned json that are not present in the reference json."""

    # if we see a primitive type, return immediately
    if not isinstance(to_be_cleaned, (list, dict)):
        return to_be_cleaned

    # should never throw an error if the implementation is correct
    assert isinstance(to_be_cleaned, type(reference))

    # found a list, try to traverse it
    if isinstance(to_be_cleaned, list):
        reference = cast(List[JsonElement], reference)  # ensured by the assert above

        # the reference can only be smaller than to_be_cleaned if it contained env_var_strings
        # and they failed to be resolved. in that case we can use to_be_cleaned as a reference
        if len(to_be_cleaned) > len(reference):
            new_reference = to_be_cleaned
        else:
            new_reference = reference

        return [drop_deleted_attributes(tbc, ref) for tbc, ref in zip(to_be_cleaned, new_reference)]

    if isinstance(to_be_cleaned, dict):
        reference = cast(Dict[str, JsonElement], reference)

        return {k: drop_deleted_attributes(v, reference[k]) for k, v in to_be_cleaned.items() if k in reference}

    # should never happen if mypy is happy
    raise ValueError(f"Unexpected type {type(to_be_cleaned)}")


def get_free_port() -> int:
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as tcp:
        tcp.bind(("", 0))
        tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        return tcp.getsockname()[1]  # type: ignore


def stdin_generator() -> Iterator[str]:
    if select.select([sys.stdin], [], [], 0.0)[0]:
        for line in iter(sys.stdin.readline, ""):
            yield line.rstrip("\r\n")


# makes things hashable
def freeze(elem: JsonElement) -> Any:
    # check if can be hashed first
    try:
        hash(elem)
        return elem
    except TypeError:
        pass

    if isinstance(elem, Sequence):
        return tuple([freeze(v) for v in elem])
    elif isinstance(elem, Mapping):
        return frozendict({k: freeze(v) for k, v in elem.items()})
    else:
        return elem


def ensure_bw_compat() -> None:
    for i, arg in enumerate(sys.argv):
        if arg.startswith("--resoto"):
            sys.argv[i] = "--fix" + arg[len("--resoto") :]

    old_env_vars = [key for key in os.environ if key.startswith("RESOTO")]
    for old_env_var in old_env_vars:
        new_env_var = old_env_var.replace("RESOTO", "FIX")
        os.environ[new_env_var] = os.environ.pop(old_env_var)
