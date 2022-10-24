import hashlib
import os
import random
import re
import socket
import string
import time
from argparse import ArgumentParser
from datetime import date, datetime, timezone, timedelta

try:
    from zoneinfo import ZoneInfo
except ImportError:
    from backports.zoneinfo import ZoneInfo
from tzlocal import get_localzone_name
from functools import wraps
from pprint import pformat
from tarfile import TarFile, TarInfo
from typing import Dict, List, Tuple, Optional, NoReturn
from resotolib.types import DecoratedFn

import pkg_resources
import requests

from resotolib.logger import log


def rnd_str(str_len: int = 10) -> str:
    return "".join(random.choice(string.ascii_uppercase + string.digits) for _ in range(str_len))


UTC_Date_Format = "%Y-%m-%dT%H:%M:%SZ"


def utc() -> datetime:
    return datetime.now(timezone.utc)


def utc_str(dt: datetime = utc()) -> str:
    if dt.tzinfo is not None and dt.tzname() != "UTC":
        offset = dt.tzinfo.utcoffset(dt)
        if offset is not None and offset.total_seconds() != 0:
            dt = (dt - offset).replace(tzinfo=timezone.utc)
    return dt.strftime(UTC_Date_Format)


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


def get_local_tzinfo() -> ZoneInfo:
    zone_name = get_localzone_name()
    if zone_name is None:
        zone_name = "Etc/UTC"
    return ZoneInfo(zone_name)


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
        return utc_str(o)
    elif isinstance(o, Exception):
        return pformat(o)
    raise TypeError(f"Object of type {o.__class__.__name__} is not JSON serializable")


def log_runtime(f: DecoratedFn) -> DecoratedFn:
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


def type_str(o):
    cls = o.__class__
    module = cls.__module__
    if module == "builtins":
        return cls.__qualname__
    return module + "." + cls.__qualname__


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
    # via vmware/pyvcloud/vcd/utils.py
    def badpath(path: str, base: str) -> bool:
        # joinpath will ignore base if path is absolute
        return not os.path.realpath(os.path.abspath(os.path.join(base, path))).startswith(base)

    def badlink(info: TarInfo, base: str) -> bool:
        # Links are interpreted relative to the directory containing the link
        tip = os.path.realpath(os.path.abspath(os.path.join(base, os.path.dirname(info.name))))
        return badpath(info.linkname, base=tip)

    base = os.path.realpath(os.path.abspath((".")))
    basename = os.path.basename(tarfile.name)
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


class NoExitArgumentParser(ArgumentParser):
    def error(self, message: str) -> NoReturn:
        raise AttributeError(f"Could not parse arguments: {message}")

    def exit(self, status: int = 0, message: Optional[str] = None) -> NoReturn:
        msg = message if message else "unknown"
        raise AttributeError(f"Could not parse arguments: {msg}")
