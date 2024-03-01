import unittest
import threading
import time
import copy
import os
from unittest.mock import patch
from datetime import datetime

try:
    from zoneinfo import ZoneInfo
except ImportError:
    from backports.zoneinfo import ZoneInfo
from tempfile import TemporaryDirectory
from fixlib.lock import RWLock
from fixlib.utils import (
    ordinal,
    sha256sum,
    rrdata_as_dict,
    get_local_tzinfo,
    utc_str,
    replace_env_vars,
    merge_json_elements,
    drop_deleted_attributes,
    freeze,
    stdin_generator,
    ensure_bw_compat,
)
from fixlib.baseresources import BaseResource
from attrs import define
from typing import ClassVar
import pytest
import sys
import tempfile
from contextlib import contextmanager
from frozendict import frozendict


class Writer(threading.Thread):
    def __init__(self, buffer_, rw_lock, init_sleep_time, sleep_time, to_write):
        """
        @param buffer_: common buffer_ shared by the readers and writers
        @type buffer_: list
        @type rw_lock: L{RWLock}
        @param init_sleep_time: sleep time before doing any action
        @type init_sleep_time: C{float}
        @param sleep_time: sleep time while in critical section
        @type sleep_time: C{float}
        @param to_write: data that will be appended to the buffer
        """
        threading.Thread.__init__(self)
        self.__buffer = buffer_
        self.__rw_lock = rw_lock
        self.__init_sleep_time = init_sleep_time
        self.__sleep_time = sleep_time
        self.__to_write = to_write
        self.entry_time = None
        """Time of entry to the critical section"""
        self.exit_time = None
        """Time of exit from the critical section"""

    def run(self):
        time.sleep(self.__init_sleep_time)
        self.__rw_lock.writer_acquire()
        self.entry_time = time.time()
        time.sleep(self.__sleep_time)
        self.__buffer.append(self.__to_write)
        self.exit_time = time.time()
        self.__rw_lock.writer_release()


class Reader(threading.Thread):
    def __init__(self, buffer_, rw_lock, init_sleep_time, sleep_time):
        """
        @param buffer_: common buffer shared by the readers and writers
        @type buffer_: list
        @type rw_lock: L{RWLock}
        @param init_sleep_time: sleep time before doing any action
        @type init_sleep_time: C{float}
        @param sleep_time: sleep time while in critical section
        @type sleep_time: C{float}
        """
        threading.Thread.__init__(self)
        self.__buffer = buffer_
        self.__rw_lock = rw_lock
        self.__init_sleep_time = init_sleep_time
        self.__sleep_time = sleep_time
        self.buffer_read = None
        """a copy of a the buffer read while in critical section"""
        self.entry_time = None
        """Time of entry to the critical section"""
        self.exit_time = None
        """Time of exit from the critical section"""

    def run(self):
        time.sleep(self.__init_sleep_time)
        self.__rw_lock.reader_acquire()
        self.entry_time = time.time()
        time.sleep(self.__sleep_time)
        self.buffer_read = copy.deepcopy(self.__buffer)
        self.exit_time = time.time()
        self.__rw_lock.reader_release()


class RWLockTestCase(unittest.TestCase):
    def test_readers_nonexclusive_access(self):
        (buffer_, rw_lock, threads) = self.__init_variables()

        threads.append(Reader(buffer_, rw_lock, 0, 0))
        threads.append(Writer(buffer_, rw_lock, 0.2, 0.4, 1))
        threads.append(Reader(buffer_, rw_lock, 0.3, 0.3))
        threads.append(Reader(buffer_, rw_lock, 0.5, 0))

        self.__start_and_join_threads(threads)

        # The third reader should enter after the second one but it should
        # exit before the second one exits
        # (i.e. the readers should be in the critical section
        # at the same time)

        self.assertEqual([], threads[0].buffer_read)
        self.assertEqual([1], threads[2].buffer_read)
        self.assertEqual([1], threads[3].buffer_read)
        self.assertTrue(threads[1].exit_time <= threads[2].entry_time)
        self.assertTrue(threads[2].entry_time <= threads[3].entry_time)
        self.assertTrue(threads[3].exit_time < threads[2].exit_time)

    def test_writers_exclusive_access(self):
        (buffer_, rw_lock, threads) = self.__init_variables()

        threads.append(Writer(buffer_, rw_lock, 0, 0.4, 1))
        threads.append(Writer(buffer_, rw_lock, 0.1, 0, 2))
        threads.append(Reader(buffer_, rw_lock, 0.2, 0))

        self.__start_and_join_threads(threads)

        # The second writer should wait for the first one to exit

        self.assertEqual([1, 2], threads[2].buffer_read)
        self.assertTrue(threads[0].exit_time <= threads[1].entry_time)
        self.assertTrue(threads[1].exit_time <= threads[2].exit_time)

    def test_writer_priority(self):
        (buffer_, rw_lock, threads) = self.__init_variables()

        threads.append(Writer(buffer_, rw_lock, 0, 0, 1))
        threads.append(Reader(buffer_, rw_lock, 0.1, 0.4))
        threads.append(Writer(buffer_, rw_lock, 0.2, 0, 2))
        threads.append(Reader(buffer_, rw_lock, 0.3, 0))
        threads.append(Reader(buffer_, rw_lock, 0.3, 0))

        self.__start_and_join_threads(threads)

        # The second writer should go before the second and the third reader

        self.assertEqual([1], threads[1].buffer_read)
        self.assertEqual([1, 2], threads[3].buffer_read)
        self.assertEqual([1, 2], threads[4].buffer_read)
        self.assertTrue(threads[0].exit_time < threads[1].entry_time)
        self.assertTrue(threads[1].exit_time <= threads[2].entry_time)
        self.assertTrue(threads[2].exit_time <= threads[3].entry_time)
        self.assertTrue(threads[2].exit_time <= threads[4].entry_time)

    def test_many_writers_priority(self):
        (buffer_, rw_lock, threads) = self.__init_variables()

        threads.append(Writer(buffer_, rw_lock, 0, 0, 1))
        threads.append(Reader(buffer_, rw_lock, 0.1, 0.6))
        threads.append(Writer(buffer_, rw_lock, 0.2, 0.1, 2))
        threads.append(Reader(buffer_, rw_lock, 0.3, 0))
        threads.append(Reader(buffer_, rw_lock, 0.4, 0))
        threads.append(Writer(buffer_, rw_lock, 0.5, 0.1, 3))

        self.__start_and_join_threads(threads)

        # The two last writers should go first -- after the first reader and
        # before the second and the third reader

        self.assertEqual([1], threads[1].buffer_read)
        self.assertEqual([1, 2, 3], threads[3].buffer_read)
        self.assertEqual([1, 2, 3], threads[4].buffer_read)
        self.assertTrue(threads[0].exit_time < threads[1].entry_time)
        self.assertTrue(threads[1].exit_time <= threads[2].entry_time)
        self.assertTrue(threads[1].exit_time <= threads[5].entry_time)
        self.assertTrue(threads[2].exit_time <= threads[3].entry_time)
        self.assertTrue(threads[2].exit_time <= threads[4].entry_time)
        self.assertTrue(threads[5].exit_time <= threads[3].entry_time)
        self.assertTrue(threads[5].exit_time <= threads[4].entry_time)

    @staticmethod
    def __init_variables():
        buffer_ = []
        rw_lock = RWLock()
        threads = []
        return (buffer_, rw_lock, threads)

    @staticmethod
    def __start_and_join_threads(threads):
        for t in threads:
            t.start()
        for t in threads:
            t.join()


@define(eq=False, slots=False)
class SomeTestResource(BaseResource):
    kind: ClassVar[str] = "some_test_resource"

    def __attrs_post_init__(self) -> None:
        super().__attrs_post_init__()
        self.key = None
        self.value = None

    def update_tag(self, key, value):
        self.key = key
        self.value = value
        return True

    def delete(self, graph) -> bool:
        return False


def test_ordinal():
    assert ordinal(1) == "1st"
    assert ordinal(2) == "2nd"
    assert ordinal(3) == "3rd"
    assert ordinal(4) == "4th"
    assert ordinal(11) == "11th"
    assert ordinal(12) == "12th"
    assert ordinal(13) == "13th"
    assert ordinal(21) == "21st"
    assert ordinal(22) == "22nd"
    assert ordinal(23) == "23rd"


def test_sha256sum():
    test_string = b"Hello World!"
    expected_sha256sum = "7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069"
    with TemporaryDirectory() as tmp:
        tmp_file = f"{tmp}/testfile"
        with open(tmp_file, "wb") as f:
            f.write(test_string)
        assert sha256sum(tmp_file) == expected_sha256sum


def test_rrdata_as_dict():
    test_soa1 = """ns.icann.org. noc.dns.icann.org. (
        2020080302  ;Serial
        7200        ;Refresh
        3600        ;Retry
        1209600     ;Expire
        3600        ;Negative response caching TTL
)
"""
    test_soa2 = "ns-1620.awsdns-10.co.uk. awsdns-hostmaster.amazon.com. 1 7200 900 1209600 86400"
    test_txt1 = '"Hello World"'
    test_txt2 = '"foo" "bar"'
    test_txt3 = (
        '"v=spf1 a mx ip4:192.168.0.0/24 ip4:192.168.1.0/24 ip4:192.168.1.0/24'
        " ip4:192.168.1.0/24 ip4:192.168.1.0/24 ip4:192.168.1.0/24 ip4:192.168.1.0/24"
        ' ip4:1" "92.168.1.0/24 ip4:192.168.1.0/24 ip4:192.168.1.0/24'
        ' ip4:192.168.1.0/24 ip4:192.168.1.0/24 ip4:192.168.1.0/24 -all"'
    )
    test_txt4 = r'"Hello \" "World " "this is a test" "of TXT"'
    test_mx = "1 ASPMX.L.GOOGLE.com."
    test_a = "10.0.0.1"
    test_aaaa = "2a05:d014:275:cb00:7dff:602c:d0e7:9c4"
    test_ns = "ns-137-b.gandi.net."
    test_srv = "0 10 443 inventory.fix.security."
    res_soa1 = rrdata_as_dict("SOA", test_soa1)
    res_soa2 = rrdata_as_dict("SOA", test_soa2)
    res_txt1 = rrdata_as_dict("TXT", test_txt1)
    res_txt2 = rrdata_as_dict("TXT", test_txt2)
    res_txt3 = rrdata_as_dict("TXT", test_txt3)
    res_txt4 = rrdata_as_dict("TXT", test_txt4)
    res_mx = rrdata_as_dict("MX", test_mx)
    res_a = rrdata_as_dict("A", test_a)
    res_aaaa = rrdata_as_dict("AAAA", test_aaaa)
    res_ns = rrdata_as_dict("NS", test_ns)
    res_srv = rrdata_as_dict("SRV", test_srv)
    assert res_a["record_value"] == test_a
    assert res_aaaa["record_value"] == test_aaaa
    assert res_ns["record_value"] == test_ns
    assert res_mx["record_value"] == "ASPMX.L.GOOGLE.com."
    assert res_mx["record_priority"] == 1
    assert res_txt1["record_value"] == "Hello World"
    assert res_txt2["record_value"] == "foobar"
    assert res_txt3["record_value"] == (
        "v=spf1 a mx ip4:192.168.0.0/24 ip4:192.168.1.0/24 ip4:192.168.1.0/24"
        " ip4:192.168.1.0/24 ip4:192.168.1.0/24 ip4:192.168.1.0/24"
        " ip4:192.168.1.0/24 ip4:192.168.1.0/24 ip4:192.168.1.0/24"
        " ip4:192.168.1.0/24 ip4:192.168.1.0/24 ip4:192.168.1.0/24"
        " ip4:192.168.1.0/24 -all"
    )
    assert res_txt4["record_value"] == r'Hello \" "World this is a testof TXT'
    assert res_srv["record_priority"] == 0
    assert res_srv["record_weight"] == 10
    assert res_srv["record_port"] == 443
    assert res_srv["record_value"] == "inventory.fix.security."
    assert res_soa1["record_mname"] == "ns.icann.org."
    assert res_soa1["record_rname"] == "noc.dns.icann.org."
    assert res_soa1["record_serial"] == 2020080302
    assert res_soa1["record_refresh"] == 7200
    assert res_soa1["record_retry"] == 3600
    assert res_soa1["record_expire"] == 1209600
    assert res_soa1["record_minimum"] == 3600
    assert res_soa2["record_mname"] == "ns-1620.awsdns-10.co.uk."
    assert res_soa2["record_rname"] == "awsdns-hostmaster.amazon.com."
    assert res_soa2["record_serial"] == 1
    assert res_soa2["record_refresh"] == 7200
    assert res_soa2["record_retry"] == 900
    assert res_soa2["record_expire"] == 1209600
    assert res_soa2["record_minimum"] == 86400


def test_get_local_tzinfo():
    tz = get_local_tzinfo()
    assert isinstance(tz, ZoneInfo)


def test_utc_str():
    dt = datetime(2020, 8, 3, 18, 0, 0)
    assert utc_str(dt) == "2020-08-03T18:00:00Z"
    assert utc_str(dt.replace(tzinfo=ZoneInfo("CET"))) == "2020-08-03T16:00:00Z"
    assert utc_str(dt.replace(tzinfo=ZoneInfo("GMT"))) == "2020-08-03T18:00:00Z"
    assert utc_str(dt.replace(tzinfo=ZoneInfo("US/Eastern"))) == "2020-08-03T22:00:00Z"
    assert utc_str(dt.replace(tzinfo=ZoneInfo("US/Pacific"))) == "2020-08-04T01:00:00Z"


def test_replace_env_vars():
    json = {
        "foo": {
            "foo": "$(BAR) $(BAR)",
            "bar": ["$(BAZ)"],
        },
        "bar-$(BAR)": ["$(BAR)", "$(BAZ)"],
    }
    env = {"BAR": "bar"}
    assert replace_env_vars(json, env) == {
        "foo": {
            "foo": "bar bar",
            "bar": ["$(BAZ)"],
        },
        "bar-$(BAR)": ["bar", "$(BAZ)"],
    }

    assert replace_env_vars(json, env, keep_unresolved=False) == {
        "foo": {
            "foo": "bar bar",
            "bar": [],
        },
        "bar-$(BAR)": ["bar"],
    }


def test_resolve_env_do_not_drop_nulls():
    a = {"a": "foo", "b": None}

    assert replace_env_vars(a, environment={}, keep_unresolved=False) == {"a": "foo", "b": None}
    assert replace_env_vars("$(FOO)", environment={}, keep_unresolved=True) == "$(FOO)"
    assert replace_env_vars("$(FOO)", environment={}, keep_unresolved=False) is None


def test_merge_json_elements():
    a = {"a": {"foo": {"first": "first", "last": "laaaast"}}, "b": {"bar": 123}, "c": [6, 7]}
    b = {"a": {"foo": {"last": "last"}}, "b": {"baz": 456}, "c": [8, 9]}

    assert merge_json_elements(a, b) == {
        "a": {"foo": {"first": "first", "last": "last"}},
        "b": {"bar": 123, "baz": 456},
        "c": [8, 9],
    }

    update = {
        "a": {
            "aa": 1,
            "ab": 2,
        },
        "b": {
            "ba": 3,
            "bb": {
                "bba": 4,
            },
        },
    }
    default = {"b": {"ba": 42}, "c": 2}

    def merge_fn(existing, update):
        if existing is None:
            return None
        return update

    assert merge_json_elements(default, update, merge_fn) == {"b": {"ba": 3}, "c": 2}


def test_do_not_drop_nulls():
    a = {"a": "foo", "b": None}

    b = {}
    assert merge_json_elements(a, b) == {"a": "foo", "b": None}

    c = {"a": "bar", "b": None}
    assert merge_json_elements(a, c) == {"a": "bar", "b": None}

    d = {"a": "bar", "b": "baz"}
    assert merge_json_elements(a, d) == {"a": "bar", "b": "baz"}


def test_drop_deleted_attributes():
    to_be_cleaned = {
        "foo": {
            "foo": "foo bar",
            "bar": ["bar"],
            "baz": "baz",
        },
        "bar": ["bar", "baz"],
        "baz": [1, 2, 3],
        "foobar": {
            "foo": "foo",
        },
    }

    reference = {
        "foo": {
            "foo": "1234",
            "bar": ["1234"],
        },
        "baz": [],
        "foobar": {
            "foo": "1234",
        },
    }

    assert drop_deleted_attributes(to_be_cleaned, reference) == {
        "foo": {
            "foo": "foo bar",
            "bar": ["bar"],
        },
        "baz": [1, 2, 3],
        "foobar": {
            "foo": "foo",
        },
    }


@contextmanager
def replace_stdin(input_data: str):
    with tempfile.TemporaryFile(mode="w+t") as temp_file:
        temp_file.write(input_data)
        temp_file.seek(0)
        original_stdin = sys.stdin
        sys.stdin = temp_file
        try:
            yield
        finally:
            sys.stdin = original_stdin


@pytest.mark.parametrize(
    "input_data, expected_output",
    [
        ("line1\nline2\nline3", ["line1", "line2", "line3"]),
        ("line1\r\nline2\r\nline3", ["line1", "line2", "line3"]),
        ("", []),
    ],
)
def test_sync_stdin_generator(input_data, expected_output):
    with replace_stdin(input_data):
        output = list(stdin_generator())
    assert output == expected_output


def test_freeze():
    tpl = (1, 2, 3)
    # hashable things are not touched
    assert id(tpl) == id(freeze(tpl))
    # dict to frozendict
    flat_dict = {"foo": "bar"}
    assert freeze(flat_dict) == frozendict(flat_dict)
    # nested too
    nested_dict = {"foo": flat_dict}
    assert freeze(nested_dict) == frozendict({"foo": frozendict(flat_dict)})
    # and a list to tupple
    assert freeze([1, 2]) == (1, 2)


def test_ensure_bw_compat_cli_args():
    with patch("sys.argv", ["program_name", "--resotocore-uri", "some_value", "--another-arg"]):
        ensure_bw_compat()
        assert sys.argv == ["program_name", "--fixcore-uri", "some_value", "--another-arg"]


def test_ensure_bw_compat_env_vars_single_replacement():
    with patch.dict("os.environ", {"RESOTOCORE_URI": "123", "OTHER_ENV_VAR": "abc"}):
        ensure_bw_compat()
        assert "FIXCORE_URI" in os.environ
        assert os.environ["FIXCORE_URI"] == "123"
        assert "OTHER_ENV_VAR" in os.environ


def test_ensure_bw_compat_env_vars_multiple_replacements():
    with patch.dict("os.environ", {"RESOTOWORKER_RESOTOCORE_URI": "123"}):
        ensure_bw_compat()
        assert "FIXWORKER_FIXCORE_URI" in os.environ
        assert os.environ["FIXWORKER_FIXCORE_URI"] == "123"


def test_ensure_bw_compat_no_changes_needed():
    with patch("sys.argv", ["program_name", "--another-arg"]), patch.dict("os.environ", {"OTHER_ENV_VAR": "abc"}):
        ensure_bw_compat()
        assert sys.argv == ["program_name", "--another-arg"]
        assert "OTHER_ENV_VAR" in os.environ
