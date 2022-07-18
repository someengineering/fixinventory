from datetime import datetime

import pytest

from resotolib.baseresources import InstanceStatus
from resotolib.json_bender import (
    StringToUnitNumber,
    bend,
    CPUCoresToNumber,
    MapValue,
    AsDate,
    Sort,
    S,
    MapEnum,
    StripNones,
    MapDict,
    F,
)


def test_map_value() -> None:
    assert bend(MapValue(dict(a=1, b=2)), "a") == 1
    assert bend(MapValue(dict(a=1, b=2)), "b") == 2
    assert bend(MapValue(dict(a=1, b=2)), "c") is None
    assert bend(MapValue(dict(a=1, b=2), default=3), "c") == 3


def test_map_enum() -> None:
    assert bend(MapEnum(dict(foo=InstanceStatus.BUSY)), "foo") == InstanceStatus.BUSY.value
    assert bend(MapEnum(dict(), InstanceStatus.BUSY), "foo") == InstanceStatus.BUSY.value
    with pytest.raises(AttributeError):
        bend(MapEnum(dict(foo="bla")), "foo")


def test_string_to_unit() -> None:
    assert bend(StringToUnitNumber("B", int), "4041564Ki") == 4138561536

    assert bend(StringToUnitNumber("GB", int), "4041564Ki") == 4
    assert bend(StringToUnitNumber("MB", int), "4041564Ki") == 4138
    assert bend(StringToUnitNumber("KB", int), "4041564Ki") == 4138561
    assert bend(StringToUnitNumber("GiB", int), "4041564Ki") == 3
    assert bend(StringToUnitNumber("MiB", int), "4041564Ki") == 3946
    assert bend(StringToUnitNumber("KiB", int), "4041564Ki") == 4041564

    assert bend(StringToUnitNumber("GiB", int), "2GiB") == 2
    assert bend(StringToUnitNumber("GiB", int), "2048MiB") == 2
    assert bend(StringToUnitNumber("GiB", int), "2097152KiB") == 2
    assert bend(StringToUnitNumber("GiB", int), "2Gi") == 2
    assert bend(StringToUnitNumber("GiB", int), "2048Mi") == 2
    assert bend(StringToUnitNumber("GiB", int), "2097152Ki") == 2


def test_cpu_cores_to_number() -> None:
    assert bend(CPUCoresToNumber(), "1") == 1
    assert bend(CPUCoresToNumber(), 1) == 1
    assert bend(CPUCoresToNumber(), "1000m") == 1
    assert bend(CPUCoresToNumber(), "3500m") == 3.5


def test_as_date() -> None:
    assert bend(AsDate(), "2022-06-07T14:43:49Z") == datetime(2022, 6, 7, 14, 43, 49)
    assert bend(AsDate(), None) is None


def test_sort() -> None:
    assert bend(Sort(S("i")), [{"i": 2}, {"i": 3}, {"i": 1}]) == [{"i": 1}, {"i": 2}, {"i": 3}]


def test_or_else() -> None:
    assert bend(S("a").or_else(S("b")), {"a": 1, "b": 2}) == 1
    assert bend(S("a").or_else(S("b")), {"b": 2}) == 2


def test_strip_nones() -> None:
    assert bend(StripNones(), [1, None, 2, None, None, 3]) == [1, 2, 3]


def test_map_dict() -> None:
    src = {"a": 1, "b": 2}
    assert bend(MapDict(value_bender=F(lambda x: x + 1)), src) == {"a": 2, "b": 3}
    assert bend(MapDict(key_bender=F(lambda x: x + "b")), src) == {"ab": 1, "bb": 2}
    assert bend(MapDict(key_bender=F(lambda x: x + "b"), value_bender=F(lambda x: x + 1)), src) == {"ab": 2, "bb": 3}
