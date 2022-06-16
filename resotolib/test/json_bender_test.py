from resotolib.json_bender import StringToUnitNumber, bend, CPUCoresToNumber, MapValue


def test_map_value() -> None:
    assert bend(MapValue(dict(a=1, b=2)), "a") == 1
    assert bend(MapValue(dict(a=1, b=2)), "b") == 2
    assert bend(MapValue(dict(a=1, b=2)), "c") is None
    assert bend(MapValue(dict(a=1, b=2), default=3), "c") == 3


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
