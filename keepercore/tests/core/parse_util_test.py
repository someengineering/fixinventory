from core.parse_util import integer_dp, float_dp


def test_number_parse() -> None:
    assert integer_dp.parse("-123") == -123
    assert integer_dp.parse("123") == 123
    assert integer_dp.parse("+123") == 123
    assert float_dp.parse("-123.321") == -123.321
    assert float_dp.parse("123.321") == 123.321
    assert float_dp.parse("+123.321") == 123.321
