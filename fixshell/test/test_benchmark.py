import pytest
from typing import Mapping, Union
from unittest.mock import patch
from fixshell.benchmark import Benchmark, parse_metrics


def test_benchmark_initial_state() -> None:
    benchmark = Benchmark()
    assert benchmark.should_benchmark is False
    assert benchmark.request_started_at is None
    assert benchmark.first_byte_at is None
    assert benchmark.last_byte_at is None
    assert benchmark.time_to_first_byte is None
    assert benchmark.time_to_last_byte is None


@pytest.mark.parametrize("should_benchmark", [True, False])
def test_request_sent(should_benchmark: bool) -> None:
    with patch("time.time", return_value=123456789):
        benchmark = Benchmark(should_benchmark)
        benchmark.request_sent()
        if should_benchmark:
            assert benchmark.request_started_at == 123456789
            assert benchmark.first_byte_at is None
            assert benchmark.last_byte_at is None
        else:
            assert benchmark.request_started_at is None


@pytest.mark.parametrize("should_benchmark", [True, False])
def test_first_byte_received(should_benchmark: bool) -> None:
    with patch("time.time", return_value=123456790):
        benchmark = Benchmark(should_benchmark)
        benchmark.request_sent()
        benchmark.first_byte_received()
        if should_benchmark:
            assert benchmark.first_byte_at == 123456790
        else:
            assert benchmark.first_byte_at is None


@pytest.mark.parametrize("should_benchmark", [True, False])
def test_last_byte_received(should_benchmark: bool) -> None:
    with patch("time.time", side_effect=[123456789, 123456790, 123456795]):
        benchmark = Benchmark(should_benchmark)
        benchmark.request_sent()
        benchmark.first_byte_received()
        benchmark.last_byte_received()
        if should_benchmark:
            assert benchmark.last_byte_at == 123456795
            assert benchmark.time_to_first_byte == 1.0
            assert benchmark.time_to_last_byte == 6.0
        else:
            assert benchmark.last_byte_at is None
            assert benchmark.time_to_first_byte is None
            assert benchmark.time_to_last_byte is None


def test_parse_metrics_integers() -> None:
    input_str = "filtered=10, ignored=20"
    expected_output = {"filtered": 10, "ignored": 20}
    assert parse_metrics(input_str) == expected_output


def test_parse_metrics_floats() -> None:
    input_str = "execution_time=0.002, load_factor=0.75"
    expected_output = {"execution_time": 0.002, "load_factor": 0.75}
    assert parse_metrics(input_str) == expected_output


def test_parse_metrics_non_numeric() -> None:
    input_str = "status=ok, mode=test"
    expected_output = {"status": "ok", "mode": "test"}
    assert parse_metrics(input_str) == expected_output


def test_parse_metrics_mixed_types() -> None:
    input_str = "count=100, rate=0.95, status=active"
    expected_output = {"count": 100, "rate": 0.95, "status": "active"}
    assert parse_metrics(input_str) == expected_output


def test_parse_metrics_empty_string() -> None:
    input_str = ""
    expected_output: Mapping[str, Union[str, float, int]] = {}
    assert parse_metrics(input_str) == expected_output


def test_parse_metrics_special_characters() -> None:
    input_str = "message=Hello World!, error=None"
    expected_output = {"message": "Hello World!", "error": "None"}
    assert parse_metrics(input_str) == expected_output
