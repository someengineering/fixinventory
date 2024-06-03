import pytest
from unittest.mock import patch
from fixshell.benchmark import Benchmark
from typing import Any


def test_benchmark_initial_state() -> None:
    benchmark = Benchmark()
    assert benchmark.should_benchmark == False
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


def test_print_results(capsys: Any) -> None:
    with patch("time.time", side_effect=[100, 101, 105]):
        benchmark = Benchmark(True)
        benchmark.request_sent()
        benchmark.first_byte_received()
        benchmark.last_byte_received()
        benchmark.print_results()
        captured = capsys.readouterr()
        expected_output = (
            "\n┌─────────| Benchmark Results |─────────┐\n"
            "│ Time to first byte:         1000.0 ms │\n"
            "│ Time to last byte:          5000.0 ms │\n"
            "└───────────────────────────────────────┘\n"
        )
        assert captured.out == expected_output
