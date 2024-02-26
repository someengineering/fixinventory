import pytest

from fixcore.db.reportdb import ReportCheckDb, BenchmarkDb
from fixcore.report.inspector_service import checks_from_file, benchmarks_from_file


@pytest.mark.asyncio
async def test_update_load_delete_checks(report_check_db: ReportCheckDb) -> None:
    some_checks = {a.id: a for a in list(checks_from_file().values())[0:10]}
    # insert some checks
    await report_check_db.update_many(list(some_checks.values()))
    # load them again
    loaded = {sub.id: sub async for sub in report_check_db.all()}
    assert some_checks == loaded
    # delete them
    await report_check_db.delete_many(list(some_checks.keys()))
    assert len([a async for a in report_check_db.keys()]) == 0


@pytest.mark.asyncio
async def test_update_load_delete_benchmarks(benchmark_db: BenchmarkDb) -> None:
    some_benchmarks = {a.id: a for a in list(benchmarks_from_file().values())[0:2]}
    # insert some checks
    await benchmark_db.update_many(list(some_benchmarks.values()))
    # load them again
    loaded = {sub.id: sub async for sub in benchmark_db.all()}
    assert some_benchmarks == loaded
    # delete them
    await benchmark_db.delete_many(list(some_benchmarks.keys()))
    assert len([a async for a in benchmark_db.keys()]) == 0
