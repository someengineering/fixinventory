from fixcore.db.async_arangodb import AsyncArangoDB
from fixcore.db.entitydb import EntityDb, ArangoEntityDb, EventEntityDb
from fixcore.report import ReportCheck, Benchmark

ReportCheckDb = EntityDb[str, ReportCheck]
EventReportCheckDb = EventEntityDb[str, ReportCheck]

BenchmarkDb = EntityDb[str, Benchmark]
EventBenchmarkDb = EventEntityDb[str, Benchmark]


def report_check_db(db: AsyncArangoDB, collection: str) -> ArangoEntityDb[str, ReportCheck]:
    return ArangoEntityDb(db, collection, ReportCheck, lambda k: k.id)


def benchmark_db(db: AsyncArangoDB, collection: str) -> ArangoEntityDb[str, Benchmark]:
    return ArangoEntityDb(db, collection, Benchmark, lambda k: k.id)
