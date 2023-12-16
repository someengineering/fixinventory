from datetime import datetime, timedelta, timezone
from typing import Any, List

from resotocore.db.graphdb import GraphDB
from resotocore.db.model import QueryModel
from resotocore.db.timeseriesdb import TimeSeriesDB
from resotocore.model.model import Model
from resotocore.query.model import P
from resotocore.query.query_parser import parse_query
from resotocore.types import Json


async def test_create_time_series(timeseries_db: TimeSeriesDB, foo_model: Model, filled_graph_db: GraphDB) -> None:
    await timeseries_db.wipe()  # clean up
    qm = QueryModel(parse_query("aggregate(reported.some_int, reported.identifier: sum(1)): is(foo)"), foo_model)
    # create timeseries at 10 different points in time
    for a in range(10):
        await timeseries_db.add_entries("test", qm, filled_graph_db, at=3600 * a)
    begin = datetime.fromtimestamp(0)
    after5h = datetime.fromtimestamp(3600 * 5 - 1)

    async def load_ts(**kwargs: Any) -> List[Json]:
        return [t async for t in await timeseries_db.load_time_series(**kwargs)]

    ## check start end is working
    # first 5 hours with 10 entries each: 50 entries
    assert len(await load_ts(name="test", start=begin, end=datetime.fromtimestamp(3600 * 1 - 1))) == 10
    assert len(await load_ts(name="test", start=begin, end=datetime.fromtimestamp(3600 * 2 - 1))) == 20
    assert len(await load_ts(name="test", start=begin, end=datetime.fromtimestamp(3600 * 4 - 1))) == 40
    assert len(await load_ts(name="test", start=datetime.fromtimestamp(3600 * 4), end=after5h)) == 10

    ## check granularity is working
    # first 5 hours with 10 entries each: 50 entries
    assert len(await load_ts(name="test", start=begin, end=after5h)) == 50
    # first 5 hours with 10 entries each: granularity 2 hours: at 0, 2 and 4: 30 entries
    assert len(await load_ts(name="test", start=begin, end=after5h, granularity=timedelta(hours=2))) == 30
    # first 5 hours with 10 entries each: granularity 5 hours: at 0: 10 entries
    assert len(await load_ts(name="test", start=begin, end=after5h, granularity=timedelta(hours=5))) == 10

    ## check group_by is working
    # some_int is the same for all entries: one every hour: 5 entries
    assert len(await load_ts(name="test", start=begin, end=after5h, group_by=["some_int"])) == 5
    # identifier is different for each entry: 50 entries
    assert len(await load_ts(name="test", start=begin, end=after5h, group_by=["identifier"])) == 50
    # do not use any groups: 5 entries
    assert len(await load_ts(name="test", start=begin, end=after5h, group_by=[])) == 5

    ## check filter_by is working
    # some_int is the same for all entries: one every hour: 5 entries
    assert len(await load_ts(name="test", start=begin, end=after5h, filter_by=[(P("identifier").eq("1"))])) == 5


async def test_compact_time_series(timeseries_db: TimeSeriesDB, foo_model: Model, filled_graph_db: GraphDB) -> None:
    await timeseries_db.wipe()  # clean up
    qm = QueryModel(parse_query("aggregate(reported.some_int, reported.identifier: sum(1)): is(foo)"), foo_model)
    now = datetime(2023, 12, 1, tzinfo=timezone.utc)

    async def create_ts(before_now: timedelta, granularity: timedelta, number_of_entries: int) -> None:
        start = now - before_now
        for a in range(number_of_entries):
            await timeseries_db.add_entries("test", qm, filled_graph_db, at=int((start - a * granularity).timestamp()))

    # after 180 days, we want a 3-day resolution: 24 daily entries --> reduce by factor 3
    await create_ts(timedelta(days=181), timedelta(days=1), 24)
    # after 30 days, we want a 1-day resolution: 24 entries every 4 hour --> reduce by factor 4
    await create_ts(timedelta(days=31), timedelta(hours=4), 24)
    # after 2 days we want a 4-hour resolution: 24 entries --> reduce by factor 4
    await create_ts(timedelta(days=3), timedelta(hours=1), 24)
    # after now we want a 1-hour resolution: 24 entries --> no reduction
    await create_ts(timedelta(), timedelta(hours=1), 24)

    assert timeseries_db.db.collection(timeseries_db.collection_name).count() == 960
    assert await timeseries_db.downsample(now) == {
        "test": [
            {
                "bucket": "Bucket(start=2d, end=30d, resolution=4h)",
                "start": "2023-11-01T00:00:00Z",
                "end": "2023-11-29T00:00:00Z",
                "data_points": 70,
            },
            {
                "bucket": "Bucket(start=30d, end=5mo25d, resolution=1d)",
                "start": "2023-06-04T00:00:00Z",
                "end": "2023-11-01T00:00:00Z",
                "data_points": 50,
            },
            {
                "bucket": "Bucket(start=5mo25d, end=2yr, resolution=3d)",
                "start": "2021-12-01T00:00:00Z",
                "end": "2023-06-04T00:00:00Z",
                "data_points": 80,
            },
        ]
    }
    assert timeseries_db.db.collection(timeseries_db.collection_name).count() == 440
    assert await timeseries_db.downsample(now) == "No changes since last downsample run"
    assert timeseries_db.db.collection(timeseries_db.collection_name).count() == 440
    assert await timeseries_db.downsample(now=now + timedelta(days=27)) == {
        "test": [
            {
                "bucket": "Bucket(start=2d, end=30d, resolution=4h)",
                "start": "2023-11-29T00:00:00Z",
                "end": "2023-12-26T00:00:00Z",
                "data_points": 70,
            },
            {
                "bucket": "Bucket(start=30d, end=5mo25d, resolution=1d)",
                "start": "2023-11-01T00:00:00Z",
                "end": "2023-11-28T00:00:00Z",
                "data_points": 20,
            },
        ]
    }
    assert timeseries_db.db.collection(timeseries_db.collection_name).count() == 220
    assert await timeseries_db.downsample(now=now + timedelta(days=200)) == {
        "test": [
            {
                "bucket": "Bucket(start=5mo25d, end=2yr, resolution=3d)",
                "start": "2023-06-04T00:00:00Z",
                "end": "2023-12-21T00:00:00Z",
                "data_points": 50,
            }
        ]
    }
    assert timeseries_db.db.collection(timeseries_db.collection_name).count() == 130
    assert await timeseries_db.downsample(now=now + timedelta(days=400)) == {}
    assert timeseries_db.db.collection(timeseries_db.collection_name).count() == 130
