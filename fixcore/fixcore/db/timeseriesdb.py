import asyncio
import logging
import time
from collections import defaultdict
from contextlib import asynccontextmanager
from datetime import timedelta, datetime, timezone
from functools import partial
from numbers import Number
from typing import Optional, List, Set, Union, cast, Callable, Dict, AsyncIterator, Literal

from attr import evolve, define
from fixcore.core_config import CoreConfig
from fixcore.db import arango_query
from fixcore.db.async_arangodb import AsyncArangoDB, AsyncCursor, AsyncArangoTransactionDB
from fixcore.db.graphdb import GraphDB
from fixcore.db.model import QueryModel
from fixcore.error import ConflictingChangeInProgress
from fixcore.query.model import Predicate
from fixcore.types import Json, JsonElement
from fixcore.util import utc_str, utc, if_set, parse_utc
from fixlib.durations import duration_str

log = logging.getLogger(__name__)
max_delta = timedelta(days=730)
last_run_name = "last_run"


@define(repr=False, str=False)
class TimeSeriesBucket:
    start: timedelta
    end: timedelta
    resolution: timedelta

    def __repr__(self) -> str:
        return f"{duration_str(self.start)}:{duration_str(self.end)}:{duration_str(self.resolution)}"

    def __str__(self) -> str:
        return (
            f"Bucket(start={duration_str(self.start)}, "
            f"end={duration_str(self.end)}, resolution={duration_str(self.resolution)})"
        )


@define
class TimeSeriesMeta:
    name: str
    created_at: datetime
    last_updated: datetime
    downsample_times: Dict[str, datetime]


class TimeSeriesDB:
    def __init__(self, db: AsyncArangoDB, collection_name: str, config: CoreConfig) -> None:
        self.db = db
        self.collection_name = collection_name
        self.meta_db = f"{collection_name}_meta"
        self.names_db = f"{collection_name}_names"
        self.config = config
        self.buckets = self._buckets()
        self.smallest_resolution = min(bucket.resolution for bucket in self.buckets)

    async def __execute_aql(
        self, query: str, bind_vars: Optional[Json] = None, tx: Optional[AsyncArangoTransactionDB] = None
    ) -> List[JsonElement]:
        async with await (tx or self.db).aql_cursor(query, bind_vars=bind_vars) as crsr:
            return [el async for el in crsr]

    async def list_time_series(self) -> List[TimeSeriesMeta]:
        all_ts = cast(List[Json], await self.__execute_aql(f"FOR d IN {self.names_db} return d"))
        return [
            TimeSeriesMeta(
                e["_key"],
                datetime.fromtimestamp(e["created_at"] / 1000.0, timezone.utc),
                datetime.fromtimestamp(e["last_updated"] / 1000.0, timezone.utc),
                {k: datetime.fromtimestamp(v / 1000.0, timezone.utc) for k, v in e.get("downsample_times", {}).items()},
            )
            for e in all_ts
        ]

    async def add_entries(self, name: str, query_model: QueryModel, graph_db: GraphDB, at: Optional[int] = None) -> int:
        query = query_model.query
        model = query_model.model
        assert query.aggregate is not None, "Only aggregate queries are supported for time series."
        assert len(query.aggregate.group_func) == 1, "Only a single group function is supported for time series."
        # make sure the final value is called "v"
        query = evolve(
            query,
            aggregate=evolve(query.aggregate, group_func=[evolve(query.aggregate.group_func[0], as_name="v")]),
        )
        at = at if at is not None else int(time.time())  # only use seconds
        qs, bv = arango_query.create_time_series(QueryModel(query, model), graph_db, self.collection_name, name, at)
        async with self._lock() as locked:
            if not locked:
                raise ConflictingChangeInProgress("Another update is already in progress.")
            result, *_ = cast(List[int], await self.__execute_aql(qs, bv))
            if result > 0:
                # update meta information
                await self.__execute_aql(
                    "UPSERT { _key: @key } "
                    "INSERT { _key: @key, created_at: DATE_NOW(), last_updated: DATE_NOW(), count: @count } "
                    f"UPDATE {{ last_updated: DATE_NOW(), count: @count }} IN `{self.names_db}`",
                    dict(key=name, count=result),
                )
            return result

    async def load_time_series(
        self,
        name: str,
        start: datetime,
        end: datetime,
        *,
        group_by: Optional[Set[str]] = None,
        filter_by: Optional[List[Predicate]] = None,
        granularity: Optional[Union[timedelta, int]] = None,
        trafo: Optional[Callable[[Json], Json]] = None,
        batch_size: Optional[int] = None,
        timeout: Optional[timedelta] = None,
        aggregation: Literal["avg", "sum", "min", "max"] = "avg",
    ) -> AsyncCursor:
        """
        Load time series data.
        :param name: The name of the time series.
        :param start: Filter data after this time.
        :param end: Filter data before this time.
        :param group_by: Combine defined group properties. Only existing group properties can be used.
        :param filter_by: Filter specific group properties by predicate.
        :param granularity: Optional timedelta to retrieve data in a specific granularity.
               The minimum granularity is one hour.
               In case this number is an integer, it is interpreted as the number of steps between start and end.
        :param trafo: Optional transformation function to apply to each result.
        :param batch_size: Optional batch size for the query.
        :param timeout: Timeout for the query to run.
        :param aggregation: The aggregation function to use.
        :return: A cursor to iterate over the time series data.
        """
        assert start < end, "start must be before end"
        assert name, "name must not be empty"
        duration = end - start

        # compute effective granularity
        if isinstance(granularity, int):
            grl = duration / granularity
        elif isinstance(granularity, timedelta):
            grl = granularity
        else:
            grl = duration / 20  # default to 20 datapoints if nothing is specified

        grl = max(grl, timedelta(hours=1))

        qs, bv = arango_query.load_time_series(
            self.collection_name, name, start, end, grl, aggregation, group_by, filter_by
        )

        def result_trafo(js: Json) -> Json:
            js["at"] = utc_str(datetime.fromtimestamp(js["at"], timezone.utc))
            return js

        ttl = cast(Number, int(timeout.total_seconds())) if timeout else None
        async with await self.db.aql_cursor(
            query=qs, bind_vars=bv, batch_size=batch_size or 10_000, ttl=ttl, trafo=trafo or result_trafo
        ) as crsr:
            return crsr

    async def downsample(self, now: Optional[datetime] = None) -> Union[str, Json]:
        def ts_format(ts: str, js: Json) -> Json:
            js["ts"] = ts
            js["at"] = int(js["at"])
            return js

        now = now or utc()
        oldest = now - max_delta
        # check if there is something to do
        last_run = if_set(await self.db.get(self.meta_db, last_run_name), lambda d: parse_utc(d[last_run_name]), oldest)
        if (now - last_run) < self.smallest_resolution:
            return "No changes since last downsample run"
        async with self._lock() as locked:
            if not locked:
                return "Another downsample run is already in progress."
            result: Json = defaultdict(list)
            for ts in await self.list_time_series():
                dst = ts.downsample_times.copy()
                for bucket in self.buckets:
                    ts_bucket_last = ts.downsample_times.get(repr(bucket), oldest)
                    c_start = max(now - bucket.end, ts_bucket_last - bucket.start)
                    c_end = now - bucket.start
                    # Only downsample when the resolution duration is reached
                    if c_end <= c_start or (c_end - c_start) < bucket.resolution or ts.last_updated < c_start:
                        continue
                    if ts_data := [
                        e
                        async for e in await self.load_time_series(
                            ts.name,
                            c_start,
                            c_end,
                            granularity=bucket.resolution,
                            trafo=partial(ts_format, ts.name),
                            batch_size=100_000,  # The values are tiny. Use a large batch size.
                            timeout=timedelta(seconds=60),
                            aggregation="avg",
                        )
                    ]:
                        log.info(f"Compact {ts.name} bucket {bucket} to {len(ts_data)} entries (last={ts_bucket_last})")
                        result[ts.name].append(
                            {
                                "bucket": str(bucket),
                                "start": utc_str(c_start),
                                "end": utc_str(c_end),
                                "data_points": len(ts_data),
                            }
                        )
                        dst[repr(bucket)] = now  # update last downsample time in this bucket
                        async with self.db.begin_transaction(write=[self.collection_name, self.names_db]) as tx:
                            await self.__execute_aql(
                                "FOR a in @@coll FILTER a.ts==@ts and a.at>=@start and a.at<@end REMOVE a IN @@coll",
                                {
                                    "ts": ts.name,
                                    "start": c_start.timestamp(),
                                    "end": c_end.timestamp(),
                                    "@coll": self.collection_name,
                                },
                                tx=tx,
                            )
                            await tx.insert_many(self.collection_name, ts_data)
                            await self.__execute_aql(
                                "UPDATE {_key: @key, downsample_times: @dst} IN @@coll",
                                bind_vars={
                                    "@coll": self.names_db,
                                    "key": ts.name,
                                    "dst": {k: int(v.timestamp() * 1000) for k, v in dst.items()},
                                },
                                tx=tx,
                            )
            # update last run
            await self.db.insert(self.meta_db, {"_key": last_run_name, last_run_name: utc_str(now)}, overwrite=True)
        return result

    async def create_update_schema(self) -> None:
        if not await self.db.has_collection(self.collection_name):
            await self.db.create_collection(self.collection_name)
        collection = self.db.collection(self.collection_name)
        indexes = {idx["name"]: idx for idx in cast(List[Json], collection.indexes())}
        if "ttl" in indexes:
            collection.delete_index("ttl")
        if "access" not in indexes:
            collection.add_persistent_index(["ts", "at"], name="access")
        if not await self.db.has_collection(self.meta_db):
            await self.db.create_collection(self.meta_db)
        # meta collection: store information to handle ts
        collection = self.db.collection(self.meta_db)
        indexes = {idx["name"]: idx for idx in cast(List[Json], collection.indexes())}
        if "ttl" not in indexes:
            collection.add_ttl_index(["expires"], expiry_time=int(timedelta(hours=3).total_seconds()), name="ttl")
        # names collection: store all names of time series
        if not await self.db.has_collection(self.names_db):
            await self.db.create_collection(self.names_db)

    async def wipe(self) -> bool:
        return (
            await self.db.truncate(self.collection_name)
            and await self.db.truncate(self.names_db)
            and await self.db.truncate(self.meta_db)
        )

    @asynccontextmanager
    async def _lock(
        self,
        get_lock: timedelta = timedelta(seconds=30),  # how long to try to get the lock
        lock_for: timedelta = timedelta(minutes=10),  # acquired: how long to hold the lock max
        retry_interval: timedelta = timedelta(seconds=1),  # how long to wait between retries
    ) -> AsyncIterator[bool]:
        now = utc()
        ttl = int((now + lock_for).timestamp())
        deadline = now + get_lock
        flag = True
        while flag and utc() < deadline:
            try:
                # try to insert a document with key __lock__
                await self.db.insert(self.meta_db, dict(_key="__lock__", expires=ttl), sync=True)
            except Exception:
                # could not insert the document. Wait and try again
                await asyncio.sleep(retry_interval.total_seconds())
                continue
            flag = False
            try:
                yield True
            finally:
                await self.db.delete(self.meta_db, "__lock__", ignore_missing=True)
        if flag:
            yield False

    def _buckets(self) -> List[TimeSeriesBucket]:
        result: List[TimeSeriesBucket] = []
        if bs := self.config.timeseries.buckets:
            cfg = sorted(bs, key=lambda b: b.start)
            for a, z in zip(cfg, cfg[1:] + [None]):
                end = timedelta(seconds=z.start) if z else max_delta
                result.append(TimeSeriesBucket(timedelta(seconds=a.start), end, timedelta(seconds=a.resolution)))
        return result
