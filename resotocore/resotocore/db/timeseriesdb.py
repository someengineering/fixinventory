import time
from datetime import timedelta, datetime, timezone
from typing import Optional, List, Set, Union, cast

from attr import evolve

from resotocore.db import arango_query
from resotocore.db.async_arangodb import AsyncArangoDB, AsyncCursor
from resotocore.db.graphdb import GraphDB
from resotocore.db.model import QueryModel
from resotocore.query.model import Predicate
from resotocore.types import Json
from resotocore.util import utc_str


class TimeSeriesDB:
    def __init__(self, db: AsyncArangoDB, collection_name: str, keep_history: timedelta) -> None:
        self.db = db
        self.collection_name = collection_name
        self.keep_history = keep_history

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
        async with await self.db.aql_cursor(qs, bind_vars=bv) as crsr:
            async for v in crsr:
                return cast(int, v)  # The query will return the number of inserted documents
        return 0

    async def load_time_series(
        self,
        name: str,
        start: datetime,
        end: datetime,
        *,
        group_by: Optional[Set[str]] = None,
        filter_by: Optional[List[Predicate]] = None,
        granularity: Optional[Union[timedelta, int]] = None,
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
        if grl < timedelta(hours=1):
            grl = timedelta(hours=1)

        qs, bv = arango_query.load_time_series(self.collection_name, name, start, end, grl, group_by, filter_by)

        def result_trafo(js: Json) -> Json:
            js["at"] = utc_str(datetime.fromtimestamp(js["at"], timezone.utc))
            return js

        async with await self.db.aql_cursor(qs, bind_vars=bv, trafo=result_trafo) as crsr:
            return crsr

    async def create_update_schema(self) -> None:
        if not await self.db.has_collection(self.collection_name):
            await self.db.create_collection(self.collection_name)
        collection = self.db.collection(self.collection_name)
        indexes = {idx["name"]: idx for idx in cast(List[Json], collection.indexes())}
        if "ttl" not in indexes:
            collection.add_ttl_index(["at"], expiry_time=int(self.keep_history.total_seconds()), name="ttl")
        if "access" not in indexes:
            collection.add_persistent_index(["ts", "at"], name="access")

    async def wipe(self) -> bool:
        return await self.db.truncate(self.collection_name)
