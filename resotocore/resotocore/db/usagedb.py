from resotocore.db.async_arangodb import AsyncArangoDB
from resotocore.db.entitydb import EntityDb, ArangoEntityDb
from attrs import frozen
from typing import List, Dict


@frozen
class UsageDatapoint:
    """
    A single datapoint of resource usage.

    id: `str`
        Identifier of the resource as named by the cloud.
    at: `int`
        Timestamp of the datapoint in seconds since epoch.
        Name of the metric.
    v: `Dict[str, List[float]]]`
        Dictionary of metric names to lists of values. The values are `min`, `avg` and `max`.

    """

    at: int
    id: str
    v: Dict[str, List[float]]


ResourceUsageDb = EntityDb[str, UsageDatapoint]


def resource_usage_db(db: AsyncArangoDB, collection: str) -> ArangoEntityDb[str, UsageDatapoint]:
    return ArangoEntityDb(db, collection, UsageDatapoint, lambda d: d.id + str(d.at))
