from resotocore.db.async_arangodb import AsyncArangoDB
from resotocore.db.entitydb import EntityDb, ArangoEntityDb
from attrs import frozen
from typing import List


@frozen
class UsageDatapoint:
    """
    A single datapoint of resource usage.

    id: str
        Unique identifier of the datapoint.
    resource_id: str
        Identifier of the resource as named by the cloud.
    timestamp: int
        Timestamp of the datapoint in seconds since epoch.
    metric_name: str
        Name of the metric.
    values: List[float]
        min, avg, max

    """

    id: str
    resource_id: str
    timestamp: int
    metric_name: str
    values: List[float]


ResourceUsageDb = EntityDb[str, UsageDatapoint]


def resource_usage_db(db: AsyncArangoDB, collection: str) -> ArangoEntityDb[str, UsageDatapoint]:
    return ArangoEntityDb(db, collection, UsageDatapoint, lambda d: d.id)
