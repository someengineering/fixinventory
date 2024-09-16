from typing import Optional

from attrs import define
from datetime import datetime
from enum import Enum

from fixcore.core_config import current_git_hash
from fixcore.types import Json

MigrateAlways = False
CurrentDatabaseVersion = 2


@define
class SystemData:
    system_id: str
    created_at: datetime
    db_version: int
    version: Optional[str] = None

    def detect_change(self) -> bool:
        git_hash = current_git_hash()
        return (
            MigrateAlways
            or self.db_version != CurrentDatabaseVersion
            or self.version is None
            or git_hash is None
            or git_hash != self.version
        )


@define
class DatabaseChange:
    previous: Optional[SystemData]
    current: SystemData

    def has_changed(self) -> bool:
        return (
            self.previous is None
            or self.previous.version != self.current.version
            or self.previous.db_version != self.current.db_version
        )


class EstimatedQueryCostRating(Enum):
    simple = 1
    complex = 2
    bad = 3


@define
class EstimatedSearchCost:
    # Absolute number that shows the cost of this query. See rating for an interpreted number.
    estimated_cost: int
    # This is the estimated number of items returned for this query.
    # Please note: it is computed based on query statistics and heuristics and does not reflect the real number.
    estimated_nr_items: int
    # This is the number of available nodes in the graph.
    available_nr_items: int
    # Indicates, if a full collection scan is required.
    # This means, that the query does not take advantage of any indexes!
    full_collection_scan: bool
    # The rating of this query
    rating: EstimatedQueryCostRating


def drop_arango_props(json: Json) -> Json:
    json.pop("_rev", None)
    json.pop("_id", None)
    json.pop("_key", None)
    return json
