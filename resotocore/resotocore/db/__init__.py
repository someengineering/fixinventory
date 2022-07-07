from attrs import define
from datetime import datetime
from enum import Enum


@define
class SystemData:
    system_id: str
    created_at: datetime
    db_version: int


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
