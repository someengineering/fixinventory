from typing import Callable, Dict, List

from attr import define

from resotocore.model.db_updater import GraphMerger
from resotocore.task.model import Subscriber


@define(eq=True, hash=True, order=True, repr=True, frozen=True)
class TaskDependencies:
    graph_merger: GraphMerger
    subscribers_by_event: Callable[[], Dict[str, List[Subscriber]]]
