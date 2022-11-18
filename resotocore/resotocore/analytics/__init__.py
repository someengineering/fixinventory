from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from attrs import define
from datetime import datetime
from typing import Optional, Mapping, List, Union

from resotocore.types import JsonElement
from resotocore.util import utc

log = logging.getLogger(__name__)


class CoreEvent:
    SystemInstalled = "system.installed"
    SystemConfigurationChanged = "system.configuration-changed"
    SystemConfigurationDeleted = "system.configuration-deleted"
    SystemStarted = "system.started"
    SystemStopped = "system.stopped"
    NodeCreated = "graphdb.node-created"
    NodeUpdated = "graphdb.node-updated"
    NodesDesiredUpdated = "graphdb.nodes-desired-updated"
    NodesMetadataUpdated = "graphdb.nodes-metadata-updated"
    NodeDeleted = "graphdb.node-deleted"
    DeferredEdgesUpdated = "graphdb.deferred-edges-updated"
    GraphMerged = "graphdb.graph-merged"
    BatchUpdateGraphMerged = "graphdb.batch-update-graph-merged"
    BatchUpdateCommitted = "graphdb.batch-update-committed"
    BatchUpdateAborted = "graphdb.batch-update-aborted"
    GraphDBWiped = "graphdb.wiped"
    CLICommand = "cli.command"
    Query = "graphdb.query"
    HistoryQuery = "graphdb.query.history"
    ModelInfo = "model.info"
    SubscriberInfo = "subscriber.info"
    WorkerQueueInfo = "worker-queue.info"
    TaskStarted = "task-handler.task-started"
    TaskCompleted = "task-handler.task-completed"
    ClientError = "error.client"
    ServerError = "error.server"
    UsageMetricsTurnedOff = "usage-metrics.turned-off"


@define(frozen=True)
class AnalyticsEvent:
    system: str  # e.g. creator of the event: resotocore, resotoui, resotosh, etc.
    kind: str  # kind of the event. Every kind has a specific set of data and context vars
    context: Mapping[str, JsonElement]  # context properties
    counters: Mapping[str, Union[int, float]]  # all counters of this event
    at: datetime  # time, when this event has been created


class AnalyticsEventSender(ABC):
    events: List[AnalyticsEvent]

    async def core_event(
        self, kind: str, context: Optional[Mapping[str, JsonElement]] = None, **counters: Union[int, float]
    ) -> AnalyticsEvent:
        event = AnalyticsEvent("resotocore", kind, context if context else {}, counters, utc())
        await self.capture([event])
        return event

    @abstractmethod
    async def capture(self, event: List[AnalyticsEvent]) -> None:
        pass

    async def start(self) -> AnalyticsEventSender:
        return self

    async def stop(self) -> None:
        return None


class NoEventSender(AnalyticsEventSender):
    """
    Use this sender to not emit any events other than writing it to the log file.
    """

    async def capture(self, event: Union[AnalyticsEvent, List[AnalyticsEvent]]) -> None:
        log.debug(event)

    async def start(self) -> AnalyticsEventSender:
        log.info("Analytics has been turned off. No insights can be created.")
        return self


class InMemoryEventSender(AnalyticsEventSender):
    """
    This sender is used to collect events happening in other processes as well as for testing purposes.
    """

    def __init__(self) -> None:
        self.events: List[AnalyticsEvent] = []

    async def capture(self, event: List[AnalyticsEvent]) -> None:
        self.events.extend(event)
