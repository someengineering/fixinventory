from __future__ import annotations
import asyncio
import logging
from collections import deque
from datetime import timedelta
from typing import Any, MutableSequence

from posthog import Client

from core.analytics import AnalyticsEventSender, AnalyticsEvent
from core.db import SystemData
from core.util import uuid_str, Periodic


class PostHogEventSender(AnalyticsEventSender):
    """
    This analytics event sender uses PostHog (https://posthog.com) to capture all analytics events.
    """

    def __init__(
        self,
        system_data: SystemData,
        flush_at: int = 10000,
        interval: timedelta = timedelta(minutes=1),
        api_key: str = "phc_rw1AuIY01ER5Go7TAfOVX243zAtG5VfzcyEIseuaN0A",
        host: str = "https://analytics.some.engineering",
        client_flush_interval: float = 0.5,
        client_retries: int = 3,
    ):
        # Note: the client also has the ability to queue events with a flush interval.
        # Sadly: in order to shutdown one has to wait the full interval in worst case!
        # In order to circumvent this behaviour, the queue is maintained here with a configurable interval.
        # In case of shutdown all events are flushed directly and the system is stopped.
        self.client = Client(
            api_key=api_key, host=host, flush_interval=client_flush_interval, max_retries=client_retries, gzip=True
        )
        self.uid = uuid_str()  # create a unique id for this instance run
        self.client.identify(system_data.system_id, {"run_id": self.uid, "created_at": system_data.created_at})
        self.system_data = system_data
        self.queue: MutableSequence[AnalyticsEvent] = deque()
        self.flush_at = flush_at
        self.flusher = Periodic("flush_analytics", self.flush, interval)
        self.lock = asyncio.Lock()

    async def capture(self, event: AnalyticsEvent) -> None:
        async with self.lock:
            self.queue.append(event)

        if len(self.queue) >= self.flush_at:
            await self.flush()

    async def flush(self) -> None:
        async with self.lock:
            for event in self.queue:
                self.client.capture(
                    distinct_id=self.system_data.system_id,
                    event=event.kind,
                    properties={**event.context, **event.counters, "run_id": self.uid},  # type: ignore
                    timestamp=event.at,
                )
            self.queue.clear()

    async def __aenter__(self) -> PostHogEventSender:
        await self.flusher.start()
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        await self.flusher.stop()
        await self.flush()
        self.client.shutdown()
        logging.info("AnalyticsEventSender closed.")
