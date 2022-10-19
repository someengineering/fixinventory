from __future__ import annotations

import asyncio
import logging
from collections import deque
from datetime import timedelta, datetime
from typing import Any, MutableSequence, Optional, List

from aiohttp import ClientSession
from posthog import Client

from resotocore.analytics import AnalyticsEventSender, AnalyticsEvent
from resotocore.db import SystemData
from resotocore.util import uuid_str, Periodic, utc

log = logging.getLogger(__name__)


class PostHogEventSender(AnalyticsEventSender):
    """
    This analytics event sender uses PostHog (https://posthog.com) to capture all analytics events.
    """

    def __init__(
        self,
        system_data: SystemData,
        flush_at: int = 10000,
        interval: timedelta = timedelta(minutes=1),
        host: str = "https://analytics.some.engineering",
        client_flush_interval: float = 0.5,
        client_retries: int = 3,
    ):
        """
        Create a new PostHog sender.
        :param system_data: information about the current executing system.
        :param flush_at: number of events that can queue up, before the queue is flushed directly.
        :param interval: the frequency when the queue should be flushed.
        :param host: Only here for testing purposes.
        :param client_flush_interval: only here for testing purposes.
        :param client_retries: only here for testing purposes.
        """
        # Note: the client also has the ability to queue events with a flush interval.
        # Sadly: in order to shutdown one has to wait the full interval in worst case!
        # In order to circumvent this behaviour, the queue is maintained here with a configurable interval.
        # In case of shutdown all events are flushed directly and the system is stopped.
        # Note 2: the public api-key is fetched on demand
        self.client = Client(
            api_key="n/a", host=host, flush_interval=client_flush_interval, max_retries=client_retries, gzip=True
        )
        self.run_id = uuid_str()  # create a unique id for this instance run
        self.system_data = system_data
        self.queue: MutableSequence[AnalyticsEvent] = deque()
        self.flush_at = flush_at
        self.flusher = Periodic("flush_analytics", self.flush, interval)
        self.lock = asyncio.Lock()
        self.last_fetched: Optional[datetime] = None
        self.session: Optional[ClientSession] = None

    async def capture(self, event: List[AnalyticsEvent]) -> None:
        """
        Capture a single event by adding it to an internal queue.
        The queue is flushed by a scheduled function.
        Only in the rare case when the queue size reached its maximum the queue will be flushed directly.
        """
        async with self.lock:
            self.queue.extend(event)

        if len(self.queue) >= self.flush_at:
            await self.flush()

    async def refresh_public_api_key(self) -> None:
        """
        The API key is public but not static, so we need to refresh it periodically.
        """
        try:
            if not self.session:
                self.session = ClientSession()
            async with self.session.get("https://cdn.some.engineering/posthog/public_api_key") as resp:
                api_key = (await resp.text()).strip()
                self.client.api_key = api_key
                for consumer in self.client.consumers:
                    consumer.api_key = api_key
                self.last_fetched = utc()
        except Exception as ex:
            log.debug(f"Could not fetch latest api key. Will use the current one. {ex}")

    async def flush(self) -> None:
        """
        Flush all events to the posthog server.
        """
        # check, if we need to fetch or refresh the public api key
        if not self.last_fetched:
            await self.refresh_public_api_key()
            sd = self.system_data
            self.client.identify(sd.system_id, {"run_id": self.run_id, "created_at": sd.created_at})
        elif (utc() - self.last_fetched) > timedelta(hours=1):
            await self.refresh_public_api_key()

        # acquire the lock, send all events to the client and clear the queue
        async with self.lock:
            for event in self.queue:
                self.client.capture(
                    distinct_id=self.system_data.system_id,
                    event=event.kind,
                    properties={
                        **event.context,  # type: ignore
                        **event.counters,  # type: ignore
                        "source": event.system,
                        "run_id": self.run_id,
                    },
                    timestamp=event.at,
                )
            self.queue.clear()

    async def __aenter__(self) -> PostHogEventSender:
        return await self.start()

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        return await self.stop()

    async def start(self) -> PostHogEventSender:
        await self.flusher.start()
        return self

    async def stop(self) -> None:
        await self.flusher.stop()
        await self.flush()
        if self.session:
            await self.session.close()
        self.client.shutdown()
        logging.info("AnalyticsEventSender closed.")
