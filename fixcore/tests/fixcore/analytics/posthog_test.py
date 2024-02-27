import pytest

from fixcore.analytics.posthog import PostHogEventSender
from fixcore.db import SystemData
from fixcore.util import utc


@pytest.mark.asyncio
async def test_send_analytics_proper() -> None:
    sd = SystemData("test", utc(), 1, "test-version")
    async with PostHogEventSender(sd, client_flush_interval=0.01, client_retries=0) as sender:
        event = await sender.core_event("test-event")
        assert event.kind == "test-event"
    # reaching this point means: no exception has been thrown, which is the real test


@pytest.mark.asyncio
async def test_send_analytics_no_service() -> None:
    sd = SystemData("test", utc(), 1, "test-version")
    async with PostHogEventSender(
        sd, flush_at=1, host="https://127.0.0.1:54321", client_flush_interval=0.01, client_retries=0
    ) as sender:
        event = await sender.core_event("test-event")
        assert event.kind == "test-event"
    # reaching this point means: no exception has been thrown, which is the real test
