from pytest import fixture

from core.analytics import AnalyticsEventSender, NoEventSender, AnalyticsEvent, InMemoryEventSender


@fixture
def event_sender() -> InMemoryEventSender:
    return InMemoryEventSender()
