from pytest import fixture

from resotocore.analytics import AnalyticsEventSender, NoEventSender, AnalyticsEvent, InMemoryEventSender


@fixture
def event_sender() -> InMemoryEventSender:
    return InMemoryEventSender()
