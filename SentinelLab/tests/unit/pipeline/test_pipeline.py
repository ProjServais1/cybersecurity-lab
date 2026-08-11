from collections.abc import Iterator

from sentinellab.models.security_event import (
    CollectorInfo,
    EventCategory,
    EventContext,
    EventType,
    SecurityEvent,
)
from sentinellab.pipeline.pipeline import Pipeline


class FakeCollector:
    def __init__(self, events: list[str]) -> None:
        self.events = events

    def collect(self) -> Iterator[str]:
        yield from self.events


class FakeParser:
    def parse(self, raw_event: str) -> SecurityEvent | None:
        if raw_event == "valid-event":
            return SecurityEvent(
                event=EventContext(
                    type=EventType.LOGIN_FAILED,
                    category=EventCategory.AUTHENTICATION,
                    action="ssh_login",
                ),
                collector=CollectorInfo(
                    name="test-parser",
                    version="1.0.0",
                ),
                timestamp="2026-08-09T15:20:31+00:00",
            )

        return None


def test_pipeline_converts_raw_events_to_security_events() -> None:
    collector = FakeCollector(
        [
            "valid-event",
        ]
    )

    parser = FakeParser()

    pipeline = Pipeline(
        collector=collector,
        parser=parser,
    )

    events = list(pipeline.run())

    assert len(events) == 1
    assert events[0].event.type == EventType.LOGIN_FAILED
    assert events[0].event.category == EventCategory.AUTHENTICATION


def test_pipeline_ignores_unrecognized_events() -> None:
    collector = FakeCollector(
        [
            "unknown-event",
            "valid-event",
            "another-unknown-event",
        ]
    )

    parser = FakeParser()

    pipeline = Pipeline(
        collector=collector,
        parser=parser,
    )

    events = list(pipeline.run())

    assert len(events) == 1
    assert events[0].event.action == "ssh_login"


def test_pipeline_preserves_event_order() -> None:
    class OrderedParser:
        def parse(self, raw_event: str) -> SecurityEvent | None:
            return SecurityEvent(
                event=EventContext(
                    type=EventType.LOGIN_FAILED,
                    category=EventCategory.AUTHENTICATION,
                    action=raw_event,
                ),
                collector=CollectorInfo(
                    name="test-parser",
                    version="1.0.0",
                ),
                timestamp="2026-08-09T15:20:31+00:00",
            )

    collector = FakeCollector(
        [
            "event-one",
            "event-two",
            "event-three",
        ]
    )

    pipeline = Pipeline(
        collector=collector,
        parser=OrderedParser(),
    )

    events = list(pipeline.run())

    assert [event.event.action for event in events] == [
        "event-one",
        "event-two",
        "event-three",
    ]
