from datetime import datetime, timezone

from sentinellab.detection.base import Detector
from sentinellab.detection.engine import DetectionEngine
from sentinellab.detection.models import SecurityAlert
from sentinellab.models.security_event import (
    CollectorInfo,
    EventCategory,
    EventContext,
    EventSeverity,
    EventType,
    SecurityEvent,
)


class FakeDetector(Detector):
    """Simple detector used to test DetectionEngine."""

    def __init__(self, alerts: list[SecurityAlert]) -> None:
        self.alerts = alerts
        self.received_events: list[SecurityEvent] | None = None

    def detect(
        self,
        events: list[SecurityEvent],
    ) -> list[SecurityAlert]:
        self.received_events = events
        return self.alerts


def make_event() -> SecurityEvent:
    """Create a minimal valid SecurityEvent."""

    return SecurityEvent(
        timestamp=datetime.now(timezone.utc),
        event=EventContext(
            type=EventType.LOGIN_FAILED,
            category=EventCategory.AUTHENTICATION,
            action="ssh_login",
        ),
        severity=EventSeverity.INFO,
        collector=CollectorInfo(
            name="test",
            version="1.0.0",
        ),
    )


def make_alert() -> SecurityAlert:
    """Create a minimal valid SecurityAlert."""

    event = make_event()

    return SecurityAlert(
        timestamp=event.timestamp,
        rule_id="TEST-001",
        rule_name="Test Detection",
        severity=EventSeverity.HIGH,
        description="Test alert.",
        source_ip="192.168.1.50",
        event_count=1,
        first_event_timestamp=event.timestamp,
        last_event_timestamp=event.timestamp,
        event_ids=[event.event_id],
    )


def test_detection_engine_runs_registered_detector() -> None:
    """The engine must execute registered detectors."""

    event = make_event()
    alert = make_alert()

    detector = FakeDetector([alert])

    engine = DetectionEngine([detector])

    alerts = engine.process([event])

    assert alerts == [alert]
    assert detector.received_events == [event]


def test_detection_engine_combines_alerts_from_multiple_detectors() -> None:
    """Alerts from all detectors must be returned."""

    event = make_event()

    alert_one = make_alert()
    alert_two = make_alert()

    detector_one = FakeDetector([alert_one])
    detector_two = FakeDetector([alert_two])

    engine = DetectionEngine(
        [
            detector_one,
            detector_two,
        ]
    )

    alerts = engine.process([event])

    assert alerts == [
        alert_one,
        alert_two,
    ]


def test_detection_engine_returns_empty_list_when_no_detector_matches() -> None:
    """The engine must return an empty list when no alert is generated."""

    event = make_event()

    detector = FakeDetector([])

    engine = DetectionEngine([detector])

    alerts = engine.process([event])

    assert alerts == []
