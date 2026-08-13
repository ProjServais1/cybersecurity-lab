from datetime import datetime, timezone

from sentinellab.detection.ssh_bruteforce import SSHBruteForceDetector
from sentinellab.models.security_event import (
    CollectorInfo,
    Endpoint,
    EventCategory,
    EventContext,
    EventStatus,
    EventType,
    Outcome,
    SecurityEvent,
)


def make_failed_ssh_event(
    timestamp: str,
    source_ip: str = "192.168.1.50",
) -> SecurityEvent:
    """Create a failed SSH authentication event for testing."""

    return SecurityEvent(
        timestamp=datetime.fromisoformat(timestamp).astimezone(timezone.utc),
        event=EventContext(
            type=EventType.LOGIN_FAILED,
            category=EventCategory.AUTHENTICATION,
            action="ssh_login",
        ),
        source=Endpoint(
            ip=source_ip,
            port=45221,
        ),
        destination=Endpoint(
            hostname="server01",
            port=22,
        ),
        outcome=Outcome(
            status=EventStatus.FAILURE,
            reason="invalid_credentials",
        ),
        collector=CollectorInfo(
            name="ssh-parser",
            version="0.1.0",
        ),
    )


def test_ssh_bruteforce_requires_five_failed_logins() -> None:
    """Four failed SSH logins must not trigger an alert."""

    detector = SSHBruteForceDetector(
        threshold=5,
        window_seconds=60,
    )

    events = [
        make_failed_ssh_event("2026-08-09T15:20:01+00:00"),
        make_failed_ssh_event("2026-08-09T15:20:12+00:00"),
        make_failed_ssh_event("2026-08-09T15:20:25+00:00"),
        make_failed_ssh_event("2026-08-09T15:20:31+00:00"),
    ]

    alerts = detector.detect(events)

    assert alerts == []


def test_ssh_bruteforce_triggers_after_five_failures() -> None:
    """Five failed SSH logins from one IP must trigger an alert."""

    detector = SSHBruteForceDetector(
        threshold=5,
        window_seconds=60,
    )

    events = [
        make_failed_ssh_event("2026-08-09T15:20:01+00:00"),
        make_failed_ssh_event("2026-08-09T15:20:12+00:00"),
        make_failed_ssh_event("2026-08-09T15:20:25+00:00"),
        make_failed_ssh_event("2026-08-09T15:20:31+00:00"),
        make_failed_ssh_event("2026-08-09T15:20:44+00:00"),
    ]

    alerts = detector.detect(events)

    assert len(alerts) == 1

    alert = alerts[0]

    assert alert.rule_id == "SSH-BRUTE-FORCE-001"
    assert alert.rule_name == "SSH Brute Force"
    assert alert.severity.value == "high"
    assert str(alert.source_ip) == "192.168.1.50"
    assert alert.event_count == 5


def test_ssh_bruteforce_requires_same_source_ip() -> None:
    """Failures from different IPs must not be combined."""

    detector = SSHBruteForceDetector(
        threshold=5,
        window_seconds=60,
    )

    events = [
        make_failed_ssh_event(
            "2026-08-09T15:20:01+00:00",
            "192.168.1.50",
        ),
        make_failed_ssh_event(
            "2026-08-09T15:20:12+00:00",
            "192.168.1.50",
        ),
        make_failed_ssh_event(
            "2026-08-09T15:20:25+00:00",
            "192.168.1.50",
        ),
        make_failed_ssh_event(
            "2026-08-09T15:20:31+00:00",
            "192.168.1.60",
        ),
        make_failed_ssh_event(
            "2026-08-09T15:20:44+00:00",
            "192.168.1.60",
        ),
    ]

    alerts = detector.detect(events)

    assert alerts == []


def test_ssh_bruteforce_respects_time_window() -> None:
    """Failures outside the detection window must not trigger an alert."""

    detector = SSHBruteForceDetector(
        threshold=5,
        window_seconds=60,
    )

    events = [
        make_failed_ssh_event("2026-08-09T15:20:01+00:00"),
        make_failed_ssh_event("2026-08-09T15:20:12+00:00"),
        make_failed_ssh_event("2026-08-09T15:20:25+00:00"),
        make_failed_ssh_event("2026-08-09T15:20:31+00:00"),
        make_failed_ssh_event("2026-08-09T15:22:01+00:00"),
    ]

    alerts = detector.detect(events)

    assert alerts == []


def test_ssh_bruteforce_ignores_successful_logins() -> None:
    """Successful SSH logins must not count toward brute-force detection."""

    detector = SSHBruteForceDetector(
        threshold=5,
        window_seconds=60,
    )

    failed_events = [
        make_failed_ssh_event("2026-08-09T15:20:01+00:00"),
        make_failed_ssh_event("2026-08-09T15:20:12+00:00"),
        make_failed_ssh_event("2026-08-09T15:20:25+00:00"),
        make_failed_ssh_event("2026-08-09T15:20:31+00:00"),
    ]

    successful_event = SecurityEvent(
        timestamp=datetime.fromisoformat(
            "2026-08-09T15:20:44+00:00"
        ),
        event=EventContext(
            type=EventType.LOGIN_SUCCESS,
            category=EventCategory.AUTHENTICATION,
            action="ssh_login",
        ),
        source=Endpoint(
            ip="192.168.1.50",
            port=45221,
        ),
        destination=Endpoint(
            hostname="server01",
            port=22,
        ),
        outcome=Outcome(
            status=EventStatus.SUCCESS,
        ),
        collector=CollectorInfo(
            name="ssh-parser",
            version="0.1.0",
        ),
    )

    alerts = detector.detect(
        failed_events + [successful_event]
    )

    assert alerts == []
