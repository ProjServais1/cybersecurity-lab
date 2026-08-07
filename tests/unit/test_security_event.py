from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from sentinellab.models.security_event import (
    CollectorInfo,
    Endpoint,
    EventCategory,
    EventContext,
    EventSeverity,
    EventStatus,
    EventType,
    NetworkContext,
    Outcome,
    SecurityEvent,
    UserContext,
)


def test_create_ssh_failed_login_event() -> None:
    """A valid SSH authentication failure must be accepted."""

    event = SecurityEvent(
        timestamp=datetime.now(timezone.utc),
        event=EventContext(
            type=EventType.LOGIN_FAILED,
            category=EventCategory.AUTHENTICATION,
            action="ssh_login",
        ),
        source=Endpoint(
            ip="192.168.1.50",
            port=45221,
            hostname="attacker-lab",
        ),
        destination=Endpoint(
            ip="192.168.1.10",
            port=22,
            hostname="server01",
        ),
        user=UserContext(
            username="admin",
        ),
        network=NetworkContext(
            protocol="ssh",
            direction="inbound",
        ),
        outcome=Outcome(
            status=EventStatus.FAILURE,
            reason="invalid_credentials",
        ),
        severity=EventSeverity.INFO,
        collector=CollectorInfo(
            name="linux-auth-collector",
            version="0.1.0",
        ),
        raw_message=(
            "Failed password for invalid user admin "
            "from 192.168.1.50 port 45221 ssh2"
        ),
    )

    assert event.event_id is not None
    assert event.event.type == EventType.LOGIN_FAILED
    assert str(event.source.ip) == "192.168.1.50"
    assert event.destination.port == 22
    assert event.user.username == "admin"
    assert event.outcome.status == EventStatus.FAILURE
    assert event.timestamp.tzinfo is not None


def test_timestamp_is_normalized_to_utc() -> None:
    """A timezone-aware timestamp must be converted to UTC."""

    event = SecurityEvent(
        timestamp=datetime.fromisoformat(
            "2026-08-07T20:15:00+02:00"
        ),
        event=EventContext(
            type=EventType.LOGIN_FAILED,
            category=EventCategory.AUTHENTICATION,
            action="ssh_login",
        ),
        collector=CollectorInfo(
            name="test",
            version="1.0.0",
        ),
    )

    assert event.timestamp.isoformat() == "2026-08-07T18:15:00+00:00"


def test_naive_timestamp_is_rejected() -> None:
    """A timestamp without timezone information must be rejected."""

    with pytest.raises(ValidationError):
        SecurityEvent(
            timestamp=datetime.now(),
            event=EventContext(
                type=EventType.LOGIN_FAILED,
                category=EventCategory.AUTHENTICATION,
                action="ssh_login",
            ),
            collector=CollectorInfo(
                name="test",
                version="1.0.0",
            ),
        )


def test_unknown_fields_are_rejected() -> None:
    """Unexpected fields must not be silently accepted."""

    with pytest.raises(ValidationError):
        SecurityEvent(
            timestamp=datetime.now(timezone.utc),
            event=EventContext(
                type=EventType.LOGIN_FAILED,
                category=EventCategory.AUTHENTICATION,
                action="ssh_login",
            ),
            collector=CollectorInfo(
                name="test",
                version="1.0.0",
            ),
            malicious_field="should_not_be_accepted",
        )
