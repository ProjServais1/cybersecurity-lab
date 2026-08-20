from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from sentinellab.correlation.models import Incident, IncidentStatus
from sentinellab.models.security_event import EventSeverity


def test_create_incident() -> None:
    """A valid incident must be created correctly."""

    timestamp = datetime.now(timezone.utc)

    incident = Incident(
        title="SSH Brute Force",
        description="Multiple failed SSH authentication attempts detected.",
        severity=EventSeverity.HIGH,
        status=IncidentStatus.OPEN,
        created_at=timestamp,
        updated_at=timestamp,
        source_ip="192.168.1.50",
    )

    assert incident.title == "SSH Brute Force"
    assert incident.severity == EventSeverity.HIGH
    assert incident.status == IncidentStatus.OPEN
    assert str(incident.source_ip) == "192.168.1.50"
    assert incident.alert_ids == []
    assert incident.event_ids == []


def test_incident_generates_unique_id() -> None:
    """Each incident must receive a unique identifier."""

    timestamp = datetime.now(timezone.utc)

    incident_one = Incident(
        title="Incident One",
        description="First incident.",
        severity=EventSeverity.MEDIUM,
        status=IncidentStatus.OPEN,
        created_at=timestamp,
        updated_at=timestamp,
    )

    incident_two = Incident(
        title="Incident Two",
        description="Second incident.",
        severity=EventSeverity.MEDIUM,
        status=IncidentStatus.OPEN,
        created_at=timestamp,
        updated_at=timestamp,
    )

    assert incident_one.incident_id != incident_two.incident_id


def test_incident_accepts_ipv4_and_ipv6() -> None:
    """An incident must accept IPv4 and IPv6 source addresses."""

    timestamp = datetime.now(timezone.utc)

    ipv4_incident = Incident(
        title="IPv4 Incident",
        description="Test IPv4 source.",
        severity=EventSeverity.HIGH,
        status=IncidentStatus.OPEN,
        created_at=timestamp,
        updated_at=timestamp,
        source_ip="192.168.1.50",
    )

    ipv6_incident = Incident(
        title="IPv6 Incident",
        description="Test IPv6 source.",
        severity=EventSeverity.HIGH,
        status=IncidentStatus.OPEN,
        created_at=timestamp,
        updated_at=timestamp,
        source_ip="2001:db8::1",
    )

    assert str(ipv4_incident.source_ip) == "192.168.1.50"
    assert str(ipv6_incident.source_ip) == "2001:db8::1"


def test_incident_rejects_unknown_fields() -> None:
    """Unknown fields must be rejected."""

    timestamp = datetime.now(timezone.utc)

    with pytest.raises(ValidationError):
        Incident(
            title="Invalid Incident",
            description="Contains an unknown field.",
            severity=EventSeverity.HIGH,
            status=IncidentStatus.OPEN,
            created_at=timestamp,
            updated_at=timestamp,
            unknown_field="unexpected",
        )


def test_incident_status_values() -> None:
    """Incident status must expose the expected lifecycle."""

    assert IncidentStatus.OPEN.value == "open"
    assert IncidentStatus.INVESTIGATING.value == "investigating"
    assert IncidentStatus.RESOLVED.value == "resolved"
    assert IncidentStatus.CLOSED.value == "closed"
