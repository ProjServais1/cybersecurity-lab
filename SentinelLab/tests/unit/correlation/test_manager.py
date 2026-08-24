from datetime import datetime, timezone
from uuid import uuid4

import pytest

from sentinellab.correlation.manager import IncidentManager
from sentinellab.correlation.models import Incident, IncidentStatus
from sentinellab.detection.models import SecurityAlert
from sentinellab.models.security_event import EventSeverity


def make_incident(
    severity: EventSeverity = EventSeverity.MEDIUM,
    status: IncidentStatus = IncidentStatus.OPEN,
) -> Incident:
    timestamp = datetime(
        2026,
        8,
        20,
        20,
        0,
        0,
        tzinfo=timezone.utc,
    )

    return Incident(
        title="SSH brute-force attack",
        description="Multiple SSH authentication failures.",
        severity=severity,
        status=status,
        created_at=timestamp,
        updated_at=timestamp,
        source_ip="192.168.1.50",
    )


def make_alert(
    severity: EventSeverity = EventSeverity.HIGH,
) -> SecurityAlert:
    timestamp = datetime(
        2026,
        8,
        20,
        20,
        1,
        0,
        tzinfo=timezone.utc,
    )

    return SecurityAlert(
        timestamp=timestamp,
        rule_id="SSH-BRUTE-FORCE-001",
        rule_name="SSH Brute Force",
        severity=severity,
        description="Multiple failed SSH authentication attempts.",
        source_ip="192.168.1.50",
        event_count=5,
        first_event_timestamp=timestamp,
        last_event_timestamp=timestamp,
    )


def test_get_returns_existing_incident() -> None:
    manager = IncidentManager()
    incident = make_incident()

    result = manager.get(
        [incident],
        incident.incident_id,
    )

    assert result is incident


def test_get_returns_none_for_unknown_incident() -> None:
    manager = IncidentManager()
    incident = make_incident()

    result = manager.get(
        [incident],
        uuid4(),
    )

    assert result is None


def test_add_alert_updates_incident() -> None:
    manager = IncidentManager()
    incident = make_incident()
    alert = make_alert()

    manager.add_alert(
        incident,
        alert,
    )

    assert alert.alert_id in incident.alert_ids


def test_add_alert_preserves_highest_severity() -> None:
    manager = IncidentManager()
    incident = make_incident(
        severity=EventSeverity.MEDIUM,
    )
    alert = make_alert(
        severity=EventSeverity.CRITICAL,
    )

    manager.add_alert(
        incident,
        alert,
    )

    assert incident.severity == EventSeverity.CRITICAL


def test_update_status_changes_incident_status() -> None:
    manager = IncidentManager()
    incident = make_incident()

    manager.update_status(
        incident,
        IncidentStatus.INVESTIGATING,
    )

    assert incident.status == IncidentStatus.INVESTIGATING


def test_resolve_incident() -> None:
    manager = IncidentManager()
    incident = make_incident(
        status=IncidentStatus.INVESTIGATING,
    )

    manager.resolve(incident)

    assert incident.status == IncidentStatus.RESOLVED


def test_only_resolved_incident_can_be_closed() -> None:
    manager = IncidentManager()
    incident = make_incident(
        status=IncidentStatus.INVESTIGATING,
    )

    with pytest.raises(ValueError):
        manager.close(incident)


def test_close_resolved_incident() -> None:
    manager = IncidentManager()
    incident = make_incident(
        status=IncidentStatus.RESOLVED,
    )

    manager.close(incident)

    assert incident.status == IncidentStatus.CLOSED


def test_closed_incident_cannot_be_modified() -> None:
    manager = IncidentManager()
    incident = make_incident(
        status=IncidentStatus.CLOSED,
    )

    with pytest.raises(ValueError):
        manager.update_status(
            incident,
            IncidentStatus.INVESTIGATING,
        )
