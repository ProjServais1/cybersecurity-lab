from datetime import datetime, timedelta, timezone

from sentinellab.correlation.engine import CorrelationEngine
from sentinellab.correlation.models import IncidentStatus
from sentinellab.detection.models import SecurityAlert
from sentinellab.models.security_event import EventSeverity


def make_alert(
    source_ip: str,
    timestamp: datetime,
    severity: EventSeverity = EventSeverity.HIGH,
) -> SecurityAlert:
    """Create a minimal valid SecurityAlert for correlation tests."""

    return SecurityAlert(
        timestamp=timestamp,
        rule_id="SSH-BRUTE-FORCE-001",
        rule_name="SSH Brute Force",
        severity=severity,
        description="Multiple failed SSH authentication attempts.",
        source_ip=source_ip,
        event_count=5,
        first_event_timestamp=timestamp - timedelta(seconds=10),
        last_event_timestamp=timestamp,
    )


def test_same_ip_alerts_within_window_create_one_incident() -> None:
    """Alerts from the same IP within the window create one incident."""

    base_time = datetime(
        2026,
        8,
        17,
        18,
        0,
        0,
        tzinfo=timezone.utc,
    )

    alert_one = make_alert(
        source_ip="192.168.1.50",
        timestamp=base_time,
    )

    alert_two = make_alert(
        source_ip="192.168.1.50",
        timestamp=base_time + timedelta(seconds=30),
    )

    engine = CorrelationEngine(window_seconds=300)

    incidents = engine.correlate(
        [alert_one, alert_two]
    )

    assert len(incidents) == 1

    incident = incidents[0]

    assert incident.source_ip is not None
    assert str(incident.source_ip) == "192.168.1.50"
    assert len(incident.alert_ids) == 2
    assert alert_one.alert_id in incident.alert_ids
    assert alert_two.alert_id in incident.alert_ids
    assert incident.status == IncidentStatus.OPEN


def test_different_ips_create_two_incidents() -> None:
    """Alerts from different IPs create separate incidents."""

    base_time = datetime(
        2026,
        8,
        17,
        18,
        0,
        0,
        tzinfo=timezone.utc,
    )

    alert_one = make_alert(
        source_ip="192.168.1.50",
        timestamp=base_time,
    )

    alert_two = make_alert(
        source_ip="192.168.1.60",
        timestamp=base_time + timedelta(seconds=30),
    )

    engine = CorrelationEngine(window_seconds=300)

    incidents = engine.correlate(
        [alert_one, alert_two]
    )

    assert len(incidents) == 2

    source_ips = {
        str(incident.source_ip)
        for incident in incidents
    }

    assert source_ips == {
        "192.168.1.50",
        "192.168.1.60",
    }


def test_same_ip_alerts_outside_window_create_two_incidents() -> None:
    """Alerts from the same IP outside the window create separate incidents."""

    base_time = datetime(
        2026,
        8,
        17,
        18,
        0,
        0,
        tzinfo=timezone.utc,
    )

    alert_one = make_alert(
        source_ip="192.168.1.50",
        timestamp=base_time,
    )

    alert_two = make_alert(
        source_ip="192.168.1.50",
        timestamp=base_time + timedelta(seconds=301),
    )

    engine = CorrelationEngine(window_seconds=300)

    incidents = engine.correlate(
        [alert_one, alert_two]
    )

    assert len(incidents) == 2

    assert all(
        str(incident.source_ip) == "192.168.1.50"
        for incident in incidents
    )
def test_correlated_incident_contains_alert_ids() -> None:
    """A correlated incident must contain all related alert IDs."""

    base_time = datetime(
        2026,
        8,
        17,
        18,
        0,
        0,
        tzinfo=timezone.utc,
    )

    alert_one = make_alert(
        source_ip="192.168.1.50",
        timestamp=base_time,
    )

    alert_two = make_alert(
        source_ip="192.168.1.50",
        timestamp=base_time + timedelta(seconds=30),
    )

    engine = CorrelationEngine(window_seconds=300)

    incidents = engine.correlate(
        [alert_one, alert_two]
    )

    assert len(incidents) == 1

    incident = incidents[0]

    assert incident.alert_ids == [
        alert_one.alert_id,
        alert_two.alert_id,
    ]
def test_correlated_incident_contains_event_ids() -> None:
    """A correlated incident must contain event IDs from its alerts."""

    base_time = datetime(
        2026,
        8,
        17,
        18,
        0,
        0,
        tzinfo=timezone.utc,
    )

    alert_one = make_alert(
        source_ip="192.168.1.50",
        timestamp=base_time,
    )

    alert_two = make_alert(
        source_ip="192.168.1.50",
        timestamp=base_time + timedelta(seconds=30),
    )

    engine = CorrelationEngine(window_seconds=300)

    incidents = engine.correlate(
        [alert_one, alert_two]
    )

    assert len(incidents) == 1

    incident = incidents[0]

    assert incident.event_ids == (
        alert_one.event_ids
        + alert_two.event_ids
    )
def test_correlated_incident_preserves_security_context() -> None:
    """The incident must preserve the important security context."""

    base_time = datetime(
        2026,
        8,
        17,
        18,
        0,
        0,
        tzinfo=timezone.utc,
    )

    alert_one = make_alert(
        source_ip="192.168.1.50",
        timestamp=base_time,
        severity=EventSeverity.MEDIUM,
    )

    alert_two = make_alert(
        source_ip="192.168.1.50",
        timestamp=base_time + timedelta(seconds=30),
        severity=EventSeverity.HIGH,
    )

    engine = CorrelationEngine(window_seconds=300)

    incidents = engine.correlate(
        [alert_one, alert_two]
    )

    assert len(incidents) == 1

    incident = incidents[0]

    assert incident.source_ip == alert_one.source_ip
    assert incident.severity == EventSeverity.HIGH
    assert incident.status == IncidentStatus.OPEN
    assert incident.created_at == alert_one.timestamp
    assert incident.updated_at == alert_two.timestamp
