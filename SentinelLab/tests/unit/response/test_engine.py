from datetime import datetime, timezone

from sentinellab.correlation.models import Incident, IncidentStatus
from sentinellab.models.security_event import EventSeverity
from sentinellab.response.engine import ResponseEngine
from sentinellab.response.models import (
    ResponseActionStatus,
    ResponseActionType,
)


def make_incident(
    severity: EventSeverity = EventSeverity.HIGH,
    source_ip: str = "192.168.1.50",
    status: IncidentStatus = IncidentStatus.OPEN,
) -> Incident:
    return Incident(
        title="SSH brute-force incident",
        description="Repeated failed SSH authentication attempts.",
        severity=severity,
        status=status,
        created_at=datetime(
            2026,
            8,
            24,
            12,
            0,
            0,
            tzinfo=timezone.utc,
        ),
        updated_at=datetime(
            2026,
            8,
            24,
            12,
            1,
            0,
            tzinfo=timezone.utc,
        ),
        source_ip=source_ip,
    )


def test_high_severity_incident_generates_response_actions() -> None:
    incident = make_incident(
        severity=EventSeverity.HIGH,
    )

    engine = ResponseEngine()

    actions = engine.generate_actions(incident)

    assert len(actions) == 2


def test_high_severity_incident_generates_notification() -> None:
    incident = make_incident(
        severity=EventSeverity.HIGH,
    )

    engine = ResponseEngine()

    actions = engine.generate_actions(incident)

    notification = next(
        action
        for action in actions
        if action.action_type == ResponseActionType.NOTIFY
    )

    assert notification.target == "soc-team"
    assert notification.status == ResponseActionStatus.PENDING
    assert notification.incident_id == incident.incident_id


def test_high_severity_incident_generates_block_ip_action() -> None:
    incident = make_incident(
        severity=EventSeverity.HIGH,
        source_ip="10.10.10.50",
    )

    engine = ResponseEngine()

    actions = engine.generate_actions(incident)

    block_action = next(
        action
        for action in actions
        if action.action_type == ResponseActionType.BLOCK_IP
    )

    assert block_action.target == "10.10.10.50"
    assert block_action.incident_id == incident.incident_id


def test_low_severity_incident_generates_no_actions() -> None:
    incident = make_incident(
        severity=EventSeverity.LOW,
    )

    engine = ResponseEngine()

    actions = engine.generate_actions(incident)

    assert actions == []


def test_closed_incident_generates_no_actions() -> None:
    incident = make_incident(
        severity=EventSeverity.CRITICAL,
        status=IncidentStatus.CLOSED,
    )

    engine = ResponseEngine()

    actions = engine.generate_actions(incident)

    assert actions == []
