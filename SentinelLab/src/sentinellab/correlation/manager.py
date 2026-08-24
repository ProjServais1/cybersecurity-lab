from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID

from sentinellab.correlation.models import Incident, IncidentStatus
from sentinellab.detection.models import SecurityAlert
from sentinellab.models.security_event import EventSeverity


class IncidentManager:
    """Manage the lifecycle of security incidents."""

    def get(
        self,
        incidents: list[Incident],
        incident_id: UUID,
    ) -> Incident | None:
        """Return an incident by its identifier."""

        for incident in incidents:
            if incident.incident_id == incident_id:
                return incident

        return None

    def add_alert(
        self,
        incident: Incident,
        alert: SecurityAlert,
    ) -> Incident:
        """Add an alert to an existing incident."""

        if alert.alert_id not in incident.alert_ids:
            incident.alert_ids.append(alert.alert_id)

        for event_id in alert.event_ids:
            if event_id not in incident.event_ids:
                incident.event_ids.append(event_id)

        if self._severity_rank(alert.severity) > self._severity_rank(
            incident.severity
        ):
            incident.severity = alert.severity

        incident.updated_at = self._utc_now()

        return incident

    def update_status(
        self,
        incident: Incident,
        status: IncidentStatus,
    ) -> Incident:
        """Update the lifecycle status of an incident."""

        if incident.status == IncidentStatus.CLOSED:
            raise ValueError("A closed incident cannot be modified")

        if (
            incident.status == IncidentStatus.RESOLVED
            and status == IncidentStatus.OPEN
        ):
            raise ValueError(
                "A resolved incident cannot return to open"
            )

        incident.status = status
        incident.updated_at = self._utc_now()

        return incident

    def resolve(
        self,
        incident: Incident,
    ) -> Incident:
        """Resolve an incident."""

        return self.update_status(
            incident,
            IncidentStatus.RESOLVED,
        )

    def close(
        self,
        incident: Incident,
    ) -> Incident:
        """Close an incident."""

        if incident.status != IncidentStatus.RESOLVED:
            raise ValueError(
                "Only resolved incidents can be closed"
            )

        return self.update_status(
            incident,
            IncidentStatus.CLOSED,
        )

    @staticmethod
    def _severity_rank(
        severity: EventSeverity,
    ) -> int:
        """Return the ordering used for incident severity."""

        ranking = {
            EventSeverity.INFO: 1,
            EventSeverity.LOW: 2,
            EventSeverity.MEDIUM: 3,
            EventSeverity.HIGH: 4,
            EventSeverity.CRITICAL: 5,
        }

        return ranking[severity]

    @staticmethod
    def _utc_now() -> datetime:
        """Return the current timezone-aware UTC timestamp."""

        return datetime.now(timezone.utc)
