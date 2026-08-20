from __future__ import annotations

from datetime import timedelta

from sentinellab.correlation.models import Incident, IncidentStatus
from sentinellab.detection.models import SecurityAlert
from sentinellab.models.security_event import EventSeverity


class CorrelationEngine:
    """Correlate security alerts into security incidents."""

    def __init__(self, window_seconds: int = 300) -> None:
        if window_seconds < 1:
            raise ValueError("window_seconds must be greater than zero")

        self._window = timedelta(seconds=window_seconds)

    def correlate(
        self,
        alerts: list[SecurityAlert],
    ) -> list[Incident]:
        """Group related security alerts into incidents."""

        if not alerts:
            return []

        sorted_alerts = sorted(
            alerts,
            key=lambda alert: alert.timestamp,
        )

        incidents: list[Incident] = []

        current_alerts: list[SecurityAlert] = []

        for alert in sorted_alerts:
            if not current_alerts:
                current_alerts = [alert]
                continue

            first_alert = current_alerts[0]
            last_alert = current_alerts[-1]

            same_source = alert.source_ip == first_alert.source_ip
            within_window = (
                alert.timestamp - last_alert.timestamp <= self._window
            )

            if same_source and within_window:
                current_alerts.append(alert)
                continue

            incidents.append(self._build_incident(current_alerts))
            current_alerts = [alert]

        if current_alerts:
            incidents.append(self._build_incident(current_alerts))

        return incidents

    def _build_incident(
        self,
        alerts: list[SecurityAlert],
    ) -> Incident:
        """Build an incident from a correlated group of alerts."""

        first_alert = alerts[0]
        last_alert = alerts[-1]

        severity = max(
            (alert.severity for alert in alerts),
            key=self._severity_rank,
        )

        alert_ids = [
            alert.alert_id
            for alert in alerts
        ]

        event_ids = [
            event_id
            for alert in alerts
            for event_id in alert.event_ids
        ]

        return Incident(
            title=f"Security incident from {first_alert.source_ip}",
            description=(
                f"{len(alerts)} security alert(s) correlated "
                f"from source IP {first_alert.source_ip}."
            ),
            severity=severity,
            status=IncidentStatus.OPEN,
            created_at=first_alert.timestamp,
            updated_at=last_alert.timestamp,
            source_ip=first_alert.source_ip,
            alert_ids=alert_ids,
            event_ids=event_ids,
        )

    @staticmethod
    def _severity_rank(severity: EventSeverity) -> int:
        """Return the ordering used to select incident severity."""

        ranking = {
            EventSeverity.INFO: 1,
            EventSeverity.LOW: 2,
            EventSeverity.MEDIUM: 3,
            EventSeverity.HIGH: 4,
            EventSeverity.CRITICAL: 5,
        }

        return ranking[severity]
