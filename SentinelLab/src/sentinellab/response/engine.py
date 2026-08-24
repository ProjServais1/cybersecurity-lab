from __future__ import annotations

from sentinellab.correlation.models import Incident, IncidentStatus
from sentinellab.models.security_event import EventSeverity
from sentinellab.response.models import (
    ResponseAction,
    ResponseActionType,
)


class ResponseEngine:
    """Generate response actions from security incidents."""

    def __init__(
        self,
        minimum_severity: EventSeverity = EventSeverity.HIGH,
    ) -> None:
        self._minimum_severity = minimum_severity

    def generate_actions(
        self,
        incident: Incident,
    ) -> list[ResponseAction]:
        """Generate appropriate response actions for an incident."""

        if incident.status == IncidentStatus.CLOSED:
            return []

        if self._severity_rank(incident.severity) < self._severity_rank(
            self._minimum_severity
        ):
            return []

        actions: list[ResponseAction] = []

        actions.append(
            ResponseAction(
                incident_id=incident.incident_id,
                action_type=ResponseActionType.NOTIFY,
                target="soc-team",
                reason=(
                    f"Security incident detected with "
                    f"{incident.severity.value} severity."
                ),
            )
        )

        if incident.source_ip is not None:
            actions.append(
                ResponseAction(
                    incident_id=incident.incident_id,
                    action_type=ResponseActionType.BLOCK_IP,
                    target=str(incident.source_ip),
                    reason=(
                        "Block the source IP associated with "
                        "the security incident."
                    ),
                )
            )

        return actions

    @staticmethod
    def _severity_rank(severity: EventSeverity) -> int:
        """Return the severity ordering."""

        ranking = {
            EventSeverity.INFO: 1,
            EventSeverity.LOW: 2,
            EventSeverity.MEDIUM: 3,
            EventSeverity.HIGH: 4,
            EventSeverity.CRITICAL: 5,
        }

        return ranking[severity]
