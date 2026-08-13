from __future__ import annotations

from datetime import timedelta
from sentinellab.detection.base import Detector
from sentinellab.detection.models import SecurityAlert
from sentinellab.models.security_event import (
    EventSeverity,
    EventStatus,
    EventType,
    SecurityEvent,
)


class SSHBruteForceDetector(Detector):
    """Detect repeated failed SSH authentications from one source IP."""

    RULE_ID = "SSH-BRUTE-FORCE-001"
    RULE_NAME = "SSH Brute Force"

    def __init__(
        self,
        threshold: int = 5,
        window_seconds: int = 60,
    ) -> None:
        if threshold < 1:
            raise ValueError("threshold must be greater than zero")

        if window_seconds < 1:
            raise ValueError("window_seconds must be greater than zero")

        self._threshold = threshold
        self._window = timedelta(seconds=window_seconds)

    def detect(
        self,
        events: list[SecurityEvent],
    ) -> list[SecurityAlert]:
        """Detect SSH brute-force activity."""

        failed_events = [
            event
            for event in events
            if (
                event.event.type == EventType.LOGIN_FAILED
                and event.event.category.value == "authentication"
                and event.outcome.status == EventStatus.FAILURE
                and event.source is not None
                and event.source.ip is not None
                and event.destination is not None
                and event.destination.port == 22
            )
        ]

        events_by_ip: dict[str, list[SecurityEvent]] = {}

        for event in failed_events:
            assert event.source is not None
            assert event.source.ip is not None

            source_ip = str(event.source.ip)

            events_by_ip.setdefault(source_ip, []).append(event)

        alerts: list[SecurityAlert] = []

        for source_ip, ip_events in events_by_ip.items():
            ip_events.sort(key=lambda event: event.timestamp)

            for index, first_event in enumerate(ip_events):
                window_events = [
                    event
                    for event in ip_events[index:]
                    if event.timestamp - first_event.timestamp <= self._window
                ]

                if len(window_events) < self._threshold:
                    continue

                last_event = window_events[self._threshold - 1]

                alert_events = window_events[: self._threshold]

                alerts.append(
                    SecurityAlert(
                        timestamp=last_event.timestamp,
                        rule_id=self.RULE_ID,
                        rule_name=self.RULE_NAME,
                        severity=EventSeverity.HIGH,
                        description=(
                            "Multiple failed SSH authentication attempts "
                            f"detected from {source_ip}."
                        ),
                        source_ip=first_event.source.ip,
                        event_count=len(alert_events),
                        first_event_timestamp=first_event.timestamp,
                        last_event_timestamp=last_event.timestamp,
                        event_ids=[
                            event.event_id
                            for event in alert_events
                        ],
                    )
                )

                break

        return alerts
