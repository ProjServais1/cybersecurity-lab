from __future__ import annotations

from collections.abc import Iterable

from sentinellab.detection.base import Detector
from sentinellab.detection.models import SecurityAlert
from sentinellab.models.security_event import SecurityEvent


class DetectionEngine:
    """Run registered detection rules against security events."""

    def __init__(self, detectors: Iterable[Detector]) -> None:
        self._detectors = tuple(detectors)

    def process(
        self,
        events: list[SecurityEvent],
    ) -> list[SecurityAlert]:
        """Run all registered detectors against a batch of events."""

        alerts: list[SecurityAlert] = []

        for detector in self._detectors:
            alerts.extend(detector.detect(events))

        return alerts
