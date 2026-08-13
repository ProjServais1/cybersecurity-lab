from __future__ import annotations

from abc import ABC, abstractmethod

from sentinellab.detection.models import SecurityAlert
from sentinellab.models.security_event import SecurityEvent


class Detector(ABC):
    """Contract implemented by all SentinelLab detection rules."""

    @abstractmethod
    def detect(
        self,
        events: list[SecurityEvent],
    ) -> list[SecurityAlert]:
        """Analyze security events and return generated alerts."""
        raise NotImplementedError
