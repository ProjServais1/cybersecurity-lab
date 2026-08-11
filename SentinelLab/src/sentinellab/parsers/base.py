from __future__ import annotations

from abc import ABC, abstractmethod

from sentinellab.models.security_event import SecurityEvent


class Parser(ABC):
    """Contract implemented by SentinelLab event parsers."""

    @abstractmethod
    def parse(self, raw_message: str) -> SecurityEvent | None:
        """Parse a raw message into a canonical SecurityEvent."""
        raise NotImplementedError
