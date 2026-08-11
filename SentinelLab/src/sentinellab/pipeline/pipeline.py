from __future__ import annotations

from collections.abc import Iterator
from typing import Protocol

from sentinellab.models.security_event import SecurityEvent


class CollectorProtocol(Protocol):
    """Contract expected from event collectors."""

    def collect(self) -> Iterator[str]:
        """Yield raw security events."""
        ...


class ParserProtocol(Protocol):
    """Contract expected from event parsers."""

    def parse(self, raw_event: str) -> SecurityEvent | None:
        """Parse a raw event into a SecurityEvent."""
        ...


class Pipeline:
    """Connect a collector to a parser."""

    def __init__(
        self,
        collector: CollectorProtocol,
        parser: ParserProtocol,
    ) -> None:
        self._collector = collector
        self._parser = parser

    def run(self) -> Iterator[SecurityEvent]:
        """Collect raw events and yield successfully parsed events."""
        for raw_event in self._collector.collect():
            event = self._parser.parse(raw_event)

            if event is not None:
                yield event
