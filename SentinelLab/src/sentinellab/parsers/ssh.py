from __future__ import annotations

from datetime import datetime, tzinfo
import re
from typing import Final

from sentinellab.models.security_event import (
    CollectorInfo,
    Endpoint,
    EventCategory,
    EventContext,
    EventSeverity,
    EventStatus,
    EventType,
    NetworkContext,
    Outcome,
    ProcessContext,
    SecurityEvent,
    UserContext,
)
from sentinellab.parsers.base import Parser


class SSHParser(Parser):
    """Parse OpenSSH authentication log messages."""

    VERSION: Final[str] = "0.1.0"

    _FAILED_PASSWORD_PATTERN: Final[re.Pattern[str]] = re.compile(
        r"^"
        r"(?P<month>[A-Z][a-z]{2})\s+"
        r"(?P<day>\d{1,2})\s+"
        r"(?P<time>\d{2}:\d{2}:\d{2})\s+"
        r"(?P<hostname>\S+)\s+"
        r"sshd\[(?P<pid>\d+)\]:\s+"
        r"Failed password for "
        r"(?:(?P<invalid>invalid user)\s+)?"
        r"(?P<username>\S+)\s+"
        r"from\s+"
        r"(?P<source_ip>\S+)\s+"
        r"port\s+"
        r"(?P<source_port>\d+)\s+"
        r"(?P<protocol>\S+)"
        r"$"
    )

    _ACCEPTED_PASSWORD_PATTERN: Final[re.Pattern[str]] = re.compile(
        r"^"
        r"(?P<month>[A-Z][a-z]{2})\s+"
        r"(?P<day>\d{1,2})\s+"
        r"(?P<time>\d{2}:\d{2}:\d{2})\s+"
        r"(?P<hostname>\S+)\s+"
        r"sshd\[(?P<pid>\d+)\]:\s+"
        r"Accepted password for "
        r"(?P<username>\S+)\s+"
        r"from\s+"
        r"(?P<source_ip>\S+)\s+"
        r"port\s+"
        r"(?P<source_port>\d+)\s+"
        r"(?P<protocol>\S+)"
        r"$"
    )

    def __init__(self, year: int, timezone: tzinfo) -> None:
        self._year = year
        self._timezone = timezone

    def parse(self, raw_message: str) -> SecurityEvent | None:
        """Parse a raw SSH log into a SecurityEvent."""

        failed_match = self._FAILED_PASSWORD_PATTERN.match(raw_message)

        if failed_match is not None:
            match = failed_match
            event_type = EventType.LOGIN_FAILED
            outcome_status = EventStatus.FAILURE
            outcome_reason = "invalid_credentials"
            invalid_user = match.group("invalid") is not None

        else:
            accepted_match = self._ACCEPTED_PASSWORD_PATTERN.match(raw_message)

            if accepted_match is None:
                return None

            match = accepted_match
            event_type = EventType.LOGIN_SUCCESS
            outcome_status = EventStatus.SUCCESS
            outcome_reason = None
            invalid_user = False

        timestamp = datetime.strptime(
            (
                f"{self._year} "
                f"{match.group('month')} "
                f"{match.group('day')} "
                f"{match.group('time')}"
            ),
            "%Y %b %d %H:%M:%S",
        ).replace(tzinfo=self._timezone)

        username = match.group("username")

        metadata = {
            "invalid_user": invalid_user,
            "ssh_protocol_version": match.group("protocol"),
        }

        return SecurityEvent(
            timestamp=timestamp,
            event=EventContext(
                type=event_type,
                category=EventCategory.AUTHENTICATION,
                action="ssh_login",
            ),
            source=Endpoint(
                ip=match.group("source_ip"),
                port=int(match.group("source_port")),
            ),
            destination=Endpoint(
                hostname=match.group("hostname"),
                port=22,
            ),
            user=UserContext(
                username=username,
            ),
            process=ProcessContext(
                name="sshd",
                pid=int(match.group("pid")),
            ),
            network=NetworkContext(
                protocol="ssh",
                direction="inbound",
            ),
            outcome=Outcome(
                status=outcome_status,
                reason=outcome_reason,
            ),
            severity=EventSeverity.INFO,
            collector=CollectorInfo(
                name="ssh-parser",
                version=self.VERSION,
            ),
            raw_message=raw_message,
            metadata=metadata,
        )
