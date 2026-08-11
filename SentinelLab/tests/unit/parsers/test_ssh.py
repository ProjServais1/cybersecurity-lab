from datetime import timezone

from sentinellab.models.security_event import (
    EventCategory,
    EventSeverity,
    EventStatus,
    EventType,
)
from sentinellab.parsers.ssh import SSHParser


def test_parse_failed_ssh_login() -> None:
    raw_event = (
        "Aug 09 15:20:31 server01 sshd[4217]: "
        "Failed password for invalid user admin "
        "from 192.168.1.50 port 45221 ssh2"
    )

    parser = SSHParser(
        year=2026,
        timezone=timezone.utc,
    )

    event = parser.parse(raw_event)

    assert event is not None

    assert event.event.type == EventType.LOGIN_FAILED
    assert event.event.category == EventCategory.AUTHENTICATION
    assert event.event.action == "ssh_login"

    assert str(event.source.ip) == "192.168.1.50"
    assert event.source.port == 45221

    assert event.destination.hostname == "server01"
    assert event.destination.port == 22

    assert event.user.username == "admin"

    assert event.process.name == "sshd"
    assert event.process.pid == 4217

    assert event.network.protocol == "ssh"
    assert event.metadata["ssh_protocol_version"] == "ssh2"
    assert event.network.direction == "inbound"

    assert event.outcome.status == EventStatus.FAILURE
    assert event.outcome.reason == "invalid_credentials"

    assert event.severity == EventSeverity.INFO

    assert event.collector.name == "ssh-parser"
    assert event.collector.version == "0.1.0"

    assert event.raw_message == raw_event

    assert event.timestamp.tzinfo is not None
    assert event.timestamp.utcoffset() is not None
def test_parse_failed_ssh_login_preserves_invalid_user_metadata() -> None:
    raw_event = (
        "Aug 09 15:20:31 server01 sshd[4217]: "
        "Failed password for invalid user admin "
        "from 192.168.1.50 port 45221 ssh2"
    )

    parser = SSHParser(
        year=2026,
        timezone=timezone.utc,
    )

    event = parser.parse(raw_event)

    assert event is not None
    assert event.user.username == "admin"
    assert event.metadata["invalid_user"] is True
def test_parse_non_ssh_event_returns_none() -> None:
    raw_event = (
        "Aug 09 15:20:31 server01 CRON[5000]: "
        "pam_unix(cron:session): session opened"
    )

    parser = SSHParser(
        year=2026,
        timezone=timezone.utc,
    )

    event = parser.parse(raw_event)

    assert event is None
def test_parse_timestamp_is_timezone_aware_and_utc() -> None:
    raw_event = (
        "Aug 09 15:20:31 server01 sshd[4217]: "
        "Failed password for invalid user admin "
        "from 192.168.1.50 port 45221 ssh2"
    )

    parser = SSHParser(
        year=2026,
        timezone=timezone.utc,
    )

    event = parser.parse(raw_event)

    assert event is not None
    assert event.timestamp.isoformat() == "2026-08-09T15:20:31+00:00"
def test_parse_successful_ssh_login() -> None:
    """A successful SSH password login must be parsed."""

    raw_event = (
        "Aug 09 15:21:10 server01 sshd[4218]: "
        "Accepted password for servais "
        "from 192.168.1.20 port 45100 ssh2"
    )

    parser = SSHParser(
        year=2026,
        timezone=timezone.utc,
    )

    event = parser.parse(raw_event)

    assert event is not None

    assert event.event.type == EventType.LOGIN_SUCCESS
    assert event.event.category == EventCategory.AUTHENTICATION
    assert event.event.action == "ssh_login"

    assert str(event.source.ip) == "192.168.1.20"
    assert event.source.port == 45100

    assert event.destination.hostname == "server01"
    assert event.destination.port == 22

    assert event.user.username == "servais"

    assert event.process.name == "sshd"
    assert event.process.pid == 4218

    assert event.network.protocol == "ssh"
    assert event.network.direction == "inbound"

    assert event.outcome.status == EventStatus.SUCCESS

    assert event.metadata["ssh_protocol_version"] == "ssh2"
