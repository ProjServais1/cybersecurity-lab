from pathlib import Path
from datetime import timezone

from sentinellab.collectors.file import FileCollector
from sentinellab.models.security_event import EventType
from sentinellab.parsers.ssh import SSHParser
from sentinellab.pipeline.pipeline import Pipeline


def test_file_collector_ssh_parser_pipeline(tmp_path: Path) -> None:
    """The real collector, parser and pipeline must work together."""

    log_file = tmp_path / "auth.log"

    log_file.write_text(
        "Aug 09 15:20:31 server01 sshd[4217]: "
        "Failed password for invalid user admin "
        "from 192.168.1.50 port 45221 ssh2\n"
        "Aug 09 15:21:10 server01 sshd[4218]: "
        "Accepted password for servais "
        "from 192.168.1.20 port 45100 ssh2\n"
        "this line is not an SSH event\n",
        encoding="utf-8",
    )

    collector = FileCollector(log_file)

    parser = SSHParser(
        year=2026,
        timezone=timezone.utc,
    )

    pipeline = Pipeline(
        collector=collector,
        parser=parser,
    )

    events = list(pipeline.run())

    assert len(events) == 2

    assert events[0].event.type == EventType.LOGIN_FAILED
    assert events[0].user.username == "admin"

    assert events[1].event.type == EventType.LOGIN_SUCCESS
    assert events[1].user.username == "servais"

    assert events[0].timestamp.tzinfo is not None
    assert events[1].timestamp.tzinfo is not None
