from datetime import timezone
from pathlib import Path

from sentinellab.collectors.file import FileCollector
from sentinellab.detection.engine import DetectionEngine
from sentinellab.detection.ssh_bruteforce import SSHBruteForceDetector
from sentinellab.models.security_event import EventSeverity
from sentinellab.parsers.ssh import SSHParser
from sentinellab.pipeline.pipeline import Pipeline


def test_file_collector_parser_detection_pipeline(
    tmp_path: Path,
) -> None:
    """The complete ingestion and detection pipeline must detect SSH brute force."""

    log_file = tmp_path / "auth.log"

    log_file.write_text(
        "Aug 09 15:20:01 server01 sshd[4201]: "
        "Failed password for invalid user admin "
        "from 192.168.1.50 port 45201 ssh2\n"
        "Aug 09 15:20:10 server01 sshd[4202]: "
        "Failed password for invalid user admin "
        "from 192.168.1.50 port 45202 ssh2\n"
        "Aug 09 15:20:20 server01 sshd[4203]: "
        "Failed password for invalid user admin "
        "from 192.168.1.50 port 45203 ssh2\n"
        "Aug 09 15:20:30 server01 sshd[4204]: "
        "Failed password for invalid user admin "
        "from 192.168.1.50 port 45204 ssh2\n"
        "Aug 09 15:20:40 server01 sshd[4205]: "
        "Failed password for invalid user admin "
        "from 192.168.1.50 port 45205 ssh2\n"
        "Aug 09 15:21:00 server01 sshd[4206]: "
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

    detection_engine = DetectionEngine(
        detectors=[
            SSHBruteForceDetector(
                threshold=5,
                window_seconds=60,
            )
        ]
    )

    alerts = detection_engine.process(events)

    assert len(events) == 6

    assert len(alerts) == 1

    alert = alerts[0]

    assert alert.rule_id == "SSH-BRUTE-FORCE-001"
    assert alert.rule_name == "SSH Brute Force"
    assert alert.severity == EventSeverity.HIGH
    assert str(alert.source_ip) == "192.168.1.50"

    assert alert.event_count == 5
    assert len(alert.event_ids) == 5

    assert alert.first_event_timestamp.isoformat() == (
        "2026-08-09T15:20:01+00:00"
    )

    assert alert.last_event_timestamp.isoformat() == (
        "2026-08-09T15:20:40+00:00"
    )
