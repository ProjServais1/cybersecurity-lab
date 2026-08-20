from datetime import timezone
from pathlib import Path

from sentinellab.collectors.file import FileCollector
from sentinellab.correlation.engine import CorrelationEngine
from sentinellab.detection.engine import DetectionEngine
from sentinellab.detection.ssh_bruteforce import SSHBruteForceDetector
from sentinellab.models.security_event import EventSeverity
from sentinellab.parsers.ssh import SSHParser
from sentinellab.pipeline.pipeline import Pipeline


def test_file_collector_parser_detection_correlation_pipeline(
    tmp_path: Path,
) -> None:
    """The complete SSH pipeline must produce a security incident."""

    log_file = tmp_path / "auth.log"

    log_file.write_text(
        "Aug 17 18:00:00 server01 sshd[4217]: "
        "Failed password for invalid user admin "
        "from 192.168.1.50 port 45221 ssh2\n"
        "Aug 17 18:00:10 server01 sshd[4218]: "
        "Failed password for invalid user admin "
        "from 192.168.1.50 port 45222 ssh2\n"
        "Aug 17 18:00:20 server01 sshd[4219]: "
        "Failed password for invalid user admin "
        "from 192.168.1.50 port 45223 ssh2\n"
        "Aug 17 18:00:30 server01 sshd[4220]: "
        "Failed password for invalid user admin "
        "from 192.168.1.50 port 45224 ssh2\n"
        "Aug 17 18:00:40 server01 sshd[4221]: "
        "Failed password for invalid user admin "
        "from 192.168.1.50 port 45225 ssh2\n",
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

    assert len(events) == 5

    detection_engine = DetectionEngine(
        detectors=[
            SSHBruteForceDetector(
                threshold=5,
                window_seconds=60,
            )
        ]
    )

    alerts = detection_engine.process(events)

    assert len(alerts) == 1
    assert alerts[0].severity == EventSeverity.HIGH
    assert str(alerts[0].source_ip) == "192.168.1.50"
    assert alerts[0].event_count == 5
    assert len(alerts[0].event_ids) == 5

    correlation_engine = CorrelationEngine(
        window_seconds=300,
    )

    incidents = correlation_engine.correlate(alerts)

    assert len(incidents) == 1

    incident = incidents[0]

    assert incident.severity == EventSeverity.HIGH
    assert str(incident.source_ip) == "192.168.1.50"
    assert incident.alert_ids == [alerts[0].alert_id]
    assert incident.event_ids == alerts[0].event_ids
    assert incident.created_at == alerts[0].timestamp
    assert incident.updated_at == alerts[0].timestamp
