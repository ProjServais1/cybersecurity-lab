from datetime import timezone
from pathlib import Path

from sentinellab.collectors.file import FileCollector
from sentinellab.correlation.engine import CorrelationEngine
from sentinellab.correlation.manager import IncidentManager
from sentinellab.correlation.models import IncidentStatus
from sentinellab.detection.engine import DetectionEngine
from sentinellab.detection.ssh_bruteforce import SSHBruteForceDetector
from sentinellab.models.security_event import EventSeverity
from sentinellab.parsers.ssh import SSHParser
from sentinellab.pipeline.pipeline import Pipeline


def test_complete_detection_correlation_incident_lifecycle(
    tmp_path: Path,
) -> None:
    """Test the complete SentinelLab detection-to-incident lifecycle."""

    log_file = tmp_path / "auth.log"

    log_file.write_text(
        "Aug 20 20:00:00 server01 sshd[4200]: "
        "Failed password for invalid user admin "
        "from 192.168.1.50 port 45221 ssh2\n"
        "Aug 20 20:00:10 server01 sshd[4201]: "
        "Failed password for invalid user admin "
        "from 192.168.1.50 port 45222 ssh2\n"
        "Aug 20 20:00:20 server01 sshd[4202]: "
        "Failed password for invalid user admin "
        "from 192.168.1.50 port 45223 ssh2\n"
        "Aug 20 20:00:30 server01 sshd[4203]: "
        "Failed password for invalid user admin "
        "from 192.168.1.50 port 45224 ssh2\n"
        "Aug 20 20:00:40 server01 sshd[4204]: "
        "Failed password for invalid user admin "
        "from 192.168.1.50 port 45225 ssh2\n",
        encoding="utf-8",
    )

    # ---------------------------------------------------------
    # 1. INGESTION
    # ---------------------------------------------------------

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

    # ---------------------------------------------------------
    # 2. DETECTION
    # ---------------------------------------------------------

    detector = SSHBruteForceDetector(
        threshold=5,
        window_seconds=60,
    )

    detection_engine = DetectionEngine(
        detectors=[detector],
    )

    alerts = detection_engine.process(events)

    assert len(alerts) == 1

    alert = alerts[0]

    assert alert.rule_id == "SSH-BRUTE-FORCE-001"
    assert alert.rule_name == "SSH Brute Force"
    assert alert.severity == EventSeverity.HIGH
    assert str(alert.source_ip) == "192.168.1.50"
    assert alert.event_count == 5
    assert len(alert.event_ids) == 5

    # ---------------------------------------------------------
    # 3. CORRELATION
    # ---------------------------------------------------------

    correlation_engine = CorrelationEngine(
        window_seconds=300,
    )

    incidents = correlation_engine.correlate(
        alerts,
    )

    assert len(incidents) == 1

    incident = incidents[0]

    assert str(incident.source_ip) == "192.168.1.50"
    assert incident.severity == EventSeverity.HIGH
    assert incident.status == IncidentStatus.OPEN

    assert len(incident.alert_ids) == 1
    assert len(incident.event_ids) == 5

    # ---------------------------------------------------------
    # 4. INCIDENT MANAGEMENT
    # ---------------------------------------------------------

    manager = IncidentManager()

    manager.update_status(
        incident,
        IncidentStatus.INVESTIGATING,
    )

    assert incident.status == IncidentStatus.INVESTIGATING

    manager.resolve(incident)

    assert incident.status == IncidentStatus.RESOLVED

    manager.close(incident)

    assert incident.status == IncidentStatus.CLOSED
