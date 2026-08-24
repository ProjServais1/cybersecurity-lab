from datetime import timezone
from pathlib import Path

from sentinellab.collectors.file import FileCollector
from sentinellab.correlation.engine import CorrelationEngine
from sentinellab.detection.engine import DetectionEngine
from sentinellab.detection.ssh_bruteforce import SSHBruteForceDetector
from sentinellab.parsers.ssh import SSHParser
from sentinellab.response.engine import ResponseEngine
from sentinellab.response.models import ResponseActionType
from sentinellab.pipeline.pipeline import Pipeline


def test_complete_detection_correlation_response_pipeline(
    tmp_path: Path,
) -> None:
    """The complete SOC detection-to-response pipeline must work."""

    log_file = tmp_path / "auth.log"

    log_file.write_text(
        "Aug 24 12:00:00 server01 sshd[4201]: "
        "Failed password for invalid user admin "
        "from 192.168.1.50 port 45221 ssh2\n"
        "Aug 24 12:00:05 server01 sshd[4202]: "
        "Failed password for invalid user admin "
        "from 192.168.1.50 port 45222 ssh2\n"
        "Aug 24 12:00:10 server01 sshd[4203]: "
        "Failed password for invalid user admin "
        "from 192.168.1.50 port 45223 ssh2\n"
        "Aug 24 12:00:15 server01 sshd[4204]: "
        "Failed password for invalid user admin "
        "from 192.168.1.50 port 45224 ssh2\n"
        "Aug 24 12:00:20 server01 sshd[4205]: "
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

    assert str(alert.source_ip) == "192.168.1.50"
    assert alert.event_count == 5

    correlation_engine = CorrelationEngine(
        window_seconds=300,
    )

    incidents = correlation_engine.correlate(alerts)

    assert len(incidents) == 1

    incident = incidents[0]

    assert str(incident.source_ip) == "192.168.1.50"
    assert incident.severity.value == "high"
    assert len(incident.alert_ids) == 1
    assert len(incident.event_ids) == 5

    response_engine = ResponseEngine()

    actions = response_engine.generate_actions(incident)

    assert len(actions) == 2

    action_types = {
        action.action_type
        for action in actions
    }

    assert ResponseActionType.NOTIFY in action_types
    assert ResponseActionType.BLOCK_IP in action_types

    block_action = next(
        action
        for action in actions
        if action.action_type == ResponseActionType.BLOCK_IP
    )

    assert block_action.target == "192.168.1.50"
    assert block_action.incident_id == incident.incident_id
