from datetime import datetime, timezone
from uuid import uuid4

import pytest
from pydantic import ValidationError

from sentinellab.response.models import (
    ResponseAction,
    ResponseActionStatus,
    ResponseActionType,
)


def test_create_pending_response_action() -> None:
    incident_id = uuid4()

    action = ResponseAction(
        incident_id=incident_id,
        action_type=ResponseActionType.BLOCK_IP,
        target="192.168.1.50",
        reason="Repeated SSH brute-force attempts.",
    )

    assert action.incident_id == incident_id
    assert action.action_type == ResponseActionType.BLOCK_IP
    assert action.status == ResponseActionStatus.PENDING
    assert action.target == "192.168.1.50"
    assert action.executed_at is None
    assert action.error_message is None


def test_response_action_generates_unique_id() -> None:
    incident_id = uuid4()

    action_one = ResponseAction(
        incident_id=incident_id,
        action_type=ResponseActionType.NOTIFY,
        target="soc-team",
        reason="Security incident detected.",
    )

    action_two = ResponseAction(
        incident_id=incident_id,
        action_type=ResponseActionType.NOTIFY,
        target="soc-team",
        reason="Security incident detected.",
    )

    assert action_one.action_id != action_two.action_id


def test_response_action_timestamp_is_timezone_aware() -> None:
    action = ResponseAction(
        incident_id=uuid4(),
        action_type=ResponseActionType.NOTIFY,
        target="soc-team",
        reason="Security incident detected.",
    )

    assert action.created_at.tzinfo is not None
    assert action.created_at.utcoffset() is not None


def test_response_action_accepts_execution_timestamp() -> None:
    executed_at = datetime(
        2026,
        8,
        24,
        12,
        0,
        0,
        tzinfo=timezone.utc,
    )

    action = ResponseAction(
        incident_id=uuid4(),
        action_type=ResponseActionType.BLOCK_IP,
        target="192.168.1.50",
        reason="SSH brute-force detected.",
        status=ResponseActionStatus.EXECUTED,
        executed_at=executed_at,
    )

    assert action.status == ResponseActionStatus.EXECUTED
    assert action.executed_at == executed_at


def test_response_action_rejects_unknown_fields() -> None:
    with pytest.raises(ValidationError):
        ResponseAction(
            incident_id=uuid4(),
            action_type=ResponseActionType.NOTIFY,
            target="soc-team",
            reason="Security incident detected.",
            unexpected_field="value",
        )
