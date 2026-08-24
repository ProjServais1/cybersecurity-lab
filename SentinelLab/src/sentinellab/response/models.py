from __future__ import annotations

from datetime import datetime, timezone
from enum import StrEnum
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field


class ResponseActionType(StrEnum):
    """Supported SOC response action types."""

    NOTIFY = "notify"
    BLOCK_IP = "block_ip"
    DISABLE_USER = "disable_user"
    ISOLATE_HOST = "isolate_host"


class ResponseActionStatus(StrEnum):
    """Lifecycle status of a response action."""

    PENDING = "pending"
    EXECUTED = "executed"
    FAILED = "failed"


class ResponseAction(BaseModel):
    """A response action associated with a security incident."""

    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
    )

    action_id: UUID = Field(default_factory=uuid4)

    incident_id: UUID

    action_type: ResponseActionType

    status: ResponseActionStatus = ResponseActionStatus.PENDING

    target: str

    reason: str

    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    executed_at: datetime | None = None

    error_message: str | None = None
