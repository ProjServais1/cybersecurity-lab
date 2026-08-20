from __future__ import annotations

from datetime import datetime
from enum import Enum
from ipaddress import IPv4Address, IPv6Address
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field

from sentinellab.models.security_event import EventSeverity


class IncidentStatus(str, Enum):
    """Lifecycle status of a security incident."""

    OPEN = "open"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"
    CLOSED = "closed"


class Incident(BaseModel):
    """Security incident grouping related security alerts."""

    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
    )

    incident_id: UUID = Field(default_factory=uuid4)

    title: str
    description: str

    severity: EventSeverity
    status: IncidentStatus

    created_at: datetime
    updated_at: datetime

    source_ip: IPv4Address | IPv6Address | None = None

    alert_ids: list[UUID] = Field(default_factory=list)
    event_ids: list[UUID] = Field(default_factory=list)
