from datetime import datetime, timezone
from enum import StrEnum
from ipaddress import IPv4Address, IPv6Address
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator


class EventCategory(StrEnum):
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    PROCESS = "process"
    NETWORK = "network"
    FILE = "file"
    SYSTEM = "system"
    WEB = "web"
    MALWARE = "malware"
    CONFIGURATION = "configuration"


class EventType(StrEnum):
    LOGIN = "login"
    LOGOUT = "logout"
    LOGIN_FAILED = "login_failed"
    LOGIN_SUCCESS = "login_success"
    PROCESS_START = "process_start"
    PROCESS_STOP = "process_stop"
    CONNECTION = "connection"
    FILE_CREATE = "file_create"
    FILE_MODIFY = "file_modify"
    FILE_DELETE = "file_delete"
    PRIVILEGE_CHANGE = "privilege_change"
    USER_CREATE = "user_create"
    USER_DELETE = "user_delete"


class EventSeverity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class EventStatus(StrEnum):
    SUCCESS = "success"
    FAILURE = "failure"
    UNKNOWN = "unknown"


class Endpoint(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ip: IPv4Address | IPv6Address | None = None
    port: int | None = Field(default=None, ge=1, le=65535)
    hostname: str | None = None
    asset_id: str | None = None


class UserContext(BaseModel):
    model_config = ConfigDict(extra="forbid")

    username: str | None = None
    uid: int | None = Field(default=None, ge=0)
    domain: str | None = None


class ProcessContext(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str | None = None
    pid: int | None = Field(default=None, ge=0)
    executable: str | None = None
    command_line: str | None = None


class NetworkContext(BaseModel):
    model_config = ConfigDict(extra="forbid")

    protocol: str | None = None
    direction: str | None = None


class Outcome(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: EventStatus = EventStatus.UNKNOWN
    reason: str | None = None


class CollectorInfo(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    version: str


class EventContext(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: EventType
    category: EventCategory
    action: str


class SecurityEvent(BaseModel):
    """
    Canonical security event used throughout SentinelLab.
    """

    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
        validate_assignment=True,
    )

    schema_version: str = "1.0"

    event_id: UUID = Field(default_factory=uuid4)

    timestamp: datetime

    event: EventContext

    source: Endpoint | None = None
    destination: Endpoint | None = None

    user: UserContext | None = None
    process: ProcessContext | None = None
    network: NetworkContext | None = None

    outcome: Outcome = Field(default_factory=Outcome)

    severity: EventSeverity = EventSeverity.INFO

    collector: CollectorInfo

    raw_message: str | None = None

    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("timestamp")
    @classmethod
    def timestamp_must_be_timezone_aware(
        cls,
        value: datetime,
    ) -> datetime:
        """Require timezone-aware timestamps and normalize to UTC."""

        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError(
                "timestamp must include timezone information"
            )

        return value.astimezone(timezone.utc)
