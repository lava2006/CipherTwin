"""Pydantic v2 schemas for multi-source telemetry events.

Defines the canonical event models accepted by the /ingest endpoints and
published to the RabbitMQ topic exchange. Each model maps to a routing key
via ROUTING_KEY_TO_MODEL so the twin consumer can deserialize correctly.
"""
from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field


class EDREvent(BaseModel):
    """Endpoint Detection and Response event from a remote agent."""
    event_id: str = Field(..., description="Unique event identifier (client-generated UUID).")
    timestamp: datetime = Field(..., description="UTC timestamp of the event.")
    device_id: str = Field(..., description="Source device hostname or ID.")
    event_type: str = Field(..., description="EDR event category (process_start, file_write, etc.).")
    process_name: Optional[str] = Field(None, max_length=255)
    process_path: Optional[str] = Field(None, max_length=512)
    command_line: Optional[str] = Field(None, max_length=2048)
    user: Optional[str] = Field(None, max_length=128)
    risk_indicators: list[str] = Field(default_factory=list)
    raw: dict = Field(default_factory=dict)


class IAMEvent(BaseModel):
    """Identity and Access Management event (ssh login, auth, etc.)."""
    event_id: str = Field(..., description="Unique event identifier (client-generated UUID).")
    timestamp: datetime = Field(..., description="UTC timestamp of the event.")
    device_id: str = Field(..., description="Source device hostname or ID.")
    event_type: str = Field(..., description="IAM event category (ssh_success, ssh_failed, etc.).")
    username: Optional[str] = Field(None, max_length=128)
    src_ip: Optional[str] = Field(None, max_length=64)
    src_port: Optional[int] = Field(None, ge=1, le=65535)
    dst_port: Optional[int] = Field(None, ge=1, le=65535)
    success: bool = Field(False)
    raw: dict = Field(default_factory=dict)


class NetFlowEvent(BaseModel):
    """Network flow event (connections, traffic)."""
    event_id: str = Field(..., description="Unique event identifier (client-generated UUID).")
    timestamp: datetime = Field(..., description="UTC timestamp of the event.")
    device_id: str = Field(..., description="Source device hostname or ID.")
    src_ip: str = Field(..., max_length=64)
    dst_ip: str = Field(..., max_length=64)
    src_port: int = Field(..., ge=1, le=65535)
    dst_port: int = Field(..., ge=1, le=65535)
    protocol: str = Field("tcp", max_length=16)
    bytes_sent: int = Field(0, ge=0)
    bytes_recv: int = Field(0, ge=0)
    raw: dict = Field(default_factory=dict)


class CowrieEvent(BaseModel):
    """Cowrie honeypot event normalized for the telemetry pipeline.

    Passwords are never stored raw — only a boolean flag indicating presence.
    """
    event_id: str = Field(..., description="Cowrie session ID + event sequence (unique per event).")
    timestamp: datetime = Field(..., description="UTC timestamp of the Cowrie event.")
    session: str = Field(..., max_length=128, description="Cowrie session identifier.")
    src_ip: str = Field(..., max_length=64, description="Attacker source IP.")
    eventid: str = Field(..., max_length=64, description="Cowrie eventid (e.g. cowrie.login.failed).")
    username: Optional[str] = Field(None, max_length=128)
    password_present: bool = Field(False, description="True if a password was observed (value not stored).")
    command: Optional[str] = Field(None, max_length=2048, description="Command input, if any.")
    url: Optional[str] = Field(None, max_length=1024, description="Download URL, if any.")
    url_sha256: Optional[str] = Field(None, max_length=64, description="SHA-256 of downloaded file, if any.")
    raw: dict = Field(default_factory=dict)


# Registry mapping routing keys to pydantic models. The twin consumer uses this
# to deserialize messages from the topic exchange based on their routing key.
ROUTING_KEY_TO_MODEL: dict[str, type[BaseModel]] = {
    "telemetry.edr": EDREvent,
    "telemetry.iam": IAMEvent,
    "telemetry.netflow": NetFlowEvent,
    "telemetry.cowrie": CowrieEvent,
}

# All known routing keys for binding the twin.events queue to the topic exchange.
ALL_ROUTING_KEYS: list[str] = list(ROUTING_KEY_TO_MODEL.keys())
