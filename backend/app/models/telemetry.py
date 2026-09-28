"""Telemetry events emitted by simulated EDR/agents."""
from sqlalchemy import Column, DateTime, Float, Integer, String, Text
from sqlalchemy.sql import func

from app.db.session import Base


class TelemetryEvent(Base):
    __tablename__ = "telemetry_events"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime(timezone=True), server_default=func.now(), index=True)
    user_id = Column(String, nullable=True, index=True)
    device_id = Column(String, nullable=True, index=True)
    target_id = Column(String, nullable=True)
    event_type = Column(String, nullable=False, index=True)
    location = Column(String, nullable=True)
    ip_address = Column(String, nullable=True)
    status = Column(String, default="success")  # success, failure, blocked
    risk_indicators = Column(Text, nullable=True)  # JSON array of strings
    raw = Column(Text, nullable=True)  # JSON payload
    processed = Column(Integer, default=0)  # flag for risk engine

    def to_dict(self):
        import json as _json
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "user_id": self.user_id,
            "device_id": self.device_id,
            "target_id": self.target_id,
            "event_type": self.event_type,
            "location": self.location,
            "ip_address": self.ip_address,
            "status": self.status,
            "risk_indicators": _json.loads(self.risk_indicators) if self.risk_indicators else [],
        }
