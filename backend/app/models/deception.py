"""Deception engine: decoy sessions and honeytokens."""
from sqlalchemy import Column, DateTime, Integer, String, Text
from sqlalchemy.sql import func

from app.db.session import Base


class DecoySession(Base):
    __tablename__ = "decoy_sessions"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime(timezone=True), server_default=func.now(), index=True)
    threat_id = Column(Integer, nullable=True, index=True)
    decoy_type = Column(String, nullable=False)  # ssh, database, web, admin_panel
    actor = Column(String, nullable=True)
    source_ip = Column(String, nullable=True)
    activity = Column(Text, nullable=True)  # JSON list of recorded actions
    commands = Column(Text, nullable=True)  # JSON list
    pages = Column(Text, nullable=True)  # JSON list
    credentials_used = Column(String, nullable=True)
    notes = Column(Text, nullable=True)

    def to_dict(self):
        import json as _json
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "threat_id": self.threat_id,
            "decoy_type": self.decoy_type,
            "actor": self.actor,
            "source_ip": self.source_ip,
            "activity": _json.loads(self.activity) if self.activity else [],
            "commands": _json.loads(self.commands) if self.commands else [],
            "pages": _json.loads(self.pages) if self.pages else [],
            "credentials_used": self.credentials_used,
            "notes": self.notes,
        }


class Honeytoken(Base):
    __tablename__ = "honeytokens"

    id = Column(Integer, primary_key=True, index=True)
    token_type = Column(String, nullable=False)  # credential, file, api_key, cookie
    label = Column(String, nullable=False)
    value = Column(String, nullable=False)
    planted_on = Column(String, nullable=True)
    triggered = Column(Integer, default=0)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    def to_dict(self):
        return {
            "id": self.id,
            "token_type": self.token_type,
            "label": self.label,
            "value": self.value,
            "planted_on": self.planted_on,
            "triggered": bool(self.triggered),
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
