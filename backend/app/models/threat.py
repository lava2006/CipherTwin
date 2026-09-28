"""Threat actor profiles with MITRE ATT&CK mapping."""
from sqlalchemy import Column, DateTime, Float, Integer, String, Text
from sqlalchemy.sql import func

from app.db.session import Base


class Threat(Base):
    __tablename__ = "threats"

    id = Column(Integer, primary_key=True, index=True)
    actor_name = Column(String, nullable=False, unique=True)
    username = Column(String, nullable=True)
    ip_address = Column(String, nullable=True)
    risk_score = Column(Float, default=0.0)
    severity = Column(String, default="medium")  # low, medium, high, critical
    techniques = Column(Text, nullable=True)  # JSON list of MITRE IDs
    commands = Column(Text, nullable=True)  # JSON list
    first_seen = Column(DateTime(timezone=True), server_default=func.now())
    last_seen = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    description = Column(Text, nullable=True)
    status = Column(String, default="active")  # active, contained, neutralized

    def to_dict(self):
        import json as _json
        return {
            "id": self.id,
            "actor_name": self.actor_name,
            "username": self.username,
            "ip_address": self.ip_address,
            "risk_score": self.risk_score,
            "severity": self.severity,
            "techniques": _json.loads(self.techniques) if self.techniques else [],
            "commands": _json.loads(self.commands) if self.commands else [],
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "description": self.description,
            "status": self.status,
        }


class ThreatTechnique(Base):
    """Reference catalog of MITRE ATT&CK techniques."""
    __tablename__ = "threat_techniques"

    id = Column(String, primary_key=True)  # T1003 etc
    name = Column(String, nullable=False)
    tactic = Column(String, nullable=False)
    description = Column(Text, nullable=True)
