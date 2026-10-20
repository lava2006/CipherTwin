"""Audit logs for everything important."""
from sqlalchemy import Column, DateTime, Integer, String, Text
from sqlalchemy.sql import func

from app.db.session import Base


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime(timezone=True), server_default=func.now(), index=True)
    actor = Column(String, nullable=True)  # user or system
    action = Column(String, nullable=False, index=True)
    target = Column(String, nullable=True)
    details = Column(Text, nullable=True)
    severity = Column(String, default="info")  # info, warning, critical
    ip_address = Column(String, nullable=True)

    def to_dict(self):
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "actor": self.actor,
            "action": self.action,
            "target": self.target,
            "details": self.details,
            "severity": self.severity,
            "ip_address": self.ip_address,
        }
