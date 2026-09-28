"""Digital twin models: nodes (assets) and relationships."""
from sqlalchemy import Column, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.sql import func

from app.db.session import Base


class TwinNode(Base):
    """A single asset in the digital twin graph."""
    __tablename__ = "twin_nodes"

    id = Column(String, primary_key=True, index=True)  # stable uuid-like key
    label = Column(String, nullable=False)
    type = Column(String, nullable=False, index=True)  # user, device, server, database, application
    ip_address = Column(String, nullable=True)
    location = Column(String, nullable=True)
    department = Column(String, nullable=True)
    status = Column(String, default="online")  # online, offline, compromised
    trust_score = Column(Float, default=80.0)
    risk_score = Column(Float, default=0.0)
    sensitivity = Column(String, default="medium")  # low, medium, high, critical
    os = Column(String, nullable=True)
    tags = Column(String, nullable=True)  # comma-separated
    last_seen = Column(DateTime(timezone=True), server_default=func.now())
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    def to_dict(self):
        return {
            "id": self.id,
            "label": self.label,
            "type": self.type,
            "ip_address": self.ip_address,
            "location": self.location,
            "department": self.department,
            "status": self.status,
            "trust_score": self.trust_score,
            "risk_score": self.risk_score,
            "sensitivity": self.sensitivity,
            "os": self.os,
            "tags": (self.tags or "").split(",") if self.tags else [],
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
        }


class TwinRelationship(Base):
    """An edge in the digital twin graph."""
    __tablename__ = "twin_relationships"

    id = Column(Integer, primary_key=True, index=True)
    source_id = Column(String, ForeignKey("twin_nodes.id"), nullable=False)
    target_id = Column(String, ForeignKey("twin_nodes.id"), nullable=False)
    relation = Column(String, nullable=False)  # uses, owns, accesses, hosts, connects_to, administers
    weight = Column(Float, default=1.0)
    description = Column(Text, nullable=True)
