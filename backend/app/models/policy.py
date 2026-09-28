"""Zero Trust policies and improvement history."""
from sqlalchemy import Column, DateTime, Float, Integer, String, Text
from sqlalchemy.sql import func

from app.db.session import Base


class Policy(Base):
    __tablename__ = "policies"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, nullable=False)
    description = Column(Text, nullable=True)
    rule = Column(String, nullable=False)  # e.g. "deny_if:risk>60 AND location!=trusted"
    priority = Column(Integer, default=100)
    enabled = Column(Integer, default=1)
    weight = Column(Float, default=1.0)  # quantum weight
    false_positive_rate = Column(Float, default=0.0)
    false_negative_rate = Column(Float, default=0.0)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "rule": self.rule,
            "priority": self.priority,
            "enabled": bool(self.enabled),
            "weight": self.weight,
            "false_positive_rate": self.false_positive_rate,
            "false_negative_rate": self.false_negative_rate,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


class PolicyImprovement(Base):
    __tablename__ = "policy_improvements"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime(timezone=True), server_default=func.now())
    algorithm = Column(String, default="QAOA-Sim")
    before_score = Column(Float, default=0.0)
    after_score = Column(Float, default=0.0)
    before_fp = Column(Float, default=0.0)
    after_fp = Column(Float, default=0.0)
    before_fn = Column(Float, default=0.0)
    after_fn = Column(Float, default=0.0)
    duration_ms = Column(Integer, default=0)
    iterations = Column(Integer, default=0)
    summary = Column(Text, nullable=True)
    changes = Column(Text, nullable=True)  # JSON list

    def to_dict(self):
        import json as _json
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "algorithm": self.algorithm,
            "before_score": self.before_score,
            "after_score": self.after_score,
            "before_fp": self.before_fp,
            "after_fp": self.after_fp,
            "before_fn": self.before_fn,
            "after_fn": self.after_fn,
            "duration_ms": self.duration_ms,
            "iterations": self.iterations,
            "summary": self.summary,
            "changes": _json.loads(self.changes) if self.changes else [],
        }
