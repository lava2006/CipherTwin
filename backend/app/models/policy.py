from sqlalchemy import Column, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import relationship
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


class PolicyRule(Base):
    __tablename__ = "policy_rules"

    id = Column(Integer, primary_key=True, index=True)
    policy_id = Column(Integer, ForeignKey("policies.id"), nullable=False, index=True)
    condition_field = Column(String, nullable=False)  # risk_threshold, action, resource, role, device_trust, location
    operator = Column(String, nullable=False)  # >, <, >=, <=, ==, !=, contains
    condition_value = Column(String, nullable=False)
    action = Column(String, nullable=False)  # allow, restricted, deceive, deny
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    def to_dict(self):
        return {
            "id": self.id,
            "policy_id": self.policy_id,
            "condition_field": self.condition_field,
            "operator": self.operator,
            "condition_value": self.condition_value,
            "action": self.action,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class PolicyVersion(Base):
    __tablename__ = "policy_versions"

    id = Column(Integer, primary_key=True, index=True)
    policy_id = Column(Integer, ForeignKey("policies.id"), nullable=False, index=True)
    version_number = Column(Integer, nullable=False)
    snapshot = Column(Text, nullable=False)  # JSON snapshot of policy configuration
    created_by = Column(String, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    def to_dict(self):
        import json as _json
        return {
            "id": self.id,
            "policy_id": self.policy_id,
            "version_number": self.version_number,
            "snapshot": _json.loads(self.snapshot) if self.snapshot else {},
            "created_by": self.created_by,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class PolicyChange(Base):
    __tablename__ = "policy_changes"

    id = Column(Integer, primary_key=True, index=True)
    policy_id = Column(Integer, ForeignKey("policies.id"), nullable=False, index=True)
    change_type = Column(String, nullable=False)  # created, updated, tuned, rule_added
    changed_by = Column(String, nullable=True)
    old_value = Column(Text, nullable=True)
    new_value = Column(Text, nullable=True)
    reason = Column(Text, nullable=True)
    timestamp = Column(DateTime(timezone=True), server_default=func.now(), index=True)

    def to_dict(self):
        import json as _json
        return {
            "id": self.id,
            "policy_id": self.policy_id,
            "change_type": self.change_type,
            "changed_by": self.changed_by,
            "old_value": _json.loads(self.old_value) if self.old_value else None,
            "new_value": _json.loads(self.new_value) if self.new_value else None,
            "reason": self.reason,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
        }
