"""Risk engine decisions and contributing factors."""
from sqlalchemy import Column, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

from app.db.session import Base


class RiskDecision(Base):
    __tablename__ = "risk_decisions"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime(timezone=True), server_default=func.now(), index=True)
    telemetry_id = Column(Integer, nullable=True, index=True)
    user_id = Column(String, nullable=True, index=True)
    device_id = Column(String, nullable=True)
    resource_id = Column(String, nullable=True)
    risk_score = Column(Float, nullable=False)
    decision = Column(String, nullable=False)  # allow, restricted, deny, deceive
    confidence = Column(Float, default=0.0)
    summary = Column(Text, nullable=True)
    factors = relationship("RiskFactor", back_populates="decision", cascade="all, delete-orphan")

    def to_dict(self):
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "telemetry_id": self.telemetry_id,
            "user_id": self.user_id,
            "device_id": self.device_id,
            "resource_id": self.resource_id,
            "risk_score": self.risk_score,
            "decision": self.decision,
            "confidence": self.confidence,
            "summary": self.summary,
            "factors": [f.to_dict() for f in self.factors],
        }


class RiskFactor(Base):
    __tablename__ = "risk_factors"

    id = Column(Integer, primary_key=True, index=True)
    decision_id = Column(Integer, ForeignKey("risk_decisions.id"), nullable=False)
    name = Column(String, nullable=False)  # identity, behavior, device, location, history
    weight = Column(Float, default=0.0)
    score = Column(Float, default=0.0)
    contribution = Column(Float, default=0.0)
    description = Column(Text, nullable=True)
    decision = relationship("RiskDecision", back_populates="factors")

    def to_dict(self):
        return {
            "name": self.name,
            "weight": self.weight,
            "score": self.score,
            "contribution": self.contribution,
            "description": self.description,
        }


class AnalystFeedback(Base):
    __tablename__ = "analyst_feedback"

    id = Column(Integer, primary_key=True, index=True)
    decision_id = Column(Integer, ForeignKey("risk_decisions.id"), nullable=False, index=True)
    analyst_id = Column(String, nullable=False, index=True)
    original_prediction = Column(String, nullable=False)  # allow, restricted, deceive, deny
    analyst_label = Column(String, nullable=False)  # TRUE_POSITIVE, FALSE_POSITIVE, TRUE_NEGATIVE, FALSE_NEGATIVE
    reason = Column(Text, nullable=True)
    timestamp = Column(DateTime(timezone=True), server_default=func.now(), index=True)

    def to_dict(self):
        return {
            "id": self.id,
            "decision_id": self.decision_id,
            "analyst_id": self.analyst_id,
            "original_prediction": self.original_prediction,
            "analyst_label": self.analyst_label,
            "reason": self.reason,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
        }
