from typing import List
from pydantic import BaseModel, Field


class RiskFactorOut(BaseModel):
    name: str
    weight: float
    score: float
    contribution: float
    description: str | None


class RiskDecisionOut(BaseModel):
    id: int
    timestamp: str | None
    telemetry_id: int | None
    user_id: str | None
    device_id: str | None
    resource_id: str | None
    risk_score: float
    decision: str
    confidence: float
    summary: str | None
    factors: List[RiskFactorOut] = []


class RiskPredictionIn(BaseModel):
    """Telemetry payload accepted by the standalone ML prediction endpoint."""
    event_type: str = Field(min_length=1, max_length=64)
    user_id: str | None = Field(default=None, max_length=128)
    device_id: str | None = Field(default=None, max_length=128)
    target_id: str | None = Field(default=None, max_length=128)
    location: str | None = Field(default=None, max_length=256)
    ip_address: str | None = Field(default=None, max_length=64)
    status: str = Field(default="success", max_length=32)
    risk_indicators: List[str] = Field(default_factory=list)
    failed_logins: int = Field(default=0, ge=0, le=20)
    device_trust: float | None = Field(default=None, ge=0, le=100)
