"""Explainable Zero Trust risk engine.

Computes a weighted risk score in [0, 100] from contributing factors and
returns a human-readable explanation of the decision.
"""
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from jinja2 import Environment, FileSystemLoader

from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.risk import RiskDecision, RiskFactor
from app.models.telemetry import TelemetryEvent
from app.models.twin import TwinNode
from app.ml.inference import predict as ml_predict


# Default factor weights. Sum is normalized to 1.0 in the engine.
DEFAULT_WEIGHTS = {
    "identity": 0.20,
    "behavior": 0.30,
    "device": 0.20,
    "location": 0.10,
    "history": 0.20,
}


_TEMPLATE_ENV = Environment(
    loader=FileSystemLoader(Path(__file__).resolve().parents[1] / "templates"),
    autoescape=False,
)
_RISK_SUMMARY_TEMPLATE = _TEMPLATE_ENV.get_template("risk_summary.j2")


@dataclass
class FactorResult:
    name: str
    score: float
    weight: float
    contribution: float
    description: str


@dataclass
class EngineResult:
    risk_score: float
    decision: str
    confidence: float
    summary: str
    factors: List[FactorResult] = field(default_factory=list)
    reasons: List[str] = field(default_factory=list)
    ml: Dict[str, float | str] = field(default_factory=dict)


class ZeroTrustEngine:
    """Weighted, explainable Zero Trust decision engine."""

    def __init__(self, weights: Optional[Dict[str, float]] = None):
        self.weights = {**DEFAULT_WEIGHTS, **(weights or {})}

    # ---- per-factor scoring helpers ----
    def score_identity(self, event: TelemetryEvent) -> Tuple[float, str]:
        indicators = event.risk_indicators or []
        score = 0.0
        reasons: List[str] = []
        # failed logins
        if event.event_type == "failed_login":
            score += 35
            reasons.append("Authentication failure recorded")
        if "brute_force" in indicators:
            score += 35
            reasons.append("Brute-force pattern detected")
        if "impossible_travel" in indicators:
            score += 25
            reasons.append("Impossible-travel event detected")
        if "credential_stuffing" in indicators:
            score += 30
            reasons.append("Credential-stuffing signature")
        score = min(100, score)
        desc = "; ".join(reasons) if reasons else "Identity signals within baseline"
        return score, desc

    def score_behavior(self, event: TelemetryEvent) -> Tuple[float, str]:
        indicators = event.risk_indicators or []
        score = 0.0
        reasons: List[str] = []
        high_risk_types = {
            "privilege_escalation": 55,
            "powershell": 45,
            "abnormal_process": 35,
            "usb_insertion": 25,
            "lateral_movement": 60,
            "data_exfiltration": 70,
        }
        if event.event_type in high_risk_types:
            score += high_risk_types[event.event_type]
            reasons.append(f"{event.event_type.replace('_', ' ').title()} observed")
        if "off_hours" in indicators:
            score += 15
            reasons.append("Activity outside business hours")
        if "high_volume" in indicators:
            score += 20
            reasons.append("Anomalous request volume")
        if "sensitive_resource" in indicators:
            score += 25
            reasons.append("Sensitive resource touched")
        score = min(100, score)
        desc = "; ".join(reasons) if reasons else "Behaviour matches baseline"
        return score, desc

    def score_device(self, event: TelemetryEvent, db: Session) -> Tuple[float, str]:
        score = 0.0
        reasons: List[str] = []
        node = None
        if event.device_id:
            node = db.query(TwinNode).filter(TwinNode.id == event.device_id).first()
        indicators = event.risk_indicators or []
        if node:
            if node.status == "compromised":
                score += 80
                reasons.append(f"Device {node.label} is marked compromised")
            if node.trust_score < 40:
                score += 40
                reasons.append(f"Device trust score low ({node.trust_score:.0f})")
            if node.os and "Unknown" in node.os:
                score += 25
                reasons.append("Unrecognised operating system")
        if "usb_insertion" in indicators:
            score += 30
            reasons.append("USB device inserted")
        if "unsigned_binary" in indicators:
            score += 30
            reasons.append("Unsigned binary executed")
        score = min(100, score)
        desc = "; ".join(reasons) if reasons else "Device posture healthy"
        return score, desc

    def score_location(self, event: TelemetryEvent) -> Tuple[float, str]:
        score = 0.0
        reasons: List[str] = []
        loc = (event.location or "").lower()
        if "impossible_travel" in (event.risk_indicators or []):
            score += 70
            reasons.append("Impossible travel between locations")
        if any(token in loc for token in ["tor", "anonymous", "unknown", "proxy"]):
            score += 40
            reasons.append(f"Anonymous network: {event.location}")
        if any(c in loc for c in ["ru", "cn", "kp", "ir"]) and "headquarters" not in loc:
            score += 25
            reasons.append(f"High-risk geolocation: {event.location}")
        if "vpn" in loc:
            score += 10
            reasons.append("VPN egress detected")
        score = min(100, score)
        desc = "; ".join(reasons) if reasons else f"Location consistent: {event.location or 'unknown'}"
        return score, desc

    def score_history(self, event: TelemetryEvent, db: Session) -> Tuple[float, str]:
        score = 0.0
        reasons: List[str] = []
        if event.user_id:
            recent = (
                db.query(TelemetryEvent)
                .filter(TelemetryEvent.user_id == event.user_id)
                .order_by(TelemetryEvent.timestamp.desc())
                .limit(20)
                .all()
            )
            failures = sum(1 for e in recent if e.status == "failure" or e.event_type == "failed_login")
            if failures >= 3:
                score += 40
                reasons.append(f"{failures} failed actions in recent history")
            risky = sum(1 for e in recent if (e.risk_indicators or "").count("sensitive_resource"))
            if risky >= 1:
                score += 20
                reasons.append("Prior sensitive resource access")
        score = min(100, score)
        desc = "; ".join(reasons) if reasons else "No adverse history for this principal"
        return score, desc

    # ---- main evaluation ----
    def evaluate(self, event: TelemetryEvent, db: Session) -> EngineResult:
        identity_score, identity_desc = self.score_identity(event)
        behavior_score, behavior_desc = self.score_behavior(event)
        device_score, device_desc = self.score_device(event, db)
        location_score, location_desc = self.score_location(event)
        history_score, history_desc = self.score_history(event, db)

        factors = [
            FactorResult("Identity Confidence", identity_score, self.weights["identity"],
                         identity_score * self.weights["identity"], identity_desc),
            FactorResult("Behaviour Deviation", behavior_score, self.weights["behavior"],
                         behavior_score * self.weights["behavior"], behavior_desc),
            FactorResult("Device Posture", device_score, self.weights["device"],
                         device_score * self.weights["device"], device_desc),
            FactorResult("Location Anomaly", location_score, self.weights["location"],
                         location_score * self.weights["location"], location_desc),
            FactorResult("Previous History", history_score, self.weights["history"],
                         history_score * self.weights["history"], history_desc),
        ]
        rule_score = round(min(100.0, sum(f.contribution for f in factors)), 2)

        # Confidence: 100 - variance of factor scores (higher variance = lower confidence)
        import statistics
        scores = [f.score for f in factors]
        variance = statistics.pvariance(scores) if len(scores) > 1 else 0
        confidence = max(40.0, min(99.0, 100 - (variance / 5.0)))

        ml_result: Dict[str, float | str] = {}
        total = rule_score
        try:
            node = None
            if event.device_id:
                node = db.query(TwinNode).filter(TwinNode.id == event.device_id).first()
            ml_result = ml_predict(event, device_trust=node.trust_score if node else None)
            total = round(min(100.0, 0.65 * rule_score + 0.35 * float(ml_result["ml_risk_score"])), 2)
            confidence = round(min(99.0, 0.70 * confidence + 0.30 * float(ml_result["confidence"])), 2)
            import logging
            logging.getLogger("ciphertwin.risk").info(
                "ML risk inference | event=%s class=%s malicious=%.2f%% anomaly=%.2f ml_risk=%.2f rule=%.2f final=%.2f",
                event.id, ml_result["predicted_class"], ml_result["malicious_probability"],
                ml_result["anomaly_score"], ml_result["ml_risk_score"], rule_score, total,
            )
        except Exception:
            total = rule_score
            import logging
            logging.getLogger("ciphertwin.risk").exception(
                "ML inference unavailable; using explainable rule score | event=%s", event.id
            )

        if total < settings.risk_threshold_allow:
            decision = "allow"
        elif total < settings.risk_threshold_restricted:
            decision = "restricted"
        elif total < settings.risk_threshold_deny:
            decision = "deceive"
        else:
            decision = "deny"

        contributing = [f for f in factors if f.score >= 35]
        if decision == "allow":
            summary = "Access allowed. All Zero Trust factors within baseline."
        else:
            reasons = [f.description for f in contributing if f.description]
            summary = _RISK_SUMMARY_TEMPLATE.render(
                decision=decision,
                elevated_count=len(reasons),
                reasons=reasons[:3],
                ml=ml_result,
            )

        return EngineResult(
            risk_score=total,
            decision=decision,
            confidence=round(confidence, 2),
            summary=summary,
            factors=factors,
            reasons=[f.description for f in contributing],
            ml=ml_result,
        )

    def persist(self, event: TelemetryEvent, result: EngineResult, db: Session) -> RiskDecision:
        decision = RiskDecision(
            telemetry_id=event.id,
            user_id=event.user_id,
            device_id=event.device_id,
            resource_id=event.target_id,
            risk_score=result.risk_score,
            decision=result.decision,
            confidence=result.confidence,
            summary=result.summary,
        )
        db.add(decision)
        db.flush()
        for f in result.factors:
            db.add(
                RiskFactor(
                    decision_id=decision.id,
                    name=f.name,
                    weight=f.weight,
                    score=f.score,
                    contribution=f.contribution,
                    description=f.description,
                )
            )
        event.processed = 1
        db.flush()
        return decision


engine = ZeroTrustEngine()
