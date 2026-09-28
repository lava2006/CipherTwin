"""Threat intelligence and MITRE ATT&CK correlation."""
import json
import random
from datetime import datetime, timezone
from typing import Dict, List, Optional

from sqlalchemy.orm import Session

from app.models.threat import Threat
from app.models.telemetry import TelemetryEvent
from app.services.mitre import MITRE_TECHNIQUES


# Map event types / risk indicators to MITRE techniques
EVENT_TO_MITRE = {
    "failed_login": ["T1110"],
    "privilege_escalation": ["T1098"],
    "powershell": ["T1059.001"],
    "lateral_movement": ["T1021"],
    "data_exfiltration": ["T1041", "T1567"],
    "usb_insertion": ["T1098"],
    "abnormal_process": ["T1059"],
    "ssh_attempt": ["T1021.004"],
    "credential_dump": ["T1003"],
}


class ThreatIntel:
    def __init__(self, db: Session):
        self.db = db

    def correlate(self, event: TelemetryEvent, risk_score: float,
                  decision: str) -> Optional[Threat]:
        if decision not in ("deceive", "deny") and risk_score < 70:
            return None

        # Find or create threat actor
        actor = (
            self.db.query(Threat)
            .filter(Threat.username == event.user_id)
            .first()
        )
        if not actor:
            severity = "critical" if risk_score >= 80 else "high"
            actor = Threat(
                actor_name=self._generate_actor_name(event.user_id or "unknown"),
                username=event.user_id,
                ip_address=event.ip_address,
                risk_score=risk_score,
                severity=severity,
                techniques=json.dumps([]),
                commands=json.dumps([]),
                description="Auto-correlated from high-risk telemetry stream",
            )
            self.db.add(actor)
            self.db.flush()

        # Update techniques
        techniques = set(json.loads(actor.techniques or "[]"))
        for evt, ids in EVENT_TO_MITRE.items():
            if event.event_type == evt or evt in (event.risk_indicators or []):
                techniques.update(ids)
        actor.techniques = json.dumps(sorted(techniques))

        # Update commands
        cmds = json.loads(actor.commands or "[]")
        if event.event_type in ("powershell", "ssh_attempt", "privilege_escalation", "abnormal_process"):
            cmds.append(f"{event.event_type} from {event.ip_address} ({event.location})")
        actor.commands = json.dumps(cmds[-20:])

        # Escalate risk
        actor.risk_score = max(actor.risk_score, risk_score)
        if risk_score >= 90:
            actor.severity = "critical"
        elif risk_score >= 75 and actor.severity not in ("critical",):
            actor.severity = "high"
        actor.last_seen = datetime.now(timezone.utc)
        self.db.commit()
        self.db.refresh(actor)
        return actor

    def list_threats(self) -> List[Threat]:
        return self.db.query(Threat).order_by(Threat.risk_score.desc()).all()

    def get(self, threat_id: int) -> Optional[Threat]:
        return self.db.query(Threat).filter(Threat.id == threat_id).first()

    @staticmethod
    def _generate_actor_name(seed: str) -> str:
        adjectives = ["Coiled", "Crimson", "Silent", "Phantom", "Shadow", "Glitch", "Iron", "Cipher"]
        animals = ["Viper", "Owl", "Bear", "Spider", "Wraith", "Lynx", "Hound", "Raven"]
        rnd = random.Random(seed)
        return f"{rnd.choice(adjectives)} {rnd.choice(animals)}"

    @staticmethod
    def tactics_breakdown(threat: Threat) -> Dict[str, List[str]]:
        techniques = json.loads(threat.techniques or "[]")
        out: Dict[str, List[str]] = {}
        for tid in techniques:
            info = MITRE_TECHNIQUES.get(tid)
            if not info:
                continue
            out.setdefault(info["tactic"], []).append(f"{tid} – {info['name']}")
        return out
