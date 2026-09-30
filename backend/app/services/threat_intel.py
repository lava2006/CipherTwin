"""Threat intelligence and MITRE ATT&CK correlation."""
import json
from datetime import datetime, timezone
from typing import Dict, List, Optional

from sqlalchemy.orm import Session

from app.models.threat import Threat
from app.models.telemetry import TelemetryEvent
from app.models.deception import DecoySession
from app.services.mitre import MITRE_TECHNIQUES
from app.services.cowrie import cowrie_service


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
        actor = None
        if event.ip_address:
            actor = self.db.query(Threat).filter(Threat.ip_address == event.ip_address).first()
        if actor is None and event.user_id:
            actor = self.db.query(Threat).filter(Threat.username == event.user_id).first()
        if not actor:
            severity = "critical" if risk_score >= 80 else "high"
            observed_identity = event.ip_address or event.user_id
            if not observed_identity:
                return None
            actor = Threat(
                actor_name=observed_identity,
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

        # Retain commands only when present in the observed event payload.
        cmds = json.loads(actor.commands or "[]")
        try:
            raw_event = json.loads(event.raw or "{}")
        except (TypeError, json.JSONDecodeError):
            raw_event = {}
        observed_command = raw_event.get("command") or raw_event.get("input")
        if isinstance(observed_command, str) and observed_command:
            cmds.append(observed_command)
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

    def list_threats(self) -> List[Dict]:
        """Return observed Cowrie evidence, never seeded/generated threat claims."""
        cowrie_service.ingest_logs_to_db(self.db)
        sessions = (
            self.db.query(DecoySession)
            .filter(DecoySession.mode == "COWRIE", DecoySession.source_ip.isnot(None))
            .order_by(DecoySession.timestamp.desc())
            .all()
        )
        grouped: Dict[str, Dict] = {}
        for session in sessions:
            observations = json.loads(session.activity or "[]")
            source_ip = session.source_ip
            profile = grouped.setdefault(source_ip, {
                "id": session.id,
                "actor_name": source_ip,
                "username": None,
                "ip_address": source_ip,
                "techniques": set(),
                "commands": [],
                "first_seen": None,
                "last_seen": None,
                "observations": [],
                "protocols": set(),
                "source_ports": set(),
                "ports": set(),
                "session_ids": set(),
            })
            profile["id"] = max(profile["id"], session.id)
            profile["username"] = profile["username"] or session.actor
            profile["session_ids"].add(session.id)
            session_time = session.timestamp.isoformat() if session.timestamp else None
            for observation in observations:
                observed_at = observation.get("timestamp")
                if observed_at and (not profile["first_seen"] or observed_at < profile["first_seen"]):
                    profile["first_seen"] = observed_at
                if observed_at and (not profile["last_seen"] or observed_at > profile["last_seen"]):
                    profile["last_seen"] = observed_at
                technique = observation.get("mitre_technique")
                if technique:
                    profile["techniques"].add(technique)
                protocol = observation.get("protocol")
                if protocol:
                    profile["protocols"].add(protocol)
                source_port = observation.get("src_port")
                if source_port is not None:
                    profile["source_ports"].add(source_port)
                port = observation.get("dst_port")
                if port is not None:
                    profile["ports"].add(port)
                request = observation.get("request")
                if observation.get("event_type") == "command_input" and request:
                    profile["commands"].append(request)
                profile["observations"].append(observation)
            if not observations and session_time:
                profile["first_seen"] = profile["first_seen"] or session_time
                profile["last_seen"] = session_time

        results = []
        for profile in grouped.values():
            techniques = sorted(profile["techniques"])
            tactics: Dict[str, List[str]] = {}
            for technique in techniques:
                info = MITRE_TECHNIQUES.get(technique)
                if info:
                    tactics.setdefault(info["tactic"], []).append(f"{technique} – {info['name']}")
            observations = sorted(
                profile["observations"],
                key=lambda observation: observation.get("timestamp") or "",
            )
            results.append({
                "id": profile["id"],
                "actor_name": profile["actor_name"],
                "username": profile["username"],
                "ip_address": profile["ip_address"],
                "techniques": techniques,
                "commands": list(dict.fromkeys(profile["commands"])),
                "first_seen": profile["first_seen"],
                "last_seen": profile["last_seen"],
                "description": "Observed by Cowrie honeypot; external intelligence unavailable.",
                "status": "observed",
                "event_source": "Cowrie honeypot",
                "event_count": len(observations),
                "session_count": len(profile["session_ids"]),
                "protocols": sorted(profile["protocols"]),
                "source_ports": sorted(profile["source_ports"]),
                "ports": sorted(profile["ports"]),
                "observations": observations,
                "tactics": tactics,
                "external_intelligence": {
                    "status": "not_available",
                    "provider": None,
                },
            })
        return sorted(results, key=lambda profile: profile["last_seen"] or "", reverse=True)

    def get(self, threat_id: int) -> Optional[Dict]:
        return next((profile for profile in self.list_threats() if profile["id"] == threat_id), None)

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
