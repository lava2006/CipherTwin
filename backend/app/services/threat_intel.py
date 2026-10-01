"""Threat intelligence and MITRE ATT&CK correlation."""
import json
import re
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

_CREDENTIAL_FILE_READ = re.compile(
    r"(?:^|[;&|]\s*)(?:cat|head|tail|less|more|grep|awk|sed|strings)\b.*"
    r"(?:/etc/(?:passwd|shadow|gshadow|sudoers)|\.ssh/(?:id_rsa|id_ed25519)|ntds\.dit)",
    re.IGNORECASE,
)
_ELEVATED_COMMAND = re.compile(
    r"\b(?:sudo|su|chmod|chown|useradd|usermod|passwd|setcap|rm|dd|mkfs|wget)\b",
    re.IGNORECASE,
)


def classify_observed_severity(observations: List[Dict]) -> Dict[str, str]:
    """Classify only observed activity using the displayed deterministic rules."""
    commands = [
        observation.get("request", "").strip()
        for observation in observations
        if observation.get("event_type") == "command_input"
        and isinstance(observation.get("request"), str)
        and observation["request"].strip()
    ]

    for command in commands:
        if _CREDENTIAL_FILE_READ.search(command):
            return {
                "label": "Elevated activity",
                "reason": f"Credential file read observed: {command}",
            }
    for command in commands:
        match = _ELEVATED_COMMAND.search(command)
        if match:
            return {
                "label": "Elevated activity",
                "reason": f"Privilege, write, destructive, or file-transfer command observed: {command}",
            }

    if commands:
        return {
            "label": "Active probing",
            "reason": f"Command observed without a configured elevated-activity pattern: {commands[0]}",
        }
    return {
        "label": "Reconnaissance only",
        "reason": "Connection/login events observed; no commands recorded.",
    }


def _duration_seconds(first_seen: Optional[str], last_seen: Optional[str]) -> Optional[float]:
    if not first_seen or not last_seen:
        return None
    try:
        first = datetime.fromisoformat(first_seen.replace("Z", "+00:00"))
        last = datetime.fromisoformat(last_seen.replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    if first.tzinfo is None:
        first = first.replace(tzinfo=timezone.utc)
    if last.tzinfo is None:
        last = last.replace(tzinfo=timezone.utc)
    return max(0.0, (last - first).total_seconds())


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
                "sessions": [],
                "command_set": set(),
                "protocol_ports": set(),
            })
            profile["id"] = max(profile["id"], session.id)
            profile["username"] = profile["username"] or session.actor
            profile["session_ids"].add(session.id)
            session_time = session.timestamp.isoformat() if session.timestamp else None
            session_first_seen = None
            session_last_seen = None
            session_protocols = set()
            session_ports = set()
            session_source_ports = set()
            for observation in observations:
                observed_at = observation.get("timestamp")
                if observed_at and (not session_first_seen or observed_at < session_first_seen):
                    session_first_seen = observed_at
                if observed_at and (not session_last_seen or observed_at > session_last_seen):
                    session_last_seen = observed_at
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
                    session_protocols.add(protocol)
                source_port = observation.get("src_port")
                if source_port is not None:
                    profile["source_ports"].add(source_port)
                    session_source_ports.add(source_port)
                port = observation.get("dst_port")
                if port is not None:
                    profile["ports"].add(port)
                    session_ports.add(port)
                    if protocol:
                        profile["protocol_ports"].add((protocol, port))
                request = observation.get("request")
                if observation.get("event_type") == "command_input" and request:
                    profile["commands"].append(request)
                    profile["command_set"].add(request.strip().casefold())
                if technique:
                    profile.setdefault("technique_evidence", []).append({
                        "technique_id": technique,
                        "event_id": observation.get("event_id"),
                        "event_type": observation.get("event_type"),
                        "timestamp": observed_at,
                        "request": request,
                    })
                profile["observations"].append(observation)
            if not observations and session_time:
                profile["first_seen"] = profile["first_seen"] or session_time
                profile["last_seen"] = session_time
                session_first_seen = session_time
                session_last_seen = session_time
            session_id = (
                session.notes.removeprefix("Cowrie session ID: ")
                if session.notes and session.notes.startswith("Cowrie session ID: ")
                else None
            )
            profile["sessions"].append({
                "id": session.id,
                "session_id": session_id,
                "first_seen": session_first_seen or session_time,
                "last_seen": session_last_seen or session_time,
                "protocols": sorted(session_protocols),
                "source_ports": sorted(session_source_ports),
                "ports": sorted(session_ports),
            })

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
                "duration_seconds": _duration_seconds(profile["first_seen"], profile["last_seen"]),
                "return_activity": len(profile["session_ids"]) > 1,
                "sessions": profile["sessions"],
                "severity": classify_observed_severity(observations),
                "description": "Observed by Cowrie honeypot; external intelligence unavailable.",
                "status": "observed",
                "event_source": "Cowrie honeypot",
                "event_count": len(observations),
                "session_count": len(profile["session_ids"]),
                "protocols": sorted(profile["protocols"]),
                "source_ports": sorted(profile["source_ports"]),
                "ports": sorted(profile["ports"]),
                "observations": observations,
                "technique_evidence": profile.get("technique_evidence", []),
                "tactics": tactics,
                "related_activity": [],
                "external_intelligence": {
                    "status": "not_available",
                    "provider": None,
                },
            })

        for profile in grouped.values():
            related = next(
                (item for item in results if item["ip_address"] == profile["actor_name"]),
                None,
            )
            if related is None:
                continue
            if len(profile["sessions"]) > 1:
                related["related_activity"].append({
                    "kind": "same_source_ip_sessions",
                    "actor_id": related["id"],
                    "actor_ip": profile["actor_name"],
                    "detail": "This source IP appears in multiple observed Cowrie sessions.",
                    "session_ids": [session["id"] for session in profile["sessions"]],
                })
            for other in grouped.values():
                if other is profile:
                    continue
                for command in sorted(profile["command_set"] & other["command_set"]):
                    related["related_activity"].append({
                        "kind": "shared_command_pattern",
                        "actor_id": other["id"],
                        "actor_ip": other["actor_name"],
                        "detail": f"Both actors ran: {command}",
                    })
                for technique in sorted(profile["techniques"] & other["techniques"]):
                    related["related_activity"].append({
                        "kind": "shared_technique",
                        "actor_id": other["id"],
                        "actor_ip": other["actor_name"],
                        "detail": f"Both actors have observed technique {technique}",
                    })
                for protocol, port in sorted(profile["protocol_ports"] & other["protocol_ports"]):
                    related["related_activity"].append({
                        "kind": "shared_protocol_port",
                        "actor_id": other["id"],
                        "actor_ip": other["actor_name"],
                        "detail": f"Both actors connected via {protocol} to destination port {port}",
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
