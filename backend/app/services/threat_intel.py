"""Threat intelligence and MITRE ATT&CK correlation."""
import json
import re
from datetime import datetime, timezone
from typing import Dict, List, Optional

from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.threat import Threat
from app.models.telemetry import TelemetryEvent
from app.models.deception import DecoySession
from app.services.mitre import MITRE_TECHNIQUES
from app.services.cowrie import cowrie_service


# Map event types / risk indicators to MITRE techniques
EVENT_TO_MITRE = {
    "failed_login": ["T1110"],
    "login_failed": ["T1110"],
    "ssh_failed": ["T1110", "T1021.004"],
    "ssh_attempt": ["T1021.004"],
    "ssh_success": ["T1078", "T1021.004"],
    "cowrie.login.failed": ["T1110"],
    "cowrie.login.success": ["T1078"],
    "privilege_escalation": ["T1098", "T1068"],
    "powershell": ["T1059.001"],
    "lateral_movement": ["T1021", "T1021.004"],
    "data_exfiltration": ["T1041", "T1567"],
    "usb_insertion": ["T1098"],
    "abnormal_process": ["T1059"],
    "process_start": ["T1059"],
    "command_input": ["T1059"],
    "credential_dump": ["T1003"],
    "reverse_shell": ["T1059.004", "T1071"],
    "file_download": ["T1105"],
}

_CREDENTIAL_FILE_READ = re.compile(
    r"(?:^|[;&|]\s*)(?:cat|head|tail|less|more|grep|awk|sed|strings)\b.*"
    r"(?:/etc/(?:passwd|shadow|gshadow|sudoers)|\.ssh/(?:id_rsa|id_ed25519)|ntds\.dit)",
    re.IGNORECASE,
)
_ELEVATED_COMMAND = re.compile(
    r"\b(?:sudo|su|chmod|chown|useradd|usermod|passwd|setcap|rm|dd|mkfs|wget|curl)\b",
    re.IGNORECASE,
)
_REVERSE_SHELL_COMMAND = re.compile(
    r"\b(?:nc\s+-e|netcat|ncat|bash\s+-i|sh\s+-i|socat|reverse|shred)\b",
    re.IGNORECASE,
)


def classify_observed_severity(observations: List[Dict], commands: Optional[List[str]] = None) -> Dict[str, str]:
    """Classify only observed activity using deterministic rules."""
    all_cmds = list(commands or [])
    for obs in observations:
        if obs.get("event_type") == "command_input":
            req = obs.get("request") or obs.get("command") or obs.get("input")
            if req and isinstance(req, str) and req.strip():
                all_cmds.append(req.strip())

    for command in all_cmds:
        if _CREDENTIAL_FILE_READ.search(command):
            return {
                "label": "Elevated activity",
                "reason": f"Credential file read observed: {command}",
            }
        if _REVERSE_SHELL_COMMAND.search(command):
            return {
                "label": "Elevated activity",
                "reason": f"Reverse shell / execution payload observed: {command}",
            }
        if _ELEVATED_COMMAND.search(command):
            return {
                "label": "Elevated activity",
                "reason": f"Privilege, write, destructive, or file-transfer command observed: {command}",
            }

    if all_cmds:
        return {
            "label": "Active probing",
            "reason": f"Command observed without a configured elevated-activity pattern: {all_cmds[0]}",
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
        is_attack = (
            decision in ("deceive", "deny")
            or risk_score >= 45.0
            or event.status == "failure"
            or (event.event_type and any(k in event.event_type.lower() for k in ["fail", "attack", "escalat", "exfiltrat", "honeypot", "lateral", "abnormal", "powershell"]))
            or (event.risk_indicators and len(str(event.risk_indicators)) > 4)
        )
        if not is_attack:
            return None

        # Find or create threat actor
        actor = None
        if event.ip_address:
            actor = self.db.query(Threat).filter(Threat.ip_address == event.ip_address).first()
        if actor is None and event.user_id:
            actor = self.db.query(Threat).filter(Threat.username == event.user_id).first()
        if actor is None and event.device_id:
            actor = self.db.query(Threat).filter(Threat.actor_name == event.device_id).first()

        if not actor:
            severity = "critical" if risk_score >= 80 else "high" if risk_score >= 60 else "medium"
            observed_identity = event.ip_address or event.user_id or event.device_id or "unknown_attacker"
            actor = Threat(
                actor_name=observed_identity,
                username=event.user_id,
                ip_address=event.ip_address,
                risk_score=risk_score,
                severity=severity,
                techniques=json.dumps([]),
                commands=json.dumps([]),
                description=f"Auto-correlated threat ({event.event_type}) from {event.location or 'External'}",
            )
            self.db.add(actor)
            self.db.flush()

        # Update techniques
        techniques = set(json.loads(actor.techniques or "[]"))
        for evt, ids in EVENT_TO_MITRE.items():
            if event.event_type == evt or evt in (event.risk_indicators or []):
                techniques.update(ids)
        if event.mitre_technique:
            techniques.add(event.mitre_technique)

        try:
            raw_event = json.loads(event.raw or "{}") if isinstance(event.raw, str) else dict(event.raw or {})
        except Exception:
            raw_event = {}

        if raw_event.get("mitre_technique"):
            techniques.add(raw_event["mitre_technique"])
        actor.techniques = json.dumps(sorted(techniques))

        # Retain commands
        cmds = json.loads(actor.commands or "[]")
        observed_command = raw_event.get("command") or raw_event.get("input") or raw_event.get("command_line")
        if isinstance(observed_command, str) and observed_command and observed_command not in cmds:
            cmds.append(observed_command)
        actor.commands = json.dumps(cmds[-25:])

        # Escalate risk
        actor.risk_score = max(actor.risk_score, risk_score)
        if actor.risk_score >= 85:
            actor.severity = "critical"
        elif actor.risk_score >= 65:
            actor.severity = "high"
        elif actor.risk_score >= 45:
            actor.severity = "medium"

        actor.last_seen = datetime.now(timezone.utc)
        self.db.commit()
        self.db.refresh(actor)
        return actor

    def list_threats(self, mode: Optional[str] = "COWRIE") -> List[Dict]:
        """Return dynamic observed evidence from Cowrie honeypots and correlated threat streams."""
        try:
            cowrie_service.ingest_logs_to_db(self.db)
        except Exception:
            pass

        # 1. Gather active Decoy sessions
        query = self.db.query(DecoySession).filter(DecoySession.source_ip.isnot(None))
        if mode == "COWRIE":
            query = query.filter(DecoySession.mode == "COWRIE")
        sessions = query.order_by(DecoySession.timestamp.desc()).all()
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
                "threat_risk_score": 0.0,
                "threat_severity": "medium",
                "source_type": "Cowrie honeypot" if session.mode == "COWRIE" else "Live Decoy Trap",
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

            session_cmds = json.loads(session.commands or "[]")
            if session_cmds:
                for c in session_cmds:
                    if c and c not in profile["commands"]:
                        profile["commands"].append(c)
                        profile["command_set"].add(str(c).strip().casefold())

            for observation in observations:
                if not isinstance(observation, dict):
                    continue
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
                protocol = observation.get("protocol") or session.decoy_type or "ssh"
                profile["protocols"].add(protocol)
                session_protocols.add(protocol)

                source_port = observation.get("src_port")
                if source_port is not None:
                    profile["source_ports"].add(source_port)
                    session_source_ports.add(source_port)
                port = observation.get("dst_port") or 2222
                profile["ports"].add(port)
                session_ports.add(port)
                profile["protocol_ports"].add((protocol, port))

                request = observation.get("request") or observation.get("command") or observation.get("input")
                if request:
                    if request not in profile["commands"]:
                        profile["commands"].append(request)
                    profile["command_set"].add(str(request).strip().casefold())

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
                else f"sess-{session.id}"
            )
            profile["sessions"].append({
                "id": session.id,
                "session_id": session_id,
                "first_seen": session_first_seen or session_time,
                "last_seen": session_last_seen or session_time,
                "protocols": sorted(session_protocols) or ["ssh"],
                "source_ports": sorted(session_source_ports) or [2222],
                "ports": sorted(session_ports) or [2222],
            })

        # 2. Merge all correlated Threats from the database when mode != 'COWRIE'
        db_threats = self.db.query(Threat).order_by(Threat.last_seen.desc()).all() if mode != "COWRIE" else []
        for t in db_threats:
            key = t.ip_address or t.actor_name
            if not key:
                continue

            first_seen_iso = t.first_seen.isoformat() if t.first_seen else datetime.now(timezone.utc).isoformat()
            last_seen_iso = t.last_seen.isoformat() if t.last_seen else datetime.now(timezone.utc).isoformat()

            if key not in grouped:
                profile = {
                    "id": t.id + 10000,
                    "actor_name": t.actor_name,
                    "username": t.username,
                    "ip_address": t.ip_address or t.actor_name,
                    "techniques": set(),
                    "commands": [],
                    "first_seen": first_seen_iso,
                    "last_seen": last_seen_iso,
                    "observations": [],
                    "protocols": {"ssh", "tcp"},
                    "source_ports": set(),
                    "ports": {22, 8000},
                    "session_ids": {t.id},
                    "sessions": [{
                        "id": t.id,
                        "session_id": f"threat-{t.id}",
                        "first_seen": first_seen_iso,
                        "last_seen": last_seen_iso,
                        "protocols": ["ssh"],
                        "source_ports": [],
                        "ports": [22],
                    }],
                    "command_set": set(),
                    "protocol_ports": {("ssh", 22)},
                    "threat_risk_score": t.risk_score,
                    "threat_severity": t.severity,
                    "source_type": "External Ingest / Threat Stream",
                }
                grouped[key] = profile
            else:
                profile = grouped[key]
                profile["threat_risk_score"] = max(profile.get("threat_risk_score", 0.0), t.risk_score)
                profile["username"] = profile["username"] or t.username

            # Add techniques
            if t.techniques:
                try:
                    t_list = json.loads(t.techniques) if isinstance(t.techniques, str) else list(t.techniques)
                    profile["techniques"].update(t_list)
                except Exception:
                    pass

            # Add commands
            if t.commands:
                try:
                    c_list = json.loads(t.commands) if isinstance(t.commands, str) else list(t.commands)
                    for c in c_list:
                        if c and c not in profile["commands"]:
                            profile["commands"].append(c)
                            profile["command_set"].add(str(c).strip().casefold())
                except Exception:
                    pass

        # 3. Pull recent TelemetryEvents for each actor to enrich observations when mode != "COWRIE"
        if mode != "COWRIE":
            for key, profile in grouped.items():
                if len(profile["observations"]) < 5:
                    recent_events = (
                        self.db.query(TelemetryEvent)
                        .filter(
                            (TelemetryEvent.ip_address == profile["ip_address"]) |
                            (TelemetryEvent.user_id == profile["username"]) |
                            (TelemetryEvent.device_id == profile["actor_name"])
                        )
                        .order_by(TelemetryEvent.timestamp.desc())
                        .limit(20)
                        .all()
                    )
                    for ev in recent_events:
                        ts_str = ev.timestamp.isoformat() if ev.timestamp else datetime.now(timezone.utc).isoformat()
                        try:
                            raw_data = json.loads(ev.raw or "{}") if isinstance(ev.raw, str) else dict(ev.raw or {})
                        except Exception:
                            raw_data = {}
                        cmd = raw_data.get("command") or raw_data.get("command_line") or raw_data.get("input")
                        if cmd and cmd not in profile["commands"]:
                            profile["commands"].append(cmd)
                            profile["command_set"].add(str(cmd).strip().casefold())
                        if ev.mitre_technique:
                            profile["techniques"].add(ev.mitre_technique)

                        obs_item = {
                            "timestamp": ts_str,
                            "event_id": f"evt-{ev.id}",
                            "event_type": ev.event_type,
                            "src_ip": ev.ip_address or profile["ip_address"],
                            "src_port": raw_data.get("src_port"),
                            "protocol": raw_data.get("protocol") or "tcp",
                            "dst_ip": ev.target_id,
                            "dst_port": raw_data.get("dst_port") or 8000,
                            "request": cmd or ev.event_type,
                            "mitre_technique": ev.mitre_technique,
                        }
                        profile["observations"].append(obs_item)
                        if ev.mitre_technique:
                            profile.setdefault("technique_evidence", []).append({
                                "technique_id": ev.mitre_technique,
                                "event_id": f"evt-{ev.id}",
                                "event_type": ev.event_type,
                                "timestamp": ts_str,
                                "request": cmd or ev.event_type,
                            })

        # 4. Final compilation of response list
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

            severity = classify_observed_severity(observations, profile["commands"])
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
                "severity": severity,
                "description": f"Active threat actor observed via {profile.get('source_type', 'Honeypot & Ingestion')}.",
                "status": "observed",
                "event_source": profile.get("source_type", "Cowrie honeypot"),
                "event_count": max(len(observations), len(profile["commands"]), 1),
                "session_count": max(len(profile["session_ids"]), 1),
                "protocols": sorted(profile["protocols"]) or ["ssh"],
                "source_ports": sorted(profile["source_ports"]) or [2222],
                "ports": sorted(profile["ports"]) or [2222],
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
                    "detail": "This source IP appears in multiple observed attack sessions.",
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
                        "detail": f"Both actors executed: {command}",
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
