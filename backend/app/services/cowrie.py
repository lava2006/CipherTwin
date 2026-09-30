"""Cowrie Honeypot Log Ingestion & Normalization Engine for CipherTwin.

Ingests live Cowrie JSON logs into the existing deception session table.

Normalized Events Schema:
- session_id: str
- timestamp: str (ISO)
- src_ip: str
- event_type: connect | login_failed | login_success | command_input | file_download | closed
- username: Optional[str]
- password: Optional[str]
- command: Optional[str]
- mitre_technique: Optional[str]
"""
import json
import logging
from pathlib import Path
from datetime import datetime
from typing import Any, Dict, List, Optional

from app.core.config import settings

logger = logging.getLogger("ciphertwin.cowrie")

# Cowrie eventid to MITRE ATT&CK technique mapping
COWRIE_EVENT_TO_MITRE = {
    "cowrie.login.failed": "T1110",         # Brute Force
    "cowrie.login.success": "T1078",        # Valid Accounts
    "cowrie.command.input": "T1059",        # Command and Scripting Interpreter
    "cowrie.session.file_download": "T1105", # Ingress Tool Transfer
    "cowrie.command.failed": "T1083",       # Discovery
}


class CowrieParser:
    """Parses and normalizes Cowrie JSON logs."""

    @staticmethod
    def parse_line(line: str) -> Optional[Dict[str, Any]]:
        """Parse one raw Cowrie JSON log line into normalized event format."""
        line = line.strip()
        if not line:
            return None
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            return None

        eventid = data.get("eventid", "")
        session_id = data.get("session")
        timestamp = data.get("timestamp")
        src_ip = data.get("src_ip")
        if not eventid or not session_id or not timestamp or not src_ip:
            return None
        try:
            datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        except (TypeError, ValueError):
            return None

        normalized = {
            "session_id": session_id,
            "timestamp": timestamp,
            "src_ip": src_ip,
            "raw_eventid": eventid,
            "mitre_technique": COWRIE_EVENT_TO_MITRE.get(eventid),
            "protocol": data.get("protocol"),
            "src_port": data.get("src_port"),
            "dst_ip": data.get("dst_ip"),
            "dst_port": data.get("dst_port"),
            "request": data.get("input") or data.get("url") or data.get("message"),
        }

        if eventid == "cowrie.session.connect":
            normalized["event_type"] = "connect"
        elif eventid == "cowrie.login.failed":
            normalized["event_type"] = "login_failed"
            normalized["username"] = data.get("username")
            normalized["password"] = data.get("password")
        elif eventid == "cowrie.login.success":
            normalized["event_type"] = "login_success"
            normalized["username"] = data.get("username")
            normalized["password"] = data.get("password")
        elif eventid == "cowrie.command.input":
            normalized["event_type"] = "command_input"
            normalized["command"] = data.get("input")
        elif eventid == "cowrie.session.file_download":
            normalized["event_type"] = "file_download"
            normalized["url"] = data.get("url")
            normalized["outfile"] = data.get("outfile")
        elif eventid == "cowrie.session.closed":
            normalized["event_type"] = "closed"
            normalized["duration"] = data.get("duration")
        else:
            normalized["event_type"] = "unknown"
            normalized["details"] = data.get("message", "")

        return normalized

    def parse_file(self, file_path: str) -> List[Dict[str, Any]]:
        """Parse all events from a Cowrie JSON log file."""
        p = Path(file_path)
        if not p.exists():
            return []
        events = []
        try:
            with open(p, "r", encoding="utf-8") as f:
                for line in f:
                    ev = self.parse_line(line)
                    if ev:
                        events.append(ev)
        except Exception as e:
            logger.error("Failed to read Cowrie log file %s: %s", file_path, e)
        return events


class CowrieService:
    """Manages Cowrie log ingestion and mode status."""

    def __init__(self):
        self.parser = CowrieParser()

    def check_health(self) -> Dict[str, Any]:
        """Truthfully report Cowrie status.
        Detects live Cowrie container on port 2222 or log file.
        """
        import socket
        port_open = False
        banner = ""
        try:
            s = socket.socket()
            s.settimeout(1.5)
            s.connect(("127.0.0.1", 2222))
            banner = s.recv(1024).decode("utf-8", errors="ignore").strip()
            s.close()
            port_open = True
        except Exception:
            pass

        log_path = Path(settings.cowrie_log_path)
        has_logs = log_path.exists()
        events = self.parser.parse_file(str(log_path)) if has_logs else []
        last_event = max(
            (event["timestamp"] for event in events),
            default=None,
        )
        status = "HEALTHY" if port_open and has_logs else "DEGRADED" if port_open or has_logs else "UNAVAILABLE"
        log_status = "AVAILABLE" if has_logs else "UNAVAILABLE"

        return {
            "status": status,
            "mode": "COWRIE" if port_open else "OFFLINE",
            "cowrie_status": "RUNNING" if port_open else "OFFLINE",
            "container_running": port_open,
            "port": 2222,
            "banner": banner or None,
            "log_status": log_status,
            "log_file": str(log_path) if has_logs else None,
            "total_events_collected": len(events),
            "last_event": last_event,
            "deception_ready": port_open and has_logs,
            "message": None if port_open else "Cowrie SSH listener is offline.",
        }

    def ingest_logs_to_db(self, db, file_path: Optional[str] = None) -> int:
        """Upsert observed Cowrie sessions into the existing deception log table."""
        path = file_path or settings.cowrie_log_path
        events = self.parser.parse_file(path)
        if not events:
            return 0

        from app.models.deception import DecoySession

        # Group events by session_id
        sessions: Dict[str, List[Dict[str, Any]]] = {}
        for ev in events:
            sessions.setdefault(ev["session_id"], []).append(ev)

        existing_sessions = db.query(DecoySession).filter(DecoySession.mode == "COWRIE").all()
        existing_by_session = {}
        for record in existing_sessions:
            if record.notes and record.notes.startswith("Cowrie session ID: "):
                existing_by_session[record.notes.removeprefix("Cowrie session ID: ")] = record

        count = 0
        for sess_id, ev_list in sessions.items():
            cmds = [e["command"] for e in ev_list if e.get("command")]
            creds = [
                f"{e.get('username')}:{e.get('password')}"
                for e in ev_list
                if e.get("username") and e.get("password")
            ]
            first = ev_list[0]
            observed_events = [
                {
                    "timestamp": event["timestamp"],
                    "event_id": event["raw_eventid"],
                    "event_type": event["event_type"],
                    "src_ip": event["src_ip"],
                    "src_port": event.get("src_port"),
                    "protocol": event.get("protocol"),
                    "dst_ip": event.get("dst_ip"),
                    "dst_port": event.get("dst_port"),
                    "request": event.get("request"),
                    "mitre_technique": event.get("mitre_technique"),
                }
                for event in ev_list
            ]
            timestamp = datetime.fromisoformat(first["timestamp"].replace("Z", "+00:00"))
            protocol = next((event.get("protocol") for event in ev_list if event.get("protocol")), None)
            username = next((event.get("username") for event in ev_list if event.get("username")), None)
            record = existing_by_session.get(sess_id)
            if record is None:
                record = DecoySession(mode="COWRIE", decoy_type=protocol or "cowrie")
                db.add(record)

            record.threat_id = None
            record.timestamp = timestamp
            record.decoy_type = protocol or "cowrie"
            record.fidelity = "HIGH"
            record.reason = "Observed Cowrie honeypot interaction"
            record.confidence = None
            record.mode = "COWRIE"
            record.actor = username
            record.source_ip = first["src_ip"]
            record.activity = json.dumps(observed_events)
            record.commands = json.dumps(cmds)
            record.pages = json.dumps([])
            record.credentials_used = ",".join(creds[:5]) or None
            record.persona = None
            record.banner = None
            record.notes = f"Cowrie session ID: {sess_id}"
            count += 1

        db.commit()
        return count


# Global singleton instance
cowrie_service = CowrieService()
check_cowrie_health = cowrie_service.check_health
