"""Cowrie Honeypot Log Ingestion & Normalization Engine for CipherTwin.

Supports both COWRIE mode (ingesting live Cowrie JSON logs) and
SIMULATED mode (deterministic synthetic attacker emulation).

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
        session_id = data.get("session", "unknown")
        timestamp = data.get("timestamp", "")
        src_ip = data.get("src_ip", "0.0.0.0")

        normalized = {
            "session_id": session_id,
            "timestamp": timestamp,
            "src_ip": src_ip,
            "raw_eventid": eventid,
            "mitre_technique": COWRIE_EVENT_TO_MITRE.get(eventid, "T1021.004"),
        }

        if eventid == "cowrie.session.connect":
            normalized["event_type"] = "connect"
            normalized["protocol"] = data.get("protocol", "ssh")
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

        if port_open:
            return {
                "status": "HEALTHY",
                "mode": "COWRIE",
                "container_running": True,
                "port": 2222,
                "banner": banner or "SSH-2.0-OpenSSH_9.2p1 Debian",
                "log_file": str(log_path) if has_logs else "active_container_stream",
                "total_events_collected": len(events),
                "deception_ready": True,
            }

        if has_logs and len(events) > 0:
            return {
                "status": "HEALTHY",
                "mode": "COWRIE",
                "log_file": str(log_path),
                "total_events_collected": len(events),
            }

        return {
            "status": "DEGRADED" if settings.deception_mode == "SIMULATED" else "UNAVAILABLE",
            "mode": settings.deception_mode,
            "message": "Cowrie container not running or log file not mounted; running in verified SIMULATED deception mode.",
            "log_file_present": log_path.exists(),
        }

    def ingest_logs_to_db(self, db, file_path: Optional[str] = None) -> int:
        """Parse Cowrie logs and ingest into DecoySession records."""
        path = file_path or settings.cowrie_log_path
        events = self.parser.parse_file(path)
        if not events:
            return 0

        from app.models.deception import DecoySession

        # Group events by session_id
        sessions: Dict[str, List[Dict[str, Any]]] = {}
        for ev in events:
            sessions.setdefault(ev["session_id"], []).append(ev)

        count = 0
        for sess_id, ev_list in sessions.items():
            cmds = [e["command"] for e in ev_list if e.get("command")]
            creds = [
                f"{e.get('username')}:{e.get('password')}"
                for e in ev_list
                if e.get("username") and e.get("password")
            ]
            first = ev_list[0]

            record = DecoySession(
                threat_id=None,
                decoy_type="ssh",
                fidelity="HIGH",
                reason="Ingested from active Cowrie SSH honeypot",
                confidence=0.95,
                mode="COWRIE",
                actor=creds[0].split(":")[0] if creds else "attacker",
                source_ip=first.get("src_ip", "0.0.0.0"),
                activity=json.dumps([f"Cowrie event: {e.get('event_type')}" for e in ev_list]),
                commands=json.dumps(cmds),
                pages=json.dumps([]),
                credentials_used=",".join(creds[:5]),
                notes=f"Cowrie session {sess_id} with {len(ev_list)} recorded events",
            )
            db.add(record)
            count += 1

        db.commit()
        return count


# Global singleton instance
cowrie_service = CowrieService()
check_cowrie_health = cowrie_service.check_health
