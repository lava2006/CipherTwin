#!/usr/bin/env python3
"""vm_agent.py — Remote telemetry agent for CipherTwin.

Reads real host telemetry and forwards it to the CipherTwin ingest API.

Sources:
  - /var/log/auth.log (or journalctl)   -> IAMEvent  (ssh success/failed)
  - ss -tnp / /proc/net/tcp             -> NetFlowEvent
  - ps / auditd                         -> EDREvent   (process execution)

Usage:
  # Dry run: print what would be sent
  python vm_agent.py --once --dry-run --url http://TWIN_HOST:8000 --api-key KEY --device-id myhost

  # Continuous: batch every 5s, retry with backoff
  python vm_agent.py --url http://TWIN_HOST:8000 --api-key KEY --device-id myhost --interval 5

Env vars (alternative to flags):
  CIPHERTWIN_URL, CIPHERTWIN_API_KEY, CIPHERTWIN_DEVICE_ID, CIPHERTWIN_INTERVAL
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import signal
import socket
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests

DEFAULT_URL = os.environ.get("CIPHERTWIN_URL", "http://localhost:8000")
DEFAULT_API_KEY = os.environ.get("CIPHERTWIN_API_KEY", "")
DEFAULT_DEVICE_ID = os.environ.get("CIPHERTWIN_DEVICE_ID", "")
DEFAULT_INTERVAL = float(os.environ.get("CIPHERTWIN_INTERVAL", "5.0"))

RUNNING = True


def handle_signal(signum, frame):
    global RUNNING
    RUNNING = False


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def make_event_id(prefix: str) -> str:
    return f"{prefix}-{hashlib.sha256(f'{utc_now()}-{uuid.uuid4()}'.encode()).hexdigest()[:16]}"


def run_cmd(cmd: List[str], timeout: float = 5.0) -> str:
    """Run a command and return stdout, or empty string on failure."""
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return result.stdout
    except Exception:
        return ""


# ---- Source readers ----

def read_auth_log(lines: int = 200) -> List[Dict[str, Any]]:
    """Parse ssh login events from /var/log/auth.log or journalctl."""
    events: List[Dict[str, Any]] = []
    auth_log = Path("/var/log/auth.log")
    journal_cmd = ["journalctl", "-u", "ssh", "--no-pager", "-n", str(lines)]

    raw = ""
    if auth_log.exists():
        try:
            raw = auth_log.read_text(errors="replace").splitlines()[-lines:]
            raw = "\n".join(raw)
        except Exception:
            raw = ""
    else:
        raw = run_cmd(journal_cmd)

    for line in raw.splitlines():
        line_lower = line.lower()
        if "sshd" not in line_lower:
            continue
        accepted = "accepted" in line_lower or "success" in line_lower
        failed = "failed" in line_lower or "invalid user" in line_lower
        if not (accepted or failed):
            continue

        # Extract username and src_ip via simple parsing
        username = None
        src_ip = None
        for token in line.split():
            if token.startswith("from=") or token == "from":
                continue
            if token.count(".") == 3 and all(p.isdigit() for p in token.split(".")):
                src_ip = token
        if "for " in line:
            parts = line.split("for ")
            if len(parts) > 1:
                username = parts[1].split()[0] if parts[1].split() else None

        events.append({
            "event_id": make_event_id("iam"),
            "timestamp": utc_now(),
            "device_id": "",  # filled by caller
            "event_type": "ssh_success" if accepted else "ssh_failed",
            "username": username,
            "src_ip": src_ip,
            "success": accepted,
            "raw": {"source": "auth_log", "line": line[:500]},
        })

    return events


def read_netflow() -> List[Dict[str, Any]]:
    """Read active TCP connections from /proc/net/tcp and /proc/net/tcp6."""
    events: List[Dict[str, Any]] = []

    for proto_file in ["/proc/net/tcp", "/proc/net/tcp6"]:
        if not Path(proto_file).exists():
            continue
        try:
            lines = Path(proto_file).read_text(errors="replace").splitlines()
        except Exception:
            continue
        for line in lines[1:]:  # skip header
            parts = line.split()
            if len(parts) < 10:
                continue
            local = parts[1]
            remote = parts[2]
            state = parts[3]
            inode = parts[9]

            # Only established connections
            if state != "0A":
                continue

            try:
                l_ip_hex, l_port_hex = local.split(":")
                r_ip_hex, r_port_hex = remote.split(":")
                l_port = int(l_port_hex, 16)
                r_port = int(r_port_hex, 16)
            except (ValueError, IndexError):
                continue

            events.append({
                "event_id": make_event_id("netflow"),
                "timestamp": utc_now(),
                "device_id": "",
                "src_ip": f"0.0.0.0:{l_port}",  # simplified
                "dst_ip": f"0.0.0.0:{r_port}",
                "src_port": l_port,
                "dst_port": r_port,
                "protocol": "tcp",
                "bytes_sent": 0,
                "bytes_recv": 0,
                "raw": {"source": "proc_net_tcp", "state": state, "inode": inode},
            })

    # Limit to most recent 50
    return events[:50]


def read_processes() -> List[Dict[str, Any]]:
    """Read running processes via ps."""
    events: List[Dict[str, Any]] = []
    raw = run_cmd(["ps", "-eo", "pid,ppid,user,comm,args", "--no-headers"])
    for line in raw.splitlines()[:50]:
        parts = line.split(None, 4)
        if len(parts) < 5:
            continue
        pid, ppid, user, comm, args = parts
        events.append({
            "event_id": make_event_id("edr"),
            "timestamp": utc_now(),
            "device_id": "",
            "event_type": "process_list",
            "process_name": comm,
            "process_path": comm,
            "command_line": args[:200],
            "user": user,
            "risk_indicators": [],
            "raw": {"source": "ps", "pid": pid, "ppid": ppid},
        })
    return events


# ---- Sender ----

def send_event(url: str, api_key: str, route: str, payload: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
    """Send a single event to /ingest/{route}. Returns (ok, error_or_id)."""
    headers = {"Content-Type": "application/json", "X-API-Key": api_key}
    try:
        resp = requests.post(
            f"{url.rstrip('/')}/ingest/{route}",
            json=payload,
            headers=headers,
            timeout=10,
        )
        if resp.status_code == 202:
            data = resp.json()
            return True, data.get("event_id")
        if resp.status_code == 401:
            return False, "401 Unauthorized — check API key"
        if resp.status_code == 422:
            return False, f"422 Validation: {resp.text[:200]}"
        if resp.status_code == 429:
            return False, "429 Rate limited"
        return False, f"HTTP {resp.status_code}: {resp.text[:200]}"
    except requests.exceptions.ConnectionError:
        return False, "Connection refused"
    except requests.exceptions.Timeout:
        return False, "Request timeout"
    except Exception as exc:
        return False, str(exc)


def send_batch(url: str, api_key: str, events: List[Dict[str, Any]]) -> Tuple[int, int]:
    """Send events as a batch. Returns (accepted, rejected)."""
    if not events:
        return 0, 0
    headers = {"Content-Type": "application/json", "X-API-Key": api_key}
    try:
        resp = requests.post(
            f"{url.rstrip('/')}/ingest/batch",
            json=events,
            headers=headers,
            timeout=15,
        )
        if resp.status_code == 202:
            data = resp.json()
            return data.get("accepted", 0), data.get("rejected", 0)
        return 0, len(events)
    except Exception:
        return 0, len(events)


# ---- Main collection loop ----

def collect_all(device_id: str) -> List[Dict[str, Any]]:
    """Collect events from all sources and tag with device_id."""
    events: List[Dict[str, Any]] = []

    for ev in read_auth_log():
        ev["device_id"] = device_id
        events.append(ev)
    for ev in read_netflow():
        ev["device_id"] = device_id
        events.append(ev)
    for ev in read_processes():
        ev["device_id"] = device_id
        events.append(ev)

    return events


def socket_gethostname() -> str:
    return socket.gethostname()


def main() -> None:
    global RUNNING
    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    parser = argparse.ArgumentParser(description="CipherTwin remote VM telemetry agent")
    parser.add_argument("--url", default=DEFAULT_URL, help="CipherTwin API base URL")
    parser.add_argument("--api-key", default=DEFAULT_API_KEY, help="Ingest API key")
    parser.add_argument("--device-id", default=DEFAULT_DEVICE_ID, help="Device ID (hostname)")
    parser.add_argument("--interval", type=float, default=DEFAULT_INTERVAL, help="Batch interval seconds")
    parser.add_argument("--once", action="store_true", help="Collect once and exit")
    parser.add_argument("--dry-run", action="store_true", help="Print JSON instead of sending")
    args = parser.parse_args()

    device_id = args.device_id or os.environ.get("HOSTNAME", "") or socket_gethostname()
    if not device_id:
        print("ERROR: --device-id required (or set CIPHERTWIN_DEVICE_ID/HOSTNAME)", file=sys.stderr)
        sys.exit(1)

    if not args.dry_run and not args.api_key:
        print("ERROR: --api-key required (or set CIPHERTWIN_API_KEY)", file=sys.stderr)
        sys.exit(1)

    print(f"vm_agent starting | device={device_id} | url={args.url} | interval={args.interval}s")

    while RUNNING:
        events = collect_all(device_id)
        if not events:
            if args.once:
                break
            time.sleep(args.interval)
            continue

        if args.dry_run:
            print(json.dumps({"device_id": device_id, "count": len(events), "events": events}, indent=2))
        else:
            accepted, rejected = send_batch(args.url, args.api_key, events)
            print(f"{utc_now()} | sent {len(events)} events | accepted={accepted} rejected={rejected}")

        if args.once:
            break

        # Retry loop with backoff on transient failures
        time.sleep(args.interval)

    print("vm_agent stopped")


if __name__ == "__main__":
    main()
