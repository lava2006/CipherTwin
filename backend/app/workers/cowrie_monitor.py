"""Cowrie Honeypot Monitor & Live Bridge for CipherTwin.

Continuously ensures live Cowrie honeypot logs from the container
are synced to the host and published to RabbitMQ exchange `telemetry`
with routing key `telemetry.cowrie`.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import shutil
import subprocess
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from app.core.config import settings
from app.schemas.telemetry_events import CowrieEvent
from app.services.publisher import publisher

logger = logging.getLogger("ciphertwin.cowrie_monitor")

STATE_FILE = Path("./data/cowrie_bridge_offset.json")


class CowrieMonitor:
    """Tails Cowrie honeypot logs, syncs from Docker if running, and publishes to RabbitMQ."""

    def __init__(self, log_path: Optional[Path] = None):
        self.log_path = log_path or Path(settings.cowrie_log_path)
        self.state_file = STATE_FILE
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._offset = 0
        self._inode: Optional[int] = None
        self.stats = {
            "synced_from_docker": 0,
            "events_published": 0,
            "errors": 0,
        }
        self._load_offset()

    def _load_offset(self) -> None:
        try:
            if self.state_file.exists():
                data = json.loads(self.state_file.read_text(encoding="utf-8"))
                entry = data.get(str(self.log_path.resolve()), {})
                self._offset = entry.get("offset", 0)
                self._inode = entry.get("inode")
        except Exception:
            self._offset = 0
            self._inode = None

    def _save_offset(self) -> None:
        try:
            self.state_file.parent.mkdir(parents=True, exist_ok=True)
            data = {}
            if self.state_file.exists():
                try:
                    data = json.loads(self.state_file.read_text(encoding="utf-8"))
                except Exception:
                    data = {}
            data[str(self.log_path.resolve())] = {
                "inode": self._inode,
                "offset": self._offset,
            }
            self.state_file.write_text(json.dumps(data, indent=2), encoding="utf-8")
        except Exception as exc:
            logger.warning("Could not save offset state: %s", exc)

    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive() and not self._stop_event.is_set()

    def start(self) -> None:
        if self.is_running():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run_loop,
            name="ciphertwin-cowrie-monitor",
            daemon=True,
        )
        self._thread.start()
        logger.info("CowrieMonitor started | log_path=%s", self.log_path)

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=3.0)
        logger.info("CowrieMonitor stopped.")

    def _sync_from_docker(self) -> bool:
        """Attempt to sync latest cowrie.json from the running Docker container."""
        try:
            # Check if container is running
            res = subprocess.run(
                ["docker", "inspect", "-f", "{{.State.Running}}", "ciphertwin-cowrie"],
                capture_output=True,
                text=True,
                timeout=3,
            )
            if res.returncode == 0 and res.stdout.strip() == "true":
                self.log_path.parent.mkdir(parents=True, exist_ok=True)
                cp_res = subprocess.run(
                    ["docker", "cp", "ciphertwin-cowrie:/cowrie/cowrie-git/var/log/cowrie/cowrie.json", str(self.log_path)],
                    capture_output=True,
                    timeout=5,
                )
                if cp_res.returncode == 0:
                    self.stats["synced_from_docker"] += 1
                    return True
        except Exception:
            pass
        return False

    def _run_loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                # 1. Sync from docker
                self._sync_from_docker()

                # 2. Check if log file exists
                if not self.log_path.exists():
                    time.sleep(2.0)
                    continue

                st = self.log_path.stat()
                inode = st.st_ino
                size = st.st_size

                # Detect truncation or rotation: only reset offset if file shrank
                if size < self._offset:
                    self._offset = 0
                self._inode = inode

                if size > self._offset:
                    with open(self.log_path, "r", encoding="utf-8", errors="replace") as f:
                        f.seek(self._offset)
                        while not self._stop_event.is_set():
                            line = f.readline()
                            if not line:
                                break
                            self._process_line(line)
                            self._offset = f.tell()
                            self._save_offset()

            except Exception as exc:
                self.stats["errors"] += 1
                logger.error("Error in cowrie monitor loop: %s", exc)

            time.sleep(1.5)

    def _process_line(self, line: str) -> None:
        line = line.strip()
        if not line:
            return
        try:
            raw = json.loads(line)
        except Exception:
            return
        if not isinstance(raw, dict) or "eventid" not in raw or "session" not in raw:
            return

        eventid = raw.get("eventid", "")
        session = raw.get("session", "")
        src_ip = raw.get("src_ip", "0.0.0.0")
        timestamp = raw.get("timestamp", "")
        event_id_input = f"{session}|{eventid}|{timestamp}"
        event_id = hashlib.sha256(event_id_input.encode("utf-8")).hexdigest()

        try:
            ts = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        except Exception:
            ts = datetime.now(timezone.utc)

        cmd = raw.get("input")
        url = raw.get("url")
        url_sha256 = hashlib.sha256(url.encode("utf-8")).hexdigest() if url else None

        event = CowrieEvent(
            event_id=event_id,
            timestamp=ts,
            session=session,
            src_ip=src_ip,
            eventid=eventid,
            username=raw.get("username"),
            password_present=bool(raw.get("password")),
            command=cmd,
            url=url,
            url_sha256=url_sha256,
            raw=raw,
        )

        ok, msg = publisher.publish("telemetry.cowrie", event.model_dump(mode="json"))
        if ok:
            self.stats["events_published"] += 1


# Module-level singleton
cowrie_monitor = CowrieMonitor()
