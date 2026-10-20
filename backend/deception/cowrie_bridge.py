"""Cowrie -> RabbitMQ bridge.

Tails the Cowrie JSON log file, normalizes each line into a CowrieEvent,
and publishes to the `telemetry` topic exchange with routing key
`telemetry.cowrie`.

Features:
- Persists file offset in a state file so it survives restarts and log rotation.
- Follows truncated/rotated logs (re-opens when inode changes or file shrinks).
- Malformed lines are logged and skipped — never crash the bridge.
- Can run standalone (python -m deception.cowrie_bridge) or as a Docker container.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import signal
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import pika

# Allow running both as a package module and as a standalone script.
if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from app.core.config import settings
    from app.services.publisher import publisher
    from app.schemas.telemetry_events import CowrieEvent
else:
    from app.core.config import settings
    from app.services.publisher import publisher
    from app.schemas.telemetry_events import CowrieEvent

logger = logging.getLogger("ciphertwin.cowrie_bridge")

# Cowrie eventid -> normalized event type
EVENTID_TO_TYPE = {
    "cowrie.session.connect": "connect",
    "cowrie.login.failed": "login_failed",
    "cowrie.login.success": "login_success",
    "cowrie.command.input": "command_input",
    "cowrie.session.file_download": "file_download",
    "cowrie.session.closed": "closed",
}

STATE_FILE = Path(os.environ.get("COWRIE_BRIDGE_STATE_FILE", "/data/cowrie_bridge_offset.json"))
POLL_INTERVAL = float(os.environ.get("COWRIE_BRIDGE_POLL_INTERVAL", "1.0"))
LOG_PATH = Path(os.environ.get("COWRIE_LOG_PATH", settings.cowrie_log_path))


class OffsetStore:
    """Persists (inode, byte_offset) so the bridge resumes after restarts."""

    def __init__(self, path: Path = STATE_FILE):
        self.path = path
        self._data: dict[str, dict] = {}
        self._load()

    def _load(self) -> None:
        try:
            if self.path.exists():
                self._data = json.loads(self.path.read_text(encoding="utf-8"))
        except Exception as exc:
            logger.warning("Could not read offset state %s: %s", self.path, exc)
            self._data = {}

    def _save(self) -> None:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text(json.dumps(self._data, indent=2), encoding="utf-8")
        except Exception as exc:
            logger.warning("Could not write offset state %s: %s", self.path, exc)

    def get(self, log_path: str) -> tuple[Optional[int], int]:
        """Return (inode, offset) for a log path, or (None, 0)."""
        entry = self._data.get(log_path, {})
        return entry.get("inode"), entry.get("offset", 0)

    def set(self, log_path: str, inode: Optional[int], offset: int) -> None:
        self._data[log_path] = {"inode": inode, "offset": offset}
        self._save()


class CowrieBridge:
    """Tail Cowrie JSON logs and publish to RabbitMQ."""

    def __init__(
        self,
        log_path: Path = LOG_PATH,
        state_file: Path = STATE_FILE,
        poll_interval: float = POLL_INTERVAL,
    ):
        self.log_path = log_path
        self.offset_store = OffsetStore(state_file)
        self.poll_interval = poll_interval
        self._running = False
        self._inode: Optional[int] = None
        self._offset: int = 0
        self._file = None

    def _stat(self) -> Optional[tuple[int, int]]:
        try:
            st = self.log_path.stat()
            return st.st_ino, st.st_size
        except FileNotFoundError:
            return None
        except Exception as exc:
            logger.warning("Cannot stat %s: %s", self.log_path, exc)
            return None

    def _open(self) -> None:
        stat = self._stat()
        if stat is None:
            self._file = None
            self._inode = None
            self._offset = 0
            return
        inode, size = stat
        saved_inode, saved_offset = self.offset_store.get(str(self.log_path))

        # Detect rotation/truncation: new file or file shrank
        if saved_inode is not None and (saved_inode != inode or saved_offset > size):
            logger.info("Log rotation/truncation detected; starting from beginning")
            saved_offset = 0
            saved_inode = inode

        self._inode = inode
        self._offset = saved_offset
        try:
            self._file = open(self.log_path, "r", encoding="utf-8", errors="replace")
            self._file.seek(self._offset)
        except Exception as exc:
            logger.error("Cannot open %s: %s", self.log_path, exc)
            self._file = None

    def _close(self) -> None:
        if self._file:
            try:
                self._file.close()
            except Exception:
                pass
            self._file = None

    def _publish_cowrie_event(self, raw: dict) -> None:
        """Convert a raw Cowrie JSON line to a CowrieEvent and publish."""
        eventid = raw.get("eventid", "")
        session = raw.get("session", "")
        src_ip = raw.get("src_ip", "")
        timestamp = raw.get("timestamp", "")

        # Build a stable event_id: sha256 of session+eventid+timestamp
        event_id_input = f"{session}|{eventid}|{timestamp}"
        event_id = hashlib.sha256(event_id_input.encode("utf-8")).hexdigest()

        # Parse timestamp
        try:
            ts = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        except Exception:
            ts = datetime.now(timezone.utc)

        # Determine fields by event type
        username: Optional[str] = raw.get("username")
        password = raw.get("password")
        password_present = bool(password)
        command: Optional[str] = raw.get("input")
        url: Optional[str] = raw.get("url")
        url_sha256: Optional[str] = None
        if url:
            url_sha256 = hashlib.sha256(url.encode("utf-8")).hexdigest()

        try:
            event = CowrieEvent(
                event_id=event_id,
                timestamp=ts,
                session=session,
                src_ip=src_ip,
                eventid=eventid,
                username=username,
                password_present=password_present,
                command=command,
                url=url,
                url_sha256=url_sha256,
                raw=raw,
            )
        except Exception as exc:
            logger.warning("CowrieEvent validation failed: %s | raw=%s", exc, raw)
            return

        ok, msg = publisher.publish("telemetry.cowrie", event.model_dump(mode="json"))
        if ok:
            logger.debug("Published cowrie event %s (rk=telemetry.cowrie)", event_id)
        else:
            logger.warning("Failed to publish cowrie event %s: %s", event_id, msg)

    def _process_line(self, line: str) -> None:
        line = line.strip()
        if not line:
            return
        try:
            raw = json.loads(line)
        except json.JSONDecodeError as exc:
            logger.warning("Malformed Cowrie line (skipped): %s", exc)
            return
        if not isinstance(raw, dict):
            logger.warning("Non-object Cowrie line (skipped)")
            return
        if "eventid" not in raw or "session" not in raw:
            logger.warning("Cowrie line missing eventid/session (skipped)")
            return
        self._publish_cowrie_event(raw)

    def run(self) -> None:
        """Main loop: tail the log file and publish events."""
        self._running = True
        logger.info("Cowrie bridge starting | log=%s | state=%s", self.log_path, STATE_FILE)

        def handle_stop(signum, frame):
            logger.info("Received signal %s; shutting down", signum)
            self._running = False

        signal.signal(signal.SIGTERM, handle_stop)
        signal.signal(signal.SIGINT, handle_stop)

        while self._running:
            try:
                self._open()
                if self._file is None:
                    time.sleep(self.poll_interval)
                    continue

                while self._running:
                    line = self._file.readline()
                    if not line:
                        # No new data; check if file was rotated/truncated
                        stat = self._stat()
                        if stat is None:
                            break  # file gone, re-open next iteration
                        inode, size = stat
                        if inode != self._inode or size < self._offset:
                            break  # rotated or truncated
                        time.sleep(self.poll_interval)
                        break

                    self._process_line(line)
                    self._offset = self._file.tell()
                    self.offset_store.set(str(self.log_path), self._inode, self._offset)

            except Exception as exc:
                logger.error("Bridge loop error: %s", exc)
                time.sleep(self.poll_interval)

        self._close()
        logger.info("Cowrie bridge stopped")


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s :: %(message)s",
    )
    bridge = CowrieBridge()
    bridge.run()


if __name__ == "__main__":
    main()
