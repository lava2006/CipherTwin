"""Controlled Event Simulator & Telemetry Engine for CipherTwin.

Provides a thread-safe, controllable event generation engine:
- Explicit START and STOP controls
- Exact 1-second event cadence (1 event / second)
- State machine preventing duplicate worker threads
- Real-time event counter and event timeline tracking
- Full pipeline routing:
  EventEngine -> TelemetryMessage -> RabbitMQ Pipeline -> Consumer -> Risk Engine -> Deception -> Database
"""
from datetime import datetime, timezone
import logging
import random
import threading
import time
from typing import Any, Dict, List, Optional
import uuid

from app.db.session import SessionLocal
from app.models.twin import TwinNode
from app.services.rabbitmq import rabbitmq_pipeline
from app.workers.telemetry_simulator import TelemetrySimulator

logger = logging.getLogger("ciphertwin.event_engine")


class EventEngine:
    """Thread-safe, rate-controlled event generation engine (1 event/sec)."""

    def __init__(self):
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

        self.running: bool = False
        self.event_count: int = 0
        self.interval_seconds: float = 1.0
        self.started_at: Optional[str] = None
        self.stopped_at: Optional[str] = None
        self.last_event_time: Optional[str] = None
        self.recent_events: List[Dict[str, Any]] = []

    @property
    def events_generated(self) -> int:
        return self.event_count

    def is_running(self) -> bool:
        with self._lock:
            return self.running

    def emit_one_event(self) -> Optional[Dict[str, Any]]:
        """Public trigger to emit and process a single event through the full pipeline."""
        return self._generate_and_process_one()

    def get_status(self) -> Dict[str, Any]:
        """Return truthful runtime state of the event engine."""
        with self._lock:
            return {
                "running": self.running,
                "state": "RUNNING" if self.running else "STOPPED",
                "status": "RUNNING" if self.running else "STOPPED",
                "event_count": self.event_count,
                "events_generated": self.event_count,
                "interval_seconds": self.interval_seconds,
                "events_per_second": 1.0 if self.running else 0.0,
                "rate": "1 event/sec" if self.running else "0 event/sec",
                "started_at": self.started_at,
                "stopped_at": self.stopped_at,
                "last_event_time": self.last_event_time,
                "last_event_at": self.last_event_time,
                "recent_events": list(self.recent_events[-15:]),
            }

    def start(self) -> Dict[str, Any]:
        """Start generating events at exactly 1 event / second. Prevents duplicate workers."""
        with self._lock:
            if self.running:
                logger.info("EventEngine start requested, but already RUNNING. Duplicate ignored.")
                return {
                    "running": True,
                    "status": "already_running",
                    "state": "RUNNING",
                    "message": "Event engine is already running (duplicate start suppressed).",
                    "event_count": self.event_count,
                    "events_generated": self.event_count,
                    "events_per_second": 1.0,
                    "rate": "1 event/sec",
                }

            self.running = True
            self.started_at = datetime.now(timezone.utc).isoformat()
            self._stop_event.clear()

            self._thread = threading.Thread(
                target=self._run_loop,
                name="ciphertwin-controlled-event-engine",
                daemon=True,
            )
            self._thread.start()
            logger.info("EventEngine STARTED | Cadence: 1 event / sec | Thread: %s", self._thread.name)

            return {
                "running": True,
                "status": "started",
                "state": "RUNNING",
                "message": "Event engine started at 1 event/sec.",
                "event_count": self.event_count,
                "events_generated": self.event_count,
                "events_per_second": 1.0,
                "rate": "1 event/sec",
                "started_at": self.started_at,
            }

    def stop(self) -> Dict[str, Any]:
        """Stop event generation immediately."""
        with self._lock:
            if not self.running:
                logger.info("EventEngine stop requested, but already STOPPED.")
                return {
                    "running": False,
                    "status": "already_stopped",
                    "state": "STOPPED",
                    "message": "Event engine is already stopped.",
                    "event_count": self.event_count,
                    "events_generated": self.event_count,
                    "events_per_second": 0.0,
                    "rate": "0 event/sec",
                }

            self.running = False
            self.stopped_at = datetime.now(timezone.utc).isoformat()
            self._stop_event.set()
            logger.info("EventEngine STOPPED | Final event count: %d", self.event_count)

            return {
                "running": False,
                "status": "stopped",
                "state": "STOPPED",
                "message": "Event engine stopped successfully.",
                "event_count": self.event_count,
                "events_generated": self.event_count,
                "events_per_second": 0.0,
                "rate": "0 event/sec",
                "stopped_at": self.stopped_at,
            }

    def _generate_and_process_one(self) -> Optional[Dict[str, Any]]:
        """Generate one event and pass it through the full RabbitMQ -> Risk Engine pipeline."""
        db = SessionLocal()
        try:
            sim = TelemetrySimulator(db)
            force_attack = random.random() < 0.22  # ~22% attack probability for active security monitoring
            ev = sim.generate_one(force_attack=force_attack)
            if not ev:
                return None

            msg_id = str(uuid.uuid4())
            indicators = []
            if ev.risk_indicators:
                try:
                    import json
                    indicators = json.loads(ev.risk_indicators) if isinstance(ev.risk_indicators, str) else list(ev.risk_indicators)
                except Exception:
                    indicators = []

            # 1. Publish to RabbitMQ pipeline
            payload = {
                "message_id": msg_id,
                "event_type": ev.event_type,
                "user_id": ev.user_id,
                "device_id": ev.device_id,
                "target_id": ev.target_id,
                "ip_address": ev.ip_address,
                "location": ev.location,
                "status": ev.status,
                "risk_indicators": indicators,
                "raw_payload": {"generated_by": "controlled_event_engine", "force_attack": force_attack},
            }

            pub_ok, pub_result = rabbitmq_pipeline.publish(payload)
            if not pub_ok:
                logger.warning("Event %s rejected by RabbitMQ pipeline: %s", msg_id, pub_result)
                return None

            # 2. Process message through consumer & Zero Trust Risk Engine
            proc_result = rabbitmq_pipeline.process_one(db)
            now_iso = datetime.now(timezone.utc).isoformat()

            with self._lock:
                self.event_count += 1
                self.last_event_time = now_iso
                summary_item = {
                    "event_id": self.event_count,
                    "message_id": msg_id,
                    "timestamp": now_iso,
                    "event_type": ev.event_type,
                    "user_id": ev.user_id,
                    "risk_score": proc_result.get("risk_score", 0.0) if proc_result else 0.0,
                    "decision": proc_result.get("decision", "allow") if proc_result else "allow",
                }
                self.recent_events.append(summary_item)
                if len(self.recent_events) > 50:
                    self.recent_events.pop(0)

            logger.info(
                "Event #%d generated & processed | type=%s risk=%.1f decision=%s | interval=1.0s",
                self.event_count,
                ev.event_type,
                proc_result.get("risk_score", 0.0) if proc_result else 0.0,
                proc_result.get("decision", "allow") if proc_result else "allow",
            )
            return summary_item

        except Exception as e:
            logger.exception("Error during event generation/processing: %s", e)
            return None
        finally:
            db.close()

    def _run_loop(self):
        """Asynchronous execution loop maintaining exact 1-second cadence."""
        while not self._stop_event.is_set():
            start_time = time.time()
            self._generate_and_process_one()

            # Compute remaining time to sleep for exact 1.0s interval
            elapsed = time.time() - start_time
            sleep_duration = max(0.05, self.interval_seconds - elapsed)

            # Wait on stop_event so stop() breaks sleep immediately
            if self._stop_event.wait(timeout=sleep_duration):
                break


# Global singleton instance (initial state is STOPPED)
event_engine = EventEngine()
