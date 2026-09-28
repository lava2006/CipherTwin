"""Background pipeline: telemetry -> risk -> deception -> threat intel."""
import logging
import random
import threading
import time
from datetime import datetime, timezone

from app.core.config import settings
from app.db.session import SessionLocal
from app.services.audit import log_event
from app.services.deception import DeceptionEngine
from app.services.risk_engine import engine
from app.services.threat_intel import ThreatIntel
from app.workers.telemetry_simulator import TelemetrySimulator


logger = logging.getLogger("ciphertwin.workers")
_state = {
    "running": False,
    "thread": None,
    "events_processed": 0,
    "decisions_made": 0,
    "decoys_activated": 0,
    "threats_correlated": 0,
    "last_event_at": None,
}


def _run_once() -> None:
    db = SessionLocal()
    try:
        sim = TelemetrySimulator(db)
        force_attack = random.random() < 0.18
        event = sim.generate_one(force_attack=force_attack)
        if not event:
            return
        result = engine.evaluate(event, db)
        decision = engine.persist(event, result, db)
        logger.info("Telemetry processed | event=%s type=%s risk=%.2f decision=%s confidence=%.2f", event.id, event.event_type, result.risk_score, result.decision, result.confidence)
        _state["events_processed"] += 1
        _state["decisions_made"] += 1
        _state["last_event_at"] = datetime.now(timezone.utc).isoformat()

        # Threat intel + deception on risky events
        threat = None
        if result.risk_score >= 60:
            intel = ThreatIntel(db)
            threat = intel.correlate(event, result.risk_score, result.decision)
            if threat:
                _state["threats_correlated"] += 1
                deception = DeceptionEngine(db)
                session = deception.open_decoy(
                    actor=event.user_id or "unknown",
                    source_ip=event.ip_address or "0.0.0.0",
                    threat_id=threat.id,
                )
                _state["decoys_activated"] += 1
                deception.simulate_activity(session)
                log_event(db, action="decoy_activated",
                          actor=event.user_id, target=session.decoy_type,
                          details=f"Threat={threat.actor_name}; risk={result.risk_score}",
                          severity="warning", ip_address=event.ip_address)
        db.commit()
    except Exception:
        logger.exception("pipeline iteration failed")
    finally:
        db.close()


def _loop():
    while _state["running"]:
        _run_once()
        time.sleep(settings.telemetry_interval_seconds)


def start_background() -> None:
    if _state["running"]:
        return
    _state["running"] = True
    thread = threading.Thread(target=_loop, name="ciphertwin-pipeline", daemon=True)
    thread.start()
    _state["thread"] = thread
    logger.info("Background telemetry pipeline started | interval=%ss | ML risk engine enabled", settings.telemetry_interval_seconds)


def stop_background() -> None:
    _state["running"] = False


def status() -> dict:
    return {
        "running": _state["running"],
        "events_processed": _state["events_processed"],
        "decisions_made": _state["decisions_made"],
        "decoys_activated": _state["decoys_activated"],
        "threats_correlated": _state["threats_correlated"],
        "last_event_at": _state["last_event_at"],
    }
