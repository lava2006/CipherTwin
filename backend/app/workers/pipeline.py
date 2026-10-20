"""Controlled background pipeline wrapping the EventEngine."""
from typing import Any, Dict
from app.services.event_engine import event_engine


def start_background() -> Dict[str, Any]:
    """Start the controlled 1-event/sec generator."""
    return event_engine.start()


def stop_background() -> Dict[str, Any]:
    """Stop the controlled generator."""
    return event_engine.stop()


def status() -> Dict[str, Any]:
    """Return pipeline status from the authoritative EventEngine and database."""
    from app.db.session import SessionLocal
    from app.models.risk import RiskDecision
    from app.models.deception import DecoySession
    from app.models.threat import Threat
    from app.models.telemetry import TelemetryEvent

    st = event_engine.get_status()
    db = SessionLocal()
    try:
        total_telemetry = db.query(TelemetryEvent).count()
        decisions_count = db.query(RiskDecision).count()
        decoys_count = db.query(DecoySession).count()
        threats_count = db.query(Threat).count()
    except Exception:
        total_telemetry = st.get("event_count", 0)
        decisions_count = 0
        decoys_count = 0
        threats_count = 0
    finally:
        db.close()

    return {
        "running": st["running"],
        "status": st["status"],
        "events_processed": total_telemetry,
        "event_count": st["event_count"],
        "decisions_made": decisions_count,
        "decoys_activated": decoys_count,
        "threats_correlated": threats_count,
        "interval_seconds": st["interval_seconds"],
        "rate": st["rate"],
        "started_at": st["started_at"],
        "stopped_at": st["stopped_at"],
        "last_event_at": st["last_event_time"],
        "recent_events": st["recent_events"],
    }
