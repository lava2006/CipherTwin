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
    """Return pipeline status from the authoritative EventEngine."""
    st = event_engine.get_status()
    return {
        "running": st["running"],
        "status": st["status"],
        "events_processed": st["event_count"],
        "event_count": st["event_count"],
        "interval_seconds": st["interval_seconds"],
        "rate": st["rate"],
        "started_at": st["started_at"],
        "stopped_at": st["stopped_at"],
        "last_event_at": st["last_event_time"],
        "recent_events": st["recent_events"],
    }
