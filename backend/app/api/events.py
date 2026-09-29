"""Controlled event engine API endpoints."""
from fastapi import APIRouter, Depends
from app.deps import get_current_user
from app.models.user import User
from app.services.event_engine import event_engine

router = APIRouter(prefix="/api/events", tags=["events"])


@router.get("/status")
def get_events_status(_: User = Depends(get_current_user)):
    """Return live status of the controlled event engine."""
    return event_engine.get_status()


@router.post("/start")
def start_events(_: User = Depends(get_current_user)):
    """Start the event engine at 1 event / second."""
    return event_engine.start()


@router.post("/stop")
def stop_events(_: User = Depends(get_current_user)):
    """Stop the event engine."""
    return event_engine.stop()
