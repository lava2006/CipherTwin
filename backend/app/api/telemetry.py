"""Telemetry endpoints."""
from typing import Optional
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.deps import get_current_user
from app.models.telemetry import TelemetryEvent
from app.models.user import User

router = APIRouter(prefix="/api/telemetry", tags=["telemetry"])


@router.get("")
def list_telemetry(event_type: Optional[str] = None,
                   user_id: Optional[str] = None,
                   search: Optional[str] = None,
                   page: int = Query(1, ge=1),
                   page_size: int = Query(50, ge=1, le=500),
                   db: Session = Depends(get_db),
                   _: User = Depends(get_current_user)):
    q = db.query(TelemetryEvent).order_by(TelemetryEvent.timestamp.desc())
    if event_type:
        q = q.filter(TelemetryEvent.event_type == event_type)
    if user_id:
        q = q.filter(TelemetryEvent.user_id == user_id)
    if search:
        like = f"%{search}%"
        from sqlalchemy import or_
        q = q.filter(or_(TelemetryEvent.user_id.like(like),
                         TelemetryEvent.location.like(like),
                         TelemetryEvent.event_type.like(like),
                         TelemetryEvent.ip_address.like(like)))
    total = q.count()
    items = q.offset((page - 1) * page_size).limit(page_size).all()
    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "items": [e.to_dict() for e in items],
    }


@router.get("/event-types")
def event_types(db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    rows = (
        db.query(TelemetryEvent.event_type, TelemetryEvent.id)
        .group_by(TelemetryEvent.event_type)
        .all()
    )
    # Distinct event types
    types = sorted({r[0] for r in db.query(TelemetryEvent.event_type).all()})
    counts = {t: 0 for t in types}
    for et, _ in rows:
        counts[et] = sum(1 for e in db.query(TelemetryEvent).filter(TelemetryEvent.event_type == et).all())
    return list(counts.items())
