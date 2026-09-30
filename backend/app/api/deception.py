"""Deception engine endpoints."""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.deps import get_current_user
from app.models.deception import DecoySession
from app.models.user import User
from app.services.deception import DeceptionEngine
from app.services.cowrie import cowrie_service

router = APIRouter(prefix="/api/deception", tags=["deception"])


@router.get("/sessions")
def list_sessions(db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    cowrie_service.ingest_logs_to_db(db)
    sessions = (
        db.query(DecoySession)
        .filter(DecoySession.mode == "COWRIE")
        .order_by(DecoySession.timestamp.desc())
        .limit(100)
        .all()
    )
    return [session.to_dict() for session in sessions]


@router.get("/honeytokens")
def list_tokens(db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    return [t.to_dict() for t in DeceptionEngine(db).list_tokens()]


@router.post("/seed")
def seed(db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    tokens = DeceptionEngine(db).seed_honeytokens()
    return [t.to_dict() for t in tokens]


@router.post("/trigger/{token_id}")
def trigger(token_id: int, db: Session = Depends(get_db),
            user: User = Depends(get_current_user)):
    engine = DeceptionEngine(db)
    result = engine.trigger_honeytoken_lifecycle(
        token_id_or_value=token_id,
        actor=user.username,
        source_ip="127.0.0.1",
    )
    if not result:
        raise HTTPException(status_code=404, detail="Honeytoken not found")
    return result


@router.get("/cowrie/status")
def cowrie_status(_: User = Depends(get_current_user)):
    """Truthful Cowrie honeypot status check."""
    from app.services.cowrie import cowrie_service
    return cowrie_service.check_health()


@router.post("/cowrie/ingest")
def cowrie_ingest(db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    """Manually trigger ingestion of Cowrie logs."""
    from app.services.cowrie import cowrie_service
    count = cowrie_service.ingest_logs_to_db(db)
    return {"ingested_sessions": count}


@router.get("/fidelity/status")
def fidelity_status(db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    """Return deception fidelity and mode breakdown."""
    from app.models.deception import DecoySession

    health = cowrie_service.check_health()
    sessions = db.query(DecoySession).filter(DecoySession.mode == "COWRIE").all()
    low = sum(1 for s in sessions if (s.fidelity or "MEDIUM").upper() == "LOW")
    med = sum(1 for s in sessions if (s.fidelity or "MEDIUM").upper() == "MEDIUM")
    high = sum(1 for s in sessions if (s.fidelity or "MEDIUM").upper() == "HIGH")

    return {
        "mode": health.get("mode", "UNAVAILABLE"),
        "status": health.get("status", "UNAVAILABLE"),
        "cowrie_status": health.get("cowrie_status", "OFFLINE"),
        "log_status": health.get("log_status", "UNAVAILABLE"),
        "log_file": health.get("log_file"),
        "total_events": health.get("total_events_collected", 0),
        "last_event": health.get("last_event"),
        "cowrie_enabled": health.get("status") == "HEALTHY",
        "total_sessions": len(sessions),
        "fidelity_breakdown": {
            "low": low,
            "medium": med,
            "high": high,
        },
    }
