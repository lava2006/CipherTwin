"""Deception engine endpoints."""
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.deps import get_current_user
from app.models.deception import DecoySession
from app.models.user import User
from app.services.deception import DeceptionEngine
from app.services.cowrie import cowrie_service

router = APIRouter(prefix="/api/deception", tags=["deception"])


@router.get("/route/{event_id}")
def route_http_event(event_id: int, db: Session = Depends(get_db),
                     user: User = Depends(get_current_user)):
    """Explicitly route a reviewed HTTP event to the isolated local decoy.

    This is a controlled HTTP redirect broker for requests that deliberately
    enter this endpoint. It is NOT transparent interception of arbitrary network
    sessions and does not redirect SSH/Telnet traffic.
    """
    from app.core.config import settings
    from app.models.risk import RiskDecision
    from app.models.telemetry import TelemetryEvent
    from app.services.audit import log_event

    event = db.query(TelemetryEvent).filter(TelemetryEvent.id == event_id).first()
    if event is None:
        raise HTTPException(status_code=404, detail="Telemetry event not found")
    decision = (
        db.query(RiskDecision)
        .filter(RiskDecision.telemetry_id == event.id)
        .order_by(RiskDecision.timestamp.desc())
        .first()
    )
    if decision is None:
        raise HTTPException(status_code=409, detail="Event has no processed risk decision yet")

    if float(decision.risk_score) < float(settings.deception_risk_threshold):
        return {
            "status": "NORMAL_PATH",
            "event_id": event.id,
            "risk_score": decision.risk_score,
            "threshold": settings.deception_risk_threshold,
            "message": "Risk is below the deception threshold; no redirect was issued.",
        }

    session = DecoySession(
        decoy_type="web",
        target_node_id="decoy-web-local",
        fidelity="LOW",
        reason=f"Explicit HTTP redirect for risk score {decision.risk_score:.1f}",
        confidence=None,
        mode="HTTP_REDIRECT",
        actor=event.user_id,
        source_ip=event.ip_address,
        activity="[]",
        commands="[]",
        pages="[]",
        notes=(f"HTTP redirect broker event_id={event.id}; requested_by={user.username}; "
               "This is explicit HTTP redirection, not transparent network interception."),
    )
    db.add(session)
    db.flush()
    log_event(
        db, action="deception_http_redirect", actor=user.username,
        target=f"telemetry_event_{event.id}",
        details=f"Risk={decision.risk_score:.1f}; redirected to isolated local decoy web service",
        severity="warning",
    )
    db.commit()

    base_url = settings.decoy_web_public_url.rstrip("/")
    return RedirectResponse(
        url=f"{base_url}/?event_id={event.id}&decoy_session_id={session.id}",
        status_code=307,
    )


@router.get("/sessions")
def list_sessions(mode: str | None = None, db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    from app.core.config import settings
    query = db.query(DecoySession)
    if mode is not None:
        if mode.upper() != "ALL":
            query = query.filter(DecoySession.mode == mode.upper())
    elif str(settings.deception_mode).upper() == "COWRIE":
        query = query.filter(DecoySession.mode == "COWRIE")
    sessions = query.order_by(DecoySession.timestamp.desc()).limit(100).all()
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


def _normalize_fidelity(fidelity: str | None) -> str:
    val = (fidelity or "").strip().upper()
    if "HIGH" in val:
        return "HIGH"
    if "LOW" in val:
        return "LOW"
    return "MEDIUM"


@router.get("/fidelity/status")
def fidelity_status(db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    """Return deception fidelity and mode breakdown derived from single source of truth."""
    from datetime import datetime
    from app.models.deception import DecoySession

    cowrie_service.ingest_logs_to_db(db)
    health = cowrie_service.check_health()
    sessions = db.query(DecoySession).all()

    counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for s in sessions:
        counts[_normalize_fidelity(s.fidelity)] += 1

    last_event = health.get("last_event")
    total_events = health.get("total_events_collected", 0)
    if not last_event and sessions:
        valid_dates = [s.timestamp for s in sessions if s.timestamp]
        if valid_dates:
            last_event = max(valid_dates).isoformat()
    if total_events == 0 and sessions:
        total_events = len(sessions)

    return {
        "mode": health.get("mode", "OFFLINE"),
        "status": health.get("status", "OFFLINE"),
        "reason": health.get("reason", health.get("message", "Status check complete.")),
        "cowrie_status": health.get("cowrie_status", "OFFLINE"),
        "log_status": health.get("log_status", "UNAVAILABLE"),
        "log_file": health.get("log_file"),
        "total_events": total_events,
        "last_event": last_event,
        "cowrie_enabled": health.get("status") in ("LIVE", "HEALTHY", "SIMULATED"),
        "total_sessions": len(sessions),
        "fidelity_breakdown": {
            "low": counts["LOW"],
            "medium": counts["MEDIUM"],
            "high": counts["HIGH"],
        },
    }
