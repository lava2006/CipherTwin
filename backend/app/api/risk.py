"""Risk decision endpoints."""
from typing import Optional
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.deps import get_current_user
from app.models.risk import RiskDecision
from app.models.user import User
from app.ml.inference import metadata as ml_metadata, predict as ml_predict
from app.models.telemetry import TelemetryEvent
from app.models.twin import TwinNode
from app.schemas.risk import RiskPredictionIn

router = APIRouter(prefix="/api/risk", tags=["risk"])


@router.get("/decisions")
def list_decisions(decision: Optional[str] = None, user_id: Optional[str] = None,
                   page: int = Query(1, ge=1), page_size: int = Query(50, ge=1, le=500),
                   db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    q = db.query(RiskDecision).order_by(RiskDecision.timestamp.desc())
    if decision:
        q = q.filter(RiskDecision.decision == decision)
    if user_id:
        q = q.filter(RiskDecision.user_id == user_id)
    total = q.count()
    items = q.offset((page - 1) * page_size).limit(page_size).all()
    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "items": [d.to_dict() for d in items],
    }


@router.get("/decisions/{decision_id}")
def decision_detail(decision_id: int, db: Session = Depends(get_db),
                     _: User = Depends(get_current_user)):
    d = db.query(RiskDecision).filter(RiskDecision.id == decision_id).first()
    if not d:
        return {"error": "not found"}
    return d.to_dict()


@router.get("/ml-status")
def ml_status(_: User = Depends(get_current_user)):
    """Return training metadata for verification without changing the dashboard UI."""
    return ml_metadata()


@router.post("/predict")
def predict_risk(
    payload: RiskPredictionIn,
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
):
    """Run persisted Random Forest inference on one incoming telemetry payload.

    The event is not persisted and the model is loaded from disk; it is never
    retrained during an API request.
    """
    import json

    event = TelemetryEvent(
        user_id=payload.user_id,
        device_id=payload.device_id,
        target_id=payload.target_id,
        event_type=payload.event_type,
        location=payload.location,
        ip_address=payload.ip_address,
        status=payload.status,
        risk_indicators=json.dumps(payload.risk_indicators),
        raw=json.dumps({"failed_logins": payload.failed_logins}),
    )
    device_trust = payload.device_trust
    if device_trust is None and payload.device_id:
        node = db.query(TwinNode).filter(TwinNode.id == payload.device_id).first()
        device_trust = node.trust_score if node else None

    return ml_predict(event, device_trust=device_trust)
