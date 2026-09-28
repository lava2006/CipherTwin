"""Policy management endpoints."""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.deps import get_current_user, require_admin
from app.models.policy import Policy
from app.models.user import User
from app.services.audit import log_event

router = APIRouter(prefix="/api/policies", tags=["policies"])


@router.get("")
def list_policies(db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    return [p.to_dict() for p in db.query(Policy).order_by(Policy.priority.desc()).all()]


@router.get("/{policy_id}")
def get_policy(policy_id: int, db: Session = Depends(get_db),
               _: User = Depends(get_current_user)):
    p = db.query(Policy).filter(Policy.id == policy_id).first()
    if not p:
        raise HTTPException(status_code=404, detail="Not found")
    return p.to_dict()


@router.patch("/{policy_id}")
def update_policy(policy_id: int, payload: dict,
                  db: Session = Depends(get_db), user: User = Depends(require_admin)):
    p = db.query(Policy).filter(Policy.id == policy_id).first()
    if not p:
        raise HTTPException(status_code=404, detail="Not found")
    for field in ("enabled", "weight", "priority"):
        if field in payload:
            setattr(p, field, payload[field])
    db.commit()
    log_event(db, action="policy_updated", actor=user.username,
              target=p.name, details=str(payload))
    return p.to_dict()
