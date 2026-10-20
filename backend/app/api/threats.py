"""Threat intelligence endpoints."""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.deps import get_current_user
from app.models.user import User
from app.services.threat_intel import ThreatIntel

router = APIRouter(prefix="/api/threats", tags=["threats"])


@router.get("")
def list_threats(db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    return ThreatIntel(db).list_threats()


@router.get("/{threat_id}")
def threat_detail(threat_id: int, db: Session = Depends(get_db),
                   _: User = Depends(get_current_user)):
    t = ThreatIntel(db).get(threat_id)
    if not t:
        raise HTTPException(status_code=404, detail="Not found")
    return t
