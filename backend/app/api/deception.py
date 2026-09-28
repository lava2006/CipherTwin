"""Deception engine endpoints."""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.deps import get_current_user
from app.models.user import User
from app.services.deception import DeceptionEngine

router = APIRouter(prefix="/api/deception", tags=["deception"])


@router.get("/sessions")
def list_sessions(db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    return [s.to_dict() for s in DeceptionEngine(db).list_sessions()]


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
    token = next((t for t in engine.list_tokens() if t.id == token_id), None)
    if not token:
        raise HTTPException(status_code=404, detail="Token not found")
    triggered = engine.trigger_honeytoken(token.value)
    if not triggered:
        return {"ok": False}
    return triggered.to_dict()
