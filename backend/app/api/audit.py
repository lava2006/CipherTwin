"""Audit log endpoints."""
from typing import Optional
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.deps import get_current_user
from app.models.user import User
from app.services.audit import list_logs

router = APIRouter(prefix="/api/audit", tags=["audit"])


@router.get("")
def logs(severity: Optional[str] = None, action: Optional[str] = None,
         page: int = Query(1, ge=1), page_size: int = Query(50, ge=1, le=500),
         db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    items = list_logs(db, limit=page_size * page, severity=severity, action=action)
    total = len(items)
    offset = (page - 1) * page_size
    page_items = items[offset: offset + page_size]
    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "items": [i.to_dict() for i in page_items],
    }
