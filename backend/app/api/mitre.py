"""MITRE ATT&CK reference catalog."""
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.deps import get_current_user
from app.models.user import User
from app.services.mitre import all_techniques

router = APIRouter(prefix="/api/mitre", tags=["mitre"])


@router.get("")
def techniques(_: User = Depends(get_current_user)):
    return all_techniques()
