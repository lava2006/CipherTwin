from typing import Optional
from pydantic import BaseModel


class AuditLogOut(BaseModel):
    id: int
    timestamp: Optional[str]
    actor: Optional[str]
    action: str
    target: Optional[str]
    details: Optional[str]
    severity: str
    ip_address: Optional[str]
