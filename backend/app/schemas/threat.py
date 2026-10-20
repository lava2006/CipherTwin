from typing import List, Optional
from pydantic import BaseModel


class ThreatOut(BaseModel):
    id: int
    actor_name: str
    username: Optional[str]
    ip_address: Optional[str]
    risk_score: float
    severity: str
    techniques: List[str]
    commands: List[str]
    first_seen: Optional[str]
    last_seen: Optional[str]
    description: Optional[str]
    status: str
