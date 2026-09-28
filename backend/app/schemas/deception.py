from typing import List, Optional
from pydantic import BaseModel


class DecoySessionOut(BaseModel):
    id: int
    timestamp: Optional[str]
    threat_id: Optional[int]
    decoy_type: str
    actor: Optional[str]
    source_ip: Optional[str]
    activity: List[str]
    commands: List[str]
    pages: List[str]
    credentials_used: Optional[str]
    notes: Optional[str]


class HoneytokenOut(BaseModel):
    id: int
    token_type: str
    label: str
    value: str
    planted_on: Optional[str]
    triggered: bool
    created_at: Optional[str]
