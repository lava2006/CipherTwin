from typing import List
from pydantic import BaseModel


class TelemetryOut(BaseModel):
    id: int
    timestamp: str | None
    user_id: str | None
    device_id: str | None
    target_id: str | None
    event_type: str
    location: str | None
    ip_address: str | None
    status: str
    risk_indicators: List[str] = []
