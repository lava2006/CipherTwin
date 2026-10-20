from typing import Dict, List
from pydantic import BaseModel


class OverviewStats(BaseModel):
    online_devices: int
    offline_devices: int
    compromised_assets: int
    trust_relationships: int
    active_sessions: int
    risk_level: str  # low, medium, high, critical
    total_users: int
    total_telemetry_24h: int
    threats_active: int
    decoy_sessions: int
    policies_count: int
    risk_trend: List[Dict]
    telemetry_by_type: List[Dict]
    top_attacked: List[Dict]
    top_risky_users: List[Dict]
