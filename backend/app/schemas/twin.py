from typing import List
from pydantic import BaseModel


class TwinNodeOut(BaseModel):
    id: str
    label: str
    type: str
    ip_address: str | None = None
    location: str | None = None
    department: str | None = None
    status: str
    trust_score: float
    risk_score: float
    sensitivity: str
    os: str | None = None
    tags: List[str] = []
    last_seen: str | None = None


class TwinRelationshipOut(BaseModel):
    source: str
    target: str
    relation: str
    weight: float = 1.0


class TwinGraph(BaseModel):
    nodes: List[TwinNodeOut]
    edges: List[TwinRelationshipOut]
