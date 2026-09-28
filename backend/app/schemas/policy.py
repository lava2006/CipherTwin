from typing import List, Optional
from pydantic import BaseModel


class PolicyOut(BaseModel):
    id: int
    name: str
    description: Optional[str]
    rule: str
    priority: int
    enabled: bool
    weight: float
    false_positive_rate: float
    false_negative_rate: float


class PolicyImprovementOut(BaseModel):
    id: int
    timestamp: Optional[str]
    algorithm: str
    before_score: float
    after_score: float
    before_fp: float
    after_fp: float
    before_fn: float
    after_fn: float
    duration_ms: int
    iterations: int
    summary: Optional[str]
    changes: List[dict] = []
