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


class PolicyRuleOut(BaseModel):
    id: int
    policy_id: int
    condition_field: str
    operator: str
    condition_value: str
    action: str
    created_at: Optional[str]


class PolicyVersionOut(BaseModel):
    id: int
    policy_id: int
    version_number: int
    snapshot: dict
    created_by: Optional[str]
    created_at: Optional[str]


class PolicyChangeOut(BaseModel):
    id: int
    policy_id: int
    change_type: str
    changed_by: Optional[str]
    old_value: Optional[dict]
    new_value: Optional[dict]
    reason: Optional[str]
    timestamp: Optional[str]


class PolicySimulateIn(BaseModel):
    threshold_allow: Optional[float] = 30.0
    threshold_restricted: Optional[float] = 60.0
    threshold_deny: Optional[float] = 100.0
    hypothetical_rules: Optional[List[dict]] = None
    sample_size: int = 50


class PolicySimulateOut(BaseModel):
    total_evaluated: int
    allow_count: int
    restricted_count: int
    deceive_count: int
    deny_count: int
    changed_decisions: int
    details: List[dict]
    summary: str
