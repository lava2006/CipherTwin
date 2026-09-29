"""Policy management endpoints."""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.deps import get_current_user, require_admin
from app.models.policy import Policy
from app.models.user import User
from app.services.audit import log_event

router = APIRouter(prefix="/api/policies", tags=["policies"])


@router.get("")
def list_policies(db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    return [p.to_dict() for p in db.query(Policy).order_by(Policy.priority.desc()).all()]


@router.get("/{policy_id}")
def get_policy(policy_id: int, db: Session = Depends(get_db),
               _: User = Depends(get_current_user)):
    p = db.query(Policy).filter(Policy.id == policy_id).first()
    if not p:
        raise HTTPException(status_code=404, detail="Not found")
    return p.to_dict()


@router.patch("/{policy_id}")
def update_policy(policy_id: int, payload: dict,
                  db: Session = Depends(get_db), user: User = Depends(require_admin)):
    p = db.query(Policy).filter(Policy.id == policy_id).first()
    if not p:
        raise HTTPException(status_code=404, detail="Not found")
    import json as _json
    from app.models.policy import PolicyChange, PolicyVersion

    old_snapshot = _json.dumps(p.to_dict())
    changed_fields = {}
    for field in ("enabled", "weight", "priority", "description", "rule"):
        if field in payload and getattr(p, field) != payload[field]:
            changed_fields[field] = {"old": getattr(p, field), "new": payload[field]}
            setattr(p, field, payload[field])

    db.commit()

    if changed_fields:
        # Record change
        change = PolicyChange(
            policy_id=p.id,
            change_type="updated",
            changed_by=user.username,
            old_value=_json.dumps({k: v["old"] for k, v in changed_fields.items()}),
            new_value=_json.dumps({k: v["new"] for k, v in changed_fields.items()}),
            reason=payload.get("reason", "Policy parameters tuned"),
        )
        db.add(change)

        # Record version
        prev_ver = db.query(PolicyVersion).filter(PolicyVersion.policy_id == p.id).count()
        ver = PolicyVersion(
            policy_id=p.id,
            version_number=prev_ver + 1,
            snapshot=_json.dumps(p.to_dict()),
            created_by=user.username,
        )
        db.add(ver)
        db.commit()

    log_event(db, action="policy_updated", actor=user.username,
              target=p.name, details=str(changed_fields or payload))
    return p.to_dict()


@router.get("/{policy_id}/versions")
def policy_versions(policy_id: int, db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    from app.models.policy import PolicyVersion
    versions = db.query(PolicyVersion).filter(PolicyVersion.policy_id == policy_id).order_by(PolicyVersion.version_number.desc()).all()
    return [v.to_dict() for v in versions]


@router.get("/{policy_id}/changes")
def policy_changes(policy_id: int, db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    from app.models.policy import PolicyChange
    changes = db.query(PolicyChange).filter(PolicyChange.policy_id == policy_id).order_by(PolicyChange.timestamp.desc()).all()
    return [c.to_dict() for c in changes]


@router.post("/simulate")
def simulate_policy(
    payload: dict,
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
):
    """Safe 'What If?' policy simulation.

    Simulates the effect of hypothetical Zero Trust thresholds on real recent telemetry
    without mutating production database policies.
    """
    from app.models.risk import RiskDecision

    th_allow = float(payload.get("threshold_allow", 30.0))
    th_restricted = float(payload.get("threshold_restricted", 60.0))
    th_deny = float(payload.get("threshold_deny", 100.0))
    sample_size = int(payload.get("sample_size", 50))

    recent = (
        db.query(RiskDecision)
        .order_by(RiskDecision.timestamp.desc())
        .limit(sample_size)
        .all()
    )

    allow_count = 0
    restricted_count = 0
    deceive_count = 0
    deny_count = 0
    changed_count = 0
    details = []

    for d in recent:
        score = d.risk_score
        if score < th_allow:
            sim_decision = "allow"
            allow_count += 1
        elif score < th_restricted:
            sim_decision = "restricted"
            restricted_count += 1
        elif score < th_deny:
            sim_decision = "deceive"
            deceive_count += 1
        else:
            sim_decision = "deny"
            deny_count += 1

        flipped = sim_decision != d.decision
        if flipped:
            changed_count += 1

        details.append({
            "id": d.id,
            "risk_score": d.risk_score,
            "current_decision": d.decision,
            "simulated_decision": sim_decision,
            "flipped": flipped,
        })

    summary = (
        f"Simulated {len(recent)} recent decisions: {allow_count} allow, {restricted_count} restricted, "
        f"{deceive_count} deceive, {deny_count} deny. {changed_count} decisions ({round(changed_count / max(1, len(recent)) * 100, 1)}%) "
        f"flipped from current policy."
    )

    return {
        "total_evaluated": len(recent),
        "allow_count": allow_count,
        "restricted_count": restricted_count,
        "deceive_count": deceive_count,
        "deny_count": deny_count,
        "changed_decisions": changed_count,
        "details": details[:25],
        "summary": summary,
    }
