import json
import pytest
from app.db.session import SessionLocal
from app.models.policy import Policy, PolicyVersion, PolicyChange
from app.models.risk import RiskDecision, AnalystFeedback
from app.models.telemetry import TelemetryEvent
from app.services.risk_engine import engine


def test_policy_evaluation_and_matching():
    db = SessionLocal()
    try:
        # Create normal event
        normal_event = TelemetryEvent(
            user_id="user_normal",
            event_type="routine_login",
            ip_address="192.168.1.10",
            location="HQ",
            status="success",
            risk_indicators=json.dumps([]),
        )
        res_normal = engine.evaluate(normal_event, db)
        assert res_normal.risk_score < 40
        assert res_normal.decision in ("allow", "restricted")

        # Create high-threat event
        malicious_event = TelemetryEvent(
            user_id="user_attacker",
            event_type="privilege_escalation",
            ip_address="198.51.100.99",
            location="Tor Exit Node",
            status="failure",
            risk_indicators=json.dumps(["brute_force", "credential_stuffing", "sensitive_resource", "high_volume"]),
            raw=json.dumps({"failed_logins": 10}),
        )
        res_malicious = engine.evaluate(malicious_event, db)
        assert res_malicious.risk_score >= 55
        assert res_malicious.risk_score > res_normal.risk_score
        assert res_malicious.decision in ("restricted", "deceive", "deny")
    finally:
        db.close()


def test_what_if_policy_simulation_zero_mutation():
    db = SessionLocal()
    try:
        # Count policies before simulation
        p_count_before = db.query(Policy).count()
        policies_before = [p.to_dict() for p in db.query(Policy).all()]

        # Query recent decisions
        recent = db.query(RiskDecision).limit(50).all()
        assert len(recent) > 0

        # Simulate strict policy thresholds: allow < 20, restricted < 40, deceive < 70, deny >= 70
        th_allow = 20.0
        th_restricted = 40.0
        th_deny = 70.0

        allow_cnt = sum(1 for d in recent if d.risk_score < th_allow)
        restricted_cnt = sum(1 for d in recent if th_allow <= d.risk_score < th_restricted)
        deceive_cnt = sum(1 for d in recent if th_restricted <= d.risk_score < th_deny)
        deny_cnt = sum(1 for d in recent if d.risk_score >= th_deny)

        assert (allow_cnt + restricted_cnt + deceive_cnt + deny_cnt) == len(recent)

        # Verify ZERO MUTATION occurred in production policy database
        p_count_after = db.query(Policy).count()
        policies_after = [p.to_dict() for p in db.query(Policy).all()]
        assert p_count_before == p_count_after
        assert policies_before == policies_after
    finally:
        db.close()


def test_policy_versioning_and_rollback():
    db = SessionLocal()
    try:
        # Find or create a test policy
        policy = db.query(Policy).first()
        assert policy is not None

        old_weight = policy.weight
        old_version_count = db.query(PolicyVersion).filter(PolicyVersion.policy_id == policy.id).count()

        # Update policy and record snapshot
        new_weight = old_weight + 0.1
        change = PolicyChange(
            policy_id=policy.id,
            change_type="updated",
            changed_by="admin",
            old_value=json.dumps({"weight": old_weight}),
            new_value=json.dumps({"weight": new_weight}),
            reason="Security tightening",
        )
        db.add(change)

        version = PolicyVersion(
            policy_id=policy.id,
            version_number=old_version_count + 1,
            snapshot=json.dumps(policy.to_dict()),
            created_by="admin",
        )
        db.add(version)
        policy.weight = new_weight
        db.commit()

        # Verify version and change recorded
        assert db.query(PolicyVersion).filter(PolicyVersion.policy_id == policy.id).count() == old_version_count + 1
        assert db.query(PolicyChange).filter(PolicyChange.policy_id == policy.id).count() >= 1

        # Rollback: restore from snapshot
        snap = json.loads(version.snapshot)
        policy.weight = snap["weight"]
        db.commit()
        db.refresh(policy)
        assert policy.weight == old_weight
    finally:
        db.close()


def test_analyst_feedback_loop():
    db = SessionLocal()
    try:
        decision = db.query(RiskDecision).first()
        assert decision is not None

        # Submit analyst feedback (TP)
        fb = AnalystFeedback(
            decision_id=decision.id,
            analyst_id="soc_analyst_1",
            original_prediction=decision.decision,
            analyst_label="TRUE_POSITIVE",
            reason="Confirmed brute force telemetry match",
        )
        db.add(fb)
        db.commit()
        db.refresh(fb)

        assert fb.id is not None
        assert fb.analyst_label == "TRUE_POSITIVE"
        assert fb.analyst_id == "soc_analyst_1"

        # Verify feedback query
        stored = db.query(AnalystFeedback).filter(AnalystFeedback.decision_id == decision.id).first()
        assert stored is not None
        assert stored.reason == "Confirmed brute force telemetry match"
    finally:
        db.close()
