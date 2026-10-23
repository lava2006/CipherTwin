"""Test Guarded Actions Workflow with User Confirmation."""
import pytest
from app.db.session import SessionLocal
from app.guide.service import GuideService
from app.models.audit import AuditLog


def test_action_proposal_requires_confirmation():
    """Verify that action proposal creates a pending action without modifying system state."""
    service = GuideService()
    db = SessionLocal()
    try:
        res = service.ask(
            question="Please block device laptop-alice-01 immediately",
            lens="analyst",
        )
        assert res is not None
        assert res.get("proposed_action") is not None
        act = res["proposed_action"]
        assert act["action_type"] == "block_device"
        assert act["status"] == "pending_confirmation"
        assert "action_id" in act
    finally:
        db.close()


def test_action_confirmation_executes_and_logs_audit():
    """Verify confirming an action executes and records an audit log entry."""
    service = GuideService()
    db = SessionLocal()
    try:
        # First stage an action
        res = service.ask(
            question="Propose blocking device laptop-alice-01",
            lens="simple",
        )
        act = res.get("proposed_action")
        assert act is not None
        action_id = act["action_id"]

        audit_count_before = db.query(AuditLog).count()

        # Confirm action
        conf_res = service.confirm_action(action_id=action_id, confirmed=True)
        assert conf_res["success"] is True
        assert conf_res["status"] == "executed"

        # Check audit log
        audit_count_after = db.query(AuditLog).count()
        assert audit_count_after > audit_count_before
    finally:
        db.close()


def test_action_cancellation():
    """Verify that unconfirmed / cancelled action safely expires."""
    service = GuideService()
    db = SessionLocal()
    try:
        res = service.ask(
            question="Propose blocking device laptop-alice-01",
            lens="simple",
        )
        act = res.get("proposed_action")
        action_id = act["action_id"]

        conf_res = service.confirm_action(action_id=action_id, confirmed=False)
        assert conf_res["success"] is True
        assert conf_res["status"] == "cancelled"
    finally:
        db.close()
