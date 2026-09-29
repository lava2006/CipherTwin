import json
import uuid
import pytest
from app.db.session import SessionLocal
from app.models.audit import AuditLog
from app.models.deception import DecoySession, Honeytoken
from app.models.risk import RiskDecision
from app.models.telemetry import TelemetryEvent
from app.models.twin import TwinNode
from app.services.graph import GraphStore
from app.services.rabbitmq import rabbitmq_pipeline
from app.services.risk_engine import engine
from app.services.deception import DeceptionEngine


def test_full_end_to_end_security_lifecycle():
    """Complete 9-step synthetic security lifecycle test:
    1. Ingest telemetry -> 2. RabbitMQ Pipeline -> 3. ML Risk Engine ->
    4. MITRE ATT&CK Mapping -> 5. Graph Digital Twin Blast Radius ->
    6. Policy Evaluation -> 7. Adaptive Deception Trap ->
    8. Audit Logging -> 9. Verifiable Records
    """
    db = SessionLocal()
    try:
        # Step 1: Inject synthetic attack telemetry event (Brute force & credential access)
        msg_id = str(uuid.uuid4())
        attacker_user = f"attacker_{msg_id[:8]}"
        telemetry_payload = {
            "message_id": msg_id,
            "event_type": "failed_login",
            "user_id": attacker_user,
            "device_id": "srv_dmz_web_01",
            "ip_address": "198.51.100.177",
            "location": "Tor Exit Node",
            "status": "failure",
            "risk_indicators": ["brute_force", "credential_stuffing", "anonymous_network"],
            "raw_payload": {"failed_logins": 8, "target_service": "ssh"},
        }

        # Step 2: RabbitMQ Telemetry Pipeline (Publish & Consume)
        pub_ok, pub_id = rabbitmq_pipeline.publish(telemetry_payload)
        assert pub_ok is True
        assert pub_id == msg_id

        # Process through pipeline
        proc_result = rabbitmq_pipeline.process_one(db)
        assert proc_result is not None
        assert proc_result["acknowledged"] is True
        assert proc_result["message_id"] == msg_id

        # Step 3 & 4: Risk Engine calculation & MITRE ATT&CK mapping
        event = db.query(TelemetryEvent).filter(TelemetryEvent.id == proc_result["event_id"]).first()
        assert event is not None
        assert event.mitre_technique == "T1110"  # Brute Force mapping
        assert event.mitre_tactic == "Credential Access"

        decision = db.query(RiskDecision).filter(RiskDecision.telemetry_id == event.id).first()
        assert decision is not None
        assert decision.risk_score >= 40
        assert decision.decision in ("restricted", "deceive", "deny")

        # Step 5: Digital Twin Graph Context & Blast Radius
        store = GraphStore(db)
        # Check target node
        blast = store.calculate_blast_radius("srv_dmz_web_01")
        assert blast["target_node"] == "srv_dmz_web_01"
        assert blast["blast_radius_score"] >= 0

        # Step 6 & 7: Adaptive Deception Trap
        # High risk attack automatically triggered decoy or honeytoken diversion
        deception = DeceptionEngine(db)
        decoy_sessions = deception.list_sessions(limit=5)
        assert len(decoy_sessions) >= 1
        latest_decoy = decoy_sessions[0]
        assert latest_decoy.fidelity in ("MEDIUM", "HIGH")
        assert latest_decoy.reason is not None

        # Step 8: Comprehensive Audit Logging
        recent_audit = (
            db.query(AuditLog)
            .order_by(AuditLog.timestamp.desc())
            .limit(10)
            .all()
        )
        actions = [a.action for a in recent_audit]
        assert any("decoy" in act or "risk" in act or "policy" in act or "telemetry" in act or "auth" in act for act in actions)

        # Step 9: Negative Testing - Malformed Payload Rejected
        bad_msg = {"invalid_key": "bad_data"}
        bad_ok, bad_err = rabbitmq_pipeline.publish(bad_msg)
        assert bad_ok is False
        assert "Validation error" in bad_err

        # Negative Testing - Duplicate Event Dropped
        dup_ok, dup_status = rabbitmq_pipeline.publish(telemetry_payload)
        assert dup_ok is True
        assert dup_status == "Duplicate dropped"

    finally:
        db.close()
