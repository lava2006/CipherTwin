import pytest
from app.db.session import SessionLocal
from app.api.system import system_health
from app.services.audit import log_event
from app.models.audit import AuditLog


def test_system_health_all_subsystems_reported():
    db = SessionLocal()
    try:
        health = system_health(db)
        assert "status" in health
        assert health["status"] in ("HEALTHY", "DEGRADED", "UNAVAILABLE")
        assert "timestamp" in health
        assert "services" in health

        services = health["services"]
        expected_services = [
            "fastapi",
            "sqlite",
            "neo4j",
            "rabbitmq",
            "ml",
            "deception",
            "cowrie",
            "telemetry_worker",
        ]
        for s in expected_services:
            assert s in services, f"Missing service {s} in system health report"
            assert "status" in services[s]
            assert services[s]["status"] in ("HEALTHY", "DEGRADED", "UNAVAILABLE")
    finally:
        db.close()


def test_truthful_health_reporting_no_fake_status():
    db = SessionLocal()
    try:
        health = system_health(db)
        services = health["services"]

        # FastAPI and SQLite are running in this test environment
        assert services["fastapi"]["status"] == "HEALTHY"
        assert services["sqlite"]["status"] == "HEALTHY"

        # ML model is trained and persisted
        assert services["ml"]["status"] == "HEALTHY"

        # Verify each service reports a valid, truthful status
        valid_statuses = {"HEALTHY", "DEGRADED", "UNAVAILABLE"}
        for s_name, s_info in services.items():
            assert s_info["status"] in valid_statuses, f"Service {s_name} has invalid status {s_info.get('status')}"

        # Aggregate status must match individual service health
        any_unhealthy = any(s["status"] in ("DEGRADED", "UNAVAILABLE") for s in services.values())
        if any_unhealthy:
            assert health["status"] in ("DEGRADED", "UNAVAILABLE")
        else:
            assert health["status"] == "HEALTHY"
    finally:
        db.close()


def test_audit_logging_and_querying():
    db = SessionLocal()
    try:
        entry = log_event(
            db,
            action="policy_override",
            actor="admin_security",
            target="firewall_rule_4",
            details="Emergency bypass approved for incident response",
            severity="warning",
            ip_address="192.168.1.100",
        )
        assert entry is not None
        assert entry.id is not None
        assert entry.action == "policy_override"
        assert entry.actor == "admin_security"
        assert entry.target == "firewall_rule_4"
        assert entry.severity == "warning"
        assert entry.timestamp is not None

        # Verify query persistence
        queried = db.query(AuditLog).filter(AuditLog.id == entry.id).first()
        assert queried is not None
        assert queried.details == "Emergency bypass approved for incident response"
        assert queried.ip_address == "192.168.1.100"
    finally:
        db.close()
