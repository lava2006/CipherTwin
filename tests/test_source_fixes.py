"""Regression tests for source-level defects found during deep verification."""
import json
from pathlib import Path

import numpy as np
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db.session import Base
from app.models import AnalystFeedback, DecoySession, Policy, RiskDecision, TelemetryEvent, TwinNode, TwinRelationship
from app.services.cowrie import CowrieService
from app.services.qubo_builder import build_policy_qubo, decode_solution, evaluate_solution_cost
from app.services.quantum_optimizer import QuantumOptimizer


@pytest.fixture
def isolated_db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    db = Session()
    try:
        yield db
    finally:
        db.close()
        engine.dispose()


def test_qubo_dictionary_contains_capacity_slack_variables():
    units = [
        {"id": "a", "risk_score": 20, "trust_score": 90},
        {"id": "b", "risk_score": 80, "trust_score": 20},
        {"id": "c", "risk_score": 60, "trust_score": 40},
    ]
    Q, offset, names, qubo_dict = build_policy_qubo(units, decoy_capacity=2)
    assert Q.shape == (11, 11)
    assert len(names) == Q.shape[0]
    assert max(max(index) for index in qubo_dict) == Q.shape[0] - 1
    # At least one quadratic term must touch a capacity slack variable.
    assert any(i >= 9 or j >= 9 for i, j in qubo_dict)


def test_scipy_classical_solver_returns_full_feasible_qubo_solution():
    units = [
        {"id": "a", "risk_score": 20, "trust_score": 90},
        {"id": "b", "risk_score": 80, "trust_score": 20},
        {"id": "c", "risk_score": 60, "trust_score": 40},
    ]
    Q, offset, _, qubo_dict = build_policy_qubo(units, decoy_capacity=2)
    bits, reported_cost, _duration = QuantumOptimizer(None)._solve_classical_baseline(
        qubo_dict, offset, units, num_variables=Q.shape[0], decoy_capacity=2
    )
    valid, _assignments, counts = decode_solution(bits, units)
    assert len(bits) == Q.shape[0]
    assert valid
    assert counts["restrict"] <= 2
    assert reported_cost == pytest.approx(evaluate_solution_cost(bits, Q, offset))


def test_cowrie_records_enter_pending_telemetry_once(tmp_path):
    log_path = tmp_path / "cowrie.json"
    records = [
        {
            "eventid": "cowrie.session.connect", "timestamp": "2026-10-15T10:00:00Z",
            "session": "test-session-1", "src_ip": "192.0.2.10", "dst_ip": "127.0.0.1",
            "dst_port": 2222, "protocol": "ssh", "message": "test connect",
        },
        {
            "eventid": "cowrie.login.failed", "timestamp": "2026-10-15T10:00:01Z",
            "session": "test-session-1", "src_ip": "192.0.2.10", "username": "root",
            "password": "example-secret", "message": "test login failed",
        },
    ]
    log_path.write_text("\n".join(json.dumps(row) for row in records) + "\n", encoding="utf-8")
    from app.core.config import settings
    old_mode = settings.deception_mode
    old_simulation = settings.enable_simulation
    try:
        settings.deception_mode = "COWRIE"
        settings.enable_simulation = False
        db_engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(bind=db_engine)
        Session = sessionmaker(bind=db_engine, autoflush=False, autocommit=False)
        db = Session()
        try:
            service = CowrieService()
            assert service.ingest_logs_to_db(db, str(log_path)) == 1
            assert db.query(TelemetryEvent).count() == 2
            assert db.query(TelemetryEvent).filter(TelemetryEvent.processed == 0).count() == 2
            # A second scan must not duplicate event records.
            assert service.ingest_logs_to_db(db, str(log_path)) == 1
            assert db.query(TelemetryEvent).count() == 2
            session = db.query(DecoySession).one()
            assert "example-secret" not in (session.credentials_used or "")
            assert "[REDACTED]" in (session.credentials_used or "")
        finally:
            db.close()
            db_engine.dispose()
    finally:
        settings.deception_mode = old_mode
        settings.enable_simulation = old_simulation


def test_analyst_feedback_changes_optimizer_risk_estimate(isolated_db):
    p = Policy(name="Ordinary policy", rule="allow_if:trusted", weight=1.0,
               false_positive_rate=0.1, false_negative_rate=0.1)
    decision = RiskDecision(risk_score=50.0, decision="allow", confidence=0.8)
    isolated_db.add_all([p, decision])
    isolated_db.commit()
    optimizer = QuantumOptimizer(isolated_db)
    baseline = optimizer._extract_policy_units()[0]["risk_score"]

    labels = ["TRUE_POSITIVE"] * 3 + ["FALSE_NEGATIVE"] + ["TRUE_NEGATIVE"] + ["FALSE_POSITIVE"] * 3
    for label in labels:
        isolated_db.add(AnalystFeedback(
            decision_id=decision.id, analyst_id="test-analyst",
            original_prediction="allow", analyst_label=label, reason="test fixture",
        ))
    isolated_db.commit()
    adjusted = optimizer._extract_policy_units()[0]["risk_score"]
    assert adjusted < baseline


def test_neo4j_projection_reports_unavailable_instead_of_claiming_synced(isolated_db, monkeypatch):
    from app.services import graph as graph_module
    monkeypatch.setattr(graph_module.neo4j_client, "check_health", lambda: {
        "status": "UNAVAILABLE", "message": "test broker unavailable"
    })
    result = graph_module.GraphStore(isolated_db).sync_all_to_neo4j()
    assert result["status"] == "UNAVAILABLE"
    assert result["nodes_synced"] == 0
    assert result["errors"]


def test_neo4j_projection_syncs_nodes_and_relationships(isolated_db, monkeypatch):
    from app.services import graph as graph_module

    isolated_db.add_all([
        TwinNode(id="user-1", label="Analyst", type="user", status="online", trust_score=90),
        TwinNode(id="server-1", label="App server", type="server", status="online", trust_score=60),
    ])
    isolated_db.flush()
    isolated_db.add(TwinRelationship(
        source_id="user-1", target_id="server-1", relation="accesses", weight=0.8,
        description="test access relationship",
    ))
    isolated_db.commit()

    seen_nodes = []
    seen_relationships = []
    monkeypatch.setattr(graph_module.neo4j_client, "check_health", lambda: {"status": "HEALTHY"})
    monkeypatch.setattr(
        graph_module.neo4j_client, "upsert_node",
        lambda node_id, label, props: seen_nodes.append((node_id, label, props)) or True,
    )
    monkeypatch.setattr(
        graph_module.neo4j_client, "upsert_relationship",
        lambda source, target, relation, props: seen_relationships.append((source, target, relation, props)) or True,
    )
    monkeypatch.setattr(
        graph_module.neo4j_client, "execute_cypher",
        lambda statement, params: {"results": [{"data": []}], "errors": []},
    )

    result = graph_module.GraphStore(isolated_db).sync_all_to_neo4j()
    assert result["status"] == "SYNCED"
    assert result["nodes_synced"] == 2
    assert result["relationships_synced"] == 1
    assert {node[1] for node in seen_nodes} == {"User", "Server"}
    assert all(node[2]["ciphertwin_managed"] is True for node in seen_nodes)
    assert seen_relationships[0][2] == "ACCESSES"
