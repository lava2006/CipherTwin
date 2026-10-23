"""Test Grounded Tool Registry Evidence Fidelity."""
import pytest
from app.db.session import SessionLocal
from app.guide.tools import tool_registry
from app.models.risk import RiskDecision
from app.models.twin import TwinNode


def test_get_decision_returns_grounded_evidence():
    """Verify get_decision fetches real stored decisions or honestly reports not found."""
    db = SessionLocal()
    try:
        sample = db.query(RiskDecision).first()
        if sample:
            res = tool_registry.execute("get_decision", db=db, decision_id=sample.id)
            assert res["found"] is True
            evidence = res["evidence"]
            assert evidence["id"] == sample.id
            assert evidence["risk_score"] == sample.risk_score
            assert evidence["decision"] == sample.decision
        else:
            res = tool_registry.execute("get_decision", db=db, decision_id="non-existent-id")
            assert res["found"] is False
    finally:
        db.close()


def test_twin_neighbors_returns_grounded_nodes():
    """Verify twin_neighbors returns graph neighbors for an active node."""
    db = SessionLocal()
    try:
        sample = db.query(TwinNode).first()
        if sample:
            res = tool_registry.execute("twin_neighbors", db=db, node_id=sample.id)
            assert res["found"] is True
            assert "neighbors" in res["evidence"]
    finally:
        db.close()


def test_solver_comparison_honesty():
    """Verify solver comparison honestly assesses QAOA vs SciPy without false supremacy claims."""
    db = SessionLocal()
    try:
        res = tool_registry.execute("solver_comparison", db=db)
        assert res["found"] is True
        evidence = res["evidence"]
        assert "qaoa_cost" in evidence
        assert "classical_cost" in evidence
        assert "winner" in evidence
        assert "assessment" in evidence
        # Honest assessment check
        assert "classical" in evidence["assessment"].lower()
    finally:
        db.close()


def test_blast_radius_depth_bounding():
    """Verify blast radius BFS is strictly bounded within max_depth."""
    db = SessionLocal()
    try:
        sample = db.query(TwinNode).first()
        target = sample.id if sample else "admin-workstation"
        res = tool_registry.execute("blast_radius", db=db, node_id=target, max_depth=3)
        assert res["found"] is True
        evidence = res["evidence"]
        assert evidence["max_depth"] <= 3
        for node in evidence.get("reachable_nodes", []):
            assert node["depth"] <= 3
    finally:
        db.close()
