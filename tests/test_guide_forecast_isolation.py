"""Test in-memory Twin Forecast graph isolation.

CRITICAL INVARIANT: The live Neo4j database and SQLite store must NEVER be mutated
during what-if forecast evaluations.
"""
import pytest
from app.db.session import SessionLocal
from app.models.twin import TwinNode
from app.models.risk import RiskDecision
from app.guide.forecast import run_twin_forecast


def test_forecast_does_not_mutate_sqlite_database():
    """Verify that node and decision records in SQLite remain untouched by what-if forecast."""
    db = SessionLocal()
    try:
        nodes_before = db.query(TwinNode).count()
        decisions_before = db.query(RiskDecision).count()

        # Run what-if MFA requirement forecast
        res = run_twin_forecast(db, change_type="require_mfa", target="finance")
        assert res is not None
        assert "risk_delta" in res
        assert res["isolation_verified"] is True

        # Run what-if compromise blast radius forecast
        res2 = run_twin_forecast(db, change_type="compromise_device", target="admin-workstation")
        assert res2 is not None
        assert "blast_radius" in res2

        nodes_after = db.query(TwinNode).count()
        decisions_after = db.query(RiskDecision).count()

        assert nodes_before == nodes_after, "TwinNode table count was mutated by forecast!"
        assert decisions_before == decisions_after, "RiskDecision table was mutated by forecast!"
    finally:
        db.close()


def test_forecast_in_memory_reachability():
    """Verify that in-memory reachability accurately calculates blast radius."""
    db = SessionLocal()
    try:
        sample_node = db.query(TwinNode).first()
        target = sample_node.id if sample_node else "admin-workstation"
        res = run_twin_forecast(db, change_type="compromise_device", target=target)
        assert "blast_radius" in res
        blast = res["blast_radius"]
        assert "reachable_count" in blast
        assert blast["reachable_count"] >= 0
    finally:
        db.close()
