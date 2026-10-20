import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.db.session import SessionLocal
from app.models import TwinNode, TwinRelationship


def test_honeypot_node_seeded_in_sqlite():
    """Verify that decoy-ssh-01 is properly seeded as a honeypot node with full deception attributes."""
    db = SessionLocal()
    try:
        hp = db.query(TwinNode).filter(TwinNode.id == "decoy-ssh-01").first()
        assert hp is not None, "decoy-ssh-01 should be seeded in the digital twin"
        assert hp.type == "honeypot"
        assert "SSH" in hp.label or "Cowrie" in hp.label
        assert hp.status == "online"
        assert hp.os == "Cowrie Linux Honeypot"
        assert "honeypot" in hp.tags
        assert "cowrie" in hp.tags
        assert "decoy" in hp.tags
        assert hp.ip_address == "10.20.10.99"
    finally:
        db.close()


def test_honeypot_relationship_traps():
    """Verify the digital twin traps relationship linking production server to the honeypot."""
    db = SessionLocal()
    try:
        rel = db.query(TwinRelationship).filter(TwinRelationship.target_id == "decoy-ssh-01").first()
        assert rel is not None, "decoy-ssh-01 should have an inbound relationship from a server"
        assert rel.relation == "traps"
        assert rel.weight == 1.0

        # Check source is a server
        source = db.query(TwinNode).filter(TwinNode.id == rel.source_id).first()
        assert source is not None
        assert source.type == "server"
    finally:
        db.close()


def test_twin_graph_api_includes_honeypot():
    """Verify GET /api/twin/graph payload contains honeypot node and traps relationship."""
    from app.core.security import create_access_token
    token = create_access_token(subject="admin", role="admin")
    headers = {"Authorization": f"Bearer {token}"}

    client = TestClient(app)
    resp = client.get("/api/twin/graph", headers=headers)
    assert resp.status_code == 200
    graph = resp.json()

    assert "nodes" in graph
    assert "edges" in graph

    # Verify honeypot node in graph nodes
    hp_nodes = [n for n in graph["nodes"] if n["id"] == "decoy-ssh-01"]
    assert len(hp_nodes) == 1
    assert hp_nodes[0]["type"] == "honeypot"
    assert hp_nodes[0]["ip_address"] == "10.20.10.99"

    # Verify traps edge in graph edges
    trap_edges = [e for e in graph["edges"] if e["target"] == "decoy-ssh-01"]
    assert len(trap_edges) >= 1
    assert trap_edges[0]["relation"] == "traps"
