import pytest
from app.services.neo4j_client import Neo4jClient, neo4j_client
from app.services.graph import GraphStore
from app.db.session import SessionLocal
from app.models.twin import TwinNode, TwinRelationship


def test_neo4j_truthful_health_check():
    client = Neo4jClient()
    health = client.check_health()
    assert "status" in health
    assert health["status"] in ("HEALTHY", "UNAVAILABLE", "DEGRADED")
    assert "url" in health


def test_neo4j_synthetic_verification_pipeline():
    client = Neo4jClient()
    result = client.verify_synthetic_pipeline()
    assert "success" in result
    assert "nodes_created" in result
    assert "relationships_created" in result
    assert "traversal_verified" in result
    assert "cleanup_verified" in result
    if result.get("mode") == "STANDALONE_FALLBACK":
        pytest.skip("Live Neo4j is unavailable; this test requires the actual service.")
    assert result["success"] is True
    assert result["nodes_created"] > 0
    assert result["relationships_created"] > 0
    assert result["traversal_verified"] is True
    assert result["cleanup_verified"] is True


def test_graph_store_digital_twin_traversal():
    db = SessionLocal()
    try:
        # Keep this test self-contained; do not depend on a previously seeded local DB.
        if db.query(TwinNode).filter(TwinNode.id == "test-graph-user").first() is None:
            db.add_all([
                TwinNode(id="test-graph-user", label="Test User", type="user", status="online", trust_score=90),
                TwinNode(id="test-graph-device", label="Test Device", type="device", status="online", trust_score=75),
                TwinNode(id="test-graph-server", label="Test Server", type="server", status="online", trust_score=60),
            ])
            db.flush()
            db.add_all([
                TwinRelationship(source_id="test-graph-user", target_id="test-graph-device", relation="uses"),
                TwinRelationship(source_id="test-graph-device", target_id="test-graph-server", relation="accesses"),
            ])
            db.commit()

        store = GraphStore(db)
        twin = store.build_digital_twin()
        assert "nodes" in twin
        assert "edges" in twin
        assert len(twin["nodes"]) > 0
        assert len(twin["edges"]) > 0

        # Verify node types exist
        node_types = {n.get("type") for n in twin["nodes"]}
        assert "user" in node_types or "device" in node_types or "server" in node_types

        # Verify blast radius calculation
        first_node = twin["nodes"][0]["id"]
        blast = store.calculate_blast_radius(first_node)
        assert "target_node" in blast
        assert "blast_radius_score" in blast
        assert "affected_nodes_count" in blast
        assert blast["target_node"] == first_node
        assert 0 <= blast["blast_radius_score"] <= 100

        # Verify chokepoints detection
        chokepoints = store.find_chokepoints()
        assert isinstance(chokepoints, list)
        assert len(chokepoints) > 0

        # Verify shortest path
        if len(twin["nodes"]) >= 2:
            src = twin["nodes"][0]["id"]
            dst = twin["nodes"][1]["id"]
            path = store.get_shortest_path(src, dst)
            assert "source" in path
            assert "target" in path
            assert "connected" in path
            assert "path" in path
    finally:
        db.close()


def test_neo4j_client_cypher_fallback_on_offline():
    client = Neo4jClient()
    # Execute cypher against client (returns rows or empty if offline)
    res = client.run_cypher("RETURN 1 as test")
    assert isinstance(res, list)
