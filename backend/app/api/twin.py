"""Digital Twin endpoints."""
from collections import defaultdict
from datetime import datetime, timezone
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.deps import get_current_user
from app.models.twin import TwinNode
from app.models.user import User
from app.services.graph import GraphStore

router = APIRouter(prefix="/api/twin", tags=["digital-twin"])


@router.get("/graph")
def get_graph(db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    from fastapi import HTTPException
    try:
        return GraphStore(db).to_payload()
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc))


@router.get("/summary")
def twin_summary(db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    """Return aggregate twin statistics (SQLite authoritative, Neo4j when available)."""
    from app.models.twin import TwinNode, TwinRelationship
    from app.models.risk import RiskDecision
    from app.models.deception import DecoySession
    from app.models.threat import Threat

    nodes = db.query(TwinNode).all()
    node_count = len(nodes)
    rel_count = db.query(TwinRelationship).count()
    online = sum(1 for n in nodes if n.status == "online")
    compromised = sum(1 for n in nodes if n.status == "compromised")
    decisions = db.query(RiskDecision).count()
    decoys = db.query(DecoySession).count()
    threats = db.query(Threat).count()
    by_type = {}
    for n in nodes:
        by_type[n.type] = by_type.get(n.type, 0) + 1

    return {
        "nodes": node_count,
        "relationships": rel_count,
        "online": online,
        "compromised": compromised,
        "decisions": decisions,
        "decoy_sessions": decoys,
        "threats": threats,
        "nodes_by_type": by_type,
    }


@router.get("/device/{device_id}")
def twin_device(device_id: str, db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    """Return a single device node and its outgoing relationships."""
    from app.models.twin import TwinNode, TwinRelationship
    node = db.query(TwinNode).filter(TwinNode.id == device_id).first()
    if not node:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail=f"Device {device_id} not found")
    rels = db.query(TwinRelationship).filter(TwinRelationship.source_id == device_id).all()
    return {
        "node": node.to_dict(),
        "relationships": [
            {
                "target": r.target_id,
                "relation": r.relation,
                "weight": r.weight,
                "description": r.description,
            }
            for r in rels
        ],
    }


@router.get("/user/{user_id}")
def twin_user(user_id: str, db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    """Return a single user node and its outgoing relationships."""
    from app.models.twin import TwinNode, TwinRelationship
    node = db.query(TwinNode).filter(TwinNode.id == user_id).first()
    if not node:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail=f"User {user_id} not found")
    rels = db.query(TwinRelationship).filter(TwinRelationship.source_id == user_id).all()
    return {
        "node": node.to_dict(),
        "relationships": [
            {
                "target": r.target_id,
                "relation": r.relation,
                "weight": r.weight,
                "description": r.description,
            }
            for r in rels
        ],
    }


@router.get("/nodes")
def list_nodes(type: str | None = None, db: Session = Depends(get_db),
               _: User = Depends(get_current_user)):
    from fastapi import HTTPException
    from app.services.neo4j_client import neo4j_client
    from app.services.graph import GraphStore
    health = neo4j_client.check_health()
    if health.get("status") == "HEALTHY":
        graph = neo4j_client.get_graph()
        nodes = graph.get("nodes", [])
    else:
        nodes = [n.to_dict() for n in GraphStore(db).all_nodes()]
    if type:
        nodes = [n for n in nodes if (n.get("type") or "").lower() == type.lower()]
    return nodes


@router.get("/stats")
def twin_stats(db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    from fastapi import HTTPException
    try:
        return GraphStore(db).stats()
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc))


@router.get("/recommendations")
def get_decoy_recommendations(limit: int = 5, db: Session = Depends(get_db),
                             _: User = Depends(get_current_user)):
    """Derive honeypot/decoy placement recommendations directly from Neo4j topology."""
    from fastapi import HTTPException
    try:
        return GraphStore(db).recommend_decoys(limit=limit)
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc))


@router.post("/heartbeat")
def heartbeat(node_id: str, db: Session = Depends(get_db),
              user: User = Depends(get_current_user)):
    """Mark a node as online in SQLite (authoritative) and Neo4j (when available)."""
    from fastapi import HTTPException
    from app.services.neo4j_client import neo4j_client
    from app.services.graph import GraphStore

    now_ts = datetime.now(timezone.utc)

    node = db.query(TwinNode).filter(TwinNode.id == node_id).first()
    if not node:
        raise HTTPException(status_code=404, detail="Twin node not found")

    node.status = "online"
    node.last_seen = now_ts
    db.commit()

    neo4j_ok = False
    health = neo4j_client.check_health()
    if health.get("status") == "HEALTHY":
        try:
            neo4j_client.execute_cypher(
                "MATCH (n {id: $node_id}) SET n.status = 'online', n.last_seen = $ts RETURN n",
                {"node_id": node_id, "ts": now_ts.isoformat()},
            )
            neo4j_ok = True
        except Exception:
            neo4j_ok = False

    return {"ok": True, "node": node.to_dict(), "source": "Neo4j+SQLite" if neo4j_ok else "SQLite"}



@router.get("/neo4j/status")
def neo4j_status(_: User = Depends(get_current_user)):
    """Truthful Neo4j connectivity and status report."""
    from app.services.neo4j_client import neo4j_client
    return neo4j_client.check_health()


@router.post("/neo4j/sync")
def neo4j_sync(db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    """Explicitly synchronize the complete SQLite Digital Twin into Neo4j."""
    from app.services.graph import GraphStore
    return GraphStore(db).sync_all_to_neo4j()


@router.post("/neo4j/verify")
def neo4j_verify(_: User = Depends(get_current_user)):
    """Execute synthetic graph creation, query validation, and safe cleanup in Neo4j."""
    from app.services.neo4j_client import neo4j_client
    return neo4j_client.run_synthetic_verification()
