"""Digital Twin endpoints."""
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
    return GraphStore(db).to_payload()


@router.get("/nodes")
def list_nodes(type: str | None = None, db: Session = Depends(get_db),
               _: User = Depends(get_current_user)):
    q = db.query(TwinNode)
    if type:
        q = q.filter(TwinNode.type == type)
    return [n.to_dict() for n in q.all()]


@router.get("/stats")
def twin_stats(db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    return GraphStore(db).stats()


@router.post("/heartbeat")
def heartbeat(node_id: str, db: Session = Depends(get_db),
              user: User = Depends(get_current_user)):
    """Mark a node as online. Useful for demos where an analyst 'refreshes' a node."""
    node = db.query(TwinNode).filter(TwinNode.id == node_id).first()
    if not node:
        return {"ok": False, "error": "node not found"}
    node.status = "online"
    node.last_seen = datetime.now(timezone.utc)
    db.commit()
    return {"ok": True, "node": node.to_dict()}


@router.get("/neo4j/status")
def neo4j_status(_: User = Depends(get_current_user)):
    """Truthful Neo4j connectivity and status report."""
    from app.services.neo4j_client import neo4j_client
    return neo4j_client.check_health()


@router.post("/neo4j/verify")
def neo4j_verify(_: User = Depends(get_current_user)):
    """Execute synthetic graph creation, query validation, and safe cleanup in Neo4j."""
    from app.services.neo4j_client import neo4j_client
    return neo4j_client.run_synthetic_verification()
