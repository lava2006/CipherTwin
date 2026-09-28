"""Digital Twin graph operations.

In a production deployment this layer would speak to Neo4j via a Cypher driver.
For the MVP the same interface is implemented against SQLite so the demo is
fully self-contained and runs anywhere. Swapping in a real Neo4j backend is a
matter of replacing ``GraphStore`` with a Neo4j implementation that exposes
the same async methods.
"""
from typing import Dict, List, Optional

from sqlalchemy.orm import Session

from app.models.twin import TwinNode, TwinRelationship


class GraphStore:
    """Lightweight wrapper around the twin node/relationship tables."""

    def __init__(self, db: Session):
        self.db = db

    # ---- node helpers ----
    def add_node(self, node: TwinNode) -> TwinNode:
        existing = self.db.query(TwinNode).filter(TwinNode.id == node.id).first()
        if existing:
            for attr, value in node.__dict__.items():
                if attr.startswith("_") or attr == "id":
                    continue
                setattr(existing, attr, value)
            node = existing
        else:
            self.db.add(node)
        self.db.flush()
        return node

    def get_node(self, node_id: str) -> Optional[TwinNode]:
        return self.db.query(TwinNode).filter(TwinNode.id == node_id).first()

    def all_nodes(self) -> List[TwinNode]:
        return self.db.query(TwinNode).all()

    def all_relationships(self) -> List[TwinRelationship]:
        return self.db.query(TwinRelationship).all()

    def add_relationship(self, source: str, target: str, relation: str, weight: float = 1.0, description: str = ""):
        rel = TwinRelationship(
            source_id=source, target_id=target, relation=relation, weight=weight, description=description
        )
        self.db.add(rel)
        self.db.flush()
        return rel

    def to_payload(self) -> Dict:
        """Serialize graph in the form expected by the frontend vis renderer."""
        nodes = [n.to_dict() for n in self.all_nodes()]
        edges = [
            {
                "source": r.source_id,
                "target": r.target_id,
                "relation": r.relation,
                "weight": r.weight,
            }
            for r in self.all_relationships()
        ]
        return {"nodes": nodes, "edges": edges}

    def stats(self) -> Dict:
        nodes = self.all_nodes()
        rels = self.all_relationships()
        online = sum(1 for n in nodes if n.status == "online")
        offline = sum(1 for n in nodes if n.status == "offline")
        compromised = sum(1 for n in nodes if n.status == "compromised")
        return {
            "total_nodes": len(nodes),
            "total_relationships": len(rels),
            "online": online,
            "offline": offline,
            "compromised": compromised,
        }
