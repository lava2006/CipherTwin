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
from app.services.neo4j_client import neo4j_client


class GraphStore:
    """Enterprise graph store with Dual-Layer Neo4j + SQLite persistence."""

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

        # Opportunistic sync to Neo4j if available
        try:
            neo4j_client.upsert_node(
                node.id,
                node.type or "Asset",
                {
                    "label": node.label,
                    "ip_address": node.ip_address,
                    "status": node.status,
                    "trust_score": node.trust_score,
                    "risk_score": node.risk_score,
                    "sensitivity": node.sensitivity,
                },
            )
        except Exception:
            pass

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

        # Opportunistic sync to Neo4j
        try:
            neo4j_client.upsert_relationship(
                source, target, relation, {"weight": weight, "description": description}
            )
        except Exception:
            pass

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

    def build_digital_twin(self) -> Dict:
        """Alias for to_payload providing complete topology."""
        return self.to_payload()

    def calculate_blast_radius(self, node_id: str, max_depth: int = 2) -> Dict:
        """Calculate blast radius and affected downstream assets from a compromised node."""
        all_rels = self.all_relationships()
        adj: Dict[str, List[str]] = {}
        for r in all_rels:
            adj.setdefault(r.source_id, []).append(r.target_id)
            adj.setdefault(r.target_id, []).append(r.source_id)

        visited = {node_id}
        queue = [(node_id, 0)]
        while queue:
            curr, depth = queue.pop(0)
            if depth >= max_depth:
                continue
            for neighbor in adj.get(curr, []):
                if neighbor not in visited:
                    visited.add(neighbor)
                    queue.append((neighbor, depth + 1))

        affected = visited - {node_id}
        score = min(100, len(affected) * 20)
        return {
            "target_node": node_id,
            "affected_nodes_count": len(affected),
            "affected_nodes": list(affected),
            "blast_radius_score": score,
        }

    def get_shortest_path(self, source_id: str, target_id: str) -> Dict:
        """Compute shortest path between two assets using Breadth-First Search."""
        if source_id == target_id:
            return {"source": source_id, "target": target_id, "connected": True, "path": [source_id], "hops": 0}

        all_rels = self.all_relationships()
        adj: Dict[str, List[str]] = {}
        for r in all_rels:
            adj.setdefault(r.source_id, []).append(r.target_id)
            adj.setdefault(r.target_id, []).append(r.source_id)

        queue = [[source_id]]
        visited = {source_id}

        while queue:
            path = queue.pop(0)
            curr = path[-1]
            if curr == target_id:
                return {
                    "source": source_id,
                    "target": target_id,
                    "connected": True,
                    "path": path,
                    "hops": len(path) - 1,
                }
            for neighbor in adj.get(curr, []):
                if neighbor not in visited:
                    visited.add(neighbor)
                    queue.append(path + [neighbor])

        return {
            "source": source_id,
            "target": target_id,
            "connected": False,
            "path": [],
            "hops": -1,
        }

    def find_chokepoints(self) -> List[Dict]:
        """Identify critical bridge assets and chokepoints based on connectivity degree."""
        all_rels = self.all_relationships()
        degree: Dict[str, int] = {}
        for r in all_rels:
            degree[r.source_id] = degree.get(r.source_id, 0) + 1
            degree[r.target_id] = degree.get(r.target_id, 0) + 1

        chokepoints = []
        for node_id, count in sorted(degree.items(), key=lambda x: x[1], reverse=True)[:5]:
            node = self.get_node(node_id)
            chokepoints.append({
                "node_id": node_id,
                "label": node.label if node else node_id,
                "degree": count,
                "criticality": "HIGH" if count >= 4 else "MEDIUM",
            })
        return chokepoints

