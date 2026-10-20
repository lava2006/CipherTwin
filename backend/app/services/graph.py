"""Digital Twin graph operations.

SQLite remains the authoritative application store. When the configured Neo4j
HTTP transactional client is reachable, graph mutations are projected to Neo4j.
Projection failures are logged; the Neo4j health endpoint reports service connectivity
separately and does not guarantee that every prior projection succeeded.
"""
import logging
from typing import Any, Dict, List, Optional
from sqlalchemy.orm import Session

from app.models.twin import TwinNode, TwinRelationship
from app.services.neo4j_client import neo4j_client

logger = logging.getLogger("ciphertwin.graph")


class GraphStore:
    """Enterprise graph store with Dual-Layer Neo4j + SQLite persistence."""

    def __init__(self, db: Session, neo4j: Optional[Any] = None):
        self.db = db
        self.neo4j = neo4j or neo4j_client

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
            label_map = {
                "user": "User", "laptop": "Device", "desktop": "Device",
                "tablet": "Device", "server": "Server", "database": "Database",
                "application": "Application", "network": "Network", "ip": "IP",
                "honeypot": "Decoy", "decoy": "Decoy", "threat": "Threat",
            }
            neo4j_client.upsert_node(
                node.id,
                label_map.get((node.type or "").lower(), "Asset"),
                {
                    "label": node.label,
                    "ip_address": node.ip_address,
                    "status": node.status,
                    "trust_score": node.trust_score,
                    "risk_score": node.risk_score,
                    "sensitivity": node.sensitivity,
                    "type": node.type,
                    "ciphertwin_managed": True,
                },
            )
        except Exception as exc:
            logger.warning("Neo4j node projection failed for %s: %s", node.id, exc)

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
        except Exception as exc:
            logger.warning("Neo4j relationship projection failed for %s -> %s: %s", source, target, exc)

        return rel

    def sync_all_to_neo4j(self) -> Dict[str, object]:
        """Project the complete SQLite Digital Twin into Neo4j.

        SQLite remains authoritative. This method is intentionally explicit and
        returns counts/errors so callers can distinguish a successful projection
        from merely having a configured Neo4j URL.
        """
        client = getattr(self, "neo4j", None) or neo4j_client
        health = client.check_health()
        if health.get("status") != "HEALTHY":
            return {"status": "UNAVAILABLE", "nodes_synced": 0, "relationships_synced": 0,
                    "errors": [health.get("message", "Neo4j unavailable")]}

        label_map = {
            "user": "User", "laptop": "Device", "desktop": "Device",
            "tablet": "Device", "server": "Server", "database": "Database",
            "application": "Application", "network": "Network", "ip": "IP",
            "honeypot": "Decoy", "decoy": "Decoy", "threat": "Threat",
        }
        node_count = 0
        rel_count = 0
        errors = []
        nodes = self.all_nodes()
        node_ids = {node.id for node in nodes}

        # Batch upsert all nodes in a single transactional HTTP request
        for node in nodes:
            clean_label = label_map.get((node.type or "").lower(), "Asset")
            props = {
                "label": node.label, "type": node.type,
                "ip_address": node.ip_address, "location": node.location,
                "department": node.department, "status": node.status,
                "trust_score": float(node.trust_score or 0),
                "risk_score": float(node.risk_score or 0),
                "sensitivity": node.sensitivity, "os": node.os, "tags": node.tags,
                "ciphertwin_managed": True,
            }
            if client.upsert_node(node.id, clean_label, props):
                node_count += 1
            else:
                errors.append(f"node_upsert_failed:{node.id}")

        rel_map = {
            "uses": "USES", "accesses": "ACCESSES", "hosts": "RUNS",
            "connects_to": "CONNECTS_TO", "trusts": "USES", "traps": "AFFECTS",
            "member_of": "MEMBER_OF", "targets": "TARGETS", "generates": "GENERATES",
        }
        for rel in self.all_relationships():
            if rel.source_id not in node_ids or rel.target_id not in node_ids:
                errors.append(f"relationship_missing_endpoint:{rel.source_id}->{rel.target_id}")
                continue
            rel_type = rel_map.get((rel.relation or "").lower(), "CONNECTS_TO")
            props = {"weight": float(rel.weight or 1.0), "description": rel.description or ""}
            if client.upsert_relationship(rel.source_id, rel.target_id, rel_type, props):
                rel_count += 1
            else:
                errors.append(f"relationship_upsert_failed:{rel.source_id}->{rel.target_id}")

        # Remove only stale nodes previously marked as managed by CipherTwin when syncing a populated dataset.
        # When syncing an empty/isolated test store, do not wipe live Neo4j topology.
        if node_ids:
            current_ids = sorted(node_ids)
            prune = client.execute_cypher(
                "MATCH (n) WHERE n.ciphertwin_managed = true "
                "AND NOT n.id IN $current_ids DETACH DELETE n RETURN count(n) AS deleted",
                {"current_ids": current_ids},
            )
            if prune.get("errors"):
                errors.append("stale_node_prune_failed")

        status = "SYNCED" if not errors and node_count == len(nodes) and rel_count == len(self.all_relationships()) else "PARTIAL"
        return {"status": status, "nodes_synced": node_count,
                "relationships_synced": rel_count, "errors": errors}

    def to_payload(self) -> Dict:
        """Serialize graph directly from Neo4j as exclusive authoritative source.

        Silent fallback to SQLite or fabricated data is strictly prohibited.
        """
        client = getattr(self, "neo4j", None) or neo4j_client
        health = client.check_health()
        if health.get("status") != "HEALTHY":
            raise RuntimeError(
                f"Neo4j graph database is unavailable ({health.get('message', 'offline')}). "
                "Silent fallback to SQLite is strictly disabled."
            )
        return client.get_graph()

    def stats(self) -> Dict:
        """Derive graph statistics directly from authoritative Neo4j database."""
        client = getattr(self, "neo4j", None) or neo4j_client
        health = client.check_health()
        if health.get("status") != "HEALTHY":
            raise RuntimeError(
                f"Neo4j graph database is unavailable ({health.get('message', 'offline')}). "
                "Silent fallback to SQLite is strictly disabled."
            )
        return client.get_stats()

    def recommend_decoys(self, limit: int = 5) -> List[Dict]:
        """Derive topological decoy placement recommendations directly from Neo4j."""
        client = getattr(self, "neo4j", None) or neo4j_client
        health = client.check_health()
        if health.get("status") != "HEALTHY":
            raise RuntimeError(
                f"Neo4j graph database is unavailable ({health.get('message', 'offline')}). "
                "Silent fallback to SQLite is strictly disabled."
            )
        return client.recommend_decoy_placements(limit=limit)

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

