"""Twin Events Consumer for CipherTwin.

Consumes telemetry events from the RabbitMQ `twin.events` queue
(published by the Ingest API, Remote VM Agent, and Cowrie Bridge),
processes them through the Zero Trust Risk Engine, persists to SQLite,
and writes live Graph nodes and relationships to Neo4j.
"""
from __future__ import annotations

import json
import logging
import threading
import time
from datetime import datetime, timezone
from typing import Any, Dict, Optional

import pika
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.session import SessionLocal
from app.models.deception import DecoySession
from app.models.telemetry import TelemetryEvent
from app.services.audit import log_event
from app.services.neo4j_client import neo4j_client
from app.services.rabbitmq_topology import get_connection_params, get_topology
from app.services.risk_engine import engine
from app.services.threat_intel import ThreatIntel

logger = logging.getLogger("ciphertwin.twin_consumer")


def _infer_fidelity(eventid: str, command: Optional[str] = None) -> str:
    """Infer deception fidelity from Cowrie event."""
    if command:
        cmd_lower = command.lower()
        if any(h in cmd_lower for h in ["wget", "curl", "chmod", "sudo", "bash", "sh", "python", "perl"]):
            return "HIGH"
        return "HIGH"
    if "login" in eventid or "command" in eventid:
        return "MEDIUM"
    return "LOW"


class TwinEventsConsumer:
    """Consumes from RabbitMQ queue `twin.events` in a background daemon thread."""

    def __init__(self):
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self.stats = {
            "consumed": 0,
            "cowrie_events": 0,
            "iam_events": 0,
            "edr_events": 0,
            "netflow_events": 0,
            "errors": 0,
        }

    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive() and not self._stop_event.is_set()

    def start(self) -> None:
        if self.is_running():
            logger.info("TwinEventsConsumer already running.")
            return

        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run_consumer,
            name="ciphertwin-twin-events-consumer",
            daemon=True,
        )
        self._thread.start()
        logger.info("TwinEventsConsumer thread started.")

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=3.0)
        logger.info("TwinEventsConsumer thread stopped.")

    def _run_consumer(self) -> None:
        """Continuous consumer loop with reconnect backoff."""
        while not self._stop_event.is_set():
            if not settings.rabbitmq_enabled:
                time.sleep(2.0)
                continue

            connection = None
            try:
                params = get_connection_params()
                connection = pika.BlockingConnection(params)
                channel = connection.channel()

                # Declare topology on dedicated consumer channel
                channel.exchange_declare(
                    exchange=settings.topic_exchange,
                    exchange_type="topic",
                    durable=True,
                )
                channel.exchange_declare(
                    exchange=settings.dlx_exchange,
                    exchange_type="fanout",
                    durable=True,
                )
                channel.queue_declare(
                    queue=settings.twin_events_queue,
                    durable=True,
                    arguments={
                        "x-dead-letter-exchange": settings.dlx_exchange,
                        "x-message-ttl": 86400000,
                    },
                )
                for rk in [
                    settings.routing_key_edr,
                    settings.routing_key_iam,
                    settings.routing_key_netflow,
                    settings.routing_key_cowrie,
                ]:
                    channel.queue_bind(
                        exchange=settings.topic_exchange,
                        queue=settings.twin_events_queue,
                        routing_key=rk,
                    )

                channel.basic_qos(prefetch_count=10)
                logger.info("TwinEventsConsumer connected to RabbitMQ; consuming '%s'", settings.twin_events_queue)

                while not self._stop_event.is_set():
                    method, properties, body = channel.basic_get(queue=settings.twin_events_queue, auto_ack=False)
                    if method is None:
                        # Queue empty; brief pause
                        time.sleep(0.5)
                        continue

                    rk = method.routing_key or (properties.headers.get("routing_key") if properties.headers else "") or ""
                    try:
                        payload = json.loads(body.decode("utf-8", errors="replace"))
                        self._process_message(rk, payload)
                        channel.basic_ack(delivery_tag=method.delivery_tag)
                        self.stats["consumed"] += 1
                    except Exception as exc:
                        logger.error("Failed processing message from twin.events: %s", exc)
                        self.stats["errors"] += 1
                        channel.basic_ack(delivery_tag=method.delivery_tag)

            except Exception as exc:
                if not self._stop_event.is_set():
                    logger.warning("RabbitMQ consumer error: %s (reconnecting in 3s)", exc)
                    time.sleep(3.0)
            finally:
                if connection and connection.is_open:
                    try:
                        connection.close()
                    except Exception:
                        pass

    def _process_message(self, routing_key: str, payload: Dict[str, Any]) -> None:
        """Dispatch event by type, update Neo4j, SQLite, and Risk Engine."""
        db: Session = SessionLocal()
        try:
            now_iso = datetime.now(timezone.utc).isoformat()

            # 1. COWRIE EVENT (Honeypot attack)
            if "cowrie" in routing_key or "session" in payload and "src_ip" in payload and "eventid" in payload:
                self.stats["cowrie_events"] += 1
                src_ip = payload.get("src_ip", "0.0.0.0")
                session_id = payload.get("session", f"cowrie-{int(time.time())}")
                eventid = payload.get("eventid", "cowrie.session.connect")
                username = payload.get("username")
                cmd = payload.get("command")
                fidelity = _infer_fidelity(eventid, cmd)

                # A. Update Neo4j graph: Attacker -> Decoy interaction
                if settings.neo4j_enabled:
                    try:
                        neo4j_client.merge_attacker_decoy_interaction(
                            attacker_ip=src_ip,
                            decoy_id="decoy-cowrie-ssh",
                            session_id=session_id,
                        )
                    except Exception as neo_err:
                        logger.warning("Neo4j merge attacker failed: %s", neo_err)

                # B. Record in SQLite DecoySession
                existing_session = db.query(DecoySession).filter(DecoySession.notes.like(f"%{session_id}%")).first()
                if not existing_session:
                    new_session = DecoySession(
                        decoy_type="ssh",
                        fidelity=fidelity,
                        reason="Observed Cowrie honeypot interaction",
                        mode="COWRIE",
                        actor=username or f"attacker_{src_ip.replace('.', '_')}",
                        source_ip=src_ip,
                        activity=json.dumps([payload]),
                        commands=json.dumps([cmd] if cmd else []),
                        pages=json.dumps([]),
                        credentials_used=username,
                        notes=f"Cowrie session ID: {session_id}",
                    )
                    db.add(new_session)
                else:
                    if cmd:
                        cmds = json.loads(existing_session.commands or "[]")
                        if cmd not in cmds:
                            cmds.append(cmd)
                            existing_session.commands = json.dumps(cmds)
                    if fidelity == "HIGH":
                        existing_session.fidelity = "HIGH"

                # C. TelemetryEvent & Risk Engine
                event = TelemetryEvent(
                    user_id=username or f"attacker_{src_ip.replace('.', '_')}",
                    device_id=f"device-{src_ip.replace('.', '_')}",
                    target_id="decoy-cowrie-ssh",
                    event_type=f"honeypot_{eventid.replace('cowrie.', '')}",
                    location="External",
                    ip_address=src_ip,
                    status="detected",
                    risk_indicators=json.dumps(["honeypot_interaction", eventid] + ([cmd] if cmd else [])),
                    raw=json.dumps(payload),
                )
                db.add(event)
                db.flush()

                res = engine.evaluate(event, db)
                engine.persist(event, res, db)

                # Correlate Threat dynamically
                try:
                    ThreatIntel(db).correlate(event, res.risk_score, res.decision)
                except Exception as ti_err:
                    logger.warning("Threat correlation failed: %s", ti_err)

                db.commit()

            # 2. IAM EVENT (Remote VM SSH / Auth)
            elif "iam" in routing_key or payload.get("event_type", "").startswith("ssh_"):
                self.stats["iam_events"] += 1
                device_id = payload.get("device_id") or "remote-vm"
                username = payload.get("username") or "user"
                src_ip = payload.get("src_ip") or "127.0.0.1"
                ev_type = payload.get("event_type", "ssh_event")
                success = bool(payload.get("success", False))

                # A. Update Neo4j graph: Device & User nodes
                if settings.neo4j_enabled:
                    try:
                        neo4j_client.upsert_node(
                            node_id=device_id,
                            label="Device",
                            properties={"id": device_id, "type": "device", "ip": src_ip, "last_seen": now_iso},
                        )
                        if username:
                            neo4j_client.upsert_node(
                                node_id=username,
                                label="User",
                                properties={"id": username, "username": username, "last_seen": now_iso},
                            )
                            neo4j_client.upsert_relationship(username, device_id, rel_type="USES")
                    except Exception as neo_err:
                        logger.warning("Neo4j upsert IAM node failed: %s", neo_err)

                # B. SQLite TelemetryEvent & Risk Engine
                event = TelemetryEvent(
                    user_id=username,
                    device_id=device_id,
                    target_id="server-gateway-01",
                    event_type=ev_type,
                    location="Remote VM",
                    ip_address=src_ip,
                    status="success" if success else "failed",
                    risk_indicators=json.dumps([] if success else ["failed_authentication"]),
                    raw=json.dumps(payload),
                )
                db.add(event)
                db.flush()

                res = engine.evaluate(event, db)
                engine.persist(event, res, db)

                # Correlate Threat dynamically
                try:
                    ThreatIntel(db).correlate(event, res.risk_score, res.decision)
                except Exception as ti_err:
                    logger.warning("Threat correlation failed: %s", ti_err)

                db.commit()

            # 3. EDR EVENT (Remote VM Process Execution)
            elif "edr" in routing_key or "process_name" in payload or "command_line" in payload:
                self.stats["edr_events"] += 1
                device_id = payload.get("device_id") or "remote-vm"
                user = payload.get("user") or "unknown"
                proc = payload.get("process_name") or "process"
                cmd = payload.get("command_line") or ""
                indicators = payload.get("risk_indicators") or []

                if settings.neo4j_enabled:
                    try:
                        neo4j_client.upsert_node(
                            node_id=device_id,
                            label="Device",
                            properties={"id": device_id, "type": "device", "last_seen": now_iso},
                        )
                    except Exception as neo_err:
                        logger.warning("Neo4j upsert EDR node failed: %s", neo_err)

                event = TelemetryEvent(
                    user_id=user,
                    device_id=device_id,
                    target_id=device_id,
                    event_type=payload.get("event_type", "process_start"),
                    location="Remote VM",
                    ip_address="127.0.0.1",
                    status="success",
                    risk_indicators=json.dumps(indicators),
                    raw=json.dumps(payload),
                )
                db.add(event)
                db.flush()

                res = engine.evaluate(event, db)
                engine.persist(event, res, db)

                # Correlate Threat dynamically
                try:
                    ThreatIntel(db).correlate(event, res.risk_score, res.decision)
                except Exception as ti_err:
                    logger.warning("Threat correlation failed: %s", ti_err)

                db.commit()

            # 4. NETFLOW EVENT
            elif "netflow" in routing_key or "dst_ip" in payload:
                self.stats["netflow_events"] += 1
                device_id = payload.get("device_id") or "remote-vm"
                src_ip = payload.get("src_ip", "0.0.0.0")
                dst_ip = payload.get("dst_ip", "0.0.0.0")

                event = TelemetryEvent(
                    user_id="netflow_monitor",
                    device_id=device_id,
                    target_id=dst_ip,
                    event_type="network_flow",
                    location="Network",
                    ip_address=src_ip,
                    status="success",
                    risk_indicators=json.dumps([]),
                    raw=json.dumps(payload),
                )
                db.add(event)
                db.flush()

                res = engine.evaluate(event, db)
                engine.persist(event, res, db)

                # Correlate Threat dynamically
                try:
                    ThreatIntel(db).correlate(event, res.risk_score, res.decision)
                except Exception as ti_err:
                    logger.warning("Threat correlation failed: %s", ti_err)

                db.commit()

        except Exception as exc:
            db.rollback()
            logger.error("Error processing telemetry event: %s", exc)
            raise
        finally:
            db.close()


# Module-level singleton instance
twin_consumer = TwinEventsConsumer()
