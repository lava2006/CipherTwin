"""RabbitMQ Telemetry Pipeline for CipherTwin.

Implements an enterprise-grade message-driven pipeline:
Producer -> RabbitMQ Queue -> Consumer -> Pydantic Validation -> Risk Engine -> Database

Features:
- TelemetryMessage schema with Pydantic validation
- Message deduplication & replay protection
- Acknowledgement (ACK) on successful processing
- Rejection (NACK) with retry counter & exponential backoff
- Dead-Letter Queue (DLQ) for malformed or permanently failing messages
- Health check checking genuine RabbitMQ broker status
- Resilient fallback / in-process broker for offline and unit test verification
"""
import json
import logging
import time
import uuid
from collections import deque
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from pydantic import BaseModel, Field, ValidationError

import httpx
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.telemetry import TelemetryEvent
from app.models.twin import TwinNode
from app.services.audit import log_event
from app.services.deception import DeceptionEngine
from app.services.risk_engine import engine
from app.services.threat_intel import ThreatIntel

logger = logging.getLogger("ciphertwin.rabbitmq")


class TelemetryMessage(BaseModel):
    """Normalized message schema for telemetry transported over RabbitMQ."""
    message_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    event_type: str = Field(min_length=1, max_length=64)
    user_id: Optional[str] = Field(default=None, max_length=128)
    device_id: Optional[str] = Field(default=None, max_length=128)
    target_id: Optional[str] = Field(default=None, max_length=128)
    location: Optional[str] = Field(default=None, max_length=256)
    ip_address: Optional[str] = Field(default=None, max_length=64)
    status: str = Field(default="success", max_length=32)
    risk_indicators: List[str] = Field(default_factory=list)
    raw_payload: Dict[str, Any] = Field(default_factory=dict)
    retry_count: int = Field(default=0)


class InMemoryBroker:
    """In-memory broker that precisely mimics RabbitMQ queue, DLQ, and ACK semantics."""
    def __init__(self):
        self.queues: Dict[str, deque] = {
            settings.rabbitmq_queue: deque(),
            settings.rabbitmq_dlq: deque(),
        }
        self.unacked: Dict[str, Tuple[str, TelemetryMessage]] = {}

    def publish(self, queue_name: str, message: TelemetryMessage) -> bool:
        if queue_name not in self.queues:
            self.queues[queue_name] = deque()
        self.queues[queue_name].append(message)
        return True

    def get(self, queue_name: str) -> Optional[Tuple[str, TelemetryMessage]]:
        if queue_name not in self.queues or not self.queues[queue_name]:
            return None
        msg = self.queues[queue_name].popleft()
        delivery_tag = str(uuid.uuid4())
        self.unacked[delivery_tag] = (queue_name, msg)
        return delivery_tag, msg

    def ack(self, delivery_tag: str) -> bool:
        return self.unacked.pop(delivery_tag, None) is not None

    def nack(self, delivery_tag: str, requeue: bool = True) -> Optional[TelemetryMessage]:
        item = self.unacked.pop(delivery_tag, None)
        if not item:
            return None
        queue_name, msg = item
        if requeue:
            self.queues[queue_name].appendleft(msg)
        return msg

    def size(self, queue_name: str) -> int:
        return len(self.queues.get(queue_name, []))

    def clear(self):
        for q in self.queues.values():
            q.clear()
        self.unacked.clear()


class DeduplicationFilter:
    """LRU deduplication filter preventing duplicate events within a time window."""
    def __init__(self, max_size: int = 10000, ttl_seconds: int = 300):
        self.seen: Dict[str, float] = {}
        self.max_size = max_size
        self.ttl = ttl_seconds

    def is_duplicate(self, message_id: str) -> bool:
        now = time.time()
        self._purge(now)
        if message_id in self.seen:
            return True
        if len(self.seen) >= self.max_size:
            oldest = next(iter(self.seen))
            self.seen.pop(oldest, None)
        self.seen[message_id] = now
        return False

    def forget(self, message_id: str) -> None:
        """Allow a caller to retry an event that failed before being accepted."""
        self.seen.pop(message_id, None)

    def _purge(self, now: float):
        expired = [k for k, v in self.seen.items() if now - v > self.ttl]
        for k in expired:
            self.seen.pop(k, None)


class RabbitMQPipeline:
    """Enterprise RabbitMQ telemetry pipeline coordinator."""

    def __init__(self):
        self.broker = InMemoryBroker()
        self.dedup = DeduplicationFilter()
        self.max_retries = 3
        self.stats = {
            "published": 0,
            "consumed": 0,
            "validated": 0,
            "acknowledged": 0,
            "rejected": 0,
            "dlq_routed": 0,
            "duplicates_dropped": 0,
            "retries": 0,
        }

    def _open_amqp(self):
        """Open an authenticated AMQP connection when live RabbitMQ is enabled."""
        try:
            import pika
        except ImportError as exc:
            raise RuntimeError(
                "RABBITMQ_ENABLED=true but the optional 'pika' package is not installed"
            ) from exc
        credentials = pika.PlainCredentials(settings.rabbitmq_user, settings.rabbitmq_password)
        params = pika.ConnectionParameters(
            host=settings.rabbitmq_host,
            port=settings.rabbitmq_port,
            virtual_host=settings.rabbitmq_vhost,
            credentials=credentials,
            heartbeat=30,
            blocked_connection_timeout=5,
            socket_timeout=5,
            connection_attempts=1,
        )
        connection = pika.BlockingConnection(params)
        channel = connection.channel()
        channel.queue_declare(queue=settings.rabbitmq_queue, durable=True)
        channel.queue_declare(queue=settings.rabbitmq_dlq, durable=True)
        channel.confirm_delivery()
        return connection, channel

    def _publish_live(self, queue_name: str, msg: TelemetryMessage) -> None:
        """Publish a persistent JSON message to the real RabbitMQ durable queue."""
        import pika
        connection, channel = self._open_amqp()
        try:
            confirmed = channel.basic_publish(
                exchange="",
                routing_key=queue_name,
                body=msg.model_dump_json(),
                properties=pika.BasicProperties(
                    delivery_mode=2,
                    content_type="application/json",
                    message_id=msg.message_id,
                    headers={"retry_count": msg.retry_count},
                ),
                mandatory=True,
            )
            if confirmed is False:
                raise RuntimeError("RabbitMQ did not confirm telemetry publication")
        finally:
            if connection.is_open:
                connection.close()

    def check_health(self, force_refresh: bool = False) -> Dict[str, Any]:
        """Report the transport actually used by this process, with 3s caching to prevent lag."""
        now = time.time()
        if not force_refresh and getattr(self, "_health_cache", None) is not None and (now - getattr(self, "_health_cache_time", 0.0)) < 3.0:
            return self._health_cache

        if not settings.rabbitmq_enabled:
            res = {
                "status": "DEGRADED",
                "mode": "IN_MEMORY_TEST_MODE",
                "message": "RabbitMQ transport is disabled; this process uses the in-memory test broker.",
                "queue_depth": self.broker.size(settings.rabbitmq_queue),
                "dlq_depth": self.broker.size(settings.rabbitmq_dlq),
            }
            self._health_cache = res
            self._health_cache_time = now
            return res

        base_url = f"http://{settings.rabbitmq_host}:{settings.rabbitmq_mgmt_port}/api"
        res: Dict[str, Any]
        try:
            resp = httpx.get(
                f"{base_url}/health/checks/alarms",
                auth=(settings.rabbitmq_user, settings.rabbitmq_password),
                timeout=2.0,
            )
            if resp.status_code == 200:
                if settings.rabbitmq_enabled:
                    try:
                        probe_connection, _probe_channel = self._open_amqp()
                        probe_connection.close()
                    except Exception as exc:
                        res = {
                            "status": "DEGRADED",
                            "mode": "LIVE_BROKER_AMQP_UNAVAILABLE",
                            "host": settings.rabbitmq_host,
                            "port": settings.rabbitmq_port,
                            "message": f"Management API is reachable but AMQP connection failed: {type(exc).__name__}: {exc}",
                        }
                        self._health_cache = res
                        self._health_cache_time = now
                        return res
                # Queue depths must come from RabbitMQ in live mode, never from the local test broker.
                queue_depth = None
                dlq_depth = None
                queue_resp = httpx.get(
                    f"{base_url}/queues/%2F/{settings.rabbitmq_queue}",
                    auth=(settings.rabbitmq_user, settings.rabbitmq_password),
                    timeout=2.0,
                )
                if queue_resp.status_code == 200:
                    queue_depth = queue_resp.json().get("messages")
                dlq_resp = httpx.get(
                    f"{base_url}/queues/%2F/{settings.rabbitmq_dlq}",
                    auth=(settings.rabbitmq_user, settings.rabbitmq_password),
                    timeout=2.0,
                )
                if dlq_resp.status_code == 200:
                    dlq_depth = dlq_resp.json().get("messages")
                res = {
                    "status": "HEALTHY",
                    "mode": "LIVE_BROKER",
                    "host": settings.rabbitmq_host,
                    "port": settings.rabbitmq_port,
                    "queue": settings.rabbitmq_queue,
                    "queue_depth": queue_depth,
                    "dlq_depth": dlq_depth,
                    "queue_depth_source": "RabbitMQ management API",
                }
            else:
                res = {
                    "status": "DEGRADED",
                    "mode": "LIVE_BROKER_DEGRADED",
                    "message": f"RabbitMQ responded with status {resp.status_code}",
                }
        except Exception:
            res = {
                "status": "UNAVAILABLE",
                "mode": "LIVE_BROKER_UNAVAILABLE",
                "host": settings.rabbitmq_host,
                "port": settings.rabbitmq_port,
                "message": "RabbitMQ broker is unreachable. Silent fallback to memory broker is disabled.",
            }
        self._health_cache = res
        self._health_cache_time = now
        return res

    # ---- Producer ----
    def publish(self, payload: Dict[str, Any], queue_name: Optional[str] = None) -> Tuple[bool, str]:
        """Validate and publish a telemetry message to the queue."""
        queue_name = queue_name or settings.rabbitmq_queue
        try:
            msg = TelemetryMessage(**payload)
        except ValidationError as e:
            self.stats["rejected"] += 1
            logger.warning("Telemetry rejected by schema validation: %s", e)
            return False, f"Validation error: {e}"

        # Duplicate check at producer level if message_id provided
        if self.dedup.is_duplicate(msg.message_id):
            self.stats["duplicates_dropped"] += 1
            logger.info("Duplicate telemetry message %s dropped", msg.message_id)
            return True, "Duplicate dropped"

        try:
            if settings.rabbitmq_enabled:
                self._publish_live(queue_name, msg)
            else:
                self.broker.publish(queue_name, msg)
        except Exception as exc:
            self.dedup.forget(msg.message_id)
            logger.error("Telemetry publish failed (live=%s): %s", settings.rabbitmq_enabled, exc)
            # Do not silently switch to an in-memory queue when live RabbitMQ was requested.
            return False, f"Publish failed: {type(exc).__name__}: {exc}"
        self.stats["published"] += 1
        return True, msg.message_id

    # ---- Consumer & Processor ----
    def process_one(self, db: Session, queue_name: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Consume one message, validate, process through Risk Engine, and persist."""
        queue_name = queue_name or settings.rabbitmq_queue
        live_connection = None
        live_channel = None
        if settings.rabbitmq_enabled:
            try:
                live_connection, live_channel = self._open_amqp()
                method, properties, body = live_channel.basic_get(queue=queue_name, auto_ack=False)
                if method is None:
                    live_connection.close()
                    return None
                tag = method.delivery_tag
                try:
                    msg = TelemetryMessage.model_validate_json(body)
                except Exception as exc:
                    # Invalid messages are preserved in the DLQ, then acknowledged from the source queue.
                    live_channel.basic_publish(
                        exchange="", routing_key=settings.rabbitmq_dlq, body=body,
                        properties=properties, mandatory=True,
                    )
                    live_channel.basic_ack(delivery_tag=tag)
                    self.stats["dlq_routed"] += 1
                    logger.error("Invalid RabbitMQ telemetry moved to DLQ: %s", exc)
                    live_connection.close()
                    return {"acknowledged": True, "dlq_routed": True, "error": "invalid_message"}
            except Exception as exc:
                if live_connection and live_connection.is_open:
                    live_connection.close()
                logger.error("RabbitMQ consume failed: %s", exc)
                return None
        else:
            delivery = self.broker.get(queue_name)
            if not delivery:
                return None
            tag, msg = delivery
        self.stats["consumed"] += 1

        try:
            # Validate model
            if not isinstance(msg, TelemetryMessage):
                msg = TelemetryMessage(**dict(msg))
            self.stats["validated"] += 1

            # Convert to DB TelemetryEvent
            event = TelemetryEvent(
                user_id=msg.user_id,
                device_id=msg.device_id,
                target_id=msg.target_id,
                event_type=msg.event_type,
                location=msg.location,
                ip_address=msg.ip_address,
                status=msg.status,
                risk_indicators=json.dumps(msg.risk_indicators),
                raw=json.dumps(msg.raw_payload or {"message_id": msg.message_id}),
            )
            db.add(event)
            db.flush()

            # Zero Trust Risk Engine evaluation
            result = engine.evaluate(event, db)
            decision = engine.persist(event, result, db)

            # Adaptive Deception on risky events
            if result.risk_score >= settings.deception_risk_threshold:
                intel = ThreatIntel(db)
                threat = intel.correlate(event, result.risk_score, result.decision)
                if threat:
                    node = None
                    if event.target_id:
                        node = db.query(TwinNode).filter(TwinNode.id == event.target_id).first()
                    if not node and event.device_id:
                        node = db.query(TwinNode).filter(TwinNode.id == event.device_id).first()
                    device_trust = node.trust_score if node else None
                    sensitivity = node.sensitivity if node else None

                    deception = DeceptionEngine(db)
                    session = deception.open_decoy(
                        actor=event.user_id or "unknown",
                        source_ip=event.ip_address or "0.0.0.0",
                        threat_id=threat.id,
                        risk_score=result.risk_score,
                        mitre_technique=event.mitre_technique,
                        event_type=event.event_type,
                        device_trust=device_trust,
                        sensitivity=sensitivity,
                    )
                    deception.simulate_activity(session)
                    log_event(
                        db,
                        action="decoy_activated",
                        actor=event.user_id,
                        target=session.decoy_type,
                        details=f"Threat={threat.actor_name}; risk={result.risk_score}; persona={session.persona}; fidelity={session.fidelity}",
                        severity="warning",
                        ip_address=event.ip_address,
                    )

            db.commit()
            if settings.rabbitmq_enabled:
                live_channel.basic_ack(delivery_tag=tag)
                if live_connection and live_connection.is_open:
                    live_connection.close()
            else:
                self.broker.ack(tag)
            self.stats["acknowledged"] += 1

            return {
                "message_id": msg.message_id,
                "event_id": event.id,
                "risk_score": result.risk_score,
                "decision": result.decision,
                "acknowledged": True,
            }

        except Exception as e:
            db.rollback()
            logger.error("Processing failed for message %s: %s", msg.message_id, e)
            msg.retry_count += 1
            self.stats["retries"] += 1

            if settings.rabbitmq_enabled:
                try:
                    # Republish the incremented retry count before ACKing the original delivery.
                    # This avoids an infinite retry loop with a stale message body.
                    target_queue = settings.rabbitmq_dlq if msg.retry_count > self.max_retries else queue_name
                    self._publish_live(target_queue, msg)
                    live_channel.basic_ack(delivery_tag=tag)
                    if target_queue == settings.rabbitmq_dlq:
                        self.stats["dlq_routed"] += 1
                        logger.error("Message %s exceeded max retries (%d); routed to DLQ",
                                     msg.message_id, self.max_retries)
                except Exception:
                    # Preserve the original delivery if retry/DLQ publication fails.
                    try:
                        live_channel.basic_nack(delivery_tag=tag, requeue=True)
                    except Exception:
                        pass
                finally:
                    if live_connection and live_connection.is_open:
                        live_connection.close()
            elif msg.retry_count > self.max_retries:
                self.broker.ack(tag)
                self.broker.publish(settings.rabbitmq_dlq, msg)
                self.stats["dlq_routed"] += 1
                logger.error("Message %s exceeded max retries (%d); routed to DLQ", msg.message_id, self.max_retries)
            else:
                self.broker.nack(tag, requeue=True)
            return None


# Global singleton instance
rabbitmq_pipeline = RabbitMQPipeline()
