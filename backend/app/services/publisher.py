"""Publisher for the CipherTwin telemetry topic exchange.

Publishes validated telemetry events to the `telemetry` topic exchange with
the appropriate routing key. Supports deduplication by event_id and graceful
degradation to an in-memory buffer when RabbitMQ is unavailable.
"""
import json
import logging
import time
import uuid
from collections import deque
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple

import pika

from app.core.config import settings
from app.schemas.telemetry_events import ROUTING_KEY_TO_MODEL, ALL_ROUTING_KEYS

logger = logging.getLogger("ciphertwin.publisher")


class Publisher:
    """Publishes telemetry events to the RabbitMQ topic exchange.

    Usage:
        pub = Publisher()
        ok, msg = pub.publish("telemetry.edr", event_dict)
    """

    def __init__(self):
        self._buffer: deque = deque(maxlen=10000)
        self._seen_ids: dict[str, float] = {}
        self._dedup_ttl: int = 300
        self.stats: dict[str, int] = {
            "published": 0,
            "deduplicated": 0,
            "rejected": 0,
            "buffered": 0,
        }

    # ---- dedup ----
    def _is_duplicate(self, event_id: str) -> bool:
        now = time.time()
        self._purge(now)
        if event_id in self._seen_ids:
            return True
        if len(self._seen_ids) >= 10000:
            oldest = next(iter(self._seen_ids))
            self._seen_ids.pop(oldest, None)
        self._seen_ids[event_id] = now
        return False

    def _purge(self, now: float) -> None:
        expired = [k for k, v in self._seen_ids.items() if now - v > self._dedup_ttl]
        for k in expired:
            self._seen_ids.pop(k, None)

    # ---- publish ----
    def publish(self, routing_key: str, payload: Dict[str, Any]) -> Tuple[bool, str]:
        """Validate and publish an event to the topic exchange.

        Returns (ok, message_id_or_error).
        """
        # Validate routing key
        if routing_key not in ALL_ROUTING_KEYS:
            self.stats["rejected"] += 1
            return False, f"Unknown routing key: {routing_key}"

        # Validate payload against the matching model
        model_cls = ROUTING_KEY_TO_MODEL.get(routing_key)
        if model_cls is None:
            self.stats["rejected"] += 1
            return False, f"No schema for routing key: {routing_key}"

        try:
            model_cls(**payload)
        except Exception as exc:
            self.stats["rejected"] += 1
            logger.warning("Schema validation failed for %s: %s", routing_key, exc)
            return False, f"Validation error: {exc}"

        event_id = payload.get("event_id") or str(uuid.uuid4())

        # Dedup
        if self._is_duplicate(event_id):
            self.stats["deduplicated"] += 1
            logger.info("Duplicate event dropped: %s", event_id)
            return True, "Duplicate dropped"

        # Try live RabbitMQ
        try:
            import pika
            credentials = pika.PlainCredentials(settings.rabbitmq_user, settings.rabbitmq_password)
            params = pika.ConnectionParameters(
                host=settings.rabbitmq_host,
                port=settings.rabbitmq_port,
                virtual_host=settings.rabbitmq_vhost,
                credentials=credentials,
                heartbeat=30,
                connection_attempts=1,
            )
            connection = pika.BlockingConnection(params)
            channel = connection.channel()
            channel.exchange_declare(
                exchange=settings.topic_exchange,
                exchange_type="topic",
                durable=True,
            )
            channel.basic_publish(
                exchange=settings.topic_exchange,
                routing_key=routing_key,
                body=json.dumps(payload, default=str),
                properties=pika.BasicProperties(
                    delivery_mode=2,
                    content_type="application/json",
                    message_id=event_id,
                    timestamp=int(time.time()),
                ),
            )
            connection.close()
            self.stats["published"] += 1
            return True, event_id
        except Exception as exc:
            logger.error("Publish to RabbitMQ failed: %s", exc)
            # Buffer for later retry — event is accepted even when broker is down
            self._buffer.append((routing_key, payload, event_id))
            self.stats["buffered"] += 1
            return True, event_id

    def flush_buffer(self) -> int:
        """Attempt to publish any buffered events. Returns count flushed."""
        flushed = 0
        while self._buffer:
            routing_key, payload, event_id = self._buffer.popleft()
            ok, _ = self.publish(routing_key, payload)
            if ok:
                flushed += 1
            else:
                # Put back at front to retry later
                self._buffer.appendleft((routing_key, payload, event_id))
                break
        return flushed

    def buffer_size(self) -> int:
        return len(self._buffer)


# Module-level singleton
publisher = Publisher()
