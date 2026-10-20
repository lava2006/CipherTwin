"""RabbitMQ topic exchange topology for multi-source telemetry.

Declares the exchange, DLX, queues, and bindings required by the CipherTwin
pipeline:

  Exchange: telemetry (topic)
  DLX:      telemetry.dlx (fanout)
  Queue:    twin.events   (bound to telemetry.edr, .iam, .netflow, .cowrie)
  Queue:    telemetry.dlq (dead-letter for malformed/expired messages)

All declarations are idempotent — safe to call on every startup.
"""
import logging
import threading
from typing import List

import pika

from app.core.config import settings

logger = logging.getLogger("ciphertwin.rabbitmq_topology")


def get_connection_params() -> pika.ConnectionParameters:
    """Build authenticated AMQP connection parameters from settings."""
    credentials = pika.PlainCredentials(settings.rabbitmq_user, settings.rabbitmq_password)
    return pika.ConnectionParameters(
        host=settings.rabbitmq_host,
        port=settings.rabbitmq_port,
        virtual_host=settings.rabbitmq_vhost,
        credentials=credentials,
        heartbeat=30,
        blocked_connection_timeout=5,
        connection_attempts=3,
        retry_delay=2,
    )


class RabbitMQTopology:
    """Declares and manages the topic exchange topology."""

    def __init__(self):
        self._lock = threading.Lock()
        self.connection: pika.BlockingConnection | None = None
        self.channel: pika.channel.Channel | None = None

    def connect(self) -> None:
        try:
            self.connection = pika.BlockingConnection(get_connection_params())
            self.channel = self.connection.channel()
        except Exception as exc:
            logger.warning("RabbitMQTopology connect failed: %s", exc)
            self.connection = None
            self.channel = None

    def close(self) -> None:
        with self._lock:
            try:
                if self.channel and self.channel.is_open:
                    self.channel.close()
            except Exception:
                pass
            try:
                if self.connection and self.connection.is_open:
                    self.connection.close()
            except Exception:
                pass
            self.channel = None
            self.connection = None

    def declare(self) -> None:
        """Declare exchanges, queues, and bindings (idempotent)."""
        with self._lock:
            if not self.channel or self.channel.is_closed or not self.connection or self.connection.is_closed:
                self.connect()

            if not self.channel:
                return

            ch = self.channel

        # 1. Topic exchange for multi-source telemetry
        ch.exchange_declare(
            exchange=settings.topic_exchange,
            exchange_type="topic",
            durable=True,
        )
        logger.info("Declared topic exchange: %s", settings.topic_exchange)

        # 2. Dead-letter exchange (fanout) for malformed / expired messages
        ch.exchange_declare(
            exchange=settings.dlx_exchange,
            exchange_type="fanout",
            durable=True,
        )
        logger.info("Declared DLX exchange: %s", settings.dlx_exchange)

        # 3. twin.events queue — bound to all telemetry routing keys
        ch.queue_declare(
            queue=settings.twin_events_queue,
            durable=True,
            arguments={
                "x-dead-letter-exchange": settings.dlx_exchange,
                "x-message-ttl": 86400000,  # 24 hours
            },
        )
        logger.info("Declared queue: %s", settings.twin_events_queue)

        # 4. telemetry.dlq queue
        ch.queue_declare(
            queue=settings.rabbitmq_dlq,
            durable=True,
        )
        logger.info("Declared queue: %s", settings.rabbitmq_dlq)

        # 5. Bind twin.events to the topic exchange with each routing key
        for rk in [
            settings.routing_key_edr,
            settings.routing_key_iam,
            settings.routing_key_netflow,
            settings.routing_key_cowrie,
        ]:
            ch.queue_bind(
                exchange=settings.topic_exchange,
                queue=settings.twin_events_queue,
                routing_key=rk,
            )
            logger.info("Bound %s -> %s (rk=%s)", settings.twin_events_queue, settings.topic_exchange, rk)

    def get_queue_depth(self, queue_name: str) -> int:
        """Return current message count for a queue."""
        with self._lock:
            if not self.channel or self.channel.is_closed:
                self.connect()
            if not self.channel:
                return 0
            try:
                method = self.channel.queue_declare(queue=queue_name, durable=True, passive=True)
                return method.method.message_count
            except Exception:
                return 0

    def get_consumer_count(self, queue_name: str) -> int:
        """Return active consumer count for a queue."""
        with self._lock:
            if not self.channel or self.channel.is_closed:
                self.connect()
            if not self.channel:
                return 0
            try:
                method = self.channel.queue_declare(queue=queue_name, durable=True, passive=True)
                return method.method.consumer_count
            except Exception:
                return 0

    def purge_queue(self, queue_name: str) -> int:
        """Purge a queue and return the number of messages removed."""
        with self._lock:
            if not self.channel or self.channel.is_closed:
                self.connect()
            if not self.channel:
                return 0
            try:
                method = self.channel.queue_purge(queue=queue_name)
                return method.method.message_count
            except Exception:
                return 0


# Module-level singleton (lazy-initialized)
_topology: RabbitMQTopology | None = None


def get_topology() -> RabbitMQTopology:
    global _topology
    if _topology is None:
        _topology = RabbitMQTopology()
    return _topology
