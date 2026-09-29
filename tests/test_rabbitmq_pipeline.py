import json
import uuid
import pytest
from app.core.config import settings
from app.db.session import SessionLocal
from app.services.rabbitmq import RabbitMQPipeline, TelemetryMessage


def test_rabbitmq_pipeline_publish_and_process():
    pipe = RabbitMQPipeline()
    db = SessionLocal()
    try:
        msg_id = str(uuid.uuid4())
        msg = {
            "message_id": msg_id,
            "event_type": "login_attempt",
            "user_id": "test_user_01",
            "ip_address": "192.168.1.50",
            "location": "HQ Branch",
            "risk_indicators": ["new_ip"],
            "raw_payload": {"status": "success"},
        }
        # 1. Test publish
        ok, res_msg = pipe.publish(msg)
        assert ok is True
        assert res_msg == msg_id
        assert pipe.stats["published"] == 1
        assert pipe.broker.size(settings.rabbitmq_queue) == 1

        # 2. Test process_one (consume, risk engine evaluation, ACK, persist)
        proc_res = pipe.process_one(db)
        assert proc_res is not None
        assert proc_res["message_id"] == msg_id
        assert proc_res["acknowledged"] is True
        assert "risk_score" in proc_res
        assert "decision" in proc_res
        assert pipe.stats["acknowledged"] == 1
        assert pipe.broker.size(settings.rabbitmq_queue) == 0
    finally:
        db.close()


def test_rabbitmq_pydantic_validation():
    pipe = RabbitMQPipeline()
    # Malformed message missing required event_type
    bad_msg = {
        "message_id": str(uuid.uuid4()),
        "user_id": "missing_event_type",
    }
    ok, err = pipe.publish(bad_msg)
    assert ok is False
    assert "Validation error" in err
    assert pipe.stats["rejected"] == 1


def test_rabbitmq_duplicate_suppression():
    pipe = RabbitMQPipeline()
    msg_id = str(uuid.uuid4())
    msg = {
        "message_id": msg_id,
        "event_type": "file_access",
        "user_id": "user_dup",
        "ip_address": "10.0.0.5",
    }
    # First publish: accepted
    ok1, res1 = pipe.publish(msg)
    assert ok1 is True
    assert res1 == msg_id

    # Second publish with identical message_id: dropped as duplicate
    ok2, res2 = pipe.publish(msg)
    assert ok2 is True
    assert res2 == "Duplicate dropped"
    assert pipe.stats["duplicates_dropped"] == 1
    # Only 1 message was added to queue
    assert pipe.broker.size(settings.rabbitmq_queue) == 1


def test_rabbitmq_retry_and_dlq_routing(monkeypatch):
    pipe = RabbitMQPipeline()
    db = SessionLocal()
    try:
        msg_id = str(uuid.uuid4())
        msg = {
            "message_id": msg_id,
            "event_type": "privilege_escalation",
            "user_id": "bad_actor",
            "risk_indicators": ["root_access"],
        }
        pipe.publish(msg)
        assert pipe.broker.size(settings.rabbitmq_queue) == 1

        # Force failure during processing
        from app.services import risk_engine
        def mock_failing_evaluate(*args, **kwargs):
            raise RuntimeError("Downstream risk engine failure")
        monkeypatch.setattr(risk_engine.engine, "evaluate", mock_failing_evaluate)

        # Retry 1
        res1 = pipe.process_one(db)
        assert res1 is None
        assert pipe.stats["retries"] == 1
        assert pipe.broker.size(settings.rabbitmq_queue) == 1

        # Retry 2
        res2 = pipe.process_one(db)
        assert res2 is None
        assert pipe.stats["retries"] == 2
        assert pipe.broker.size(settings.rabbitmq_queue) == 1

        # Retry 3
        res3 = pipe.process_one(db)
        assert res3 is None
        assert pipe.stats["retries"] == 3
        assert pipe.broker.size(settings.rabbitmq_queue) == 1

        # Attempt 4 (exceeds max_retries=3): routed to DLQ!
        res4 = pipe.process_one(db)
        assert res4 is None
        assert pipe.stats["dlq_routed"] == 1
        assert pipe.broker.size(settings.rabbitmq_queue) == 0
        assert pipe.broker.size(settings.rabbitmq_dlq) == 1
    finally:
        db.close()


def test_rabbitmq_truthful_health_check():
    pipe = RabbitMQPipeline()
    health = pipe.check_health()
    assert "status" in health
    assert health["status"] in ("HEALTHY", "UNAVAILABLE", "DEGRADED")
    assert "mode" in health
    assert "queue_depth" in health
    assert "dlq_depth" in health
