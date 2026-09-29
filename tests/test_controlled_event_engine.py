import time
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.services.event_engine import event_engine
from app.db.session import SessionLocal
from app.models import TelemetryEvent, RiskDecision


def test_event_engine_initial_state():
    """Verify event engine adheres to stopped default state and 1.0s interval."""
    # Ensure stopped
    event_engine.stop()
    status = event_engine.get_status()
    assert status["running"] is False
    assert status["state"] == "STOPPED"
    assert status["events_per_second"] == 0.0
    assert status["interval_seconds"] == 1.0


def test_event_engine_start_stop_lifecycle():
    """Verify start/stop transitions, duplicate suppression, and counter increments."""
    event_engine.stop()
    initial_count = event_engine.events_generated

    # 1. Start engine
    res1 = event_engine.start()
    assert res1["status"] == "started"
    assert res1["running"] is True
    assert event_engine.is_running() is True

    # 2. Duplicate start suppression
    res2 = event_engine.start()
    assert res2["status"] == "already_running"
    assert res2["running"] is True

    # 3. Allow at least 2 events to emit (polling up to 6.0s to account for cold-start ML model load)
    deadline = time.time() + 6.0
    while time.time() < deadline:
        if event_engine.events_generated >= initial_count + 2:
            break
        time.sleep(0.2)
    assert event_engine.events_generated >= initial_count + 2

    # 4. Stop engine
    res_stop = event_engine.stop()
    assert res_stop["status"] == "stopped"
    assert res_stop["running"] is False
    assert event_engine.is_running() is False

    # 5. Duplicate stop suppression
    res_stop2 = event_engine.stop()
    assert res_stop2["status"] == "already_stopped"
    assert res_stop2["running"] is False

    # 6. Verify counter remains fixed after stop
    frozen_count = event_engine.events_generated
    time.sleep(1.2)
    assert event_engine.events_generated == frozen_count


def test_event_engine_api_endpoints():
    """Verify REST API routes for /api/events/start, /stop, and /status."""
    from app.core.security import create_access_token
    token = create_access_token(subject="admin", role="admin")
    headers = {"Authorization": f"Bearer {token}"}

    client = TestClient(app)

    # 1. Get status
    r_status = client.get("/api/events/status", headers=headers)
    assert r_status.status_code == 200
    data = r_status.json()
    assert "running" in data
    assert "events_generated" in data
    assert "events_per_second" in data

    # 2. Start via API
    r_start = client.post("/api/events/start", headers=headers)
    assert r_start.status_code == 200
    assert r_start.json()["running"] is True

    time.sleep(1.2)

    # 3. Stop via API
    r_stop = client.post("/api/events/stop", headers=headers)
    assert r_stop.status_code == 200
    assert r_stop.json()["running"] is False

    # Verify status reflects stopped
    r_status_after = client.get("/api/events/status", headers=headers)
    assert r_status_after.status_code == 200
    assert r_status_after.json()["running"] is False


def test_event_engine_pipeline_routing():
    """Verify that emit_one_event routes through RabbitMQ -> ML -> Risk -> DB."""
    event_engine.stop()
    db = SessionLocal()
    try:
        initial_events = db.query(TelemetryEvent).count()
        initial_decisions = db.query(RiskDecision).count()

        # Emit single event synchronously through pipeline
        emitted = event_engine.emit_one_event()
        assert emitted is not None
        assert "event_type" in emitted
        assert "user_id" in emitted

        # Verify persisted in database
        final_events = db.query(TelemetryEvent).count()
        final_decisions = db.query(RiskDecision).count()
        assert final_events >= initial_events + 1
        assert final_decisions >= initial_decisions + 1
    finally:
        db.close()
        event_engine.stop()
