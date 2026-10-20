"""Tests for the /ingest endpoints (remote VM ingestion path)."""

import json
import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.core.config import settings


API_KEY = "test-ingest-key-12345"


@pytest.fixture(autouse=True)
def set_ingest_key(monkeypatch):
    """Set INGEST_API_KEY for all ingest tests."""
    monkeypatch.setattr(settings, "ingest_api_key", API_KEY)
    monkeypatch.setattr(settings, "rabbitmq_enabled", False)  # use in-memory broker
    monkeypatch.setattr(settings, "enable_simulation", True)


@pytest.fixture
def client():
    return TestClient(app)


def test_ingest_edr_missing_key(client):
    """Missing X-API-Key => 401."""
    resp = client.post("/ingest/edr", json={"event_id": "e1", "timestamp": "2026-01-01T00:00:00Z", "device_id": "d1", "event_type": "process_start"})
    assert resp.status_code == 401


def test_ingest_edr_wrong_key(client):
    """Wrong X-API-Key => 401."""
    resp = client.post("/ingest/edr", json={"event_id": "e1", "timestamp": "2026-01-01T00:00:00Z", "device_id": "d1", "event_type": "process_start"}, headers={"X-API-Key": "wrong"})
    assert resp.status_code == 401


def test_ingest_edr_valid(client):
    """Valid EDR event => 202."""
    payload = {
        "event_id": "evt-edr-001",
        "timestamp": "2026-01-01T00:00:00Z",
        "device_id": "dev-01",
        "event_type": "process_start",
        "process_name": "bash",
        "process_path": "/bin/bash",
        "command_line": "ls -la",
        "user": "root",
        "risk_indicators": [],
    }
    resp = client.post("/ingest/edr", json=payload, headers={"X-API-Key": API_KEY})
    assert resp.status_code == 202
    data = resp.json()
    assert data["status"] == "accepted"
    assert data["routing_key"] == "telemetry.edr"


def test_ingest_edr_invalid(client):
    """Invalid EDR event (missing required fields) => 422."""
    payload = {"event_id": "e1"}  # missing required fields
    resp = client.post("/ingest/edr", json=payload, headers={"X-API-Key": API_KEY})
    assert resp.status_code == 422


def test_ingest_iam_valid(client):
    """Valid IAM event => 202."""
    payload = {
        "event_id": "evt-iam-001",
        "timestamp": "2026-01-01T00:00:00Z",
        "device_id": "dev-01",
        "event_type": "ssh_failed",
        "username": "root",
        "src_ip": "198.51.100.42",
        "success": False,
    }
    resp = client.post("/ingest/iam", json=payload, headers={"X-API-Key": API_KEY})
    assert resp.status_code == 202
    data = resp.json()
    assert data["status"] == "accepted"
    assert data["routing_key"] == "telemetry.iam"


def test_ingest_netflow_valid(client):
    """Valid NetFlow event => 202."""
    payload = {
        "event_id": "evt-nf-001",
        "timestamp": "2026-01-01T00:00:00Z",
        "device_id": "dev-01",
        "src_ip": "10.0.0.5",
        "dst_ip": "10.0.0.99",
        "src_port": 12345,
        "dst_port": 443,
        "protocol": "tcp",
        "bytes_sent": 1024,
        "bytes_recv": 2048,
    }
    resp = client.post("/ingest/netflow", json=payload, headers={"X-API-Key": API_KEY})
    assert resp.status_code == 202


def test_ingest_cowrie_valid(client):
    """Valid Cowrie event => 202."""
    payload = {
        "event_id": "evt-cowrie-001",
        "timestamp": "2026-01-01T00:00:00Z",
        "session": "sess-abc123",
        "src_ip": "198.51.100.42",
        "eventid": "cowrie.login.failed",
        "username": "root",
        "password_present": True,
        "command": None,
        "url": None,
    }
    resp = client.post("/ingest/cowrie", json=payload, headers={"X-API-Key": API_KEY})
    assert resp.status_code == 202


def test_ingest_batch_valid(client):
    """Valid batch => 202 with accepted count."""
    payload = [
        {
            "event_id": "evt-batch-1",
            "timestamp": "2026-01-01T00:00:00Z",
            "device_id": "dev-01",
            "event_type": "process_start",
            "process_name": "bash",
            "route": "edr",
        },
        {
            "event_id": "evt-batch-2",
            "timestamp": "2026-01-01T00:00:00Z",
            "device_id": "dev-01",
            "event_type": "ssh_failed",
            "username": "root",
            "route": "iam",
        },
    ]
    resp = client.post("/ingest/batch", json=payload, headers={"X-API-Key": API_KEY})
    assert resp.status_code == 202
    data = resp.json()
    assert data["accepted"] == 2
    assert data["rejected"] == 0


def test_ingest_batch_too_large(client):
    """Batch exceeding max size => 422."""
    payload = []
    for i in range(settings.ingest_max_batch_size + 1):
        payload.append({
            "event_id": f"evt-big-{i}",
            "timestamp": "2026-01-01T00:00:00Z",
            "device_id": "dev-01",
            "event_type": "process_start",
            "process_name": "bash",
            "route": "edr",
        })
    resp = client.post("/ingest/batch", json=payload, headers={"X-API-Key": API_KEY})
    assert resp.status_code == 422


def test_ingest_batch_mixed(client):
    """Batch with valid and invalid events => accepted/rejected counts."""
    payload = [
        {
            "event_id": "evt-mix-1",
            "timestamp": "2026-01-01T00:00:00Z",
            "device_id": "dev-01",
            "event_type": "process_start",
            "process_name": "bash",
            "route": "edr",
        },
        {"not": "an event"},  # invalid
    ]
    resp = client.post("/ingest/batch", json=payload, headers={"X-API-Key": API_KEY})
    assert resp.status_code == 202
    data = resp.json()
    assert data["accepted"] == 1
    assert data["rejected"] == 1


def test_ingest_idempotent_resend(client):
    """Resending same event_id => duplicate dropped, not double-accepted."""
    payload = {
        "event_id": "evt-idem-001",
        "timestamp": "2026-01-01T00:00:00Z",
        "device_id": "dev-01",
        "event_type": "process_start",
        "process_name": "bash",
    }
    resp1 = client.post("/ingest/edr", json=payload, headers={"X-API-Key": API_KEY})
    assert resp1.status_code == 202
    resp2 = client.post("/ingest/edr", json=payload, headers={"X-API-Key": API_KEY})
    assert resp2.status_code == 202
    data2 = resp2.json()
    assert data2["event_id"] == "Duplicate dropped"


def test_ingest_live(client):
    """Liveness probe => 200."""
    resp = client.get("/ingest/health/live")
    assert resp.status_code == 200
    assert resp.json()["status"] == "live"
