"""Integration tests for explainable AI behaviour analysis percentages endpoint."""
import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.db.session import SessionLocal
from app.models.risk import RiskDecision
from app.models.user import User
from app.core.security import create_access_token


@pytest.fixture
def auth_headers():
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.username == "admin").first()
        token = create_access_token(user.username, role=user.role)
        return {"Authorization": f"Bearer {token}"}
    finally:
        db.close()


def test_behaviour_analysis_endpoint(auth_headers):
    client = TestClient(app)
    response = client.get("/api/risk/behaviour-analysis", headers=auth_headers)
    assert response.status_code == 200
    data = response.json()

    assert "total_evaluated" in data
    assert "normal_pct" in data
    assert "suspicious_pct" in data
    assert "anomalous_pct" in data
    assert "malicious_pct" in data
    assert "counts" in data
    assert "average_risk_score" in data
    assert "average_confidence" in data

    counts = data["counts"]
    assert "normal" in counts
    assert "suspicious" in counts
    assert "anomalous" in counts
    assert "malicious" in counts

    if data["total_evaluated"] > 0:
        total_pct = data["normal_pct"] + data["suspicious_pct"] + data["anomalous_pct"] + data["malicious_pct"]
        # Float rounding sum should be approximately 100%
        assert 99.0 <= total_pct <= 101.0
        assert sum(counts.values()) == data["total_evaluated"]
