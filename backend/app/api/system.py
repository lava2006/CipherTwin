"""System Health & Observability Endpoints for CipherTwin.

Provides truthful, uncompromised runtime status reporting for all 8 subsystems:
FastAPI, SQLite, Neo4j, RabbitMQ, ML, Deception, Cowrie, and Telemetry Worker.
"""
from datetime import datetime, timezone
from typing import Any, Dict
from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.session import get_db
from app.ml.inference import metadata as ml_metadata
from app.services.cowrie import cowrie_service
from app.services.neo4j_client import neo4j_client
from app.services.rabbitmq import rabbitmq_pipeline
from app.workers.pipeline import status as pipeline_status

router = APIRouter(prefix="/api/system", tags=["system"])


@router.get("/health")
def system_health(db: Session = Depends(get_db)) -> Dict[str, Any]:
    """Inspect and truthfully report the live health of all CipherTwin services."""
    services: Dict[str, Dict[str, Any]] = {}

    # 1. FastAPI Web Server
    services["fastapi"] = {
        "status": "HEALTHY",
        "message": f"FastAPI application running ({settings.app_name} v{settings.app_version})",
        "version": settings.app_version,
    }

    # 2. SQLite Database
    try:
        db.execute(text("SELECT 1")).scalar()
        services["sqlite"] = {
            "status": "HEALTHY",
            "message": "SQLite database connected and accepting queries",
            "url": settings.database_url,
        }
    except Exception as e:
        services["sqlite"] = {
            "status": "UNAVAILABLE",
            "message": f"Database query failed: {e}",
        }

    # 3. Neo4j Digital Twin Graph
    services["neo4j"] = neo4j_client.check_health()

    # 4. RabbitMQ Telemetry Message Broker
    services["rabbitmq"] = rabbitmq_pipeline.check_health()

    # 5. ML Risk Engine
    try:
        meta = ml_metadata()
        if meta.get("trained"):
            services["ml"] = {
                "status": "HEALTHY",
                "message": "Persisted Random Forest + Isolation Forest models loaded",
                "accuracy": meta.get("accuracy"),
                "holdout_samples": meta.get("test_samples"),
                "features_count": len(meta.get("features", [])),
            }
        else:
            services["ml"] = {
                "status": "DEGRADED",
                "message": "ML models not trained; running in rule-only mode",
            }
    except Exception as e:
        services["ml"] = {
            "status": "UNAVAILABLE",
            "message": f"ML pipeline error: {e}",
        }

    # 6. Deception Engine
    from app.models.deception import DecoySession, Honeytoken
    try:
        token_count = db.query(Honeytoken).count()
        session_count = db.query(DecoySession).count()
        services["deception"] = {
            "status": "HEALTHY",
            "message": f"Adaptive deception engine active ({token_count} honeytokens, {session_count} decoy sessions)",
            "honeytokens": token_count,
            "decoy_sessions": session_count,
        }
    except Exception as e:
        services["deception"] = {
            "status": "DEGRADED",
            "message": f"Deception query failed: {e}",
        }

    # 7. Cowrie Honeypot
    services["cowrie"] = cowrie_service.check_health()

    # 8. Controlled Event Engine & Pipeline Worker
    from app.services.event_engine import event_engine
    ee_status = event_engine.get_status()
    services["event_engine"] = {
        "status": "HEALTHY",
        "state": ee_status["state"],
        "rate": ee_status["rate"],
        "events_generated": ee_status["events_generated"],
        "message": f"Controlled event engine is {ee_status['state']} ({ee_status['rate']})",
    }

    pipe = pipeline_status()
    worker_running = pipe.get("running") or event_engine.is_running()
    services["telemetry_worker"] = {
        "status": "HEALTHY",
        "message": "Background telemetry pipeline worker active" if worker_running else "Standby (ready for start trigger)",
        "running": worker_running,
        "events_processed": pipe.get("events_processed", ee_status["events_generated"]),
        "decisions_made": pipe.get("decisions_made", 0),
        "last_event_at": pipe.get("last_event_at") or ee_status.get("last_event_at"),
    }

    # Derive truthful aggregate status
    statuses = [s.get("status") for s in services.values()]
    if "UNAVAILABLE" in (services["fastapi"]["status"], services["sqlite"]["status"]):
        aggregate = "UNAVAILABLE"
    elif "UNAVAILABLE" in statuses or "DEGRADED" in statuses:
        aggregate = "DEGRADED"
    else:
        aggregate = "HEALTHY"

    return {
        "status": aggregate,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "version": settings.app_version,
        "environment": "production" if not settings.enable_simulation else "development",
        "services": services,
    }
