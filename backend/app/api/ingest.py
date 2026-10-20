"""Secure HTTP ingest endpoints for remote VM telemetry.

Endpoints:
  POST /ingest/edr       -> routing key telemetry.edr
  POST /ingest/iam       -> routing key telemetry.iam
  POST /ingest/netflow   -> routing key telemetry.netflow
  POST /ingest/cowrie    -> routing key telemetry.cowrie
  POST /ingest/batch     -> list of typed events

Auth: X-API-Key header (INGEST_API_KEY env var, no default).
Rate limit: fixed window per API key.
Validation: pydantic v2 models from schemas.telemetry_events.
"""
import json
import time
from collections import defaultdict
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple
from fastapi import APIRouter, Depends, HTTPException, Header, Request, status
from pydantic import ValidationError

from app.core.config import settings
from app.services.publisher import publisher
from app.schemas.telemetry_events import (
    EDREvent, IAMEvent, NetFlowEvent, CowrieEvent,
    ROUTING_KEY_TO_MODEL,
)

router = APIRouter(prefix="/ingest", tags=["ingest"])

# Route -> model class
_ROUTE_TO_MODEL: dict[str, type] = {
    "edr": EDREvent,
    "iam": IAMEvent,
    "netflow": NetFlowEvent,
    "cowrie": CowrieEvent,
}

# Route -> routing key
_ROUTE_TO_RK: dict[str, str] = {
    "edr": "telemetry.edr",
    "iam": "telemetry.iam",
    "netflow": "telemetry.netflow",
    "cowrie": "telemetry.cowrie",
}

# Rate limiter: {api_key: [timestamps]}
_rate_windows: dict[str, List[float]] = defaultdict(list)
_RATE_WINDOW_SECONDS = 60.0


def _check_api_key(x_api_key: Optional[str]) -> None:
    if not settings.ingest_api_key:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="INGEST_API_KEY not configured on server",
        )
    if x_api_key != settings.ingest_api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing X-API-Key",
        )


def _check_rate_limit(api_key: str) -> None:
    now = time.time()
    window = _rate_windows[api_key]
    # Purge old entries
    cutoff = now - _RATE_WINDOW_SECONDS
    while window and window[0] < cutoff:
        window.pop(0)
    if len(window) >= settings.ingest_rate_limit_per_minute:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded",
        )
    window.append(now)


def _validate_body_size(body: bytes) -> None:
    if len(body) > settings.ingest_max_body_bytes:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"Body exceeds {settings.ingest_max_body_bytes} bytes",
        )


@router.post("/edr", status_code=status.HTTP_202_ACCEPTED)
async def ingest_edr(request: Request, x_api_key: Optional[str] = Header(None)):
    _check_api_key(x_api_key)
    _check_rate_limit(x_api_key or "")
    body = await request.body()
    _validate_body_size(body)
    try:
        payload = json.loads(body)
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=422, detail=f"Invalid JSON: {exc}")
    ok, msg = publisher.publish("telemetry.edr", payload)
    if not ok:
        raise HTTPException(status_code=422, detail=msg)
    return {"status": "accepted", "event_id": msg, "routing_key": "telemetry.edr"}


@router.post("/iam", status_code=status.HTTP_202_ACCEPTED)
async def ingest_iam(request: Request, x_api_key: Optional[str] = Header(None)):
    _check_api_key(x_api_key)
    _check_rate_limit(x_api_key or "")
    body = await request.body()
    _validate_body_size(body)
    try:
        payload = json.loads(body)
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=422, detail=f"Invalid JSON: {exc}")
    ok, msg = publisher.publish("telemetry.iam", payload)
    if not ok:
        raise HTTPException(status_code=422, detail=msg)
    return {"status": "accepted", "event_id": msg, "routing_key": "telemetry.iam"}


@router.post("/netflow", status_code=status.HTTP_202_ACCEPTED)
async def ingest_netflow(request: Request, x_api_key: Optional[str] = Header(None)):
    _check_api_key(x_api_key)
    _check_rate_limit(x_api_key or "")
    body = await request.body()
    _validate_body_size(body)
    try:
        payload = json.loads(body)
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=422, detail=f"Invalid JSON: {exc}")
    ok, msg = publisher.publish("telemetry.netflow", payload)
    if not ok:
        raise HTTPException(status_code=422, detail=msg)
    return {"status": "accepted", "event_id": msg, "routing_key": "telemetry.netflow"}


@router.post("/cowrie", status_code=status.HTTP_202_ACCEPTED)
async def ingest_cowrie(request: Request, x_api_key: Optional[str] = Header(None)):
    _check_api_key(x_api_key)
    _check_rate_limit(x_api_key or "")
    body = await request.body()
    _validate_body_size(body)
    try:
        payload = json.loads(body)
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=422, detail=f"Invalid JSON: {exc}")
    ok, msg = publisher.publish("telemetry.cowrie", payload)
    if not ok:
        raise HTTPException(status_code=422, detail=msg)
    return {"status": "accepted", "event_id": msg, "routing_key": "telemetry.cowrie"}


@router.post("/batch", status_code=status.HTTP_202_ACCEPTED)
async def ingest_batch(request: Request, x_api_key: Optional[str] = Header(None)):
    _check_api_key(x_api_key)
    _check_rate_limit(x_api_key or "")
    body = await request.body()
    _validate_body_size(body)
    try:
        items = json.loads(body)
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=422, detail=f"Invalid JSON: {exc}")

    if not isinstance(items, list):
        raise HTTPException(status_code=422, detail="Batch must be a list of events")
    if len(items) > settings.ingest_max_batch_size:
        raise HTTPException(
            status_code=422,
            detail=f"Batch size {len(items)} exceeds max {settings.ingest_max_batch_size}",
        )

    accepted = 0
    rejected = 0
    details: list[dict] = []

    for idx, item in enumerate(items):
        if not isinstance(item, dict):
            rejected += 1
            details.append({"index": idx, "error": "Not a JSON object"})
            continue

        event_type = item.get("event_type") or item.get("eventid", "")
        # Determine routing key from event_type hint or route field
        route = item.get("route", "")
        if route not in _ROUTE_TO_MODEL:
            # Try to infer from event_type and payload attributes
            et = str(event_type).lower()
            if "cowrie" in et or "session" in item or item.get("eventid"):
                route = "cowrie"
            elif et.startswith("ssh") or et.startswith("auth") or et.startswith("iam") or "username" in item or "success" in item:
                route = "iam"
            elif et.startswith("process") or et.startswith("file") or et.startswith("edr") or "command_line" in item:
                route = "edr"
            elif et.startswith("flow") or et.startswith("net") or "src_port" in item:
                route = "netflow"
            else:
                rejected += 1
                details.append({"index": idx, "error": "Unknown event type/route"})
                continue

        rk = _ROUTE_TO_RK[route]
        ok, msg = publisher.publish(rk, item)
        if ok:
            accepted += 1
        else:
            rejected += 1
        details.append({"index": idx, "event_id": msg if ok else None, "error": None if ok else msg})

    return {
        "status": "completed",
        "accepted": accepted,
        "rejected": rejected,
        "details": details,
    }


@router.get("/health/live")
async def ingest_live():
    """Liveness probe for the ingest service."""
    return {"status": "live", "service": "ingest"}
