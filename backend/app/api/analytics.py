"""Aggregate analytics endpoints used by the dashboard."""
import json
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.deps import get_current_user
from app.models.deception import DecoySession
from app.models.policy import Policy, PolicyImprovement
from app.models.risk import RiskDecision
from app.models.session import ActiveSession
from app.models.telemetry import TelemetryEvent
from app.models.threat import Threat
from app.models.twin import TwinNode
from app.models.user import User

router = APIRouter(prefix="/api/analytics", tags=["analytics"])


@router.get("/overview")
def overview(db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    nodes = db.query(TwinNode).all()
    online = sum(1 for n in nodes if n.status == "online")
    offline = sum(1 for n in nodes if n.status == "offline")
    compromised = sum(1 for n in nodes if n.status == "compromised")

    sessions = db.query(ActiveSession).filter(ActiveSession.status == "active").all()

    # Risk level = function of compromised assets + recent high-risk decisions
    last_hour = datetime.now(timezone.utc) - timedelta(hours=1)
    high_recent = db.query(RiskDecision).filter(
        RiskDecision.timestamp >= last_hour,
        RiskDecision.risk_score >= 60,
    ).count()

    if compromised >= 2 or high_recent >= 5:
        risk_level = "critical"
    elif compromised >= 1 or high_recent >= 2:
        risk_level = "high"
    elif high_recent >= 1:
        risk_level = "medium"
    else:
        risk_level = "low"

    total_users = db.query(TwinNode).filter(TwinNode.type == "user").count()
    total_tel_24h = db.query(TelemetryEvent).filter(
        TelemetryEvent.timestamp >= datetime.now(timezone.utc) - timedelta(hours=24)
    ).count()
    threats_active = db.query(Threat).filter(Threat.status == "active").count()
    decoys = db.query(DecoySession).count()
    policies_count = db.query(Policy).count()

    # Risk trend: hourly average score over last 24h
    risk_trend = []
    for hour in range(23, -1, -1):
        ts_from = datetime.now(timezone.utc) - timedelta(hours=hour + 1)
        ts_to = datetime.now(timezone.utc) - timedelta(hours=hour)
        rows = db.query(RiskDecision).filter(
            RiskDecision.timestamp >= ts_from,
            RiskDecision.timestamp < ts_to,
        ).all()
        avg = sum(r.risk_score for r in rows) / len(rows) if rows else 0
        risk_trend.append({
            "hour": ts_to.strftime("%H:%M"),
            "score": round(avg, 2),
            "count": len(rows),
        })

    # Telemetry by type
    types = db.query(TelemetryEvent.event_type).all()
    type_counter = Counter(t[0] for t in types)
    telemetry_by_type = [
        {"event_type": k, "count": v} for k, v in type_counter.most_common()
    ]

    # Top attacked assets
    target_counter = Counter()
    for ev in db.query(TelemetryEvent).filter(
        TelemetryEvent.timestamp >= datetime.now(timezone.utc) - timedelta(hours=24)
    ).all():
        target_counter[ev.target_id] += 1
    target_nodes = {n.id: n for n in nodes}
    top_attacked = [
        {"target_id": tid, "label": target_nodes[tid].label if tid in target_nodes else tid, "count": c}
        for tid, c in target_counter.most_common(8)
    ]

    # Top risky users (avg risk in last 24h)
    user_scores = defaultdict(list)
    for d in db.query(RiskDecision).filter(
        RiskDecision.timestamp >= datetime.now(timezone.utc) - timedelta(hours=24)
    ).all():
        user_scores[d.user_id].append(d.risk_score)
    top_risky_users = []
    for uid, scores in user_scores.items():
        avg = sum(scores) / len(scores)
        node = target_nodes.get(uid)
        top_risky_users.append({
            "user_id": uid,
            "label": node.label if node else uid,
            "department": node.department if node else None,
            "avg_risk": round(avg, 2),
            "events": len(scores),
        })
    top_risky_users.sort(key=lambda r: r["avg_risk"], reverse=True)
    top_risky_users = top_risky_users[:8]

    return {
        "online_devices": online,
        "offline_devices": offline,
        "compromised_assets": compromised,
        "trust_relationships": db.query(TwinNode).filter(TwinNode.type == "user").count(),
        "active_sessions": len(sessions),
        "risk_level": risk_level,
        "total_users": total_users,
        "total_telemetry_24h": total_tel_24h,
        "threats_active": threats_active,
        "decoy_sessions": decoys,
        "policies_count": policies_count,
        "risk_trend": risk_trend,
        "telemetry_by_type": telemetry_by_type,
        "top_attacked": top_attacked,
        "top_risky_users": top_risky_users,
    }


@router.get("/risk-distribution")
def risk_distribution(db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    buckets = {"0-20": 0, "20-40": 0, "40-60": 0, "60-80": 0, "80-100": 0}
    for d in db.query(RiskDecision).all():
        s = d.risk_score
        if s < 20:
            buckets["0-20"] += 1
        elif s < 40:
            buckets["20-40"] += 1
        elif s < 60:
            buckets["40-60"] += 1
        elif s < 80:
            buckets["60-80"] += 1
        else:
            buckets["80-100"] += 1
    return [{"range": k, "count": v} for k, v in buckets.items()]


@router.get("/threat-categories")
def threat_categories(db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    counter = Counter()
    for t in db.query(Threat).all():
        techniques = json.loads(t.techniques or "[]")
        counter[len(techniques)] += 1
    return [{"techniques_count": k, "threats": v} for k, v in sorted(counter.items())]


@router.get("/attack-heatmap")
def attack_heatmap(db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    """Day-of-week x hour-of-day heatmap data."""
    grid = [[0 for _ in range(24)] for _ in range(7)]
    for ev in db.query(TelemetryEvent).filter(
        TelemetryEvent.timestamp >= datetime.now(timezone.utc) - timedelta(days=7)
    ).all():
        ts = ev.timestamp
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        grid[ts.weekday()][ts.hour] += 1
    days = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
    return {"days": days, "hours": list(range(24)), "grid": grid}


@router.get("/optimization-timeline")
def optimization_timeline(db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    rows = db.query(PolicyImprovement).order_by(PolicyImprovement.timestamp.asc()).all()
    return [
        {
            "id": r.id,
            "timestamp": r.timestamp.isoformat(),
            "score": r.after_score,
            "improvement": round(r.before_score - r.after_score, 2),
        }
        for r in rows
    ]


@router.get("/telemetry-volume")
def telemetry_volume(db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    data = []
    for hour in range(23, -1, -1):
        ts_from = datetime.now(timezone.utc) - timedelta(hours=hour + 1)
        ts_to = datetime.now(timezone.utc) - timedelta(hours=hour)
        c = db.query(TelemetryEvent).filter(
            TelemetryEvent.timestamp >= ts_from,
            TelemetryEvent.timestamp < ts_to,
        ).count()
        data.append({"hour": ts_to.strftime("%H:%M"), "count": c})
    return data


@router.get("/pipeline-status")
def pipeline_status(_: User = Depends(get_current_user)):
    from app.workers.pipeline import status as pipeline_status_fn
    return pipeline_status_fn()
