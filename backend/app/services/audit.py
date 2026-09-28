"""Audit log writer."""
from typing import Optional

from sqlalchemy.orm import Session

from app.models.audit import AuditLog


def log_event(db: Session, *, action: str, actor: Optional[str] = None,
              target: Optional[str] = None, details: Optional[str] = None,
              severity: str = "info", ip_address: Optional[str] = None) -> AuditLog:
    entry = AuditLog(
        actor=actor,
        action=action,
        target=target,
        details=details,
        severity=severity,
        ip_address=ip_address,
    )
    db.add(entry)
    db.commit()
    return entry


def list_logs(db: Session, limit: int = 200, severity: Optional[str] = None,
              action: Optional[str] = None):
    q = db.query(AuditLog)
    if severity:
        q = q.filter(AuditLog.severity == severity)
    if action:
        q = q.filter(AuditLog.action == action)
    return q.order_by(AuditLog.timestamp.desc()).limit(limit).all()
