"""Quantum policy optimization endpoints."""
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.deps import get_current_user
from app.models.user import User
from app.services.audit import log_event
from app.services.quantum_optimizer import QuantumOptimizer

router = APIRouter(prefix="/api/optimization", tags=["optimization"])


@router.get("/state")
def current_state(db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    return QuantumOptimizer(db).current_state()


@router.post("/run")
def run_optimization(payload: dict | None = None,
                     db: Session = Depends(get_db),
                     user: User = Depends(get_current_user)):
    payload = payload or {}
    layers = int(payload.get("layers", 3))
    iterations = int(payload.get("iterations", 40))
    optimizer = QuantumOptimizer(db)
    result = optimizer.optimize(layers=layers, iterations=iterations)
    log_event(db, action="optimization_run", actor=user.username,
              target="QAOA",
              details=(f"layers={layers} iters={result.iterations} "
                       f"score {result.before_score} -> {result.after_score}"),
              severity="info")
    return {
        "before_score": result.before_score,
        "after_score": result.after_score,
        "before_fp": result.before_fp,
        "after_fp": result.after_fp,
        "before_fn": result.before_fn,
        "after_fn": result.after_fn,
        "iterations": result.iterations,
        "duration_ms": result.duration_ms,
        "changes": result.changes,
    }


@router.get("/history")
def history(limit: int = 20, db: Session = Depends(get_db),
            _: User = Depends(get_current_user)):
    return [r.to_dict() for r in QuantumOptimizer(db).history(limit=limit)]
