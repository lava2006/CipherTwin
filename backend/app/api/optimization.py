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
              target=f"Policy optimization ({result.method or 'not_run'})",
              details=(f"layers={layers} iters={result.iterations} "
                       f"score {result.before_score} -> {result.after_score}; "
                       f"method={result.method}; fallback_reason={result.fallback_reason}; "
                       f"decoy_method={result.decoy_method}; "
                       f"decoy_fallback_reason={result.decoy_fallback_reason}"),
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
        "method": result.method,
        "fallback_reason": result.fallback_reason,
        "qubits": result.qubits,
        "qaoa_cost": result.qaoa_cost,
        "classical_cost": result.classical_cost,
        "decoy_method": result.decoy_method,
        "decoy_fallback_reason": result.decoy_fallback_reason,
        "decoy_assignments": result.decoy_assignments or [],
    }


@router.get("/history")
def history(limit: int = 20, db: Session = Depends(get_db),
            _: User = Depends(get_current_user)):
    return [r.to_dict() for r in QuantumOptimizer(db).history(limit=limit)]
