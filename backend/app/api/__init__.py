"""HTTP API routers."""
from fastapi import APIRouter

from app.api import auth, twin, telemetry, risk, policies, threats, deception, optimization, analytics, audit, users, mitre

api_router = APIRouter()
api_router.include_router(auth.router)
api_router.include_router(users.router)
api_router.include_router(twin.router)
api_router.include_router(telemetry.router)
api_router.include_router(risk.router)
api_router.include_router(policies.router)
api_router.include_router(threats.router)
api_router.include_router(deception.router)
api_router.include_router(optimization.router)
api_router.include_router(analytics.router)
api_router.include_router(audit.router)
api_router.include_router(mitre.router)
