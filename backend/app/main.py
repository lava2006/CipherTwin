"""CipherTwin FastAPI application factory."""
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api import api_router
from app.core.config import settings
from app.seed import run_all
from app.workers.pipeline import start_background, status as pipeline_status

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(name)s :: %(message)s")


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Run database schema + seed data on startup.
    run_all()
    # Controlled event engine starts in STOPPED state; user controls it via UI / API
    yield


app = FastAPI(
    title=settings.app_name,
    description=(
        "CipherTwin – Autonomous Cyber Defense Framework combining a Digital "
        "Twin, Explainable Zero Trust, Adaptive Deception, Threat "
        "Intelligence and simulated Quantum Policy Optimization."
    ),
    version=settings.app_version,
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(api_router)


@app.get("/")
def root():
    return {
        "name": settings.app_name,
        "version": settings.app_version,
        "status": "ok",
        "pipeline": pipeline_status(),
        "endpoints": {
            "docs": "/docs",
            "openapi": "/openapi.json",
            "auth": "/api/auth/login",
            "analytics_overview": "/api/analytics/overview",
        },
    }


@app.get("/api/health")
def health():
    return {"status": "ok", "pipeline": pipeline_status()}
