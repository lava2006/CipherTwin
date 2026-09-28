"""Application configuration."""
from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict

BACKEND_DIR = Path(__file__).resolve().parents[2]


class Settings(BaseSettings):
    """Runtime configuration loaded from environment variables (.env supported)."""

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_name: str = "CipherTwin"
    app_version: str = "0.1.0"

    # JWT
    secret_key: str = "ciphertwin-dev-secret-change-me-in-production-please-32chars"
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 60 * 8

    # Database
    database_url: str = f"sqlite:///{BACKEND_DIR / 'data' / 'ciphertwin.db'}"

    # CORS
    cors_origins: list[str] = ["http://localhost:5173", "http://localhost:3000", "*"]

    # Simulation
    telemetry_interval_seconds: float = 2.5
    enable_simulation: bool = True

    # Zero Trust risk thresholds
    risk_threshold_allow: int = 30
    risk_threshold_restricted: int = 60
    risk_threshold_deny: int = 100

    # Deception trigger threshold
    deception_risk_threshold: int = 60


settings = Settings()
