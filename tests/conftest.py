"""Shared pytest setup with an isolated disposable SQLite database."""
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TEST_DB = Path(__file__).resolve().parent / ".ciphertwin_test.db"

# Always isolate tests from any developer/prod DATABASE_URL and local app database.
os.environ["DATABASE_URL"] = f"sqlite:///{TEST_DB.as_posix()}"
os.environ["SECRET_KEY"] = "test-only-secret-key-not-for-deployment-123456"
os.environ["SEED_ADMIN_PASSWORD"] = "test-admin-password-only"
os.environ["SEED_ANALYST_PASSWORD"] = "test-analyst-password-only"
os.environ["SEED_SOC_LEAD_PASSWORD"] = "test-soc-lead-password-only"
os.environ["RABBITMQ_ENABLED"] = "false"
os.environ["NEO4J_ENABLED"] = "false"
os.environ["COWRIE_ENABLED"] = "false"

sys.path.insert(0, str(ROOT / "backend"))


def pytest_sessionstart(session):
    """Create schema and seed baseline before tests that use the shared SessionLocal."""
    from app.db.session import Base, engine, SessionLocal
    import app.models  # noqa: F401 - registers all ORM models on Base.metadata
    from app.seed import init_schema, seed_users, seed_twin, seed_policies, seed_mitre, seed_threats, seed_audit

    init_schema()
    db = SessionLocal()
    try:
        seed_users(db)
        seed_twin(db)
        seed_policies(db)
        seed_mitre(db)
        seed_threats(db)
        seed_audit(db)
    finally:
        db.close()


def pytest_sessionfinish(session, exitstatus):
    """Dispose and remove the temporary test database after the test run."""
    try:
        from app.db.session import Base, engine
        Base.metadata.drop_all(bind=engine)
        engine.dispose()
    except Exception:
        pass
    for suffix in ("", "-journal", "-wal", "-shm"):
        path = Path(str(TEST_DB) + suffix)
        try:
            path.unlink(missing_ok=True)
        except OSError:
            pass
