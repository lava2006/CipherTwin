import os
import sys
sys.path.insert(0, "backend")

os.environ['DATABASE_URL'] = 'sqlite:///:memory:'
os.environ['RABBITMQ_ENABLED'] = 'false'
os.environ['SECRET_KEY'] = 'test-only-secret-key-not-for-deployment-123456'
os.environ['SEED_ADMIN_PASSWORD'] = 'test-admin'
os.environ['SEED_ANALYST_PASSWORD'] = 'test-analyst'
os.environ['SEED_SOC_LEAD_PASSWORD'] = 'test-soc'

from app.db.session import Base, engine, SessionLocal
import app.models
Base.metadata.create_all(bind=engine)
from app.seed import run_all
run_all()

from app.services.rabbitmq import rabbitmq_pipeline
from app.models.telemetry import TelemetryEvent
from app.models.risk import RiskDecision
from app.core.config import settings
from app.services.threat_intel import ThreatIntel
from app.services.deception import DeceptionEngine

db = SessionLocal()
telemetry_payload = {
    'message_id': 'test-1',
    'event_type': 'failed_login',
    'user_id': 'attacker_test',
    'device_id': 'srv_dmz_web_01',
    'ip_address': '198.51.100.177',
    'location': 'Tor Exit Node',
    'status': 'failure',
    'risk_indicators': ['brute_force', 'credential_stuffing', 'anonymous_network'],
    'raw_payload': {'failed_logins': 8, 'target_service': 'ssh'},
}
rabbitmq_pipeline.publish(telemetry_payload)
res = rabbitmq_pipeline.process_one(db)
print('res:', res)
event = db.query(TelemetryEvent).filter(TelemetryEvent.id == res['event_id']).first()
decision = db.query(RiskDecision).filter(RiskDecision.telemetry_id == event.id).first()
print('event:', event.id, event.mitre_technique)
print('decision:', decision.risk_score, decision.decision)
print('deception_risk_threshold:', settings.deception_risk_threshold)
intel = ThreatIntel(db)
threat = intel.correlate(event, decision.risk_score, decision.decision)
print('threat:', threat)
deception = DeceptionEngine(db)
print('sessions count:', len(deception.list_sessions()))
