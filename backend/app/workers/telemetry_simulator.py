"""Telemetry simulator.

Produces realistic EDR-style events every few seconds: logins, file access,
network requests, lateral movement, etc. Most events are benign; a small
fraction are malicious to exercise the risk engine.
"""
import json
import random
from datetime import datetime, timezone
from typing import List, Optional

from sqlalchemy.orm import Session

from app.models.twin import TwinNode
from app.models.telemetry import TelemetryEvent


EVENT_TYPES = [
    ("login", 0.18, "success", []),
    ("file_access", 0.20, "success", []),
    ("network_request", 0.20, "success", []),
    ("failed_login", 0.06, "failure", ["credential_issue"]),
    ("privilege_escalation", 0.02, "success", ["sensitive_resource"]),
    ("usb_insertion", 0.02, "success", ["usb_insertion"]),
    ("abnormal_process", 0.03, "success", ["sensitive_resource"]),
    ("powershell", 0.03, "success", []),
    ("lateral_movement", 0.02, "success", ["lateral_movement", "sensitive_resource"]),
    ("data_exfiltration", 0.01, "success", ["sensitive_resource", "high_volume"]),
    ("ssh_attempt", 0.04, "success", []),
    ("geolocation_change", 0.04, "success", []),
]

LOCATIONS = [
    "Headquarters, US",
    "Branch Office, UK",
    "Remote, DE",
    "Remote, IN",
    "Remote, JP",
    "Tor Exit Node",
    "VPN – Singapore",
    "Unknown Proxy",
    "Branch Office, BR",
]


class TelemetrySimulator:
    def __init__(self, db: Session):
        self.db = db
        self._cached_users: Optional[List[TwinNode]] = None
        self._cached_devices: Optional[List[TwinNode]] = None
        self._cached_targets: Optional[List[TwinNode]] = None

    def _users(self) -> List[TwinNode]:
        if self._cached_users is None:
            self._cached_users = self.db.query(TwinNode).filter(TwinNode.type == "user").all()
        return self._cached_users

    def _devices(self) -> List[TwinNode]:
        if self._cached_devices is None:
            self._cached_devices = self.db.query(TwinNode).filter(TwinNode.type.in_(["laptop", "desktop", "tablet", "device"])).all()
        return self._cached_devices

    def _targets(self) -> List[TwinNode]:
        if self._cached_targets is None:
            self._cached_targets = (
                self.db.query(TwinNode)
                .filter(TwinNode.type.in_(["server", "database", "application"]))
                .all()
            )
        return self._cached_targets

    def generate_one(self, *, force_attack: bool = False) -> Optional[TelemetryEvent]:
        users = self._users()
        devices = self._devices()
        targets = self._targets()
        if not users or not devices or not targets:
            return None

        user = random.choice(users)
        device = random.choice(devices)

        # Filter to compatible event types
        candidates = list(EVENT_TYPES)
        weights = [w for _, w, _, _ in candidates]
        if force_attack:
            # bias toward malicious events
            weights = [w if st in {"failed_login", "privilege_escalation", "abnormal_process",
                                    "powershell", "lateral_movement", "data_exfiltration",
                                    "usb_insertion"} else w * 0.1
                       for st, w, _, _ in candidates]
        chosen, weight, default_status, default_indicators = random.choices(candidates, weights=weights)[0]
        target = random.choice(targets)
        indicators = list(default_indicators)

        status = default_status
        location = user.location or random.choice(LOCATIONS)

        # Inject impossible travel occasionally
        if chosen == "geolocation_change" and random.random() < 0.3:
            new_loc = random.choice([l for l in LOCATIONS if l != location])
            indicators.append("impossible_travel")
            location = new_loc

        # Inject brute force on failed_login
        if chosen == "failed_login" and random.random() < 0.4:
            indicators.append("brute_force")

        if chosen == "privilege_escalation" and random.random() < 0.4:
            indicators.append("off_hours")
            location = random.choice(["Tor Exit Node", "Unknown Proxy"])

        if chosen == "data_exfiltration" and random.random() < 0.5:
            indicators.append("high_volume")

        # Persist a small set of numeric telemetry features so live inference uses
        # the same feature semantics as the synthetic training data.
        feature_weight = weight
        failed_logins = random.randint(1, 4) if chosen == "failed_login" else (1 if random.random() < 0.08 else 0)
        raw_payload = {
            "weight": feature_weight,
            "user_label": user.label,
            "device_label": device.label,
            "failed_logins": failed_logins,
        }

        event = TelemetryEvent(
            timestamp=datetime.now(timezone.utc),
            user_id=user.id,
            device_id=device.id,
            target_id=target.id,
            event_type=chosen,
            location=location,
            ip_address=f"{random.randint(10, 220)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}",
            status=status,
            risk_indicators=json.dumps(indicators),
            raw=json.dumps(raw_payload),
        )
        self.db.add(event)
        self.db.commit()
        self.db.refresh(event)
        return event

    def generate_burst(self, n: int = 5) -> List[TelemetryEvent]:
        out = []
        for _ in range(n):
            ev = self.generate_one()
            if ev:
                out.append(ev)
        return out
