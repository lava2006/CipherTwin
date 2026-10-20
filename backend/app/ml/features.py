"""Feature extraction shared by synthetic training and live inference."""
import json
import math
from typing import Any, Dict

from app.models.telemetry import TelemetryEvent

FEATURE_NAMES = [
    "failed_logins",
    "event_risk_weight",
    "is_privilege_escalation",
    "is_powershell",
    "is_lateral_movement",
    "is_data_exfiltration",
    "is_abnormal_process",
    "is_usb_insertion",
    "is_ssh_attempt",
    "off_hours",
    "high_volume",
    "sensitive_resource",
    "impossible_travel",
    "anonymous_network",
    "high_risk_geo",
    "vpn_network",
    "device_trust",
    "location_risk",
]

EVENT_WEIGHTS = {
    "login": 0.05,
    "file_access": 0.08,
    "network_request": 0.10,
    "failed_login": 0.35,
    "privilege_escalation": 0.85,
    "usb_insertion": 0.45,
    "abnormal_process": 0.55,
    "powershell": 0.50,
    "lateral_movement": 0.90,
    "data_exfiltration": 1.00,
    "ssh_attempt": 0.25,
    "geolocation_change": 0.30,
}


def _parse_raw(event: TelemetryEvent) -> Dict[str, Any]:
    try:
        return json.loads(event.raw or "{}")
    except (TypeError, json.JSONDecodeError):
        return {}


def extract_event_features(event: TelemetryEvent, device_trust: float | None = None) -> Dict[str, float]:
    raw = _parse_raw(event)
    try:
        parsed_indicators = json.loads(event.risk_indicators or "[]")
        indicators = set(parsed_indicators if isinstance(parsed_indicators, list) else [])
    except (TypeError, json.JSONDecodeError):
        indicators = set()
    loc = (event.location or "").lower()
    device_trust = 75.0 if device_trust is None else float(device_trust)

    failed_logins = float(raw.get("failed_logins", 1 if event.event_type == "failed_login" else 0))
    anonymous = float(any(x in loc for x in ("tor", "anonymous", "unknown", "proxy")))
    high_risk_geo = float(any(x in loc for x in ("ru", "cn", "kp", "ir")) and "headquarters" not in loc)
    vpn = float("vpn" in loc)
    off_hours = float("off_hours" in indicators)
    high_volume = float("high_volume" in indicators)
    sensitive = float("sensitive_resource" in indicators)
    impossible = float("impossible_travel" in indicators)
    location_risk = min(100.0, 60 * anonymous + 30 * high_risk_geo + 15 * vpn + 70 * impossible)

    values = {
        "failed_logins": min(10.0, failed_logins),
        "event_risk_weight": float(raw.get("weight", EVENT_WEIGHTS.get(event.event_type, 0.15))),
        "is_privilege_escalation": float(event.event_type == "privilege_escalation"),
        "is_powershell": float(event.event_type == "powershell"),
        "is_lateral_movement": float(event.event_type == "lateral_movement"),
        "is_data_exfiltration": float(event.event_type == "data_exfiltration"),
        "is_abnormal_process": float(event.event_type == "abnormal_process"),
        "is_usb_insertion": float(event.event_type == "usb_insertion"),
        "is_ssh_attempt": float(event.event_type == "ssh_attempt"),
        "off_hours": off_hours,
        "high_volume": high_volume,
        "sensitive_resource": sensitive,
        "impossible_travel": impossible,
        "anonymous_network": anonymous,
        "high_risk_geo": high_risk_geo,
        "vpn_network": vpn,
        "device_trust": max(0.0, min(100.0, device_trust)),
        "location_risk": location_risk,
    }
    return {name: float(values[name]) for name in FEATURE_NAMES}


def vectorize(features: Dict[str, float]):
    return [features[name] for name in FEATURE_NAMES]
