"""Generate reproducible, domain-grounded synthetic cybersecurity telemetry.

The labels are produced from a noisy latent threat-risk process rather than
being direct copies of a single feature. This keeps the training task
realistic enough to exercise a Random Forest without fabricating accuracy.
"""
from pathlib import Path
import random

import numpy as np
import pandas as pd

from app.ml.features import FEATURE_NAMES, EVENT_WEIGHTS

BASE_DIR = Path(__file__).resolve().parents[2]
DEFAULT_OUTPUT = BASE_DIR / "data" / "ml" / "synthetic_security_events.csv"

EVENT_TYPES = list(EVENT_WEIGHTS)
EVENT_PROBABILITIES = np.array(
    [0.18, 0.20, 0.20, 0.06, 0.02, 0.02, 0.03, 0.03, 0.02, 0.01, 0.04, 0.04],
    dtype=float,
)
EVENT_PROBABILITIES /= EVENT_PROBABILITIES.sum()


def generate_dataset(n: int = 15000, seed: int = 42) -> pd.DataFrame:
    """Create cybersecurity telemetry with overlapping normal/suspicious/malicious classes."""
    if n < 300:
        raise ValueError("n must be at least 300 so all classes can be evaluated reliably")

    rng = np.random.default_rng(seed)
    py_rng = random.Random(seed)
    rows = []

    for _ in range(n):
        event_type = str(rng.choice(EVENT_TYPES, p=EVENT_PROBABILITIES))

        # Event-specific behaviour is realistic but intentionally overlapping.
        failed_logins = min(
            10,
            int(rng.poisson(0.5 if event_type != "failed_login" else 2.8)),
        )
        off_hours = int(
            rng.random()
            < (0.10 if event_type in {"login", "file_access", "network_request"} else 0.35)
        )
        high_volume = int(
            rng.random()
            < (0.08 if event_type in {"login", "file_access"} else 0.35)
        )
        sensitive_resource = int(
            rng.random()
            < (0.08 if event_type in {"login", "file_access", "network_request"} else 0.45)
        )
        impossible_travel = int(rng.random() < 0.03)
        anonymous_network = int(rng.random() < 0.08)
        high_risk_geo = int(rng.random() < 0.06)
        vpn_network = int(rng.random() < 0.18)

        elevated_event = event_type in {
            "failed_login",
            "privilege_escalation",
            "powershell",
            "lateral_movement",
            "data_exfiltration",
            "abnormal_process",
        }
        device_trust = float(
            np.clip(
                rng.normal(84 if not elevated_event else 68, 12),
                5,
                100,
            )
        )

        location_risk = float(
            np.clip(
                60 * anonymous_network
                + 30 * high_risk_geo
                + 15 * vpn_network
                + 70 * impossible_travel,
                0,
                100,
            )
        )

        # Latent risk is based on several correlated security signals plus
        # measurement noise. The latent value is never exposed as a feature.
        latent_risk = (
            18 * failed_logins
            + 30 * EVENT_WEIGHTS[event_type]
            + 30 * int(event_type == "privilege_escalation")
            + 18 * int(event_type == "powershell")
            + 30 * int(event_type == "lateral_movement")
            + 35 * int(event_type == "data_exfiltration")
            + 18 * int(event_type == "abnormal_process")
            + 12 * int(event_type == "usb_insertion")
            + 8 * int(event_type == "ssh_attempt")
            + 10 * off_hours
            + 15 * high_volume
            + 18 * sensitive_resource
            + 20 * impossible_travel
            + 15 * anonymous_network
            + 10 * high_risk_geo
            + 5 * vpn_network
            + (90 - device_trust) * 0.65
            + location_risk * 0.18
            + rng.normal(0, 8)
        )

        # Convert latent risk into a probability and then into three
        # overlapping operational classes. This avoids deterministic labels.
        malicious_probability = 1.0 / (1.0 + np.exp(-(latent_risk - 58.0) / 12.0))
        if malicious_probability < 0.25:
            label = "normal"
        elif malicious_probability < 0.55:
            label = "suspicious"
        else:
            label = "malicious"

        # Small label uncertainty prevents a perfect feature->label mapping.
        if py_rng.random() < 0.025:
            label = py_rng.choice(
                {"normal": ["suspicious"], "suspicious": ["normal", "malicious"], "malicious": ["suspicious"]}[label]
            )

        rows.append(
            {
                "failed_logins": failed_logins,
                "event_risk_weight": EVENT_WEIGHTS[event_type],
                "is_privilege_escalation": int(event_type == "privilege_escalation"),
                "is_powershell": int(event_type == "powershell"),
                "is_lateral_movement": int(event_type == "lateral_movement"),
                "is_data_exfiltration": int(event_type == "data_exfiltration"),
                "is_abnormal_process": int(event_type == "abnormal_process"),
                "is_usb_insertion": int(event_type == "usb_insertion"),
                "is_ssh_attempt": int(event_type == "ssh_attempt"),
                "off_hours": off_hours,
                "high_volume": high_volume,
                "sensitive_resource": sensitive_resource,
                "impossible_travel": impossible_travel,
                "anonymous_network": anonymous_network,
                "high_risk_geo": high_risk_geo,
                "vpn_network": vpn_network,
                "device_trust": device_trust,
                "location_risk": location_risk,
                "label": label,
            }
        )

    df = pd.DataFrame(rows)
    return df[FEATURE_NAMES + ["label"]]


def save_dataset(
    n: int = 15000, seed: int = 42, output: Path = DEFAULT_OUTPUT
) -> Path:
    output.parent.mkdir(parents=True, exist_ok=True)
    df = generate_dataset(n=n, seed=seed)
    df.to_csv(output, index=False)
    return output


if __name__ == "__main__":
    path = save_dataset()
    print(f"Synthetic dataset written to {path}")
