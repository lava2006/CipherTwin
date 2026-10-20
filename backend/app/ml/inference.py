"""Live Random Forest + Isolation Forest inference for CipherTwin telemetry."""
from functools import lru_cache
import json
import logging
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

from app.ml.features import FEATURE_NAMES, extract_event_features

BASE_DIR = Path(__file__).resolve().parents[2]
MODEL_DIR = BASE_DIR / "app" / "ml" / "models"
RF_PATH = MODEL_DIR / "random_forest.joblib"
IF_PATH = MODEL_DIR / "isolation_forest.joblib"
META_PATH = MODEL_DIR / "metadata.json"

logger = logging.getLogger("ciphertwin.ml.inference")


@lru_cache(maxsize=1)
def _models():
    """Load persisted models once per backend process; never retrain per request."""
    if not RF_PATH.exists() or not IF_PATH.exists():
        from app.ml.train_models import train

        train()
    return joblib.load(RF_PATH), joblib.load(IF_PATH)


def _explain(features: dict[str, float], model) -> list[dict]:
    """Return global RF importance paired with signals that are active/elevated."""
    importances = dict(zip(FEATURE_NAMES, model.feature_importances_))
    ranked = sorted(importances.items(), key=lambda item: item[1], reverse=True)

    explanations = []
    for name, importance in ranked:
        value = float(features[name])
        if name == "device_trust":
            active = value < 70
            description = f"Device trust is {value:.1f}/100"
        elif name == "event_risk_weight":
            active = value >= 0.35
            description = f"Event risk weight is {value:.2f}"
        elif name == "failed_logins":
            active = value >= 2
            description = f"{value:.0f} failed login attempt(s)"
        elif name.endswith("_risk") or name in {
            "off_hours",
            "high_volume",
            "sensitive_resource",
            "impossible_travel",
            "anonymous_network",
            "high_risk_geo",
            "vpn_network",
        }:
            active = value > 0
            description = f"{name.replace('_', ' ').title()} signal is active"
        else:
            active = value > 0
            description = f"{name.replace('_', ' ').title()} event signal is active"

        if active:
            explanations.append(
                {
                    "feature": name,
                    "importance": round(float(importance), 6),
                    "value": round(value, 4),
                    "description": description,
                }
            )
        if len(explanations) == 4:
            break

    return explanations


def predict(event, device_trust: float | None = None) -> dict:
    rf, iso = _models()
    features = extract_event_features(event, device_trust=device_trust)
    vector = pd.DataFrame(
        [[features[name] for name in FEATURE_NAMES]],
        columns=FEATURE_NAMES,
    )

    probabilities = rf.predict_proba(vector)[0]
    classes = list(rf.classes_)
    probs = {label: float(probabilities[i]) for i, label in enumerate(classes)}
    threat_probability = probs.get("malicious", 0.0) + 0.55 * probs.get("suspicious", 0.0)

    # IsolationForest decision_function is larger for normal observations.
    raw_anomaly = float(-iso.decision_function(vector)[0])
    anomaly_score = float(np.clip(50.0 + raw_anomaly * 100.0, 0.0, 100.0))

    ml_risk = float(
        np.clip(
            100.0
            * (0.72 * threat_probability + 0.28 * anomaly_score / 100.0),
            0.0,
            100.0,
        )
    )
    predicted_class = str(rf.predict(vector)[0])
    confidence = float(max(probabilities)) * 100.0

    result = {
        "predicted_class": predicted_class,
        "malicious_probability": round(probs.get("malicious", 0.0) * 100, 2),
        "suspicious_probability": round(probs.get("suspicious", 0.0) * 100, 2),
        "normal_probability": round(probs.get("normal", 0.0) * 100, 2),
        "anomaly_score": round(anomaly_score, 2),
        "ml_risk_score": round(ml_risk, 2),
        "confidence": round(confidence, 2),
        "features": features,
        "explanations": _explain(features, rf),
    }
    logger.info(
        "ML inference | event=%s class=%s malicious=%.2f suspicious=%.2f anomaly=%.2f risk=%.2f confidence=%.2f",
        getattr(event, "id", None),
        predicted_class,
        result["malicious_probability"],
        result["suspicious_probability"],
        result["anomaly_score"],
        result["ml_risk_score"],
        result["confidence"],
    )
    return result


def metadata() -> dict:
    if not META_PATH.exists():
        return {"trained": False}
    return {"trained": True, **json.loads(META_PATH.read_text(encoding="utf-8"))}
