import json
from pathlib import Path

import pandas as pd

from app.ml.features import FEATURE_NAMES
from app.ml.inference import metadata, predict
from app.ml.synthetic_data import generate_dataset


def test_synthetic_dataset_is_deterministic_and_valid():
    a = generate_dataset(600, seed=42)
    b = generate_dataset(600, seed=42)
    pd.testing.assert_frame_equal(a, b)
    assert list(a.columns) == FEATURE_NAMES + ["label"]
    assert set(a["label"].unique()) == {"normal", "suspicious", "malicious"}
    assert a[FEATURE_NAMES].isna().sum().sum() == 0


def test_saved_model_metadata_contains_honest_holdout_metrics():
    meta = metadata()
    assert meta["trained"] is True
    assert meta["samples"] == 15000
    assert meta["test_samples"] == 3000
    assert 0.0 <= meta["accuracy"] <= 1.0
    assert 0.0 <= meta["macro_f1"] <= 1.0
    assert 0.0 <= meta["roc_auc_ovr_macro"] <= 1.0
    assert sum(meta["class_distribution"].values()) == meta["samples"]


def test_live_inference_returns_real_probabilities():
    class Event:
        event_type = "data_exfiltration"
        risk_indicators = json.dumps(["high_volume", "sensitive_resource"])
        location = "Tor Exit Node"
        raw = json.dumps({"failed_logins": 4, "weight": 1.0})

    result = predict(Event(), device_trust=25)
    probs = [
        result["normal_probability"],
        result["suspicious_probability"],
        result["malicious_probability"],
    ]
    assert abs(sum(probs) - 100.0) < 0.05
    assert result["predicted_class"] == "malicious"
    assert 0 <= result["ml_risk_score"] <= 100
    assert result["explanations"]
