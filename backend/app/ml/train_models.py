"""Train CipherTwin Random Forest and anomaly models on synthetic telemetry."""
from pathlib import Path
import json
import logging

import joblib
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split

from app.ml.features import FEATURE_NAMES
from app.ml.synthetic_data import DEFAULT_OUTPUT, save_dataset

BASE_DIR = Path(__file__).resolve().parents[2]
MODEL_DIR = BASE_DIR / "app" / "ml" / "models"
RF_PATH = MODEL_DIR / "random_forest.joblib"
IF_PATH = MODEL_DIR / "isolation_forest.joblib"
META_PATH = MODEL_DIR / "metadata.json"

logger = logging.getLogger("ciphertwin.ml.training")


def train(dataset_path: Path = DEFAULT_OUTPUT) -> dict:
    """Train, evaluate and persist the ML models once; inference only loads them."""
    MODEL_DIR.mkdir(parents=True, exist_ok=True)

    if not dataset_path.exists():
        save_dataset(output=dataset_path)

    df = pd.read_csv(dataset_path)
    missing = [name for name in FEATURE_NAMES + ["label"] if name not in df.columns]
    if missing:
        raise ValueError(f"Training dataset is missing columns: {missing}")
    if df[FEATURE_NAMES].isnull().any().any():
        raise ValueError("Training features contain missing values")

    X = df[FEATURE_NAMES]
    y = df["label"]

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.20,
        random_state=42,
        stratify=y,
    )

    rf = RandomForestClassifier(
        n_estimators=350,
        max_depth=14,
        min_samples_leaf=4,
        class_weight="balanced_subsample",
        random_state=42,
        n_jobs=-1,
    )
    rf.fit(X_train, y_train)
    pred = rf.predict(X_test)
    probabilities = rf.predict_proba(X_test)

    classes = list(rf.classes_)
    try:
        roc_auc = float(
            roc_auc_score(
                y_test,
                probabilities,
                multi_class="ovr",
                labels=classes,
                average="macro",
            )
        )
    except ValueError:
        roc_auc = None

    # Fit the unsupervised detector only on normal training samples.
    iso = IsolationForest(
        n_estimators=250,
        contamination=0.10,
        max_samples="auto",
        random_state=42,
        n_jobs=-1,
    )
    iso.fit(X_train[y_train == "normal"])

    joblib.dump(rf, RF_PATH)
    joblib.dump(iso, IF_PATH)

    report = classification_report(
        y_test, pred, output_dict=True, zero_division=0
    )
    matrix = confusion_matrix(y_test, pred, labels=classes)

    metadata = {
        "dataset": str(dataset_path.relative_to(BASE_DIR))
        if dataset_path.is_absolute() and dataset_path.is_relative_to(BASE_DIR)
        else str(dataset_path),
        "random_seed": 42,
        "test_size": 0.20,
        "samples": int(len(df)),
        "train_samples": int(len(X_train)),
        "test_samples": int(len(X_test)),
        "class_distribution": {
            str(k): int(v) for k, v in y.value_counts().sort_index().items()
        },
        "features": FEATURE_NAMES,
        "models": {
            "classifier": "RandomForestClassifier",
            "anomaly_detector": "IsolationForest",
        },
        "accuracy": round(float(accuracy_score(y_test, pred)), 4),
        "macro_precision": round(
            float(precision_score(y_test, pred, average="macro", zero_division=0)), 4
        ),
        "macro_recall": round(
            float(recall_score(y_test, pred, average="macro", zero_division=0)), 4
        ),
        "macro_f1": round(
            float(f1_score(y_test, pred, average="macro", zero_division=0)), 4
        ),
        "roc_auc_ovr_macro": round(roc_auc, 4) if roc_auc is not None else None,
        "classes": classes,
        "confusion_matrix": matrix.tolist(),
        "classification_report": report,
        "feature_importance": {
            name: round(float(value), 6)
            for name, value in zip(FEATURE_NAMES, rf.feature_importances_)
        },
        "model_file": RF_PATH.name,
        "anomaly_model_file": IF_PATH.name,
    }
    META_PATH.write_text(json.dumps(metadata, indent=2), encoding="utf-8")

    logger.info(
        "ML training complete | samples=%s accuracy=%.4f macro_f1=%.4f auc=%s",
        len(df),
        metadata["accuracy"],
        metadata["macro_f1"],
        metadata["roc_auc_ovr_macro"],
    )
    return metadata


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s :: %(message)s",
    )
    result = train()
    print(
        json.dumps(
            {
                k: result[k]
                for k in (
                    "samples",
                    "train_samples",
                    "test_samples",
                    "class_distribution",
                    "accuracy",
                    "macro_precision",
                    "macro_recall",
                    "macro_f1",
                    "roc_auc_ovr_macro",
                    "confusion_matrix",
                )
            },
            indent=2,
        )
    )
