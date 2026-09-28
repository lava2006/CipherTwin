# ML Setup and Verification

## Pipeline

1. `backend/app/ml/synthetic_data.py` generates 15,000 deterministic, domain-grounded security events.
2. `backend/app/ml/train_models.py` validates the dataset and performs an 80/20 stratified split.
3. `RandomForestClassifier` predicts `normal`, `suspicious`, or `malicious`.
4. `IsolationForest` learns a normal baseline for anomaly scoring.
5. Both models are persisted with `joblib`.
6. `backend/app/ml/inference.py` loads them once per process and scores live telemetry.
7. `risk_engine.py` combines the existing explainable Zero-Trust rule score (65%) with the ML risk score (35%).
8. The standalone `/api/risk/predict` endpoint accepts validated telemetry without persisting or retraining.

## Verified metrics

The current fixed-seed held-out benchmark is stored in `backend/app/ml/models/metadata.json`.

- Samples: 15,000
- Train: 12,000
- Test: 3,000
- Accuracy: 82.33%
- Macro precision: 75.50%
- Macro recall: 77.28%
- Macro F1: 75.67%
- Macro ROC-AUC (OvR): 92.80%

The benchmark is intentionally not tuned to claim near-perfect accuracy. It is based on overlapping synthetic security signals and label uncertainty.

## Run

```powershell
cd backend
python -m app.ml.synthetic_data
python -m app.ml.train_models
```

## Test

```powershell
cd PROJECT_FINAL
pytest -q tests
```
