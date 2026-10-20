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

## Stored synthetic benchmark metadata (not re-run in this environment)

The model metadata bundled with the uploaded source records a fixed-seed synthetic holdout benchmark in `backend/app/ml/models/metadata.json`. These values are historical metadata, not a new benchmark run during this implementation sprint. Regenerate and inspect the metadata before presenting these metrics as current.

- Samples: 15,000
- Train: 12,000
- Test: 3,000
- Accuracy: 82.33%
- Macro precision: 75.50%
- Macro recall: 77.28%
- Macro F1: 75.67%
- Macro ROC-AUC (OvR): 92.80%

The benchmark uses synthetic security signals and label uncertainty; it does not establish production detection performance. Do not present these figures as live incident-detection accuracy.

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
