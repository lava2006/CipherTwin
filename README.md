# CipherTwin — Autonomous Cyber Defense Framework

CipherTwin is a research/demo cybersecurity platform combining explainable Zero-Trust risk scoring, a Digital Twin, adaptive deception, threat intelligence, and quantum-inspired policy optimization.

**Important:** telemetry, users, assets, and threat actors in this repository are synthetic. The quantum optimizer is a classical simulation of QAOA behavior; it does not claim execution on a quantum processor.

## Implemented architecture

```text
React + Vite
    │ REST / JWT
    ▼
FastAPI
    ├── Explainable Zero-Trust risk engine
    ├── Random Forest + Isolation Forest inference
    ├── Telemetry simulation worker
    ├── Adaptive deception + honeytokens
    ├── Threat intelligence / MITRE mapping
    ├── Policy optimizer (QAOA-inspired classical simulation)
    └── SQLite persistence
           │
           └── Neo4j-ready graph abstraction (optional)
```

The existing React frontend was preserved. The ML layer is integrated behind the existing API flow, so no dashboard redesign is required.

## Random Forest ML pipeline

```text
Domain-grounded synthetic telemetry
        ↓
Validation + fixed seed
        ↓
80/20 stratified train/test split
        ↓
RandomForestClassifier
        ↓
Held-out evaluation
        ↓
joblib model artifact
        ↓
FastAPI loads persisted model once
        ↓
Live telemetry → features → probability + class + explanation
```

The training set contains overlapping `normal`, `suspicious`, and `malicious` cases. Labels come from a noisy latent security-risk process rather than being copied directly from a feature. This intentionally avoids a perfect/meaningless benchmark.

### Current held-out result

- Samples: **15,000**
- Train/test: **12,000 / 3,000**
- Accuracy: **82.33%**
- Macro precision: **75.50%**
- Macro recall: **77.28%**
- Macro F1: **75.67%**
- One-vs-rest macro ROC-AUC: **92.80%**
- Random seed: **42**

These are synthetic-data benchmark results, not real-world production accuracy.

Artifacts:
- `backend/data/ml/synthetic_security_events.csv`
- `backend/app/ml/models/random_forest.joblib`
- `backend/app/ml/models/isolation_forest.joblib`
- `backend/app/ml/models/metadata.json`

## Prerequisites

For local Windows development:

- Python 3.11+
- Node.js 20+
- npm
- Optional: Docker Desktop for the full containerized stack

## 1. Install backend

```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

If PowerShell blocks activation, use:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\.venv\Scripts\Activate.ps1
```

## 2. Environment setup

Copy:

```text
backend/.env.example
```

to:

```text
backend/.env
```

Never commit real secrets.

For a local SQLite demo, the default configuration is sufficient.

## 3. Generate synthetic data

```powershell
cd backend
python -m app.ml.synthetic_data
```

This writes:

```text
backend/data/ml/synthetic_security_events.csv
```

## 4. Train and evaluate ML

```powershell
cd backend
python -m app.ml.train_models
```

The command prints the held-out accuracy, precision, recall, F1, ROC-AUC, class distribution, and confusion matrix.

## 5. Start backend

```powershell
cd backend
python -m uvicorn app.main:app --reload --port 8000
```

Open:

- API: `http://localhost:8000`
- Swagger: `http://localhost:8000/docs`
- Health: `http://localhost:8000/api/health`

The startup lifecycle initializes the SQLite schema, seeds demo data, and starts the telemetry worker when `ENABLE_SIMULATION=true`.

## 6. Start frontend

In a second terminal:

```powershell
cd frontend
npm install
npm run dev
```

Open:

```text
http://localhost:5173
```

The existing Vite proxy sends `/api` requests to `http://localhost:8000`.

## 7. Complete application execution

Recommended order:

```powershell
# Terminal 1
cd backend
.\.venv\Scripts\Activate.ps1
python -m app.ml.synthetic_data
python -m app.ml.train_models
python -m uvicorn app.main:app --reload --port 8000

# Terminal 2
cd frontend
npm install
npm run dev
```

Or, after dependencies are installed:

```powershell
.\run-dev.ps1
```

## Demo credentials

| Role | Username | Password |
|---|---|---|
| Admin | `admin` | `admin123` |
| Analyst | `analyst` | `analyst123` |
| Analyst | `soc_lead` | `lead123` |

Change these for any non-demo deployment.

## API verification

After logging in and obtaining a JWT:

### Health

```text
GET /api/health
```

### ML status

```text
GET /api/risk/ml-status
```

Returns the actual persisted model metadata and evaluation results.

### Standalone ML prediction

```text
POST /api/risk/predict
```

Example JSON:

```json
{
  "event_type": "data_exfiltration",
  "location": "Tor Exit Node",
  "status": "success",
  "risk_indicators": ["high_volume", "sensitive_resource"],
  "failed_logins": 2,
  "device_trust": 30
}
```

The response contains:
- predicted class
- normal/suspicious/malicious probabilities
- anomaly score
- ML risk score
- confidence
- extracted features
- model-importance-based explanations

The endpoint does not retrain or persist the submitted event.

## Database

SQLite is the default self-contained store:

```text
backend/data/ciphertwin.db
```

The schema is created automatically at startup.

Neo4j is included in Docker Compose as an optional graph service. The current MVP uses the `GraphStore` abstraction backed by SQLite; it does **not** claim that Neo4j is the active persistence layer.

## Docker

With Docker Desktop running:

```powershell
docker compose up --build
```

Services:

- Frontend: `http://localhost`
- Backend Swagger: `http://localhost:8000/docs`
- Neo4j browser: `http://localhost:7474`

The backend image contains the persisted ML artifacts under `backend/app/ml/models`.

## Testing

The repository includes ML/inference tests:

```powershell
cd PROJECT_FINAL
pytest -q tests
```

The verified test suite covers:
- deterministic synthetic data
- feature/label validation
- saved model metadata
- probability consistency
- live Random Forest inference
- explanation generation

## PPT verification

The supplied PPT was compared against the implementation. The original deck over-claimed several technologies:

| PPT item | Implementation status | Final treatment |
|---|---|---|
| Python / FastAPI | Implemented | Kept |
| SQLite | Implemented | Kept |
| Explainable weighted risk | Implemented | Kept |
| Random Forest | Implemented | Added to implementation |
| Isolation Forest | Implemented | Documented |
| Digital Twin graph abstraction | Implemented | Kept as SQLite-backed MVP |
| Neo4j | Docker-ready, not active in MVP | Described as optional/ready |
| Docker / Compose | Implemented | Kept |
| Adaptive deception / honeytokens | Implemented as simulation | Kept with accurate wording |
| MITRE threat intelligence | Implemented | Kept |
| Jinja2 explanations | Implemented | Kept |
| RabbitMQ | Not implemented | Marked integration-ready/future |
| Cowrie | Not implemented | Marked integration-ready/future |
| PennyLane | Not implemented | Removed as an implementation claim |
| QUBO/SciPy QAOA | Not implemented literally | Described as QAOA-inspired classical simulation |
| Streamlit | Not implemented | Removed as an implementation claim |

See `PPT_VERIFICATION.md` for the detailed audit.

## Known scope limitations

This is an academic research prototype, not a production SOC:

- Telemetry is simulated.
- Threat actors are synthetic.
- Deception is simulated rather than a live attacker-facing honeypot.
- Neo4j, RabbitMQ, Cowrie, and PennyLane are integration targets rather than active dependencies in the self-contained MVP.
- The quantum optimization page uses a classical QAOA-inspired simulation.
- Synthetic ML metrics should not be presented as production detection accuracy.

## Security

Do not deploy the demo credentials or development secret to production. Do not connect the simulator or deception components to systems you do not own or have permission to test.
