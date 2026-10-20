# PPT Requirement Verification — Current Source Tree

Statuses below are based on inspection of implementation files and targeted tests, not on the previous status documents.

| PPT requirement | Source evidence | Status |
|---|---|---|
| FastAPI + SQLite | `backend/app/main.py`, `backend/app/db/session.py`, models and API routers | Implemented in source; live app startup blocked by missing runtime dependencies here |
| Weighted Zero-Trust risk scoring and explanations | `backend/app/services/risk_engine.py`, `backend/app/api/risk.py`, risk models/templates | Implemented in source |
| ML risk prediction | `backend/app/ml/inference.py`; `/api/risk/predict` now always returns inference and resolves device trust from the twin when available | Implemented in source; endpoint integration not run because auth dependency `bcrypt` is absent |
| Digital Twin graph | SQLite graph models, `GraphStore`; explicit `/api/twin/neo4j/sync`; seed sync uses the shared projection | Implemented in source; Neo4j live projection not verified |
| RabbitMQ telemetry | `backend/app/services/rabbitmq.py`, broker-enabled settings and Compose service | Partial pending live broker verification |
| Cowrie honeypot/log ingestion | `backend/app/services/cowrie.py`; normalized records enter pending telemetry idempotently and credential values are redacted in session records | Implemented in source; live Cowrie container not verified |
| Adaptive deception/honeytokens | `backend/app/services/deception.py` and API routes; simulated behavior explicitly labelled | Partial; no transparent session interception |
| Explicit HTTP redirection | `backend/app/api/deception.py` route endpoint and isolated `decoy-web` Compose service | Implemented as an explicit controlled HTTP redirect path; not transparent network/SSH redirection |
| Dynamic per-session decoy containers | No Docker socket or container provisioning controller is included | Missing |
| QUBO formulation | `backend/app/services/qubo_builder.py`; classical dictionary includes slack variables and the full objective | Implemented in source; regression test passed |
| PennyLane QAOA | `backend/app/services/quantum_optimizer.py`; full matrix dimensions are checked, batch bounded to 5 policy units/18 qubits | Implemented in source; runtime not verified here because PennyLane is not installed |
| SciPy classical fallback | `scipy.optimize.brute` evaluates all bounded action combinations against the full QUBO and checks feasibility | Implemented; tested |
| Analyst feedback loop | Feedback labels adjust the estimated risk baseline used for optimization; no false FP/FN improvement is fabricated | Partially implemented; this is a heuristic risk adjustment, not online ML retraining |
| Streamlit feedback dashboard | `dashboard/app.py` and requirements | Implemented in source; browser flow not live-tested |
| Explainable/auditable policy updates | optimizer explanations and `PolicyChange`/`PolicyImprovement` persistence | Implemented in source; full app integration remains unverified |
| Docker Compose deployment | `docker-compose.yml` includes six services and an isolated decoy network | Configuration parsed; live containers not started here |
| Live EDR/IAM/NetFlow adapters | No complete vendor/source adapters found | Missing |

## Safety and claims

- QAOA runs on a classical simulator, not quantum hardware; no quantum advantage is claimed.
- The HTTP redirect broker only redirects requests explicitly sent through its authenticated endpoint. It does not intercept arbitrary traffic.
- The shared local decoy web service is isolated and bound to loopback. Automatic per-session container provisioning is not implemented.

## Verification performed

- Python compile: passed.
- Targeted test command: `PYTHONPATH=backend python -m pytest -q tests/test_source_fixes.py tests/test_qubo_builder.py tests/test_ml_pipeline.py tests/test_rabbitmq_pipeline.py` — **20 passed**, four sklearn version warnings.
- Manual SciPy optimizer fallback check: passed; no fabricated FP/FN rate changes.
- Full test suite: blocked at collection because `bcrypt` is not installed in the execution environment.
- Live Neo4j/RabbitMQ/Cowrie/Docker/Streamlit and PennyLane execution: not verified here.
