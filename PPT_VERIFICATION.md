# CipherTwin PPT ↔ Implementation Verification

Source deck: `CipherTwin_Capstone.pptx`

## Result

The supplied deck describes a broader architecture than the executable MVP. The implementation audit found that the core CipherTwin workflow is present, but several named technologies in the original Tech Stack slide were not actually used by the code.

The verified deck therefore distinguishes **implemented**, **ready/optional**, and **future integration** components instead of making unsupported claims.

## Slide-by-slide verification

### Abstract
**Supported core:** Digital Twin abstraction, explainable Zero-Trust scoring, adaptive deception simulation, threat intelligence, and policy optimization are represented in code.

**Correction:** the implementation does not execute QAOA through PennyLane. The optimizer is a classical QAOA-inspired simulation. The verified wording states this explicitly.

### Problem Statement
The listed limitations are consistent with the intended research motivation. They are problem claims rather than implementation claims.

### Proposed Solution
- Digital Twin: implemented as a SQLite-backed `GraphStore` abstraction.
- Explainable Zero-Trust scoring: implemented in `risk_engine.py`.
- Adaptive deception: implemented as a simulated decoy/honeytoken engine.
- Threat intelligence / MITRE: implemented.
- Quantum policy optimization: implemented as a classical QAOA-inspired simulation.
- Jinja2 natural-language explanation templates: implemented.
- Random Forest + Isolation Forest: implemented and integrated into live risk evaluation.

### Architecture
The executable data path is:

`Telemetry simulator → Risk Engine → ML inference → Risk decision → Deception/Threat Intelligence → SQLite → React dashboard`

The graph layer is replaceable and Neo4j-ready, but SQLite remains the active MVP store.

## Tech Stack audit

| Technology / method | Evidence in source | Status |
|---|---|---|
| Python | backend source | Implemented |
| FastAPI | `backend/app/main.py` and routers | Implemented |
| SQLAlchemy | database/session/models | Implemented |
| SQLite | active database configuration | Implemented |
| React / TypeScript / Vite | frontend source | Implemented |
| Tailwind / Recharts / Axios | frontend dependencies/source | Implemented |
| Docker / Compose | Dockerfiles + compose | Implemented |
| Weighted Zero-Trust risk function | `services/risk_engine.py` | Implemented |
| Random Forest | `ml/train_models.py` + inference | Implemented |
| Isolation Forest | `ml/train_models.py` + inference | Implemented |
| Digital Twin graph abstraction | `services/graph.py` | Implemented |
| Neo4j | compose service only; no backend driver/use | Optional / ready |
| Adaptive deception | `services/deception.py` | Implemented as simulation |
| Honeytokens | deception service | Implemented as simulation |
| MITRE ATT&CK mapping | MITRE service + seeded techniques | Implemented |
| Jinja2 | risk explanation template | Implemented |
| RabbitMQ | no source/dependency | Not implemented |
| Cowrie | no source/dependency | Not implemented |
| PennyLane | no source/dependency | Not implemented |
| Literal QUBO + PennyLane QAOA | optimizer is classical simulation | Not implemented literally |
| SciPy optimizer | no dependency/use in optimizer | Not implemented |
| Streamlit | no source/dependency | Not implemented |

## ML verification

The Random Forest is trained with:
- 15,000 domain-grounded synthetic events
- deterministic seed 42
- 80/20 stratified split
- class weighting
- 350 trees
- maximum depth 14
- minimum leaf size 4

Held-out results:
- Accuracy: 82.33%
- Macro precision: 75.50%
- Macro recall: 77.28%
- Macro F1: 75.67%
- Macro ROC-AUC (one-vs-rest): 92.80%

These metrics are synthetic-data benchmark results only.

## Frontend preservation

No existing frontend source file was modified for the Random Forest integration. The backend response remains compatible with the existing dashboard, while the new `/api/risk/predict` endpoint is available for direct ML verification.

## Known implementation bug fixed

The original telemetry simulator searched for `TwinNode.type == "device"`, while the seeded workstation records use `laptop`, `desktop`, and `tablet`. This prevented the background telemetry pipeline from generating events. The simulator now accepts those actual workstation types.

## Verification conclusion

**Core project:** implemented and ML-integrated.

**Original PPT as written:** not fully compliant because RabbitMQ, Cowrie, PennyLane, literal QUBO/SciPy optimization, and Streamlit were claimed without implementation evidence.

**Verified PPT:** corrected to accurately describe the executable MVP and explicitly label future/integration-ready technologies.
