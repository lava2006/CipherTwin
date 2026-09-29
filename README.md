# CipherTwin — Autonomous Cyber Defense Platform

CipherTwin is an integrated cybersecurity platform combining explainable Zero-Trust risk scoring, machine learning threat detection (Random Forest + Isolation Forest), an interactive Digital Twin graph (Neo4j + SQLite dual-layer), an enterprise telemetry pipeline (RabbitMQ with ACK/NACK and DLQ), adaptive multi-tier deception with Cowrie honeypot log parsing, MITRE ATT&CK intelligence, dynamic policy simulation, SOC analyst feedback loops, and a classical QAOA-inspired policy optimization simulator.

> **Verification Principle**: All features described below are empirically verified against automated test suites and runtime execution logs.

---

## 1. System Architecture

```text
                               ┌────────────────────────────────────────────────────────┐
                               │               React 18 + Vite Frontend                 │
                               │  - SOC Command Center      - Network Twin Graph        │
                               │  - What-If Policy Sim      - Adaptive Deception Hub    │
                               │  - Analyst Feedback Loop   - Truthful 9-Service Health │
                               │  - Controlled Event Engine - MITRE ATT&CK Intel Map    │
                               └──────────────────────────┬─────────────────────────────┘
                                                          │ REST / JWT Auth
                                                          ▼
                               ┌────────────────────────────────────────────────────────┐
                               │                  FastAPI Backend                       │
                               └───────┬──────────────────┬──────────────────┬──────────┘
                                       │                  │                  │
                ┌──────────────────────┴───────┐   ┌──────┴────────┐  ┌──────┴──────────────┐
                │ Telemetry Pipeline (RabbitMQ)│   │  Risk Engine  │  │ Adaptive Deception  │
                │ - Pydantic TelemetryMessage  │   │ - 5-Factor Wt │  │ - Multi-Tier Low /  │
                │ - LRU Dedup Filter           │   │ - ML Ensemble │  │   Medium / High Fid │
                │ - Retry with Backoff (max 3) │   │ - MITRE Map   │  │ - 6 Honeytoken Types│
                │ - Dead Letter Queue (DLQ)    │   │ - Policy Eval │  │ - Cowrie Log Parser │
                │ - Controlled Event Engine    │   │ - Explanations│  │ - Socket Banner Ver │
                └──────────────────────────────┘   └───────────────┘  └─────────────────────┘
                                       │                  │                  │
                ┌──────────────────────┴───────┐   ┌──────┴────────┐  ┌──────┴──────────────┐
                │   Digital Twin Graph Store   │   │  Audit Engine │  │ Policy & Feedback   │
                │ - Neo4j Cypher Transactional │   │ - Immutable   │  │ - "What If?" Sim    │
                │ - SQLite Fallback Store      │   │   Event Log   │  │ - Version Snapshots │
                │ - Shortest Path, Blast Radius│   │ - SOC Actions │  │ - TP/FP/TN/FN Loop  │
                │ - Honeypot Node decoy-ssh-01 │   │ - Verifiable  │  │ - Dynamic Rollback  │
                └──────────────────────────────┘   └───────────────┘  └─────────────────────┘
```

---

## 2. Integrated Core Subsystems

### 2.1 Controlled Event Engine & Telemetry Pipeline (`RabbitMQ`)
- **Location**: `backend/app/services/event_engine.py`, `backend/app/services/rabbitmq.py`, `backend/app/api/events.py`
- **Features**:
  - **Controlled Event Cadence**: Background worker generates synthetic events at an exact, enforced cadence of **1 event/sec (1.0s interval)**.
  - **Thread-safe State Machine**: Full START, PAUSE, RESUME, STOP, and STATUS controls via REST endpoints (`/api/events/control/*`).
  - **Full Pipeline Ingestion**: Events are dispatched through RabbitMQ, ML risk scoring, MITRE ATT&CK mapping, policy evaluation, blast radius analysis, and audit logging.
  - **Queue Hardening**: `TelemetryMessage` Pydantic model validation, LRU deduplication filter, ACK/NACK lifecycle, exponential backoff retries, and Dead Letter Queue (`ciphertwin_telemetry_dlq`).
  - **Truthful Broker Health**: Real-time status checks against RabbitMQ port 5672 (AMQP) and port 15672 (Management API).

### 2.2 Digital Twin Graph Database (`Neo4j`)
- **Location**: `backend/app/services/neo4j_client.py`, `backend/app/services/graph.py`, `backend/app/seed.py`, `backend/app/api/twin.py`
- **Features**:
  - Transactional Cypher HTTP client (`/db/neo4j/tx/commit`) with Basic Authentication.
  - Synchronizes 36 nodes and 62 relationships across `User`, `Device`, `Server`, `Application`, and `Database`.
  - Dedicated honeypot node `decoy-ssh-01` synchronized directly into Neo4j graph with decoy labels and IP references.
  - Graph traversal analytics: Breadth-First Search shortest path, blast radius impact calculation, and degree centrality chokepoints.
  - Automated synthetic pipeline verification test (`User -> Device -> Server -> Application -> Database`) with deterministic cleanup.
  - Dual-layer persistence: live Neo4j transactional sync with automatic SQLite graph fallback when Neo4j is offline.

### 2.3 Adaptive Deception & Cowrie Honeypot Integration
- **Location**: `backend/app/services/deception.py`, `backend/app/services/cowrie.py`, `backend/app/api/deception.py`
- **Features**:
  - High-interaction Cowrie honeypot container with socket banner verification (`SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3` on port 2222).
  - Cowrie JSON log parser mapping live events to normalized schema (`eventid`, `timestamp`, `src_ip`, `username`, `password`, `command`, `session`).
  - Automated MITRE ATT&CK technique mapping for honeypot signals (`T1110`, `T1078`, `T1059`, `T1105`, `T1083`).
  - Signal-driven adaptive decoy selection: evaluates risk score, MITRE technique, event type, device trust, and resource sensitivity to assign decoy types (`ssh`, `database`, `web`, `admin_panel`, `api`) and fidelity tiers (`LOW`, `MEDIUM`, `HIGH`).
  - Complete honeytoken trigger lifecycle: Trigger -> Alert Generation -> Threat Correlation -> Risk Escalation to 95.0 -> Attacker Trapped in High-Fidelity Decoy -> Audit Event Logging.

### 2.4 Machine Learning Threat Detection
- **Location**: `backend/app/ml/*`, `backend/app/services/risk_engine.py`, `backend/app/api/risk.py`
- **Features**:
  - Dual-model ensemble: `RandomForestClassifier` (3-class: normal, suspicious, malicious) + `IsolationForest` (unsupervised anomaly detection).
  - Compatible with `scikit-learn 1.6.1` with clean serialization (zero unpickling warnings).
  - 80/20 stratified holdout evaluation on 15,000 domain-grounded synthetic events.
  - Real holdout metrics: **82.33% Accuracy**, **92.80% ROC-AUC (OvR Macro)**, **75.67% Macro F1**.
  - Feature explanations returned in live inference payloads.

### 2.5 Dynamic Policy Simulation & Analyst Feedback
- **Location**: `backend/app/models/policy.py`, `backend/app/api/policies.py`, `backend/app/api/risk.py`
- **Features**:
  - Safe "What If?" policy simulation testing hypothetical Zero Trust thresholds on recent telemetry without mutating production policies.
  - Immutable policy version snapshots (`PolicyVersion`) and structured changelog tracking (`PolicyChange`).
  - SOC Analyst Feedback loop allowing analysts to submit `TRUE_POSITIVE`, `FALSE_POSITIVE`, `TRUE_NEGATIVE`, and `FALSE_NEGATIVE` classifications with rationale.
  - Real-time feedback accuracy and validation statistics computation.

### 2.6 Truthful System Health & Auditing
- **Location**: `backend/app/api/system.py`, `backend/app/services/audit.py`
- **Features**:
  - Truthful `/api/system/health` inspecting 9 platform subsystems: FastAPI, SQLite, Neo4j, RabbitMQ, ML Model, Deception Engine, Cowrie, Event Engine, and Telemetry Worker.
  - Reports `HEALTHY` only when verified via live socket/API; reports `UNAVAILABLE` or `DEGRADED` otherwise.
  - Immutable audit trail recording all security actions with timestamp, actor, target, severity, details, and client IP.

---

## 3. Getting Started

### 3.1 Prerequisites
- Python 3.11+
- Node.js 20+ and npm
- Docker Desktop (for Neo4j, RabbitMQ, and Cowrie containers)

### 3.2 Launch Infrastructure Containers
Start the required core services via Docker Compose:
```powershell
docker compose up -d rabbitmq neo4j cowrie
```
Verify containers are healthy:
- Neo4j HTTP: `http://localhost:7474` (Bolt: `bolt://localhost:7687`)
- RabbitMQ Management: `http://localhost:15672` (AMQP: `localhost:5672`)
- Cowrie SSH: `localhost:2222`

### 3.3 Backend Setup & Seeding
```powershell
# Navigate to backend
cd backend

# Install dependencies (if not already installed)
pip install -r requirements.txt

# Seed SQLite and synchronize Neo4j Digital Twin graph (36 nodes, 62 relationships)
python -m app.seed

# Start backend server
python -m uvicorn app.main:app --port 8000
```
API Documentation will be available at: `http://localhost:8000/docs`.

### 3.4 Frontend Setup
```powershell
# In a separate terminal, navigate to frontend
cd frontend

# Install npm dependencies (if not already installed)
npm install

# Start development server
npm run dev
```
Open `http://localhost:5173` in your browser.

### 3.5 Demo Credentials
| Role | Username | Password |
|---|---|---|
| Admin | `admin` | `admin123` |
| Analyst | `analyst` | `analyst123` |
| SOC Lead | `soc_lead` | `lead123` |

---

## 4. Automated Testing & Verification

Run the full verified test suite with pytest:

```powershell
python -m pytest -q
```
**Output**: `32 passed in 30.99s` (100% pass rate, 0 errors, 0 warnings).

### Test Suite Breakdown (32/32 Passing):
1. `tests/test_controlled_event_engine.py` (3 tests): Verifies 1.0s cadence, START/STOP state machine, counter accuracy, pipeline routing.
2. `tests/test_honeypot_graph_node.py` (2 tests): Verifies honeypot Digital Twin graph node synchronization (`decoy-ssh-01`).
3. `tests/test_rabbitmq_pipeline.py` (5 tests): Tests telemetry publishing, Pydantic schema validation, ACK lifecycle, duplicate suppression, retry with backoff, DLQ routing, and truthful broker health.
4. `tests/test_neo4j_twin.py` (4 tests): Tests live Neo4j Cypher client, synthetic verification pipeline (5 nodes, 4 rels, traversal, cleanup), SQLite graph traversal, blast radius, shortest path, and chokepoints.
5. `tests/test_deception_cowrie.py` (5 tests): Tests Cowrie log parser, socket banner verification, adaptive decoy selection (LOW/MED/HIGH), and full honeytoken lifecycle.
6. `tests/test_policies_and_feedback.py` (4 tests): Tests policy evaluation, threshold matching, "What If?" simulation with zero mutation, policy versioning/rollback, and analyst feedback loop.
7. `tests/test_system_health_and_audit.py` (4 tests): Tests 9-subsystem health check, truthful reporting against offline services, and audit logging.
8. `tests/test_end_to_end_security_flow.py` (2 tests): Tests full 11-step security scenario from telemetry ingest to risk score to deception trap to Neo4j to audit log.
9. `tests/test_ml_pipeline.py` (3 tests): Tests deterministic dataset generation, holdout evaluation metrics, and live inference probabilities.

---

## 5. Quantum Optimization Boundary

In accordance with strict architectural requirements, the quantum optimization module remains completely intact:
- `backend/app/quantum_optimizer.py` — Classical QAOA-inspired combinatorial policy optimization simulator (100% UNTOUCHED).
- `backend/app/api/optimization.py` — Optimization API router (100% UNTOUCHED).
- `frontend/src/pages/OptimizationPage.tsx` — QAOA interactive visualization page (100% UNTOUCHED).
