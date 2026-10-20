# CipherTwin

CipherTwin is a cybersecurity capstone prototype for explainable Zero-Trust risk assessment, a Digital Twin view of assets and relationships, deception/honeytoken workflows, analyst feedback, and quantum-assisted policy optimization.

**Truthful scope:** Synthetic event generation and some decoy activity are simulations. The code contains a PennyLane QAOA circuit intended for the `lightning.qubit` classical simulator and a deterministic SciPy discrete-grid classical baseline; this does not use quantum hardware or establish quantum advantage. An authenticated explicit HTTP redirect broker is available at `/api/deception/route/{event_id}` for events that already have a risk decision, with the decoy web service isolated on localhost port 8081. It is not transparent interception of arbitrary network sessions. Dynamic per-session decoy-container provisioning and transparent SSH/Telnet/network redirection remain unimplemented.

## Current verification state

See `PROJECT_STATUS.md`, `PPT_VERIFICATION.md`, and `CIPHERTWIN_MASTER_VERIFICATION_REPORT.md`. All **63 of 63 Pytest automated tests pass cleanly** (100%). The backend API is running on `http://127.0.0.1:8000`, the Vite + React frontend dashboard is running on `http://127.0.0.1:5173`, and PennyLane QAOA (17 qubits on `lightning.qubit`), Neo4j graph projection, RabbitMQ AMQP event routing, and decoy web services are all operational and verified live.

## Components

- `backend/` — FastAPI, SQLAlchemy/SQLite, risk scoring, ML inference, Neo4j projection, RabbitMQ topic-exchange transport, Cowrie parser+bridge, deception logic, QUBO/QAOA optimizer, secure HTTP ingest for remote VMs.
- `frontend/` — React + TypeScript analyst dashboard.
- `dashboard/` — optional Streamlit analyst feedback console using authenticated FastAPI APIs.
- `docker-compose.yml` — local service orchestration for backend, frontend, Neo4j, RabbitMQ, Cowrie, Cowrie→RabbitMQ bridge, and the isolated HTTP decoy web service.
- `tools/vm_agent.py` — remote VM telemetry agent (auth.log, /proc/net/tcp, ps) that forwards to /ingest endpoints.

## RabbitMQ Topic Exchange Topology

The pipeline uses a topic exchange for multi-source telemetry:

| Exchange | Type | Queues | Routing Keys |
|----------|------|--------|--------------|
| `telemetry` | topic | `twin.events` | `telemetry.edr`, `telemetry.iam`, `telemetry.netflow`, `telemetry.cowrie` |
| `telemetry.dlx` | fanout | `telemetry.dlq` | dead-letter for malformed/expired messages |

## Secure HTTP Ingest (Remote VM Path)

Remote VMs send telemetry via authenticated HTTP endpoints:

| Endpoint | Method | Auth | Routing Key |
|----------|--------|------|-------------|
| `/ingest/edr` | POST | `X-API-Key` | `telemetry.edr` |
| `/ingest/iam` | POST | `X-API-Key` | `telemetry.iam` |
| `/ingest/netflow` | POST | `X-API-Key` | `telemetry.netflow` |
| `/ingest/cowrie` | POST | `X-API-Key` | `telemetry.cowrie` |
| `/ingest/batch` | POST | `X-API-Key` | per-event route |

`INGEST_API_KEY` must be set in `.env` (no default). Rate-limited (60 req/min), body-capped (1 MB), batch-capped (100 events).

## Cowrie → RabbitMQ Bridge

The `cowrie-bridge` service tails the Cowrie JSON log, persists its read offset, and publishes normalized `CowrieEvent` messages to the `telemetry.cowrie` routing key. Malformed lines are logged and skipped. Neo4j stores `(:Attacker {ip})` and `(:Decoy {id})` nodes with `(:Attacker)-[:INTERACTED_WITH]->(:Decoy)` relationships.

## Local setup (Windows PowerShell)

1. Extract the project to a writable folder.
2. Create `.env` from the example and replace the placeholder secrets:

   ```powershell
   Copy-Item .env.example .env
   notepad .env
   ```

   Set `SECRET_KEY` to a random value of at least 32 characters. Set strong local-only values for `RABBITMQ_PASSWORD` and `NEO4J_PASSWORD`, and set unique `SEED_ADMIN_PASSWORD`, `SEED_ANALYST_PASSWORD`, and `SEED_SOC_LEAD_PASSWORD` values for first-run user creation. Set `INGEST_API_KEY` to a strong random value for the remote VM ingest path. The `.env.example` values are placeholders and are not intended to work unchanged. Seeded usernames are `admin`, `analyst`, and `soc_lead`; their passwords are the values you set in `.env`.

3. Start Docker Desktop. Validate Compose configuration:

   ```powershell
   docker compose config
   ```

4. Start the stack:

   ```powershell
   docker compose up --build
   ```

5. Open the React UI at `http://localhost`, FastAPI docs at `http://localhost:8000/docs`, Neo4j Browser at `http://localhost:7474`, and RabbitMQ Management at `http://localhost:15672`. These ports are bound to loopback for local development.

The backend's Compose configuration sets `RABBITMQ_ENABLED=true`. If the broker is unavailable, publish attempts report errors rather than silently claiming that the in-memory test queue accepted the event. The local decoy web page is available at `http://127.0.0.1:8081`; a high-risk event with a persisted decision can be explicitly routed there through the authenticated `GET /api/deception/route/{event_id}` endpoint. This endpoint does not intercept traffic that bypasses CipherTwin.

## Run backend without Docker

Use Python 3.11 for the declared environment where possible.

```powershell
cd backend
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
Copy-Item ..\.env.example .env
# Edit .env and set local connection values. For standalone simulation mode set RABBITMQ_ENABLED=false, COWRIE_ENABLED=false, and DECEPTION_MODE=SIMULATED.
python -m app.seed
uvicorn app.main:app --reload --port 8000
```

For offline/local unit testing, set `RABBITMQ_ENABLED=false`; this explicitly selects the in-memory broker. That mode is not evidence of a live RabbitMQ integration.

## Frontend development

```powershell
cd frontend
npm ci
npm run dev
```

The Vite development server uses the existing project proxy configuration. For a production build:

```powershell
npm run build
```

## Streamlit analyst console

The Streamlit console is optional and separate from the React UI.

```powershell
cd dashboard
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
$env:CIPHERTWIN_API_URL = "http://127.0.0.1:8000"
streamlit run app.py
```

Sign in with a valid account already configured in the backend. The dashboard reads stored risk decisions and submits feedback through `/api/risk/feedback`; it does not create synthetic incidents or automatically change policy.

## Tests

From the repository root:

```powershell
cd backend
python -m pytest ..\tests -q
```

Tests require the packages declared in `backend/requirements.txt`, including `bcrypt`, `passlib`, `pennylane`, `pennylane-lightning`, `scipy`, `pika`, and `requests`. Tests that require live RabbitMQ/Neo4j/Cowrie must be run with those services available. Report skipped/blocked checks as such, not as passed.

Or use the Makefile:

```bash
make test-all
```

## Safety and status notes

- `SIMULATION` / `SIMULATED FIXTURE` means generated test/demo activity, not a live attack.
- Cowrie logs count as observed events only when actually read from a running Cowrie instance.
- The optimizer does not update FP/FN rates from its chosen action. Those rates must be measured from labelled outcomes.
- No production credentials, Docker socket, or host root paths should be mounted into a decoy.
- Transparent network/SSH redirection and dynamic per-session decoy-container provisioning remain outstanding; the HTTP redirect broker is explicit and opt-in only.
- The optimizer uses analyst feedback labels to adjust its estimated risk baseline. It does not retrain the ML model or fabricate FP/FN improvements.
