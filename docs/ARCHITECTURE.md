# CipherTwin – Architecture

## High-level overview

CipherTwin is split into two independently deployable artefacts:

- **Backend** (`backend/`) – FastAPI service exposing a JSON API, running
  the simulation pipeline, and persisting state to SQLite.
- **Frontend** (`frontend/`) – React 18 + Vite SPA that talks to the API
  over JWT-authenticated HTTP.

Both are orchestrated by `docker-compose.yml`. A Neo4j container is
included for the graph layer; the MVP works fully against SQLite so the
Neo4j container is optional.

## Backend layout

```
backend/app/
  api/         - FastAPI routers (one per resource)
  core/        - settings (pydantic-settings), JWT helpers
  db/          - SQLAlchemy engine/session
  models/      - ORM models for users, twin nodes, telemetry, risk, etc.
  schemas/     - Pydantic v2 request/response models
  services/    - business logic: risk engine, deception, threat intel, QAOA
  workers/     - background telemetry + risk pipeline
  deps.py      - shared dependencies (JWT guard, admin guard)
  main.py      - app factory + lifespan (seeds DB, starts worker)
  seed.py      - idempotent demo data
```

### Simulation pipeline

`workers/pipeline.py` runs a daemon thread that, every
`TELEMETRY_INTERVAL_SECONDS` (default 2.5 s), does:

1. `TelemetrySimulator.generate_one()` – emits a synthetic EDR event
   biased toward attack patterns ~18% of the time.
2. `ZeroTrustEngine.evaluate(event)` – produces a weighted risk score,
   decision, and factor breakdown.
3. `engine.persist(event, result)` – writes the `RiskDecision` and its
   `RiskFactor` rows.
4. If `risk_score >= 60`:
   - `ThreatIntel.correlate(event, ...)` – creates or updates a `Threat`
     actor with MITRE techniques.
   - `DeceptionEngine.open_decoy(...)` – opens a decoy session and seeds
     it with a small amount of attacker activity.
   - `audit.log_event(... severity=warning)` – writes to the audit log.

The worker is started during the FastAPI `lifespan` startup.

### Zero Trust risk engine

`services/risk_engine.py` implements five weighted factors:

| Factor | Weight | Description |
|---|---|---|
| Identity confidence | 20% | Failed logins, brute force, impossible travel, credential stuffing. |
| Behaviour deviation | 30% | Privilege escalation, PowerShell, abnormal process, lateral movement, exfiltration, off-hours, sensitive resource. |
| Device posture | 20% | Trust score, status, OS, USB insertion, unsigned binary. |
| Location anomaly | 10% | Anonymous networks, high-risk geos, VPN, impossible travel. |
| Previous history | 20% | Recent failures, prior sensitive resource access for the same principal. |

Decision thresholds (configurable in `app/core/config.py`):

- `< 30` → `allow`
- `30 – 59` → `restricted`
- `60 – 84` → `deceive` (redirect to decoy)
- `>= 85` → `deny`

Confidence is `100 − pvariance(factor_scores)` clamped to `[40, 99]`,
intuitively: the more the factors agree, the higher the confidence.

### Adaptive deception

`services/deception.py` exposes:

- `seed_honeytokens()` – plants a curated set of fake credentials, files,
  API keys and cookies across the digital twin.
- `open_decoy(actor, source_ip, threat_id, decoy_type)` – creates a
  `DecoySession` (SSH / database / web / admin_panel).
- `simulate_activity(session)` – pretends the attacker is doing things
  while we record them.
- `trigger_honeytoken(value)` – marks a planted token as triggered when
  it shows up in telemetry.

### Threat intelligence

`services/threat_intel.py` correlates risky events to long-lived
`Threat` actors. Mapping table (`EVENT_TO_MITRE`) translates observed
behaviour to MITRE ATT&CK technique IDs. Each threat also has a
`tactics_breakdown()` helper that returns the human-readable grouping
(Initial Access, Execution, Persistence, etc.).

### Quantum policy optimization

`services/quantum_optimizer.py` runs a *simulated* QAOA optimization:

1. Build a classical cost function combining risk score, FP, FN and
   policy weight imbalance.
2. Sweep the QAOA angles `gamma`, `beta` over `p` layers classically,
   accepting any candidate that reduces the cost.
3. Persist new policy weights and emit a `PolicyImprovement` row
   capturing before/after metrics.

Even though this is purely classical, the API surface mimics what a real
QAOA run would look like: `p` parameter, classical `numpy.linalg`
backend, depolarizing noise model, animation-friendly progress.

## Frontend layout

```
frontend/src/
  components/
    ui/          - shadcn-style primitives (Button, Card, Badge, ...)
    Layout/      - Sidebar, Topbar, DashboardLayout
    *.tsx        - feature components (KpiCard, NetworkGraph, ...)
  contexts/      - AuthContext (JWT, login, logout, bootstrap)
  hooks/         - useApi, usePolling
  lib/           - api client, types, utils
  pages/         - one file per dashboard view
  App.tsx        - router + auth guard
  main.tsx       - entry
  index.css      - Tailwind + design tokens
```

### Visual language

- **Palette**: cyber-blue (#1f8ef1), cyber-cyan (#22d3ee), accent violet
  (#8b5cf6) on slate base. Defined in `tailwind.config.js`.
- **Typography**: Inter for body, JetBrains Mono for technical text.
- **Surface**: subtle glassmorphism (`backdrop-filter`) with cyan-tinted
  borders and shadows. `animated-grid` adds a faint dot grid background.
- **Motion**: Recharts for data; `animate-fade-in`, `animate-pulse2`,
  and `animate-glow` for the static UI.

### Routing

`App.tsx` defines the following routes (all behind the `<Protected>`
guard except `/login`):

| Path | Page |
|---|---|
| `/login` | LoginPage |
| `/dashboard` | OverviewPage |
| `/twin` | NetworkTwinPage |
| `/telemetry` | TelemetryPage |
| `/access-requests` | AccessRequestsPage |
| `/risk` | RiskAnalyticsPage |
| `/threats` | ThreatsPage |
| `/deception` | DeceptionPage |
| `/optimization` | OptimizationPage |
| `/policies` | PoliciesPage |
| `/audit` | AuditPage |
| `/explainer` | ExplainerPage |
| `/settings` | SettingsPage |

## Why a digital twin?

The Digital Twin is the source of truth for everything: device trust,
identity posture, sensitivity, OS, location, and trust relationships
between assets. By grounding every risk decision on twin state, the
system can:

- Reduce blind spots (no asset without context).
- Trace any decision back to its origin node.
- Provide a single graph analysts can navigate during incidents.

The `GraphStore` interface (`services/graph.py`) keeps the persistence
choice pluggable – today SQLite, tomorrow Neo4j via the same async API.
