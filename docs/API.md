# CipherTwin – API Reference

Base URL: `http://localhost:8000/api` (default).
OpenAPI/Swagger: `http://localhost:8000/docs`.
All endpoints except `auth/login` and `health` require a JWT in the
`Authorization: Bearer <token>` header.

## Auth

### POST /auth/login
Body: `{ "username": "admin", "password": "admin123" }`
Response: `{ "access_token": "...", "token_type": "bearer", "user": { ... } }`

### GET /auth/me
Returns the current user.

### POST /auth/logout
Records the logout in the audit log.

## Digital twin

### GET /twin/graph
Full graph payload:
```json
{
  "nodes": [ { "id": "u-alice", "label": "Alice Nguyen", "type": "user", ... } ],
  "edges": [ { "source": "u-alice", "target": "d-laptop-001", "relation": "uses" } ]
}
```

### GET /twin/nodes?type=user
List twin nodes optionally filtered by type (`user|device|server|database|application|iot`).

### GET /twin/stats
Summary counts (`online`, `offline`, `compromised`, etc.).

### POST /twin/heartbeat?node_id=d-laptop-001
Mark a node as online (analyst-initiated).

## Telemetry

### GET /telemetry?event_type=failed_login&search=tor&page=1&page_size=50
Paginated, filterable telemetry stream.

### GET /telemetry/event-types
Distinct event types + counts.

## Risk

### GET /risk/decisions?decision=deceive&page=1&page_size=50
Paginated risk decisions.

### GET /risk/decisions/{id}
Single decision with full factor breakdown.

## Policies

### GET /policies
List all Zero Trust policies.

### GET /policies/{id}
Single policy.

### PATCH /policies/{id}
Admin-only. Body: `{ "enabled": 1, "weight": 1.1, "priority": 100 }`.

## Threats

### GET /threats
List correlated threat actors.

### GET /threats/{id}
Single threat + `tactics` breakdown keyed by MITRE tactic.

## Deception

### GET /deception/sessions
List of decoy sessions with recorded commands and pages.

### GET /deception/honeytokens
List of planted honeytokens.

### POST /deception/seed
Plant the default honeytoken set (idempotent).

### POST /deception/trigger/{token_id}
Mark a token as triggered (simulate attacker use).

## Optimization

### GET /optimization/state
Current policy weights, average FP/FN.

### POST /optimization/run
Body: `{ "layers": 3, "iterations": 40 }` (defaults shown).
Runs a simulated QAOA optimization and returns before/after metrics plus
the per-policy weight deltas.

### GET /optimization/history?limit=20
Recent QAOA runs.

## Analytics

### GET /analytics/overview
Top-level KPIs (online/offline devices, sessions, risks, threats,
decoys, policies) plus the `risk_trend`, `telemetry_by_type`,
`top_attacked`, and `top_risky_users` series consumed by the dashboard.

### GET /analytics/risk-distribution
Histogram of risk scores in 20-point buckets.

### GET /analytics/threat-categories
Histogram of MITRE techniques per threat actor.

### GET /analytics/attack-heatmap
7-day x 24-hour grid of telemetry volume.

### GET /analytics/optimization-timeline
Score evolution across optimization runs.

### GET /analytics/telemetry-volume
Hourly telemetry volume for the last 24 hours.

### GET /analytics/pipeline-status
Live counters for the background pipeline.

## Audit

### GET /audit?severity=warning&action=login
Filterable, paginated audit log.

## MITRE

### GET /mitre
Static reference catalog of MITRE ATT&CK techniques used by the threat engine.

## Errors

The API uses standard HTTP status codes. All error responses include a
JSON body of the form `{ "detail": "..." }`.

Common cases:

| Status | Meaning |
|---|---|
| 401 | Missing or invalid JWT |
| 403 | Authenticated but missing the required role |
| 404 | Resource not found |
| 422 | Pydantic validation failed |
| 500 | Unhandled server error |

## Pagination

List endpoints accept `page` (1-indexed) and `page_size` (max 500) and
return `{ total, page, page_size, items }`.
