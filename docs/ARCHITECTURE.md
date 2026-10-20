# CipherTwin Architecture (Current Code)

## Runtime path

1. The controlled event engine can generate synthetic test events on demand.
2. The telemetry pipeline validates and transports events. `RABBITMQ_ENABLED=true` selects the AMQP transport via `pika`; `false` explicitly selects the in-memory broker for local tests.
3. The risk engine combines the project's risk rules and ML inference.
4. Risk decisions, telemetry, audit entries, and analyst feedback are stored in SQLite.
5. The graph layer updates the SQLite-backed Digital Twin and attempts a projection into Neo4j through the HTTP transactional API.
6. Risky events may create application-level decoy/honeytoken records. `simulate_activity` is simulated behaviour, not network redirection.
7. The QUBO builder encodes action selection; the PennyLane `lightning.qubit` QAOA path simulates a parameterized quantum circuit on classical hardware. `scipy.optimize.brute` exhaustively evaluates the bounded action grid as the classical baseline/fallback.
8. The React UI and optional Streamlit console read or update backend API data.

## Service boundaries

- **FastAPI:** Authentication, events, telemetry, risk, policy, deception, twin, audit, optimization.
- **SQLite:** Authoritative application state for the current prototype.
- **Neo4j:** Optional graph projection. Health status means connectivity, not proof every graph write succeeded.
- **RabbitMQ:** Real durable AMQP queues when enabled. The in-memory broker is only for explicit local test mode.
- **Cowrie:** Isolated local honeypot service and JSON log source. A configured container does not mean traffic is automatically redirected to it.
- **PennyLane:** Classical quantum-circuit simulator; no quantum hardware or quantum advantage claim.
- **Streamlit:** Optional analyst-feedback console; uses authenticated FastAPI endpoints.

## Explicit limitations

- No live network proxy/routing component redirects high-risk user sessions into decoys.
- No orchestrator provisions an isolated decoy container for each session.
- Policy optimizer changes policy weights/actions but does not fabricate improvements to false-positive/false-negative rates.
- External service connectivity and production frontend build require verification in the target environment.
