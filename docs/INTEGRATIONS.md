# Integration and Verification Notes

## RabbitMQ
- Enable with `RABBITMQ_ENABLED=true`.
- The AMQP transport uses `pika`, declares durable primary and DLQ queues, publishes persistent JSON messages, waits for publisher confirmation, and acknowledges consumed messages after successful database processing.
- Processing failures are republished with an incremented retry counter; after the retry limit, they are routed to the DLQ.
- If live mode is enabled and the broker is unavailable, publishing reports failure. It does not silently enqueue in the in-memory test broker.
- `RABBITMQ_ENABLED=false` is local test mode only.
- Live broker integration has not been executed in this environment.

## Neo4j
- Uses `NEO4J_URL`, `NEO4J_USER`, and `NEO4J_PASSWORD` for the transactional HTTP API.
- SQLite remains the authoritative store. Seed startup uses the shared full graph projection, and an authenticated `POST /api/twin/neo4j/sync` endpoint can resynchronize nodes and relationships explicitly.
- Projection results report node/relationship counts and errors. Only nodes marked `ciphertwin_managed` are considered for stale-node cleanup; unrelated nodes are preserved.
- A reachable Neo4j service is not proof of synchronization; inspect the returned sync status and counts.

## Cowrie
- `COWRIE_LOG_PATH` must point to Cowrie's JSON log file.
- In Compose, Cowrie is on an `internal: true` DMZ network and the backend is deliberately not attached to that network; the backend receives the log volume read-only. Consequently, the backend can report log availability without claiming it independently verified the Cowrie SSH socket.
- The sample fixture generator is explicitly simulated and uses reserved TEST-NET addresses.
- Cowrie records are inserted idempotently into the pending telemetry pipeline so they can be processed by the standard risk/audit workflow. The backend receives the Cowrie log volume read-only.
- A running Cowrie container does not itself implement SSH/Telnet redirection from the protected app to the honeypot.

## Quantum optimization
- QUBO decisions are encoded into a PennyLane cost Hamiltonian and evaluated by the `lightning.qubit` simulator when the dependencies work.
- This is a classical simulation of a quantum circuit, not quantum hardware.
- The SciPy discrete-grid baseline/fallback is classical and deterministic for the bounded policy batch; the complete QUBO, including capacity slack variables, is evaluated.
- Recent analyst feedback labels adjust the estimated risk baseline for optimization using a bounded heuristic. They do not retrain the ML model or prove accuracy improvements.
- Optimizer-selected actions do not justify changing FP/FN metrics. The code preserves those values pending new labelled outcome measurements.

## Streamlit
- Install `dashboard/requirements.txt`.
- Set `CIPHERTWIN_API_URL` (defaults to `http://127.0.0.1:8000`).
- Sign in through the existing API; feedback is persisted by `/api/risk/feedback`.

## Explicit HTTP decoy redirect
- `GET /api/deception/route/{event_id}` checks a processed risk decision and issues a 307 redirect only when the score meets the configured threshold.
- `decoy-web` runs on an isolated Docker network and is published only to `127.0.0.1:8081`.
- This is not transparent interception; arbitrary HTTP sessions and SSH/Telnet traffic that bypass the route are not redirected. Per-session container provisioning is not implemented.
