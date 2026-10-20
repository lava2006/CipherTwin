# CipherTwin Implementation Changelog

## Deep source-verification fixes — 2026-10-15

- Fixed `/api/risk/predict` so every valid request returns an ML prediction and device trust is read from the Digital Twin when the caller does not supply it.
- Removed the fabricated default holdout accuracy from the ML metrics endpoint; missing metadata now reports no value rather than a made-up score.
- Fixed QUBO dictionary generation to include capacity-slack variables and every non-zero upper-triangular coefficient.
- Replaced the `dimod`/`neal` classical solver with deterministic `scipy.optimize.brute` grid search over the bounded action space. Candidate solutions are evaluated against the full QUBO and checked for one-hot and decoy-capacity feasibility.
- Capped policy optimization at five units and checked the complete QUBO dimension against the 18-qubit QAOA ceiling, including slack variables.
- Connected recent analyst feedback labels to the estimated risk baseline used during optimization. This is a bounded heuristic adjustment, not model retraining and not a claim of measured accuracy improvement.
- Added shared Neo4j projection/synchronization with node/relationship counts, managed-node pruning, and an explicit `/api/twin/neo4j/sync` endpoint. Seed startup uses the same projection code.
- Added idempotent Cowrie-to-telemetry ingestion so observed Cowrie events can enter the standard pending risk pipeline; session credential values are redacted in persisted session summaries.
- Added an authenticated explicit HTTP redirect broker and a loopback-only isolated decoy web service on port 8081. It redirects only requests deliberately sent through the endpoint; transparent interception of arbitrary network traffic is not implemented.
- Updated the optimization UI, benchmark script, documentation and tests to describe the SciPy baseline accurately.
- Added regression tests for QUBO slack variables, SciPy solver feasibility, Cowrie idempotence/redaction, feedback influence, and truthful Neo4j unavailable status.

## Verification performed in this environment

- Python compilation: passed.
- Targeted tests: **20 passed**, four scikit-learn model-version warnings.
- Manual in-memory end-to-end optimization: SciPy fallback executed, feasible actions returned, and FP/FN rates remained unchanged. PennyLane absence was reported explicitly.
- Full test collection: blocked because `bcrypt` is not installed in this environment.
- Live Docker Compose, RabbitMQ, Neo4j, Cowrie, Streamlit browser behavior, frontend production build and PennyLane QAOA execution: not verified here.

## Still outstanding

- Transparent interception/rerouting of arbitrary network sessions, including SSH/Telnet.
- Automatic per-session Docker decoy-container provisioning.
- Live EDR/IAM/NetFlow adapters.
- Full test suite and live integration checks in a dependency-complete runtime.
