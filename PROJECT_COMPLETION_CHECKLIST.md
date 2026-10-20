# Completion Checklist — Current Source Tree

- [x] Risk prediction control flow fixed to return a result for every valid request; device trust is read from the twin if available.
- [x] QUBO dictionary includes capacity slack variables and all non-zero upper-triangular terms.
- [x] SciPy discrete-grid baseline/fallback evaluates the complete QUBO and validates feasibility.
- [x] Default policy batch bounded to five units and QAOA qubit limit checked against full QUBO dimensions.
- [x] Analyst feedback labels adjust the estimated risk baseline used by the optimizer.
- [x] Cowrie events enter the pending telemetry pipeline with stable idempotency keys; credentials are redacted in session summaries.
- [x] Shared Neo4j projection routine syncs nodes and relationships and prunes only stale CipherTwin-managed nodes; explicit sync endpoint available.
- [x] Controlled HTTP redirect broker and isolated loopback-only decoy web service added.
- [x] Regression tests added for QUBO slack variables, SciPy solver feasibility, Cowrie idempotence/redaction, feedback influence, and Neo4j unavailable status.
- [ ] Transparent interception/rerouting of arbitrary network and SSH/Telnet sessions.
- [ ] Automatic per-session Docker decoy container provisioning.
- [ ] Live EDR/IAM/NetFlow source adapters.
- [ ] Full test suite in a dependency-complete environment (`bcrypt` missing in this environment).
- [ ] Live Docker Compose, RabbitMQ, Neo4j, Cowrie, Streamlit and frontend production-build verification.
- [ ] PennyLane QAOA execution verification in an environment with `pennylane` and `pennylane-lightning` installed.

See `PPT_VERIFICATION.md` for the source-based PPT mapping and exact verification state.
