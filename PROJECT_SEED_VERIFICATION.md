# Seed Data Provenance

Seeded telemetry, risk decisions, threat actors, and Cowrie fixtures are demonstration/test records, not evidence of real attacks.

Changes made in this working copy:
- Seeded telemetry stores `{"seed": true, "source": "SIMULATION", "simulation": true}` in its raw payload.
- Generated event-engine telemetry stores `source=SIMULATION` and `simulation=true`.
- Generated IPs use the reserved documentation range `198.51.100.0/24`; seeded threat examples use TEST-NET ranges.
- Cowrie fixture events are explicitly described as simulated and use reserved TEST-NET IP addresses.
- Seeded optimizer history with fabricated FP/FN improvements has been removed. Optimization history is created only after an actual optimizer run.
- The seed routine no longer adds an audit event claiming a false-positive reduction.

Existing databases that were already seeded may still contain old demo rows. Use a fresh test database if you need to verify the corrected seed behavior. Do not delete a user's existing database without a backup.
