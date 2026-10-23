# CipherTwin & CipherGuide Engineering Guidelines

## Architecture Overview
CipherTwin combines five core defense capabilities:
1. **Digital Twin**: Neo4j graph of hosts, users, credentials, and topology relationships.
2. **Explainable Zero-Trust Engine (EZTE)**: Risk scoring across identity confidence, device posture, behavioral deviation, resource sensitivity, location anomalies, and history.
3. **Adaptive Cyber Deception Engine (ACDE)**: Decoys and honeytokens at high/medium/low fidelity with Cowrie honeypot integration.
4. **Quantum-Assisted Policy Re-optimization (QAPRE)**: QUBO solved with QAOA in PennyLane (`lightning.qubit`) and SciPy classical baseline.
5. **CipherGuide**: Grounded, beginner-friendly explainable assistant featuring 3 Audience Lenses (Simple, Manager, Analyst), in-memory Twin Forecast (Impact Preview), Trust Receipts, and Guarded Actions.

## Terminology Conventions (Global Rule)
Do NOT use forbidden terms:
- `simulation`, `simulate`, `simulated`, `simulator`, `mock`, `fake`, `dummy`
Approved terms:
- `telemetry generator`, `telemetry feed`, `Scenario Replay`, `Twin Forecast`, `Impact Preview`, `decoy`, `lab network`.

## Free-Model Provider Order
1. `xai` (Grok via OpenAI-compatible SDK)
2. `ollama` (Local model, default qwen2.5:7b)
3. `offline` (Jinja2 templates with grounded tool evidence)

## In-Memory Twin Forecast Invariant
The chatbot NEVER writes to or mutates the live Neo4j graph during what-if analysis. It operates exclusively on an in-memory subgraph copy.
