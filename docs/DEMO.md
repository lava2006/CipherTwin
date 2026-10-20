# CipherTwin Demo Checklist (Truthful Version)

## Before recording
1. Start the backend and required services.
2. Check `/api/system/health` and confirm each service's reported state.
3. Start the React UI and optionally the Streamlit analyst console.
4. Do not describe fixture events as live attacks. Clearly label generated data `SIMULATION`.

## Suggested demo flow
1. Sign in to the React UI.
2. Open the Digital Twin graph and show assets/relationships; explain that SQLite is authoritative and Neo4j is a graph projection when reachable.
3. Start the controlled event engine and show that generated events are synthetic.
4. Open risk analytics to inspect actual stored decisions and their explanations.
5. Open deception to show recorded sessions. Distinguish Cowrie-observed sessions from simulated decoy activity; do not claim traffic redirection.
6. Submit feedback to an existing decision using React or Streamlit and confirm it appears in the backend.
7. Run policy optimization. Report whether the returned method is `quantum` (PennyLane circuit simulation) or `classical_fallback` (SciPy discrete-grid search). Show objective and constraint validation, not a quantum-advantage claim.
8. Explain that recorded FP/FN rates are not changed by optimization alone and require labelled outcomes for remeasurement.

## Outstanding functionality
Actual high-risk network-session redirection and automatic per-session decoy container provisioning are not implemented. Do not present these as completed.
