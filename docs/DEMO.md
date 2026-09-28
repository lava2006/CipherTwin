# CipherTwin – Demo Walkthrough

This script walks an analyst (or an evaluator) through every screen of the
prototype in roughly five minutes. It is written so the presenter can
follow it verbatim while demoing.

---

## 1. Login

1. Open `http://localhost`.
2. Quick-fill **admin / admin123** (or use the buttons).
3. Land on the **SOC Command Center**.

Talking points:
- Dark mode + glassmorphism match the Microsoft Defender aesthetic.
- The topbar shows live counters fed by the background worker.

---

## 2. SOC Overview

What to highlight:
- The **risk level** badge updates based on recent decisions.
- The **risk trend** is a live, updating area chart.
- **Telemetry mix** is a donut; **top attacked assets** and **riskiest
  users** cards are clickable routes to deeper pages.

---

## 3. Network Twin

1. Click the **Network Twin** sidebar item.
2. Use the type filters to focus on Users / Servers / Databases.
3. Click any node to see posture, sensitivity, trust, last-seen.
4. Click **Heartbeat** to re-mark a node as online.

Talking points:
- The graph layout is concentric: users at the centre, outward to IoT.
- Highlight the type colour legend (cyan = user, blue = device, etc.).
- Compromised nodes pulse red.

---

## 4. Telemetry

1. Switch to **Telemetry**.
2. Filter by **failed_login**, then **privilege_escalation**, then **data_exfiltration**.
3. Show the indicators column – these are the risk-inductor signals
   consumed by the engine.
4. Click **Export CSV** to demonstrate that this is real, structured data.

---

## 5. Access Requests (Zero Trust decisions)

1. Open **Access Requests**.
2. Filter by **Deceived** to see only sessions that were redirected.
3. Click the eye icon on any row to open the **Explainability dialog**:
   - Risk score gauge.
   - Per-factor contribution (Identity, Behaviour, Device, Location,
     History).
   - Human-readable summary.

Talking points:
- Every decision is reproducible from the same inputs because the
  engine is deterministic.

---

## 6. Risk Analytics

- Hourly risk trend (line chart with both score and event count).
- Risk score distribution (20-point buckets).
- Attack heatmap (7 days × 24 hours).
- Threat categories (techniques per actor).

---

## 7. Threat Intelligence

1. Click any actor on the left.
2. The right panel shows username, IP, MITRE techniques, observed
   commands, and a tactics breakdown.
3. Explain the mapping: `failed_login → T1110`, `powershell → T1059.001`,
   etc.

---

## 8. Deception Logs

- Active decoy sessions auto-populate as the worker generates risky events.
- Click any session to see the recorded commands, pages visited, and
  credentials tried.
- Click **Plant Honeytokens** to seed (or re-seed) the default token set.
- Click **Simulate trigger** on any token to mark it as hit.

---

## 9. Quantum Optimization

1. Click **Run QAOA Optimization**.
2. Watch the progress bar animate.
3. The result card shows:
   - Cost score before / after.
   - FP rate and FN rate reductions.
   - Per-policy weight deltas.
4. Scroll down to see the optimization history and per-policy weight
   sliders (admin can edit manually).

---

## 10. Policy History

Same as step 9 but oriented toward policy management rather than the
optimization run.

---

## 11. Explainability Engine

- "Recent decision reasons" + "Optimization narratives" side by side.
- Every card is the human-readable counterpart of the underlying numeric
  decision.

---

## 12. Audit Logs

- Filter by severity (info, warning, critical) or by action.
- Export the full log to CSV.

---

## 13. Settings

- Toggle dark mode (purely client-side; persisted in localStorage).
- Toggle the simulation on/off (admin role only – this is a UI knob for
  demo convenience; the real flag is `ENABLE_SIMULATION`).

---

## Suggested talking tracks

### Track A – Zero Trust narrative (5 min)
Overview → Risk Analytics → Access Requests (open a decision) → Explainability.

### Track B – Deception narrative (5 min)
Overview → Threat Intel → Deception Logs → run a token trigger.

### Track C – Quantum narrative (5 min)
Policies → Quantum Optimization (run it) → Audit Logs.

---

## Common Q & A

**Is this real quantum computing?**
No – it's a faithful classical simulation of QAOA. The interface, the
noise model and the parameters are all there so swapping in a real
backend is a one-line change.

**Where is the Neo4j connection?**
The graph layer is abstracted behind `services/graph.py`. The MVP
persists against SQLite; the docker-compose file also spins up a real
Neo4j container so you can wire it up if you want.

**Does the demo actually update in real time?**
Yes – the background worker emits a new telemetry event every ~2.5 s and
the risk + deception engines process it immediately. The dashboards poll
every 4–10 s depending on the page.
