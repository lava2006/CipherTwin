# CipherGuide Demonstration Scripts

This guide provides structured demonstration scripts to showcase **CipherGuide**—the grounded, explainable assistant for the CipherTwin autonomous cyber defense framework.

---

## ⚡ 1-Minute Elevator Pitch (For Executives & Reviewers)

> **"Traditional cyber defense operates in silos: firewalls block access with zero explanation, honeypots are disconnected, and rule tuning is manual guesswork.**  
>
> **CipherTwin solves this with an autonomous digital loop: our Digital Twin keeps a real-time graph map of every host and user; our Explainable Zero-Trust Engine calculates continuous risk scores from 0 to 100 with clear factor breakdowns; suspicious actors are quietly diverted into Cowrie decoys to capture their tools safely; and our Quantum-Assisted Policy Reoptimization solver continuously tunes rules to prevent false positives.**  
>
> **To make this transparent for anyone—from first-time visitors to senior managers—we built CipherGuide. It offers an 8-step guided tour, three audience lenses (Simple with analogies, Manager with business impacts, Analyst with forensic receipts), an in-memory Twin Forecast that lets you preview policy impacts with zero mutations to production databases, and guarded actions that require explicit confirmation before isolating any asset."**

---

## 🧭 3-Minute Comprehensive Walkthrough (For Examiners & Technical Reviewers)

### Step 1: Launch & Beginner Welcome (0:00 – 0:45)
1. Launch the analyst and guide console:
   ```bash
   streamlit run dashboard/app.py
   ```
2. Navigate to **`🛡️ CipherGuide`** in the left sidebar.
3. Point out the **Welcome Card** with the 3 primary action buttons:
   - *"🧭 Take the Guided Tour"*
   - *"⚡ Show Me An Attack Happening"*
   - *"💬 Let Me Just Ask Questions"*
4. Highlight the **System Status Badge** (`🟢 Using: Grok / Groq LLM` or `🟡 Using: Offline Mode`). Explain the free-model provider chain: Grok/Groq cloud tool calling ➔ Ollama local model ➔ Jinja2 grounded offline fallback.

### Step 2: The Three Audience Lenses (0:45 – 1:30)
1. Select the suggested question: *"Why was the last access request redirected to a decoy?"*
2. Demonstrate the **Simple Lens**:
   - Note the plain language and relatable everyday metaphor (e.g. hotel room keys or security checkpoints).
3. Switch the dropdown to **Manager Lens**:
   - Observe the structure: Business Impact, Risk Assessment, Containment Action, and Next Steps.
4. Switch to **Analyst Lens**:
   - Expand the **🧾 Trust Receipt** drawer. Point out the grounded evidence: exact Decision ID, mathematical factor weights (Identity, Device, Behavior), and captured honeypot credentials.

### Step 3: In-Memory Twin Forecast (1:30 – 2:15)
1. Ask: *"What if device admin-workstation is compromised?"* or *"What if we require MFA for all employees in Finance?"*
2. Highlight the **Twin Forecast (Impact Preview)**:
   - Shows the before/after average network risk score, policy flips (e.g. Allowed ➔ Restricted), and reachable blast radius nodes.
   - Emphasize the **Architectural Invariant**: this evaluation runs entirely in-memory on an isolated subgraph snapshot. Live Neo4j nodes and SQLite databases experience **0 mutations**.

### Step 4: Quantum vs. Classical Honesty & Guarded Actions (2:15 – 3:00)
1. Ask: *"Why did you use quantum optimization instead of classical?"*
2. Point out the honest assessment:
   - SciPy classical evaluation is faster (10-15 ms) for small policy grids; PennyLane QAOA (lightning.qubit) demonstrates scaling theory and formulation for large combinatorial search spaces.
3. Ask: *"Propose blocking device laptop-alice-01"*.
4. Show the **Guarded Action Card**:
   - The system stages the action as `pending_confirmation`. The chatbot **never** mutates firewalls or graph nodes autonomously.
   - Click **✅ Confirm & Execute** to commit the isolation and verify the audit log entry.
5. Click **📥 Download Report (.md)** to download the generated incident briefing report.

---

## 🛠️ CLI Automated Demonstration

Run the automated CLI demo script at any time:
```bash
# On Linux / macOS:
make demo-guide

# On Windows PowerShell:
$env:PYTHONPATH='backend'; .\.venv\Scripts\python.exe scripts/demo_guide.py
```

### Provider Verification Smoke Check
Verify available LLM providers and fallbacks:
```bash
make guide-smoke
```
