"""Guided Tour for Beginners in CipherTwin.

Takes users through 8 progressive steps explaining concepts, showing live data,
and providing one-click "Try it" buttons that launch questions in CipherGuide.
"""
import os
import requests
import streamlit as st

st.set_page_config(page_title="Guided Tour · CipherTwin", page_icon="🧭", layout="wide")

API_BASE = os.getenv("CIPHERTWIN_API_URL", "http://127.0.0.1:8000").rstrip("/")
TIMEOUT = float(os.getenv("CIPHERTWIN_API_TIMEOUT", "10"))


def api_call(path: str):
    try:
        return requests.get(f"{API_BASE}{path}", timeout=TIMEOUT)
    except Exception:
        return None


# Initialize tour step state
if "tour_step_idx" not in st.session_state:
    st.session_state.tour_step_idx = 1

st.title("🧭 CipherTwin Guided Tour")
st.caption("A beginner-friendly walkthrough of autonomous cyber defense, Digital Twins, and quantum-assisted policy optimization.")

# Fetch live tour data from backend
resp = api_call("/api/guide/tour")
steps = []
if resp and resp.status_code == 200:
    steps = resp.json()
else:
    # Fallback default tour steps if backend is offline
    steps = [
        {
            "step": 1,
            "title": "What the Network and its Digital Twin Are",
            "concept": "Digital Twin",
            "plain_text": "Imagine a live, interactive 3D blueprint of a city building, but for computers. CipherTwin keeps a real-time graph model of every laptop, database, and employee account.",
            "live_example": "Tracking active nodes and relationships in the Neo4j graph.",
            "try_question": "What is the Digital Twin and how many devices are connected?",
        },
        {
            "step": 2,
            "title": "How the System Decides Who Gets In (Risk Score)",
            "concept": "Zero Trust Risk Score",
            "plain_text": "Rather than trusting anyone who has a password, CipherTwin calculates a dynamic 'Risk Score' from 0 to 100 for every single action.",
            "live_example": "Risk decisions continually evaluate identity, device posture, and behavior.",
            "try_question": "How was the most recent risk score calculated?",
        },
        {
            "step": 3,
            "title": "Why the System Explains its Decisions",
            "concept": "Explainability",
            "plain_text": "CipherTwin generates clear, plain-English explanations showing exactly which factors triggered the decision.",
            "live_example": "Each decision produces a breakdown showing percentage contributions of factors.",
            "try_question": "Explain why the last decision was made in plain English.",
        },
        {
            "step": 4,
            "title": "What a Decoy is and Why Attackers Get Sent There",
            "concept": "Adaptive Deception",
            "plain_text": "When someone's risk score looks suspicious, we route them into a 'decoy'—a realistic lure server where they are safely contained.",
            "live_example": "Cowrie honeypot lures are running on port 2222 emulating real services.",
            "try_question": "Why was this session sent to a decoy?",
        },
        {
            "step": 5,
            "title": "What the System Learns from the Attacker",
            "concept": "Threat Intelligence",
            "plain_text": "Inside the decoy trap, we record every command and tool the attacker runs, mapping them to MITRE ATT&CK techniques.",
            "live_example": "Interaction events classify adversary tactics like T1059 and T1110.",
            "try_question": "What tools and commands did attackers run in the honeypot?",
        },
        {
            "step": 6,
            "title": "How Policies Get Improved (Why Quantum?)",
            "concept": "Quantum-Assisted Policy Reoptimization",
            "plain_text": "Balancing security rules is a massive combinatorial math puzzle. CipherTwin uses QAOA to find optimal weights, comparing against classical solvers.",
            "live_example": "Optimizations evaluate QUBO matrices to reweight access rules and decoy allocations.",
            "try_question": "Why did you use quantum optimization instead of classical?",
        },
        {
            "step": 7,
            "title": "The What-If Twin Forecast (Impact Preview)",
            "concept": "Twin Forecast",
            "plain_text": "Before changing a rule, managers can test it in a 'Twin Forecast' on an in-memory copy without mutating the live network.",
            "live_example": "Evaluates reachability and risk re-scoring with 0 modifications to production databases.",
            "try_question": "What if device admin-workstation is compromised?",
        },
        {
            "step": 8,
            "title": "How to Ask Good Questions",
            "concept": "CipherGuide Assistant",
            "plain_text": "You can ask CipherGuide anything in plain English! Switch between Simple, Manager, and Analyst lenses anytime.",
            "live_example": "Includes trust receipts and guarded action verification for complete transparency.",
            "try_question": "Give me a daily briefing of what happened across the network today.",
        },
    ]

total_steps = len(steps)
current_idx = min(max(st.session_state.tour_step_idx, 1), total_steps)
step_data = steps[current_idx - 1]

# Progress Bar
progress_pct = int((current_idx / total_steps) * 100)
st.progress(progress_pct, text=f"Step {current_idx} of {total_steps}: {step_data.get('concept', '')}")

st.divider()

# Step Content Card
card_cols = st.columns([3, 2])

with card_cols[0]:
    st.markdown(f"### {step_data.get('title')}")
    st.markdown(f"**Core Concept**: `{step_data.get('concept')}`")
    st.write(step_data.get("plain_text"))

    st.info(
        f"""
        📊 **Live System Metric / Telemetry:**  
        {step_data.get('live_example')}
        """
    )

with card_cols[1]:
    st.markdown("#### 💬 Try it in CipherGuide")
    st.write("Click below to send this question directly to the assistant:")
    q_text = step_data.get("try_question", "Explain this concept.")
    st.code(q_text, language="markdown")
    
    if st.button("🚀 Ask in CipherGuide", type="primary", use_container_width=True):
        st.session_state.selected_suggestion = q_text
        st.session_state.show_welcome = False
        st.switch_page("pages/1_🛡️_CipherGuide.py")

st.divider()

# Navigation Buttons
nav_cols = st.columns([1, 1, 2])
with nav_cols[0]:
    if current_idx > 1:
        if st.button("⬅️ Previous Step", use_container_width=True):
            st.session_state.tour_step_idx -= 1
            st.rerun()
with nav_cols[1]:
    if current_idx < total_steps:
        if st.button("Next Step ➡️", type="primary", use_container_width=True):
            st.session_state.tour_step_idx += 1
            st.rerun()
    else:
        if st.button("🎉 Finish Tour & Open Assistant", type="primary", use_container_width=True):
            st.switch_page("pages/1_🛡️_CipherGuide.py")
