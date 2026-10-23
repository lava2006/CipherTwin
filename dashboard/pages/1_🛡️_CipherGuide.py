"""CipherGuide: Grounded, Explainable Assistant for CipherTwin.

Designed for all audiences (beginners, managers, examiners, analysts):
- Audience Lenses: Simple (with analogies), Manager (business impact), Analyst (forensic receipts)
- Beginner Mode with jargon highlights
- Multi-provider status badge (Grok / Local Model / Offline)
- Trust Receipts with confidence score & grounding evidence
- Guarded Actions with explicit user confirmation
- Downloadable Incident Reports
"""
import os
import requests
import streamlit as st

st.set_page_config(page_title="CipherGuide · AI Assistant", page_icon="🛡️", layout="wide")

API_BASE = os.getenv("CIPHERTWIN_API_URL", "http://127.0.0.1:8000").rstrip("/")
TIMEOUT = float(os.getenv("CIPHERTWIN_API_TIMEOUT", "15"))


def api_call(method: str, path: str, **kwargs):
    try:
        return requests.request(method, f"{API_BASE}{path}", timeout=TIMEOUT, **kwargs)
    except Exception as exc:
        return None


# Initialize Session State
if "messages" not in st.session_state:
    st.session_state.messages = []
if "show_welcome" not in st.session_state:
    st.session_state.show_welcome = True
if "lens" not in st.session_state:
    st.session_state.lens = "simple"
if "beginner_mode" not in st.session_state:
    st.session_state.beginner_mode = True
if "pending_action" not in st.session_state:
    st.session_state.pending_action = None
if "selected_suggestion" not in st.session_state:
    st.session_state.selected_suggestion = None

# Header & Provider Status Badge
header_cols = st.columns([3, 1])
with header_cols[0]:
    st.title("🛡️ CipherGuide Assistant")
    st.caption("Ask anything about network security, risk decisions, honeypot traps, and what-if scenarios in plain English.")

# Fetch provider smoke status or default label
with header_cols[1]:
    prov_resp = api_call("GET", "/api/guide/providers")
    badge_label = "Using: Offline Mode (Safe Fallback)"
    if prov_resp and prov_resp.status_code == 200:
        p_data = prov_resp.json()
        if p_data.get("xai", {}).get("status") == "ok":
            badge_label = "🟢 Using: Grok / Groq LLM"
        elif p_data.get("ollama", {}).get("status") == "ok":
            badge_label = "🔵 Using: Local Model (Ollama)"
        else:
            badge_label = "🟡 Using: Offline Mode"
    st.markdown(f"**System Status**  \n`{badge_label}`")

# Audience Lens & Beginner Mode Controls
ctrl_cols = st.columns([1, 1, 2])
with ctrl_cols[0]:
    lens_choice = st.selectbox(
        "Audience Lens",
        options=["simple", "manager", "analyst"],
        index=["simple", "manager", "analyst"].index(st.session_state.lens),
        format_func=lambda x: {
            "simple": "🌱 Simple (Plain English + Analogy)",
            "manager": "💼 Manager (Business & Risk Impact)",
            "analyst": "🔬 Analyst (Forensic Math & Receipts)",
        }.get(x, x),
    )
    st.session_state.lens = lens_choice

with ctrl_cols[1]:
    st.session_state.beginner_mode = st.toggle("Beginner Mode (Jargon Tooltips)", value=st.session_state.beginner_mode)

with ctrl_cols[2]:
    st.markdown(
        """
        <div style="font-size: 0.85rem; color: #666; margin-top: 1.6rem;">
        💡 <i>Tip: Simple mode includes everyday metaphors; Analyst mode includes full mathematical factor breakdowns.</i>
        </div>
        """,
        unsafe_allow_html=True,
    )

st.divider()

# Welcome Card for First-Time Users
if st.session_state.show_welcome and len(st.session_state.messages) == 0:
    st.info(
        """
        ### 👋 Welcome to CipherTwin!
        CipherTwin is an autonomous cyber-defense platform that protects company networks without getting in the way of real work.
        It builds a live **Digital Twin** (a real-time virtual map) of all devices and employees, computes a dynamic **Risk Score** for every request, quietly diverts suspicious intruders into realistic **decoys**, and continuously tunes its defense rules with **quantum optimization**.
        """
    )
    b_cols = st.columns(3)
    if b_cols[0].button("🧭 Take the Guided Tour", use_container_width=True, type="primary"):
        st.switch_page("pages/2_🧭_Guided_Tour.py")
    if b_cols[1].button("⚡ Show Me An Attack Happening", use_container_width=True):
        st.session_state.selected_suggestion = "Tell me the story of the most recent session from start to finish."
        st.session_state.show_welcome = False
        st.rerun()
    if b_cols[2].button("💬 Let Me Just Ask Questions", use_container_width=True):
        st.session_state.show_welcome = False
        st.rerun()
    st.divider()

# Pending Guarded Action Modal / Confirmation Banner
if st.session_state.pending_action:
    act = st.session_state.pending_action
    st.warning(
        f"""
        ### ⚠️ Guarded Action Requires Explicit Confirmation
        **Action Proposed**: `{act.get('action_type', 'System Update')}`  
        **Target Asset**: `{act.get('target', 'Network Asset')}`  
        **Reason**: {act.get('reason', 'Security containment')}  
        **Blast Radius / Impact**: {act.get('impact', 'Immediate containment')}
        
        *CipherGuide never alters live firewalls or the Neo4j graph without your explicit verification.*
        """
    )
    act_cols = st.columns([1, 1, 3])
    if act_cols[0].button("✅ Confirm & Execute", type="primary"):
        resp = api_call("POST", "/api/guide/actions/confirm", json={"action_id": act.get("action_id"), "confirmed": True})
        if resp and resp.status_code == 200:
            st.success("Action confirmed and executed successfully!")
        else:
            st.error("Failed to execute confirmed action.")
        st.session_state.pending_action = None
        st.rerun()
    if act_cols[1].button("❌ Cancel Action"):
        st.session_state.pending_action = None
        st.info("Proposed action cancelled safely.")
        st.rerun()

# Display Chat Message History
for msg in st.session_state.messages:
    with st.chat_message(msg["role"]):
        st.markdown(msg["content"])
        
        # Display Trust Receipts drawer for assistant responses
        if msg["role"] == "assistant" and "receipt" in msg:
            rcpt = msg["receipt"]
            with st.expander("🧾 Trust Receipt & Forensic Grounding Evidence", expanded=False):
                r_cols = st.columns([2, 1])
                with r_cols[0]:
                    st.markdown(f"**Confidence Score**: `{rcpt.get('confidence', 95)}%`")
                    st.markdown(f"**Data Provider**: `{rcpt.get('provider_label', 'CipherTwin Twin Engine')}`")
                    st.markdown(f"**Audience Lens Applied**: `{rcpt.get('lens', 'simple').capitalize()}`")
                with r_cols[1]:
                    if "incident_id" in rcpt:
                        rep_resp = api_call("GET", f"/api/guide/report/{rcpt['incident_id']}")
                        if rep_resp and rep_resp.status_code == 200:
                            md_report = rep_resp.json().get("markdown", "")
                            st.download_button(
                                label="📥 Download Report (.md)",
                                data=md_report,
                                file_name=f"ciphertwin-report-{rcpt['incident_id']}.md",
                                mime="text/markdown",
                            )
                st.markdown("**Retrieved Verification Evidence:**")
                st.json(rcpt.get("evidence", {}))

# Categorized Quick-Starter Suggestions
st.markdown("##### 💡 Suggested Questions")
cat_tabs = st.tabs(["What Happened", "Why Did It Decide", "What-If (Twin Forecast)", "Learn Basics", "Take Action"])

suggestions_by_tab = {
    0: [
        "What happened in the latest security incident?",
        "What tools and commands did attackers run in the honeypot?",
        "Tell me the story of the most recent session from start to finish.",
    ],
    1: [
        "Why was the last access request blocked or restricted?",
        "Why was this session sent to a decoy?",
        "Show me the factor contributions that calculated the risk score.",
    ],
    2: [
        "What if device admin-workstation is compromised?",
        "What if we require MFA for all employees in Finance?",
        "What if we tighten the risk threshold from 60 to 45?",
    ],
    3: [
        "What is Zero Trust in plain English with an analogy?",
        "Why do we use quantum optimization instead of classical?",
        "What is a honeytoken and how does it catch intruders?",
    ],
    4: [
        "Propose blocking device laptop-alice-01",
        "Propose marking incident #1 as a false positive",
        "Propose reweighting the Strict Lockout policy",
    ],
}

for tab_idx, tab in enumerate(cat_tabs):
    with tab:
        cols = st.columns(len(suggestions_by_tab[tab_idx]))
        for i, q_text in enumerate(suggestions_by_tab[tab_idx]):
            if cols[i].button(q_text, key=f"sug_{tab_idx}_{i}"):
                st.session_state.selected_suggestion = q_text
                st.rerun()

# User Input Handling
prompt_input = st.chat_input("Ask CipherGuide any question...")
question_to_send = None

if prompt_input:
    question_to_send = prompt_input
elif st.session_state.selected_suggestion:
    question_to_send = st.session_state.selected_suggestion
    st.session_state.selected_suggestion = None

if question_to_send:
    # Append user question
    st.session_state.messages.append({"role": "user", "content": question_to_send})
    with st.chat_message("user"):
        st.markdown(question_to_send)

    with st.chat_message("assistant"):
        with st.spinner("Analyzing Digital Twin and security telemetry..."):
            payload = {
                "question": question_to_send,
                "lens": st.session_state.lens,
                "beginner_mode": st.session_state.beginner_mode,
            }
            resp = api_call("POST", "/api/guide/ask", json=payload)
            
            if resp and resp.status_code == 200:
                data = resp.json()
                answer_text = data.get("answer", "No answer received.")
                
                # Check for guarded action in response
                if data.get("pending_action"):
                    st.session_state.pending_action = data["pending_action"]
                
                receipt = {
                    "confidence": int(data.get("confidence", 0.95) * 100),
                    "provider_label": data.get("provider_label", badge_label),
                    "lens": data.get("lens", st.session_state.lens),
                    "evidence": data.get("evidence", {}),
                    "incident_id": data.get("incident_id", "inc-latest"),
                }
                
                st.markdown(answer_text)
                st.session_state.messages.append({
                    "role": "assistant",
                    "content": answer_text,
                    "receipt": receipt,
                })
                st.rerun()
            else:
                err_msg = "⚠️ CipherGuide backend is currently connecting. Please ensure the FastAPI backend is running on port 8000."
                st.warning(err_msg)
                st.session_state.messages.append({"role": "assistant", "content": err_msg})
