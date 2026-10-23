"""CipherTwin analyst feedback console.

This is a separate Streamlit UI that reads/writes real API records. It does not
create synthetic incidents and never treats a failed API call as a successful action.
"""
import os
from typing import Any

import requests
import streamlit as st

st.set_page_config(page_title="CipherTwin Analyst Console", page_icon="🛡️", layout="wide")
API_BASE = os.getenv("CIPHERTWIN_API_URL", "http://127.0.0.1:8000").rstrip("/")
TIMEOUT = float(os.getenv("CIPHERTWIN_API_TIMEOUT", "5"))


def api_request(method: str, path: str, token: str | None = None, **kwargs: Any):
    headers = dict(kwargs.pop("headers", {}))
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return requests.request(
        method, f"{API_BASE}{path}", headers=headers, timeout=TIMEOUT, **kwargs
    )


st.title("CipherTwin · Analyst Feedback Console")
st.caption("Connected to the existing FastAPI backend. Data shown here comes from stored API records.")

st.info("💡 **New to CipherTwin?** Use the sidebar navigation to open **🛡️ CipherGuide Assistant**, take the **🧭 Guided Tour**, or browse the **📖 Glossary**.")


if "token" not in st.session_state:
    st.session_state.token = ""
if "user" not in st.session_state:
    st.session_state.user = {}

if not st.session_state.token:
    st.subheader("Sign in")
    with st.form("login_form"):
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        submitted = st.form_submit_button("Sign in", type="primary")
    if submitted:
        try:
            response = api_request(
                "POST", "/api/auth/login",
                json={"username": username, "password": password},
            )
            if response.status_code == 200:
                payload = response.json()
                st.session_state.token = payload["access_token"]
                st.session_state.user = payload.get("user", {})
                st.rerun()
            else:
                st.error(f"Sign-in failed ({response.status_code}): {response.text[:300]}")
        except requests.RequestException as exc:
            st.error(f"Backend unavailable: {exc}")
    st.info(f"API endpoint: {API_BASE}. Start the FastAPI backend before signing in.")
    st.stop()

top = st.columns([4, 1])
top[0].write(f"Signed in as **{st.session_state.user.get('username', 'analyst')}**")
if top[1].button("Sign out"):
    st.session_state.token = ""
    st.session_state.user = {}
    st.rerun()

try:
    health_resp = api_request("GET", "/api/system/health", st.session_state.token)
    if health_resp.status_code == 200:
        health = health_resp.json()
        st.caption(f"Backend health endpoint responded. Status: {health.get('status', 'reported')}")
    elif health_resp.status_code == 401:
        st.session_state.token = ""
        st.error("Session expired. Sign in again.")
        st.stop()
    else:
        st.warning(f"Health endpoint returned HTTP {health_resp.status_code}.")
except requests.RequestException as exc:
    st.error(f"Cannot reach the backend: {exc}")
    st.stop()

left, right = st.columns([3, 2])
with left:
    st.subheader("Recent risk decisions")
    try:
        response = api_request(
            "GET", "/api/risk/decisions?page=1&page_size=100",
            st.session_state.token,
        )
        response.raise_for_status()
        payload = response.json()
        decisions = payload.get("items", []) if isinstance(payload, dict) else payload
        if decisions:
            rows = [{
                "ID": d.get("id"),
                "Timestamp": d.get("timestamp"),
                "User": d.get("user_id"),
                "Resource": d.get("resource_id") or d.get("target_id"),
                "Risk": d.get("risk_score"),
                "Decision": d.get("decision"),
                "Confidence": d.get("confidence"),
            } for d in decisions]
            st.dataframe(rows, use_container_width=True, hide_index=True)
        else:
            st.info("No stored risk decisions are available yet.")
    except requests.RequestException as exc:
        st.error(f"Could not load risk decisions: {exc}")
        decisions = []

with right:
    st.subheader("Submit analyst feedback")
    if decisions:
        ids = [d.get("id") for d in decisions if d.get("id") is not None]
        with st.form("feedback_form"):
            selected_id = st.selectbox("Risk decision ID", ids)
            label = st.selectbox(
                "Analyst label",
                ["TRUE_POSITIVE", "FALSE_POSITIVE", "TRUE_NEGATIVE", "FALSE_NEGATIVE"],
            )
            reason = st.text_area("Rationale", max_chars=1000)
            submitted = st.form_submit_button("Save feedback", type="primary")
        if submitted:
            try:
                response = api_request(
                    "POST", "/api/risk/feedback", st.session_state.token,
                    json={"decision_id": selected_id, "analyst_label": label, "reason": reason},
                )
                if response.status_code == 200 and not response.json().get("error"):
                    st.success("Feedback saved to the backend.")
                    st.rerun()
                else:
                    st.error(f"Feedback was not saved: HTTP {response.status_code} — {response.text[:300]}")
            except requests.RequestException as exc:
                st.error(f"Feedback request failed: {exc}")
    else:
        st.info("A risk decision must exist before feedback can be submitted.")

st.divider()
st.subheader("Saved analyst feedback")
try:
    response = api_request("GET", "/api/risk/feedback", st.session_state.token)
    response.raise_for_status()
    feedback = response.json()
    if feedback:
        st.dataframe(feedback, use_container_width=True, hide_index=True)
    else:
        st.info("No analyst feedback has been recorded.")
except requests.RequestException as exc:
    st.warning(f"Could not load feedback: {exc}")

st.caption("This dashboard submits feedback only. It does not automatically change security policy or claim model improvement.")
