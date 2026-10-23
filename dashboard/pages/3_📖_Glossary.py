"""Cybersecurity & Quantum Glossary for CipherTwin.

Provides simple explanations, everyday analogies, and technical context for
Zero Trust, Digital Twin, Deception, and Quantum Reoptimization terms.
"""
import os
import requests
import streamlit as st

st.set_page_config(page_title="Glossary · CipherTwin", page_icon="📖", layout="wide")

API_BASE = os.getenv("CIPHERTWIN_API_URL", "http://127.0.0.1:8000").rstrip("/")
TIMEOUT = float(os.getenv("CIPHERTWIN_API_TIMEOUT", "10"))


def api_call(path: str):
    try:
        return requests.get(f"{API_BASE}{path}", timeout=TIMEOUT)
    except Exception:
        return None


st.title("📖 CipherTwin Terminology Glossary")
st.caption("Clear, plain-English definitions with everyday analogies and technical breakdowns for all personas.")

# Search and Category Filters
filter_cols = st.columns([2, 1])
with filter_cols[0]:
    search_query = st.text_input("🔍 Search terms or definitions...", placeholder="e.g. Zero Trust, Decoy, QAOA, Honeytoken")

resp = api_call("/api/guide/glossary")
terms = []
if resp and resp.status_code == 200:
    terms = resp.json()
else:
    # Direct import fallback if backend is offline
    from app.guide.glossary import get_all_terms
    terms = [t.to_dict() for t in get_all_terms()]

categories = ["All"] + sorted(list({t.get("category", "General") for t in terms}))

with filter_cols[1]:
    selected_cat = st.selectbox("Filter by Category", categories)

# Apply filters
filtered = terms
if selected_cat != "All":
    filtered = [t for t in filtered if t.get("category") == selected_cat]

if search_query:
    q = search_query.lower()
    filtered = [
        t for t in filtered
        if q in t.get("term", "").lower()
        or q in t.get("simple_definition", "").lower()
        or q in t.get("technical_definition", "").lower()
    ]

st.markdown(f"Showing **{len(filtered)}** terminology entries:")
st.divider()

if not filtered:
    st.info("No matching terms found. Try a different search term or category.")
else:
    for item in filtered:
        with st.container():
            t_cols = st.columns([3, 1])
            with t_cols[0]:
                st.markdown(f"### {item.get('term')}")
                st.markdown(f"**Category**: `{item.get('category')}`")
            with t_cols[1]:
                ask_q = f"What is {item.get('term')} in plain English with an analogy?"
                if st.button("💬 Ask CipherGuide", key=f"ask_{item.get('term')}", use_container_width=True):
                    st.session_state.selected_suggestion = ask_q
                    st.session_state.show_welcome = False
                    st.switch_page("pages/1_🛡️_CipherGuide.py")

            st.write(f"**Definition**: {item.get('simple_definition')}")
            
            st.info(f"💡 **Everyday Analogy**: {item.get('analogy')}")

            with st.expander("🔬 Technical Breakdown & Formula", expanded=False):
                st.markdown(f"**NIST / Technical Formulation**: {item.get('technical_definition')}")
                st.markdown(f"**CipherTwin Implementation**: {item.get('example')}")

            st.divider()
