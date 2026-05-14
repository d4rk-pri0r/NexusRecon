"""Streamlit UI for NexusRecon — campaign launch, live progress, findings browser."""
from __future__ import annotations

import json
from pathlib import Path

import streamlit as st

st.set_page_config(
    page_title="NexusRecon",
    page_icon="🔍",
    layout="wide",
)

st.title("🔍 NexusRecon — OSINT Campaign Manager")
st.caption("Authorized use only. See DISCLAIMER.md.")

# ── Sidebar: Configuration ────────────────────────────────────────────────────

with st.sidebar:
    st.header("Configuration")

    scope_file = st.text_input("Scope File Path", value="./examples/scopes/m365_enterprise.yaml")
    mode = st.selectbox("Campaign Mode", ["light", "medium", "deep", "monitor"])
    seeds = st.text_area("Seeds (comma-separated)", placeholder="acme.com, john@acme.com, AS64500")

    if st.button("Validate Scope", type="primary"):
        try:
            from nexusrecon.core.scope import ScopeModel, preflight_check
            scope = ScopeModel.from_yaml(scope_file)
            st.success("Scope file is valid!")
            st.code(scope.summary())
            warnings = preflight_check(scope)
            for level, msg in warnings:
                if level == "ERROR":
                    st.error(msg)
                else:
                    st.warning(msg)
        except Exception as e:
            st.error(f"Validation failed: {e}")

# ── Main: Campaign Status ─────────────────────────────────────────────────────

tab1, tab2, tab3, tab4 = st.tabs(["Campaigns", "Findings", "Entity Graph", "Reports"])

with tab1:
    st.header("Active Campaigns")
    campaigns_dir = Path("./campaigns")
    if campaigns_dir.exists():
        campaigns = list(campaigns_dir.rglob("state.json"))
        if campaigns:
            for state_path in campaigns:
                try:
                    state = json.loads(state_path.read_text())
                    st.expander(
                        f"**{state.get('campaign_id', 'unknown')}** — "
                        f"Phase: {state.get('current_phase', 'N/A')} | "
                        f"Findings: {len(state.get('findings', []))}"
                    )
                except Exception:
                    st.warning(f"Could not load {state_path}")
        else:
            st.info("No campaigns found. Start one from the sidebar.")
    else:
        st.info("No campaigns directory found.")

with tab2:
    st.header("Findings Browser")
    st.info("Findings appear here after a campaign runs.")

with tab3:
    st.header("Entity Graph")
    st.info("Interactive entity graph visualization.")

with tab4:
    st.header("Reports")
    st.info("Generated reports appear here.")
