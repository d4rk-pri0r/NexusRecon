"""
Reusable campaign loop — extracted from CLI so both CLI and TUI invoke it.

Both the existing `nexusrecon run` CLI and the V3 TUI runner screen call
``run_campaign()``. The CLI passes ``on_event=None`` (no UI updates beyond
its own Rich Progress display); the TUI passes a callback that forwards
events to its live runner widget.
"""
from __future__ import annotations

from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from typing import Any

# (phase_id, display_name, tier_floor)
_PHASE_TIER_FLOOR: dict[str, int] = {
    "phase1": 0,
    "phase2": 0,
    "phase2_5": 0,
    "phase3": 0,
    "phase4": 0,
    "phase5": 2,
    "phase6": 3,
    "phase7": 0,
    "phase7_5": 0,
    "phase7_7": 0,
    "phase8": 0,
    "phase9": 0,
}


async def run_campaign(
    state: dict[str, Any],
    campaign: Any,
    scope_model: Any,
    on_event: Callable[[dict[str, Any]], None] | None = None,
) -> dict[str, Any]:
    """
    Run the campaign through all authorized phases.

    Args:
        state: live campaign state dict.
        campaign: CampaignManager instance (begin_phase/end_phase/save_state).
        scope_model: ScopeModel — used to read the tier ceiling.
        on_event: optional callback invoked on phase transitions, dispatch
                  decisions, completion, and errors. Event payloads have a
                  ``type`` field plus type-specific keys.

    Returns:
        The (mutated) state dict after all phases complete.

    Event types:
        - phase_start  {phase, name, timestamp}
        - phase_end    {phase, name, findings_count, cost_usd, timestamp}
        - phase_skipped {phase, name, reason}
        - dispatch_decision {phase, dispatched}
        - campaign_error {phase, subsystem, error}
        - campaign_complete {campaign_id, total_findings, total_cost_usd, timestamp}
    """
    from nexusrecon.graph.nodes import (
        phase1_passive_footprinting,
        phase2_5_personal_identity_pivot,
        phase2_identity_cloud,
        phase3_code_leakage,
        phase4_correlation,
        phase5_light_active,
        phase6_active,
        phase7_5_harvest,
        phase7_7_pretext_intelligence,
        phase7_vuln_pretext,
        phase8_attack_surface,
        phase9_reporting,
        reflection_node,
    )

    # phase2_5 (personal-identity pivot + credential punch list) and phase7_7
    # (relationship graph + pretext scoring) are tier-0 passive phases that
    # operate on plain campaign state. They were previously reachable only via
    # the --use-graph LangGraph path, which left their marquee deliverables
    # (credential_exposure_paths.md, spear_phishing_intelligence.md) empty on a
    # default run. Both degrade gracefully: they skip cleanly when no identity
    # data exists, breach lookups stay gated by the scope guard's
    # allow_breach_db_lookup constraint, and phishing-draft generation remains
    # behind --generate-phishing. Slotted to match graph/workflow.py: 2_5 after
    # corp identity is confirmed (phase2), 7_7 after credential harvest (7_5).
    phases = [
        ("phase1", "Passive Footprinting", phase1_passive_footprinting),
        ("phase2", "Identity & Cloud", phase2_identity_cloud),
        ("phase2_5", "Personal Identity Pivot", phase2_5_personal_identity_pivot),
        ("phase3", "Code Leakage", phase3_code_leakage),
        ("phase4", "Correlation", phase4_correlation),
        ("phase5", "Light Active", phase5_light_active),
        ("phase6", "Active (T3)", phase6_active),
        ("phase7", "Vuln & Pretext", phase7_vuln_pretext),
        ("phase7_5", "Credential Harvest", phase7_5_harvest),
        ("phase7_7", "Pretext Intelligence", phase7_7_pretext_intelligence),
        ("phase8", "Attack Surface", phase8_attack_surface),
        ("phase9", "Reporting", phase9_reporting),
    ]
    max_tier = scope_model.tier_value()

    def _emit(evt: dict[str, Any]) -> None:
        if on_event:
            try:
                on_event(evt)
            except Exception:
                # Never let a misbehaving listener break the campaign.
                pass

    # ── Preflight tool-availability report (Wave F-A3) ──────────────────────
    # Surface the capability surface BEFORE the first phase: which tools
    # will run, and which are skipped for a missing binary, a missing key,
    # or an engagement policy. The operator learns up front rather than
    # grepping the audit log after the run.
    try:
        from nexusrecon.tools.registry import get_registry
        preflight = get_registry().availability_report()
        if getattr(campaign, "audit_log", None):
            campaign.audit_log.log_preflight(preflight["counts"], preflight["buckets"])
        _emit({"type": "preflight", **preflight})
        state["preflight"] = preflight
    except Exception as pf_err:
        state.setdefault("errors", []).append(f"preflight: {pf_err}")

    # Bind the campaign's cost tracker to the shared agent executor so LLM
    # spend reaches phase_end / finalize instead of dying in the executor's
    # private tracker (Wave F-A6: the disconnect behind every-phase-$0.00).
    try:
        from nexusrecon.graph.nodes import set_executor_cost_tracker
        if getattr(campaign, "cost_tracker", None) is not None:
            set_executor_cost_tracker(campaign.cost_tracker)
    except Exception as ct_err:
        state.setdefault("errors", []).append(f"cost_tracker_bind: {ct_err}")

    s = state
    for phase_id, phase_name, phase_fn in phases:
        if _PHASE_TIER_FLOOR.get(phase_id, 0) > max_tier:
            _emit({
                "type": "phase_skipped",
                "phase": phase_id,
                "name": phase_name,
                "reason": "above max tier",
            })
            continue

        try:
            campaign.begin_phase(phase_id, phase_id)
        except Exception:
            pass
        _emit({
            "type": "phase_start",
            "phase": phase_id,
            "name": phase_name,
            "timestamp": datetime.utcnow().isoformat(),
        })

        try:
            s = await phase_fn(s)
            try:
                campaign.save_state(s)
            except Exception:
                pass
            findings_count = len(s.get("findings", []))
            # Real entity count for the run-health summary (F-A5). phase4/phase8
            # persist the built EntityGraph as state["entity_graph"]
            # (nodes/edges/stats); before phase4 the graph is absent and 0 is the
            # honest count. run_health takes the max entities_count across phases,
            # so the post-phase4/8 counts dominate. Passing the real count instead
            # of a hardcoded 0 stops the "entity extraction may be broken" caveat
            # from firing on every healthy run, the false alarm that trained
            # operators to distrust the entire run-health block.
            entity_graph_state = s.get("entity_graph") or {}
            entities_count = len(entity_graph_state.get("nodes", []))
            try:
                campaign.end_phase(phase_id, findings_count, entities_count)
            except Exception:
                pass
            _emit({
                "type": "phase_end",
                "phase": phase_id,
                "name": phase_name,
                "findings_count": findings_count,
                "cost_usd": float(s.get("llm_cost_usd", 0.0)),
                "timestamp": datetime.utcnow().isoformat(),
            })

            # Reflection / dispatcher between phases (gated by dispatch_mode).
            try:
                prior_dispatches = len(s.get("dispatch_log", []) or [])
                s = await reflection_node(s)
                try:
                    campaign.save_state(s)
                except Exception:
                    pass
                new_dispatches = len(s.get("dispatch_log", []) or []) - prior_dispatches
                if new_dispatches > 0:
                    _emit({
                        "type": "dispatch_decision",
                        "phase": phase_id,
                        "dispatched": new_dispatches,
                    })
            except Exception as ref_err:
                s.setdefault("errors", []).append(
                    f"{phase_id}/reflection: {ref_err}"
                )
                _emit({
                    "type": "campaign_error",
                    "phase": phase_id,
                    "subsystem": "reflection",
                    "error": str(ref_err),
                })
        except Exception as e:
            s.setdefault("errors", []).append(f"{phase_id}: {e}")
            _emit({
                "type": "campaign_error",
                "phase": phase_id,
                "subsystem": "phase",
                "error": str(e),
            })

    # ── Run-level health summary (Wave F-A5) ────────────────────────────────
    # Read the audit log back and tell the operator how the run actually
    # went: degraded/failed tools, policy skips, degraded capabilities, and
    # whether the graph stayed empty. Written as run_health.md, stashed in
    # state, and folded into the campaign_complete event so a confident
    # report is never mistaken for a complete one.
    run_health: dict[str, Any] = {}
    try:
        from nexusrecon.core.run_health import (
            llm_provenance_from_state,
            read_entries,
            render_run_health_md,
            summarize_run_health,
        )
        from nexusrecon.tools.registry import get_registry

        audit = getattr(campaign, "audit_log", None)
        if audit is not None and getattr(audit, "log_path", None):
            name_to_cat = {
                name: tool.category.value
                for name, tool in get_registry()._tools.items()
            }
            health = summarize_run_health(
                read_entries(audit.log_path),
                name_to_cat,
                llm_provenance=llm_provenance_from_state(s),
            )
            run_health = health.to_dict()
            s["run_health"] = run_health
            campaign_dir = getattr(campaign, "campaign_dir", None)
            if campaign_dir is not None:
                reports_dir = Path(campaign_dir) / "reports"
                reports_dir.mkdir(parents=True, exist_ok=True)
                (reports_dir / "run_health.md").write_text(
                    render_run_health_md(health, s.get("campaign_id", "")),
                    encoding="utf-8",
                )
    except Exception as hl_err:
        s.setdefault("errors", []).append(f"run_health: {hl_err}")

    _emit({
        "type": "campaign_complete",
        "campaign_id": s.get("campaign_id"),
        "total_findings": len(s.get("findings", [])),
        "total_cost_usd": float(s.get("llm_cost_usd", 0.0)),
        "run_health": run_health,
        "timestamp": datetime.utcnow().isoformat(),
    })
    return s
