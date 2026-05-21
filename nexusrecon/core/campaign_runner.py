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
from typing import Any

# (phase_id, display_name, tier_floor)
_PHASE_TIER_FLOOR: dict[str, int] = {
    "phase1": 0,
    "phase2": 0,
    "phase3": 0,
    "phase4": 0,
    "phase5": 2,
    "phase6": 3,
    "phase7": 0,
    "phase7_5": 0,
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
        phase2_identity_cloud,
        phase3_code_leakage,
        phase4_correlation,
        phase5_light_active,
        phase6_active,
        phase7_5_harvest,
        phase7_vuln_pretext,
        phase8_attack_surface,
        phase9_reporting,
        reflection_node,
    )

    phases = [
        ("phase1", "Passive Footprinting", phase1_passive_footprinting),
        ("phase2", "Identity & Cloud", phase2_identity_cloud),
        ("phase3", "Code Leakage", phase3_code_leakage),
        ("phase4", "Correlation", phase4_correlation),
        ("phase5", "Light Active", phase5_light_active),
        ("phase6", "Active (T3)", phase6_active),
        ("phase7", "Vuln & Pretext", phase7_vuln_pretext),
        ("phase7_5", "Credential Harvest", phase7_5_harvest),
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
            try:
                campaign.end_phase(phase_id, findings_count, 0)
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

    _emit({
        "type": "campaign_complete",
        "campaign_id": s.get("campaign_id"),
        "total_findings": len(s.get("findings", [])),
        "total_cost_usd": float(s.get("llm_cost_usd", 0.0)),
        "timestamp": datetime.utcnow().isoformat(),
    })
    return s
