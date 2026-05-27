"""
Dynamic Dispatcher — evaluate trigger hints, call LLM, validate plan, execute.

Entry point: ``await run_dynamic_dispatch(state)``

Hard caps
---------
- MAX_PER_CYCLE  (5)  — max dispatches in one reflection_node call
- MAX_TOTAL     (30)  — max dispatches across the entire campaign

Lite mode: only phases in LITE_DISPATCH_PHASES trigger the dispatcher.
Full mode: every reflection triggers the dispatcher.
Off  mode: dispatcher is never called (handled by reflection_node).
"""
from __future__ import annotations

import asyncio
import json
import re
from datetime import UTC, datetime
from typing import Any

import structlog

from nexusrecon.graph.state import CampaignGraphState
from nexusrecon.tools.registry import get_registry

log = structlog.get_logger(__name__)

# Hard caps
MAX_PER_CYCLE: int = 5
MAX_TOTAL: int = 30

# Phases eligible for dispatch in lite mode
LITE_DISPATCH_PHASES: frozenset[str] = frozenset({"phase1", "phase4", "phase7"})

# Map tool category value → state key for result merging.
# Rule: each Category enum value maps to the state key that best represents its findings.
CATEGORY_TO_STATE_KEY: dict[str, str] = {
    "domain": "domain_intel",
    "subdomain": "subdomain_intel",
    "dns": "domain_intel",
    "certificate": "domain_intel",
    "email": "email_intel",
    "identity": "identity_intel",
    "breach": "breach_intel",       # was "dark_intel" — breach results go to breach_intel
    "infrastructure": "infra_intel",
    "cloud": "cloud_intel",         # generic cloud category
    "cloud_aws": "cloud_intel",
    "cloud_azure": "cloud_intel",
    "cloud_gcp": "cloud_intel",
    "code": "code_intel",
    "secret": "code_intel",
    "web": "infra_intel",
    "vulnerability": "vuln_intel",
    "mobile": "mobile_intel",       # was "infra_intel" — mobile results go to mobile_intel
    "social": "social_intel",       # new: social/SOCMINT tools
    "pretext": "pretext_intel",
    "news": "pretext_intel",
}


# ── Prompt builder ────────────────────────────────────────────────────────────

def _build_dispatch_prompt(state: CampaignGraphState) -> str:
    """Build the LLM prompt with current intel summary and available tools."""
    registry = get_registry()
    seeds = state.get("seeds", [])
    current_phase = state.get("current_phase", "unknown")
    dispatch_log = state.get("dynamic_dispatch_log", [])
    already_run = [f"{d['tool']}:{d['target']}" for d in dispatch_log]

    intel_summary = [
        f"Current phase: {current_phase}",
        f"Seeds: {', '.join(seeds)}",
        f"Subdomains found: {len(state.get('subdomain_intel', {}))}",
        f"Emails found: {len(state.get('email_intel', {}).get('emails', {}))}",
        f"Dark intel keys: {list(state.get('dark_intel', {}).keys())[:10]}",
        f"Cloud intel keys: {list(state.get('cloud_intel', {}).keys())[:10]}",
        f"Code intel keys: {list(state.get('code_intel', {}).keys())[:10]}",
        f"Total findings: {len(state.get('findings', []))}",
        f"Open hypotheses: {state.get('hypotheses', [])}",
    ]

    # Only list tools that have trigger hints
    tool_summaries: list[str] = []
    for tool in registry.available_tools():
        hints: list[str] = getattr(tool, "dynamic_trigger_hints", [])
        if hints:
            tool_summaries.append(
                f"  - {tool.name} [{tool.category.value}]"
                f" targets={tool.target_types}"
                f" hints={hints}"
            )

    already_run_lines: list[str] = [f"  - {x}" for x in already_run] if already_run else ["  (none)"]
    tool_lines: list[str] = tool_summaries if tool_summaries else ["  (none with hints)"]

    lines = [
        "## Current Intelligence State",
        *intel_summary,
        "",
        "## Already Dispatched (do not repeat):",
        *already_run_lines,
        "",
        "## Available Tools with Trigger Hints:",
        *tool_lines,
        "",
        "## Task",
        "Based on the intelligence state above, output a JSON array (max 5 items) "
        "of tool dispatches that would close the most important intelligence gaps. "
        "Return [] if no additional tools are warranted.",
    ]
    return "\n".join(lines)


# ── JSON parse ────────────────────────────────────────────────────────────────

def _parse_dispatch_plan(raw: str) -> list[dict[str, Any]]:
    """
    Fail-safe: extract and parse a JSON array from LLM output.
    Returns [] on any failure — never raises.
    """
    try:
        m = re.search(r"\[.*?\]", raw, re.DOTALL)
        if not m:
            return []
        parsed = json.loads(m.group(0))
        if isinstance(parsed, list):
            return parsed
        return []
    except Exception:
        return []


# ── Plan validation ───────────────────────────────────────────────────────────

def _validate_plan(
    plan: list[dict[str, Any]],
    state: CampaignGraphState,
) -> list[dict[str, Any]]:
    """
    Validate each dispatch item:
    - required fields present
    - tool exists in registry
    - target_type accepted by that tool
    - not already run (dedup)

    Returns at most MAX_PER_CYCLE valid items.
    """
    registry = get_registry()
    dispatch_log = state.get("dynamic_dispatch_log", [])
    already_run: set[tuple[str, str]] = {(d["tool"], d["target"]) for d in dispatch_log}

    valid: list[dict[str, Any]] = []
    for item in plan:
        tool_name = str(item.get("tool", "")).strip()
        target = str(item.get("target", "")).strip()
        target_type = str(item.get("target_type", "")).strip()
        reason = str(item.get("reason", ""))

        if not tool_name or not target or not target_type:
            log.debug("Dispatch item missing required fields", item=item)
            continue

        tool_obj = registry.get(tool_name)
        if tool_obj is None:
            log.info("Dynamic dispatch skipped: tool not in registry", tool=tool_name)
            continue

        accepted_types: list[str] = getattr(tool_obj, "target_types", [])
        if target_type not in accepted_types:
            log.info(
                "Dynamic dispatch skipped: target_type mismatch",
                tool=tool_name,
                target_type=target_type,
                accepted=accepted_types,
            )
            continue

        if (tool_name, target) in already_run:
            log.debug("Dynamic dispatch skipped: already run", tool=tool_name, target=target)
            continue

        valid.append({
            "tool": tool_name,
            "target": target,
            "target_type": target_type,
            "reason": reason,
        })

        if len(valid) >= MAX_PER_CYCLE:
            break

    return valid


# ── Execution ─────────────────────────────────────────────────────────────────

async def _execute_plan(
    plan: list[dict[str, Any]],
    state: CampaignGraphState,
) -> CampaignGraphState:
    """
    Fan-out: execute all valid dispatch items concurrently, merge results into state.
    """
    registry = get_registry()
    current_phase = state.get("current_phase", "unknown")
    dispatch_log = list(state.get("dynamic_dispatch_log", []))

    async def _run_one(
        item: dict[str, Any],
    ) -> tuple[dict[str, Any], Any | None]:
        try:
            result = await registry.execute(
                item["tool"], item["target"], item["target_type"]
            )
            return item, result
        except Exception as exc:
            log.warning(
                "Dynamic dispatch execution error",
                tool=item["tool"],
                error=str(exc),
            )
            return item, None

    entries = await asyncio.gather(*(_run_one(i) for i in plan), return_exceptions=True)

    all_tools = {t.name: t for t in registry.available_tools()}

    for entry in entries:
        if isinstance(entry, Exception):
            continue
        item, result = entry

        log_entry: dict[str, Any] = {
            "tool": item["tool"],
            "target": item["target"],
            "target_type": item["target_type"],
            "reason": item["reason"],
            "phase": current_phase,
            "timestamp": datetime.now(UTC).isoformat(),
            "success": result is not None and getattr(result, "success", False),
        }
        dispatch_log.append(log_entry)

        if result is None or not getattr(result, "success", False):
            continue

        # Merge result data into the appropriate state dict
        tool_obj = all_tools.get(item["tool"])
        if tool_obj is None:
            continue

        cat = tool_obj.category.value
        state_key = CATEGORY_TO_STATE_KEY.get(cat)
        if state_key:
            existing = state.get(state_key) or {}
            if isinstance(existing, dict):
                merge_key = f"dynamic/{item['tool']}/{item['target']}"
                existing[merge_key] = result.data
                state[state_key] = existing  # type: ignore[literal-required]

    state["dynamic_dispatch_log"] = dispatch_log
    return state


# ── Main entry point ──────────────────────────────────────────────────────────

def _resolve_policy(state: CampaignGraphState) -> Any:
    """Phase 1 PR A: resolve the active :class:`DispatchPolicy`.

    Order of precedence (highest → lowest):
      1. ``state["dispatch_policy_name"]`` — set by an
         operator-authored Strategy or by a future planner
         agent.
      2. ``state["dispatch_mode"]`` — legacy field carrying
         the ``--dispatch-mode`` CLI flag value
         (``lite`` / ``full`` / ``off``).
      3. Default ``LitePolicy``.

    Falling back gracefully on import error keeps the module
    importable even when the new ``strategy`` package is
    missing (matters for tests that monkey-patch only the
    legacy surface)."""
    try:
        from nexusrecon.strategy.policy import get_policy
        name = (
            state.get("dispatch_policy_name")
            or state.get("dispatch_mode")
            or "lite"
        )
        return get_policy(str(name))
    except Exception as exc:
        log.warning("Dispatch policy resolution failed, falling back to lite",
                    error=str(exc))
        # Last-resort: re-import the bundled LitePolicy.
        from nexusrecon.strategy.policy import LitePolicy
        return LitePolicy()


async def run_dynamic_dispatch(state: CampaignGraphState) -> CampaignGraphState:
    """
    Build LLM prompt → parse plan → validate → execute → merge.

    Returns state unchanged if:
    - Total budget (MAX_TOTAL) is already exhausted
    - LLM call fails
    - Plan parses to []
    - No items survive validation

    Phase 1 PR A: the cap values + the per-phase eligibility
    check now come from the active :class:`DispatchPolicy`
    (resolved via ``state["dispatch_policy_name"]`` or the
    legacy ``state["dispatch_mode"]``). Module-level
    constants (``MAX_PER_CYCLE``, ``MAX_TOTAL``,
    ``LITE_DISPATCH_PHASES``) are kept as backward-compat
    defaults referenced by tests that pre-date the policy
    interface; the runtime uses the policy values.
    """
    policy = _resolve_policy(state)
    dispatch_log = state.get("dynamic_dispatch_log", [])

    # Hard total cap comes from the policy. ``OffPolicy`` has
    # ``max_total=0`` so this short-circuits immediately when
    # the operator picked ``off``.
    remaining = policy.max_total - len(dispatch_log)
    if remaining <= 0:
        log.info(
            "Total dispatch budget exhausted",
            total=len(dispatch_log), policy=policy.name,
        )
        return state

    # ── Call LLM ──────────────────────────────────────────────────────────────
    try:
        from nexusrecon.agents.dynamic_dispatcher import DISPATCHER_SYSTEM_PROMPT
        from nexusrecon.core.config import get_config
        from nexusrecon.graph.agent_executor import get_llm_from_config

        config = get_config()
        llm = get_llm_from_config(config)
        prompt = DISPATCHER_SYSTEM_PROMPT + "\n\n" + _build_dispatch_prompt(state)
        response = llm.invoke(prompt)
        raw = str(response.content) if hasattr(response, "content") else str(response)
    except Exception as exc:
        log.warning("Dynamic dispatcher LLM call failed", error=str(exc))
        return state

    # ── Parse (fail-safe) ─────────────────────────────────────────────────────
    plan = _parse_dispatch_plan(raw)
    if not plan:
        log.info("Dynamic dispatcher: empty plan from LLM")
        return state

    # ── Validate ──────────────────────────────────────────────────────────────
    valid_plan = _validate_plan(plan, state)
    # Per-cycle + remaining-total caps come from the policy.
    valid_plan = valid_plan[: min(policy.max_per_cycle, remaining)]
    if not valid_plan:
        log.info("Dynamic dispatcher: no valid items after validation")
        return state

    # ── Simulate (Phase 1 PR C) ───────────────────────────────────────────────
    # Pre-execution forecast of cost, expected graph growth, and
    # scope-creep risk. Always recorded to ``state["simulation_log"]``
    # so the audit trail can answer "what did we expect vs. what
    # happened?". When ``state["simulation_gating"]`` is truthy and
    # the simulator recommends ``abort``, the dispatch is suppressed;
    # otherwise the recommendation is advisory only.
    try:
        from nexusrecon.strategy.simulation import (
            append_simulation_log,
            simulate_dispatch_plan,
        )
        simulation = simulate_dispatch_plan(valid_plan, state)
    except Exception as exc:
        # Simulator failures must not block real dispatch.
        log.warning("Simulator failed — proceeding without forecast",
                    error=str(exc))
        simulation = None

    # Audit log access — read once and reuse for every
    # strategic decision in this dispatch cycle. ``None`` when
    # running outside a campaign context (tests, dry runs).
    audit_log = getattr(get_registry(), "audit_log", None)

    if audit_log is not None:
        try:
            audit_log.log_dispatch_policy_resolved(
                policy_name=policy.name,
                source=_policy_source(state),
                current_phase=str(state.get("current_phase", "")),
                eligible=True,
            )
        except Exception as exc:
            log.debug("Audit log write failed", error=str(exc))

    if (
        simulation is not None
        and simulation.recommendation == "abort"
        and state.get("simulation_gating")
    ):
        log.warning(
            "Dispatch aborted by simulation gate",
            rationale=simulation.rationale,
            estimated_cost=simulation.estimated_cost_usd,
        )
        append_simulation_log(state, simulation, decision="aborted_by_gate")
        _audit_simulation(audit_log, simulation, decision="aborted_by_gate")
        return state

    # ── Route plan items (Phase 1 PR D) ────────────────────────────
    # Split into immediate-execute, deep-pivot grants, and
    # human-approval queue adds. Items without the new fields
    # behave exactly as before (action == "execute" with the
    # campaign policy unchanged).
    from nexusrecon.strategy.bounded_agency import (
        queue_for_approval,
        resolve_pivot_policy,
        route_plan_items,
    )

    decisions = route_plan_items(
        valid_plan,
        default_policy_name=policy.name,
    )

    items_to_execute: list[dict[str, Any]] = []
    for decision in decisions:
        if decision.action == "human_approval":
            cost_estimate = _per_item_cost_estimate(
                simulation, decision.item,
            )
            queued = queue_for_approval(
                state, decision.item,
                reason=decision.queue_reason,
                estimated_cost_usd=cost_estimate,
                tier=_item_tier(decision.item),
            )
            if audit_log is not None:
                try:
                    audit_log.log_human_approval_queued(
                        tool=queued["tool"],
                        target=queued["target"],
                        reason=queued["approval_reason"],
                        tier=queued["tier"],
                        estimated_cost_usd=queued["estimated_cost_usd"],
                    )
                except Exception as exc:
                    log.debug("Audit log write failed", error=str(exc))
            continue

        if decision.action == "deep_pivot":
            override = resolve_pivot_policy(
                decision.override_policy_name or policy.name,
                default_policy_name=policy.name,
            )
            if audit_log is not None:
                try:
                    audit_log.log_deep_pivot_grant(
                        tool=str(decision.item.get("tool", "")),
                        target=str(decision.item.get("target", "")),
                        granting_policy=policy.name,
                        override_policy=override.name,
                        rationale=decision.queue_reason,
                    )
                except Exception as exc:
                    log.debug("Audit log write failed", error=str(exc))
            items_to_execute.append(decision.item)
            continue

        items_to_execute.append(decision.item)

    if not items_to_execute:
        # Everything routed to approval / rejected — nothing to
        # run, but the simulation outcome is still part of the
        # audit trail.
        if simulation is not None:
            append_simulation_log(
                state, simulation, decision="queued_for_approval",
            )
            _audit_simulation(
                audit_log, simulation, decision="queued_for_approval",
            )
        return state

    log.info(
        "Dynamic dispatcher executing",
        count=len(items_to_execute), policy=policy.name,
    )
    state = await _execute_plan(items_to_execute, state)
    if simulation is not None:
        append_simulation_log(state, simulation, decision="executed")
        _audit_simulation(audit_log, simulation, decision="executed")
    return state


# ── Audit helpers (Phase 1 PR D) ─────────────────────────────────────


def _policy_source(state: CampaignGraphState) -> str:
    """Mirror of :func:`_resolve_policy`'s precedence chain —
    surfaces which slot the active policy name came from so
    audit reviewers can trace how the dispatcher arrived at
    its choice."""
    if state.get("dispatch_policy_name"):
        return "strategy"
    if state.get("dispatch_mode"):
        return "state.dispatch_mode"
    return "default"


def _audit_simulation(
    audit_log: Any,
    simulation: Any,
    *,
    decision: str,
) -> None:
    """Write a hash-chained simulation reference. The full
    body lives in ``state["simulation_log"]``; this entry is
    the tamper-evident pointer."""
    if audit_log is None or simulation is None:
        return
    try:
        audit_log.log_simulation(
            plan_size=simulation.plan_size,
            estimated_cost_usd=simulation.estimated_cost_usd,
            expected_new_nodes=simulation.expected_new_nodes,
            recommendation=simulation.recommendation,
            confidence=simulation.confidence,
            decision=decision,
            flag_kinds=[f["kind"] for f in simulation.scope_creep_flags],
        )
    except Exception as exc:
        log.debug("Audit log write failed", error=str(exc))


def _per_item_cost_estimate(simulation: Any, item: dict[str, Any]) -> float:
    """Find the simulated cost for one plan item (if any).
    Falls back to ``0.0`` so audit / approval queues always
    have a number even when the simulator didn't run."""
    if simulation is None:
        return 0.0
    tool = str(item.get("tool", ""))
    target = str(item.get("target", ""))
    for sim_item in getattr(simulation, "items", []):
        if sim_item.tool == tool and sim_item.target == target:
            return float(sim_item.estimated_cost_usd)
    return 0.0


def _item_tier(item: dict[str, Any]) -> str:
    """Best-effort: read the tier the planner / dispatcher
    knew about. Tools whose tier we can't determine show as
    ``?`` in the approval queue — operators see this and know
    the underlying tool registration is missing tier metadata."""
    try:
        registry = get_registry()
        tool_obj = registry.get(str(item.get("tool", "")))
        if tool_obj is None:
            return "?"
        tier = getattr(tool_obj, "tier", None)
        return str(getattr(tier, "value", tier or "?"))
    except Exception:
        return "?"
