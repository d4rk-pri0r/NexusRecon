"""Campaign-level planner orchestration — Phase 1 PR B.

PR A introduced the :class:`~nexusrecon.strategy.plan.Strategy`
shape and the :class:`~nexusrecon.strategy.policy.DispatchPolicy`
hierarchy. PR B operationalises the
:class:`~nexusrecon.agents.planner.CampaignPlannerAgent` —
which has lived in the agent registry since Phase D but was
never called — and turns its output into a real ``Strategy``
the reflection node can consult.

The single public entry point is :func:`plan_campaign`. It
takes the same inputs the operator already gives ``nexusrecon
run`` (scope, seeds, mode, dispatch policy preference), invokes
the planner LLM, parses the response into a ``Strategy``, and
falls back to :meth:`Strategy.default` on any failure. The
fallback is intentional: a planner outage or a malformed
response must NOT block a campaign — the operator can always
run with default behavior.

Why route this through an explicit orchestrator (instead of
letting the workflow run the planner as another phase node):

  - ``--plan-only`` UX. The operator wants to see the strategy
    before any tools fire so they can sanity-check what the
    planner picked. A phase node can't do that — it runs after
    the workflow is committed.
  - Re-planning hook. :func:`replan` runs the same path mid-
    campaign when fresh intel changes the picture (Phase 1 PR
    B §3 in the plan). Surfacing it as a function (not a node)
    keeps the workflow shape unchanged.
  - Audit. Every plan / replan emits a record into
    ``state["strategy_history"]`` so the audit trail can
    reconstruct what the operator was told vs. what actually
    ran.

What's intentionally NOT here yet
  - Simulation / what-if (PR C).
  - Hash-chained signature on the strategy record (PR D).
  - Auto-replan triggers (PR D — for now ``replan`` is
    operator-initiated).
"""
from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from typing import Any

import structlog

from nexusrecon.strategy.plan import (
    KillCriterion,
    Strategy,
    SuccessCriterion,
)
from nexusrecon.strategy.policy import get_policy

log = structlog.get_logger(__name__)


# ──────────────────────────────────────────────────────────────────────
# Prompt builder
# ──────────────────────────────────────────────────────────────────────


def _build_planner_prompt(
    *,
    scope_summary: str,
    seeds: list[str],
    mode: str,
    dispatch_policy_name: str,
    max_llm_cost_usd: float,
) -> str:
    """Build the strategic-planning prompt the
    :class:`CampaignPlannerAgent` sees.

    The output contract is a strict JSON envelope so the parser
    doesn't have to be clever. The agent already has the
    high-level role description baked into its system prompt
    (see :mod:`nexusrecon.agents.planner`); this prompt is the
    task-specific addendum.
    """
    seeds_line = ", ".join(seeds) if seeds else "(none — use scope domains)"
    return (
        "## Engagement Summary\n"
        f"{scope_summary}\n\n"
        "## Operator Inputs\n"
        f"- Seeds: {seeds_line}\n"
        f"- Mode: {mode}\n"
        f"- Operator-selected dispatch policy: {dispatch_policy_name}\n"
        f"- LLM budget (USD): {max_llm_cost_usd:.2f}\n\n"
        "## Task\n"
        "Produce a campaign strategy as a strict JSON object with the\n"
        "fields below. Use null for any field you are not\n"
        "confident about — the orchestrator will fill defaults.\n\n"
        "```json\n"
        "{\n"
        '  "name": "short-kebab-case-name",\n'
        '  "rationale": "one-paragraph explanation of the choices",\n'
        '  "phases": ["phase1", "phase2", ...],\n'
        '  "dispatch_policy_name": "lite|full|off",\n'
        '  "tool_budgets": {"shodan": 10, "category:cloud": 25},\n'
        '  "success_criteria": [\n'
        '    {"metric": "confirmed_leads", "op": ">=", "threshold": 5,\n'
        '     "description": "Why this matters"}\n'
        "  ],\n"
        '  "kill_criteria": [\n'
        '    {"metric": "llm_cost_usd", "op": ">", "threshold": 20.0,\n'
        '     "action": "pause_for_review",\n'
        '     "description": "Why this matters"}\n'
        "  ]\n"
        "}\n"
        "```\n\n"
        "CONSTRAINTS:\n"
        "- Respect the scope's tier ceiling. Never pick active\n"
        "  (T2/T3) tools if scope only allows T0/T1.\n"
        "- Pick a `dispatch_policy_name` that matches the\n"
        "  operator's risk posture: `lite` for stealth/safety,\n"
        "  `full` for time-boxed deep dives, `off` for\n"
        "  pre-engagement reconnaissance reviews.\n"
        "- Phase identifiers MUST come from the canonical set:\n"
        "  phase1, phase2, phase2_5, phase3, phase4, phase5,\n"
        "  phase6, phase7, phase7_5, phase7_7, phase8, phase9.\n"
        "- Keep `tool_budgets` empty if you don't have a strong\n"
        "  reason to constrain a specific tool.\n"
    )


# ──────────────────────────────────────────────────────────────────────
# Response parsing
# ──────────────────────────────────────────────────────────────────────


def _extract_json_object(raw: str) -> dict[str, Any] | None:
    """Pull the first JSON object out of an LLM response. Tolerant
    of code-fenced blocks + chatter on either side. Returns
    ``None`` if no parsable object is found — the caller falls
    back to :meth:`Strategy.default`."""
    fenced = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", raw, re.DOTALL)
    candidate = fenced.group(1) if fenced else None
    if candidate is None:
        match = re.search(r"\{.*\}", raw, re.DOTALL)
        if not match:
            return None
        candidate = match.group(0)
    try:
        parsed = json.loads(candidate)
    except Exception:
        return None
    return parsed if isinstance(parsed, dict) else None


def _coerce_to_strategy(
    parsed: dict[str, Any],
    *,
    fallback_dispatch_policy_name: str,
    operator_metadata: dict[str, Any],
) -> Strategy:
    """Lift a parsed planner-response dict into a validated
    :class:`Strategy`. Unknown phase identifiers are dropped
    rather than raised — the planner occasionally hallucinates
    phase names and we'd rather degrade than crash."""
    canonical_phases = {
        "phase1", "phase2", "phase2_5", "phase3", "phase4",
        "phase5", "phase6", "phase7", "phase7_5", "phase7_7",
        "phase8", "phase9",
    }
    requested_phases = parsed.get("phases") or []
    if not isinstance(requested_phases, list):
        requested_phases = []
    phases = [
        str(p) for p in requested_phases
        if isinstance(p, str) and p in canonical_phases
    ]
    if not phases:
        # Empty / all-invalid → fall back to the canonical order.
        phases = list(Strategy().phases)

    dispatch_policy_name = str(
        parsed.get("dispatch_policy_name")
        or fallback_dispatch_policy_name
        or "lite",
    ).lower()
    # Validate against the policy registry; unknown names land
    # on lite (matches :func:`get_policy`'s behavior so we don't
    # write a strategy that disagrees with what the dispatcher
    # would resolve later).
    resolved = get_policy(dispatch_policy_name)
    dispatch_policy_name = resolved.name

    tool_budgets_raw = parsed.get("tool_budgets") or {}
    if isinstance(tool_budgets_raw, dict):
        tool_budgets = {
            str(k): int(v)
            for k, v in tool_budgets_raw.items()
            if isinstance(v, (int, float)) and int(v) > 0
        }
    else:
        tool_budgets = {}

    success_criteria = _coerce_criteria(
        parsed.get("success_criteria"),
        SuccessCriterion,
    )
    kill_criteria = _coerce_criteria(
        parsed.get("kill_criteria"),
        KillCriterion,
    )

    metadata = dict(operator_metadata)
    rationale = parsed.get("rationale")
    if isinstance(rationale, str) and rationale.strip():
        metadata["planner_rationale"] = rationale.strip()
    metadata["planner_response_kind"] = "structured"

    return Strategy(
        name=str(parsed.get("name") or "planner_generated"),
        phases=phases,
        dispatch_policy_name=dispatch_policy_name,
        tool_budgets=tool_budgets,
        success_criteria=success_criteria,
        kill_criteria=kill_criteria,
        metadata=metadata,
    )


def _coerce_criteria(items: Any, klass: type) -> list:
    """Best-effort coercion for ``success_criteria`` /
    ``kill_criteria`` arrays. Drops malformed entries instead of
    raising — see the parse-tolerance rationale on
    :func:`_coerce_to_strategy`."""
    if not isinstance(items, list):
        return []
    out: list = []
    for item in items:
        if not isinstance(item, dict):
            continue
        try:
            metric = str(item["metric"])
            op = str(item["op"])
        except (KeyError, TypeError):
            continue
        kwargs: dict[str, Any] = {
            "metric": metric,
            "op": op,
            "threshold": item.get("threshold"),
            "scope": dict(item.get("scope") or {}),
            "description": str(item.get("description") or ""),
        }
        if klass is KillCriterion:
            action = str(item.get("action") or "pause_for_review")
            if action not in {"abort", "pause_for_review"}:
                action = "pause_for_review"
            kwargs["action"] = action
        out.append(klass(**kwargs))
    return out


# ──────────────────────────────────────────────────────────────────────
# Public entry points
# ──────────────────────────────────────────────────────────────────────


async def plan_campaign(
    *,
    scope_summary: str,
    seeds: list[str],
    mode: str,
    dispatch_policy_name: str = "lite",
    max_llm_cost_usd: float = 10.0,
    executor: Any | None = None,
    state: dict[str, Any] | None = None,
) -> Strategy:
    """Produce a :class:`Strategy` for the campaign.

    Arguments mirror the operator-facing inputs to ``nexusrecon
    run``. ``executor`` is an
    :class:`~nexusrecon.graph.agent_executor.AgentExecutor`;
    when ``None`` we construct one from the active config so
    callers don't need to plumb it through. ``state`` is the
    live campaign state if available — used for budget
    enforcement + the strategy-history audit entry.

    Failure modes (planner unavailable, malformed response,
    parse error) all degrade to :meth:`Strategy.default` with
    ``metadata.planner_response_kind = "fallback"`` so the
    audit trail shows the planner was invoked but didn't yield
    a usable strategy."""
    timestamp = datetime.now(UTC).isoformat()
    operator_metadata: dict[str, Any] = {
        "planner_timestamp": timestamp,
        "planner_operator_inputs": {
            "seeds": list(seeds),
            "mode": mode,
            "dispatch_policy_name": dispatch_policy_name,
            "max_llm_cost_usd": max_llm_cost_usd,
        },
    }

    # Build the executor on demand. Tests inject a fake to skip
    # the LLM round-trip.
    if executor is None:
        try:
            from nexusrecon.core.config import get_config
            from nexusrecon.graph.agent_executor import AgentExecutor
            executor = AgentExecutor(get_config())
        except Exception as exc:
            log.warning(
                "Planner: could not construct AgentExecutor",
                error=str(exc),
            )
            return _fallback_strategy(operator_metadata, reason="no_executor")

    prompt = _build_planner_prompt(
        scope_summary=scope_summary,
        seeds=seeds,
        mode=mode,
        dispatch_policy_name=dispatch_policy_name,
        max_llm_cost_usd=max_llm_cost_usd,
    )

    try:
        result = await executor.run_agent(
            "campaign_planner",
            task_data={"seeds": seeds, "mode": mode},
            task_prompt=prompt,
            state=state,
        )
    except Exception as exc:
        log.warning(
            "Planner LLM call failed — falling back to default",
            error=str(exc),
        )
        return _fallback_strategy(operator_metadata, reason=str(exc))

    raw = str(result.get("output", "")) if isinstance(result, dict) else ""
    parsed = _extract_json_object(raw)
    if parsed is None:
        log.info("Planner: no parsable JSON in response — falling back")
        return _fallback_strategy(
            operator_metadata,
            reason="parse_failure",
            extra={"planner_raw_output": raw[:2000]},
        )

    strategy = _coerce_to_strategy(
        parsed,
        fallback_dispatch_policy_name=dispatch_policy_name,
        operator_metadata=operator_metadata,
    )

    if state is not None:
        _append_history(state, strategy, reason="initial")

    # Phase 1 PR D: hash-chained record of the strategic
    # decision. Goes through the campaign's AuditLog if one is
    # bound to the tool registry; silent no-op otherwise (tests,
    # dry runs).
    try:
        from nexusrecon.tools.registry import get_registry
        audit = getattr(get_registry(), "audit_log", None)
        if audit is not None:
            audit.log_strategy_generated(
                strategy_name=strategy.name,
                dispatch_policy_name=strategy.dispatch_policy_name,
                phases=strategy.phases,
                response_kind=str(strategy.metadata.get(
                    "planner_response_kind", "structured",
                )),
                fallback_reason=str(strategy.metadata.get(
                    "planner_fallback_reason", "",
                )) or None,
            )
    except Exception as exc:
        log.debug("Strategy audit log write failed", error=str(exc))

    log.info(
        "Planner produced strategy",
        name=strategy.name,
        phases=len(strategy.phases),
        dispatch_policy=strategy.dispatch_policy_name,
        success_criteria=len(strategy.success_criteria),
        kill_criteria=len(strategy.kill_criteria),
    )
    return strategy


async def replan(
    state: dict[str, Any],
    *,
    reason: str,
    executor: Any | None = None,
) -> Strategy:
    """Re-invoke the planner mid-campaign.

    ``reason`` is a short human-readable string explaining why
    the operator (or an upstream trigger) asked for a re-plan.
    The new strategy is appended to ``state["strategy_history"]``
    and returned; callers decide whether to swap it into
    ``state["strategy"]`` (PR D will add the
    confidence-graded auto-swap; today it's operator-explicit).

    PR B scope: surface the function. Auto-triggers (state-
    change detectors that fire ``replan`` automatically) come
    in PR D."""
    seeds = list(state.get("seeds") or [])
    mode = str(state.get("campaign_mode") or "medium")
    dispatch_policy_name = str(
        state.get("strategy", {}).get("dispatch_policy_name")
        or state.get("dispatch_policy_name")
        or state.get("dispatch_mode")
        or "lite",
    )
    max_llm_cost_usd = float(state.get("max_llm_cost_usd", 10.0))
    scope_summary = str(state.get("scope_summary") or "(scope summary unavailable)")

    old_strategy_name = str(
        (state.get("strategy") or {}).get("name") or "default",
    )

    new_strategy = await plan_campaign(
        scope_summary=scope_summary,
        seeds=seeds,
        mode=mode,
        dispatch_policy_name=dispatch_policy_name,
        max_llm_cost_usd=max_llm_cost_usd,
        executor=executor,
        state=state,
    )
    # plan_campaign() appended an "initial" history record;
    # overwrite the last record's reason so the audit trail
    # shows this came from replan().
    history = state.get("strategy_history") or []
    if history:
        history[-1]["reason"] = f"replan: {reason}"
        state["strategy_history"] = history

    # Phase 1 PR D: hash-chained replan record. Pairs with the
    # ``strategy_generated`` entry plan_campaign() already wrote.
    try:
        from nexusrecon.tools.registry import get_registry
        audit = getattr(get_registry(), "audit_log", None)
        if audit is not None:
            audit.log_strategy_replan(
                reason=reason,
                old_name=old_strategy_name,
                new_name=new_strategy.name,
                new_dispatch_policy_name=new_strategy.dispatch_policy_name,
            )
    except Exception as exc:
        log.debug("Replan audit log write failed", error=str(exc))
    return new_strategy


# ──────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────


def _fallback_strategy(
    operator_metadata: dict[str, Any],
    *,
    reason: str,
    extra: dict[str, Any] | None = None,
) -> Strategy:
    """Produce a default strategy + tag it as a fallback so the
    audit trail records that the planner ran but didn't yield
    a usable result."""
    metadata = dict(operator_metadata)
    metadata["planner_response_kind"] = "fallback"
    metadata["planner_fallback_reason"] = reason
    if extra:
        metadata.update(extra)
    base = Strategy.default()
    strategy = Strategy(
        name=base.name,
        phases=list(base.phases),
        dispatch_policy_name=base.dispatch_policy_name,
        tool_budgets=dict(base.tool_budgets),
        success_criteria=list(base.success_criteria),
        kill_criteria=list(base.kill_criteria),
        metadata=metadata,
    )
    # Phase 1 PR D: fallbacks are strategic decisions too —
    # record so the audit trail shows when the planner couldn't
    # give us a real plan.
    try:
        from nexusrecon.tools.registry import get_registry
        audit = getattr(get_registry(), "audit_log", None)
        if audit is not None:
            audit.log_strategy_generated(
                strategy_name=strategy.name,
                dispatch_policy_name=strategy.dispatch_policy_name,
                phases=strategy.phases,
                response_kind="fallback",
                fallback_reason=reason,
            )
    except Exception as exc:
        log.debug("Fallback audit log write failed", error=str(exc))
    return strategy


def _append_history(
    state: dict[str, Any],
    strategy: Strategy,
    *,
    reason: str,
) -> None:
    """Append a strategy record to ``state["strategy_history"]``.

    The record is the strategy dict + a wrapper carrying the
    reason and timestamp. Future PR D will hash-chain these
    records into the audit log; for now they're plain dicts so
    they survive ``state.json`` round-trips."""
    history = list(state.get("strategy_history") or [])
    history.append({
        "timestamp": datetime.now(UTC).isoformat(),
        "reason": reason,
        "strategy": strategy.to_dict(),
    })
    state["strategy_history"] = history
