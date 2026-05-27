"""Simulation & What-If — Phase 1 PR C.

Cheap pre-execution estimator for a dispatch plan. Answers three
questions the operator (and the audit log) wants on record
before tools fire:

  1. **What's this going to cost?** Sum of per-tool
     ``cost_per_run_usd`` values from the registry. Best-case:
     all tools have an honest cost field. Worst-case: missing
     fields fall back to ``0.0`` and the estimate is tagged
     "low_confidence" so the operator knows.
  2. **How much will the graph grow?** Per-category heuristic
     (see ``_EXPECTED_NEW_NODES_PER_TOOL``). Tuned from real
     campaign telemetry — not a guarantee, just an order-of-
     magnitude estimate so the operator can spot a plan that
     would double the graph size.
  3. **Where's the scope-creep risk?** Two checks:
     - Per-item: tool tier > scope's ``max_tier`` (the
       scope_guard already enforces this at execution time, but
       surfacing it in simulation lets the operator catch a
       broken plan before the LLM round-trips it).
     - Pivot fan-out: dispatching against a target that
       isn't already an entity in the graph (i.e. the plan
       wants to pivot to a new seed). Not always wrong, but
       worth flagging.

Today the simulator runs synchronously on the validated
dispatch plan. Tomorrow (PR D) it'll plug into a more elaborate
"strategy preview" surface in the TUI; the shape here is the
minimum that supports both.

What this is NOT
- A guarantee. Tool outputs vary wildly with target shape;
  the estimates are reference numbers, not contracts.
- A replacement for the scope_guard. The guard is the legal
  boundary; this is a forecast.
- LLM-based. The plan §147 says "cheap simulation" — we want
  this <100ms even on big plans. No model calls.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import structlog

log = structlog.get_logger(__name__)


# ──────────────────────────────────────────────────────────────────────
# Heuristics
# ──────────────────────────────────────────────────────────────────────

#: Expected number of NEW graph entities a tool of a given
#: category contributes per run, on average. Numbers come from
#: rough telemetry across the bundled tool suite; community
#: tools can override by setting a class-level
#: ``expected_new_nodes_per_run`` attribute (read at simulation
#: time). Conservative bias: prefer to under-estimate, since
#: a plan that "only" produces 50 nodes might produce 200, but
#: that's a smaller surprise than the reverse.
_EXPECTED_NEW_NODES_PER_TOOL: dict[str, int] = {
    "subdomain": 25,         # subfinder/amass typically yield dozens
    "domain": 1,             # whois, dns -> a few records, mostly metadata
    "dns": 5,                # records -> A/AAAA/MX/NS
    "certificate": 8,        # crtsh -> a handful of related domains
    "email": 8,              # hunter/h8mail -> a few addresses
    "identity": 5,           # github/linkedin -> a person + handles
    "breach": 3,             # h8mail/hibp -> credentials + email-link
    "infrastructure": 4,     # naabu/shodan -> services
    "cloud": 6,              # cloud_enum -> buckets/keys/instances
    "cloud_aws": 6,
    "cloud_azure": 6,
    "cloud_gcp": 6,
    "code": 4,               # github_dorks -> repos/files
    "secret": 3,
    "web": 3,
    "vulnerability": 2,      # nuclei -> findings, not always entities
    "mobile": 4,
    "social": 6,
    "pretext": 2,            # pretext intel is mostly metadata enrichment
    "news": 2,
}

#: Default fallback when a tool's category isn't in the table.
#: Set conservatively so unknown categories don't dominate the
#: total via a runaway estimate.
_DEFAULT_EXPECTED_NEW_NODES: int = 3

#: Tier ordering so we can compare "T2 > T1" without string
#: gymnastics elsewhere.
_TIER_ORDER: dict[str, int] = {"T0": 0, "T1": 1, "T2": 2, "T3": 3}


# ──────────────────────────────────────────────────────────────────────
# Result types
# ──────────────────────────────────────────────────────────────────────


@dataclass
class SimulatedItem:
    """Per-dispatch-item simulation result. One entry for each
    plan item the simulator saw — surfaces in the audit log so
    forensics can answer "why did the simulator OK this?"."""

    tool: str
    target: str
    target_type: str
    estimated_cost_usd: float
    expected_new_nodes: int
    tier: str
    flags: list[str] = field(default_factory=list)
    """Per-item scope-creep / risk markers. Free-form so future
    PRs can add new flag types without breaking consumers; the
    operator-facing TUI just renders them as a bulleted list."""


@dataclass
class SimulationResult:
    """Aggregate simulation across a dispatch plan."""

    plan_size: int
    estimated_cost_usd: float
    estimated_runtime_sec: int
    expected_new_nodes: int
    expected_new_nodes_by_category: dict[str, int]
    scope_creep_flags: list[dict[str, Any]]
    items: list[SimulatedItem]
    recommendation: str
    """One of ``proceed`` / ``warn`` / ``abort``. ``warn`` is
    advisory only — the dispatcher still executes by default;
    ``abort`` only stops execution when
    ``state["simulation_gating"]`` is truthy."""

    rationale: str
    confidence: str  # "high" | "medium" | "low"
    timestamp: str

    def to_dict(self) -> dict[str, Any]:
        """Serialise for ``state["simulation_log"]`` + JSON
        audit. Keeps the shape stable so forensics tools can
        parse old simulations without a version negotiation."""
        return {
            "plan_size": self.plan_size,
            "estimated_cost_usd": round(self.estimated_cost_usd, 4),
            "estimated_runtime_sec": self.estimated_runtime_sec,
            "expected_new_nodes": self.expected_new_nodes,
            "expected_new_nodes_by_category":
                dict(self.expected_new_nodes_by_category),
            "scope_creep_flags": list(self.scope_creep_flags),
            "items": [
                {
                    "tool": i.tool, "target": i.target,
                    "target_type": i.target_type,
                    "estimated_cost_usd": round(i.estimated_cost_usd, 4),
                    "expected_new_nodes": i.expected_new_nodes,
                    "tier": i.tier,
                    "flags": list(i.flags),
                }
                for i in self.items
            ],
            "recommendation": self.recommendation,
            "rationale": self.rationale,
            "confidence": self.confidence,
            "timestamp": self.timestamp,
        }


# ──────────────────────────────────────────────────────────────────────
# Public API
# ──────────────────────────────────────────────────────────────────────


def simulate_dispatch_plan(
    plan: list[dict[str, Any]],
    state: dict[str, Any] | None = None,
    *,
    scope_max_tier: str | None = None,
    registry: Any | None = None,
) -> SimulationResult:
    """Estimate the cost, graph growth, and scope-creep risk of
    executing ``plan``.

    ``state`` is the live campaign state. When present, the
    simulator pulls ``scope_max_tier`` from
    ``state["scope_max_tier"]`` if not explicitly passed, and
    cross-references known graph entities to spot pivot fan-out.

    ``registry`` is the
    :class:`~nexusrecon.tools.registry.ToolRegistry` — passed in
    by the dispatcher to avoid re-importing. Default behavior:
    fetch the singleton via :func:`get_registry`.
    """
    timestamp = datetime.now(UTC).isoformat()
    if registry is None:
        try:
            from nexusrecon.tools.registry import get_registry
            registry = get_registry()
        except Exception as exc:
            log.warning(
                "Simulator: registry unavailable — falling back",
                error=str(exc),
            )
            return _empty_simulation(
                plan, reason=f"registry_error: {exc}",
                timestamp=timestamp,
            )

    scope_max_tier = (
        scope_max_tier
        or (state or {}).get("scope_max_tier")
    )
    known_entity_targets = _collect_known_entity_targets(state)

    items: list[SimulatedItem] = []
    flags: list[dict[str, Any]] = []
    total_cost = 0.0
    total_runtime = 0
    total_new_nodes = 0
    nodes_by_category: dict[str, int] = {}
    missing_cost_count = 0

    for raw_item in plan:
        item = _simulate_one(
            raw_item,
            registry=registry,
            scope_max_tier=scope_max_tier,
            known_entity_targets=known_entity_targets,
        )
        items.append(item)
        total_cost += item.estimated_cost_usd
        total_new_nodes += item.expected_new_nodes
        cat = _tool_category_value(registry, item.tool)
        if cat:
            nodes_by_category[cat] = (
                nodes_by_category.get(cat, 0) + item.expected_new_nodes
            )
        tool_obj = _tool_obj(registry, item.tool)
        if tool_obj is not None:
            total_runtime += int(getattr(tool_obj, "avg_runtime_sec", 30))
            if not getattr(tool_obj, "cost_per_run_usd", 0.0):
                missing_cost_count += 1
        # Lift per-item flags to the plan-level flag list so the
        # audit log has one place to scan.
        for flag in item.flags:
            flags.append({
                "kind": flag,
                "tool": item.tool,
                "target": item.target,
            })

    confidence = _confidence(missing_cost_count, len(plan))
    recommendation, rationale = _recommend(
        flags=flags,
        cost=total_cost,
        state=state,
    )

    return SimulationResult(
        plan_size=len(plan),
        estimated_cost_usd=total_cost,
        estimated_runtime_sec=total_runtime,
        expected_new_nodes=total_new_nodes,
        expected_new_nodes_by_category=nodes_by_category,
        scope_creep_flags=flags,
        items=items,
        recommendation=recommendation,
        rationale=rationale,
        confidence=confidence,
        timestamp=timestamp,
    )


def append_simulation_log(
    state: dict[str, Any],
    simulation: SimulationResult,
    *,
    decision: str,
) -> None:
    """Append a simulation record to ``state["simulation_log"]``.

    ``decision`` is what the dispatcher actually did after
    seeing the simulation: ``executed`` / ``aborted_by_gate``
    / ``aborted_by_other``. Keeping the decision next to the
    simulation lets the audit trail answer "did we listen to
    the simulator?"."""
    record = simulation.to_dict()
    record["decision"] = decision
    log_list = list(state.get("simulation_log") or [])
    log_list.append(record)
    state["simulation_log"] = log_list


# ──────────────────────────────────────────────────────────────────────
# Internals
# ──────────────────────────────────────────────────────────────────────


def _simulate_one(
    raw_item: dict[str, Any],
    *,
    registry: Any,
    scope_max_tier: str | None,
    known_entity_targets: set[str],
) -> SimulatedItem:
    tool_name = str(raw_item.get("tool", ""))
    target = str(raw_item.get("target", ""))
    target_type = str(raw_item.get("target_type", ""))
    tool_obj = _tool_obj(registry, tool_name)

    if tool_obj is None:
        # The validator usually filters these, but a defensive
        # simulator entry lets the audit trail show the planner
        # asked for a tool the registry doesn't have.
        return SimulatedItem(
            tool=tool_name, target=target,
            target_type=target_type,
            estimated_cost_usd=0.0,
            expected_new_nodes=_DEFAULT_EXPECTED_NEW_NODES,
            tier="?",
            flags=["unknown_tool"],
        )

    tier = str(getattr(tool_obj, "tier", "T0"))
    if hasattr(tier, "value"):
        tier = tier.value  # type: ignore[attr-defined]
    category = _tool_category_value(registry, tool_name) or ""

    cost = float(getattr(tool_obj, "cost_per_run_usd", 0.0))
    expected_nodes = _expected_new_nodes(tool_obj, category)

    flags: list[str] = []
    if scope_max_tier and tier in _TIER_ORDER and scope_max_tier in _TIER_ORDER:
        if _TIER_ORDER[tier] > _TIER_ORDER[scope_max_tier]:
            flags.append("tier_exceeds_scope")
    if target and known_entity_targets and target not in known_entity_targets:
        flags.append("pivot_to_new_target")

    return SimulatedItem(
        tool=tool_name, target=target,
        target_type=target_type,
        estimated_cost_usd=cost,
        expected_new_nodes=expected_nodes,
        tier=tier,
        flags=flags,
    )


def _expected_new_nodes(tool_obj: Any, category: str) -> int:
    """Per-tool overrides win; otherwise fall back to the
    category heuristic; otherwise the conservative default."""
    override = getattr(tool_obj, "expected_new_nodes_per_run", None)
    if isinstance(override, int) and override >= 0:
        return override
    return _EXPECTED_NEW_NODES_PER_TOOL.get(
        category, _DEFAULT_EXPECTED_NEW_NODES,
    )


def _tool_obj(registry: Any, tool_name: str) -> Any | None:
    try:
        return registry.get(tool_name)
    except Exception:
        return None


def _tool_category_value(registry: Any, tool_name: str) -> str | None:
    tool = _tool_obj(registry, tool_name)
    if tool is None:
        return None
    cat = getattr(tool, "category", None)
    if cat is None:
        return None
    return getattr(cat, "value", str(cat))


def _collect_known_entity_targets(
    state: dict[str, Any] | None,
) -> set[str]:
    """Best-effort: collect the targets the campaign already
    knows about. Used to flag pivots to entirely new entities.

    Walks the new-format ``entity_graph`` (``nodes`` / ``edges``)
    when present; falls back to the truncated bucket format
    (``subdomains`` / ``emails`` lists) for old state files.
    """
    if not state:
        return set()
    seeds = set(state.get("seeds") or [])
    eg = state.get("entity_graph") or {}
    if not isinstance(eg, dict):
        return seeds
    if "nodes" in eg and isinstance(eg["nodes"], list):
        return seeds | {
            str(node.get("id") or node.get("value") or "")
            for node in eg["nodes"]
            if isinstance(node, dict)
        } - {""}
    # Old truncated format.
    out: set[str] = set(seeds)
    for k in ("subdomains", "emails", "domains", "ips"):
        vals = eg.get(k) or []
        if isinstance(vals, list):
            out |= {str(v) for v in vals if v}
    return out


def _confidence(missing_cost_count: int, plan_size: int) -> str:
    """Confidence falls when many tools lack a known
    ``cost_per_run_usd``. Empty plans get medium confidence —
    nothing to be wrong about, but no signal either."""
    if plan_size == 0:
        return "medium"
    miss_ratio = missing_cost_count / plan_size
    if miss_ratio >= 0.6:
        return "low"
    if miss_ratio >= 0.3:
        return "medium"
    return "high"


def _recommend(
    *,
    flags: list[dict[str, Any]],
    cost: float,
    state: dict[str, Any] | None,
) -> tuple[str, str]:
    """Produce ``(recommendation, rationale)``.

    Recommendations are intentionally conservative; PR D may
    fold in operator-tunable thresholds from the Strategy
    itself. For PR C the policy is:

    - any ``tier_exceeds_scope`` flag → ``abort``
    - cost above ``state["max_llm_cost_usd"] * 0.25`` → ``warn``
      (one dispatch shouldn't eat a quarter of the budget)
    - any ``pivot_to_new_target`` → ``warn``
    - otherwise ``proceed``
    """
    tier_flags = [f for f in flags if f["kind"] == "tier_exceeds_scope"]
    if tier_flags:
        offenders = ", ".join(
            f"{f['tool']}({f['target']})" for f in tier_flags[:3]
        )
        return "abort", f"Tool tier exceeds scope: {offenders}"

    budget = float((state or {}).get("max_llm_cost_usd", 10.0))
    if cost > budget * 0.25:
        return "warn", (
            f"Estimated cost ${cost:.4f} exceeds 25% of remaining "
            f"budget (${budget:.2f})"
        )

    pivot_flags = [f for f in flags if f["kind"] == "pivot_to_new_target"]
    if pivot_flags:
        return "warn", (
            f"{len(pivot_flags)} pivot(s) to targets not in graph yet"
        )

    return "proceed", "no risk flags raised"


def _empty_simulation(
    plan: list[dict[str, Any]],
    *,
    reason: str,
    timestamp: str,
) -> SimulationResult:
    """Fallback used when the simulator can't run (registry
    unavailable, etc.). Returns a result tagged ``low`` so the
    audit log shows the simulator was asked + couldn't answer."""
    return SimulationResult(
        plan_size=len(plan),
        estimated_cost_usd=0.0,
        estimated_runtime_sec=0,
        expected_new_nodes=0,
        expected_new_nodes_by_category={},
        scope_creep_flags=[{"kind": "simulator_unavailable", "reason": reason}],
        items=[],
        recommendation="proceed",  # don't block on simulator outages
        rationale=f"Simulator unavailable: {reason}",
        confidence="low",
        timestamp=timestamp,
    )
