"""Strategy — declarative campaign plan.

A ``Strategy`` is the operator's (or planner agent's)
high-level description of what a campaign should do, expressed
as data instead of code. Today's workflow has the same
information scattered across:

  - CLI flags (``--mode``, ``--dispatch-mode``,
    ``--max-tier``).
  - ``CampaignGraphState`` fields
    (``generate_phishing_drafts``, ``pretext_targets``).
  - Module-level constants in ``nodes.py`` (which phases run
    in what order).
  - Hardcoded heuristics in the dispatcher.

The ``Strategy`` object pulls that into one declarative shape
the planner agent can author, the reflection node can consult,
and the audit trail can record verbatim. This Phase 1 PR A
defines the shape but does NOT yet wire it into the workflow
(the existing constants keep working). PR B operationalises the
planner agent that authors ``Strategy`` instances; PR C+ wire
them into the actual phase execution.

What lives in a Strategy
- ``phases``: ordered list of phase identifiers to run.
- ``dispatch_policy_name``: which
  :class:`~nexusrecon.strategy.policy.DispatchPolicy` to use.
- ``tool_budgets``: per-tool / per-category caps on invocations.
- ``success_criteria``: what makes the campaign "done early"
  (e.g. "≥5 confirmed leads with severity >= high").
- ``kill_criteria``: when to abort (e.g. "no findings after
  phase 4" or "LLM cost crossed $20 and no high-severity
  finding").
- ``metadata``: free-form bag for planner notes, operator
  comments, etc.

What does NOT live in a Strategy (intentional separation)
- Tool invocation arguments (those come from the registry +
  per-tool kwargs).
- Scope (lives in the scope.yaml ── safety-critical,
  separate file).
- Credentials / .env values (operator-managed, never plan
  data).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class SuccessCriterion:
    """One condition that, when met, signals the campaign has
    achieved its goal.

    Example: ``SuccessCriterion(metric="confirmed_leads",
    op=">=", threshold=5, scope={"min_severity": "high"})``.

    Evaluation happens at phase boundaries. When any criterion
    fires the reflection node may decide to short-circuit the
    workflow (operator-configurable; default is to log + keep
    going, since short-circuiting an in-flight campaign loses
    coverage)."""

    metric: str
    """Which state field / graph query to evaluate. Resolution
    happens in the strategy evaluator (Phase 1 PR C); for
    now this is documented free-form."""

    op: str  # one of "==", ">=", ">", "<=", "<", "exists"
    threshold: Any = None
    scope: dict[str, Any] = field(default_factory=dict)
    description: str = ""


@dataclass
class KillCriterion:
    """One condition that, when met, signals the campaign should
    abort (or pause for human review).

    Example: ``KillCriterion(metric="llm_cost_usd", op=">",
    threshold=20.0, scope={"and": "no_high_finding"})``.
    """

    metric: str
    op: str
    threshold: Any = None
    scope: dict[str, Any] = field(default_factory=dict)
    description: str = ""
    action: str = "pause_for_review"  # "abort" | "pause_for_review"


@dataclass
class Strategy:
    """Declarative campaign plan.

    Authored by the operator (default templates ship with
    NexusRecon) or by the :class:`CampaignPlannerAgent` in
    PR B's planner-driven flow. Stored alongside the campaign
    state so the audit trail captures what was attempted.
    """

    name: str = "default"
    """Operator-facing identifier ── e.g. ``corp_recon``,
    ``supply_chain_audit``, ``executive_pretext_only``. Surfaces
    in the dispatch audit log + the TUI status bar."""

    phases: list[str] = field(default_factory=lambda: [
        # Default phase order matches today's hardcoded
        # PHASE_ORDER in workflow.py. A future PR adds support
        # for skipping phases or running them in alternate
        # orders.
        "phase1", "phase2", "phase2_5", "phase3", "phase4",
        "phase5", "phase6", "phase7", "phase7_5", "phase7_7",
        "phase8", "phase9",
    ])

    dispatch_policy_name: str = "lite"
    """Which :class:`~nexusrecon.strategy.policy.DispatchPolicy`
    the dispatcher should use. Resolved via
    :func:`~nexusrecon.strategy.policy.get_policy`."""

    tool_budgets: dict[str, int] = field(default_factory=dict)
    """Per-tool or per-category invocation caps. Empty means
    'use the registry defaults' (which are themselves loose).
    Example: ``{"shodan": 10, "category:cloud": 25}``."""

    success_criteria: list[SuccessCriterion] = field(default_factory=list)
    """When ANY of these fire, the reflection node can opt to
    short-circuit. None today → run to completion."""

    kill_criteria: list[KillCriterion] = field(default_factory=list)
    """When ANY of these fire, the reflection node aborts or
    pauses (per criterion ``action``). Default empty so
    existing campaigns aren't affected; operators populate
    these for production work."""

    metadata: dict[str, Any] = field(default_factory=dict)
    """Free-form bag for planner notes, operator comments,
    references to external tracking tickets, etc. Persisted
    verbatim in the audit log."""

    def to_dict(self) -> dict[str, Any]:
        """Serialise for state.json + the audit log. ``dataclasses
        .asdict`` would also work but we want explicit control
        over the schema so future fields don't silently land in
        the audit trail without a version bump."""
        return {
            "name": self.name,
            "phases": list(self.phases),
            "dispatch_policy_name": self.dispatch_policy_name,
            "tool_budgets": dict(self.tool_budgets),
            "success_criteria": [
                {
                    "metric": c.metric, "op": c.op,
                    "threshold": c.threshold, "scope": dict(c.scope),
                    "description": c.description,
                }
                for c in self.success_criteria
            ],
            "kill_criteria": [
                {
                    "metric": c.metric, "op": c.op,
                    "threshold": c.threshold, "scope": dict(c.scope),
                    "description": c.description, "action": c.action,
                }
                for c in self.kill_criteria
            ],
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Strategy:
        """Restore a Strategy from its serialised dict shape.
        Tolerant of missing fields ── old strategies missing
        new optional fields get the dataclass defaults."""
        return cls(
            name=data.get("name", "default"),
            phases=list(data.get("phases") or []) or cls().phases,
            dispatch_policy_name=data.get(
                "dispatch_policy_name", "lite",
            ),
            tool_budgets=dict(data.get("tool_budgets") or {}),
            success_criteria=[
                SuccessCriterion(**c)
                for c in (data.get("success_criteria") or [])
            ],
            kill_criteria=[
                KillCriterion(**c)
                for c in (data.get("kill_criteria") or [])
            ],
            metadata=dict(data.get("metadata") or {}),
        )

    @classmethod
    def default(cls) -> Strategy:
        """The strategy a campaign gets when the operator
        doesn't author one. Matches today's hardcoded
        behavior exactly so launching without a Strategy is
        a no-op compared to pre-Phase-1."""
        return cls(name="default", dispatch_policy_name="lite")
