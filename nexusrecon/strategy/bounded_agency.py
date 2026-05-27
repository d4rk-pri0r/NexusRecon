"""Advanced bounded-agency primitives — Phase 1 PR D.

PR D extends the dispatcher with two new capabilities the plan
calls for (§Phase 1 §4):

  1. **Deep-pivot dispatch** — a single dispatch item can
     declare ``deep_pivot: "<policy_name>"`` to temporarily
     escalate to a wider policy *for that one item* without
     changing the campaign's default. Lets the LLM say "this
     branch is worth a full-mode burst" without flipping the
     operator's risk posture for the whole run. Every grant
     is logged to the hash-chained audit log so accidental
     escalations stand out in review.

  2. **Human-approval gating** — a dispatch item can declare
     ``requires_human_approval: true``. Instead of executing,
     the item lands in ``state["pending_approvals"]`` with a
     queued-at timestamp + the originating reason. The TUI's
     approval surface (separate PR) lets the operator approve
     or reject. The audit log records both the queue add and
     the decision so the trail shows every escalation point.

Both capabilities are opt-in: dispatch plans that don't set
these fields behave exactly as before, so existing campaigns
+ tests carry no behavior change.

Why a separate module
- Keeps :mod:`nexusrecon.graph.dynamic_dispatcher` focused on
  the orchestration loop.
- Makes the bounded-agency surface easy to test in isolation
  (small, pure functions with explicit state contracts).
- Plugins can later import these helpers without dragging in
  the dispatcher's LLM-call machinery.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import structlog

log = structlog.get_logger(__name__)


# ──────────────────────────────────────────────────────────────────────
# Per-item escalation parsing
# ──────────────────────────────────────────────────────────────────────


@dataclass
class _ItemDecision:
    """Per-dispatch-item routing decision produced by
    :func:`route_plan_items`."""

    item: dict[str, Any]
    """The original plan item (untouched)."""

    action: str  # one of "execute" | "deep_pivot" | "human_approval"
    override_policy_name: str | None = None
    """Set only when ``action == "deep_pivot"`` — the policy
    the item should execute under, replacing the campaign's
    default for this one call."""

    queue_reason: str = ""
    """Human-readable reason this item is being held back
    (for ``human_approval``) or escalated
    (for ``deep_pivot``). Goes into the audit log + the
    operator-facing TUI surface."""

    audit_metadata: dict[str, Any] = field(default_factory=dict)


def route_plan_items(
    plan: list[dict[str, Any]],
    *,
    default_policy_name: str,
) -> list[_ItemDecision]:
    """Map each plan item to an :class:`_ItemDecision`.

    Items with ``requires_human_approval=True`` are queued for
    human review. Items with a non-empty ``deep_pivot``
    string get an override policy. Everything else executes
    under ``default_policy_name``.

    Defensive against malformed items — anything missing the
    required fields falls back to plain execution; the
    simulator + validator already filter most garbage out
    upstream."""
    out: list[_ItemDecision] = []
    for item in plan:
        if not isinstance(item, dict):
            continue

        if item.get("requires_human_approval"):
            reason = str(
                item.get("approval_reason")
                or item.get("reason")
                or "operator approval requested"
            )
            out.append(_ItemDecision(
                item=item, action="human_approval",
                queue_reason=reason,
            ))
            continue

        pivot_to = item.get("deep_pivot")
        if isinstance(pivot_to, str) and pivot_to.strip():
            out.append(_ItemDecision(
                item=item, action="deep_pivot",
                override_policy_name=pivot_to.strip(),
                queue_reason=str(item.get("pivot_reason") or item.get("reason") or ""),
            ))
            continue

        out.append(_ItemDecision(
            item=item, action="execute",
            override_policy_name=default_policy_name,
        ))
    return out


# ──────────────────────────────────────────────────────────────────────
# Human-approval queue helpers
# ──────────────────────────────────────────────────────────────────────


def queue_for_approval(
    state: dict[str, Any],
    item: dict[str, Any],
    *,
    reason: str,
    estimated_cost_usd: float = 0.0,
    tier: str = "?",
) -> dict[str, Any]:
    """Append a dispatch item to ``state["pending_approvals"]``.

    Returns the queued record so callers can pass it to the
    audit log. The record carries everything the TUI needs to
    render the approval prompt; the operator's later
    approve/reject decision lands in ``state["approval_log"]``
    via :func:`resolve_approval`."""
    record = {
        "queued_at": datetime.now(UTC).isoformat(),
        "tool": str(item.get("tool", "")),
        "target": str(item.get("target", "")),
        "target_type": str(item.get("target_type", "")),
        "original_reason": str(item.get("reason", "")),
        "approval_reason": reason,
        "estimated_cost_usd": float(estimated_cost_usd),
        "tier": tier,
        "status": "pending",
    }
    pending = list(state.get("pending_approvals") or [])
    pending.append(record)
    state["pending_approvals"] = pending
    return record


def resolve_approval(
    state: dict[str, Any],
    *,
    tool: str,
    target: str,
    approved: bool,
    operator: str,
    notes: str = "",
) -> dict[str, Any] | None:
    """Mark the matching pending-approval record as
    approved/rejected and append to ``state["approval_log"]``.

    Returns the resolved record (with ``status`` updated) so
    callers can pipe it into the audit log + downstream
    handlers. Returns ``None`` if no matching record was found
    — the operator may have approved an item that was already
    handled, which we treat as a no-op + warning."""
    pending = list(state.get("pending_approvals") or [])
    record: dict[str, Any] | None = None
    for entry in pending:
        if (
            entry.get("tool") == tool
            and entry.get("target") == target
            and entry.get("status") == "pending"
        ):
            record = entry
            break
    if record is None:
        log.warning(
            "Approval resolution: no pending record found",
            tool=tool, target=target,
        )
        return None

    record["status"] = "approved" if approved else "rejected"
    record["resolved_at"] = datetime.now(UTC).isoformat()
    record["resolved_by"] = operator
    record["resolution_notes"] = notes
    state["pending_approvals"] = pending

    approval_log = list(state.get("approval_log") or [])
    approval_log.append(dict(record))
    state["approval_log"] = approval_log
    return record


# ──────────────────────────────────────────────────────────────────────
# Deep-pivot policy resolution
# ──────────────────────────────────────────────────────────────────────


def resolve_pivot_policy(name: str, *, default_policy_name: str) -> Any:
    """Resolve a deep-pivot override policy name to a concrete
    :class:`DispatchPolicy`. Refuses to *narrow* — e.g. if the
    campaign is in ``full`` and the LLM asks to pivot to
    ``off``, we reject the override and stay on full (an
    accidental scope-narrowing escalation is still a behavior
    change the operator should explicitly approve).

    Returns the resolved policy. Caller is responsible for
    logging the grant via
    :meth:`AuditLog.log_deep_pivot_grant`."""
    from nexusrecon.strategy.policy import get_policy

    default = get_policy(default_policy_name)
    requested = get_policy(name)

    # Refuse a narrowing override. ``max_total`` is the proxy
    # for "agency budget": lower means less capability.
    if requested.max_total < default.max_total:
        log.info(
            "Deep-pivot rejected: would narrow agency",
            requested=requested.name, default=default.name,
        )
        return default
    return requested
