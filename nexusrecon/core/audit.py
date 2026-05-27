"""
Tamper-evident audit log — hash-chained JSONL.

Every tool invocation, scope violation, agent action, and significant
event is logged here.  Each entry contains the SHA-256 hash of the
previous entry, creating an append-only chain where tampering is
detectable.

Log format (one JSON object per line):
{
  "seq": 1,
  "entry_hash": "sha256:<hex>",
  "prev_hash": "sha256:<hex>",
  "timestamp": "2026-05-01T12:00:00.000Z",
  "event_type": "tool_invocation",
  "data": { ... }
}
"""

from __future__ import annotations

import hashlib
import json
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import structlog

log = structlog.get_logger(__name__)

GENESIS_HASH = "sha256:" + "0" * 64  # Initial prev_hash for first entry


class AuditLog:
    """
    Hash-chained append-only audit log.

    Thread-safe via internal lock.  One instance per campaign.
    """

    def __init__(self, log_path: str | Path, campaign_id: str, scope_hash: str) -> None:
        self.log_path = Path(log_path)
        self.campaign_id = campaign_id
        self.scope_hash = scope_hash
        self._lock = threading.Lock()
        self._seq = 0
        self._prev_hash = GENESIS_HASH
        self._init_log()

    def _init_log(self) -> None:
        """Initialize or resume the log file."""
        self.log_path.parent.mkdir(parents=True, exist_ok=True)

        if self.log_path.exists() and self.log_path.stat().st_size > 0:
            # Resume: find last entry and extract prev_hash
            last_entry = self._read_last_entry()
            if last_entry:
                self._seq = last_entry.get("seq", 0)
                self._prev_hash = last_entry.get("entry_hash", GENESIS_HASH)
                log.info(
                    "Resumed audit log",
                    path=str(self.log_path),
                    last_seq=self._seq,
                )
                return

        # New log: write genesis entry
        self._append_raw({
            "event_type": "audit_log_init",
            "campaign_id": self.campaign_id,
            "scope_hash": self.scope_hash,
        })

    def _read_last_entry(self) -> dict[str, Any] | None:
        """Read the last JSONL entry from the log."""
        try:
            with open(self.log_path, "rb") as f:
                f.seek(0, 2)  # seek to end
                pos = f.tell()
                if pos == 0:
                    return None
                # Walk backward to find the last newline
                last_line = b""
                while pos > 0:
                    pos -= 1
                    f.seek(pos)
                    char = f.read(1)
                    if char == b"\n" and last_line:
                        break
                    last_line = char + last_line
                return json.loads(last_line.decode("utf-8")) if last_line else None
        except Exception as e:
            log.warning("Could not read last audit log entry", error=str(e))
            return None

    def _compute_entry_hash(self, prev_hash: str, data: dict[str, Any], timestamp: str) -> str:
        """Compute SHA-256 of (prev_hash | timestamp | sorted_json_data)."""
        canonical = f"{prev_hash}|{timestamp}|{json.dumps(data, sort_keys=True)}"
        return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def _append_raw(self, data: dict[str, Any]) -> str:
        """Append a single entry to the log. Returns the entry hash."""
        with self._lock:
            self._seq += 1
            timestamp = datetime.now(UTC).isoformat()
            entry_hash = self._compute_entry_hash(self._prev_hash, data, timestamp)

            entry = {
                "seq": self._seq,
                "entry_hash": entry_hash,
                "prev_hash": self._prev_hash,
                "timestamp": timestamp,
                **data,
            }

            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, default=str) + "\n")

            self._prev_hash = entry_hash
            return entry_hash

    # ── Public logging methods ────────────────────────────────────────────────

    def log_tool_start(
        self,
        tool_name: str,
        tier: str,
        target: str,
        query: str,
        proxy_used: str | None = None,
    ) -> str:
        """Log the start of a tool invocation. Returns entry hash."""
        return self._append_raw({
            "event_type": "tool_start",
            "tool_name": tool_name,
            "tier": tier,
            "target": target,
            "query": query,
            "proxy_used": proxy_used or "none",
        })

    def log_tool_result(
        self,
        tool_name: str,
        target: str,
        response_hash: str,
        runtime_ms: int,
        result_count: int,
        cached: bool = False,
    ) -> str:
        """Log the result of a tool invocation."""
        return self._append_raw({
            "event_type": "tool_result",
            "success": True,
            "tool_name": tool_name,
            "target": target,
            "response_hash": response_hash,
            "runtime_ms": runtime_ms,
            "result_count": result_count,
            "cached": cached,
        })

    def log_tool_error(self, tool_name: str, target: str, error: str) -> str:
        """Log a tool error."""
        return self._append_raw({
            "event_type": "tool_error",
            "success": False,
            "tool_name": tool_name,
            "target": target,
            "error": error,
        })

    def log_scope_violation(self, target: str, reason: str, tool_name: str) -> str:
        """Log a scope violation (target dropped)."""
        return self._append_raw({
            "event_type": "scope_violation",
            "target": target,
            "reason": reason,
            "tool_name": tool_name,
        })

    def log_tier_violation(self, tool_name: str, tool_tier: str, max_tier: str) -> str:
        """Log a tier violation (tool blocked)."""
        return self._append_raw({
            "event_type": "tier_violation",
            "tool_name": tool_name,
            "tool_tier": tool_tier,
            "max_tier": max_tier,
        })

    def log_phase_start(self, phase_name: str, agent: str) -> str:
        return self._append_raw({
            "event_type": "phase_start",
            "phase_name": phase_name,
            "agent": agent,
        })

    def log_phase_end(
        self,
        phase_name: str,
        findings_count: int,
        entities_count: int,
        cost_usd: float,
    ) -> str:
        return self._append_raw({
            "event_type": "phase_end",
            "phase_name": phase_name,
            "findings_count": findings_count,
            "entities_count": entities_count,
            "cost_usd": cost_usd,
        })

    def log_finding(self, finding_id: str, title: str, severity: str, source: str) -> str:
        return self._append_raw({
            "event_type": "finding",
            "finding_id": finding_id,
            "title": title,
            "severity": severity,
            "source": source,
        })

    def log_agent_action(self, agent: str, action: str, details: dict[str, Any] | None = None) -> str:
        return self._append_raw({
            "event_type": "agent_action",
            "agent": agent,
            "action": action,
            "details": details or {},
        })

    def log_campaign_end(self, findings_total: int, report_paths: dict[str, str]) -> str:
        return self._append_raw({
            "event_type": "campaign_end",
            "findings_total": findings_total,
            "report_paths": report_paths,
        })

    # ── Strategic decisions (Phase 1 PR D) ────────────────────────────────────
    # Each strategic decision (plan generation, dispatch policy
    # resolution, simulation outcome, deep-pivot grant,
    # human-approval queue add) lands as its own hash-chained
    # entry. This means an auditor can replay the entire
    # reasoning trail and prove that ``state.json`` /
    # ``simulation_log`` haven't been retroactively edited.

    def log_strategy_generated(
        self,
        *,
        strategy_name: str,
        dispatch_policy_name: str,
        phases: list[str],
        response_kind: str,
        fallback_reason: str | None = None,
    ) -> str:
        """Record that the planner produced (or fell back to)
        a Strategy. ``response_kind`` is ``structured`` for a
        real planner output, ``fallback`` for the default."""
        return self._append_raw({
            "event_type": "strategy_generated",
            "strategy_name": strategy_name,
            "dispatch_policy_name": dispatch_policy_name,
            "phases": list(phases),
            "response_kind": response_kind,
            "fallback_reason": fallback_reason or "",
        })

    def log_strategy_replan(
        self,
        *,
        reason: str,
        old_name: str,
        new_name: str,
        new_dispatch_policy_name: str,
    ) -> str:
        """Record a mid-campaign replan. ``reason`` is the
        operator's (or auto-trigger's) explanation; old/new
        names let auditors reconstruct the swap without
        loading the full strategy bodies."""
        return self._append_raw({
            "event_type": "strategy_replan",
            "reason": reason,
            "old_strategy_name": old_name,
            "new_strategy_name": new_name,
            "new_dispatch_policy_name": new_dispatch_policy_name,
        })

    def log_dispatch_policy_resolved(
        self,
        *,
        policy_name: str,
        source: str,
        current_phase: str,
        eligible: bool,
    ) -> str:
        """Record each dispatcher invocation's policy choice.
        ``source`` is ``strategy``, ``state.dispatch_mode``,
        ``default``, or ``fallback`` depending on which slot in
        ``_resolve_policy``'s precedence chain matched."""
        return self._append_raw({
            "event_type": "dispatch_policy_resolved",
            "policy_name": policy_name,
            "source": source,
            "current_phase": current_phase,
            "eligible": bool(eligible),
        })

    def log_simulation(
        self,
        *,
        plan_size: int,
        estimated_cost_usd: float,
        expected_new_nodes: int,
        recommendation: str,
        confidence: str,
        decision: str,
        flag_kinds: list[str] | None = None,
    ) -> str:
        """Record one simulation outcome. ``decision`` is what
        the dispatcher actually did after seeing the simulation
        (``executed`` / ``aborted_by_gate``). The simulation's
        full body lives in ``state["simulation_log"]``; this
        entry is the hash-chained reference."""
        return self._append_raw({
            "event_type": "simulation",
            "plan_size": plan_size,
            "estimated_cost_usd": round(float(estimated_cost_usd), 4),
            "expected_new_nodes": int(expected_new_nodes),
            "recommendation": recommendation,
            "confidence": confidence,
            "decision": decision,
            "flag_kinds": list(flag_kinds or []),
        })

    def log_deep_pivot_grant(
        self,
        *,
        tool: str,
        target: str,
        granting_policy: str,
        override_policy: str,
        rationale: str,
    ) -> str:
        """Record that a single dispatch item was granted a
        per-item dispatch-policy override (``deep_pivot``).
        High-signal — these grants temporarily widen the
        operator's bounded-agency envelope; auditors want them
        prominent so unexpected escalations show up
        immediately."""
        return self._append_raw({
            "event_type": "deep_pivot_grant",
            "tool": tool,
            "target": target,
            "granting_policy": granting_policy,
            "override_policy": override_policy,
            "rationale": rationale,
        })

    def log_human_approval_queued(
        self,
        *,
        tool: str,
        target: str,
        reason: str,
        tier: str,
        estimated_cost_usd: float,
    ) -> str:
        """Record that a dispatch item was queued for human
        approval rather than executed. Pairs with
        ``state["pending_approvals"]``; the operator approving
        or rejecting later emits ``log_human_approval_decision``."""
        return self._append_raw({
            "event_type": "human_approval_queued",
            "tool": tool,
            "target": target,
            "reason": reason,
            "tier": tier,
            "estimated_cost_usd": round(float(estimated_cost_usd), 4),
        })

    def log_human_approval_decision(
        self,
        *,
        tool: str,
        target: str,
        approved: bool,
        operator: str,
        notes: str = "",
    ) -> str:
        """Record an operator's approve / reject decision on a
        queued item. ``operator`` is whatever identifier the
        TUI captures (a name, an ID, ``cli`` if approved
        through the CLI)."""
        return self._append_raw({
            "event_type": "human_approval_decision",
            "tool": tool,
            "target": target,
            "approved": bool(approved),
            "operator": operator,
            "notes": notes,
        })

    # ── Verification ──────────────────────────────────────────────────────────

    def verify_chain(self) -> bool:
        """
        Verify the integrity of the audit chain.
        Returns True if chain is intact, False if tampering detected.
        """
        prev_hash = GENESIS_HASH
        try:
            with open(self.log_path, encoding="utf-8") as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue
                    entry = json.loads(line)
                    timestamp = entry["timestamp"]
                    # Reconstruct the data payload (everything except chain fields)
                    data = {
                        k: v for k, v in entry.items()
                        if k not in ("seq", "entry_hash", "prev_hash", "timestamp")
                    }
                    expected = self._compute_entry_hash(prev_hash, data, timestamp)
                    if expected != entry["entry_hash"]:
                        log.error(
                            "Audit chain broken",
                            line=line_num,
                            expected=expected,
                            got=entry["entry_hash"],
                        )
                        return False
                    if entry["prev_hash"] != prev_hash:
                        log.error("Audit prev_hash mismatch", line=line_num)
                        return False
                    prev_hash = entry["entry_hash"]
            return True
        except Exception as e:
            log.error("Audit chain verification failed", error=str(e))
            return False
