"""Run-level health summary (Wave F-A5).

The campaign audit log records every tool outcome, but nothing reads it
back to tell the operator how the run actually went. A campaign can
"complete 9 phases" and emit a confident report while half its tools
errored, were degraded, or were skipped by policy, and zero entities
landed in the graph (exactly the 2026-05-27 ginandjuice.shop run).

This module turns the audit trail into an honest health block: what
succeeded, what failed, which *capabilities* are degraded (a whole
category attempted but produced no usable data), and plain-language
caveats so "no vulnerabilities found" is never reported when the truth
is "the scanners did not run".

Pure functions over a list of audit-entry dicts so they are trivially
testable and have no campaign-object dependency.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# Categories whose failure most undermines the report's headline claims:
# if active scanning did not run, "no vulnerabilities" is not a finding.
_ACTIVE_SCAN_CATEGORIES = {"web", "vulnerability"}


@dataclass
class RunHealth:
    tools_invoked: int = 0
    productive: int = 0          # non-degraded results that returned data
    empty_ok: int = 0           # non-degraded results that legitimately found nothing
    degraded: list[dict[str, str]] = field(default_factory=list)
    errors: list[dict[str, str]] = field(default_factory=list)
    policy_skipped: list[dict[str, str]] = field(default_factory=list)
    scope_violations: list[dict[str, str]] = field(default_factory=list)
    degraded_capabilities: list[dict[str, Any]] = field(default_factory=list)
    entities_total: int = 0
    zero_entities: bool = False
    caveats: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "tools_invoked": self.tools_invoked,
            "productive": self.productive,
            "empty_ok": self.empty_ok,
            "degraded": self.degraded,
            "errors": self.errors,
            "policy_skipped": self.policy_skipped,
            "scope_violations": self.scope_violations,
            "degraded_capabilities": self.degraded_capabilities,
            "entities_total": self.entities_total,
            "zero_entities": self.zero_entities,
            "caveats": self.caveats,
        }


def read_entries(log_path: str | Path) -> list[dict[str, Any]]:
    """Read a JSONL audit log into a list of entry dicts. Missing file or
    malformed lines yield an empty / partial list rather than raising ──
    a health summary must never be the thing that breaks a campaign."""
    path = Path(log_path)
    if not path.exists():
        return []
    out: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out


def summarize_run_health(
    entries: list[dict[str, Any]],
    name_to_category: dict[str, str] | None = None,
) -> RunHealth:
    """Aggregate audit entries into a :class:`RunHealth`.

    ``name_to_category`` maps tool name -> category so the per-capability
    assessment can group tools; when omitted, capability degradation is
    skipped but per-tool counts still work.
    """
    name_to_category = name_to_category or {}
    h = RunHealth()

    # category -> outcome tallies, to decide which capabilities are degraded.
    cat_data: dict[str, dict[str, int]] = {}

    def _cat(tool: str) -> str:
        return name_to_category.get(tool, "unknown")

    def _bump(tool: str, key: str) -> None:
        c = cat_data.setdefault(_cat(tool), {"data": 0, "empty": 0, "degraded": 0, "error": 0})
        c[key] += 1

    for e in entries:
        et = e.get("event_type")
        if et == "tool_result":
            if e.get("cached"):
                continue  # cache hits are not fresh evidence of tool health
            tool = e.get("tool_name", "?")
            h.tools_invoked += 1
            if e.get("degraded"):
                h.degraded.append({"tool": tool, "reason": e.get("degraded_reason") or "implausibly empty result"})
                _bump(tool, "degraded")
            elif (e.get("result_count") or 0) > 0:
                h.productive += 1
                _bump(tool, "data")
            else:
                h.empty_ok += 1
                _bump(tool, "empty")
        elif et == "tool_error":
            tool = e.get("tool_name", "?")
            h.tools_invoked += 1
            h.errors.append({"tool": tool, "error": e.get("error") or "(no error message recorded)"})
            _bump(tool, "error")
        elif et == "policy_skipped":
            h.policy_skipped.append({"tool": e.get("tool_name", "?"), "reason": e.get("reason") or ""})
        elif et == "scope_violation":
            h.scope_violations.append({
                "tool": e.get("tool_name", "?"),
                "target": e.get("target", ""),
                "reason": e.get("reason", ""),
            })
        elif et == "phase_end":
            h.entities_total = max(h.entities_total, int(e.get("entities_count") or 0))

    # A capability is degraded when it was attempted and *failed* (errors
    # or degraded results) yet produced no usable data. A category that
    # only returned clean empties is a legitimate negative, not a failure,
    # so it is never flagged ── that distinction is the whole point.
    for cat, t in sorted(cat_data.items()):
        failed = t["error"] + t["degraded"]
        if failed > 0 and t["data"] == 0:
            h.degraded_capabilities.append({
                "capability": cat,
                "errors": t["error"],
                "degraded": t["degraded"],
                "empty": t["empty"],
            })

    h.zero_entities = h.entities_total == 0
    h.caveats = _build_caveats(h)
    return h


def _build_caveats(h: RunHealth) -> list[str]:
    caveats: list[str] = []
    degraded_cats = {c["capability"] for c in h.degraded_capabilities}
    if degraded_cats & _ACTIVE_SCAN_CATEGORIES:
        caveats.append(
            "Active scanning was degraded or failed (web/vulnerability tools "
            "produced no usable data). Treat any 'no vulnerabilities found' "
            "conclusion as UNVERIFIED, not as a clean result."
        )
    if h.zero_entities and h.productive > 0:
        caveats.append(
            f"{h.productive} tool(s) returned data but zero entities were "
            "extracted into the graph; entity extraction may be broken and "
            "downstream correlation/findings are unreliable."
        )
    if h.degraded:
        caveats.append(
            f"{len(h.degraded)} tool result(s) were degraded (ran but returned "
            "implausibly empty output); these are silent failures, not negatives."
        )
    if h.errors:
        caveats.append(f"{len(h.errors)} tool error(s) occurred during the run.")
    if h.policy_skipped:
        caveats.append(
            f"{len(h.policy_skipped)} tool(s) were skipped by engagement policy "
            "(paid APIs / breach-DB lookups disabled); some intelligence was "
            "intentionally not collected."
        )
    other_degraded = degraded_cats - _ACTIVE_SCAN_CATEGORIES
    if other_degraded:
        caveats.append(
            "Degraded capabilities (attempted, no usable data): "
            + ", ".join(sorted(other_degraded)) + "."
        )
    return caveats


def render_run_health_md(health: RunHealth, campaign_id: str = "") -> str:
    """Render a RunHealth as an operator-facing markdown deliverable."""
    h = health
    lines: list[str] = ["# Run Health Summary"]
    if campaign_id:
        lines.append(f"\n**Campaign:** {campaign_id}")
    lines.append("")
    lines.append("> Did the pipeline actually do its job? This summary reads the")
    lines.append("> audit log so a confident report is never mistaken for a")
    lines.append("> complete one.")
    lines.append("")

    if h.caveats:
        lines.append("## Read this first")
        lines.append("")
        for c in h.caveats:
            lines.append(f"- **{c}**")
        lines.append("")

    lines.append("## Tool outcomes")
    lines.append("")
    lines.append("| Outcome | Count |")
    lines.append("|---------|-------|")
    lines.append(f"| Returned data | {h.productive} |")
    lines.append(f"| Ran, found nothing (valid) | {h.empty_ok} |")
    lines.append(f"| Degraded (silent failure) | {len(h.degraded)} |")
    lines.append(f"| Errored | {len(h.errors)} |")
    lines.append(f"| Skipped by policy | {len(h.policy_skipped)} |")
    lines.append(f"| Entities extracted | {h.entities_total} |")
    lines.append("")

    if h.degraded_capabilities:
        lines.append("## Degraded capabilities")
        lines.append("")
        lines.append("These categories were attempted but returned no usable data,")
        lines.append("so any conclusion that relies on them is unverified.")
        lines.append("")
        for c in h.degraded_capabilities:
            lines.append(
                f"- **{c['capability']}**: {c['errors']} error(s), "
                f"{c['degraded']} degraded, {c['empty']} empty."
            )
        lines.append("")

    if h.degraded:
        lines.append("## Degraded results (ran but implausibly empty)")
        lines.append("")
        for d in h.degraded:
            lines.append(f"- `{d['tool']}`: {d['reason']}")
        lines.append("")

    if h.errors:
        lines.append("## Errors")
        lines.append("")
        for e in h.errors:
            lines.append(f"- `{e['tool']}`: {e['error']}")
        lines.append("")

    if h.policy_skipped:
        lines.append("## Skipped by engagement policy")
        lines.append("")
        for p in h.policy_skipped:
            lines.append(f"- `{p['tool']}`: {p['reason']}")
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"
