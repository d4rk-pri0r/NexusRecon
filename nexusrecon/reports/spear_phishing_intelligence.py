"""Spear-phishing intelligence report (Phase E11 deliverable).

Per-target dossier ── top plausible senders, top plausible pretexts,
recent-activity timeline, and the audit trail that produced each
score. Operator-facing markdown.

Always written when Phase 7.7 ran (with empty content when no
candidates surfaced). The optional draft text appears only when the
operator passed ``--generate-phishing``.

Companion JSON ``pretext_candidates.json`` carries the raw scored
candidates for machine-readable consumption (Maltego import,
follow-on analysis).
"""
from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


def build_spear_phishing_intelligence_md(
    *,
    campaign_id: str,
    engagement_id: str,
    state: dict[str, Any],
    output_dir: Path,
) -> tuple[str, str]:
    """Write ``spear_phishing_intelligence.md`` + ``pretext_candidates.json``.

    Returns ``(md_path, json_path)`` as strings for the engine's
    ``report_paths`` map.
    """
    output_dir.mkdir(parents=True, exist_ok=True)

    intel: dict[str, Any] = state.get("spear_phishing_intelligence") or {}
    summary: dict[str, Any] = intel.get("summary") or {}
    targets: dict[str, Any] = intel.get("targets") or {}
    pretext_scores: list[dict[str, Any]] = state.get("pretext_scores") or []
    relationship_graph_data: dict[str, Any] = state.get("relationship_graph") or {}
    edge_count = int(relationship_graph_data.get("edge_count", 0))

    # ── Companion JSON (raw candidates) ─────────────────────────────
    json_path = output_dir / "pretext_candidates.json"
    json_payload = {
        "campaign_id": campaign_id,
        "engagement_id": engagement_id,
        "generated_at": datetime.now(UTC).isoformat(),
        "summary": summary,
        "edge_count": edge_count,
        "candidates": pretext_scores,
    }
    json_path.write_text(json.dumps(json_payload, indent=2, default=str))

    # ── Markdown ────────────────────────────────────────────────────
    lines: list[str] = [
        "# Spear-Phishing Intelligence",
        "",
        f"**Campaign:** {campaign_id}",
        f"**Engagement:** {engagement_id}",
        f"**Generated:** {datetime.now(UTC).isoformat()}",
        "",
        "> **OPERATOR NOTICE — CONFIDENTIAL**",
        ">",
        "> This document ranks plausible *sender × topic × timing* "
        "pretexts per target, derived from public OSINT signals (E1-E8).",
        "> Every candidate carries an audit trail (`sources`) and a "
        "human-readable rationale.",
        ">",
        "> **The framework does not send email. Drafts (when present) "
        "are gated on `--generate-phishing` and require explicit "
        "operator review before any use.**",
        "",
        "---",
        "",
        "## Executive Summary",
        "",
    ]
    if not targets:
        lines += [
            "_No pretext candidates surfaced for this campaign._",
            "",
            "Possible reasons:",
            "",
            "- The relationship graph is sparse — no E2-E8 tool surfaced "
            "edges anchored to the campaign's identities.",
            "- No recent-activity records matched the campaign's identity "
            "anchors (corp domain, handles).",
            "- Pretext targets were narrowed via `--pretext-targets` and "
            "the selected identities had no candidates.",
            "",
        ]
    else:
        lines += [
            f"- Targets covered: **{summary.get('target_count', len(targets))}**",
            f"- Total candidates: **{summary.get('candidate_count', len(pretext_scores))}**",
            f"- Score range: **min {summary.get('score_min', 0.0)}** / "
            f"median {summary.get('score_median', 0.0)} / "
            f"max **{summary.get('score_max', 0.0)}**",
            f"- Relationship edges in graph: **{edge_count}**",
            "",
            "Per-target dossiers follow below. Each target shows the top "
            "plausible senders + top plausible pretexts ranked by "
            "combined plausibility (sender × topic × timing geometric mean).",
            "",
            "---",
            "",
        ]

    # ── Per-target dossiers ─────────────────────────────────────────
    for target_id, dossier in targets.items():
        lines += _render_target_dossier(target_id, dossier)

    md_path = output_dir / "spear_phishing_intelligence.md"
    md_path.write_text("\n".join(lines))

    return (str(md_path), str(json_path))


# ──────────────────────────────────────────────────────────────────────
# Internal renderers
# ──────────────────────────────────────────────────────────────────────


def _render_target_dossier(
    target_id: str, dossier: dict[str, Any],
) -> list[str]:
    target_label = dossier.get("target_label") or target_id
    candidates: list[dict[str, Any]] = dossier.get("top_candidates") or []
    draft = dossier.get("draft")

    lines: list[str] = [
        f"## Target — {target_label}",
        "",
        f"**Identity ID:** `{target_id}`",
        "",
    ]
    if not candidates:
        lines += [
            "_No candidates for this target._",
            "",
        ]
        return lines

    # Top 3 plausible senders (deduplicated by sender identity).
    seen_senders: set[str] = set()
    top_senders: list[dict[str, Any]] = []
    for c in candidates:
        sid = c.get("sender_identity_id") or ""
        if sid in seen_senders:
            continue
        seen_senders.add(sid)
        top_senders.append(c)
        if len(top_senders) >= 3:
            break

    lines += [
        "### Top plausible senders",
        "",
    ]
    for i, sender in enumerate(top_senders, 1):
        lines += [
            f"{i}. **{sender.get('sender_label', sender.get('sender_identity_id'))}** "
            f"(sender plausibility {sender.get('sender_plausibility', 0):.2f})",
            f"   - rationale: {sender.get('rationale', '')}",
        ]
        srcs = sender.get("sources") or []
        if srcs:
            lines.append(f"   - sources: `{', '.join(srcs)}`")
        lines.append("")

    # Top 3 plausible pretexts (the top candidates).
    lines += [
        "### Top plausible pretexts",
        "",
    ]
    for i, cand in enumerate(candidates[:3], 1):
        anchor = cand.get("timing_anchor") or {}
        topic = cand.get("topic") or "(no title)"
        score = cand.get("combined_score", 0)
        timing = cand.get("timing_score", 0)
        published = anchor.get("published_at") or "unknown"
        source = anchor.get("source") or "unknown"
        url = anchor.get("url") or ""
        lines += [
            f"{i}. **{topic}** (combined plausibility {score:.2f})",
            f"   - timing: {timing:.2f} (published {published}, via {source})",
            f"   - sender: {cand.get('sender_label', '?')}"
            f" (plausibility {cand.get('sender_plausibility', 0):.2f})",
        ]
        if url:
            lines.append(f"   - anchor: <{url}>")
        srcs = cand.get("sources") or []
        if srcs:
            lines.append(f"   - sources: `{', '.join(srcs)}`")
        lines.append("")

    # Recent activity timeline (distinct timing anchors).
    seen_anchors: set[str] = set()
    timeline_entries: list[dict[str, Any]] = []
    for c in candidates:
        anchor = c.get("timing_anchor") or {}
        key = (anchor.get("title") or "") + "|" + (anchor.get("published_at") or "")
        if key in seen_anchors:
            continue
        seen_anchors.add(key)
        timeline_entries.append(anchor)
    if timeline_entries:
        lines += [
            "### Recent activity timeline",
            "",
        ]
        for entry in timeline_entries:
            published = entry.get("published_at") or "(undated)"
            title = entry.get("title") or "(no title)"
            source = entry.get("source") or "?"
            url = entry.get("url")
            line = f"- **{published}** — {title} _(via {source})_"
            if url:
                line += f" <{url}>"
            lines.append(line)
        lines.append("")

    # Recommended draft framing (derived from the top candidate).
    if candidates:
        top = candidates[0]
        lines += [
            "### Recommended draft framing",
            "",
            f"Lead the message from **{top.get('sender_label', '?')}** "
            f"with a hook tied to **\"{top.get('topic', '?')}\"**. "
            f"Keep the ask small and specific. Cite the timing anchor's "
            f"publication date to ground the urgency.",
            "",
        ]

    # Optional generated draft.
    if draft:
        lines += [
            "### Generated draft",
            "",
            "_Operator review required before use._",
            "",
            "```",
            str(draft),
            "```",
            "",
        ]
    else:
        lines += [
            "_No draft generated — pass `--generate-phishing` to enable._",
            "",
        ]

    lines.append("---")
    lines.append("")
    return lines
