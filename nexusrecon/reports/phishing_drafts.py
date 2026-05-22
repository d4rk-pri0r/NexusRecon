"""Per-target phishing draft generator for authorized red-team engagements."""
from __future__ import annotations

import asyncio
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any

import structlog

log = structlog.get_logger(__name__)

_AUTHORIZATION_BANNER = """\
⚠ AUTHORIZATION REQUIRED ⚠
This file contains AI-generated phishing content for an authorized engagement only.
Verify scope permits phishing simulations before sending. Do not send without operator review.

---
"""

_DRAFT_SCHEMA = {
    "target_email": str,
    "target_role": str,
    "lure_category": str,
    "subject": str,
    "sender_display_name": str,
    "sender_address": str,
    "sender_strategy": str,
    "body_markdown": str,
    "body_plaintext": str,
    "recommended_attachment_type": str,
    "recommended_landing_page": str,
    "send_day": str,
    "send_time": str,
    "rationale": str,
    "osint_citations": list,
    "operator_review_required": bool,
}

_JSON_PROMPT = f"""Return ONLY a JSON object matching exactly this schema (no prose, no markdown code fences):
{json.dumps({k: type(v).__name__ for k, v in _DRAFT_SCHEMA.items()}, indent=2)}

The landing_pages HTML field in the GoPhish output must NOT contain a functional credential-harvesting page — use the template name only."""


def _extract_json(text: str) -> dict[str, Any] | None:
    """Try to extract the first JSON object from an LLM response.

    B34: defensive against FINDINGS_JSON contamination from the B25 prompt
    injection. If the response contains a FINDINGS_JSON:[...] array followed
    by the actual draft {...} object, we strip the array first and find the
    object. Also handles markdown code fences and trailing prose.
    """
    text = text.strip()

    # Strip FINDINGS_JSON block if present (B34 defensive — should not occur
    # after agent_executor was patched to skip it for phishing_drafter,
    # but kept here as a backstop).
    marker = "FINDINGS_JSON:"
    if marker in text:
        idx = text.find(marker)
        after_marker = text[idx + len(marker):].lstrip()
        # Skip past the JSON array using raw_decode
        try:
            _, end = json.JSONDecoder().raw_decode(after_marker)
            text = after_marker[end:].strip()
        except (json.JSONDecodeError, ValueError):
            # Couldn't parse the FINDINGS array — fall through to other strategies
            pass

    # Strip markdown code fences if present
    text = re.sub(r"^```(?:json)?\s*", "", text)
    text = re.sub(r"\s*```$", "", text)

    # Try direct parse first
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    # Use raw_decode to find a balanced JSON object anywhere in the text
    # (more robust than the greedy regex which can match across multiple braces).
    decoder = json.JSONDecoder()
    for i, ch in enumerate(text):
        if ch == "{":
            try:
                obj, _ = decoder.raw_decode(text[i:])
                if isinstance(obj, dict):
                    return obj
            except (json.JSONDecodeError, ValueError):
                continue
    return None


def _build_target_context(
    email: str,
    info: dict[str, Any],
    dmarc_posture: str,
    seed_domain: str,
) -> dict[str, Any]:
    role = info.get("position") or "Employee"
    dept = info.get("department") or "Unknown"
    breach_sources = []
    if info.get("breaches"):
        breach_sources = [b.get("name", "") for b in info["breaches"] if isinstance(b, dict)]
    registered_services = [
        s.get("service", "") for s in info.get("registered_services", [])
        if isinstance(s, dict)
    ]
    infostealer = bool(info.get("stealer_logs") or info.get("infostealer_hits"))

    # Determine sender strategy and recommended domain.
    # Only p=reject blocks spoofing effectively → lookalike required.
    # p=quarantine, p=none, or absent → direct domain spoofing viable.
    if "p=reject" in dmarc_posture.lower():
        sender_strategy = "lookalike_domain"
        base = seed_domain.rsplit(".", 1)[0]
        tld = seed_domain.rsplit(".", 1)[1] if "." in seed_domain else "com"
        recommended_sender_domain = f"{base}-corp.{tld}"
    else:
        sender_strategy = "direct_domain"
        recommended_sender_domain = seed_domain

    return {
        "target_email": email,
        "target_role": role,
        "target_dept": dept,
        "breach_sources": breach_sources,
        "registered_services": registered_services[:10],
        "infostealer_hit": infostealer,
        "dmarc_posture": dmarc_posture,
        "sender_strategy": sender_strategy,
        "recommended_sender_domain": recommended_sender_domain,
    }


async def _draft_one_target(
    context: dict[str, Any],
    executor: Any,
) -> dict[str, Any] | None:
    task_prompt = (
        f"Draft ONE phishing email for this target. Use the context below. "
        f"Sender strategy is '{context['sender_strategy']}' using domain '{context['recommended_sender_domain']}'.\n\n"
        f"{_JSON_PROMPT}"
    )
    try:
        result = await executor.run_agent(
            "phishing_drafter",
            task_data=context,
            task_prompt=task_prompt,
        )
        raw = result.get("output", "")
        parsed = _extract_json(raw)
        if parsed and isinstance(parsed, dict):
            return parsed
        log.warning("phishing_drafter returned unparseable output", email=context["target_email"])
    except Exception as exc:
        log.warning("phishing_drafter failed", email=context["target_email"], error=str(exc))
    return None


async def generate_phishing_drafts(
    state: dict[str, Any],
    executor: Any,
    output_dir: Path,
    max_targets: int = 10,
) -> dict[str, str]:
    """Generate per-target draft emails. Returns {target_email: draft_file_path}."""
    output_dir.mkdir(parents=True, exist_ok=True)

    emails = state.get("email_intel", {}).get("emails", {})
    breach_intel = state.get("breach_intel", {})
    seeds = state.get("seeds", [])
    seed_domain = seeds[0] if seeds else "example.com"

    # DMARC posture from domain_intel
    dns_data = state.get("domain_intel", {}).get("dns", {})
    dmarc_records = dns_data.get("dmarc_record", [])
    dmarc_posture = dmarc_records[0] if isinstance(dmarc_records, list) and dmarc_records else str(dmarc_records)

    # Priority sort: infostealer > executive > breached
    exec_keywords = {"ceo", "cfo", "cto", "ciso", "vp", "director", "executive", "president", "founder"}

    def _priority(em: str) -> int:
        info = emails.get(em, {}) or {}
        score = 0
        if info.get("stealer_logs") or info.get("infostealer_hits"):
            score += 40
        pos = str(info.get("position", "")).lower()
        if any(k in pos for k in exec_keywords):
            score += 30
        if info.get("breaches") or breach_intel.get(em):
            score += 20
        return score

    top_targets = sorted(emails.keys(), key=_priority, reverse=True)[:max_targets]

    # Declare early so the empty-state branch below can use it (was previously
    # declared after the empty-state check, causing UnboundLocalError on `results`).
    results: dict[str, str] = {}

    # B32: graceful empty-state. If no emails were harvested, still write the
    # index file and GoPhish JSON so the operator gets clear, actionable output
    # instead of silent missing files. Skip LLM cost entirely.
    if not top_targets:
        empty_lines = [
            _AUTHORIZATION_BANNER,
            "# Phishing Drafts Index",
            "",
            f"**Campaign:** {state.get('campaign_id', 'unknown')}",
            f"**Generated:** {datetime.utcnow().isoformat()}",
            "",
            "## No Targets",
            "",
            "Per-target drafts were not generated because no email addresses were",
            "harvested for this campaign.",
            "",
            "To enable phishing draft generation, ensure at least one of the",
            "following produces emails in earlier phases:",
            "",
            "- `HUNTER_API_KEY` is configured (Hunter.io email pattern lookup)",
            "- `theHarvester` binary is on PATH (PyPI: `theHarvester`)",
            "- GitHub recon (`GITHUB_TOKEN`) discovers committer emails",
            "- Manual seeds via the scope's `email_domains` field",
            "",
            "Then re-run with `--generate-phishing` and at least `--mode medium`.",
            "",
        ]
        index_path = output_dir / "phishing_drafts.md"
        index_path.write_text("\n".join(empty_lines), encoding="utf-8")
        results["__index"] = str(index_path)

        campaign_json = {
            "campaign_id": state.get("campaign_id", "unknown"),
            "generated": datetime.utcnow().isoformat(),
            "warnings": [
                "AUTHORIZATION REQUIRED — verify scope before sending",
                "No targets harvested; this file is a structural placeholder.",
            ],
            "templates": [],
            "targets": [],
            "landing_pages": [],
        }
        gophish_path = output_dir / "phishing_campaign.json"
        gophish_path.write_text(json.dumps(campaign_json, indent=2), encoding="utf-8")
        results["__gophish"] = str(gophish_path)

        log.info("Phishing drafts skipped — no harvested emails", index=str(index_path))
        return results

    # Rate-limit LLM calls
    sem = asyncio.Semaphore(3)
    master_entries: list[str] = []
    gophish_templates: list[dict[str, Any]] = []
    gophish_targets: list[dict[str, Any]] = []

    async def _process_target(email: str) -> None:
        info = emails.get(email, {}) or {}
        context = _build_target_context(email, info, dmarc_posture, seed_domain)
        async with sem:
            draft = await _draft_one_target(context, executor)

        if draft is None:
            return

        # Write per-target draft file
        safe_name = re.sub(r"[^\w@.\-]", "_", email)
        draft_path = output_dir / f"phishing_draft_{safe_name}.md"
        lines = [
            _AUTHORIZATION_BANNER,
            f"# Phishing Draft: {email}",
            "",
            f"**Generated:** {datetime.utcnow().isoformat()}",
            "",
            "| Field | Value |",
            "|-------|-------|",
            f"| Target | `{draft.get('target_email', email)}` |",
            f"| Role | {draft.get('target_role', '')} |",
            f"| Lure Category | {draft.get('lure_category', '')} |",
            f"| Subject | {draft.get('subject', '')} |",
            f"| Sender | {draft.get('sender_display_name', '')} `<{draft.get('sender_address', '')}>` |",
            f"| Sender Strategy | {draft.get('sender_strategy', '')} |",
            f"| Send | {draft.get('send_day', '')} @ {draft.get('send_time', '')} |",
            f"| Attachment | {draft.get('recommended_attachment_type', '')} |",
            f"| Landing Page | {draft.get('recommended_landing_page', '')} |",
            "",
            "## Email Body",
            "",
            draft.get("body_markdown", ""),
            "",
            "## Rationale",
            "",
            draft.get("rationale", ""),
            "",
            "## OSINT Citations",
            "",
        ]
        for citation in draft.get("osint_citations", []):
            lines.append(f"- {citation}")
        lines.append("")

        draft_path.write_text("\n".join(lines), encoding="utf-8")
        results[email] = str(draft_path)
        master_entries.append(f"- [{email}]({draft_path.name}) — {draft.get('lure_category', '')} lure")

        # GoPhish template — convert markdown body to HTML for the html field
        try:
            import markdown as _markdown
            body_html = _markdown.markdown(draft.get("body_markdown", ""))
        except Exception:
            body_html = draft.get("body_markdown", "")
        template_name = draft.get("subject", email)[:50]
        gophish_templates.append({
            "name": template_name,
            "subject": draft.get("subject", ""),
            "html": body_html,
            "text": draft.get("body_plaintext", ""),
            "envelope_sender": draft.get("sender_address", ""),
        })
        parts = email.split("@")[0].split(".")
        gophish_targets.append({
            "email": email,
            "first_name": parts[0].capitalize() if parts else "",
            "last_name": parts[1].capitalize() if len(parts) > 1 else "",
            "position": draft.get("target_role", ""),
            "template": template_name,
        })

    await asyncio.gather(*(_process_target(em) for em in top_targets), return_exceptions=True)

    # Master index
    if master_entries:
        index_path = output_dir / "phishing_drafts.md"
        index_lines = [
            _AUTHORIZATION_BANNER,
            "# Phishing Drafts Index",
            "",
            f"**Campaign:** {state.get('campaign_id', 'unknown')}",
            f"**Generated:** {datetime.utcnow().isoformat()}",
            f"**Targets:** {len(results)}",
            "",
        ] + master_entries + [""]
        index_path.write_text("\n".join(index_lines), encoding="utf-8")
        results["__index__"] = str(index_path)

    # GoPhish-compatible campaign JSON
    if gophish_templates:
        campaign_id = state.get("campaign_id", "nexusrecon")
        gophish = {
            "campaign_id": campaign_id,
            "warnings": ["AUTHORIZATION REQUIRED — verify scope before sending"],
            "templates": gophish_templates,
            "targets": gophish_targets,
            "landing_pages": [
                {
                    "name": "fake_office365_login",
                    "html": "<!-- operator must build the landing page; do not auto-generate functional credential-harvesting pages -->",
                }
            ],
        }
        gophish_path = output_dir / "phishing_campaign.json"
        gophish_path.write_text(json.dumps(gophish, indent=2, default=str), encoding="utf-8")
        results["__gophish__"] = str(gophish_path)

    log.info("Phishing drafts generated", count=len(results))
    return results
