"""Obsidian-flavored master report.

The standard ``master_report.md`` is GitHub-flavored Markdown.
Obsidian renders most of it correctly but misses out on three
things vaults make heavy use of:

  - Frontmatter (YAML at the top of the file → Obsidian
    Properties). Lets the report show up in dataview queries,
    graph view filters, and the file's Properties panel.
  - Wikilinks (``[[asset_inventory]]``) for the graph view.
    Standard markdown links work but don't draw the cross-
    deliverable graph that operators rely on.
  - Callouts (``> [!warning]``) instead of bare blockquotes.
    Obsidian's built-in callout types add colored borders +
    icons; a bare ``> **CRITICAL**: …`` blockquote renders as
    plain quoted text.

This module produces a parallel ``master_report.obsidian.md``
that adds those three. The content is otherwise byte-identical
to ``master_report.md`` so we don't fork the prose generation.

Pure functions; the caller decides where to write.
"""
from __future__ import annotations

import re
from typing import Any


def render_frontmatter(
    state: dict[str, Any],
    scope_hash: str,
    nexusrecon_version: str,
) -> str:
    """Build the YAML frontmatter block.

    Obsidian indexes these as Properties — they show up in the
    sidebar and in the file's Properties panel, and become
    queryable via the Dataview plugin.

    Args:
        state: Campaign state (needs ``seeds``, ``campaign_id``,
            ``engagement_id``, ``generated``).
        scope_hash: SHA256 of the scope file. Carries through to
            the standard report footer too.
        nexusrecon_version: Package version that generated the
            report.

    Returns:
        A YAML frontmatter block delimited by ``---`` lines,
        with a trailing blank line so a body can be appended
        directly.
    """
    target = (state.get("seeds") or ["unknown"])[0]
    return (
        "---\n"
        f"campaign_id: {state.get('campaign_id', 'unknown')}\n"
        f"engagement_id: {state.get('engagement_id', 'unknown')}\n"
        f"target: {target}\n"
        f"generated: {state.get('generated', '')}\n"
        f"scope_hash: {scope_hash}\n"
        f"nexusrecon_version: {nexusrecon_version}\n"
        "tags:\n"
        "  - nexusrecon\n"
        "  - recon\n"
        "  - redteam\n"
        "---\n\n"
    )


# Match ``[label](file.ext)`` style markdown links to files in
# the same directory (no leading ``http://`` or path separator).
# Extensions are deliberately scoped to what NexusRecon emits as
# deliverables. Adding a new deliverable type = extending this
# regex.
_LOCAL_LINK = re.compile(
    r"\[([^\]]+)\]\((?!https?://)([^)/\s]+\.(?:md|json|html|csv|xml|zip))\)"
)


def rewrite_local_links_to_wikilinks(md: str) -> str:
    """Convert ``[Asset Inventory](asset_inventory.md)`` →
    ``[[asset_inventory|Asset Inventory]]``.

    Obsidian's pipe syntax lets us keep the visible label
    distinct from the file name. Non-local links (``http://``,
    ``../foo``, images with paths) are left alone.

    The link text is preserved verbatim so existing ALL-CAPS or
    title-cased labels in the source report still render the
    same way in the vault.
    """
    def _sub(m: re.Match[str]) -> str:
        label, fname = m.group(1), m.group(2)
        stem = fname.rsplit(".", 1)[0]
        return f"[[{stem}|{label}]]"

    return _LOCAL_LINK.sub(_sub, md)


# Severity → Obsidian callout type mapping. These are the
# built-in callout names Obsidian ships with — no plugin
# required.
_SEVERITY_CALLOUTS: dict[str, str] = {
    "CRITICAL": "danger",
    "HIGH": "warning",
    "MEDIUM": "note",
    "LOW": "info",
}


# Pattern: blockquote line whose first content is a known
# severity marker. Matches both ``> **CRITICAL**: text`` and
# ``> **CRITICAL** text`` (with or without the colon).
_SEVERITY_LINE = re.compile(
    r"^> \*\*(CRITICAL|HIGH|MEDIUM|LOW)\*\*[:.]?\s*(.*)$",
    re.MULTILINE,
)


def upgrade_severity_blockquotes(md: str) -> str:
    """Find bare ``> **CRITICAL**: …`` blockquotes and rewrite
    them as Obsidian callouts (``> [!danger] CRITICAL\\n> …``).

    Intentionally narrow: only the leading line of a blockquote
    that explicitly starts with a known severity gets upgraded.
    Prose blockquotes (``> A general note``) are left alone so
    we don't accidentally re-style author-controlled emphasis.
    """
    def _sub(m: re.Match[str]) -> str:
        sev, rest = m.group(1), m.group(2).strip()
        callout = _SEVERITY_CALLOUTS[sev]
        if rest:
            return f"> [!{callout}] {sev}\n> {rest}"
        return f"> [!{callout}] {sev}"

    return _SEVERITY_LINE.sub(_sub, md)


def build_obsidian_master(
    standard_md: str,
    state: dict[str, Any],
    scope_hash: str,
    nexusrecon_version: str,
) -> str:
    """Transform a standard master_report.md body into Obsidian-
    flavored output.

    Pure function. The caller is responsible for reading the
    standard file from disk and writing the result back.

    Composition order matters:
      1. Rewrite local links → wikilinks. Has to happen before
         frontmatter so the frontmatter's structure isn't
         mistaken for a link.
      2. Upgrade severity blockquotes → callouts. Operates on
         the body; the frontmatter has no blockquotes.
      3. Prepend the YAML frontmatter block.
    """
    body = rewrite_local_links_to_wikilinks(standard_md)
    body = upgrade_severity_blockquotes(body)
    return render_frontmatter(state, scope_hash, nexusrecon_version) + body
