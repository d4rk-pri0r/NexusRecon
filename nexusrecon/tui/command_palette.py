"""Command palette infrastructure (TUI-2).

The palette is the operator's universal jump surface — Ctrl+P / `:`
from any screen, type a query, see ranked matches across tools,
screens, reports, and (later) campaigns + config keys. Modelled on
atuin / VS Code / posting.

Architecture: a thin extensible provider system. Each
:class:`CommandSource` advertises a slice of the world (tools,
navigation targets, reports, …) via a single ``query(text)``
method that returns ranked matches. The palette merges matches
across all registered sources and presents the global ranking.

Adding a future source (say, "saved searches") is one subclass +
one registration line; the palette doesn't need to know what kinds
of things exist.

Pure Python. No Textual imports in this module — sources stay
unit-testable without spinning up the TUI. The Textual modal
that *renders* the palette lives in
:mod:`nexusrecon.tui.screens.command_palette`.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

# ──────────────────────────────────────────────────────────────────────
# Match dataclass
# ──────────────────────────────────────────────────────────────────────


@dataclass
class CommandMatch:
    """One ranked palette result.

    Attributes:
        title: Bold first-line label rendered in the palette
            (e.g. ``"github_social"``, ``"Open: harvested_credentials.md"``).
        subtitle: Dimmed second-line metadata (category, path,
            description snippet). Optional; left blank when not useful.
        icon: Single-character / emoji prefix used to communicate
            the match's KIND at a glance. Severity-style colour is
            implied by ``kind`` rather than a separate field.
        kind: Coarse classification —
            ``"tool"``, ``"nav"``, ``"report"``, ``"campaign"``,
            ``"config"``, ``"action"``. The palette uses this to
            apply the appropriate icon colour and group ranking
            ties stably.
        score: Match score in ``[0, 1]``. Higher is better. The
            palette sorts descending then by ``kind`` then by
            ``title`` for deterministic ordering across renders.
        execute: Zero-arg callable that performs the navigation
            or action when the operator selects the match. May be
            sync or async; the palette awaits if a coroutine is
            returned.
        metadata: Source-specific extras (the underlying tool name,
            the campaign id, etc.) — not rendered, but useful for
            tests and for plugging into future telemetry.
    """

    title: str
    subtitle: str = ""
    icon: str = "•"
    kind: str = "action"
    score: float = 0.0
    execute: Callable[[], Any] | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


# ──────────────────────────────────────────────────────────────────────
# Matching helper
# ──────────────────────────────────────────────────────────────────────


def fuzzy_score(haystack: str, needle: str) -> float:
    """Return a ``[0, 1]`` similarity score between ``needle`` and
    ``haystack`` using a permissive subsequence + prefix heuristic.

    Scoring intent (in order of strength):

      1. Empty needle → 1.0 (everything matches; sources can use
         this to populate the palette on first open with the
         full set, ranked by source-specific priority).
      2. Exact case-insensitive substring → 0.9–1.0 (higher when
         the substring is at the start of the haystack).
      3. Out-of-order subsequence match (every char of needle
         appears in haystack in order) → 0.4–0.7 depending on
         contiguity.
      4. No match → 0.0.

    Deliberately not a full Smith-Waterman / fzf-quality matcher
    — the palette ranks against a few hundred items, not millions;
    correctness + readability beat perfection. fzf-style matching
    can land later if needed.
    """
    if not needle:
        return 1.0
    if not haystack:
        return 0.0
    h = haystack.lower()
    n = needle.lower()
    # Tier 2: exact substring
    if n in h:
        # Front-anchored matches score higher than middle.
        idx = h.find(n)
        # 0.9 base, +0.1 if it's at the start of the haystack
        # (or right after a word boundary like ``_`` / ``-`` / ``/`` / ``.``).
        anchored = idx == 0 or (idx > 0 and h[idx - 1] in "-_./ ")
        return 0.9 + (0.1 if anchored else 0.0)
    # Tier 3: subsequence match.
    pos = 0
    contiguous = 0
    longest = 0
    last_idx = -1
    for char in n:
        found = h.find(char, pos)
        if found == -1:
            return 0.0
        if last_idx >= 0 and found == last_idx + 1:
            contiguous += 1
            longest = max(longest, contiguous)
        else:
            contiguous = 1
        last_idx = found
        pos = found + 1
    # Contiguity bonus: a needle that matches as a single run scores
    # closer to 0.7; one that's scattered across the haystack stays
    # at 0.4.
    contig_ratio = longest / max(1, len(n))
    return 0.4 + 0.3 * contig_ratio


# ──────────────────────────────────────────────────────────────────────
# Source base class
# ──────────────────────────────────────────────────────────────────────


class CommandSource(ABC):
    """Provider of one slice of the palette's universe.

    Implement :meth:`query` to surface matches; the palette will
    call it for every keystroke (debounced upstream) and merge the
    output across all registered sources.
    """

    #: Display name for debugging + the future palette filter
    #: (`tools:` prefix narrows to the tools source, etc.).
    name: str = "source"

    @abstractmethod
    def query(self, text: str) -> list[CommandMatch]:
        """Return ranked matches for ``text``.

        Implementations should:

          - Return an empty list if no plausible matches exist.
          - Cap their output (typical: top 20) so a single source
            can't drown the palette.
          - Use :func:`fuzzy_score` (or equivalent) for ranking.
          - NEVER raise ── the palette must remain stable when one
            source has a bug.
        """


# ──────────────────────────────────────────────────────────────────────
# Concrete sources
# ──────────────────────────────────────────────────────────────────────


class ToolsSource(CommandSource):
    """Surface every registered tool by name."""

    name = "tools"

    def __init__(self, jump_to_tools_screen: Callable[[str], Any] | None = None):
        """``jump_to_tools_screen`` is the callable invoked when a
        match is selected. Accepts the chosen tool's name. Injected
        rather than imported so this source stays unit-testable
        without a live Textual app."""
        self._jump = jump_to_tools_screen

    def query(self, text: str) -> list[CommandMatch]:
        try:
            from nexusrecon.tools.registry import get_registry
            entries = get_registry().list_tools()
        except Exception:
            return []
        matches: list[CommandMatch] = []
        for entry in entries:
            name = entry.get("name", "")
            if not name:
                continue
            description = entry.get("description", "")
            category = entry.get("category", "")
            # Score per field separately + weight: an operator typing
            # "github" wants tools whose NAME matches first, with
            # description-only matches strictly below. Without this
            # weighting, ``exploitdb`` ranks alongside
            # ``github_actions_leaks`` because exploitdb's description
            # mentions GitHub.
            name_score = fuzzy_score(name, text)
            cat_score = fuzzy_score(category, text)
            desc_score = fuzzy_score(description, text)
            score = max(
                name_score,           # full weight on name
                cat_score * 0.6,      # category match still useful but secondary
                desc_score * 0.4,     # description matches surface tools
                                      # but rank below name/category hits
            )
            if score <= 0.0:
                continue
            available = entry.get("available", "False") == "True"
            stubbed = entry.get("stubbed", "False") == "True"
            # The icon communicates state at a glance:
            #   ✓ ready, ✗ missing keys, ⚠ stub.
            if stubbed:
                icon = "⚠"
            elif available:
                icon = "✓"
            else:
                icon = "✗"
            subtitle = (
                f"{category or '?'} · {entry.get('tier', '?')}"
                + (f" · {description}" if description else "")
            )[:120]
            matches.append(CommandMatch(
                title=name,
                subtitle=subtitle,
                icon=icon,
                kind="tool",
                score=score,
                execute=(lambda n=name: (self._jump(n) if self._jump else None)),
                metadata={"tool_name": name, "category": category},
            ))
        matches.sort(key=lambda m: (-m.score, m.title))
        return matches[:20]


class NavigationSource(CommandSource):
    """Surface every top-level navigation target.

    Operators can type ``go config`` or just ``conf`` to jump to
    the config screen, regardless of where they are.
    """

    name = "navigation"

    def __init__(
        self,
        navigate: Callable[[str], Any] | None = None,
    ):
        """``navigate`` accepts one of the canonical destination
        IDs (``"dashboard"``, ``"config"``, ``"tools"``, ``"help"``,
        ``"campaigns"``, ``"new_campaign"``). Injected for
        testability."""
        self._navigate = navigate

    # The static catalog of navigation targets the palette knows
    # about. Each entry is (id, title, subtitle, icon).
    _CATALOG = (
        ("dashboard", "Dashboard", "Welcome / overview", "📊"),
        ("new_campaign", "New campaign", "Open the campaign wizard", "🎯"),
        ("campaigns", "Past campaigns", "Browse + resume previous runs", "📁"),
        ("tools", "Tools", "Browse registered tools", "🛠"),
        ("config", "Configuration", "Edit secrets + integrations", "🔧"),
        ("help", "Help", "Keyboard cheat sheet", "❓"),
    )

    def query(self, text: str) -> list[CommandMatch]:
        matches: list[CommandMatch] = []
        for entry_id, title, subtitle, icon in self._CATALOG:
            haystack = f"go {title} {entry_id} {subtitle}"
            score = fuzzy_score(haystack, text)
            if score <= 0.0:
                continue
            matches.append(CommandMatch(
                title=title,
                subtitle=subtitle,
                icon=icon,
                kind="nav",
                score=score,
                execute=(
                    lambda eid=entry_id: (
                        self._navigate(eid) if self._navigate else None
                    )
                ),
                metadata={"destination": entry_id},
            ))
        matches.sort(key=lambda m: (-m.score, m.title))
        return matches


class ReportsSource(CommandSource):
    """Surface every deliverable from the most-recent campaign.

    Operators can type ``creds`` and jump straight to
    ``harvested_credentials.md`` without browsing the campaigns
    list. Looks up the most-recently-modified ``state.json`` under
    the configured output directory; reports come from the
    sibling files.
    """

    name = "reports"

    #: Names of report files we surface (matches
    #: ``reports/engine.py`` outputs). Operators type any substring.
    _REPORT_FILES = (
        ("master_report.md", "Master report"),
        ("executive_summary.md", "Executive summary"),
        ("top_threads.md", "Top threads to pull"),
        ("attack_surface.md", "Attack surface matrix"),
        ("phishing_package.md", "Phishing package"),
        ("vuln_correlation.md", "Vulnerability correlation"),
        ("harvested_credentials.md", "Harvested credentials"),
        ("credential_exposure_paths.md", "Credential exposure paths"),
        ("spear_phishing_intelligence.md", "Spear-phishing intelligence"),
        ("pretext_candidates.json", "Pretext candidates (JSON)"),
        ("asset_inventory.md", "Asset inventory"),
        ("people_map.md", "People map"),
        ("vendor_supply_chain.md", "Vendor supply chain"),
        ("jira_tracker.md", "Jira tracker"),
        ("entity_graph.html", "Entity graph (HTML)"),
        ("findings.json", "Findings (JSON)"),
        ("campaign_meta.json", "Campaign metadata"),
    )

    def __init__(self, open_path: Callable[[str], Any] | None = None):
        self._open_path = open_path

    def query(self, text: str) -> list[CommandMatch]:
        from pathlib import Path

        try:
            from nexusrecon.core.config import get_config
            cfg = get_config()
            out_dir = Path(cfg.output_dir)
        except Exception:
            return []
        if not out_dir.exists():
            return []
        # Find the most-recently-modified state.json — its parent
        # directory holds the latest campaign's reports.
        try:
            states = list(out_dir.rglob("state.json"))
            if not states:
                return []
            latest_dir = max(states, key=lambda p: p.stat().st_mtime).parent
        except Exception:
            return []

        matches: list[CommandMatch] = []
        for filename, label in self._REPORT_FILES:
            path = latest_dir / filename
            haystack = f"{filename} {label}"
            score = fuzzy_score(haystack, text)
            if score <= 0.0:
                continue
            exists = path.exists()
            icon = "📄" if exists else "○"
            subtitle = f"{latest_dir.name}/{filename}"
            if not exists:
                subtitle += " (not generated)"
            matches.append(CommandMatch(
                title=label,
                subtitle=subtitle,
                icon=icon,
                kind="report",
                score=score if exists else score * 0.5,
                execute=(
                    lambda p=str(path): (
                        self._open_path(p) if self._open_path else None
                    )
                ) if exists else None,
                metadata={"report_path": str(path), "exists": exists},
            ))
        matches.sort(key=lambda m: (-m.score, m.title))
        return matches[:15]


# ──────────────────────────────────────────────────────────────────────
# Palette engine
# ──────────────────────────────────────────────────────────────────────


class CommandPalette:
    """Merges results across registered :class:`CommandSource` providers.

    Use one instance per :class:`App` ── the modal screen looks up
    the palette via the app reference. Sources are registered at
    app startup and stay for the app's lifetime; we don't currently
    support hot-swapping sources during a session (no use case yet).
    """

    def __init__(self) -> None:
        self._sources: list[CommandSource] = []

    def register(self, source: CommandSource) -> None:
        """Append a source. Order doesn't affect ranking ── the
        palette sorts by score globally."""
        self._sources.append(source)

    def sources(self) -> list[CommandSource]:
        return list(self._sources)

    def query(
        self,
        text: str,
        *,
        max_results: int = 40,
    ) -> list[CommandMatch]:
        """Aggregate matches across every source, ranked descending.

        Defensive: a source that raises is logged + skipped, not
        propagated. The palette must keep responding.
        """
        results: list[CommandMatch] = []
        for source in self._sources:
            try:
                results.extend(source.query(text))
            except Exception:
                # Skip the buggy source; keep the rest of the
                # palette responsive.
                continue
        results.sort(key=lambda m: (-m.score, m.kind, m.title))
        return results[:max_results]
