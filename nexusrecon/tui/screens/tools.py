"""Tools browser (TUI-2 redesign).

Three-pane layout replacing the old flat DataTable in
``screens/config.py``:

  - **Left pane:** category list with per-category counts (and an
    "All" row at the top). Operator narrows scope by selecting a
    category.
  - **Centre pane:** filterable list of tools in the selected
    category. Press ``/`` to focus the filter input; type to
    narrow; Esc clears.
  - **Right pane:** detail card for the highlighted tool —
    description, tier, category, required keys (with live
    configured/missing status per key), availability, stub
    flag. Action shortcuts at the bottom (``c`` opens the edit
    modal directly on the first missing key, ``t`` test
    connection when implemented per-tool).

The previous screen surfaced 97 entries as a single sorted
DataTable. With Phase E live, the count is only going up; the
new layout scales linearly and gives operators a real workflow
for finding the tool they need.

Direct-edit UX: pressing ``c`` opens :class:`EditKeyModal`
in-place instead of pushing a separate ``ConfigScreen`` with
auto-edit. Two screen transitions become one — and the operator
returns to exactly the same tools list when the modal closes.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import Screen
from textual.widgets import (
    Footer,
    Header,
    Input,
    ListItem,
    ListView,
    Static,
)

from nexusrecon.tui.widgets import StatusBar

# ──────────────────────────────────────────────────────────────────────
# Data extraction
# ──────────────────────────────────────────────────────────────────────


def _load_tools() -> list[dict[str, Any]]:
    """Snapshot the registry. Cheap; called on each filter change.

    Defensive: never raises ── returns an empty list if the
    registry import / iteration fails so the screen renders an
    empty state instead of crashing.
    """
    try:
        from nexusrecon.tools.registry import get_registry
        return sorted(
            get_registry().list_tools(),
            key=lambda t: (t.get("category", ""), t.get("name", "")),
        )
    except Exception:
        return []


def _group_by_category(
    tools: list[dict[str, Any]],
) -> dict[str, list[dict[str, Any]]]:
    """Bucket tools by category. Order preserved within each
    bucket so the centre pane stays alphabetical."""
    buckets: dict[str, list[dict[str, Any]]] = {}
    for tool in tools:
        cat = tool.get("category", "uncategorized")
        buckets.setdefault(cat, []).append(tool)
    return buckets


#: Display labels for the tool functional categories. The keys are
#: the ``Category`` enum values; missing entries fall back to the
#: raw enum value. Kept in sync with ``nexusrecon.tools.base.Category``.
#: Labels mirror the emoji + Title-Case style the Config screen uses,
#: so an operator switching between the two screens isn't reading
#: two visually divergent taxonomies.
_CATEGORY_LABELS: dict[str, str] = {
    "breach": "🩸 Breach",
    "certificate": "🔏 Certificate",
    "cloud_aws": "☁  Cloud · AWS",
    "cloud_azure": "☁  Cloud · Azure",
    "cloud_gcp": "☁  Cloud · GCP",
    "code": "💻 Code & Repo",
    "dns": "🌐 DNS",
    "domain": "🌍 Domain",
    "email": "📧 Email",
    "identity": "👤 Identity",
    "infrastructure": "🛰  Infrastructure",
    "mobile": "📱 Mobile",
    "news": "📰 News",
    "pretext": "🎭 Pretext",
    "secret": "🔑 Secret",
    "social": "💬 Social",
    "subdomain": "🔍 Subdomain",
    "vulnerability": "🛡  Vulnerability",
    "web": "🕸  Web",
}


def _pretty_category(category: str) -> str:
    """Return the display label for a functional category, falling
    back to the raw enum value when no friendly label is mapped."""
    return _CATEGORY_LABELS.get(category, category)


def _category_label(category: str, count: int) -> str:
    """Render a left-pane row label: ``👤 Identity  (12)``."""
    return f"{_pretty_category(category)}  [dim]({count})[/dim]"


def _resolve_env_path() -> Path:
    """Find the project's ``.env``. Same heuristic as the config
    screen so both surfaces agree on which file they edit."""
    cwd = Path.cwd()
    if (cwd / ".env").exists():
        return cwd / ".env"
    for parent in [cwd] + list(cwd.parents):
        if (parent / "pyproject.toml").exists():
            return parent / ".env"
    return cwd / ".env"


def _editable_requires(tool: dict[str, Any]) -> list[str]:
    """Extract the env-var names a tool requires that can be edited
    from the TUI. Skips ``bin:foo`` markers (binary installs are
    handled outside the TUI). Returns uppercase names because the
    schema + .env both use uppercase.
    """
    raw = tool.get("requires", "") or ""
    out: list[str] = []
    for cand in raw.split(","):
        cand = cand.strip()
        if not cand or cand.startswith("bin:"):
            continue
        out.append(cand.upper())
    return out


def _editable_optional(tool: dict[str, Any]) -> list[str]:
    """Extract the tool's *optional* env-var names — keys that
    aren't needed to run the tool but unlock higher quotas or paid
    fields when set. Returned uppercase like ``_editable_requires``.
    Empty when the tool declares no ``optional_keys``.
    """
    raw = tool.get("optional", "") or ""
    out: list[str] = []
    for cand in raw.split(","):
        cand = cand.strip()
        if not cand:
            continue
        out.append(cand.upper())
    return out


# ──────────────────────────────────────────────────────────────────────
# Screen
# ──────────────────────────────────────────────────────────────────────


class ToolsScreen(Screen):
    """Three-pane tools browser.

    Navigation summary:
      - Tab cycles focus between the three panes.
      - ``/`` focuses the filter input (clears on Esc).
      - ``c`` (or Enter) opens :class:`EditKeyModal` directly on
        the highlighted tool's first unconfigured env var. No
        intermediate ConfigScreen — operator returns to the
        same tools list when the modal closes.
      - Tools whose only requirement is a binary on PATH surface
        a hint instead — those installs happen outside the TUI.
    """

    BINDINGS = [
        Binding("escape", "back", "Back"),
        Binding("slash", "focus_filter", "Filter"),
        Binding("tab", "focus_next_pane", "Cycle panes"),
        Binding("c", "edit_selected_key", "Configure"),
        Binding("enter", "edit_selected_key", "Configure", show=False),
        Binding("ctrl+q", "quit_app", "Quit"),
    ]

    #: Sentinel category id used for the "show everything" row.
    ALL_CATEGORIES = "__all__"

    def __init__(self) -> None:
        super().__init__()
        self._tools: list[dict[str, Any]] = []
        self._buckets: dict[str, list[dict[str, Any]]] = {}
        self._current_category: str = self.ALL_CATEGORIES
        self._filter_text: str = ""
        # Cache the visible list (after category + filter) so the
        # selected-row → tool resolution is cheap.
        self._visible: list[dict[str, Any]] = []
        # Resolve once — every per-key status check needs to read
        # ``.env``; doing it on every detail render is fine but the
        # path resolution doesn't need to repeat.
        self._env_path: Path = _resolve_env_path()

    # ── Compose ─────────────────────────────────────────────────────

    def compose(self) -> ComposeResult:
        yield Header(show_clock=False)
        yield StatusBar()
        with Vertical(id="tools-stack"):
            yield Static(
                "[bold $primary]Tools[/bold $primary]   "
                "[dim]Tab cycle · / filter · c config · Esc back[/dim]",
                id="tools-header",
            )
            with Horizontal(id="tools-panes"):
                # Left: categories
                with Vertical(id="tools-cat-pane"):
                    yield Static(
                        "[bold]Categories[/bold]",
                        id="tools-cat-header",
                    )
                    yield ListView(id="tools-cat-list")
                # Centre: tools list + filter
                with Vertical(id="tools-list-pane"):
                    yield Input(
                        placeholder="Filter tools (substring or fuzzy)…",
                        id="tools-filter",
                    )
                    yield ListView(id="tools-list")
                # Right: detail card
                with Vertical(id="tools-detail-pane"):
                    yield Static(id="tools-detail-title")
                    yield Static(id="tools-detail-meta")
                    yield Static(id="tools-detail-desc")
                    yield Static(id="tools-detail-actions")
        yield Footer()

    # ── Lifecycle ───────────────────────────────────────────────────

    async def on_mount(self) -> None:
        self._refresh_data()
        self._rebuild_categories()
        self._rebuild_tools_list()
        self._render_detail(self._first_visible_tool())
        # Land focus on the centre list so the operator can scroll
        # immediately with arrow keys.
        try:
            self.query_one("#tools-list", ListView).focus()
        except Exception:
            pass

    def _refresh_data(self) -> None:
        self._tools = _load_tools()
        self._buckets = _group_by_category(self._tools)

    # ── Rendering helpers ───────────────────────────────────────────

    def _rebuild_categories(self) -> None:
        """Populate the left pane with ``All (97)`` then each
        category in alphabetical order."""
        try:
            cat_list = self.query_one("#tools-cat-list", ListView)
        except Exception:
            return
        try:
            cat_list.clear()
        except Exception:
            pass
        cat_list.append(
            ListItem(
                Static(_category_label("All", len(self._tools))),
                id=f"cat-{self.ALL_CATEGORIES}",
            ),
        )
        for cat in sorted(self._buckets.keys()):
            count = len(self._buckets[cat])
            cat_list.append(
                ListItem(Static(_category_label(cat, count)), id=f"cat-{cat}")
            )
        # Default selection: All.
        try:
            cat_list.index = 0
        except Exception:
            pass

    def _visible_tools(self) -> list[dict[str, Any]]:
        """Compute the centre-pane content under current category +
        filter."""
        if self._current_category == self.ALL_CATEGORIES:
            pool = self._tools
        else:
            pool = self._buckets.get(self._current_category, [])
        if not self._filter_text:
            return pool
        text = self._filter_text.strip().lower()
        if not text:
            return pool
        from nexusrecon.tui.command_palette import fuzzy_score
        scored = [
            (
                fuzzy_score(
                    f"{t.get('name', '')} {t.get('description', '')} "
                    f"{t.get('category', '')}",
                    text,
                ),
                t,
            )
            for t in pool
        ]
        return [t for s, t in sorted(scored, key=lambda x: -x[0]) if s > 0]

    def _rebuild_tools_list(self) -> None:
        try:
            tool_list = self.query_one("#tools-list", ListView)
        except Exception:
            return
        try:
            tool_list.clear()
        except Exception:
            pass
        self._visible = self._visible_tools()
        for tool in self._visible:
            tool_list.append(
                ListItem(Static(self._render_tool_row(tool))),
            )
        try:
            tool_list.index = 0 if self._visible else None
        except Exception:
            pass

    def _render_tool_row(self, tool: dict[str, Any]) -> str:
        """Single-line representation for the centre list."""
        name = tool.get("name", "?")
        available = tool.get("available", "False") == "True"
        stubbed = tool.get("stubbed", "False") == "True"
        if stubbed:
            icon = "[$warning]⚠[/$warning]"
        elif available:
            icon = "[$success]✓[/$success]"
        else:
            icon = "[$error]✗[/$error]"
        return f"{icon}  [bold]{name}[/bold]  [dim]{tool.get('tier', '?')}[/dim]"

    def _first_visible_tool(self) -> dict[str, Any] | None:
        return self._visible[0] if self._visible else None

    def _render_detail(self, tool: dict[str, Any] | None) -> None:
        """Update the right pane to show the selected tool's full
        metadata. ``None`` clears it."""
        try:
            title_widget = self.query_one("#tools-detail-title", Static)
            meta_widget = self.query_one("#tools-detail-meta", Static)
            desc_widget = self.query_one("#tools-detail-desc", Static)
            actions_widget = self.query_one("#tools-detail-actions", Static)
        except Exception:
            return
        if not tool:
            title_widget.update("[dim](no tool selected)[/dim]")
            meta_widget.update("")
            desc_widget.update("")
            actions_widget.update("")
            return
        name = tool.get("name", "?")
        available = tool.get("available", "False") == "True"
        stubbed = tool.get("stubbed", "False") == "True"
        if stubbed:
            status_line = "[$warning]⚠ stub (not implemented yet)[/$warning]"
        elif available:
            status_line = "[$success]✓ available[/$success]"
        else:
            status_line = "[$error]✗ requires key(s) not yet configured[/$error]"
        meta_lines = [
            f"[dim]Tier:[/dim]     {tool.get('tier', '?')}",
            f"[dim]Category:[/dim] {_pretty_category(tool.get('category', '?'))}",
            f"[dim]Status:[/dim]   {status_line}",
            "",
            "[dim]Requires:[/dim]",
            *self._render_requires_lines(tool),
        ]
        # TUI-8: per-tool invocation history. Empty session adds
        # nothing visible (renderer collapses); the section
        # appears only once the tool has actually run.
        history_lines = self._render_invocation_history(name)
        if history_lines:
            meta_lines.append("")
            meta_lines.append("[dim]Recent invocations:[/dim]")
            meta_lines.extend(history_lines)

        title_widget.update(f"[bold $primary]{name}[/bold $primary]")
        meta_widget.update("\n".join(meta_lines))
        desc_widget.update((tool.get("description") or "").strip())
        action_hint = self._action_hint_for(tool)
        actions_widget.update(action_hint)

    def _render_invocation_history(self, tool_name: str) -> list[str]:
        """TUI-8: per-tool invocation surface.

        Reads the in-memory invocation history the registry
        records on every ``execute()`` call. Renders an
        aggregate summary line (count / avg duration / last
        status / last error) — enough signal to triage a
        "why isn't this tool working" question without
        leaving the Tools browser.

        Empty history returns an empty list so the section
        collapses cleanly. Cache hits are counted as
        invocations but excluded from the avg-duration
        calculation (they're effectively instant)."""
        try:
            from nexusrecon.tools.registry import get_registry
            summary = get_registry().invocation_summary(tool_name)
        except Exception:
            return []
        if summary["count"] == 0:
            return []
        lines: list[str] = []
        # Aggregate stats row.
        avg_ms = summary["avg_runtime_ms"]
        avg_str = f"{avg_ms} ms" if avg_ms < 1000 else f"{avg_ms / 1000:.1f} s"
        last_status = summary["last_status"] or "?"
        last_marker = (
            "[$success]✓[/$success]"
            if last_status == "success"
            else "[$error]✗[/$error]"
        )
        lines.append(
            f"  {last_marker} {summary['count']} call(s) this session   "
            f"[dim]avg {avg_str}   last: {last_status}[/dim]",
        )
        if summary.get("last_error"):
            err = str(summary["last_error"])
            if len(err) > 90:
                err = err[:87] + "…"
            lines.append(
                f"  [$error]last error:[/$error] [dim]{err}[/dim]",
            )
        return lines

    def _render_requires_lines(self, tool: dict[str, Any]) -> list[str]:
        """Per-requirement status lines for the detail pane.

        Each editable env var gets a configured / missing marker
        sourced from the live ``.env``. ``bin:`` markers get a
        PATH-presence check via ``shutil.which`` so the operator
        knows at a glance whether ``gowitness`` is installed.

        Optional keys (declared via ``optional_keys`` on the tool)
        get a separate ◯ marker so the operator can tell at a
        glance which are needed vs which enhance behaviour.
        """
        import shutil

        from nexusrecon.tui.env_editor import EnvFile

        raw = tool.get("requires", "") or ""
        required_parts = [p.strip() for p in raw.split(",") if p.strip()]
        optional_keys = _editable_optional(tool)
        if not required_parts and not optional_keys:
            return ["  [dim](none — runs unauthenticated)[/dim]"]
        env_file = EnvFile(self._env_path)
        out: list[str] = []
        for part in required_parts:
            if part.startswith("bin:"):
                binary = part[4:]
                path = shutil.which(binary)
                if path:
                    out.append(
                        f"  [$success]✓[/$success] [bold]{binary}[/bold]  "
                        f"[dim]bin · {path}[/dim]"
                    )
                else:
                    out.append(
                        f"  [$error]✗[/$error] [bold]{binary}[/bold]  "
                        "[dim]bin · not on PATH[/dim]"
                    )
                continue
            key = part.upper()
            value = env_file.get(key)
            if value:
                out.append(
                    f"  [$success]✓[/$success] [bold]{key}[/bold]  "
                    "[dim]configured[/dim]"
                )
            else:
                out.append(
                    f"  [$error]✗[/$error] [bold]{key}[/bold]  "
                    "[dim]not set[/dim]"
                )
        for key in optional_keys:
            value = env_file.get(key)
            if value:
                out.append(
                    f"  [$success]✓[/$success] [bold]{key}[/bold]  "
                    "[dim]optional · configured[/dim]"
                )
            else:
                out.append(
                    f"  [$accent]◯[/$accent] [bold]{key}[/bold]  "
                    "[dim]optional · not set (enhancement)[/dim]"
                )
        return out

    def _action_hint_for(self, tool: dict[str, Any]) -> str:
        """Build the right-pane action hint string for ``tool``.

        The hint names the first env var the operator can set so
        pressing ``c`` produces no surprise. When the tool requires
        nothing settable from the TUI (binary-only or no keys at
        all) the hint says so explicitly rather than offering a
        config shortcut that wouldn't do anything.
        """
        editable = self._editable_target(tool)
        if editable is not None:
            _, key, kind = editable
            qualifier = "" if kind == "required" else " [dim](optional)[/dim]"
            return (
                f"[bold]c[/bold] set [bold $primary]{key}[/bold $primary]"
                f"{qualifier}   [dim]Esc[/dim] back"
            )
        # Tool has no editable env vars. Surface why the operator
        # can't configure it from here, in concrete terms.
        raw = tool.get("requires", "") or ""
        bin_only = raw and all(
            p.strip().startswith("bin:")
            for p in raw.split(",")
            if p.strip()
        )
        if bin_only:
            return (
                "[dim]install binary via shell · "
                "Esc back[/dim]"
            )
        return "[dim](no env vars to configure)   Esc back[/dim]"

    def _editable_target(
        self, tool: dict[str, Any],
    ) -> tuple[Any, str, str] | None:
        """Pick the env var an operator should be sent to edit.

        Walks the required keys first (a missing required key is
        always the highest-priority gap to fix), then the optional
        keys. Within each group, prefer the first key that is
        **not yet set**. Falls back to the first declared key when
        everything is already configured (rotation case).

        Returns ``(ConfigVar, key, kind)`` where ``kind`` is
        ``"required"`` or ``"optional"`` — the caller uses it to
        word the action hint correctly. ``None`` when the tool has
        no schema-known editable keys.
        """
        try:
            from nexusrecon.tui.config_schema import find_var
            from nexusrecon.tui.env_editor import EnvFile
        except Exception:
            return None
        env_file = EnvFile(self._env_path)
        fallback: tuple[Any, str, str] | None = None

        def _scan(keys: list[str], kind: str) -> tuple[Any, str, str] | None:
            nonlocal fallback
            for key in keys:
                var = find_var(key)
                if var is None:
                    continue
                if fallback is None:
                    fallback = (var, var.key, kind)
                if not env_file.get(var.key):
                    return var, var.key, kind
            return None

        hit = _scan(_editable_requires(tool), "required")
        if hit:
            return hit
        hit = _scan(_editable_optional(tool), "optional")
        if hit:
            return hit
        return fallback

    # ── Event handlers ──────────────────────────────────────────────

    def on_list_view_highlighted(
        self, event: ListView.Highlighted,
    ) -> None:
        """Track which row is highlighted in each pane and update
        the right-side detail to match."""
        try:
            pane_id = event.list_view.id
        except Exception:
            return
        if pane_id == "tools-cat-list":
            idx = event.list_view.index
            if idx is None:
                return
            sorted_cats = sorted(self._buckets.keys())
            if idx == 0:
                self._current_category = self.ALL_CATEGORIES
            elif 1 <= idx <= len(sorted_cats):
                self._current_category = sorted_cats[idx - 1]
            else:
                return
            self._rebuild_tools_list()
            self._render_detail(self._first_visible_tool())
        elif pane_id == "tools-list":
            idx = event.list_view.index
            if idx is None or idx < 0 or idx >= len(self._visible):
                self._render_detail(None)
            else:
                self._render_detail(self._visible[idx])

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id != "tools-filter":
            return
        self._filter_text = event.value
        self._rebuild_tools_list()
        self._render_detail(self._first_visible_tool())

    # ── Actions ─────────────────────────────────────────────────────

    def action_focus_filter(self) -> None:
        try:
            self.query_one("#tools-filter", Input).focus()
        except Exception:
            pass

    def action_focus_next_pane(self) -> None:
        try:
            focused = self.focused
            focused_id = focused.id if focused else None
            order = ("tools-cat-list", "tools-filter", "tools-list")
            current_idx = order.index(focused_id) if focused_id in order else -1
            next_id = order[(current_idx + 1) % len(order)]
            self.query_one(f"#{next_id}").focus()
        except Exception:
            pass

    async def action_edit_selected_key(self) -> None:
        """Open the EditKeyModal in-place for the highlighted tool's
        first editable env var.

        This is the primary configure surface from the Tools
        browser. We open the modal directly here rather than
        pushing a ConfigScreen and letting it auto-edit — that
        added a redundant screen transition (operator sees the
        config category list flash by) and made "back" land on
        ConfigScreen instead of back on the tool the operator
        was just looking at.

        Selection rule: first missing key wins; otherwise the
        first editable key. Tools whose only requirements are
        binaries (``bin:gowitness``) or that require nothing
        flash a hint instead — there's nothing to edit from
        here.
        """
        if not self._visible:
            return
        idx = self._current_idx()
        if idx is None or idx < 0 or idx >= len(self._visible):
            return
        tool = self._visible[idx]
        target = self._editable_target(tool)
        if target is None:
            # Surface why nothing happened. The detail pane already
            # explains, but a toast makes the keypress feel acknowledged.
            try:
                raw = tool.get("requires", "") or ""
                bin_only = raw and all(
                    p.strip().startswith("bin:")
                    for p in raw.split(",")
                    if p.strip()
                )
                if bin_only:
                    self.app.notify(
                        f"{tool.get('name', '?')} requires a binary on PATH "
                        "(install via shell — can't edit from TUI)",
                        severity="warning",
                    )
                else:
                    self.app.notify(
                        f"{tool.get('name', '?')} has no env vars to configure",
                        severity="information",
                    )
            except Exception:
                pass
            return
        var, _key, _kind = target
        try:
            from nexusrecon.tui.screens.edit_key import EditKeyModal
        except Exception:
            return

        def _on_dismiss(_result: Any) -> None:
            # Re-render the detail pane so the per-key status
            # marker reflects the new .env state.
            self._render_detail(tool)

        try:
            await self.app.push_screen(
                EditKeyModal(env_path=str(self._env_path), var=var),
                _on_dismiss,
            )
        except Exception:
            pass

    def _current_idx(self) -> int:
        """Index of the highlighted tool in ``self._visible`` (-1 if
        the centre list has no selection)."""
        try:
            return self.query_one("#tools-list", ListView).index or 0
        except Exception:
            return -1

    def action_back(self) -> None:
        try:
            self.app.pop_screen()
        except Exception:
            pass

    def action_quit_app(self) -> None:
        self.app.exit()
