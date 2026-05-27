"""In-TUI Markdown report browser (TUI-5 flagship).

Replaces the previous "launch external editor for every report"
workflow with a three-pane browser that keeps operators in the TUI:

  - **Left pane:** scrollable list of deliverables from the
    selected campaign. Each row has a status icon (● generated,
    ○ absent, ✓ operator-reviewed) + the deliverable's
    human-readable name.
  - **Centre pane:** :class:`MarkdownViewer` rendering the
    currently-selected report. Inline tables, code blocks, links
    all render natively. JSON / HTML deliverables show a hint
    that opens them externally via ``e``.
  - **Right pane:** context-sensitive action hints — current
    bindings, file path, reviewed-state toggle reminder.

Reviewed-state persistence: marking a report flips a flag file
next to it (``<report>.reviewed``). The state survives reboots
and is honoured by the icon column. Reset by deleting the flag
or pressing ``m`` again.

Spec ref: ``docs/TUI_DESIGN_SPEC.md§6.4`` and §4.3.
"""
from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

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
    MarkdownViewer,
    Static,
)

from nexusrecon.tui.widgets import StatusBar

# ──────────────────────────────────────────────────────────────────────
# Catalog
# ──────────────────────────────────────────────────────────────────────


@dataclass
class ReportEntry:
    """One row in the reports list.

    Attributes:
        filename: File name within the campaign's reports/ dir
            (e.g. ``master_report.md``).
        label: Human-readable name shown in the list pane.
        path: Absolute path to the file. May not exist on disk.
        exists: Whether the file was generated for this campaign.
        reviewed: Whether the operator has flagged this as
            reviewed (persisted via a sibling ``.reviewed`` flag
            file).
        renderable: Whether the in-TUI MarkdownViewer can render
            this file directly. JSON / HTML fall back to "open
            external" prompts.
    """

    filename: str
    label: str
    path: Path
    exists: bool
    reviewed: bool
    renderable: bool


#: Canonical catalog of deliverables NexusRecon can emit. Mirrors
#: the set of files produced by ``reports/engine.py``. New
#: deliverables register here so the browser surfaces them.
REPORT_CATALOG: list[tuple[str, str]] = [
    # (filename, label) — declaration order = list order
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
]


def _is_renderable(filename: str) -> bool:
    """Markdown renders inline; JSON / HTML need an external opener."""
    return filename.endswith(".md")


def discover_reports(campaign_dir: str | Path) -> list[ReportEntry]:
    """Enumerate the catalog against a campaign's ``reports/`` dir.

    Returns one entry per known deliverable type, regardless of
    whether the file was generated — operators see the full set
    so absent reports surface as ``○`` rather than silently
    omitted.

    ``campaign_dir`` may be the campaign root OR the reports/ subdir.
    """
    base = Path(campaign_dir)
    reports_dir = base if base.name == "reports" else base / "reports"
    entries: list[ReportEntry] = []
    for filename, label in REPORT_CATALOG:
        path = reports_dir / filename
        exists = path.exists()
        reviewed = (
            (path.with_suffix(path.suffix + ".reviewed")).exists()
            if exists
            else False
        )
        entries.append(ReportEntry(
            filename=filename,
            label=label,
            path=path,
            exists=exists,
            reviewed=reviewed,
            renderable=_is_renderable(filename),
        ))
    return entries


def _flag_path(report_path: Path) -> Path:
    """Return the sibling flag path used to record review status."""
    return report_path.with_suffix(report_path.suffix + ".reviewed")


def mark_reviewed(report_path: Path) -> bool:
    """Flip a report's reviewed flag.

    Returns the new state (True = reviewed, False = unmarked).
    No-op when the report itself doesn't exist on disk.
    """
    if not report_path.exists():
        return False
    flag = _flag_path(report_path)
    if flag.exists():
        try:
            flag.unlink()
        except Exception:
            pass
        return False
    try:
        flag.touch()
    except Exception:
        return False
    return True


def render_row(entry: ReportEntry) -> str:
    """One-line label for the ListView row."""
    if not entry.exists:
        icon = "○"
        return f"{icon}  [dim]{entry.label}[/dim]  [dim](not generated)[/dim]"
    if entry.reviewed:
        return f"[$success]✓[/$success]  [bold]{entry.label}[/bold]  [dim]reviewed[/dim]"
    return f"[$primary]●[/$primary]  [bold]{entry.label}[/bold]"


# ──────────────────────────────────────────────────────────────────────
# Screen
# ──────────────────────────────────────────────────────────────────────


class ReportsBrowserScreen(Screen):
    """Three-pane in-TUI markdown report browser."""

    BINDINGS = [
        Binding("slash", "focus_filter", "Filter"),
        Binding("escape", "back", "Back"),
        Binding("tab", "focus_next_pane", "Cycle panes"),
        Binding("m", "toggle_reviewed", "Mark reviewed"),
        Binding("e", "open_external", "Open external"),
        Binding("ctrl+q", "quit_app", "Quit"),
    ]

    def __init__(self, campaign_dir: str | Path) -> None:
        super().__init__()
        self.campaign_dir = Path(campaign_dir)
        self._entries: list[ReportEntry] = []
        # Filtered view of entries (what the ListView shows). Refreshed
        # on every ``_filter_text`` change. Keep ``_entries`` as the
        # source of truth so the filter can be cleared cheaply.
        self._visible_entries: list[ReportEntry] = []
        # Substring filter; lowercased at set time.
        self._filter_text: str = ""
        self._current_idx: int = 0

    def compose(self) -> ComposeResult:
        yield Header(show_clock=False)
        yield StatusBar()
        with Horizontal(id="reports-panes"):
            with Vertical(id="reports-list-pane"):
                yield Static(
                    "[bold $primary]Reports[/bold $primary]",
                    id="reports-list-title",
                )
                # TUI-7: hidden filter Input above the list. Revealed
                # on ``/``; Esc clears + hides + restores focus to
                # the list. Substring match against the entry label,
                # case-insensitive — operators don't recall the exact
                # filename.
                yield Input(
                    placeholder="Filter reports…",
                    id="reports-filter",
                    classes="reports-filter-hidden",
                )
                yield ListView(id="reports-list")
            with Vertical(id="reports-preview-pane"):
                yield Static(id="reports-preview-title")
                yield MarkdownViewer(
                    "Select a report to preview.",
                    show_table_of_contents=False,
                    id="reports-preview",
                )
            with Vertical(id="reports-actions-pane"):
                yield Static(
                    "[bold $primary]Actions[/bold $primary]",
                    id="reports-actions-title",
                )
                yield Static(id="reports-actions-body")
        yield Footer()

    async def on_mount(self) -> None:
        self._entries = discover_reports(self.campaign_dir)
        self._populate_list()
        # Default selection: first generated report, else first row.
        first_present = next(
            (i for i, e in enumerate(self._entries) if e.exists), 0,
        )
        try:
            list_view = self.query_one("#reports-list", ListView)
            list_view.index = first_present
            list_view.focus()
        except Exception:
            pass
        # Render the default selection.
        await self._render_selection(first_present)

    def _populate_list(self) -> None:
        """Repopulate the ListView from the filtered entry set.

        TUI-7: the visible rows are now ``_visible_entries`` not
        ``_entries`` directly. ``_filter_text`` empty means show
        everything (so the unfiltered call path is identical to
        pre-TUI-7 behaviour)."""
        try:
            list_view = self.query_one("#reports-list", ListView)
        except Exception:
            return
        try:
            list_view.clear()
        except Exception:
            pass
        self._visible_entries = self._filtered_entries()
        for entry in self._visible_entries:
            list_view.append(ListItem(Static(render_row(entry))))

    def _filtered_entries(self) -> list[ReportEntry]:
        """Subset of ``_entries`` matching the active filter.
        Empty filter returns the full list. Substring match
        against the entry label (operator-facing name) AND the
        filename (so a power user can filter on technical names
        like ``credential_exposure_paths``)."""
        if not self._filter_text:
            return list(self._entries)
        needle = self._filter_text.lower()
        return [
            e for e in self._entries
            if needle in e.label.lower()
            or needle in e.filename.lower()
        ]

    # ── Selection + preview ─────────────────────────────────────────

    async def on_list_view_highlighted(
        self, event: ListView.Highlighted,
    ) -> None:
        if event.list_view.id != "reports-list":
            return
        idx = event.list_view.index or 0
        await self._render_selection(idx)

    async def _render_selection(self, idx: int) -> None:
        # TUI-7: idx is into the FILTERED list. The current idx is
        # tracked against the filtered set too, so action_open /
        # action_toggle_reviewed look up the right entry.
        if not (0 <= idx < len(self._visible_entries)):
            return
        entry = self._visible_entries[idx]
        self._current_idx = idx

        try:
            title = self.query_one("#reports-preview-title", Static)
            title.update(
                f"[bold $primary]{entry.label}[/bold $primary]\n"
                f"[dim]{entry.path}[/dim]",
            )
        except Exception:
            pass

        try:
            viewer = self.query_one("#reports-preview", MarkdownViewer)
            if not entry.exists:
                await viewer.document.update(
                    f"# {entry.label}\n\n"
                    f"*This report was not generated for the current "
                    f"campaign.*\n\n"
                    f"Possible reasons:\n"
                    f"- the phase that produces it didn't complete\n"
                    f"- the corresponding feature was disabled in the "
                    f"scope\n"
                    f"- the deliverable was added in a newer version "
                    f"than the one that ran this campaign\n",
                )
            elif entry.renderable:
                try:
                    text = entry.path.read_text(encoding="utf-8")
                except Exception as exc:
                    text = f"*Failed to read report: {exc}*"
                await viewer.document.update(text)
            else:
                await viewer.document.update(
                    f"# {entry.label}\n\n"
                    f"This deliverable is not Markdown — preview is "
                    f"not available in the TUI.\n\n"
                    f"Press **`e`** to open it in the system handler "
                    f"({entry.path.suffix} files).\n",
                )
        except Exception:
            pass

        self._render_actions(entry)

    def _render_actions(self, entry: ReportEntry) -> None:
        try:
            body = self.query_one("#reports-actions-body", Static)
        except Exception:
            return
        lines: list[str] = []
        if entry.exists:
            lines.append(
                "[bold]m[/bold]  toggle reviewed mark"
                if not entry.reviewed
                else "[bold]m[/bold]  unmark reviewed",
            )
            if not entry.renderable:
                lines.append("[bold]e[/bold]  open in system handler")
            else:
                lines.append("[bold]e[/bold]  open externally")
        else:
            lines.append("[dim](report not generated)[/dim]")
        lines.append("")
        lines.append("[bold]Tab[/bold]  cycle panes")
        lines.append("[bold]Esc[/bold]  back")
        body.update("\n".join(lines))

    # ── Actions ─────────────────────────────────────────────────────

    def action_toggle_reviewed(self) -> None:
        # TUI-7: index resolves against the visible (filtered) list.
        if not (0 <= self._current_idx < len(self._visible_entries)):
            return
        entry = self._visible_entries[self._current_idx]
        new_state = mark_reviewed(entry.path)
        entry.reviewed = new_state
        # Re-populate the list so the icon updates. The entry's
        # ``reviewed`` flag was updated in-place above; since
        # ``_visible_entries`` holds the same object refs as
        # ``_entries`` (we slice, not deep-copy), the renderer
        # picks up the new state on next populate.
        self._populate_list()
        try:
            list_view = self.query_one("#reports-list", ListView)
            list_view.index = self._current_idx
        except Exception:
            pass
        self._render_actions(entry)

    def action_open_external(self) -> None:
        # TUI-7: index resolves against the visible (filtered) list.
        if not (0 <= self._current_idx < len(self._visible_entries)):
            return
        entry = self._visible_entries[self._current_idx]
        if not entry.exists:
            return
        try:
            from nexusrecon.tui.screens.results import _open_path
            _open_path(str(entry.path))
        except Exception:
            pass

    # ── TUI-7 filter actions ────────────────────────────────────────────

    def action_focus_filter(self) -> None:
        """``/`` — reveal + focus the filter Input."""
        try:
            inp = self.query_one("#reports-filter", Input)
        except Exception:
            return
        inp.remove_class("reports-filter-hidden")
        inp.focus()

    def action_clear_filter(self) -> None:
        """Esc while filtering — clear + hide + return focus
        to the report list."""
        try:
            inp = self.query_one("#reports-filter", Input)
        except Exception:
            return
        inp.value = ""
        inp.add_class("reports-filter-hidden")
        self._filter_text = ""
        try:
            self.query_one("#reports-list", ListView).focus()
        except Exception:
            pass
        self._populate_list()

    def on_input_changed(self, event: Input.Changed) -> None:
        """Live filter — repopulate the list on every keystroke.
        Tiny entry count (~20) so the cost is irrelevant."""
        if event.input.id != "reports-filter":
            return
        self._filter_text = (event.value or "").strip()
        self._populate_list()
        # Snap selection to the first row of the new filtered
        # set so the preview stays in sync.
        try:
            list_view = self.query_one("#reports-list", ListView)
            list_view.index = 0
        except Exception:
            pass

    def on_key(self, event) -> None:  # type: ignore[no-untyped-def]
        """Esc while filter Input focused → clear filter rather
        than triggering ``action_back``."""
        try:
            focused = self.focused
        except Exception:
            focused = None
        if (
            getattr(focused, "id", None) == "reports-filter"
            and event.key == "escape"
        ):
            event.stop()
            self.action_clear_filter()

    def action_focus_next_pane(self) -> None:
        try:
            focused = self.focused
            focused_id = focused.id if focused else None
            order = ("reports-list", "reports-preview", "reports-actions-body")
            if focused_id in order:
                next_id = order[(order.index(focused_id) + 1) % len(order)]
            else:
                next_id = order[0]
            self.query_one(f"#{next_id}").focus()
        except Exception:
            pass

    def action_back(self) -> None:
        try:
            self.app.pop_screen()
        except Exception:
            pass

    def action_quit_app(self) -> None:
        self.app.exit()


# ──────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────


def visible_reports(entries: Iterable[ReportEntry]) -> list[ReportEntry]:
    """Return only generated reports — convenience filter for
    operator workflows that want to skip the absent ones."""
    return [e for e in entries if e.exists]
