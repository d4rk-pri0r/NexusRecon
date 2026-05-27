"""Past Campaigns / Resume screen — list campaigns on disk.

TUI-7: gained the k9s-style ``/`` substring filter and a
selection-driven preview strip at the bottom. The preview
shows campaign metadata that would otherwise require pushing
the ResultsScreen — engagement / scope_hash / completed
phases / findings breakdown / cost / last modified — so the
operator can scan rows without committing to a full open.
``Enter`` still drills into the ResultsScreen as before.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical
from textual.screen import Screen
from textual.widgets import DataTable, Footer, Header, Input, Static

from nexusrecon.tui.widgets import StatusBar


class CampaignsScreen(Screen):
    """List of past campaigns. Enter on a row → results screen for it.

    TUI-7 additions:
      - ``/`` reveals a substring filter Input above the table;
        rebuilds the visible rows on every keystroke. ``Esc``
        clears + hides.
      - Bottom preview strip updates when the cursor moves to a
        new row, surfacing engagement / scope_hash / completed
        phases / findings / errors / last modified ── enough
        signal to triage without opening the full ResultsScreen.
    """

    BINDINGS = [
        Binding("slash", "focus_filter", "Filter"),
        Binding("escape", "back", "Back"),
        Binding("ctrl+q", "quit_app", "Quit"),
    ]

    def __init__(self, resume_mode: bool = False) -> None:
        super().__init__()
        self.resume_mode = resume_mode
        # Full set of campaigns discovered on disk, indexed by
        # the order they were appended. The table re-renders from
        # this list every time the filter changes so we don't
        # have to re-read state.json on every keystroke.
        self._campaigns: list[dict[str, Any]] = []
        # Substring filter — empty means "show everything".
        # Lowercased at set time for case-insensitive match.
        self._filter_text: str = ""

    def compose(self) -> ComposeResult:
        yield Header(show_clock=False)
        yield StatusBar()
        title = "Resume Campaign" if self.resume_mode else "Past Campaigns"
        yield Static(f"[bold #00ff9c]{title}[/bold #00ff9c]", classes="wizard-label")
        yield Static(id="campaigns-status")
        # Hidden filter Input — same pattern as the runner's filter
        # (TUI-6b). ``/`` reveals; Esc clears + hides.
        yield Input(
            placeholder="Filter campaigns (substring, case-insensitive)…",
            id="campaigns-filter",
            classes="campaigns-filter-hidden",
        )
        yield DataTable(id="campaigns-table", zebra_stripes=True)
        # Selection-driven preview strip. Rendered as a single
        # Static so the layout stays simple; the content includes
        # newlines so the preview can span 4-5 visual rows.
        with Vertical(id="campaigns-preview-wrap"):
            yield Static(
                "[dim]Cursor a row to see its summary here.[/dim]",
                id="campaigns-preview",
            )
        yield Footer()

    async def on_mount(self) -> None:
        table = self.query_one("#campaigns-table", DataTable)
        table.add_columns(
            "Campaign ID", "Client", "Engagement",
            "Phases", "Findings", "Status",
        )
        table.cursor_type = "row"

        try:
            from nexusrecon.core.config import get_config
            out_dir = Path(get_config().output_dir)
        except Exception:
            out_dir = Path("campaigns")

        if out_dir.exists():
            for state_file in out_dir.rglob("state.json"):
                try:
                    data = json.loads(state_file.read_text(encoding="utf-8"))
                    cid = data.get("campaign_id", state_file.parent.name)
                    eid = data.get("engagement_id", "?")
                    completed = data.get("completed_phases", [])
                    findings = len(data.get("findings", []))
                    errors = len(data.get("errors", []))
                    scope_meta = state_file.parent / "scope_metadata.json"
                    client = "?"
                    if scope_meta.exists():
                        try:
                            sm = json.loads(scope_meta.read_text(encoding="utf-8"))
                            client = sm.get("engagement", {}).get("client", "?")
                        except Exception:
                            pass
                    status = (
                        "ERROR" if errors
                        else ("DONE" if "phase9" in completed else "PARTIAL")
                    )
                    if self.resume_mode and status == "DONE":
                        continue
                    self._campaigns.append({
                        "campaign_id": cid,
                        "client": client,
                        "engagement_id": eid,
                        "campaign_dir": str(state_file.parent),
                        "state_file": str(state_file),
                        "state": data,
                        "completed_phases": completed,
                        "findings_count": findings,
                        "errors_count": errors,
                        "status": status,
                        "mtime": state_file.stat().st_mtime,
                    })
                except Exception:
                    continue

        self._rebuild_table()

    # ── Render ──────────────────────────────────────────────────────────

    def _filtered_campaigns(self) -> list[dict[str, Any]]:
        """Return the subset of ``_campaigns`` that match the
        active filter. Empty filter returns the full list.

        Match is substring against the joined campaign id,
        client, engagement id, and status fields — case-
        insensitive ── so an operator typing
        ``acme`` finds every campaign for that client without
        thinking about which column to target."""
        if not self._filter_text:
            return list(self._campaigns)
        needle = self._filter_text.lower()
        out: list[dict[str, Any]] = []
        for c in self._campaigns:
            haystack = " ".join((
                str(c.get("campaign_id", "")),
                str(c.get("client", "")),
                str(c.get("engagement_id", "")),
                str(c.get("status", "")),
            )).lower()
            if needle in haystack:
                out.append(c)
        return out

    def _rebuild_table(self) -> None:
        """Wipe + repopulate the DataTable from the filtered set.
        Updates the status counter to reflect the visible row
        count + the total."""
        try:
            table = self.query_one("#campaigns-table", DataTable)
        except Exception:
            return
        # Preserve the column definitions; clear only rows.
        table.clear()
        filtered = self._filtered_campaigns()
        for c in filtered:
            table.add_row(
                str(c["campaign_id"]), str(c["client"]),
                str(c["engagement_id"]),
                str(len(c["completed_phases"])),
                str(c["findings_count"]), str(c["status"]),
            )
        # Stash the filtered list so on_data_table_row_selected
        # resolves indices against THIS list, not the raw one.
        self._visible_campaigns = filtered
        self._update_status(len(filtered))
        # Refresh the preview to match whatever row is now under
        # the cursor.
        if filtered:
            self._render_preview(filtered[0])
        else:
            self._render_preview(None)

    def _update_status(self, visible_count: int) -> None:
        try:
            status_widget = self.query_one("#campaigns-status", Static)
        except Exception:
            return
        total = len(self._campaigns)
        if total == 0:
            status_widget.update("[dim]No campaigns on disk yet.[/dim]")
            return
        if self._filter_text:
            status_widget.update(
                f"[dim]{visible_count} of {total} matching "
                f"`{self._filter_text}` — Enter to open, "
                f"Esc to clear filter.[/dim]",
            )
        else:
            status_widget.update(
                f"[dim]{total} campaign(s) — / to filter, "
                f"Enter on a row to open.[/dim]",
            )

    def _render_preview(self, c: dict[str, Any] | None) -> None:
        """Update the bottom preview strip with the selected
        campaign's metadata."""
        try:
            widget = self.query_one("#campaigns-preview", Static)
        except Exception:
            return
        if c is None:
            widget.update(
                "[dim]No campaign selected.[/dim]",
            )
            return
        state = c.get("state") or {}
        scope_hash = state.get("scope_hash") or "?"
        seeds = state.get("seeds") or []
        completed = c.get("completed_phases") or []
        when = "?"
        try:
            when = datetime.fromtimestamp(
                c["mtime"], tz=timezone.utc,
            ).strftime("%Y-%m-%d %H:%M UTC")
        except Exception:
            pass
        # Findings breakdown by severity (when available).
        findings = state.get("findings") or []
        sev_counts: dict[str, int] = {}
        for f in findings:
            sev = (f.get("severity") or "info").lower()
            sev_counts[sev] = sev_counts.get(sev, 0) + 1
        sev_str = " · ".join(
            f"{name.upper()}: {sev_counts[name]}"
            for name in ("critical", "high", "medium", "low", "info")
            if sev_counts.get(name)
        ) or "[dim]none[/dim]"

        lines = [
            f"[bold $primary]{c['campaign_id']}[/bold $primary]   "
            f"[dim]({c['status']})[/dim]",
            f"  [dim]Engagement:[/dim] {c['engagement_id']}   "
            f"[dim]Client:[/dim] {c['client']}",
            f"  [dim]Seeds:[/dim] {', '.join(seeds[:3]) or '?'}"
            f"{' …' if len(seeds) > 3 else ''}",
            f"  [dim]Phases:[/dim] {len(completed)} / 10   "
            f"[dim]Findings:[/dim] {sev_str}",
            f"  [dim]Scope hash:[/dim] {scope_hash[:24]}…   "
            f"[dim]Last modified:[/dim] {when}",
        ]
        widget.update("\n".join(lines))

    # ── Events ──────────────────────────────────────────────────────────

    async def on_data_table_row_selected(
        self, event: DataTable.RowSelected,
    ) -> None:
        # Resolve which campaign row was selected (against the
        # FILTERED list, not the raw one).
        idx = event.cursor_row
        visible = getattr(self, "_visible_campaigns", self._campaigns)
        if idx is None or idx >= len(visible):
            return
        camp = visible[idx]
        from nexusrecon.tui.screens.results import ResultsScreen
        await self.app.push_screen(ResultsScreen(
            campaign_dir=camp["campaign_dir"],
            state=camp["state"],
        ))

    def on_data_table_row_highlighted(
        self, event: DataTable.RowHighlighted,
    ) -> None:
        """Cursor moved → refresh the preview strip for the new
        row. Cheap (one Static.update) so it fires per keystroke
        without lag."""
        idx = event.cursor_row
        visible = getattr(self, "_visible_campaigns", self._campaigns)
        if idx is None or idx < 0 or idx >= len(visible):
            return
        self._render_preview(visible[idx])

    def on_input_changed(self, event: Input.Changed) -> None:
        """Live filter — rebuild the table on every keystroke.
        O(n) over the campaign list is fast even with hundreds
        of campaigns on disk."""
        if event.input.id != "campaigns-filter":
            return
        self._filter_text = (event.value or "").strip()
        self._rebuild_table()

    def on_key(self, event: Any) -> None:
        """Esc while filter Input focused → clear filter rather
        than triggering ``action_back`` (which would pop the
        screen)."""
        try:
            focused = self.focused
        except Exception:
            focused = None
        if (
            getattr(focused, "id", None) == "campaigns-filter"
            and event.key == "escape"
        ):
            event.stop()
            self.action_clear_filter()

    # ── Actions ─────────────────────────────────────────────────────────

    def action_focus_filter(self) -> None:
        """``/`` — reveal + focus the filter Input."""
        try:
            inp = self.query_one("#campaigns-filter", Input)
        except Exception:
            return
        inp.remove_class("campaigns-filter-hidden")
        inp.focus()

    def action_clear_filter(self) -> None:
        """Esc while filtering — clear + hide + return focus to
        the campaigns table."""
        try:
            inp = self.query_one("#campaigns-filter", Input)
        except Exception:
            return
        inp.value = ""
        inp.add_class("campaigns-filter-hidden")
        self._filter_text = ""
        try:
            self.query_one("#campaigns-table", DataTable).focus()
        except Exception:
            pass
        self._rebuild_table()

    def action_back(self) -> None:
        self.app.pop_screen()

    def action_quit_app(self) -> None:
        self.app.exit()
