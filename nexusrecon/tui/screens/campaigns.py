"""Past Campaigns / Resume screen — list campaigns on disk."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from textual.app import ComposeResult
from textual.screen import Screen
from textual.widgets import DataTable, Footer, Header, Static

from nexusrecon.tui.widgets import StatusBar


class CampaignsScreen(Screen):
    """List of past campaigns. Enter on a row → results screen for it."""

    BINDINGS = [
        ("escape", "back", "Back"),
        ("ctrl+q", "quit_app", "Quit"),
    ]

    def __init__(self, resume_mode: bool = False) -> None:
        super().__init__()
        self.resume_mode = resume_mode
        self._campaigns: list[dict[str, Any]] = []

    def compose(self) -> ComposeResult:
        yield Header(show_clock=False)
        yield StatusBar()
        title = "Resume Campaign" if self.resume_mode else "Past Campaigns"
        yield Static(f"[bold #00ff9c]{title}[/bold #00ff9c]", classes="wizard-label")
        yield Static(id="campaigns-status")
        yield DataTable(id="campaigns-table", zebra_stripes=True)
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

        rows = 0
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
                    status = "ERROR" if errors else ("DONE" if "phase9" in completed else "PARTIAL")
                    if self.resume_mode and status == "DONE":
                        continue
                    table.add_row(
                        cid, client, eid,
                        str(len(completed)), str(findings), status,
                    )
                    self._campaigns.append({
                        "campaign_id": cid,
                        "campaign_dir": str(state_file.parent),
                        "state": data,
                    })
                    rows += 1
                except Exception:
                    continue

        try:
            status_widget = self.query_one("#campaigns-status", Static)
            if rows == 0:
                status_widget.update("[dim]No campaigns on disk yet.[/dim]")
            else:
                status_widget.update(f"[dim]{rows} campaign(s) — Enter on a row to view reports.[/dim]")
        except Exception:
            pass

    async def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        # Resolve which campaign row was selected
        idx = event.cursor_row
        if idx is None or idx >= len(self._campaigns):
            return
        camp = self._campaigns[idx]
        from nexusrecon.tui.screens.results import ResultsScreen
        await self.app.push_screen(ResultsScreen(
            campaign_dir=camp["campaign_dir"],
            state=camp["state"],
        ))

    def action_back(self) -> None:
        self.app.pop_screen()

    def action_quit_app(self) -> None:
        self.app.exit()
