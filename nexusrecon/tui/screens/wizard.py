"""Multi-step new-campaign wizard.

TUI-4 additions:
  - Sticky right-side summary pane that updates as the operator
    advances through the steps.
  - Scope-file preset library on Step 2 (a Select that prefills
    constraints/run options from a named template).
  - Cost-preview gauge on Step 5 ── operator sees what they're
    about to spend before pressing Save & Run.

The original 5-step flow and validation surface are preserved; the
helpers live in :mod:`nexusrecon.tui.wizard_helpers` so they stay
pure-Python unit-testable.
"""
from __future__ import annotations

import datetime as _dt
import re
import tempfile
from pathlib import Path
from typing import Any

import yaml
from textual.app import ComposeResult
from textual.containers import Container, Horizontal, Vertical, VerticalScroll
from textual.screen import Screen
from textual.widgets import Button, Footer, Header, Input, Select, Static, Switch

from nexusrecon.tui.widgets import StatusBar
from nexusrecon.tui.wizard_helpers import (
    apply_preset,
    estimate_campaign_cost,
    load_presets,
    preset_by_id,
    render_summary,
)

_DOMAIN_RE = re.compile(r"^([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}$")
_HEX64_RE = re.compile(r"^[0-9a-fA-F]{64}$")

_DEFAULT_OOS_WILDCARDS = [
    "*.aws.amazon.com",
    "*.cloudfront.net",
    "*.azure.com",
    "*.cloudflare.com",
    "*.fastly.net",
    "*.akamai.net",
    "*.azurewebsites.net",
]


def _today() -> str:
    return _dt.date.today().isoformat()


def _today_plus(days: int) -> str:
    return (_dt.date.today() + _dt.timedelta(days=days)).isoformat()


def _valid_date(s: str) -> bool:
    try:
        _dt.date.fromisoformat(s.strip())
        return True
    except Exception:
        return False


class WizardScreen(Screen):
    """5-step new-campaign wizard."""

    # Keyboard-first: Esc steps back (from step 2+) or cancels (from step 1).
    # Ctrl-N advances. Ctrl-S on step 5 saves the scope without running.
    # All shortcuts surface in the Footer auto-rendered by Textual.
    BINDINGS = [
        ("escape", "back_or_cancel", "Back / Cancel"),
        ("ctrl+n", "next", "Next →"),
        ("ctrl+s", "save_only", "Save scope only"),
        ("ctrl+q", "quit_app", "Quit"),
    ]

    def __init__(self) -> None:
        super().__init__()
        self.step: int = 1
        self.data: dict[str, Any] = {
            # Step 1
            "client": "",
            "engagement_id": "",
            "authorized_by": "",
            "authorization_date": _today(),
            "start_date": _today(),
            "end_date": _today_plus(30),
            "sow_hash": "",
            # Step 2
            "seed_domain": "",
            "additional_domains": "",
            "out_of_scope": ", ".join(_DEFAULT_OOS_WILDCARDS),
            # Step 3
            "max_tier": "T2",
            "stealth": "high",
            "max_cost_usd": "20.0",
            "allow_breach": True,
            "allow_paid": True,
            # Step 4
            "mode": "medium",
            "dispatch_mode": "lite",
            "validate_creds": False,
            "generate_phishing": False,
        }
        self._error: str = ""

    def compose(self) -> ComposeResult:
        yield Header(show_clock=False)
        # TUI-3: persistent status bar on every screen.
        yield StatusBar()
        # TUI-4: the wizard now has a two-pane main area — the form
        # body on the left, a sticky summary pane on the right that
        # reflects what's been entered so far.
        with Container(id="wizard-content"):
            with Horizontal(id="wizard-layout"):
                with Vertical(id="wizard-stack"):
                    yield Static(id="wizard-title")
                    yield VerticalScroll(id="wizard-body")
                    with Horizontal(classes="wizard-nav"):
                        yield Button("Back", id="btn-back")
                        yield Button("Next", id="btn-next", classes="-primary")
                        yield Button("Cancel", id="btn-cancel")
                with Vertical(id="wizard-summary-pane"):
                    yield Static(
                        "[bold $primary]Summary[/bold $primary]",
                        id="wizard-summary-title",
                    )
                    yield Static(id="wizard-summary-body")
                    yield Static(id="wizard-summary-cost")
        yield Footer()

    async def on_mount(self) -> None:
        await self._render_step()

    async def _render_step(self) -> None:
        title = self.query_one("#wizard-title", Static)
        body = self.query_one("#wizard-body", VerticalScroll)
        await body.remove_children()
        title.update(f"  [bold #00ff9c]Step {self.step}/5[/bold #00ff9c] · "
                     + ["Engagement metadata", "Target & scope", "Constraints",
                        "Run options", "Review"][self.step - 1])

        next_btn = self.query_one("#btn-next", Button)
        back_btn = self.query_one("#btn-back", Button)
        back_btn.disabled = self.step == 1

        if self.step == 1:
            await self._render_step1(body)
            next_btn.label = "Next"
        elif self.step == 2:
            await self._render_step2(body)
            next_btn.label = "Next"
        elif self.step == 3:
            await self._render_step3(body)
            next_btn.label = "Next"
        elif self.step == 4:
            await self._render_step4(body)
            next_btn.label = "Next"
        else:
            await self._render_step5(body)
            next_btn.label = "Save & Run"

        if self._error:
            await body.mount(Static(f"⚠ {self._error}", classes="wizard-error"))

        # Refresh the sticky summary pane on every step transition so
        # the operator can verify accumulated state without scrolling
        # back through previous steps.
        self._refresh_summary()

        # Auto-focus the first focusable widget in the body so keyboard users
        # don't have to Tab in from the Header on every step. Falls back to
        # the Next button on the Review step (which has no input fields).
        try:
            for child in body.query("Input, Select, Switch"):
                child.focus()
                break
            else:
                self.query_one("#btn-next", Button).focus()
        except Exception:
            pass

    def _refresh_summary(self) -> None:
        """Re-render the sticky summary pane + cost preview.

        Called after every step transition and after preset
        application. Cost preview only renders on Step 5 ── it's
        the most useful right before the operator commits.
        """
        try:
            self.query_one("#wizard-summary-body", Static).update(
                render_summary(self.data),
            )
        except Exception:
            pass
        # Cost preview only renders on the review step.
        try:
            cost_widget = self.query_one("#wizard-summary-cost", Static)
            if self.step == 5:
                seeds = 1 if self.data.get("seed_domain", "").strip() else 0
                additional = sum(
                    1 for d in (self.data.get("additional_domains") or "").split(",")
                    if d.strip()
                )
                try:
                    budget = float(self.data.get("max_cost_usd", "0") or "0")
                except Exception:
                    budget = 0.0
                preview = estimate_campaign_cost(
                    mode=self.data.get("mode", "medium"),
                    dispatch_mode=self.data.get("dispatch_mode", "lite"),
                    max_tier=self.data.get("max_tier", "T2"),
                    stealth=self.data.get("stealth", "high"),
                    seed_count=seeds,
                    additional_count=additional,
                    generate_phishing=bool(self.data.get("generate_phishing")),
                )
                # Render a compact cost block.
                budget_warn = ""
                if budget > 0 and not preview.fits_budget(budget):
                    budget_warn = (
                        "  [$warning]⚠ upper estimate exceeds budget"
                        "[/$warning]"
                    )
                cost_widget.update(
                    f"\n[bold $primary]Cost preview[/bold $primary]\n"
                    f"  [dim]Low:[/dim]  ${preview.low_usd:.2f}\n"
                    f"  [dim]Mid:[/dim]  ${preview.mid_usd:.2f}\n"
                    f"  [dim]High:[/dim] ${preview.high_usd:.2f}"
                    f"{budget_warn}\n"
                    f"  [dim]{preview.rationale}[/dim]",
                )
            else:
                cost_widget.update("")
        except Exception:
            pass

    async def _render_step1(self, body) -> None:
        d = self.data
        await body.mount_all([
            Static("Client name", classes="wizard-label"),
            Input(value=d["client"], placeholder="Acme Corp", id="f-client"),
            Static("Engagement ID", classes="wizard-label"),
            Static("(no spaces recommended)", classes="wizard-help"),
            Input(value=d["engagement_id"], placeholder="ACM-2026-Q2-RT01", id="f-engagement_id"),
            Static("Authorized by", classes="wizard-label"),
            Input(value=d["authorized_by"], placeholder="Jane Smith, CISO", id="f-authorized_by"),
            Static("Authorization date (YYYY-MM-DD)", classes="wizard-label"),
            Input(value=d["authorization_date"], id="f-authorization_date"),
            Static("Start date (YYYY-MM-DD)", classes="wizard-label"),
            Input(value=d["start_date"], id="f-start_date"),
            Static("End date (YYYY-MM-DD)", classes="wizard-label"),
            Input(value=d["end_date"], id="f-end_date"),
            Static("Signed SOW SHA-256 hash", classes="wizard-label"),
            Static("(64 hex chars, or 'placeholder' for testing)", classes="wizard-help"),
            Input(value=d["sow_hash"], placeholder="placeholder", id="f-sow_hash"),
        ])

    async def _render_step2(self, body) -> None:
        d = self.data
        # TUI-4: scope-file preset library — pick a named preset to
        # prefill the form (operator can still edit before continuing).
        presets = load_presets()
        preset_options: list[tuple[str, str]] = [
            (f"{p.name}  ({p.id})", p.id) for p in presets
        ]
        await body.mount_all([
            Static("Load scope preset (optional)", classes="wizard-label"),
            Static(
                "Built-in templates for common engagement shapes. "
                "User presets in ~/.nexusrecon/scope-presets/ override "
                "built-ins by id.",
                classes="wizard-help",
            ),
            Select(
                preset_options,
                prompt="— choose a preset —",
                allow_blank=True,
                id="f-preset",
            ),
            Static("Seed domain *", classes="wizard-label"),
            Input(value=d["seed_domain"], placeholder="example.com", id="f-seed_domain"),
            Static("Additional in-scope domains (comma-separated)", classes="wizard-label"),
            Input(value=d["additional_domains"], id="f-additional_domains"),
            Static("Out-of-scope wildcards (comma-separated)", classes="wizard-label"),
            Input(value=d["out_of_scope"], id="f-out_of_scope"),
        ])

    async def _render_step3(self, body) -> None:
        d = self.data
        await body.mount_all([
            Static("Max tier", classes="wizard-label"),
            Static(
                "T0 passive only · T1 light fingerprinting · "
                "T2 active scanning · T3 intrusive (rarely authorized)",
                classes="wizard-help",
            ),
            Select.from_values(
                ["T0", "T1", "T2", "T3"],
                value=d["max_tier"], id="f-max_tier",
            ),
            Static("Stealth profile", classes="wizard-label"),
            Static(
                "paranoid 1 thread / long delays · high 3 threads / proxy · "
                "normal 10 threads · loud no throttling",
                classes="wizard-help",
            ),
            Select.from_values(
                ["paranoid", "high", "normal", "loud"],
                value=d["stealth"], id="f-stealth",
            ),
            Static("Max LLM cost (USD)", classes="wizard-label"),
            Input(value=d["max_cost_usd"], id="f-max_cost_usd"),
            Static("Allow breach DB lookup", classes="wizard-label"),
            Switch(value=d["allow_breach"], id="f-allow_breach"),
            Static("Allow paid APIs", classes="wizard-label"),
            Switch(value=d["allow_paid"], id="f-allow_paid"),
        ])

    async def _render_step4(self, body) -> None:
        d = self.data
        await body.mount_all([
            Static("Mode", classes="wizard-label"),
            Static(
                "light=fast/cheap · medium=balanced · deep=thorough · monitor=watch over time",
                classes="wizard-help",
            ),
            Select.from_values(
                ["light", "medium", "deep", "monitor"],
                value=d["mode"], id="f-mode",
            ),
            Static("Dispatch mode", classes="wizard-label"),
            Static(
                "lite=after phases 1/4/7 · full=after every phase · off=disabled",
                classes="wizard-help",
            ),
            Select.from_values(
                ["lite", "full", "off"],
                value=d["dispatch_mode"], id="f-dispatch_mode",
            ),
            Static("Validate harvested credentials", classes="wizard-label"),
            Static(
                "Read-only API validation (AWS sts, GitHub /user). "
                "OPSEC-sensitive — only enable on authorized engagements.",
                classes="wizard-help",
            ),
            Switch(value=d["validate_creds"], id="f-validate_creds"),
            Static("Generate phishing drafts", classes="wizard-label"),
            Static(
                "Per-target spearphishing email drafts. Authorized engagements only.",
                classes="wizard-help",
            ),
            Switch(value=d["generate_phishing"], id="f-generate_phishing"),
        ])

    async def _render_step5(self, body) -> None:
        d = self.data
        sow = d["sow_hash"].strip() or "(none)"
        if sow.lower() == "placeholder":
            sow_display = "placeholder (will be expanded to 64 zeros)"
        else:
            sow_display = sow[:20] + ("…" if len(sow) > 20 else "")
        rows = [
            ("Client", d["client"]),
            ("Engagement", d["engagement_id"]),
            ("Authorized by", d["authorized_by"]),
            ("Auth date", d["authorization_date"]),
            ("Period", f"{d['start_date']} → {d['end_date']}"),
            ("SOW hash", sow_display),
            ("Seed domain", d["seed_domain"]),
            ("Additional", d["additional_domains"] or "(none)"),
            ("Out-of-scope", d["out_of_scope"][:60] + "…"),
            ("Max tier", d["max_tier"]),
            ("Stealth", d["stealth"]),
            ("Max LLM cost", f"${d['max_cost_usd']}"),
            ("Mode", d["mode"]),
            ("Dispatch", d["dispatch_mode"]),
            ("Validate creds", "yes" if d["validate_creds"] else "no"),
            ("Phishing drafts", "yes" if d["generate_phishing"] else "no"),
        ]
        body_lines = ["[bold #00ff9c]Review your selections[/bold #00ff9c]\n"]
        for k, v in rows:
            body_lines.append(f"  [bold]{k:<18}[/bold] {v}")
        warnings: list[str] = []
        if d["max_tier"] == "T3":
            warnings.append("T3 tier selected — make sure your SOW authorizes intrusive testing.")
        if d["generate_phishing"]:
            warnings.append("Phishing draft generation enabled — drafts will be written but not sent.")
        if warnings:
            body_lines.append("")
            body_lines.append("[bold #f1c40f]Warnings:[/bold #f1c40f]")
            for w in warnings:
                body_lines.append(f"  • {w}")
        await body.mount(Static("\n".join(body_lines)))

    # ── Validation per step ────────────────────────────────────────────────

    def _collect_step(self) -> None:
        """Read current widget values into self.data."""
        if self.step == 1:
            for k in (
                "client", "engagement_id", "authorized_by",
                "authorization_date", "start_date", "end_date", "sow_hash",
            ):
                try:
                    self.data[k] = self.query_one(f"#f-{k}", Input).value
                except Exception:
                    pass
        elif self.step == 2:
            for k in ("seed_domain", "additional_domains", "out_of_scope"):
                try:
                    self.data[k] = self.query_one(f"#f-{k}", Input).value
                except Exception:
                    pass
        elif self.step == 3:
            for k in ("max_tier", "stealth"):
                try:
                    self.data[k] = self.query_one(f"#f-{k}", Select).value
                except Exception:
                    pass
            for k in ("max_cost_usd",):
                try:
                    self.data[k] = self.query_one(f"#f-{k}", Input).value
                except Exception:
                    pass
            for k in ("allow_breach", "allow_paid"):
                try:
                    self.data[k] = self.query_one(f"#f-{k}", Switch).value
                except Exception:
                    pass
        elif self.step == 4:
            for k in ("mode", "dispatch_mode"):
                try:
                    self.data[k] = self.query_one(f"#f-{k}", Select).value
                except Exception:
                    pass
            for k in ("validate_creds", "generate_phishing"):
                try:
                    self.data[k] = self.query_one(f"#f-{k}", Switch).value
                except Exception:
                    pass

    def _validate_step(self) -> str | None:
        d = self.data
        if self.step == 1:
            if not d["client"].strip():
                return "Client name is required."
            if not d["engagement_id"].strip():
                return "Engagement ID is required."
            if not d["authorized_by"].strip():
                return "Authorized-by is required."
            for k, label in [
                ("authorization_date", "Authorization date"),
                ("start_date", "Start date"),
                ("end_date", "End date"),
            ]:
                if not _valid_date(d[k]):
                    return f"{label} must be YYYY-MM-DD."
            sow = d["sow_hash"].strip()
            if sow and sow.lower() != "placeholder" and not _HEX64_RE.match(sow):
                return "SOW hash must be 64 hex chars or 'placeholder'."
        elif self.step == 2:
            seed = d["seed_domain"].strip().lower()
            if not seed:
                return "Seed domain is required."
            if not _DOMAIN_RE.match(seed):
                return f"Seed domain {seed!r} does not look like a valid domain."
        elif self.step == 3:
            try:
                cost = float(d["max_cost_usd"])
                if cost <= 0:
                    return "Max LLM cost must be positive."
            except ValueError:
                return "Max LLM cost must be a number."
        return None

    # ── Navigation ─────────────────────────────────────────────────────────

    async def on_button_pressed(self, event: Button.Pressed) -> None:
        """Mouse dispatcher — delegates to the action methods so keyboard
        shortcuts and button clicks share one code path."""
        bid = event.button.id or ""
        if bid == "btn-cancel":
            self.action_cancel()
        elif bid == "btn-back":
            await self.action_back()
        elif bid == "btn-next":
            await self.action_next()

    async def on_select_changed(self, event: Select.Changed) -> None:
        """Preset Select dropdown on Step 2: apply the chosen preset
        to ``self.data`` and re-render the step so the form picks up
        the new constraints/run-options."""
        try:
            if event.select.id != "f-preset":
                return
            if event.value is Select.BLANK:
                return
            preset = preset_by_id(str(event.value))
            if preset is None:
                return
            # Snapshot the current step's free-text inputs (seed
            # domain, additional, out-of-scope) so they survive the
            # rerender. The preset doesn't touch them.
            self._collect_step()
            apply_preset(self.data, preset)
            await self._render_step()
        except Exception:
            pass

    async def action_back(self) -> None:
        """Step backward one screen. No-op on step 1 (handled by
        back_or_cancel for Esc users)."""
        self._collect_step()
        self._error = ""
        if self.step > 1:
            self.step -= 1
            await self._render_step()

    async def action_back_or_cancel(self) -> None:
        """Smart Esc: back one step from 2+, cancel out from step 1.

        Matches operator expectations from other wizards where Esc means
        "undo my last navigation action" rather than always exiting.
        """
        if self.step > 1:
            await self.action_back()
        else:
            self.action_cancel()

    async def action_next(self) -> None:
        """Advance one step (or launch the campaign from step 5)."""
        self._collect_step()
        err = self._validate_step()
        if err:
            self._error = err
            await self._render_step()
            return
        self._error = ""
        if self.step < 5:
            self.step += 1
            await self._render_step()
        else:
            await self._launch_campaign()

    async def action_save_only(self) -> None:
        """Step 5 only: save the scope yaml without running a campaign.

        Falls through to action_next on other steps so the binding is
        always safe to press.
        """
        if self.step != 5:
            await self.action_next()
            return
        # Validate first so we don't write garbage scopes
        self._collect_step()
        err = self._validate_step()
        if err:
            self._error = err
            await self._render_step()
            return
        # Save to ~/nexusrecon-scope-<engagement_id>.yaml and return to menu
        await self._save_scope_only()

    async def _launch_campaign(self) -> None:
        """Write a scope yaml to a temp file, then push the runner screen."""
        d = self.data
        scope_yaml = self._build_scope_yaml()

        tmp = tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False, prefix="nexusrecon-tui-",
        )
        yaml.safe_dump(scope_yaml, tmp, sort_keys=False)
        tmp.close()
        scope_path = Path(tmp.name)

        from nexusrecon.tui.screens.runner import RunnerScreen
        await self.app.push_screen(RunnerScreen(
            scope_path=str(scope_path),
            mode=d["mode"],
            dispatch_mode=d["dispatch_mode"],
            validate_creds=bool(d["validate_creds"]),
            generate_phishing=bool(d["generate_phishing"]),
        ))

    def action_cancel(self) -> None:
        self.app.pop_screen()

    def action_quit_app(self) -> None:
        self.app.exit()

    async def _save_scope_only(self) -> None:
        """Save the assembled scope YAML to the operator's home directory
        without launching a campaign. Triggered by Ctrl-S on step 5."""
        scope_yaml = self._build_scope_yaml()
        eid = self.data.get("engagement_id", "scope") or "scope"
        # Sanitize engagement_id for filesystem use
        safe_eid = "".join(ch if ch.isalnum() or ch in "-_." else "_" for ch in eid)
        out_path = Path.home() / f"nexusrecon-scope-{safe_eid}.yaml"
        out_path.write_text(yaml.safe_dump(scope_yaml, sort_keys=False), encoding="utf-8")
        # Surface success then return to main menu
        body = self.query_one("#wizard-body", VerticalScroll)
        await body.remove_children()
        await body.mount(Static(
            f"[bold #00ff9c]Scope saved:[/bold #00ff9c]\n  {out_path}\n\n"
            f"[dim]Run with:[/dim]  nexusrecon run --scope {out_path}\n\n"
            f"[dim]Esc to return to the main menu.[/dim]",
            classes="wizard-label",
        ))

    def _build_scope_yaml(self) -> dict[str, Any]:
        """Shared YAML construction used by both _launch_campaign and
        _save_scope_only. Identical structure so the two paths can't drift."""
        d = self.data
        sow = d["sow_hash"].strip()
        if not sow or sow.lower() == "placeholder":
            sow_value = "sha256:" + ("0" * 64)
        elif sow.startswith("sha256:"):
            sow_value = sow
        else:
            sow_value = "sha256:" + sow.lower()

        in_scope_domains = [d["seed_domain"].strip().lower()]
        for extra in d["additional_domains"].split(","):
            extra = extra.strip().lower()
            if extra:
                in_scope_domains.append(extra)
        out_of_scope_list = [s.strip() for s in d["out_of_scope"].split(",") if s.strip()]

        return {
            "engagement": {
                "client": d["client"],
                "engagement_id": d["engagement_id"],
                "authorized_by": d["authorized_by"],
                "authorization_date": d["authorization_date"],
                "start_date": d["start_date"],
                "end_date": d["end_date"],
                "signed_sow_hash": sow_value,
            },
            "scope": {
                "in_scope": {"domains": in_scope_domains},
                "out_of_scope": {"domains": out_of_scope_list} if out_of_scope_list else {},
            },
            "constraints": {
                "max_tier": d["max_tier"],
                "stealth_profile": d["stealth"],
                "max_llm_cost_usd": float(d["max_cost_usd"]),
                "allow_breach_db_lookup": bool(d["allow_breach"]),
                "allow_paid_apis": bool(d["allow_paid"]),
            },
        }
