"""NexusRecon CLI — Typer-based command interface."""
from __future__ import annotations

import asyncio
import json
import logging
import os
import sys
from pathlib import Path

import structlog
import typer
import yaml
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from nexusrecon.core.campaign import CampaignManager
from nexusrecon.core.config import get_config
from nexusrecon.core.scope import (
    ScopeGuard,
    ScopeModel,
    preflight_check,
)
from nexusrecon.models.campaign import CampaignMode
from nexusrecon.reports.engine import ReportEngine


def _check_runtime_env() -> None:
    """Fail fast if the runtime environment is obviously broken."""
    if sys.version_info < (3, 11) or sys.version_info >= (3, 14):
        sys.stderr.write(
            f"\n[ERROR] NexusRecon requires Python 3.11–3.13. "
            f"Detected: {sys.version_info.major}.{sys.version_info.minor}.\n"
            f"Install Python 3.13 and re-run inside its venv.\n\n"
        )
        sys.exit(1)
    # Soft warning when not running inside any venv.
    # Uses reliable stdlib signals instead of a path-string heuristic:
    #   - sys.real_prefix  set by legacy virtualenv
    #   - sys.prefix != sys.base_prefix  set by the stdlib venv module
    #   - VIRTUAL_ENV env var  set by every venv/virtualenv activate script
    _in_venv = (
        hasattr(sys, "real_prefix")
        or sys.prefix != sys.base_prefix
        or os.environ.get("VIRTUAL_ENV")
    )
    if not _in_venv:
        sys.stderr.write(
            "[WARN] nexusrecon may not be running inside a venv. "
            "If commands fail unexpectedly, run: source venv/bin/activate\n"
        )


_check_runtime_env()


def _warn_empty_env_keys() -> None:
    """Warn about API key env vars set to empty string that silently beat .env values.

    pydantic-settings precedence is ``env > .env > default``.  An empty-string
    env var wins over a populated ``.env`` entry.  This causes callers that do
    ``if get_secret(...):`` to fall through to degraded mode (e.g. MockLLM)
    with no diagnostic.  This function detects the trap and emits a clear warning.
    """
    _KEY_VARS = [
        "ANTHROPIC_API_KEY", "OPENAI_API_KEY",
        "SHODAN_API_KEY", "CENSYS_API_ID", "CENSYS_API_SECRET",
        "VIRUSTOTAL_API_KEY", "GREYNOISE_API_KEY", "BINARYEDGE_API_KEY",
        "FULLHUNT_API_KEY", "ABUSEIPDB_API_KEY", "URLSCAN_API_KEY",
        "SECURITYTRAILS_API_KEY", "HUNTER_API_KEY", "HAVEIBEENPWNED_API_KEY",
        "DEHASHED_API_KEY", "INTELX_API_KEY", "EMAILREP_API_KEY",
        "NEWSAPI_API_KEY", "ADZUNA_API_KEY", "GITHUB_TOKEN", "GITLAB_TOKEN",
        "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY",
    ]
    # Parse .env values once (best-effort — if the file is missing that's fine)
    _dot_env: dict = {}
    _env_file = Path(".env")
    if _env_file.exists():
        for _line in _env_file.read_text(encoding="utf-8").splitlines():
            _line = _line.strip()
            if _line and not _line.startswith("#") and "=" in _line:
                _k, _, _v = _line.partition("=")
                _dot_env[_k.strip()] = _v.strip().strip('"').strip("'")

    for _key in _KEY_VARS:
        if os.environ.get(_key, None) == "":  # set but empty — only catches the trap case
            _dot_val = _dot_env.get(_key, "")
            if _dot_val:
                sys.stderr.write(
                    f"[WARN] {_key} is set to empty string in the shell environment.\n"
                    f"       This overrides the non-empty value in .env "
                    f"(pydantic-settings precedence: env > .env > default).\n"
                    f"       To use the .env value, run:  unset {_key}\n"
                )


_warn_empty_env_keys()

app = typer.Typer(
    name="nexusrecon",
    help="Agentic OSINT Orchestration Framework — Authorized use only.",
    add_completion=False,
    rich_markup_mode="rich",
    invoke_without_command=True,
)
console = Console()


# V3 Move 1: invoking `nexusrecon` with no subcommand launches the TUI
# when stdin/stdout are TTYs. Non-TTY environments (CI, pipes) get a
# clear fallback message and the CLI help text.
@app.callback(invoke_without_command=True)
def _default_command(ctx: typer.Context) -> None:
    if ctx.invoked_subcommand is not None:
        return
    if sys.stdin.isatty() and sys.stdout.isatty():
        # Import lazily so CLI users without textual aren't penalized
        from nexusrecon.tui.app import run_tui
        run_tui()
        raise typer.Exit(0)
    sys.stderr.write(
        "[info] No TTY detected — falling back to CLI. "
        "Use 'nexusrecon run --help' for options.\n"
    )
    console.print(ctx.get_help())
    raise typer.Exit(0)


def setup_logging(level: str = "WARNING") -> None:
    """
    Configure structlog to write to stderr at the requested level.

    Logs go to stderr so they never mix with Rich table/panel output on stdout.
    Call this once at CLI startup before any tool imports trigger registration messages.
    """
    log_level = getattr(logging, level.upper(), logging.WARNING)

    structlog.configure(
        wrapper_class=structlog.make_filtering_bound_logger(log_level),
        logger_factory=structlog.PrintLoggerFactory(file=sys.stderr),
        processors=[
            structlog.stdlib.add_log_level,
            structlog.dev.ConsoleRenderer(colors=False),
        ],
    )


# Configure logging before any tool modules are imported (which triggers @register_tool
# and fires INFO-level "Registered tool" messages that would otherwise pollute stdout).
setup_logging(get_config().log_level)


@app.command()
def run(
    scope: str = typer.Option(..., "--scope", "-s", help="Path to engagement scope YAML file"),
    seeds: str | None = typer.Option(None, "--seeds", help="Comma-separated initial targets"),
    mode: str = typer.Option("medium", "--mode", "-m", help="Campaign mode: light, medium, deep, monitor"),
    resume: str | None = typer.Option(None, "--resume", "-r", help="Resume a campaign by ID"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Validate scope and plan without running tools"),
    use_graph: bool = typer.Option(False, "--use-graph", help="Use LangGraph workflow engine"),
    validate_creds: bool = typer.Option(False, "--validate-creds", help="Validate harvested credentials via read-only API calls (AWS sts, GitHub /user, etc.). Off by default."),
    generate_phishing: bool = typer.Option(False, "--generate-phishing", help="Generate per-target phishing email drafts. Authorized engagements only."),
    dispatch_mode: str = typer.Option("lite", "--dispatch-mode", help="Dynamic dispatch mode: lite (default), full, or off."),
    plan_only: bool = typer.Option(
        False, "--plan-only",
        help=(
            "Phase 1 PR B: invoke the CampaignPlannerAgent and print "
            "the resulting Strategy, then exit without running any "
            "tools. Use this to preview what a planner-driven "
            "campaign would do before committing to LLM/tool spend."
        ),
    ),
    pretext_targets: str | None = typer.Option(None, "--pretext-targets", help="Comma-separated identity IDs to score pretexts for (Phase 7.7). Default: all identities."),
    obsidian: bool = typer.Option(
        False, "--obsidian",
        help=(
            "Also emit master_report.obsidian.md — same content as "
            "master_report.md but with YAML frontmatter, [[wikilink]] "
            "cross-references, and Obsidian callouts. Drop the campaign "
            "directory into a vault to read."
        ),
    ),
) -> None:
    """
    Launch a NexusRecon reconnaissance campaign.

    Requires a valid scope YAML file. Every tool invocation is validated
    against the scope before execution. Out-of-scope targets are dropped.
    """
    # NOTE: ROE banner is displayed by campaign.setup() → _display_roe_banner().
    # Do NOT add a second console.print(ROE_BANNER) here — it would print twice.

    # Phase 3 PR A: load recon packs BEFORE scope so any
    # pack-contributed tools / agents / policies are
    # registered by the time downstream code looks them up.
    # Failures are non-fatal (skip + warn).
    try:
        from nexusrecon.packs import load_packs
        pack_results = load_packs()
        for pr in pack_results:
            if pr.status.value == "loaded":
                console.print(
                    f"[dim]pack loaded:[/dim] "
                    f"[cyan]{pr.manifest.name}[/cyan] "
                    f"({pr.manifest.version})"
                )
            elif pr.status.value == "failed":
                console.print(
                    f"[yellow]pack failed:[/yellow] "
                    f"{pr.pack_dir.name} — {pr.error}"
                )
    except Exception as exc:
        console.print(
            f"[yellow]Pack loading raised: {exc}; continuing without packs.[/yellow]"
        )

    # Load scope
    try:
        scope_model = ScopeModel.from_yaml(scope)
    except Exception as e:
        console.print(f"[bold red]Scope validation failed:[/bold red] {e}")
        raise typer.Exit(1)

    # Preflight check
    warnings = preflight_check(scope_model)
    for level, msg in warnings:
        style = "bold red" if level == "ERROR" else "yellow"
        console.print(f"[{style}][{level}][/{style}] {msg}")

    if any(lvl == "ERROR" for lvl, _ in warnings):
        console.print("[bold red]Preflight errors — campaign aborted.[/bold red]")
        raise typer.Exit(1)

    # Parse mode
    try:
        campaign_mode = CampaignMode(mode.lower())
    except ValueError:
        console.print(f"[bold red]Invalid mode: {mode}. Use: light, medium, deep, monitor[/bold red]")
        raise typer.Exit(1)

    # Parse seeds
    seed_list = [s.strip() for s in seeds.split(",") if s.strip()] if seeds else []

    # Guard: seeds must be within the scope envelope (scope is the legal boundary).
    # Seeds that are not an exact in-scope domain or a subdomain of one are refused.
    # When --seeds is omitted the scope domains themselves become the seeds (safe by definition).
    if seed_list:
        _in_scope_domains = list(scope_model.scope.in_scope.domains or [])
        _out_of_scope = [
            s for s in seed_list
            if not any(
                s == d or s.endswith("." + d)
                for d in _in_scope_domains
            )
        ]
        if _out_of_scope:
            console.print(
                f"[bold red]Seeds outside scope:[/bold red] {', '.join(_out_of_scope)}\n"
                f"Seeds must be in scope.in_scope.domains or subdomains thereof.\n"
                f"In-scope domains: {', '.join(_in_scope_domains)}"
            )
            raise typer.Exit(1)

    # Create campaign
    campaign = CampaignManager(
        scope=scope_model,
        mode=campaign_mode,
        campaign_id=resume,
    )

    try:
        campaign.setup()
    except Exception as e:
        console.print(f"[bold red]Campaign setup failed:[/bold red] {e}")
        raise typer.Exit(1)

    # Wire scope guard and campaign services into the tool registry
    from nexusrecon.tools.registry import get_registry
    scope_guard = ScopeGuard(scope_model)
    get_registry().set_campaign_context(scope_guard, campaign.cache, campaign.audit_log)

    if dry_run:
        console.print("[bold green]Dry run — scope is valid, campaign ready.[/bold green]")
        console.print(f"Campaign ID: [cyan]{campaign.campaign_id}[/cyan]")
        console.print(f"Would create output at: [cyan]{campaign.campaign_dir}[/cyan]")
        console.print(scope_model.summary())
        return

    # Phase 1 PR B: planner orchestration. ``--plan-only`` runs
    # the planner, writes the strategy to disk + prints it, then
    # exits before any campaign tools fire. Normal runs invoke
    # the planner too (so the resulting Strategy is what the
    # reflection node consults) but proceed into execution.
    from nexusrecon.strategy import plan_campaign

    seed_list_for_planner = (
        seed_list if seed_list
        else list(scope_model.scope.in_scope.domains)
    )
    try:
        strategy = asyncio.run(plan_campaign(
            scope_summary=scope_model.summary(),
            seeds=seed_list_for_planner,
            mode=mode,
            dispatch_policy_name=dispatch_mode,
            max_llm_cost_usd=getattr(
                scope_model.constraints, "max_llm_cost_usd", 10.0,
            ),
        ))
    except Exception as exc:
        console.print(
            f"[yellow]Planner failed ({exc}); falling back to "
            f"default strategy.[/yellow]"
        )
        from nexusrecon.strategy import Strategy as _Strategy
        strategy = _Strategy.default()

    if plan_only:
        import json as _json
        strategy_dict = strategy.to_dict()
        plan_path = campaign.campaign_dir / "strategy.json"
        try:
            plan_path.write_text(
                _json.dumps(strategy_dict, indent=2, default=str),
                encoding="utf-8",
            )
        except Exception as exc:
            console.print(
                f"[yellow]Could not write {plan_path}: {exc}[/yellow]"
            )
        console.print("\n[bold green]Campaign Strategy (planner output)[/bold green]")
        console.print(f"Name:                 [cyan]{strategy.name}[/cyan]")
        console.print(
            f"Dispatch policy:      "
            f"[cyan]{strategy.dispatch_policy_name}[/cyan]"
        )
        console.print(
            f"Phases ({len(strategy.phases)}):           "
            f"[cyan]{', '.join(strategy.phases)}[/cyan]"
        )
        if strategy.tool_budgets:
            console.print(
                f"Tool budgets:         [cyan]{strategy.tool_budgets}[/cyan]"
            )
        if strategy.success_criteria:
            console.print(
                f"Success criteria ({len(strategy.success_criteria)}):"
            )
            for sc in strategy.success_criteria:
                console.print(
                    f"  • {sc.metric} {sc.op} {sc.threshold}"
                    f"  [dim]{sc.description}[/dim]"
                )
        if strategy.kill_criteria:
            console.print(
                f"Kill criteria ({len(strategy.kill_criteria)}):"
            )
            for kc in strategy.kill_criteria:
                console.print(
                    f"  • {kc.metric} {kc.op} {kc.threshold} → {kc.action}"
                    f"  [dim]{kc.description}[/dim]"
                )
        rationale = strategy.metadata.get("planner_rationale")
        if rationale:
            console.print(f"\n[dim]Rationale:[/dim] {rationale}")
        console.print(f"\nWritten to: [cyan]{plan_path}[/cyan]")
        return

    # Run the campaign
    console.print(f"\n[bold green]Launching campaign[/bold green] [cyan]{campaign.campaign_id}[/cyan]")
    console.print(f"Mode: [yellow]{mode}[/yellow] | Tier: [yellow]{scope_model.constraints.max_tier}[/yellow]\n")

    state = {
        "campaign_id": campaign.campaign_id,
        "engagement_id": scope_model.engagement.engagement_id,
        "scope_hash": scope_model.scope_hash or "",
        "seeds": seed_list or scope_model.scope.in_scope.domains,
        "completed_phases": [],
        "current_phase": "init",
        "findings": [],
        "subdomain_intel": {},
        "email_intel": {"emails": {}},
        "cloud_intel": {},
        "code_intel": {},
        "infra_intel": {},
        "domain_intel": {},
        "vuln_intel": {},
        "pretext_intel": {},
        "entity_graph": {},
        "hypotheses": [],
        "confirmed_leads": [],
        "validate_credentials": validate_creds,
        "generate_phishing_drafts": generate_phishing,
        "dispatch_mode": dispatch_mode if dispatch_mode in ("lite", "full", "off") else "lite",
        # Phase 1 PR B: persist the planner-generated strategy
        # into state so the reflection node + audit trail can
        # consult it. ``dispatch_policy_name`` shadows the
        # legacy ``dispatch_mode`` and is what
        # ``_resolve_policy`` reads first.
        "strategy": strategy.to_dict(),
        "dispatch_policy_name": strategy.dispatch_policy_name,
        "strategy_history": [],
        "pretext_targets": (
            [t.strip() for t in pretext_targets.split(",") if t.strip()]
            if pretext_targets else []
        ),
        "generate_obsidian": obsidian,
        "llm_cost_usd": 0.0,
        "max_llm_cost_usd": getattr(scope_model.constraints, "max_llm_cost_usd", 10.0),
        "tool_cost_usd": 0.0,
        "step_count": 0,
        "errors": [],
        "agent_messages": [],
        "report_paths": {},
    }

    # Run the campaign via the reusable campaign_runner (V3 Move 1 refactor —
    # both CLI and TUI share this loop).
    try:
        from nexusrecon.core.campaign_runner import run_campaign

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            if use_graph:
                from nexusrecon.graph.workflow import run_workflow
                task = progress.add_task("Running LangGraph campaign workflow...", total=None)
                try:
                    state = asyncio.run(run_workflow(state))
                    progress.update(task, description="[green]Complete: LangGraph workflow finished[/green]")
                except Exception as e:
                    state["errors"].append(f"workflow: {str(e)}")
                    progress.update(task, description=f"[red]Error in workflow: {e}[/red]")
            else:
                _progress_tasks: dict = {}

                def _cli_on_event(evt: dict) -> None:
                    etype = evt.get("type", "")
                    phase_id = evt.get("phase", "")
                    name = evt.get("name", phase_id)
                    if etype == "phase_start":
                        task = progress.add_task(f"Running: {name}...", total=None)
                        _progress_tasks[phase_id] = task
                    elif etype == "phase_end":
                        t = _progress_tasks.get(phase_id)
                        if t is not None:
                            progress.update(t, description=f"[green]Complete: {name}[/green]")
                    elif etype == "phase_skipped":
                        progress.add_task(
                            f"[dim]Skipped: {name} ({evt.get('reason', '')})[/dim]"
                        )
                    elif etype == "campaign_error":
                        t = _progress_tasks.get(phase_id)
                        msg = f"[red]Error in {name}: {evt.get('error', '')}[/red]"
                        if t is not None:
                            progress.update(t, description=msg)
                        else:
                            progress.add_task(msg)

                state = asyncio.run(
                    run_campaign(state, campaign, scope_model, on_event=_cli_on_event)
                )

        # F-019: populate real EntityGraph from execution state
        try:
            eg = campaign.entity_graph
            if eg is not None:
                seeds = state.get("seeds", [])
                for domain in seeds:
                    eg.add_domain(domain, source="scope")
                eg_state = state.get("entity_graph", {})
                for sub in eg_state.get("subdomains", []):
                    eg.add_subdomain(sub, parent=seeds[0] if seeds else "", source="campaign")
                for email in eg_state.get("emails", []):
                    eg.add_email(email, source="campaign")
        except Exception:
            pass

        # Generate reports
        report_dir = campaign.report_dir
        engine = ReportEngine(
            campaign_id=campaign.campaign_id,
            engagement_id=scope_model.engagement.engagement_id,
            scope_hash=scope_model.scope_hash or "",
            output_dir=report_dir,
        )
        report_paths = engine.generate_all(state)

        # Finalize
        summary = campaign.finalize()

        console.print()
        console.print(Panel(
            f"Findings: {summary['findings']}\n"
            f"Entities: {summary['graph'].get('total_entities', 0)}\n"
            f"Reports: {len(report_paths)}\n"
            f"Output: {summary['campaign_dir']}\n"
            f"Audit Chain: {'VALID' if summary['audit_chain_ok'] else 'BROKEN'}",
            title="[bold green]Campaign Complete[/bold green]",
            border_style="green",
        ))

        console.print("\n[bold]Reports:[/bold]")
        for name, path in report_paths.items():
            console.print(f"  {name}: {path}")

    except Exception as e:
        console.print(f"[bold red]Campaign failed:[/bold red] {e}")
        raise typer.Exit(1)


@app.command()
def validate(scope: str = typer.Argument(..., help="Path to scope YAML file")) -> None:
    """Validate a scope file without running a campaign."""
    try:
        scope_model = ScopeModel.from_yaml(scope)
        console.print("[bold green]Scope file is valid![/bold green]\n")
        console.print(scope_model.summary())

        warnings = preflight_check(scope_model)
        if warnings:
            console.print("\n[bold yellow]Warnings:[/bold yellow]")
            for level, msg in warnings:
                style = "bold red" if level == "ERROR" else "yellow"
                console.print(f"  [{style}][{level}][/{style}] {msg}")
        else:
            console.print("\n[bold green]No warnings — scope is ready for use.[/bold green]")

    except Exception as e:
        console.print(f"[bold red]Validation failed:[/bold red] {e}")
        raise typer.Exit(1)


@app.command()
def resume(campaign_id: str = typer.Argument(..., help="Campaign ID to resume")) -> None:
    """Resume a campaign from its last checkpoint."""
    console.print(f"[bold green]Resuming campaign[/bold green] [cyan]{campaign_id}[/cyan]")

    # Find campaign directory by scanning output dirs
    config = get_config()
    output_dir = Path(config.output_dir)

    state_path = None
    scope_meta_path = None
    for campaign_dir in output_dir.rglob(campaign_id):
        if campaign_dir.is_dir():
            candidate = campaign_dir / "state.json"
            if candidate.exists():
                state_path = candidate
                scope_meta_path = campaign_dir / "scope_metadata.json"
                break

    if not state_path:
        console.print(f"[bold red]Campaign {campaign_id} not found in {output_dir}[/bold red]")
        raise typer.Exit(1)

    # Load state
    state_data = json.loads(state_path.read_text(encoding="utf-8"))
    completed = set(state_data.get("completed_phases", []))
    current = state_data.get("current_phase", "phase1")

    console.print(f"Completed phases: {', '.join(completed)}")
    console.print(f"Current phase: {current}")
    console.print(f"Findings so far: {len(state_data.get('findings', []))}")

    # Load scope metadata to reconstruct scope model
    if scope_meta_path and scope_meta_path.exists():
        scope_meta = json.loads(scope_meta_path.read_text())
        console.print(f"Client: {scope_meta.get('engagement', {}).get('client', 'unknown')}")
        console.print(f"Max Tier: {scope_meta.get('constraints', {}).get('max_tier', 'T0')}")

    # Skip completed phases, continue from current
    console.print("\n[bold green]Continuing campaign execution...[/bold green]")

    # Use the same state dict structure as run()
    state = {
        "campaign_id": state_data.get("campaign_id", campaign_id),
        "engagement_id": state_data.get("engagement_id", ""),
        "scope_hash": state_data.get("scope_hash", ""),
        "seeds": state_data.get("seeds", []),
        "completed_phases": list(completed),
        "current_phase": current,
        "findings": state_data.get("findings", []),
        "subdomain_intel": state_data.get("subdomain_intel", {}),
        "email_intel": state_data.get("email_intel", {"emails": {}}),
        "cloud_intel": state_data.get("cloud_intel", {}),
        "code_intel": state_data.get("code_intel", {}),
        "infra_intel": state_data.get("infra_intel", {}),
        "domain_intel": state_data.get("domain_intel", {}),
        "vuln_intel": state_data.get("vuln_intel", {}),
        "pretext_intel": state_data.get("pretext_intel", {}),
        "entity_graph": state_data.get("entity_graph", {}),
        "hypotheses": state_data.get("hypotheses", []),
        "confirmed_leads": state_data.get("confirmed_leads", []),
        "llm_cost_usd": state_data.get("llm_cost_usd", 0.0),
        "tool_cost_usd": state_data.get("tool_cost_usd", 0.0),
        "step_count": state_data.get("step_count", 0),
        "errors": state_data.get("errors", []),
        "agent_messages": state_data.get("agent_messages", []),
        "report_paths": {},
    }

    # Import and run remaining phases
    try:
        from nexusrecon.graph.nodes import (
            phase1_passive_footprinting,
            phase2_identity_cloud,
            phase3_code_leakage,
            phase4_correlation,
            phase5_light_active,
            phase6_active,
            phase7_vuln_pretext,
            phase8_attack_surface,
            phase9_reporting,
        )

        phases = [
            ("phase1", "Passive Footprinting", phase1_passive_footprinting),
            ("phase2", "Identity & Cloud", phase2_identity_cloud),
            ("phase3", "Code Leakage", phase3_code_leakage),
            ("phase4", "Correlation", phase4_correlation),
            ("phase5", "Light Active", phase5_light_active),
            ("phase6", "Active (T3)", phase6_active),
            ("phase7", "Vuln & Pretext", phase7_vuln_pretext),
            ("phase8", "Attack Surface", phase8_attack_surface),
            ("phase9", "Reporting", phase9_reporting),
        ]

        # Parse max tier from scope metadata
        max_tier = 3
        if scope_meta_path and scope_meta_path.exists():
            tier_str = scope_meta.get("constraints", {}).get("max_tier", "T0")
            if tier_str.startswith("T"):
                try:
                    max_tier = int(tier_str[1])
                except (ValueError, IndexError):
                    max_tier = 0
        phase_map = {
            "phase1": 0, "phase2": 0, "phase3": 0, "phase4": 0,
            "phase5": 2, "phase6": 3, "phase7": 0, "phase8": 0, "phase9": 0,
        }

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            async def _resume_campaign_phases() -> dict:
                s = state
                for phase_id, phase_name, phase_fn in phases:
                    if phase_id in completed:
                        progress.add_task(f"[dim]Skipped (done): {phase_name}[/dim]")
                        continue
                    if phase_map.get(phase_id, 0) > max_tier:
                        progress.add_task(f"[dim]Skipped: {phase_name} (above max tier)[/dim]")
                        continue
                    task = progress.add_task(f"Running: {phase_name}...", total=None)
                    try:
                        s = await phase_fn(s)
                        progress.update(task, description=f"[green]Complete: {phase_name}[/green]")
                    except Exception as e:
                        s["errors"].append(f"{phase_id}: {str(e)}")
                        progress.update(task, description=f"[red]Error in {phase_name}: {e}[/red]")
                return s

            state = asyncio.run(_resume_campaign_phases())

        # Save updated state
        campaign_dir = state_path.parent
        campaign_dir.joinpath("state.json").write_text(
            json.dumps(state, indent=2, default=str), encoding="utf-8"
        )

        # Generate reports
        report_dir = campaign_dir / "reports"
        engine = ReportEngine(
            campaign_id=state["campaign_id"],
            engagement_id=state.get("engagement_id", ""),
            scope_hash=state.get("scope_hash", ""),
            output_dir=report_dir,
        )
        report_paths = engine.generate_all(state)

        console.print("\n" + Panel(
            f"Findings: {len(state.get('findings', []))}\n"
            f"Reports: {len(report_paths)}\n"
            f"Output: {campaign_dir}",
            title="[bold green]Campaign Resumed Complete[/bold green]",
            border_style="green",
        ))

        console.print("\n[bold]Reports:[/bold]")
        for name, path in report_paths.items():
            console.print(f"  {name}: {path}")

    except Exception as e:
        console.print(f"[bold red]Resume failed:[/bold red] {e}")
        raise typer.Exit(1)


@app.command()
def diff(old: str = typer.Argument(...), new: str = typer.Argument(...)) -> None:
    """Diff two campaign states to see what changed."""
    from nexusrecon.core.campaign import CampaignManager
    result = CampaignManager.diff_campaigns(old, new)
    console.print(json.dumps(result, indent=2, default=str))


@app.command()
def tools(
    available_only: bool = typer.Option(False, "--available", "-a", help="Show only available tools"),
    category: str | None = typer.Option(None, "--category", "-c", help="Filter by category"),
) -> None:
    """List all registered tools, their availability, and what they require."""
    from nexusrecon.tools.registry import get_registry
    registry = get_registry()

    all_tools = sorted(registry.list_tools(), key=lambda x: (x["category"], x["name"]))

    if available_only:
        all_tools = [t for t in all_tools if t["available"] == "True"]
    if category:
        all_tools = [t for t in all_tools if t["category"] == category.lower()]

    available_count = sum(1 for t in all_tools if t["available"] == "True")
    total_count = len(all_tools)

    table = Table(
        title=f"NexusRecon Tools  ({available_count}/{total_count} available)",
        show_lines=False,
        header_style="bold cyan",
    )
    table.add_column("Tool", style="bold", min_width=18)
    table.add_column("Category", min_width=14)
    table.add_column("Tier", justify="center", min_width=5)
    table.add_column("Status", justify="center", min_width=9)
    table.add_column("Requires", min_width=22, no_wrap=False)
    table.add_column("Description", no_wrap=False)

    TIER_STYLE = {"T0": "green", "T1": "yellow", "T2": "dark_orange", "T3": "red"}

    for t in all_tools:
        avail = t["available"] == "True"
        tier = t["tier"]
        requires = t.get("requires", "") or "[dim]—[/dim]"
        description = t.get("description") or ""

        table.add_row(
            t["name"],
            t["category"],
            f"[{TIER_STYLE.get(tier, 'white')}]{tier}[/]",
            "[green]✓ ready[/green]" if avail else "[red]✗ missing[/red]",
            f"[dim]{requires}[/dim]" if not avail and requires != "[dim]—[/dim]" else requires,
            description,
        )

    console.print()
    console.print(table)
    console.print()

    if not available_only:
        missing = [t for t in all_tools if t["available"] != "True"]
        if missing:
            need_keys = [t for t in missing if t.get("requires") and "bin:" not in t.get("requires", "")]
            need_bins = [t for t in missing if "bin:" in t.get("requires", "")]
            [t for t in missing if t.get("requires") and "bin:" in t.get("requires", "") and any(
                k for k in t.get("requires", "").split(", ") if not k.startswith("bin:")
            )]

            if need_bins:
                bin_names = sorted({
                    r.replace("bin:", "")
                    for t in need_bins
                    for r in t.get("requires", "").split(", ")
                    if r.startswith("bin:")
                })
                console.print(f"[yellow]Missing binaries:[/yellow] {', '.join(bin_names)}")
                console.print("  Install Go tools: [dim]go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest[/dim]")
            if need_keys:
                key_names = sorted({
                    r
                    for t in need_keys
                    for r in t.get("requires", "").split(", ")
                    if not r.startswith("bin:")
                })
                console.print(f"[yellow]Missing API keys:[/yellow] {', '.join(key_names)}")
                console.print("  Add keys to [dim].env[/dim] — see [dim].env.example[/dim] for all variables.")


@app.command()
def config() -> None:
    """Show current configuration and API key availability."""
    cfg = get_config()
    table = Table(title="Configuration")
    table.add_column("Setting")
    table.add_column("Value")

    table.add_row("LLM Provider", cfg.llm_provider)
    table.add_row("LLM Model", cfg.llm_model)
    table.add_row("Output Dir", cfg.output_dir)
    table.add_row("DB Path", cfg.db_path)
    table.add_row("Log Level", cfg.log_level)
    table.add_row("Proxy", cfg.proxy_url or "(none)")

    for key, available in cfg.available_keys().items():
        table.add_row(f"Key: {key}", "[green]Set[/green]" if available else "[red]Not set[/red]")

    console.print(table)


@app.command()
def campaign_list(
    client: str | None = typer.Option(None, "--client", "-c", help="Filter by client name"),
) -> None:
    """List all campaigns and their status."""
    config = get_config()
    output_dir = Path(config.output_dir)

    if not output_dir.exists():
        console.print("[yellow]No campaigns found — output directory does not exist.[/yellow]")
        return

    table = Table(title="Campaigns")
    table.add_column("Campaign ID")
    table.add_column("Client")
    table.add_column("Engagement")
    table.add_column("Phases")
    table.add_column("Findings")
    table.add_column("Status")

    count = 0
    for state_file in output_dir.rglob("state.json"):
        try:
            data = json.loads(state_file.read_text(encoding="utf-8"))
            campaign_id = data.get("campaign_id", state_file.parent.name)
            engagement_id = data.get("engagement_id", "?")
            completed = len(data.get("completed_phases", []))
            findings = len(data.get("findings", []))
            errors = len(data.get("errors", []))

            # Try to find client name from scope_metadata.json
            scope_meta_path = state_file.parent / "scope_metadata.json"
            client_name = "?"
            if scope_meta_path.exists():
                scope_meta = json.loads(scope_meta_path.read_text())
                client_name = scope_meta.get("engagement", {}).get("client", "?")

            if client and client.lower() not in client_name.lower():
                continue

            status = "[red]ERROR[/red]" if errors else "[green]DONE[/green]"
            table.add_row(campaign_id, client_name, engagement_id, str(completed), str(findings), status)
            count += 1
        except Exception:
            continue

    if count == 0:
        console.print("[yellow]No campaigns found.[/yellow]")
    else:
        console.print(table)
        console.print(f"\n[bold]{count}[/bold] campaign(s) found in [cyan]{output_dir}[/cyan]")


@app.command()
def tools_check() -> None:
    """Check tool binary dependencies and API key availability."""
    from nexusrecon.tools.registry import get_registry
    registry = get_registry()

    missing_bins = []
    available_keys = 0
    total_keys = 0

    for t in registry.list_tools():
        # Check binary requirements
        for req_bin in t.get("requires_binary", []):
            import shutil
            if shutil.which(req_bin):
                pass
            else:
                missing_bins.append((t["name"], req_bin))

        # Check API keys
        for req_key in t.get("requires_keys", []):
            total_keys += 1
            if req_key:
                available_keys += 1

    table = Table(title="Tool Dependencies")
    table.add_column("Tool")
    table.add_column("Missing Binary")
    for tool_name, binary in sorted(missing_bins):
        table.add_row(tool_name, f"[red]{binary} not found[/red]")

    if not missing_bins:
        console.print("[bold green]All required binaries found.[/bold green]")
    else:
        console.print(table)
        console.print(f"\n[yellow]{len(missing_bins)}[/yellow] missing binary dependencies.")

    console.print(f"API keys: {available_keys}/{total_keys} configured")


@app.command()
def export(
    campaign_id: str = typer.Argument(..., help="Campaign ID to export"),
    fmt: str = typer.Option("csv", "--format", "-f", help="Export format: csv, json, markdown, stix2, jira, nuclei-targets, cobaltstrike-profile"),
    jira_project: str = typer.Option(
        "SEC", "--jira-project",
        help="Jira project key for --format jira.",
    ),
    output: str | None = typer.Option(None, "--output", "-o", help="Output file path"),
) -> None:
    """Export campaign findings to CSV, JSON, or Markdown."""
    config = get_config()
    output_dir = Path(config.output_dir)

    state_path = None
    for candidate in output_dir.rglob(campaign_id):
        if candidate.is_dir():
            sp = candidate / "state.json"
            if sp.exists():
                state_path = sp
                break

    if not state_path:
        console.print(f"[bold red]Campaign {campaign_id} not found.[/bold red]")
        raise typer.Exit(1)

    data = json.loads(state_path.read_text(encoding="utf-8"))
    findings = data.get("findings", [])

    if not output:
        output = str(state_path.parent / f"findings_export.{fmt}")

    out_path = Path(output)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    if fmt == "csv":
        import csv
        with open(out_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["Title", "Severity", "Confidence", "Category", "Source", "Description", "Assets", "MITRE"])
            for f_item in findings:
                writer.writerow([
                    f_item.get("title", ""),
                    f_item.get("severity", ""),
                    f"{f_item.get('confidence', 0):.0%}",
                    f_item.get("category", ""),
                    f_item.get("source", ""),
                    f_item.get("description", ""),
                    ", ".join(f_item.get("affected_assets", [])),
                    ", ".join(f_item.get("mitre_techniques", [])),
                ])
    elif fmt == "json":
        out_path.write_text(json.dumps(findings, indent=2, default=str), encoding="utf-8")
    elif fmt == "jira":
        from nexusrecon.export.downstream import JiraTicketEmitter
        emitter = JiraTicketEmitter(project_key=jira_project)
        emitter.write_ndjson(findings, out_path)
        console.print(
            f"[green]✓ Jira NDJSON:[/green] [cyan]{out_path}[/cyan]\n"
            f"  issues: [cyan]{len(findings)}[/cyan]\n"
            f"  project key: [cyan]{jira_project}[/cyan]\n"
            f"  next: stream into Jira with curl per line."
        )
        return
    elif fmt == "nuclei-targets":
        from nexusrecon.core.entity_graph import EntityGraph
        from nexusrecon.export.downstream import emit_nuclei_targets
        graph = EntityGraph.from_state(
            data,
            campaign_id=data.get("campaign_id", ""),
            engagement_id=data.get("engagement_id", ""),
        )
        out, targets = emit_nuclei_targets(graph, out_path)
        console.print(
            f"[green]✓ Nuclei target list:[/green] [cyan]{out}[/cyan]\n"
            f"  targets: [cyan]{len(targets)}[/cyan]\n"
            f"  next: [bold]nuclei -list {out} -t cves/[/bold]"
        )
        return
    elif fmt == "cobaltstrike-profile":
        from nexusrecon.core.entity_graph import EntityGraph
        from nexusrecon.export.downstream import (
            emit_cobaltstrike_profile_stub,
        )
        graph = EntityGraph.from_state(
            data,
            campaign_id=data.get("campaign_id", ""),
            engagement_id=data.get("engagement_id", ""),
        )
        out = emit_cobaltstrike_profile_stub(graph, out_path)
        console.print(
            f"[green]✓ Cobalt Strike profile stub:[/green] "
            f"[cyan]{out}[/cyan]\n"
            f"  [yellow]Review + tune tradecraft fields "
            f"before deploying.[/yellow]"
        )
        return
    elif fmt == "stix2":
        # Phase 4 PR B: STIX 2.1 Bundle export. Rebuilds the
        # EntityGraph from state["entity_graph"] (Phase 0
        # made this serialised round-trip a first-class
        # capability) and runs it through the STIX
        # serialiser.
        from nexusrecon.core.entity_graph import EntityGraph
        from nexusrecon.export import build_stix_bundle

        graph = EntityGraph.from_state(
            data,
            campaign_id=data.get("campaign_id", ""),
            engagement_id=data.get("engagement_id", ""),
        )
        bundle = build_stix_bundle(
            graph,
            scope_hash=data.get("scope_hash", ""),
            campaign_id=data.get("campaign_id", campaign_id),
        )
        out_path.write_text(bundle.to_json(), encoding="utf-8")
        console.print(
            f"[green]✓ STIX 2.1 bundle:[/green] "
            f"[cyan]{out_path}[/cyan]\n"
            f"  objects: [cyan]{bundle.counts.get('total_objects', 0)}[/cyan]"
        )
        for kind, count in sorted(bundle.counts.items()):
            if kind == "total_objects":
                continue
            console.print(f"  {kind}: [cyan]{count}[/cyan]")
        return
    elif fmt == "markdown":
        lines = ["# Findings Export", "", f"**Campaign:** {campaign_id}", ""]
        for i, f_item in enumerate(findings, 1):
            lines.extend([
                f"### {i}. [{f_item.get('severity', 'info').upper()}] {f_item.get('title', '')}",
                f"**Confidence:** {f_item.get('confidence', 0):.0%}",
                f"**Category:** {f_item.get('category', '')}",
                f"**Source:** {f_item.get('source', '')}",
                f"**Description:** {f_item.get('description', '')}",
                f"**Assets:** {', '.join(f_item.get('affected_assets', []))}",
                "",
            ])
        out_path.write_text("\n".join(lines), encoding="utf-8")
    else:
        console.print(f"[bold red]Unknown format: {fmt}. Use csv, json, or markdown.[/bold red]")
        raise typer.Exit(1)

    console.print(f"[bold green]Exported {len(findings)} findings to {out_path}[/bold green]")


@app.command()
def smoke(
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show individual test output"),
    tb: str = typer.Option("short", "--tb", help="Traceback style: short, long, no, line"),
    keyword: str | None = typer.Option(None, "-k", help="Only run tests matching this keyword"),
) -> None:
    """Run the NexusRecon smoke test suite.

    Exercises real module code against synthetic data. Network-dependent tests
    are soft-skipped when no keys / network are available. Hard failures indicate
    real integration bugs that must be fixed before a campaign is run.
    """
    import pytest

    console.print(
        Panel(
            "NexusRecon Smoke Test Suite\n"
            "Tests run against synthetic data — network failures are skipped,\n"
            "logic failures are hard errors.",
            title="[bold cyan]Smoke Tests[/bold cyan]",
            border_style="cyan",
        )
    )

    smoke_dir = str(Path(__file__).parent.parent.parent / "tests" / "smoke")

    args: list[str] = [smoke_dir, f"--tb={tb}"]
    if verbose:
        args.append("-v")
    if keyword:
        args.extend(["-k", keyword])

    exit_code = pytest.main(args)

    console.print()
    if exit_code == 0:
        console.print(
            Panel(
                "[bold green]ALL SMOKE TESTS PASSED[/bold green]\n"
                "The module integration is healthy.",
                border_style="green",
            )
        )
    elif exit_code == 5:
        console.print(
            Panel(
                "[bold yellow]NO TESTS COLLECTED[/bold yellow]\n"
                f"Check that {smoke_dir} contains test_*.py files.",
                border_style="yellow",
            )
        )
        raise typer.Exit(1)
    else:
        console.print(
            Panel(
                f"[bold red]SMOKE TESTS FAILED (exit {exit_code})[/bold red]\n"
                "Fix the failures above before running a live campaign.",
                border_style="red",
            )
        )
        raise typer.Exit(exit_code)


@app.command()
def tui() -> None:
    """Launch the interactive Textual UI (default when no subcommand given)."""
    from nexusrecon.tui.app import run_tui
    run_tui()


# ── Phase 3 PR A: Recon Pack management ──────────────────────────────

packs_app = typer.Typer(
    help=(
        "Manage recon packs — community-authored bundles of "
        "tools, agents, dispatch policies, and report templates."
    ),
)
app.add_typer(packs_app, name="packs")


@packs_app.command("list")
def packs_list(
    pack_dir: str | None = typer.Option(
        None, "--pack-dir",
        help=(
            "Override the pack directory (default: "
            "$NEXUSRECON_PACK_DIR or ~/.nexusrecon/packs)."
        ),
    ),
) -> None:
    """List installed recon packs + their load status."""
    from nexusrecon.packs import discover_packs, load_packs

    candidates = discover_packs(pack_dir)
    if not candidates:
        console.print(
            "[yellow]No packs found.[/yellow] "
            "Drop a pack directory into "
            "[cyan]~/.nexusrecon/packs/[/cyan] and re-run."
        )
        return

    results = load_packs(pack_dir)
    table_lines = [
        f"[bold]{'NAME':<24} {'VERSION':<12} {'STATUS':<10} CONTRIBUTIONS[/bold]",
    ]
    for r in results:
        name = (r.manifest.name if r.manifest else r.pack_dir.name)
        version = r.manifest.version if r.manifest else "-"
        status = r.status.value
        contribs = ", ".join(
            f"{k}:{v}" for k, v in r.contributions_loaded.items() if v
        ) or "(none)"
        color = (
            "green" if status == "loaded"
            else "red" if status == "failed"
            else "yellow"
        )
        table_lines.append(
            f"{name:<24} {version:<12} "
            f"[{color}]{status:<10}[/{color}] {contribs}"
        )
        if r.warnings:
            for w in r.warnings:
                table_lines.append(f"    [yellow]⚠[/yellow] {w}")
        if r.error:
            table_lines.append(f"    [red]✗[/red] {r.error}")

    console.print("\n".join(table_lines))


@packs_app.command("install")
def packs_install(
    url_spec: str = typer.Argument(
        ..., help=(
            "Pack URL: `gh:owner/repo[@ref]` or a full git URL."
        ),
    ),
    pack_dir: str | None = typer.Option(
        None, "--pack-dir",
        help="Override the pack directory (default: ~/.nexusrecon/packs).",
    ),
) -> None:
    """Install a recon pack from a git URL."""
    from nexusrecon.packs import install_pack

    result = install_pack(url_spec, pack_root=pack_dir)
    if result.success:
        console.print(
            f"[green]✓ installed[/green] "
            f"[cyan]{result.pack_name or '?'}[/cyan]"
            + (f" ({result.version})" if result.version else "")
            + f" → {result.pack_path}"
        )
        if result.error:
            console.print(f"  [yellow]⚠[/yellow] {result.error}")
    else:
        console.print(f"[red]✗ install failed:[/red] {result.error}")
        raise typer.Exit(1)


@packs_app.command("uninstall")
def packs_uninstall(
    name: str = typer.Argument(
        ..., help="Pack directory name (or absolute path).",
    ),
    pack_dir: str | None = typer.Option(
        None, "--pack-dir",
        help="Override the pack directory.",
    ),
    confirm: bool = typer.Option(
        False, "--yes", "-y",
        help="Skip confirmation prompt.",
    ),
) -> None:
    """Remove an installed recon pack."""
    from rich.prompt import Confirm

    from nexusrecon.packs import uninstall_pack
    from nexusrecon.packs.loader import _resolve_pack_dir

    if not confirm:
        target = (
            Path(name).expanduser().resolve()
            if Path(name).is_absolute()
            else _resolve_pack_dir(pack_dir) / name
        )
        if not Confirm.ask(
            f"Remove [cyan]{target}[/cyan]?", default=False,
        ):
            console.print("[yellow]cancelled[/yellow]")
            return

    if uninstall_pack(name, pack_root=pack_dir):
        console.print(f"[green]✓ removed[/green] {name}")
    else:
        console.print(
            f"[yellow]nothing to remove[/yellow] (no pack at {name})"
        )


@packs_app.command("update")
def packs_update(
    name: str = typer.Argument(
        ..., help="Pack directory name (or absolute path).",
    ),
    pack_dir: str | None = typer.Option(
        None, "--pack-dir",
        help="Override the pack directory.",
    ),
) -> None:
    """Update an installed pack to its remote's latest."""
    from nexusrecon.packs import update_pack

    result = update_pack(name, pack_root=pack_dir)
    if result.success:
        console.print(
            f"[green]✓ updated[/green] "
            f"[cyan]{result.pack_name or name}[/cyan]"
            + (f" → {result.version}" if result.version else "")
        )
        if result.error:
            console.print(f"  [yellow]⚠[/yellow] {result.error}")
    else:
        console.print(f"[red]✗ update failed:[/red] {result.error}")
        raise typer.Exit(1)


@packs_app.command("search")
def packs_search(
    query: str = typer.Argument(
        "", help="Substring to search for in pack names + summaries.",
    ),
    category: str | None = typer.Option(
        None, "--category",
        help="Filter by category (exact match).",
    ),
    source: str | None = typer.Option(
        None, "--source",
        help=(
            "Marketplace URL or local index path. Defaults to "
            "$NEXUSRECON_MARKETPLACE_URL."
        ),
    ),
) -> None:
    """Search the marketplace for community packs."""
    from nexusrecon.packs import load_marketplace, resolve_marketplace_url

    url = source or resolve_marketplace_url()
    if not url:
        console.print(
            "[yellow]No marketplace configured.[/yellow]\n"
            "Set [cyan]NEXUSRECON_MARKETPLACE_URL[/cyan] to a "
            "marketplace JSON URL, or pass --source <path>."
        )
        return
    try:
        marketplace = load_marketplace(url)
    except ValueError as exc:
        console.print(f"[red]marketplace load failed:[/red] {exc}")
        raise typer.Exit(1)

    results = marketplace.search(query, category=category)
    if not results:
        console.print("[yellow]no matches[/yellow]")
        return
    for entry in results:
        cats = (
            f" [dim]({', '.join(entry.categories)})[/dim]"
            if entry.categories else ""
        )
        console.print(
            f"[cyan]{entry.name}[/cyan] "
            f"{entry.latest_version}{cats}\n"
            f"  {entry.summary}\n"
            f"  [dim]install:[/dim] "
            f"[bold]nexusrecon packs install {entry.url}[/bold]\n"
        )


@packs_app.command("validate")
def packs_validate(
    pack_path: str = typer.Argument(
        ..., help="Path to a pack directory (containing manifest.yaml).",
    ),
) -> None:
    """Validate a pack's manifest without loading it."""
    from nexusrecon.packs import compute_manifest_hash, parse_manifest

    path = Path(pack_path).expanduser().resolve()
    manifest_path = path / "manifest.yaml"
    if not manifest_path.exists():
        console.print(f"[red]No manifest.yaml at {path}[/red]")
        raise typer.Exit(1)
    try:
        manifest = parse_manifest(manifest_path)
    except Exception as exc:
        console.print(f"[red]Validation failed:[/red] {exc}")
        raise typer.Exit(1)

    actual_hash = compute_manifest_hash(manifest)
    console.print(
        f"[green]OK[/green]  {manifest.name} {manifest.version}\n"
        f"  description:    {manifest.description or '(none)'}\n"
        f"  author:         {manifest.author or '(none)'}\n"
        f"  license:        {manifest.license or '(none)'}\n"
        f"  contributions:  {manifest.contributes.total()}\n"
        f"    tools:        {len(manifest.contributes.tools)}\n"
        f"    agents:       {len(manifest.contributes.agents)}\n"
        f"    policies:     {len(manifest.contributes.policies)}\n"
        f"    templates:    {len(manifest.contributes.report_templates)}\n"
        f"    entity_types: {len(manifest.contributes.entity_types)}\n"
        f"    rel_types:    {len(manifest.contributes.relationship_types)}\n"
        f"  computed_hash:  {actual_hash}"
    )
    if manifest.manifest_hash and manifest.manifest_hash != actual_hash:
        console.print(
            f"  [yellow]⚠  declared hash differs: "
            f"{manifest.manifest_hash}[/yellow]"
        )


# ── Phase 3 PR B: Agent SDK ──────────────────────────────────────────

agent_app = typer.Typer(
    help=(
        "Author new agents for recon packs. Generates "
        "boilerplate with prompt versioning + citation "
        "guardrails wired in."
    ),
)
app.add_typer(agent_app, name="agent")


@agent_app.command("new")
def agent_new(
    name: str | None = typer.Option(
        None, "--name", help="Agent slug (snake_case).",
    ),
    role: str | None = typer.Option(
        None, "--role", help="One-line role description.",
    ),
    goal: str | None = typer.Option(
        None, "--goal", help="What the agent is trying to do.",
    ),
    backstory: str | None = typer.Option(
        None, "--backstory",
        help="Multi-sentence backstory + voice for the agent.",
    ),
    pack: str | None = typer.Option(
        None, "--pack",
        help=(
            "'new' to create a fresh pack (default), or a "
            "path to an existing pack directory to extend."
        ),
    ),
    pack_name: str | None = typer.Option(
        None, "--pack-name",
        help="Slug for the new pack (only with --pack new).",
    ),
) -> None:
    """Generate a new agent. Walks through Rich prompts for
    any missing fields; ``--`` flags bypass the prompts.
    """
    from rich.prompt import Prompt

    from nexusrecon.packs.loader import _resolve_pack_dir
    from nexusrecon.sdk.agent_scaffolder import (
        ScaffoldInputs,
        scaffold_agent,
        validate_inputs,
    )

    # ── Pack target ──────────────────────────────────────────
    pack_choice = pack
    if pack_choice is None:
        pack_choice = Prompt.ask(
            "[bold cyan]Pack target[/bold cyan] — 'new' "
            "for a fresh pack, or path to an existing pack",
            default="new",
        )

    if pack_choice == "new":
        is_new_pack = True
        pn = pack_name
        if pn is None:
            pn = Prompt.ask(
                "[bold cyan]New pack name[/bold cyan] (kebab-case)",
            )
        pack_root = _resolve_pack_dir(None) / pn
        target = pack_root
        pack_slug = pn
    else:
        is_new_pack = False
        target = Path(pack_choice).expanduser().resolve()
        if not (target / "manifest.yaml").exists():
            console.print(
                f"[red]No manifest.yaml at {target}.[/red] "
                "Pass --pack new if you meant to create a "
                "fresh pack, or correct the path."
            )
            raise typer.Exit(1)
        # Pack slug comes from the existing manifest.
        import yaml as _yaml
        raw = _yaml.safe_load((target / "manifest.yaml").read_text())
        pack_slug = (raw or {}).get("name", "pack")

    # ── Agent identity ───────────────────────────────────────
    if name is None:
        name = Prompt.ask(
            "[bold cyan]Agent slug[/bold cyan] (snake_case)",
        )
    if role is None:
        role = Prompt.ask(
            "[bold cyan]Role[/bold cyan] "
            "(one-line description of what the agent IS)",
        )
    if goal is None:
        goal = Prompt.ask(
            "[bold cyan]Goal[/bold cyan] "
            "(what the agent is trying to do)",
        )
    if backstory is None:
        backstory = Prompt.ask(
            "[bold cyan]Backstory + voice[/bold cyan] "
            "(used as system prompt; multi-sentence ok)",
        )

    inputs = ScaffoldInputs(
        agent_name=name,
        role=role,
        goal=goal,
        backstory=backstory,
        pack_target=target,
        is_new_pack=is_new_pack,
        pack_name=pack_slug if is_new_pack else "",
    )
    try:
        validate_inputs(inputs)
        result = scaffold_agent(inputs)
    except (ValueError, FileExistsError, FileNotFoundError) as exc:
        console.print(f"[red]Scaffolding failed:[/red] {exc}")
        raise typer.Exit(1)

    console.print(
        Panel(
            (
                f"[bold green]Agent scaffolded.[/bold green]\n"
                f"  module:    [cyan]{result.agent_module_path}[/cyan]\n"
                f"  manifest:  [cyan]{result.manifest_path}[/cyan]\n"
                + (
                    f"  test:      [cyan]{result.test_path}[/cyan]\n"
                    if result.test_path else ""
                )
                + "\nNext steps:\n"
                "  1. Edit the prompt / role / goal in the "
                "module to match your capability.\n"
                "  2. Run [cyan]nexusrecon packs list[/cyan] "
                "to confirm the pack loads.\n"
                "  3. Add the agent to a workflow phase or "
                "dispatch policy."
            ),
            title="✓ agent new",
            border_style="green",
        )
    )


# ── Phase 3 PR C2: Tool + policy scaffolders ─────────────────────────


tool_app = typer.Typer(
    help="Scaffold new OSINTTool subclasses inside a pack.",
)
app.add_typer(tool_app, name="tool")


@tool_app.command("new")
def tool_new(
    name: str | None = typer.Option(None, "--name"),
    description: str | None = typer.Option(None, "--description"),
    category: str | None = typer.Option(None, "--category"),
    tier: str | None = typer.Option(None, "--tier"),
    target_types: str | None = typer.Option(
        None, "--target-types",
        help="Comma-separated, e.g. 'domain,subdomain'.",
    ),
    cost: float = typer.Option(0.0, "--cost"),
    pack: str | None = typer.Option(None, "--pack"),
    pack_name: str | None = typer.Option(None, "--pack-name"),
) -> None:
    """Generate a new tool. Interactive capability picker for
    category / target_types / tier when flags are omitted."""
    from rich.prompt import IntPrompt, Prompt

    from nexusrecon.packs.loader import _resolve_pack_dir
    from nexusrecon.sdk.tool_scaffolder import (
        ToolScaffoldInputs,
        scaffold_tool,
        validate_tool_inputs,
    )
    from nexusrecon.tools.base import Category, Tier

    # Pack target
    pack_choice = pack
    if pack_choice is None:
        pack_choice = Prompt.ask(
            "[bold cyan]Pack target[/bold cyan] — 'new' or "
            "path to existing pack",
            default="new",
        )
    if pack_choice == "new":
        is_new_pack = True
        pn = pack_name or Prompt.ask(
            "[bold cyan]New pack name[/bold cyan] (kebab-case)",
        )
        target = _resolve_pack_dir(None) / pn
        pack_slug = pn
    else:
        is_new_pack = False
        target = Path(pack_choice).expanduser().resolve()
        if not (target / "manifest.yaml").exists():
            console.print(f"[red]No manifest.yaml at {target}.[/red]")
            raise typer.Exit(1)
        pack_slug = ""

    # Tool identity + capabilities
    if name is None:
        name = Prompt.ask("[bold cyan]Tool slug[/bold cyan] (snake_case)")
    if description is None:
        description = Prompt.ask(
            "[bold cyan]Description[/bold cyan] "
            "(one-line capability summary)"
        )

    if category is None:
        choices = sorted(c.value for c in Category)
        console.print(
            "[bold cyan]Category[/bold cyan] — pick one of: "
            + ", ".join(choices)
        )
        category = Prompt.ask("category", choices=choices)
    if tier is None:
        tier = Prompt.ask(
            "[bold cyan]Tier[/bold cyan] — invasiveness band",
            choices=[t.value for t in Tier],
            default="T0",
        )
    if target_types is None:
        raw = Prompt.ask(
            "[bold cyan]Target types[/bold cyan] "
            "(comma-separated, e.g. 'domain,subdomain')",
            default="domain",
        )
        targets = [t.strip() for t in raw.split(",") if t.strip()]
    else:
        targets = [t.strip() for t in target_types.split(",") if t.strip()]

    inputs = ToolScaffoldInputs(
        tool_name=name, description=description,
        category=category, tier=tier,
        target_types=targets, cost_per_run_usd=cost,
        pack_target=target, is_new_pack=is_new_pack,
        pack_name=pack_slug if is_new_pack else "",
    )
    try:
        validate_tool_inputs(inputs)
        result = scaffold_tool(inputs)
    except (ValueError, FileExistsError, FileNotFoundError) as exc:
        console.print(f"[red]Scaffolding failed:[/red] {exc}")
        raise typer.Exit(1)

    console.print(
        Panel(
            (
                f"[bold green]Tool scaffolded.[/bold green]\n"
                f"  module:    [cyan]{result.tool_module_path}[/cyan]\n"
                f"  manifest:  [cyan]{result.manifest_path}[/cyan]\n"
                + (
                    f"  test:      [cyan]{result.test_path}[/cyan]\n"
                    if result.test_path else ""
                )
                + "\nNext step: implement [bold].run()[/bold] in the "
                "generated module."
            ),
            title="✓ tool new",
            border_style="green",
        )
    )


policy_app = typer.Typer(
    help="Scaffold new DispatchPolicy subclasses inside a pack.",
)
app.add_typer(policy_app, name="policy")


@policy_app.command("new")
def policy_new(
    name: str | None = typer.Option(None, "--name"),
    description: str | None = typer.Option(None, "--description"),
    max_per_cycle: int = typer.Option(5, "--max-per-cycle"),
    max_total: int = typer.Option(30, "--max-total"),
    eligible_phases: str | None = typer.Option(
        None, "--eligible-phases",
        help=(
            "Comma-separated phase ids (empty list = all phases)."
        ),
    ),
    pack: str | None = typer.Option(None, "--pack"),
    pack_name: str | None = typer.Option(None, "--pack-name"),
) -> None:
    """Generate a new dispatch policy. Interactive picker for
    eligible_phases when the flag is omitted."""
    from rich.prompt import IntPrompt, Prompt

    from nexusrecon.packs.loader import _resolve_pack_dir
    from nexusrecon.sdk.policy_scaffolder import (
        CANONICAL_PHASES,
        PolicyScaffoldInputs,
        scaffold_policy,
        validate_policy_inputs,
    )

    pack_choice = pack
    if pack_choice is None:
        pack_choice = Prompt.ask(
            "[bold cyan]Pack target[/bold cyan] — 'new' or "
            "path to existing pack",
            default="new",
        )
    if pack_choice == "new":
        is_new_pack = True
        pn = pack_name or Prompt.ask(
            "[bold cyan]New pack name[/bold cyan] (kebab-case)",
        )
        target = _resolve_pack_dir(None) / pn
        pack_slug = pn
    else:
        is_new_pack = False
        target = Path(pack_choice).expanduser().resolve()
        if not (target / "manifest.yaml").exists():
            console.print(f"[red]No manifest.yaml at {target}.[/red]")
            raise typer.Exit(1)
        pack_slug = ""

    if name is None:
        name = Prompt.ask(
            "[bold cyan]Policy slug[/bold cyan] (snake_case)",
        )
    if description is None:
        description = Prompt.ask(
            "[bold cyan]Description[/bold cyan] "
            "(one-line policy summary)",
        )

    if eligible_phases is None:
        console.print(
            "[bold cyan]Eligible phases[/bold cyan] — comma-"
            "separated subset of: "
            + ", ".join(CANONICAL_PHASES)
            + " (empty = every phase)"
        )
        raw = Prompt.ask("eligible_phases", default="")
        phases = [p.strip() for p in raw.split(",") if p.strip()]
    else:
        phases = [p.strip() for p in eligible_phases.split(",") if p.strip()]

    inputs = PolicyScaffoldInputs(
        policy_name=name, description=description,
        max_per_cycle=max_per_cycle, max_total=max_total,
        eligible_phases=phases,
        pack_target=target, is_new_pack=is_new_pack,
        pack_name=pack_slug if is_new_pack else "",
    )
    try:
        validate_policy_inputs(inputs)
        result = scaffold_policy(inputs)
    except (ValueError, FileExistsError, FileNotFoundError) as exc:
        console.print(f"[red]Scaffolding failed:[/red] {exc}")
        raise typer.Exit(1)

    console.print(
        Panel(
            (
                f"[bold green]Policy scaffolded.[/bold green]\n"
                f"  module:    [cyan]{result.policy_module_path}[/cyan]\n"
                f"  manifest:  [cyan]{result.manifest_path}[/cyan]\n"
                + (
                    f"  test:      [cyan]{result.test_path}[/cyan]\n"
                    if result.test_path else ""
                )
                + f"\nSelect at runtime via:\n"
                f"  [bold]nexusrecon run --dispatch-mode {name} ...[/bold]"
            ),
            title="✓ policy new",
            border_style="green",
        )
    )


# ── Phase 4 PR A: NL campaign planner ────────────────────────────────


@app.command()
def plan(
    sentence: str | None = typer.Argument(
        None,
        help=(
            "Natural-language description of the campaign. "
            "When omitted, runs an interactive walk-through."
        ),
    ),
    output_dir: str | None = typer.Option(
        None, "--output-dir", "-o",
        help=(
            "Directory to write scope.yaml + strategy.json. "
            "Omit to print only."
        ),
    ),
    no_llm: bool = typer.Option(
        False, "--no-llm",
        help=(
            "Force the deterministic regex extractor (no LLM "
            "round-trip). Useful in air-gapped runs + tests."
        ),
    ),
    interactive: bool = typer.Option(
        False, "--interactive", "-i",
        help=(
            "Force the interactive walk-through even when a "
            "sentence is provided."
        ),
    ),
) -> None:
    """Convert a natural-language goal into a scope.yaml +
    Strategy. Operator confirmation is REQUIRED before any
    files are written.
    """
    from rich.prompt import Confirm, Prompt

    from nexusrecon.intent import plan_from_intent

    # Acquire the sentence — interactive when not supplied.
    if sentence is None or interactive:
        if sentence is None:
            console.print(
                "[bold cyan]Intent Planner[/bold cyan] — "
                "describe what you want this campaign to do."
            )
            sentence = Prompt.ask(
                "[bold]Intent[/bold]",
                default=sentence or "",
            )
        if not sentence.strip():
            console.print("[red]No intent provided.[/red]")
            raise typer.Exit(1)

    result = plan_from_intent(
        sentence, prefer_fallback=no_llm,
    )

    # Render the proposed plan + warnings.
    intent = result.intent
    console.print(Panel(
        (
            f"[bold]Confidence:[/bold] [cyan]{intent.confidence}[/cyan]\n"
            f"[bold]Targets:[/bold] "
            f"[cyan]{', '.join(intent.targets) or '(none)'}[/cyan]\n"
            f"[bold]Intent categories:[/bold] "
            f"[cyan]{', '.join(intent.intent_categories) or '(none)'}[/cyan]\n"
            f"[bold]Tier ceiling:[/bold] [cyan]{intent.max_tier}[/cyan]\n"
            f"[bold]Stealth profile:[/bold] [cyan]{intent.stealth_profile}[/cyan]\n"
            f"[bold]Dispatch policy:[/bold] [cyan]{intent.dispatch_policy_name}[/cyan]\n"
            f"[bold]Strategy phases:[/bold] "
            f"[cyan]{', '.join(result.strategy.phases)}[/cyan]\n"
            + (f"\n[dim]Rationale:[/dim] {intent.rationale}"
               if intent.rationale else "")
        ),
        title="✓ Parsed intent",
        border_style="cyan",
    ))

    if result.warnings:
        console.print("[yellow]Warnings:[/yellow]")
        for w in result.warnings:
            console.print(f"  ⚠  {w}")

    # Interactive refinements: only ask in interactive mode
    # or when explicitly invoked without a sentence.
    if (sentence and not interactive) and (
        # One-shot mode with a sentence + no output dir: just
        # print.
        not output_dir
    ):
        return

    if output_dir is None:
        if not Confirm.ask(
            "Write scope.yaml + strategy.json?",
            default=False,
        ):
            console.print("[dim]Not written.[/dim]")
            return
        output_dir = Prompt.ask(
            "Output directory",
            default=str(Path.cwd() / "campaigns" / "intent-draft"),
        )

    out_path = Path(output_dir).expanduser().resolve()
    out_path.mkdir(parents=True, exist_ok=True)

    # Final confirmation prompt — Auditability First. Never
    # auto-write from a single LLM-extracted record.
    if not Confirm.ask(
        f"Write to [cyan]{out_path}[/cyan]?", default=True,
    ):
        console.print("[dim]Not written.[/dim]")
        return

    import json as _json
    scope_path = out_path / "scope.yaml"
    strategy_path = out_path / "strategy.json"

    # Strip the meta fields from the scope dict before YAML
    # serialisation, surface them as comments instead.
    scope_dict = dict(result.scope_stub)
    meta_header_lines: list[str] = []
    for meta_key in (
        "_generated_by", "_intent_rationale",
        "_intent_confidence", "_intent_raw",
    ):
        value = scope_dict.pop(meta_key, None)
        if value:
            meta_header_lines.append(f"# {meta_key[1:]}: {value}")

    header = "\n".join(meta_header_lines) + "\n\n" if meta_header_lines else ""
    scope_path.write_text(
        header + yaml.safe_dump(scope_dict, sort_keys=False, default_flow_style=False),
        encoding="utf-8",
    )
    strategy_path.write_text(
        _json.dumps(result.strategy.to_dict(), indent=2, default=str),
        encoding="utf-8",
    )

    console.print(
        Panel(
            (
                f"[bold green]Plan written.[/bold green]\n"
                f"  scope:     [cyan]{scope_path}[/cyan]\n"
                f"  strategy:  [cyan]{strategy_path}[/cyan]\n\n"
                f"Next:\n"
                f"  1. Review [cyan]{scope_path.name}[/cyan] — "
                f"replace REPLACE_ME placeholders.\n"
                f"  2. Launch: [bold]nexusrecon run "
                f"--scope {scope_path}[/bold]"
            ),
            title="✓ nexusrecon plan",
            border_style="green",
        )
    )


# ── Phase 4 PR C: Bidirectional import ────────────────────────────────


import_app = typer.Typer(
    help=(
        "Ingest third-party tool output into a campaign's "
        "Living Graph. Supports STIX 2.1 bundles, Nessus "
        "XML, Nuclei JSON-lines, and generic CSV."
    ),
)
app.add_typer(import_app, name="ingest")


def _resolve_campaign_state_path(campaign_id: str) -> Path:
    """Find a campaign's state.json by ID (re-uses the same
    rglob trick the export command does)."""
    config = get_config()
    output_dir = Path(config.output_dir)
    for candidate in output_dir.rglob(campaign_id):
        if candidate.is_dir():
            sp = candidate / "state.json"
            if sp.exists():
                return sp
    raise FileNotFoundError(f"campaign {campaign_id!r} not found")


def _rebuild_graph_from_state_path(state_path: Path):
    """Common helper for `import` subcommands."""
    from nexusrecon.core.entity_graph import EntityGraph
    data = json.loads(state_path.read_text(encoding="utf-8"))
    graph = EntityGraph.from_state(
        data,
        campaign_id=data.get("campaign_id", ""),
        engagement_id=data.get("engagement_id", ""),
    )
    return graph, data


def _persist_graph_to_state_path(state_path: Path, graph, data: dict) -> None:
    data["entity_graph"] = graph.to_dict()
    state_path.write_text(
        json.dumps(data, indent=2, default=str), encoding="utf-8",
    )


def _print_import_report(report) -> None:
    console.print(
        Panel(
            (
                f"[bold green]Imported via {report.importer}[/bold green]\n"
                f"  source:       [cyan]{report.source_path}[/cyan]\n"
                f"  entities new: [cyan]{report.entities_added}[/cyan]\n"
                f"  merges:       [cyan]{report.entities_merged}[/cyan]\n"
                f"  edges:        [cyan]{report.relationships_added}[/cyan]\n"
                f"  skipped:      [cyan]{report.skipped}[/cyan]\n"
                + (
                    "  by type:      "
                    + ", ".join(
                        f"{k}={v}"
                        for k, v in sorted(report.counts_by_type.items())
                    )
                    + "\n"
                    if report.counts_by_type else ""
                )
            ),
            title="✓ ingest",
            border_style="green",
        )
    )
    for w in report.warnings:
        console.print(f"  [yellow]⚠[/yellow] {w}")


@import_app.command("stix")
def ingest_stix(
    campaign_id: str = typer.Argument(...),
    path: str = typer.Argument(..., help="Path to STIX 2.1 bundle JSON."),
) -> None:
    """Import a STIX 2.1 bundle into a campaign's graph."""
    from nexusrecon.ingest import STIXBundleImporter

    state_path = _resolve_campaign_state_path(campaign_id)
    graph, data = _rebuild_graph_from_state_path(state_path)
    report = STIXBundleImporter().import_file(path, graph)
    _persist_graph_to_state_path(state_path, graph, data)
    _print_import_report(report)


@import_app.command("nessus")
def ingest_nessus(
    campaign_id: str = typer.Argument(...),
    path: str = typer.Argument(..., help="Path to a .nessus XML report."),
) -> None:
    """Import a Nessus XML report into a campaign's graph."""
    from nexusrecon.ingest import NessusImporter

    state_path = _resolve_campaign_state_path(campaign_id)
    graph, data = _rebuild_graph_from_state_path(state_path)
    report = NessusImporter().import_file(path, graph)
    _persist_graph_to_state_path(state_path, graph, data)
    _print_import_report(report)


@import_app.command("nuclei")
def ingest_nuclei(
    campaign_id: str = typer.Argument(...),
    path: str = typer.Argument(
        ..., help="Path to Nuclei JSON-lines (or JSON array) output.",
    ),
) -> None:
    """Import Nuclei output into a campaign's graph."""
    from nexusrecon.ingest import NucleiImporter

    state_path = _resolve_campaign_state_path(campaign_id)
    graph, data = _rebuild_graph_from_state_path(state_path)
    report = NucleiImporter().import_file(path, graph)
    _persist_graph_to_state_path(state_path, graph, data)
    _print_import_report(report)


@import_app.command("csv")
def ingest_csv(
    campaign_id: str = typer.Argument(...),
    path: str = typer.Argument(..., help="Path to a CSV file."),
    entity_type: str = typer.Option(
        ..., "--entity-type",
        help="Entity type column maps to: domain, subdomain, ip_address, email, url, technology, cve.",
    ),
    value_column: str = typer.Option(
        ..., "--value-column",
        help="Name of the column carrying the entity's value.",
    ),
    confidence_column: str | None = typer.Option(
        None, "--confidence-column",
        help="Optional column carrying per-row confidence (0-1 or 0-100).",
    ),
) -> None:
    """Import a CSV file via a declarative column mapping."""
    from nexusrecon.ingest import CSVImporter

    state_path = _resolve_campaign_state_path(campaign_id)
    graph, data = _rebuild_graph_from_state_path(state_path)
    report = CSVImporter().import_file(
        path, graph,
        mapping={
            "entity_type": entity_type,
            "value_column": value_column,
            "confidence_column": confidence_column,
        },
    )
    _persist_graph_to_state_path(state_path, graph, data)
    _print_import_report(report)


# ── Phase 5 PR A: Watch Mode ─────────────────────────────────────────


watch_app = typer.Typer(
    help=(
        "Continuous monitoring: long-running sensors trigger "
        "alerts and (for high-severity events) micro-campaigns "
        "when a campaign's graph changes materially."
    ),
)
app.add_typer(watch_app, name="watch")


@watch_app.command("create")
def watch_create(
    watch_id: str = typer.Argument(..., help="Stable id for this watch."),
    campaign_id: str = typer.Argument(..., help="Campaign id to monitor."),
    parent_domain: str | None = typer.Option(
        None, "--parent-domain",
        help=(
            "ScopeSensor: watch every subdomain of this "
            "parent domain."
        ),
    ),
    entity_type: str | None = typer.Option(
        None, "--entity-type",
        help="ScopeSensor: watch every entity of this type.",
    ),
    interval_hours: float | None = typer.Option(
        None, "--interval-hours",
        help=(
            "TimedSensor: re-fire every N hours regardless "
            "of graph state. May be combined with other "
            "sensor flags."
        ),
    ),
    description: str = typer.Option("", "--description"),
) -> None:
    """Create a new watch."""
    from nexusrecon.watch import (
        ScopeSensor,
        Sensor,
        TimedSensor,
        Watch,
        WatchStorage,
    )

    sensors: list[Sensor] = []
    if parent_domain:
        sensors.append(ScopeSensor(
            sensor_id=f"{watch_id}.parent-{parent_domain}",
            parent_domain=parent_domain,
        ))
    if entity_type:
        sensors.append(ScopeSensor(
            sensor_id=f"{watch_id}.type-{entity_type}",
            entity_type=entity_type,
        ))
    if interval_hours is not None:
        sensors.append(TimedSensor(
            sensor_id=f"{watch_id}.timed",
            interval_seconds=int(interval_hours * 3600),
            description=description or f"Every {interval_hours}h",
        ))
    if not sensors:
        console.print(
            "[red]Need at least one of: --parent-domain, "
            "--entity-type, --interval-hours[/red]"
        )
        raise typer.Exit(1)

    storage = WatchStorage(watch_id)
    if storage.exists():
        console.print(
            f"[red]Watch {watch_id!r} already exists.[/red] "
            f"Use `nexusrecon watch remove {watch_id}` first."
        )
        raise typer.Exit(1)
    watch = Watch(
        watch_id=watch_id,
        campaign_id=campaign_id,
        sensors=sensors,
        description=description,
    )
    storage.save_watch(watch)
    console.print(
        Panel(
            (
                f"[bold green]Watch created.[/bold green]\n"
                f"  id:        [cyan]{watch_id}[/cyan]\n"
                f"  campaign:  [cyan]{campaign_id}[/cyan]\n"
                f"  sensors:   [cyan]{len(sensors)}[/cyan]\n"
                f"  config:    [cyan]{storage.config_path}[/cyan]\n\n"
                f"Run periodically:\n"
                f"  [bold]nexusrecon watch tick {watch_id}[/bold]"
            ),
            title="✓ watch create",
            border_style="green",
        )
    )


@watch_app.command("list")
def watch_list() -> None:
    """List configured watches."""
    from nexusrecon.watch import list_watches

    watches = list_watches()
    if not watches:
        console.print("[yellow]No watches configured.[/yellow]")
        return
    for w in watches:
        console.print(
            f"[cyan]{w.watch_id}[/cyan]  "
            f"campaign=[cyan]{w.campaign_id}[/cyan]  "
            f"sensors={len(w.sensors)}"
            + (f"  — {w.description}" if w.description else "")
        )


@watch_app.command("tick")
def watch_tick(
    watch_id: str = typer.Argument(...),
) -> None:
    """Run one pass of the watch's sensors."""
    from nexusrecon.watch import tick

    result = tick(watch_id)
    if result.errors:
        for e in result.errors:
            console.print(f"[red]✗[/red] {e}")
        if not result.sensors_evaluated:
            raise typer.Exit(1)

    body_lines = [
        f"sensors evaluated: [cyan]{result.sensors_evaluated}[/cyan]",
        f"sensors fired:     [cyan]{result.sensors_fired}[/cyan]",
    ]
    if result.actions:
        for a in result.actions:
            sev = a.action.severity
            color = (
                "red" if sev == "high"
                else "yellow" if sev == "medium"
                else "cyan"
            )
            body_lines.append(
                f"  • [{color}]{sev}[/{color}] {a.action.reason}"
            )
    else:
        body_lines.append("no actions")
    console.print(
        Panel(
            "\n".join(body_lines),
            title=f"watch tick — {watch_id}",
            border_style="cyan",
        )
    )


@watch_app.command("alerts")
def watch_alerts(
    watch_id: str = typer.Argument(...),
    limit: int = typer.Option(20, "--limit", "-n"),
) -> None:
    """Show the most-recent alert history."""
    from nexusrecon.watch import WatchStorage

    storage = WatchStorage(watch_id)
    if not storage.exists():
        console.print(f"[red]No watch {watch_id!r}.[/red]")
        raise typer.Exit(1)
    alerts = storage.read_alerts()
    if not alerts:
        console.print("[yellow]No alerts yet.[/yellow]")
        return
    for record in alerts[-limit:]:
        sev = record.get("severity", "?")
        color = (
            "red" if sev == "high"
            else "yellow" if sev == "medium"
            else "cyan"
        )
        console.print(
            f"[{color}]{sev:<6}[/{color}] "
            f"{record.get('timestamp', '')} "
            f"sensor=[cyan]{record.get('sensor_id', '')}[/cyan] "
            f"{record.get('reason', '')}"
        )


@watch_app.command("remove")
def watch_remove(
    watch_id: str = typer.Argument(...),
    confirm: bool = typer.Option(
        False, "--yes", "-y",
        help="Skip confirmation prompt.",
    ),
) -> None:
    """Delete a watch + all its history."""
    from rich.prompt import Confirm

    from nexusrecon.watch import WatchStorage

    storage = WatchStorage(watch_id)
    if not storage.exists():
        console.print(f"[yellow]No watch {watch_id!r}.[/yellow]")
        return
    if not confirm:
        if not Confirm.ask(
            f"Remove watch [cyan]{watch_id}[/cyan] and all its history?",
            default=False,
        ):
            console.print("[dim]cancelled[/dim]")
            return
    if storage.delete():
        console.print(f"[green]✓ removed[/green] {watch_id}")
    else:
        console.print(f"[red]✗[/red] could not remove {watch_id}")


def main() -> None:
    """Entry point for the nexusrecon CLI."""
    app()


if __name__ == "__main__":
    main()
