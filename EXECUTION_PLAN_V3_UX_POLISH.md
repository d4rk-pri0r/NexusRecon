# NexusRecon v3 — UX Polish Execution Plan

> **Audience:** Sonnet 4.6 with extended thinking.
> **Goal:** Two UX features that emerged from demo feedback.
>   - **Move 1 (TUI):** an interactive menu-driven setup experience so
>     operators don't have to hand-craft scope YAMLs or remember CLI
>     flags. Keyboard-driven, modern aesthetic, themed banner.
>   - **Move 2 (Master Report):** a single cohesive narrative deliverable
>     that rolls up the campaign's intel into a polished document. Only
>     populated sections appear — no blank stubs.
> **Working directory:** `/Users/waifumachine/agentic-osint`
> **Reference spec:** Section 0 of `EXECUTION_PLAN_V2_GOLD_STANDARD.md` —
> codebase conventions are binding (no new abstractions, surgical edits,
> follow existing tool/agent patterns).

---

## 0. Required reading before touching code

1. `ARCHITECTURE.md` — the platform-explainer doc. Familiarize with the
   state model, phase pipeline, agent personas, and report engine. This
   plan assumes you know how the campaign state flows.
2. `EXECUTION_PLAN_V2_GOLD_STANDARD.md` Section 0 — codebase conventions.
3. `nexusrecon/cli/main.py` — the existing CLI surface. The TUI WRAPS
   this; it does not replace it.
4. `nexusrecon/reports/engine.py` — `ReportEngine.generate_all()` orchestrates
   all current reports. The master report becomes a new method on this class.
5. `nexusrecon/graph/agent_executor.py` — agent invocation pattern. The
   master report uses a new agent persona following the same pattern.

---

## Move 1 — Interactive TUI

### Why

Current state: operators must hand-write a scope YAML, remember the
correct CLI flag combinations, and parse output across 17 report files.
Demo feedback: people want to be walked through campaign setup with a
menu-driven interface, not asked to read documentation first.

Goal: a polished, keyboard-driven TUI that:
- Launches with `nexusrecon` (no args) OR `nexusrecon tui`
- Walks through campaign setup as a wizard (multi-step form)
- Validates inputs as they're entered (don't surface errors at run time)
- Displays live campaign progress with a status panel
- Offers post-campaign navigation to reports
- **Does not replace** the existing CLI — both paths must continue to work.

The existing CLI is operationally critical (CI integration, scripts,
remote runs). The TUI is for interactive humans.

### Library choice (PIN THIS)

Use **Textual** (`textual>=0.50.0` from `pip install textual`). Rationale:

- Python-native; consistent with the rest of the platform.
- Shares the `rich` library NexusRecon already depends on.
- Async-friendly — integrates cleanly with `asyncio.run` campaign loop.
- Mature widget set (Input, Select, Button, Header, Footer, DataTable,
  Static, Markdown, ProgressBar).
- CSS-like styling — supports the "hacker-like" theme cleanly.
- Multi-screen wizards via `push_screen` / `pop_screen`.

**Do NOT** use:
- Bubble Tea (Go-only — would require subprocess wrapping)
- Curses directly (too low-level)
- prompt_toolkit (single-screen, no widget composition)
- A custom web UI (out of scope for "TUI")

Add `"textual>=0.50.0"` to `pyproject.toml` `dependencies` and pip-install
in the working venv.

### Architecture

New files:
- `nexusrecon/tui/__init__.py`
- `nexusrecon/tui/app.py` — the `NexusReconApp(textual.app.App)` entry point
- `nexusrecon/tui/screens/welcome.py` — splash + main menu
- `nexusrecon/tui/screens/wizard.py` — multi-step new-campaign wizard
- `nexusrecon/tui/screens/runner.py` — live campaign progress view
- `nexusrecon/tui/screens/results.py` — post-campaign summary + report links
- `nexusrecon/tui/screens/campaigns.py` — list/resume past campaigns
- `nexusrecon/tui/screens/config.py` — show configured API keys (status only, NEVER values)
- `nexusrecon/tui/banner.py` — the themed ASCII banner
- `nexusrecon/tui/app.tcss` — Textual CSS for the theme (colors, borders, animations)

Modify:
- `nexusrecon/cli/main.py` — add `tui` subcommand + default to TUI when
  no subcommand provided. Existing `run`, `validate`, `tools`, etc.
  unchanged.
- `pyproject.toml` — add `textual>=0.50.0` to dependencies.

### Screens (detailed spec)

#### Welcome screen

- Animated ASCII banner (the existing 6-line `NEXUS` block from
  `install.sh` lines 24–32). Place it in `nexusrecon/tui/banner.py` as a
  module-level constant `BANNER`.
- Below the banner: subtitle "Agentic OSINT Orchestration Framework"
  and version string.
- Below that: a status line with quick stats — "89 tools registered ·
  X campaigns on disk · LLM provider: anthropic" — computed at startup.
- Menu options (vertical list, Enter to select):
  - 🎯 **New Campaign** — launches the wizard
  - 🔄 **Resume Campaign** — lists campaigns with `current_phase != phase9` for resume
  - 📊 **View Past Campaigns** — list all campaigns with cost, findings, date
  - 🔧 **Configuration** — show keys configured (names only, NEVER values)
  - 🛠 **Tools** — browse the 89 tools by category, see availability
  - ❌ **Quit** (Ctrl-Q)

- Footer bar with keyboard shortcuts visible: `↑/↓ navigate · Enter
  select · Ctrl-Q quit`.

#### New Campaign Wizard

Multi-step form. Each step validates before allowing "Next". User can
"Back" to revise. State persists across steps until "Run" or "Cancel."

**Step 1 — Engagement metadata**

Fields (all required unless noted):
- Client name (free text)
- Engagement ID (free text, but warn if contains spaces)
- Authorized by (free text, name + organization)
- Authorization date (date picker, default today)
- Start date (date picker, default today)
- End date (date picker, default today + 30 days)
- Signed SOW SHA-256 hash (free text, validates 64-hex char OR
  accepts `placeholder` literal for testing). If user types
  `placeholder`, fill in 64 zeros automatically.

**Step 2 — Target & scope**

- Seed domain (free text, single value initially). Validate it's a
  plausible domain (regex: `^([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}$`).
- Additional in-scope domains (optional, comma-separated free text).
- Out-of-scope domains: pre-populate with the standard CDN/cloud
  wildcards (`*.aws.amazon.com`, `*.cloudfront.net`, `*.azure.com`,
  `*.cloudflare.com`, `*.fastly.net`, `*.akamai.net`, `*.azurewebsites.net`).
  Allow user to add or remove.
- Cloud tenant IDs (optional, advanced — collapsed by default):
  - AWS account IDs
  - GCP project IDs

**Step 3 — Constraints**

- Max tier (Select: T0, T1, T2, T3). Default T2. Description shown
  below: "T0 passive only · T1 light fingerprinting · T2 active
  scanning · T3 intrusive (rarely authorized)."
- Stealth profile (Select: low, medium, high). Default high.
- Max LLM cost USD (number input, default 20.0).
- Allow breach DB lookup (toggle, default on).
- Allow paid APIs (toggle, default on).

**Step 4 — Run options**

- Mode (Select: light, medium, deep, monitor). Default medium.
  Description: "light=fast/cheap · medium=balanced · deep=thorough+slow · monitor=watch over time."
- Dispatch mode (Select: lite, full, off). Default lite. Description:
  "lite=dispatcher after phases 1/4/7 · full=after every phase ·
  off=no dispatcher."
- Validate harvested credentials (toggle, default off). Description:
  "Validates credentials via read-only API calls (AWS sts, GitHub /user).
  Only set if you understand the OPSEC implications."
- Generate phishing drafts (toggle, default off). Description:
  "Generates per-target spearphishing email drafts. Requires
  harvested emails. Authorized engagements only."

**Step 5 — Review**

Show a summary table of all selected values. Highlight any unusual
choices (e.g., T3 selected, or no LLM key configured). Buttons:
- **[Save Scope & Run]** — writes the scope YAML to a tempfile, validates
  it via `ScopeModel.from_yaml`, then launches the campaign and
  transitions to the runner screen.
- **[Save Scope Only]** — writes the scope YAML to a user-specified path
  (with a path-input modal) without running.
- **[Back]** — return to step 4.
- **[Cancel]** — discard wizard state, return to main menu.

#### Runner screen

Live campaign progress. Layout:

```
┌─ NEXUS RECON · Campaign nr-20260513-... ─────────────────────┐
│                                                                │
│  Phase: 4/9 — Correlation & Hypothesis                        │
│  ████████████░░░░░░░░░░░░  44%                                │
│                                                                │
│  Findings:        23     Ranked threats:   pending             │
│  Subdomains:     78      Emails:           10                  │
│  Cloud:          1 verified                                    │
│  LLM cost:       $0.81 / $20.00 budget                         │
│                                                                │
├─ Recent activity ──────────────────────────────────────────────┤
│  19:42:11  Phase 3 → 4 transition                              │
│  19:42:18  Tool: shodan/<target>  result: 23 hosts             │
│  19:42:22  Tool: virustotal/<target> result: success           │
│  19:42:28  Agent: correlation executed (4 findings)            │
│  19:42:31  Dispatcher: 0 follow-up tools (lite mode, no gap)   │
│                                                                │
├─ Status: Running · Press 'p' pause · 'q' quit · 'r' reports ──┤
└────────────────────────────────────────────────────────────────┘
```

- The progress bar advances as phases complete (1/9 → 2/9 → ...).
- The "Recent activity" section shows the last ~10 log lines streamed
  from the campaign's audit log.
- A small spinner indicates active work.
- Keyboard shortcuts:
  - `q` — abort campaign (with confirm modal)
  - `p` — pause (not in scope for v1; show "Pause not yet implemented")
  - `r` — once the campaign completes, transition to results screen
  - `Esc` — return to main menu (only after completion)

The campaign runs in a `asyncio.Task` started by the runner screen. The
TUI subscribes to a `state_update` channel that the campaign emits on
each phase transition / tool result / agent execution. Use Textual's
`call_from_thread` or `post_message` to push UI updates from the campaign coroutine to the screen.

**Implementation detail:** the existing `_run_campaign_phases` in
`cli/main.py` is the campaign loop. Refactor it into a thin wrapper that
both the CLI and the TUI can call, with an optional `on_event` callback
that the TUI provides to receive progress updates. The callback is fired
on phase transitions, tool starts/ends, and agent executions.

#### Results screen

Shown when the campaign completes. Layout:

```
┌─ Campaign Complete · nr-20260513-... ──────────────────────────┐
│                                                                │
│  ✓ All phases completed                                        │
│  ✓ 38 findings · 10 ranked threats                             │
│  ✓ $1.97 LLM spend · 0 errors                                  │
│  ✓ Audit chain: VALID                                          │
│                                                                │
├─ Top 3 threats ────────────────────────────────────────────────┤
│  1. [HIGH] M365 Managed Authentication - Password Spray ...    │
│  2. [HIGH] Executive Email Cluster Identified ...              │
│  3. [HIGH] Azure Managed Federation Enables ...                │
│                                                                │
├─ Reports ──────────────────────────────────────────────────────┤
│  📋 Master Report          (open with 'm')                     │
│  🎯 Top Threads             (open with 't')                     │
│  📊 Executive Summary       (open with 'e')                     │
│  🎣 Phishing Drafts         (open with 'p') [if --generate-phishing] │
│  🔑 Harvested Credentials   (open with 'c') [if --validate-creds]   │
│  📁 All Reports             (open dir with 'a')                 │
│                                                                │
├─ Status: Done · Esc back to menu · q quit ─────────────────────┤
└────────────────────────────────────────────────────────────────┘
```

- Each key shortcut (`m`, `t`, `e`, etc.) launches the file in the
  user's `$EDITOR` (or `open` on macOS, `xdg-open` on Linux) via
  `subprocess.Popen`.
- "All Reports" opens the campaign's reports directory in the file
  manager.

#### Past Campaigns screen

A `DataTable` listing all campaigns on disk:
- Campaign ID
- Engagement ID
- Client
- Date (from campaign_id timestamp)
- Status (phase reached / Complete / Failed)
- Findings count
- LLM cost

Sortable by clicking column headers. Enter on a row → results screen for
that campaign.

#### Configuration screen

Two-column display:
- **API Keys** (left column): every recognized key name (read from
  `Config` field list), with status: `✓ configured` or `✗ not set`.
  **NEVER show values, just configured-or-not status.**
- **External Binaries** (right column): each binary the tools use, with
  `✓ installed at /path/...` or `✗ not on PATH`.

Read-only. Editing requires editing `.env` outside the TUI (and the
screen says so).

#### Tools screen

A `DataTable` of all 89 tools, columns:
- Name
- Category
- Tier
- Status (`✓ available`, `✗ key missing`, `✗ binary missing`)
- Description (truncated to 80 chars)

Filterable by category via a top-bar `Select`. Search by name via `/`
keyboard shortcut.

### Theming

CSS file at `nexusrecon/tui/app.tcss`. Use a dark, terminal-hacker
aesthetic:

- **Base palette:**
  - Background: `#0a0e1a` (deep navy near-black)
  - Foreground: `#c9d1d9` (off-white)
  - Accent primary: `#00ff9c` (terminal green)
  - Accent secondary: `#ff5555` (alert red)
  - Accent tertiary: `#1f6feb` (electric blue)
- **Borders:** double-line (`╔═╗ ║ ╚═╝`) for major panels, single-line
  for inner panels.
- **Banner:** monospace, accent green. Optional CSS animation: a subtle
  "scanline" effect using textual's CSS animation API. Don't go
  overboard — animation should be subtle, not distracting.
- **Severity colors:** critical `#ff3838`, high `#ff8c00`, medium
  `#f1c40f`, low `#5dade2`, info `#7f8c8d`.

### Required campaign-loop refactor

`cli/main.py`'s `_run_campaign_phases()` function needs to be extracted
into a reusable callable so both the CLI and the TUI can invoke it.
Suggested signature:

```python
# nexusrecon/core/campaign_runner.py
async def run_campaign(
    state: CampaignGraphState,
    campaign: CampaignManager,
    scope_model: ScopeModel,
    on_event: Optional[Callable[[Dict[str, Any]], None]] = None,
) -> CampaignGraphState:
    """
    Run the campaign through all authorized phases.

    on_event is called with dict events on phase transitions, tool
    starts/ends, agent executions, and reflection_node dispatch decisions.
    Used by the TUI to update its live progress display.
    """
```

The CLI's existing path becomes a call into this function with
`on_event=None` (no UI updates). The TUI calls it with an event handler
that pushes Textual messages to the runner screen.

Event payloads:
```python
{"type": "phase_start", "phase": "phase1", "name": "Passive Footprinting", "timestamp": "..."}
{"type": "phase_end", "phase": "phase1", "findings_count": 7, "timestamp": "..."}
{"type": "tool_start", "tool": "crtsh", "target": "<seed>", "timestamp": "..."}
{"type": "tool_end", "tool": "crtsh", "success": True, "result_count": 28, "runtime_ms": 1850}
{"type": "agent_executed", "agent": "passive_recon", "phase": "phase1", "new_findings": 7, "cost_usd": 0.18}
{"type": "dispatch_decision", "phase": "phase1", "dispatched": 5, "rationales": [...]}
{"type": "campaign_complete", "campaign_id": "...", "total_findings": 38, "total_cost_usd": 1.97}
{"type": "campaign_error", "phase": "phase4", "error": "..."}
```

### Acceptance criteria for Move 1

1. `nexusrecon` (no args) launches the TUI; `nexusrecon tui` is
   equivalent.
2. `nexusrecon run --scope X.yaml --mode light` (existing CLI) still
   works unchanged. CI/script users see no regression.
3. Wizard validates each field as it's entered (no error surfacing only
   at submit).
4. After completing the wizard with valid inputs, a campaign launches
   and the runner screen shows live progress with phase counter, cost
   meter, and recent-activity tail.
5. After campaign completion, the results screen shows top 3 threats
   and offers `m/t/e/p/c/a` keyboard shortcuts to open reports.
6. The configuration screen shows API-key NAMES only (never values).
7. Ctrl-Q from any screen returns cleanly to the terminal without
   leaving the TUI's alternate screen buffer active.
8. The TUI does NOT crash when the terminal is too small to display
   the banner (gracefully degrade to a one-line title).
9. Running in a non-TTY environment (`echo "" | nexusrecon`) detects
   the environment and falls back to the CLI with a clear message:
   `[info] No TTY detected — falling back to CLI. Use 'nexusrecon run --help' for options.`

### Pitfalls

- **Async integration:** Textual is async; the campaign loop is async;
  asyncio.run() in the wrong place will deadlock. Use Textual's
  `App.run_async()` and have the campaign run as a Task on the same loop.
- **Dependency injection for testing:** avoid hardcoding `subprocess`,
  config paths, or asyncio creation inside the TUI screens — pass them
  via constructor args or context so the screens are unit-testable.
- **Tempfile scope:** the wizard's "Save Scope & Run" path writes the
  YAML to a temp file. If the campaign launches successfully, write a
  copy to `campaigns/<campaign_id>/scope.yaml` for audit. If user
  cancels, delete the temp file.
- **Banner ASCII can break on non-UTF-8 terminals.** Detect terminal
  capabilities via `os.environ.get("TERM")` and fall back to a plain
  text banner if needed.
- **Don't import textual at the module level of `cli/main.py`** — only
  import inside the `tui` subcommand handler. This keeps the existing
  CLI fast and lets users skip textual if they only use CLI flags.

---

## Move 2 — Master Report

### Why

Current state: 17 separate report files, each accurate but
disconnected. Executive summary is one-page; full_report.md is
comprehensive but mechanical. The operator delivering this to a client
must mentally stitch the documents together.

Goal: a single cohesive narrative document — `master_report.md` — that
reads top-down as a story, deeper than the executive summary but
cleaner than the file sprawl. Only sections with content appear (no
"Section X: No data found" stubs).

This is the document an operator hands a client when they want one file
that explains everything that was found and what it means.

### Architecture

New agent persona:
- `nexusrecon/agents/master_reporter.py` — class `MasterReporterAgent` with
  `agent_name = "master_reporter"`, role/goal/backstory crafted for
  cohesive narrative synthesis.

New report-engine method:
- `nexusrecon/reports/engine.py` — add `_master_report(state)` method
  invoked from `generate_all()` as the LAST report (so it can reference
  paths of all earlier reports). Returns the path to the generated
  `master_report.md`.

The method:
1. Gathers all relevant state slices.
2. Determines which sections have content (skip-empty logic).
3. Calls the `master_reporter` agent once per major section (or once
   total — see "Synthesis approach" below).
4. Assembles the final markdown with the operator-facing structure
   below.

### Document structure (10 sections, skip-empty logic)

**Always present:**

1. **Cover & metadata**
   - Campaign ID, engagement ID, client name
   - Generation timestamp, scope hash
   - Headline counters: findings count, top severity, ranked threats count
   - Authorization banner (1 line: "Authorized engagement under SOW
     <hash>. Audit log: <path>.")

2. **Executive Brief** (narrative prose, 200–400 words, LLM-synthesized)
   - One paragraph: what was discovered (intent, scope, scale)
   - One paragraph: what it means in operational terms
   - 3–5 bullet "key risks" or "principal findings"
   - Single LLM call from `master_reporter` agent with all state context

3. **Top Threads to Pull**
   - Embedded full content from `top_threads.md` (not linked — this IS
     the action list)

**Conditional (appear only if content exists):**

4. **Attack Surface at a Glance** — only if any of these have content:
   - **Identity**: emails harvested, M365 / Azure tenant status, breach
     posture. Skip individually if empty.
   - **Cloud**: providers detected with attribution_confidence ≥ 0.5.
     Skip if no verified cloud.
   - **Code & Secrets**: repos found, leaked secrets count, exposed
     configs. Skip if no code_intel.
   - **Network**: subdomains count, exposed services, TLS posture, WAF
     status. Skip if no infra_intel.

5. **Identified Personas** — only if emails harvested:
   - Executive cluster (high-value targets) with role/department
   - Department breakdown (count by dept)
   - Phishing draft availability ("10 per-target drafts generated; see
     `phishing_drafts.md`")

6. **Vulnerability Correlation** — only if `vuln_intel.enriched_cves`
   is non-empty:
   - Live CVE list with exploit availability
   - KEV-listed CVEs called out separately
   - Tech-version evidence

7. **Harvested Credentials** — only if `harvested_credentials` is
   non-empty:
   - Summary count by type, validation status
   - Redacted samples (never raw values — use the existing redaction
     format from `harvested_credentials.md`)

8. **Pretext & HUMINT** — only if `pretext_intel` is non-empty:
   - Recent news/jobs/SEC filings relevant for social engineering
   - LinkedIn dork list (or live search results if BING_SEARCH_API_KEY)

9. **Evidence & Provenance** (always present):
   - Scope hash, audit chain status (`VALID` or `BROKEN`)
   - Tools used: count, success/fail breakdown
   - Cost ledger: LLM cost, tool cost (if tracked)

10. **Recommendations** (always present, LLM-synthesized prose)
    - 5–10 prioritized actions
    - Each cites specific finding IDs by short reference
    - References tools the operator should run next (with `--mode deep`
      hints, exploit paths, etc.)

11. **Appendix: Deeper reading** (always present)
    - "For per-target phishing drafts, see `phishing_drafts/`"
    - "For the complete findings JSON, see `findings.json`"
    - "For the interactive entity graph, see `entity_graph.html`"
    - Generated dynamically based on what reports exist.

### Skip-empty logic (PIN THIS)

The discriminator for each conditional section is the underlying state
slot's content, not the section title. Concrete rules:

- **Identity subsection**: include if `len(state["email_intel"]["emails"]) > 0`
  OR `state["cloud_intel"]` has any entry with `attribution_confidence >= 0.5`
  AND `openid_config.found`.
- **Cloud subsection**: include if any `cloud_intel` entry has
  `attribution_confidence >= 0.5`.
- **Code subsection**: include if `state["code_intel"]` has any
  non-empty value.
- **Network subsection**: include if `len(state["subdomain_intel"]) > 0`
  OR `state["infra_intel"]` non-empty.
- **Personas section**: include if `len(state["email_intel"]["emails"]) > 0`.
- **Vulnerability section**: include if `len(state["vuln_intel"].get("enriched_cves", {})) > 0`
  OR `state["vuln_intel"].get("nuclei_scan", {}).get("findings", [])`.
- **Credentials section**: include if `len(state.get("harvested_credentials", [])) > 0`.
- **Pretext section**: include if `state.get("pretext_intel")` is
  non-empty AND has at least one populated tool result.

For each section: NO PLACEHOLDER. If the section is skipped, the
heading does not appear at all. The Section 4 "Attack Surface at a
Glance" parent heading appears only if at least one of its four
subsections has content.

### Synthesis approach

The narrative prose sections (Executive Brief, Recommendations, and the
intro paragraphs of Attack Surface subsections) come from the
`master_reporter` agent. Two implementation options:

**Option A — Single large LLM call (recommended).** The agent receives
all state plus a structured prompt that says "produce a markdown
document with these sections; skip sections X, Y, Z because they're
empty." The agent returns the full document text. Cost: $0.30–$0.60 per
campaign depending on state size. Simplest to implement.

**Option B — Multiple smaller LLM calls.** The agent is called once per
narrative subsection. Cost: similar total, but more API requests. More
control over individual section quality. Slightly more complex.

**Choose Option A unless you find the LLM truncates output on large
state.** If truncation happens (response cut mid-section), fall back to
Option B for the truncating section.

### Files to create / modify

Create:
- `nexusrecon/agents/master_reporter.py` — agent class with role/goal/
  backstory and the system prompt for cohesive synthesis.

Modify:
- `nexusrecon/reports/engine.py` — add `_master_report(state)` method;
  call from `generate_all()` LAST (so all other reports exist for
  appendix linking). Add `"master_report"` to the `self.report_paths`
  dict.
- `nexusrecon/graph/agent_executor.py` — add `"master_reporter":
  MasterReporterAgent` to the `_AGENT_ROLES` registry table so the
  agent can be invoked via `executor.run_agent("master_reporter", ...)`.
  Add `"master_reporter"` to `_SKIP_FINDINGS_JSON_AGENTS` (it's a
  report-writer, not a findings-emitter).
- `nexusrecon/docs/REPORT_GUIDE.md` — add an entry for the master
  report explaining when to use it vs. the other reports.

### MasterReporterAgent system prompt (use this verbatim as the agent's role)

```
You are the chief synthesist for a NexusRecon OSINT campaign. Your job
is to produce a single cohesive narrative report — one document an
operator can hand to a client.

Your voice:
- Authoritative but not alarmist
- Specific, not vague
- Operationally focused: what was found, what it means, what to do
- Cites findings by their actual title or category, not "finding #7"

You ALWAYS:
- Include section headings exactly as specified in the structure prompt
- SKIP any conditional section the operator marks as empty — do not
  write "No data" placeholders
- Quote specific values (subdomain count, tenant ID, etc.) from the
  state, never invent numbers
- Tag low-attribution-confidence findings with [POSSIBLE] prefix when
  you reference them in prose

You NEVER:
- Repeat the executive summary verbatim in the recommendations
- Invent attack chains the platform did not discover
- Use generic boilerplate ("This represents a significant risk to
  the organization")
- Recommend exploits beyond what the platform has scored as viable
```

### Acceptance criteria for Move 2

1. A campaign on a thin target (`testphp.vulnweb.com`) produces a
   `master_report.md` with sections 1, 2, 3, 9, 10, 11 only —
   conditional sections 4–8 are absent (no headings appear).
2. A campaign on a rich target (your own authorized test domain)
   produces a master report with most or all of sections 4–8 populated,
   each with the underlying-state numbers correctly cited.
3. The master report's Executive Brief and Recommendations sections
   contain real LLM-synthesized prose (not boilerplate), with specific
   citations to findings from `state["findings"]` and `state["ranked_threads"]`.
4. The "Top Threads to Pull" section embeds the same content as
   `top_threads.md` (verify by checking the section count matches the
   number of ranked threads).
5. The Appendix dynamically generates pointers to the reports that
   actually exist (phishing_drafts/ link only appears if phishing draft
   files exist).
6. `master_report` appears in `generate_all()`'s return dict.
7. `_SKIP_FINDINGS_JSON_AGENTS` includes `master_reporter` (verified by
   the report not containing a `FINDINGS_JSON:[...]` block).
8. The master report's total cost is < $1.00 per campaign on a typical
   real target.

### Pitfalls

- **Context overflow.** A rich-target campaign's state can be 100KB+
  of JSON. Don't dump the whole thing in the prompt. Build a
  TRIMMED context object containing only the slices the agent needs:
  ranked_threads (full), email_intel.emails (first 20), cloud_intel
  (key fields), top 10 agent_messages by length, vuln_intel.enriched_cves
  (first 10), state.findings (titles + severity only — full descriptions
  are in linked reports).
- **Skip-empty bugs.** Test specifically with a campaign that has email
  intel but no cloud, vs. cloud but no email. Don't just test rich + thin.
- **Cited findings drift.** When the LLM references "finding #N" or
  "the Azure password spray finding," verify the cited finding actually
  exists in state at the time of generation. If not, log a warning and
  don't include the citation.
- **Attribution gating in the master report.** Findings with
  `attribution_gated=True` must be prefixed `[POSSIBLE]` in the master
  report just like they are in other reports. Pass this through to the
  agent prompt.

---

## Sequencing & dependencies

**Recommended order:** Move 2 (Master Report) first, then Move 1 (TUI).

Rationale:
- Move 2 is more self-contained — touches `reports/`, `agents/`,
  `graph/agent_executor.py`, and adds one new agent. Doesn't require
  changing the CLI surface.
- Move 1 (TUI) benefits from Move 2 because the TUI's results screen
  links to `master_report.md` as the primary post-campaign deliverable.
- If you must split into two Sonnet sessions due to context budget,
  Move 2 in session 1, Move 1 in session 2.

---

## Working rules (apply to both moves)

1. **Read `ARCHITECTURE.md` + Section 0 of `EXECUTION_PLAN_V2_GOLD_STANDARD.md`
   before touching code.** No new abstractions. No compat shims. No
   multi-paragraph docstrings. Surgical edits.

2. **After every edit batch**:
   ```bash
   python3 -m py_compile $(find nexusrecon -name '*.py')
   ```

3. **Add new deps to `pyproject.toml` AND pip-install in the venv**:
   ```bash
   /Users/waifumachine/agentic-osint/venv/bin/pip install -e .
   ```

4. **Do NOT create git commits.** Operator commits manually after review.

5. **Do NOT install system binaries.** PyPI dependencies are fine.

6. **Parallel tool calls for independent edits.** Don't serialize work
   that has no dependency.

7. **If a fix requires an architectural decision not specified here, STOP
   and ask the operator before guessing.** The specs are explicit;
   deviations matter.

8. **Verification REQUIRES end-to-end runs, not just unit tests.** Specifically:
   - **Move 2 verification**: run a `--mode light --dispatch-mode off`
     campaign against `testphp.vulnweb.com` and verify the
     master_report.md has correct section omissions for a thin target.
     Then if the operator has set up an authorized rich target, run
     against that and verify section population.
   - **Move 1 verification**: launch the TUI manually
     (`nexusrecon` with no args), walk through the wizard, launch a
     campaign, verify the runner screen updates, hit `m` on results
     screen to open master_report.md.
   - Intermediate log lines are NOT acceptance evidence. State file or
     output file inspection is.

9. **Mark fixes complete in `ITERATION_BACKLOG.md`** — these features
   don't have bug IDs (they're features, not bugs). Append a section
   `## Features Shipped` at the bottom of the backlog with one-line
   entries.

10. **End-of-turn report under 25 lines.** Files changed, verification
    summary (paths to generated artifacts you inspected), any deviations
    from spec or open questions.

---

## Verification (run after both moves)

```bash
cd /Users/waifumachine/agentic-osint

# Compile check
python3 -m py_compile $(find nexusrecon -name '*.py')

# Move 2 — thin-target campaign
env -u ANTHROPIC_API_KEY /Users/waifumachine/agentic-osint/venv/bin/nexusrecon run \
  --scope examples/scopes/minimal_seed.yaml \
  --mode light --dispatch-mode off
# Confirm:
CAMP=$(ls -td campaigns/*/*/*/ | head -1)
ls "${CAMP}/reports/master_report.md"   # exists
# Manually inspect:
#   - Sections 1, 2, 3, 9, 10, 11 present
#   - Sections 4-8 absent (no headings)
#   - No "No data" or boilerplate placeholders
#   - Top threads section has real content

# Move 1 — TUI launch (interactive — operator must verify)
nexusrecon       # should launch the TUI
nexusrecon tui   # equivalent
# Walk through wizard, launch campaign, check progress, open reports

# CLI regression check (must still work)
nexusrecon run --scope examples/scopes/minimal_seed.yaml --dry-run
nexusrecon tools | head -10
nexusrecon validate examples/scopes/minimal_seed.yaml
```

---

## Out of scope (do NOT do)

- Don't rewrite the existing reports — they coexist with the master
  report.
- Don't add a web UI / Streamlit dashboard.
- Don't refactor the agent_executor's prompt building (it's working).
- Don't add new tool integrations.
- Don't move to a different async framework.
- Don't restructure the campaign state schema.
- Don't add new CLI commands beyond `tui`.
- Don't change the existing scope YAML schema.
- Don't add tests for the TUI itself (Textual TUI testing is finicky;
  skip for v3 and revisit if it becomes a maintenance pain).

---

## Estimated effort

- Move 2 (Master Report): ~4 hours autonomous Sonnet work
  - 1h: agent persona + prompt design + integration
  - 1h: `_master_report()` method + skip-empty logic
  - 30min: REPORT_GUIDE.md update
  - 1.5h: verification runs + bug fixes from real-target test

- Move 1 (TUI): ~8 hours autonomous Sonnet work
  - 2h: app scaffold + welcome screen + main menu
  - 2.5h: wizard (5 steps + validation)
  - 1.5h: runner screen with live event integration
  - 1h: results + past-campaigns + config + tools screens
  - 1h: theming, banner, polish

**Total: ~12 hours.** Budget ~30% rework for Textual async edge cases
and skip-empty logic bugs the rich-target test surfaces.

---

## Hand-off prompt for Sonnet

```
You are implementing two UX features for NexusRecon. The full spec is
in EXECUTION_PLAN_V3_UX_POLISH.md at /Users/waifumachine/agentic-osint/.
Section 0 of EXECUTION_PLAN_V2_GOLD_STANDARD.md and the codebase
conventions therein are binding.

Working directory: /Users/waifumachine/agentic-osint

Read ARCHITECTURE.md and EXECUTION_PLAN_V3_UX_POLISH.md in full before
touching code. Then implement Move 2 (Master Report) FIRST, then Move 1
(TUI), per the sequencing rationale in the v3 plan.

Working rules (also listed in the plan):
1. No git commits — operator commits manually
2. No system binary installs (PyPI fine)
3. Surgical edits — don't refactor adjacent code
4. Stop and ask on architectural ambiguity (don't guess)
5. Parallel tool calls for independent edits
6. End-of-turn report under 25 lines per move

Verification REQUIRES end-to-end runs, not just unit tests:
- Move 2: run a campaign against testphp.vulnweb.com and confirm
  master_report.md has skip-empty logic working correctly. Inspect the
  generated file directly.
- Move 1: launch the TUI manually with `nexusrecon` (no args), walk
  through the wizard, launch a campaign, verify the runner screen
  shows live updates, confirm reports open from the results screen.

Begin by reading the plan in full, then state your fix order and which
acceptance criteria you'll verify against, then proceed.
```
