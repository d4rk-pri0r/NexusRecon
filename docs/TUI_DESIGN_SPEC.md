# NexusRecon TUI — Best-of-Breed Design Specification

**Status:** Architectural reference. Drives the TUI-2..TUI-6 implementation
phases. Last updated 2026-05-21.

---

## 1. Executive Vision

NexusRecon's TUI is the operator's command surface for hours-long
recon engagements. Today it works but doesn't *feel like* the tool a
red-teamer reaches for at 2am to triage a 500-finding scope. The
goal of this spec is to transform it from "functional Textual app
that does the job" into the **k9s of OSINT recon** — a dense,
keyboard-first, mode-aware command surface that operators choose
over a GUI even when one exists, and that visibly elevates the
project's perception alongside its technical capability.

The transformation rests on five load-bearing shifts:

1. **From linear push/pop navigation to a persistent dashboard
   shell.** Welcome → Wizard → Runner → Results today is a one-way
   funnel; an operator who's mid-campaign and wants to glance at
   config has to abandon what they're watching. The redesigned
   shell keeps a sidebar + main pane + status bar visible at all
   times; everything is one keystroke away.
2. **From hidden surface to discoverable command palette.**
   `Ctrl+P` / `:` opens fuzzy search across every action, tool,
   campaign, report, and config key. Operators learn the system
   by typing what they want; the palette teaches the bindings.
3. **From single-shot tail logs to a queryable activity surface.**
   The runner's append-only log loses context the moment a phase
   header scrolls off. The new activity surface supports
   scrollback, regex filter, jump-to-phase, and persists a
   pause-tail toggle so operators can read what just happened
   without killing the campaign.
4. **From external-editor reports to in-TUI markdown preview.**
   Every deliverable gets a side-by-side preview pane in the
   results browser. Operators can triage findings without
   context-switching to VS Code.
5. **From "no theme story" to a semantic colour language.** Two
   themes already ship; this spec formalises the colour tokens
   (severity, status, focus, surface depth) so every screen
   speaks the same visual grammar and operators can read severity
   at peripheral-vision distance.

The current TUI is a 3000-line Textual app with seven screens. This
spec keeps the framework (a Rust/Go rewrite is not justified) and
deliberately preserves the screens that are working
(`EditKeyModal`, `EnvFile` data layer, `ConfigScreen` two-pane
pattern). Everything else gets reframed inside a persistent shell.

---

## 2. Research & Inspiration Summary

Synthesised from `awesome-tuis` plus operator-tool deep-dives.
Specific patterns I'm borrowing, with their source:

### k9s (Kubernetes operator UX gold standard)
- **Persistent context header** — current cluster + namespace
  always visible. Operators never lose situational awareness.
- **`:` command mode** — `:pod`, `:svc`, `:ns prod` jumps between
  resource types instantly. Discovers the whole API surface by
  typing.
- **Inline filter (`/`)** — every list view supports regex filter
  with no modal; type to narrow, Esc to clear.
- **Action shortcuts** — single-key actions (`d` describe, `e`
  edit, `l` logs) for the focused row. No menus.
- **Yes/No confirms** — destructive actions always two-step but
  inline (no modal), bound to `y`.

### lazygit
- **Multi-pane focus model** — Tab cycles between four panes
  (files, branches, commits, log). Active pane gets the cursor
  + accent border; others remain readable.
- **Contextual right-side detail** — selected commit/diff renders
  in the right pane without push/pop.
- **Mouse + keyboard** — both work; neither is required.

### btop++
- **Gradient bars for resource meters** — colour shifts cool → hot
  as utilisation climbs. Communicates intensity faster than a
  percentage. We adopt this for **LLM budget consumption** and
  **phase progress within long phases**.
- **Smooth tick-based animations** — sub-second redraw; the UI
  feels alive even when idle.

### posting (HTTP client)
- **Saved request library** with hierarchical folders. We adapt
  this for **scope-file presets** in the wizard.
- **Theme picker in-app** with live preview.
- **Form fields with inline validation messages** — red underline
  + tooltip when a value's wrong. We adopt this for the wizard's
  per-field validation.

### harlequin (SQL IDE)
- **Markdown / table previews inline** — query results render
  with severity-coloured cells. We adopt this for finding
  triage and report preview.

### atuin
- **Fuzzy command palette with type-ahead** — backbone of every
  modern operator tool. Drives our `Ctrl+P` design.

### Textual (framework choice — keep)
- **Reactive widgets** out of the box (no manual redraw).
- **`run_test()` pilot harness** lets us regression-test TUI
  behaviour in pytest (already shipped in TUI-1).
- **Built-in `MarkdownViewer`** for in-TUI report preview.
- **Theme system** with custom variables (already wired in TUI-1).
- **`DataTable` with virtual scrolling** scales to 10K+ rows.
- **CSS-styled widgets** mean a designer can iterate without
  touching Python.

### Frameworks rejected (and why)
- **Ratatui (Rust)** — would require rewriting 3000+ lines, plus
  losing CrewAI/LangGraph access from the same process. The TUI
  is not the bottleneck.
- **Bubble Tea (Go)** — same rewrite cost; Go's interop with the
  Python AI stack is non-trivial.
- **Rich (Python, no Textual)** — Rich is the rendering layer
  underneath Textual; using it alone means rebuilding screens,
  navigation, and modals from scratch.

**Decision: stay on Textual. Invest in the shell architecture.**

---

## 3. Current State Analysis

Quoting the audit verbatim where it's load-bearing; my judgements
in *italics*.

### Strengths to preserve
- **`EnvFile` + `ConfigSchema`** — the data layer is well
  separated from widgets; the two-pane Config screen pattern is
  sound. *Don't touch.*
- **`ChunkyBar`** — bespoke wide progress widget. *Generalise it
  into a "gauge" component used wherever a meter is needed (LLM
  budget, phase progress, tool-fan-out).* 
- **Pre-warm on welcome mount** — heavy imports (CrewAI, LangGraph,
  LiteLLM) preload in a thread while the operator reads the
  banner. *Keep; extend pattern to other slow-to-load screens.*
- **Per-session log file + structlog rerouting** — campaign
  diagnostics go to disk where Textual can't smash them, AND
  the runner's detail panel tails the same file. *Keep.*
- **Stub-tool policy** (from earlier work) — registry already
  flags stubs; TUI just needs to surface them in the new tools
  browser.

### Weakest signals (from the audit, paraphrased)

1. **Activity/Detail logs are append-only, non-searchable, no
   scrollback.** Phase headers scroll out of view; an operator
   with a question about what phase 4 did mid-campaign has no
   way to go back without killing the run and grepping the log
   file offline.

2. **No intermediate state persistence between screens.** Wizard
   answers vanish if you navigate back. Reports button on runner
   says "not ready" but doesn't queue an auto-jump-when-done.

3. **Config validation deferred to runtime.** Operator saves a
   malformed key; campaign blows up 30s in with a cryptic
   message. No client-side regex / shape check.

4. **Linear push/pop navigation.** Welcome → Wizard → Runner →
   Results is a funnel. To check config while a campaign runs
   the operator must abandon the runner view.

5. **No global search / command palette.** Discovery of bindings
   is via the Footer or the new `?` help. There's no way to type
   "show me the credential punch list" and jump there.

6. **Reports open in external editor.** Triaging 17 deliverables
   means 17 context switches. The TUI loses the operator the
   moment the campaign finishes.

7. **Tools screen is a flat list of 97 entries.** No filter, no
   category grouping (in the menu), no search, no detail pane.
   Operators can't quickly answer "which tools need a key I haven't
   set?"

8. **Wizard has no validation feedback as you type.** Errors only
   surface on Next. Long forms with deferred validation are a
   known UX anti-pattern.

9. **No persistent status of in-progress campaigns.** If a
   campaign is running and the operator escapes to the welcome
   screen, there's no breadcrumb showing "campaign X is at
   phase 4, $2.40 spent." They have to remember.

10. **Single visual hierarchy.** Severity, focus, and status all
    compete for the same accent colour. A critical finding and a
    button highlight look alike at a glance.

---

## 4. Core Workflows → Proposed TUI Treatment

Eight workflows drive everything an operator does. Each gets a
target UX, the patterns it borrows, and the trade-off considered.

### 4.1 Launch a new campaign

**Today:** 5-step wizard, modal Select fields, validation on
Next. Press Save & Run, get pushed onto Runner.

**Proposed:** Same 5 steps, but with:
- **Live validation** — every Input has a tiny status icon
  (`✓` valid, `✗` invalid, `…` pending) that updates as the
  operator types. Errors render inline below the field, not
  in a top-of-step banner.
- **Scope file preset library** — Step 2 gains a "Load preset"
  dropdown sourced from `~/.nexusrecon/scope-presets/*.yaml`
  with built-in templates (`oss-recon`, `corp-m365`, `aws-startup`,
  `bug-bounty`). Selecting a preset prefills the form;
  operator can still edit.
- **Sticky summary panel** — right-side pane summarises what's
  been entered so far. Visible from Step 1 onward; updates
  live. Helps when the operator needs to scroll back to verify
  a field on Step 5.
- **Cost preview** — Step 5 (review) computes an estimated LLM
  cost from `mode × dispatch_mode × seed_count × tier`. Surfaces
  in the same gauge widget used elsewhere for budget.
- **Inline scope-file diff** — if the wizard would *modify* an
  existing scope file (e.g., resume + edit), Step 5 shows a
  diff of what's about to change.

**Trade-off considered:** Auto-jumping to runner vs always
returning to dashboard after launch. *Auto-jump wins* — the
operator's intent in pressing Save & Run is "I want to watch
this", and the new persistent shell keeps everything else
reachable without leaving the runner.

### 4.2 Watch a campaign run

**Today:** RunnerScreen with 4 stacked panels (header, stats,
activity, detail). 1Hz tick. Q to abort.

**Proposed:** Same panel structure but with:
- **Scrollable, searchable activity log** — `/` enters filter
  mode (regex), `j`/`k` scroll, Space pauses tail, `g` jumps
  to top, `G` to bottom, `n`/`N` next/prev match.
- **Phase-aware jump nav** — `[` and `]` jump to previous /
  next phase boundary in the activity log.
- **Per-phase mini-gauge** — between the header and stats, a
  thin strip showing per-phase progress (sub-bars within the
  overall progress). On a phase that runs 60s, the operator
  sees the sub-bar tick instead of staring at a frozen overall
  bar.
- **Tool-activity sparklines** — stats panel adds a "currently
  invoking" widget showing the names of tools fired in the
  last 5 seconds with a small spinner per active call.
- **Severity-coloured finding ticker** — bottom-right corner of
  the stats panel surfaces new findings as they're discovered,
  colour-coded by severity. Last 3 critical/high findings
  always visible.
- **Pause/resume (not abort)** — `p` pauses the campaign at the
  next safe boundary (between phases); `r` resumes. `q` still
  aborts with the existing 2-press confirmation. This requires
  campaign-runner support; the TUI is the easy half.
- **Budget gauge in header** — `[████░░░░░░] $4.23 / $20.00`
  in the runner header. Colour shifts cool → warm as it
  approaches budget; turns red 10% before the cap.

**Trade-off considered:** Adding a fifth panel for "live
findings" vs squeezing it into the stats panel. *Stats panel
wins* — adding a fifth panel pushes the activity log too small
on a 24-row terminal.

### 4.3 Triage results (post-campaign)

**Today:** Static results screen with summary + top 3 threads +
6 report shortcuts that open external editor.

**Proposed:** **In-TUI markdown report browser** with three
regions:
- **Left pane** — report list (master report, top threads,
  attack surface, harvested credentials, vendor supply chain,
  credential exposure paths, spear-phishing intelligence, plus
  any future deliverables). Each row shows a tiny status badge:
  `●` generated, `○` not generated (with hover hint why), `⚠`
  generated but contains empty sections.
- **Centre pane** — `MarkdownViewer` rendering the selected
  report. Inline tables, code blocks, links all rendered
  natively.
- **Right pane** — context-sensitive details:
  - On a *threat* link → expanded view (full evidence, MITRE
    mapping, recommended action, audit-chain ref).
  - On a *credential* row → masked secret + endpoint info.
  - On a *finding* link → severity, source, dedup history.

Key bindings:
- `Tab` cycles between the three panes.
- `m` (mark) flags a row as "operator-reviewed"; persistent
  across sessions. The badge becomes `✓`.
- `e` opens the current report in the system editor (fallback
  for power users; the TUI preview is the default).
- `c` copies the current selection (e.g., a credential) to the
  clipboard via OSC52 sequence (works in modern terminals
  including SSH sessions).
- `/` filters the report list by keyword.

**Trade-off considered:** Render reports in-place (MarkdownViewer)
vs cling to "open in $EDITOR." *In-place wins* — every modern
operator TUI (k9s, lazygit, harlequin) keeps the operator in
the same context. External editor is a power-user escape
hatch via `e`.

### 4.4 Browse / resume past campaigns

**Today:** DataTable of campaigns with 6 columns. Enter to
push results screen.

**Proposed:** Same table, but:
- **Sort + filter** — column headers sort on click / Shift+`s`
  cycles sort. `/` filters by client/seed/id.
- **Severity breakdown** in findings count: `45 (C:2 H:8)`
  rather than just `45`.
- **Action shortcuts** on focused row — `r` resume, `R` re-run
  (clone scope, new ID), `d` delete (2-step confirm), `e` export
  zipped artifact directory, `o` open in finder.
- **Persistent in-progress indicator** — campaigns with
  `status == RUNNING` get a pulsing ● in the status column.
- **Cohort comparison teaser** — `Ctrl+C` on two selected rows
  opens a side-by-side diff (placeholder until the `nexusrecon
  diff` command lands).

### 4.5 Configure secrets & integrations

**Today:** Two-pane config screen (categories | keys). Modal
for editing.

**Proposed:** Same two-pane skeleton, but:
- **Client-side validation in `EditKeyModal`** — `ConfigSchema`
  gains `validation: re.Pattern | Callable | None` per var.
  Modal shows live ✓/✗ as the operator types. Common patterns:
  - API keys with known prefixes (`sk-ant-`, `shodan-`, etc.).
  - URLs (well-formed http/https).
  - Domain lists (comma-separated, each matches
    `_DOMAIN_RE`).
  - Numeric ranges (cost cap, timeout in seconds).
- **"Test this key" action (`t`)** when defined for the var
  — makes a single read-only call against the provider and
  surfaces success/error in the modal. Off by default for
  paid APIs (would burn quota); operator opts in via the
  binding.
- **Connection summary** column on the right pane: not just
  ✓/✗ "configured" but `✓ tested 2h ago` when a `t` action has
  been run.
- **Bulk import** — `Ctrl+I` opens a paste-zone dialog where
  operators can paste a `KEY=value` block (e.g., from a vault
  export) and it batch-applies to `.env`.
- **Stub-aware tools view** — the Tools subscreen shows the
  `[STUB]` prefix prominently and groups stubs into their own
  section.

### 4.6 Discover / search across everything

**Today:** No global search. Discovery via Footer + `?` help.

**Proposed:** **Command palette** triggered by `Ctrl+P` or `:`
from any screen. Fuzzy-searches:
- All registered actions (every binding from every screen).
- All registered tools (jumps to tools browser with that tool
  selected).
- All campaigns on disk (jumps to results for that one).
- All deliverables in the current/most-recent campaign.
- All config keys (jumps to config screen and focuses the
  row).
- Common navigation: "go to runner", "go to wizard step 3",
  etc.

Pattern: type a few characters, see ranked results, Enter to
execute. Borrowed wholesale from atuin / VS Code / posting.

### 4.7 Get help / discover bindings

**Today:** `?` opens HelpModal (shipped in TUI-1).

**Proposed:** Same modal, but:
- **Two-column layout** — "this screen" + "global" instead of
  flat list.
- **Search box** at the top of the modal — type to filter.
- **Hyperlink in modal description to documentation URL** for
  context-heavy actions (e.g., "Stealth profile → see
  ROADMAP.md#opsec").

### 4.8 Run safely & survive interrupts

**Today:** `Ctrl+Q` quits the app; campaigns abort
ungracefully if the TUI dies (process state is on disk but
no checkpoint).

**Proposed:**
- **Graceful shutdown handler** — `Ctrl+Q` from runner asks
  "Pause campaign and exit, or abort?" Pause cleanly checkpoints
  the campaign; resume reopens on next launch.
- **Crash recovery on launch** — if the TUI detects a
  campaign that was running when last seen, the welcome screen
  shows a banner: "Resume <id>? (last seen 2h ago at phase
  4)".

---

## 5. Overall Architecture & Cross-Cutting Design

### 5.1 The persistent shell

The single most consequential change: **stop pushing/popping
screens** and instead host every "screen" inside a persistent
dashboard. Layout:

```
┌──────────────────────────────────────────────────────────────────────────────────┐
│  NEXUSRECON v0.5.0     • juice-shop.herokuapp.com   [████░░░░] $4.23/$20  ●● 23  │ ← HEADER
├──────────┬────────────────────────────────────────────────────┬──────────────────┤
│          │                                                    │                  │
│  📊 Dash │   ┌──── PHASE 4 / 10 · Correlation & Hypothesis ──┐│   Top findings:  │
│  🎯 New  │   │ ████████████████████░░░░░░░░░░░░░░  62%      ││   ◆ S3 bucket    │
│  ⏵ Run   │   └────────────────────────────────────────────────┘│      misconfig  │
│  📁 Past │                                                    │   ◆ Subdomain    │
│  🛠 Tools│   ─── Activity ──────────── /filter ───────────  ⏸  │      takeover   │
│  🔧 Cfg  │   18:42:17 phase4 dispatch fan-out = 5             │                  │
│  ❓ Help │   18:42:14 phase4 began                            │   Tools active:  │
│          │   18:41:55 phase3 ended                            │   ● github_recon │
│  Theme:  │   18:41:02 phase3 began                            │   ● subfinder    │
│  dark    │                                                    │   ● amass        │
│          │   ─── Detail (toggle d) ────────────── live ────  │                  │
│          │   2026-05-21 18:42:17 [info] dispatcher  count=5   │                  │
│          │   2026-05-21 18:42:17 [debug] subfinder example…   │                  │
│          │                                                    │                  │
├──────────┴────────────────────────────────────────────────────┴──────────────────┤
│  : palette · / filter · ? help · TAB cycle · p pause · q abort · Ctrl+Q exit     │ ← FOOTER
└──────────────────────────────────────────────────────────────────────────────────┘
```

**Three persistent regions:**
- **Header (always visible)** — Title, current context (campaign
  ID, target, or "Idle"), live budget gauge, finding-count
  ticker.
- **Sidebar (collapsible via `]`)** — top-level navigation. Each
  entry has a letter binding and an emoji glyph for visual scan.
- **Main pane** — whatever the active sidebar entry shows.
- **Optional right pane** — context-sensitive detail (findings,
  reports preview, tool info). Toggles via `Tab` cycle.
- **Footer** — current screen bindings + global hints.

**Why this works:**
- Operator can be watching a campaign and still hit `c` to peek
  at config without losing the runner state.
- The header status bar is the operator's "always-on" awareness
  channel — they never lose track of budget or active campaign.
- Tab key cycles focus between sidebar / main / right pane,
  matching lazygit's mental model.

### 5.2 Framework recommendation

**Stay on Textual.** Rationale:
- 3000+ lines already invested.
- Built-in `MarkdownViewer`, `DataTable`, `RichLog`, themes,
  `run_test()` pilot — all already pinned by TUI-1.
- Process-shares with the agents (CrewAI/LangGraph) and tool
  registry; a Rust/Go rewrite means inter-process plumbing.
- The bottleneck is design + interaction patterns, not the
  framework.

**Targeted upgrades worth pinning** as the TUI grows:
- Adopt `textual.containers.HorizontalGroup` /
  `VerticalGroup` for sidebar+main layouts.
- Use `textual.widgets.MarkdownViewer` for report previews
  (already in 8.x).
- Use Textual's `LoadingIndicator` for the pre-warm window.
- Adopt `reactive` properties more aggressively — currently
  most state lives in screen instance vars; pushing it to
  reactives means automatic re-render on change.

### 5.3 Theme & visual language

Three themes ship by end of TUI-2:

| Theme | Use case | Primary | Background |
|---|---|---|---|
| `nexusrecon-dark` (default) | Most operators, low-light environments | `#00ff9c` mint | `#0a0e1a` deep navy |
| `nexusrecon-hicontrast` | Accessibility / bright terminals | `#00ff00` pure | `#000000` |
| `nexusrecon-light` *(new)* | Operators on shared / projector displays | `#0a7d4b` forest | `#fafafa` |

**Semantic colour tokens** (declared as theme variables;
referenced by every screen):

| Token | Purpose | Dark | Hicontrast | Light |
|---|---|---|---|---|
| `$primary` | Brand accent, primary actions | `#00ff9c` | `#00ff00` | `#0a7d4b` |
| `$secondary` | Info, navigation | `#1f6feb` | `#00aaff` | `#1f6feb` |
| `$success` | Completed, valid | `#00ff9c` | `#00ff00` | `#10b981` |
| `$warning` | Caution, MFA expected | `#f1c40f` | `#ffff00` | `#d97706` |
| `$error` | Failed, invalid | `#ff5555` | `#ff0000` | `#dc2626` |
| `$nx-text-muted` | Metadata, hints | `#7f8c8d` | `#b0b0b0` | `#64748b` |
| `$nx-text-dim` | Disabled, tertiary | `#4a5568` | `#888888` | `#94a3b8` |
| `$nx-bg-detail` | Pane elevation 2 (below surface) | `#07090f` | `#0d0d0d` | `#e2e8f0` |
| `$nx-focus-accent` | Active pane border, focus ring | `#00ff9c` | `#00ff00` | `#0a7d4b` |
| `$severity-critical` | Findings: critical | `#ff3838` (consistent) |
| `$severity-high` | Findings: high | `#ff8c00` (consistent) |
| `$severity-medium` | Findings: medium | `#f1c40f` (consistent) |
| `$severity-low` | Findings: low | `#5dade2` (consistent) |
| `$severity-info` | Findings: info | `$nx-text-muted` |

**Rule:** severity colours never shift with theme. Operators
build muscle memory on "red = critical, orange = high" and that
mapping must hold across themes.

### 5.4 Typography & spacing

Terminal-constrained, but choices to make:
- **No mixed weights inside paragraphs.** Bold only on labels,
  panel titles, and primary actions.
- **One-line breathing room** between borders and content
  (already in current .tcss).
- **Two-column max** on dense panels — anything more is
  unreadable on 80-col terminals.
- **No emoji in critical paths** — the existing menu emojis
  (`🎯`, `🔄`) render inconsistently across terminals
  (especially in SSH sessions over `screen`/`tmux`); the new
  sidebar should support a `NEXUSRECON_TUI_GLYPHS=text` env
  var that swaps emojis for `[N]`, `[R]`, etc. on
  emoji-unfriendly terminals.

### 5.5 Command palette (the killer feature)

Activated by `Ctrl+P` or `:` from anywhere. Renders as a top-of-
screen overlay:

```
┌── Command palette ─────────────────────────────────────────┐
│  > harvest                                                  │
│                                                             │
│  📁  Open: harvested_credentials.md (1 result)              │
│  ⚡  Action: jump to phase 7.5 (Credential Harvest)          │
│  🛠  Tool: harvested_credentials                            │
│  📊  Campaign: juice-shop run #42 (Credential Harvest)      │
│                                                             │
│  ↑↓ select · Enter execute · Esc cancel                    │
└─────────────────────────────────────────────────────────────┘
```

Provider architecture:
- `CommandSource` ABC with `query(text) -> list[Match]`.
- Built-in sources: `ActionsSource`, `ToolsSource`,
  `CampaignsSource`, `ReportsSource`, `ConfigKeysSource`,
  `NavigationSource`.
- Sources rank locally; palette merges + reranks.
- Adding a future source (e.g., "saved searches") is one class.

### 5.6 Global status bar (header)

Always populated, even with no campaign running:

```
NEXUSRECON v0.5.0  •  Idle  •  97 tools / 81 active / 1 stub  •  opus-4-7  •  $0.00 budget
```

When a campaign is running:

```
NEXUSRECON v0.5.0  •  juice-shop.herokuapp.com  •  Phase 4/10  •  [████░░░░] $4.23/$20  •  ●● 23  •  ⚠ 5
```

The two trailing indicators (`●● 23` = active findings count;
`⚠ 5` = warnings raised) are clickable: pressing the binding
they expose (`f` for findings, `w` for warnings) jumps to the
respective view.

### 5.7 Notifications (non-intrusive)

Operations like "config saved", "test passed", "report
generated" surface as **toasts** at the bottom-right corner,
3-second auto-dismiss. Severity dictates colour. Toasts
queue (max 3 visible); older ones slide out.

No modal "OK to continue?" dialogs except for genuinely
destructive ops (delete campaign, abort campaign). Even
those prefer inline yes-no rows over modals.

### 5.8 Extensibility hooks

Lay the groundwork now for future plugin authors:
- **Sidebar entries** registered via decorator:
  `@register_sidebar_entry(label="📈 Diff", key="i")`.
- **Command-palette sources** registered via the
  `CommandSource` ABC.
- **Report previewers** (per-deliverable rich rendering)
  registered by deliverable name.
- **Theme contributions** — third-party themes drop into
  `~/.nexusrecon/themes/*.py` and auto-register.

---

## 6. Detailed View Designs

### 6.1 Dashboard (replaces Welcome as primary view)

**Rationale:** The operator's first impression should be an
*operations center*, not a splash screen. The dashboard
remains beautiful (banner ASCII at top) but is information-
dense and immediately useful.

```
┌──────────────────────────────────────────────────────────────────────────────────┐
│  NEXUSRECON v0.5.0  •  Idle  •  97 tools / 81 active / 1 stub  •  opus-4-7       │
├──────────┬───────────────────────────────────────────────────────────────────────┤
│          │   ███╗   ██╗███████╗██╗  ██╗██╗   ██╗███████╗                          │
│  📊 Dash │   ████╗  ██║██╔════╝╚██╗██╔╝██║   ██║██╔════╝                          │
│  🎯 New  │   ██╔██╗ ██║█████╗   ╚███╔╝ ██║   ██║███████╗                          │
│  ⏵ Run   │   ██║╚██╗██║██╔══╝   ██╔██╗ ██║   ██║╚════██║                          │
│  📁 Past │   ██║ ╚████║███████╗██╔╝ ██╗╚██████╔╝███████║                          │
│  🛠 Tools│   ╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝   v0.5.0                  │
│  🔧 Cfg  │                                                                       │
│  ❓ Help │   Agentic OSINT Orchestration Framework                                │
│          │                                                                       │
│          │   ┌─ Last 5 campaigns ────────────────────────────────────────────┐  │
│          │   │ ✓ juice-shop.herokuapp.com   2h ago    45 findings  $4.23     │  │
│          │   │ ✓ acme.example.com            yesterday  120 findings  $11.04 │  │
│          │   │ ⚠ test-target.com             3d ago    partial (phase 6)     │  │
│          │   │ ✓ contoso.org                 1w ago    87 findings  $7.80    │  │
│          │   │ ✓ widgets.co                  2w ago    23 findings  $1.20    │  │
│          │   └───────────────────────────────────────────────────────────────┘  │
│          │                                                                       │
│          │   ┌─ Quick stats ─────────────────────┐  ┌─ Recent activity ────┐    │
│          │   │ Campaigns this month:  12         │  │ 2h ago: Phase 9 done │    │
│          │   │ Findings logged:        540        │  │ 2h ago: Phase 7 done │    │
│          │   │ LLM cost MTD:          $42.17     │  │ 2h ago: Spear-phish  │    │
│          │   │ Tools used most:  subfinder ▎▎▎▎▎ │  │           dossier x12│    │
│          │   └────────────────────────────────────┘  └──────────────────────┘    │
│          │                                                                       │
│          │   [n] New campaign  [r] Resume last  [p] Browse past  [:] Palette     │
├──────────┴───────────────────────────────────────────────────────────────────────┤
│  : palette  /  ? help  • Tab focus  •  q quit                                    │
└──────────────────────────────────────────────────────────────────────────────────┘
```

**Key components:**
- Banner kept but compacted to upper-third (less vertical
  space than today).
- Recent campaigns mini-list — direct navigation by digit
  (`1`-`5` jumps to that campaign).
- Two-column stats: rollup metrics (left) + recent activity
  (right).
- Action hints across the bottom for muscle memory.

### 6.2 Runner (re-imagined inside the shell)

```
┌──────────────────────────────────────────────────────────────────────────────────┐
│  NEXUSRECON v0.5.0  •  juice-shop.herokuapp.com  •  Phase 4/10  •  $4.23/$20.00  │
├──────────┬───────────────────────────────────────────────────────────────────────┤
│          │   ┌─ Phase 4 · Correlation & Hypothesis Testing ──────────────────┐  │
│  📊 Dash │   │ Phases   ████████████████░░░░░░░░░░░░░░░░░░░░ 4/10 (40%)      │  │
│  🎯 New  │   │ Phase 4  ████████████░░░░░░░░░░░░░░░░░░░░░░░░ 30%   ~25s left │  │
│  ⏵ Run ●│   │ Budget   ████████░░░░░░░░░░░░░░░░░░░░░░░░░░░░ $4.23 / $20.00  │  │
│  📁 Past │   └───────────────────────────────────────────────────────────────┘  │
│  🛠 Tools│   ┌─ Activity ──────────────────── /filter:phase4 ──────────── ⏸  ┐  │
│  🔧 Cfg  │   │ 18:42:17  phase4 dispatch fan-out = 5                         │  │
│  ❓ Help │   │ 18:42:14  phase4 began                                        │  │
│          │   │ 18:41:55  phase3 ended (28 findings, $0.42)                   │  │
│          │   │ 18:41:02  phase3 began                                        │  │
│          │   │ 18:39:48  phase2.5 personal pivot: 8 candidates surfaced      │  │
│          │   └───────────────────────────────────────────────────────────────┘  │
│          │   ┌─ Detail (d to toggle) ────────────────────────── live ───────┐  │
│          │   │ 2026-05-21 18:42:17 [info ] dispatcher        count=5         │  │
│          │   │ 2026-05-21 18:42:17 [debug] subfinder         tgt=example.com │  │
│          │   │ 2026-05-21 18:42:17 [debug] github_subdomains tgt=example.com │  │
│          │   │ 2026-05-21 18:42:14 [info ] Phase 4: Correlation & Hypothesis │  │
│          │   └───────────────────────────────────────────────────────────────┘  │
│          │   ┌─ Stats ──────────────────────┐  ┌─ Tools live ──────────────┐  │
│          │   │ Findings        45 (C:2 H:8) │  │ ● subfinder   3.2s        │  │
│          │   │ Subdomains       127         │  │ ● amass        12s         │  │
│          │   │ Emails             5         │  │ ● github_subdomains  8s    │  │
│          │   │ Threads ranked     —         │  │ ✓ chaos        ✓ ssl_dump │  │
│          │   │ Elapsed         8m42s        │  │                             │  │
│          │   └──────────────────────────────┘  └──────────────────────────────┘  │
├──────────┴───────────────────────────────────────────────────────────────────────┤
│  / filter  • Space pause-tail  • p pause campaign  • q abort  • r reports        │
└──────────────────────────────────────────────────────────────────────────────────┘
```

**Headline changes from today:**
- Three gauges stacked (phases / current phase / budget)
  instead of one. Operator sees both the long-horizon and
  short-horizon progress.
- Activity log gets `/filter` and `⏸` pause toggle.
- Tools-live panel shows what's currently invoking (with
  elapsed time per tool). Helps debug "why is it stuck"
  visually.
- Findings counter breaks out severity in parentheses.

### 6.3 Tools browser (the TUI-2 deliverable)

```
┌──────────────────────────────────────────────────────────────────────────────────┐
│  NEXUSRECON v0.5.0  •  97 tools  •  81 active  •  15 missing keys  •  1 stub     │
├──────────┬─────────────────────┬────────────────────────────────────────────────┤
│          │  /git_                │   github_social                                │
│  📊 Dash │  ▣ Identity (12)     │   ─────────────────────────────────────────    │
│  🎯 New  │  ▣ Pretext (8)       │   [PHASE E2] GitHub per-user social graph —    │
│  ⏵ Run   │  ▣ Domain (16)       │   followers, following, repo collaborators,    │
│  📁 Past │  ▣ Cloud (7)         │   commit co-authors. Feeds Phase E             │
│  🛠 Tools│  ▣ Web (12)          │   relationship graph + pretext scoring.        │
│  🔧 Cfg  │  ▣ Code (5)          │                                                │
│  ❓ Help │  ▣ Vuln (7)          │   Tier:        T0                              │
│          │  ▣ Intel (16)        │   Category:    social                          │
│          │  ▣ Breach (4)        │   Target type: username, handle, identity      │
│          │  ▣ Mobile (2)        │   Requires:    GITHUB_TOKEN  ✓ configured      │
│          │  ▣ Stubs   (1)       │   Status:      ✓ available                     │
│          │                       │                                                │
│          │  /git filter matches: │   Recent invocations: 0 (Phase 7.7 will fire) │
│          │  ✓ github_actions     │                                                │
│          │  ✓ github_advisory    │   [c] config keys   [t] test (read-only)      │
│          │  ✓ github_org_members │   [i] invocation history                       │
│          │ ▶✓ github_social      │                                                │
│          │  ✓ github_subdomains  │                                                │
│          │  ✓ gitleaks           │                                                │
│          │  ✓ gitdorker          │                                                │
│          │  …                    │                                                │
├──────────┴─────────────────────┴────────────────────────────────────────────────┤
│  / filter  • Tab cycle pane  • Enter detail  • c configure  • Esc clear filter  │
└──────────────────────────────────────────────────────────────────────────────────┘
```

**Headline changes:**
- Category column (left) with counts.
- Filter input (`/git_` shown above) narrows the centre column
  in real time. Selected category limits the scope.
- Right pane shows full detail: tier, requires, status, recent
  invocations.
- `c` jumps to config screen with the right row focused.
- `t` (when implemented per-tool) runs a no-op probe to test
  the configuration.

### 6.4 Reports browser (the TUI-5 deliverable)

```
┌──────────────────────────────────────────────────────────────────────────────────┐
│  NEXUSRECON v0.5.0  •  juice-shop.herokuapp.com  •  Done  •  45 findings (C:2 H:8)│
├──────────┬──────────────────────────────┬───────────────────────────────────────┤
│          │  Reports                      │  ## Top Threads to Pull               │
│  📊 Dash │  ─────────                     │                                       │
│  🎯 New  │  ● Master report     ✓        │  Generated 2026-05-21 18:48 UTC       │
│  ⏵ Run   │  ● Executive summary ✓        │                                       │
│  📁 Past │  ● Top threads       ✓        │  ### 1. S3 bucket misconfiguration    │
│  🛠 Tools│  ● Attack surface    ✓        │      [CRITICAL]                       │
│  🔧 Cfg  │  ● Phishing package  ✓        │                                       │
│  ❓ Help │  ● Vuln correlation  ✓        │  Source:    bucket_enum, gowitness    │
│          │  ● Vendor supply chain ✓      │  Asset:     /uploads/                 │
│          │  ● Harvested creds   ✓        │  Severity:  critical (score 0.92)     │
│          │  ● Credential paths  ✓        │  Confidence: high                     │
│          │  ● Spear-phish intel ✓        │                                       │
│          │  ● Asset inventory   ✓        │  Recommended action:                  │
│          │  ● People map        ✓        │    Validate bucket policy ─ test if   │
│          │  ● Jira tracker      ✓        │    objects can be listed/read by an   │
│          │  ● Entity graph HTML ✓        │    anonymous principal.               │
│          │  ● PDF report        ✓        │                                       │
│          │  ● PPTX report       ✓        │  Audit chain ref: 0x4a8b…             │
│          │  ● Findings JSON     ✓        │                                       │
│          │                                │  ────────────────                     │
│          │                                │  ### 2. Subdomain takeover            │
│          │  / filter:phish               │      [HIGH]                           │
│          │  ● Phishing package  ✓        │  …                                    │
│          │  ● Spear-phish intel ✓        │                                       │
├──────────┴──────────────────────────────┴───────────────────────────────────────┤
│  Tab cycle  • Enter view  • e external editor  • c copy  • m mark reviewed       │
└──────────────────────────────────────────────────────────────────────────────────┘
```

### 6.5 Wizard (re-imagined with sticky summary)

```
┌──────────────────────────────────────────────────────────────────────────────────┐
│  NEXUSRECON v0.5.0  •  New campaign  •  Step 2/5: Target & Scope                 │
├──────────┬──────────────────────────────────────────────────┬───────────────────┤
│          │                                                   │  ── Summary ──    │
│  📊 Dash │   Load preset:    [▼ corp-m365              ]    │  Client:           │
│  🎯 New ▶│                                                   │   Acme Corp        │
│  ⏵ Run   │   Seed domain:    [acme.example                ] │  Engagement:       │
│  📁 Past │      ✓ valid                                      │   ENG-2026-05-001  │
│  🛠 Tools│                                                   │  Authorized:       │
│  🔧 Cfg  │   Additional:     [api.acme.com, app.acme.com  ] │   John Doe (CISO)  │
│  ❓ Help │      ✓ all parseable                              │  Dates:            │
│          │                                                   │   2026-05-21 →    │
│          │   Out of scope:                                   │   2026-06-21       │
│          │   [*.aws.amazon.com, *.cloudfront.net          ] │  SOW hash:         │
│          │      ✓ 7 wildcards                                │   …4f3a            │
│          │                                                   │                    │
│          │   ─── Step 2 / 5 ───                              │  ── Cost preview ─│
│          │                                                   │   T2 · medium ·   │
│          │   ┌─────┐  ┌─────┐  ┌──────────┐                  │   lite dispatch   │
│          │   │Back │  │Next │  │ Cancel   │                  │   ~$3.20 - $8.40  │
│          │   └─────┘  └─────┘  └──────────┘                  │   (5 phases LLM)  │
├──────────┴──────────────────────────────────────────────────┴───────────────────┤
│  Ctrl+N next  • Esc back  • Ctrl+S save scope only  • Ctrl+Q quit                │
└──────────────────────────────────────────────────────────────────────────────────┘
```

**Headline changes:**
- Sticky summary pane (right) shows every field from every
  step. The operator never wonders "did I set the SOW hash?"
- Live validation icons (`✓` / `✗`) per field.
- Cost preview pane updates as Step 3 / 4 toggles change.
- Preset loader at the top reduces 5 steps to 30 seconds for
  common engagements.

### 6.6 Config screen (depth additions)

The existing two-pane layout stays. Additions:
- **Validation column** in the keys pane: `✓ set` / `✗ missing` /
  `⚠ malformed` (when a regex pattern is declared).
- **`t` action** opens a connection-test toast (paid APIs
  off by default).
- **Bulk paste** (`Ctrl+I`) — paste a `KEY=value` block; preview
  diff; apply.
- **Stub tools subtab** — Tools listing already shows
  `[STUB]` per the existing policy; sort stubs into their own
  collapsible section.

---

## 7. Implementation Roadmap

Phased to ship incremental value. Each phase is independently
testable and reverts cleanly if not adopted.

### TUI-2 (next): Tools browser overhaul + command palette skeleton
- Category-grouped tools view with filter (`/`).
- Detail pane (right) with metadata + actions.
- `c` jump-to-config action; binding wired to existing
  `ConfigScreen`.
- **Command palette skeleton** — implement `Ctrl+P` + the
  `CommandSource` ABC + `ToolsSource` + `NavigationSource`.
  Other sources land in subsequent phases.

### TUI-3: Persistent shell + dashboard
- Refactor `WelcomeScreen` into `DashboardScreen` inside a new
  persistent shell.
- Implement collapsible sidebar (`]` toggle).
- Implement the status-bar header that shows live state from
  any screen.
- Promote recent campaigns + quick stats onto the dashboard.

### TUI-4: Wizard depth
- Sticky summary pane.
- Live validation icons.
- Preset library (`~/.nexusrecon/scope-presets/`).
- Cost preview computation.
- Bind into the persistent shell.

### TUI-5: Runner depth + reports browser
- Activity-log scrollback + filter + pause-tail.
- Per-phase mini-gauge + budget gauge with gradient.
- Tools-live panel.
- **In-TUI markdown report browser** with three-pane layout.
- "Mark reviewed" persistence.
- Pause/resume binding (requires runner core support).

### TUI-6: Polish + extensibility
- Light theme.
- Notifications / toast system.
- Sidebar / palette extensibility hooks.
- Crash recovery banner on dashboard.
- Two-press destructive-action confirm rendered inline
  (replace remaining modals).
- 90-second README gif (closes the existing roadmap item).

Each phase ships with a `tests/unit/test_tui_phase_N.py` mirroring
the TUI-1 pattern: regression on the failure mode that motivated
the change, plus a `run_test()` pilot smoke that exercises the
new bindings.

---

## 8. Additional Recommendations

### Performance for large recon datasets
- `DataTable` virtual scrolling handles 10K+ rows out of the
  box. The current Tools and Campaigns screens already use
  it — keep it.
- **Activity log buffer cap** stays at the current 200 lines
  in memory but with disk-backed scroll back via the session
  log file. When the operator scrolls past line 200 in the
  Activity pane, the renderer reads older entries from the
  log file on demand. Avoids the "structlog tail eats RAM"
  failure mode at scale.
- **Findings counter ticker** in the header debounces at
  500ms — high-velocity finding bursts during phase 1 (subdomain
  enumeration) shouldn't repaint the header on every tick.

### Accessibility
- Hi-contrast theme already ships.
- All severity colours pass WCAG-AAA contrast against the
  dark background (verified during TUI-1).
- The `NEXUSRECON_TUI_GLYPHS=text` env var should drop emoji
  in favour of `[N]`-style markers — common ask from operators
  running over `screen` / `tmux` over SSH.

### Extensibility (post-1.0)
- Define and document the `CommandSource` ABC, sidebar-entry
  registration decorator, and report-previewer plugin shape
  as part of the existing plugin SDK roadmap item.
- Theme contributions via `~/.nexusrecon/themes/*.py` —
  operators can drop in their org's brand palette without
  forking.

### "Wow" features that aren't gimmicks
- **OSC52 clipboard copy** (`c` on a credential row). Works
  through SSH. Operators stop falling out of the TUI to copy
  values from `cat`-ed `.env` files.
- **Inline graph for budget burn rate** in the runner.
  Operators can predict whether they'll bust budget before
  the campaign finishes.
- **"What's new" panel on the dashboard** — pulls from
  `CHANGELOG.md`'s `[Unreleased]` section the first time
  a new version launches. Operators see what they got.
- **Crash-recovery banner** — if the TUI detects a
  campaign was running last session, the dashboard banner
  surfaces `Resume <id>? (last seen 2h ago at phase 4)`.
  One-key resume.

### Out of scope (deferred)
- Mouse-first interaction. The TUI is mouse-aware (Textual
  handles clicks) but the design is keyboard-first; no
  drag-drop, no right-click menus.
- Audio cues. Operator preference varies wildly; we
  default-off.
- Web component / HTML report viewer inside the TUI — the
  existing `entity_graph_html` deliverable opens in a browser
  via `e`; this is fine.

---

## Appendix A — Key bindings table (proposed)

Global (work from any screen):

| Key | Action |
|---|---|
| `Ctrl+P`, `:` | Command palette |
| `?` | Help overlay |
| `Tab` | Cycle focus through panes |
| `[`, `]` | Collapse/expand sidebar |
| `Ctrl+Q` | Quit (with confirm if campaign running) |

Sidebar (single-letter, also work as digits):

| Key | Pane |
|---|---|
| `d` | Dashboard |
| `n` | New campaign |
| `w` | Active runner (when a campaign is in progress) |
| `p` | Past campaigns |
| `t` | Tools browser |
| `c` | Configuration |
| `r` | Reports (most-recent campaign) |
| `h` | Help / docs |

Runner (active campaign):

| Key | Action |
|---|---|
| `/` | Filter activity log |
| `Space` | Pause / resume tail |
| `j`, `k` | Scroll activity |
| `g`, `G` | Top / bottom |
| `n`, `N` | Next / prev filter match |
| `[`, `]` | Prev / next phase boundary in log |
| `d` | Toggle detail pane |
| `p` | Pause campaign (next safe boundary) |
| `q` | Abort campaign (2-press confirm) |
| `r` | Open reports (when ready) |

Reports browser:

| Key | Action |
|---|---|
| `↑`, `↓` | Navigate reports |
| `Enter` | Open in centre pane |
| `e` | Open in external editor |
| `c` | Copy current selection (OSC52) |
| `m` | Mark as operator-reviewed |
| `/` | Filter report list |

---

## Appendix B — Risk register

| Risk | Mitigation |
|---|---|
| Persistent-shell refactor regressing existing screens | Land TUI-3 behind a `NEXUSRECON_TUI_SHELL=new` opt-in env var for the first release cycle; ship classic + new in parallel until parity is confirmed. |
| Command palette becoming a "Christmas tree" of stale sources | Sources are registered, not hardcoded; deprecating one is a 5-line PR. Lint test pins the set of sources. |
| Theme variable drift between dark / hicontrast / light | Existing `test_both_themes_define_custom_variables` test already pins this; extend it to the light theme on TUI-6 landing. |
| Sidebar focus stealing keypresses meant for main pane | Tab is the explicit focus toggle; letter shortcuts only fire when the sidebar has focus AND no other modal is open. Replicates k9s. |
| Operators on bare `xterm` losing emojis | `NEXUSRECON_TUI_GLYPHS=text` env var ships in TUI-3. |
| 80-col terminals breaking the multi-pane layout | Auto-collapse sidebar at `cols < 100`, auto-hide right pane at `cols < 120`. Falls back gracefully. |

---

*End of specification. Iterate this document as the design evolves;
the implementation phases lean on its decisions directly.*
