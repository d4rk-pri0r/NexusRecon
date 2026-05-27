# NexusRecon TUI Upgrade & Polish Plan
**From "Very Good" to "World-Class Operator Experience"**

**Status:** Planning document. Builds directly on `docs/TUI_DESIGN_SPEC.md`.  
**Last updated:** 2026-05-27 (re-audit; TUI-7 items partially shipped)
**Audience:** Developers implementing TUI-6 and beyond.  
**Related:** `EXECUTION_PLAN_V3_UX_POLISH.md`, `ITERATION_BACKLOG.md`

> **Re-audit note (2026-05-27).** Since the original 2026-05 audit:
> - Tools / Config separation + in-place key editing shipped
>   (commit `8e8b7c2`) — partially covers TUI-7 §3 "Stronger
>   contextual detail panes" and the consistent row-action
>   vocabulary.
> - Sidebar arrow-key navigation shipped (commit `8e8b7c2`) —
>   covers the consistent-navigation goal called out implicitly
>   in TUI-7.
> - Dashboard top-impact gap surface shipped (commit `c77c9a1`) —
>   partial coverage of TUI-7's "Tool health card uses intensity
>   coloring for gaps." Adopting `IntensityGauge` (TUI-6) on the
>   gap counts closes the rest.
>
> The phased order below is otherwise unchanged. TUI-6 (the
> widget library + runner overhaul) stays the highest leverage
> next bucket of work.

---

## 1. Purpose

This document turns the 2026 TUI audit into a concrete, followable engineering plan. The current TUI (Textual-based, `nexusrecon/tui/`) is already one of the more ambitious domain-specific TUIs in the Python ecosystem: it has a persistent dashboard shell, an extensible command palette, three-pane browsers, semantic theming, and a custom `ChunkyBar`.

However, when compared to the absolute highest-polish open-source TUIs (btop, yazi, lazygit, k9s, Harlequin, gitui, etc.), it is missing the "it feels alive" and "every view is a power tool" qualities that make operators fall in love with a terminal interface.

**Goal:** Ship incremental upgrades that make the NexusRecon TUI earn the same kind of praise that `lazygit` and `btop` receive in 2025–2026 unixporn and operator communities.

This plan is **actionable**: every phase lists files to change, new modules to create, acceptance criteria, and "study these" references.

---

## 2. Executive Vision (2026)

> "The NexusRecon TUI should be the tool a red-teamer or OSINT operator reaches for at 2 a.m. — not because they have to, but because the live campaign view feels as rich and beautiful as the best monitoring and git TUIs, while the discovery and triage surfaces are faster than any GUI."

We keep the existing architecture (Textual + persistent shell + palette + semantic themes). We do **not** rewrite in Ratatui. We invest in:

- Live, intensity-aware visualizations (the "btop factor")
- Ubiquitous instant filter + contextual power keys (the "k9s/lazygit factor")
- Rich, contextual detail panes that make the operator never want to leave the TUI
- Micro-interactions and "alive" feel without sacrificing keyboard-first density

---

## 3. Current State Assessment (Condensed 2026 Audit)

**Already excellent (preserve & extend):**
- Persistent shell (Dashboard + `Sidebar` + `StatusBar`) on most screens
- `CommandPalette` with pluggable `CommandSource` + good fuzzy scoring
- Three-pane `ToolsScreen` and `ReportsBrowserScreen` (with real `MarkdownViewer`)
- Three themes with locked severity colours (`themes.py`)
- `ChunkyBar` (custom full-width progress)
- Defensive coding, pre-warm, session logging rerouting, toasts via `app.notify`
- Two-pane `ConfigScreen` (still the right shape)

**Biggest gaps vs. 2025–2026 SOTA:**
- Runner activity/detail surfaces are still simple append-only capped `Static` + `deque`. No `/` filter, no pause-tail, no phase navigation, no live intensity viz.
- Almost no animated or gradient data visualization beyond the single `ChunkyBar`.
- Inconsistent per-view power tools (filter, row actions, contextual detail).
- Limited custom widget library (only `ChunkyBar`, `Sidebar`, `StatusBar`).
- Micro-interactions (skeletons, focus transitions, async spinners) are minimal.
- Runner lacks the "per-phase mini-gauges + tool sparkline + finding ticker" described in the original design spec §4.2 / §6.2.

**Files of interest (primary surfaces):**
- `nexusrecon/tui/screens/runner.py` (especially `_log`, `_detail`, `ChunkyBar`, stats)
- `nexusrecon/tui/widgets/` (new home for gauge/sparkline library)
- `nexusrecon/tui/screens/tools.py`, `reports_browser.py`, `dashboard.py`
- `nexusrecon/tui/app.tcss` + `themes.py`
- `nexusrecon/tui/command_palette.py`

---

## 4. Benchmark TUIs & Stealable Patterns (2025–2026)

Study these projects. Clone them. Run them in Kitty/WezTerm/Ghostty. Steal the *feeling*, not the code.

### 4.1 btop / bottom (btm) — The Visual Intensity King
- **Repo:** https://github.com/aristocratos/btop (C++), https://github.com/ClementTsang/bottom (Rust `btm`)
- **Signature patterns to steal:**
  - Gradient bars that shift cool → hot as utilization rises (CPU, memory, network, *budget burn*).
  - Braille + block character charts that feel alive at 1–2 Hz.
  - Per-process sparklines and tiny history graphs.
  - Theme system with dozens of built-in palettes; easy Catppuccin-style customization.
- **Application to NexusRecon:**
  - Budget gauge that turns from mint → amber → red.
  - Per-phase progress mini-bars.
  - Tool invocation intensity or findings-per-minute sparkline in the runner stats.
  - "Tool health" card on dashboard that uses intensity coloring.

**Study file:** Look at btop's `draw.cpp` / meter rendering and bottom's `src/app.rs` chart widgets.

### 4.2 yazi — Modern, Fast, Preview-Rich File Manager
- **Repo:** https://github.com/sxyazi/yazi
- **Signature patterns:**
  - Async everything; UI never blocks on I/O or previews.
  - Contextual right pane with rich previews (images via kitty/sixel protocol, PDFs, video thumbnails, syntax-highlighted code).
  - Extremely clean, modern aesthetic with perfect spacing.
  - Vim-like keys + mouse support that feels first-class.
- **Application:**
  - Future entity graph or screenshot previews inside the TUI (stretch).
  - Make every list view feel "yazi-fast" (instant filter, no jank).
  - Preview pane discipline for reports, tool details, campaign state.

### 4.3 lazygit — Multi-Pane Context Mastery
- **Repo:** https://github.com/jesseduffield/lazygit
- **Signature patterns:**
  - 4–5 panes with clear focus model (active pane gets strong visual weight; others remain readable).
  - Right-hand detail pane that changes intelligently with selection (commit diff, file contents, etc.).
  - Beautiful commit graphs rendered with Unicode + color.
  - Staging view that feels like a mini-GUI.
- **Application:**
  - Runner: make the activity log the "main" pane and give it a rich contextual detail pane on the right (currently the detail log is just a toggle).
  - Campaigns list: selection drives a rich summary pane.
  - Consistent "focus ring" + inactive-pane dimming treatment.

### 4.4 k9s — Density + Discoverability God-Tier
- **Repo:** https://github.com/derailed/k9s
- **Signature patterns:**
  - `/` instant regex filter in *every* resource view (no modal).
  - `:` command mode for power navigation (`:pod`, `:svc`, `:ns prod`).
  - Single-key row actions (`d` describe, `l` logs, `e` edit) that feel discoverable.
  - Skins/themes + excellent use of color for status/severity.
  - Live updating resource views that stay scannable at high cardinality.
- **Application:**
  - Add `/` filter to runner activity, campaigns table, tools list (if missing), reports list.
  - Make row-level actions consistent (`c` = configure key, `t` = test, `i` = invocation history).
  - Command palette is already our `:` equivalent — make sure it surfaces the same actions.

### 4.5 Harlequin (Textual) & Posting (Textual) — What Our Framework Can Do
- **Harlequin:** https://github.com/tconbeer/harlequin (SQL IDE)
- **Posting:** https://github.com/darrenburns/posting (HTTP client)
- **Signature patterns:**
  - Both are Textual apps that feel *modern and premium*.
  - Rich data tables, autocomplete, side-by-side request/response or query/results.
  - Excellent theming and focus management.
  - Harlequin has charts and beautiful inline result rendering.
- **Application:** These prove we do **not** need to leave Textual to achieve high polish. Study their widget composition, CSS usage, and how they handle large datasets.

### 4.6 Other High-Value References
- **gitui** (Rust): https://github.com/extrawurst/gitui — Fast, syntax-highlighted diffs, clean panes.
- **zellij** (Rust multiplexer): https://github.com/zellij-org/zellij — Desktop-like pane management, beautiful status bars, floating panes, plugins.
- **superfile** (Go/Bubbletea): https://github.com/yorukot/superfile — Modern "pretty" file manager with sidebar + previews.
- **awesome-tuis**: https://github.com/rothgar/awesome-tuis (curated list + showcase video)
- **awesome-ratatui**: https://github.com/ratatui/awesome-ratatui (widget patterns, charts, image support via `ratatui-image`)

---

## 5. Gap Analysis (Prioritized)

| # | Gap | Impact | Effort | Phase | Benchmark |
|---|-----|--------|--------|-------|-----------|
| 1 | Runner activity is append-only, unfilterable, non-pausable | High | Medium | TUI-6 | k9s `/`, btop live logs |
| 2 | No gradient/intensity visualization or sparklines | Very High (visual "wow") | Medium | TUI-6 | btop, bottom |
| 3 | Inconsistent per-view power tools (`/`, row actions) | High | Medium | TUI-6/7 | k9s + lazygit |
| 4 | Limited custom widget library | Medium-High | Low–Med | TUI-6 | All of them |
| 5 | Weak micro-interactions (skeletons, focus, async) | Medium | Low | TUI-7 | Harlequin, yazi |
| 6 | Runner lacks spec'd per-phase mini-gauges + tool ticker | High | Med | TUI-6 | btop meters |
| 7 | No image/graphics protocol usage (future) | Low (delight) | High | TUI-8+ | yazi |

---

## 6. Phased Roadmap (TUI-6 → TUI-8)

### Phase TUI-6: "The Runner Comes Alive" (Highest Leverage)
**Goal:** The live campaign view stops feeling like a log tailer and starts feeling like a mission-control surface.

> **Split into two PRs (2026-05-27 re-audit).** The original
> deliverable list bundled the widget library and the runner
> overhaul. They are independently shippable; splitting reduces
> review surface and unblocks the dashboard from waiting on the
> runner refactor.

#### TUI-6a — Widget library + dashboard adoption (PR 1)

> **Status: SHIPPED in this PR.** `gauges.py` lands with the
> three widgets + `pick_intensity_color`, exposed via
> `nexusrecon.tui.widgets`. CSS classes added to `app.tcss`.
> Dashboard Tool Health card adopts the cool→hot intensity
> rendering on per-gap impact bars. 39 unit tests pin the
> renders; 160 TUI tests pass.

1. **New widget library** (`nexusrecon/tui/widgets/gauges.py`)
   - `IntensityGauge` — block bar with cool→hot gradient
     (mint → amber → red).
   - `MiniSparkline` — small history graph (last N values).
   - `PhaseStrip` — thin horizontal strip showing per-phase
     progress (sub-bars).
   - Refactor `ChunkyBar` (`runner.py:59`) to share code with
     the new library.
2. **Dashboard adoption** (`dashboard.py`)
   - Tool health card's existing top-impact gap counts get
     `IntensityGauge` mini-renders (cool = low impact, hot =
     high impact / many tools blocked).
   - Recent campaigns table gets severity breakdown
     (`45 (C:2 H:8)`) if not already present.
3. **CSS rules** in `app.tcss` for `.intensity-low`, `-mid`,
   `-high`, `-critical` so the gradient stops are theme-aware.

**Acceptance criteria for 6a:**
- `IntensityGauge` renders correctly at value=0.0, 0.5, 1.0,
  and out-of-range inputs.
- Budget bar visibly changes color as cost approaches limit
  when rendered in the dashboard quick-stats panel.
- 100% of new widgets have `run_test()` coverage.
- No regression in dashboard rendering on default / hicontrast
  / light themes.

#### TUI-6b — Runner overhaul (PR 2; depends on 6a)

1. **Runner activity surface overhaul**
   - Add `/` filter on the activity log. **Substring-based,
     not regex** — matches the existing palette's fuzzy/
     substring posture; operators don't already know a regex
     dialect here. Esc clears.
   - Filtering runs on a debounced worker (Textual's `@work`)
     so the 50ms perceived-latency target survives 2000-line
     buffers.
   - Add `Space` = pause/resume tail.
   - Add `[` / `]` = jump to previous/next phase boundary.
   - Add `n` / `N` = next/prev filter match (like vim).
   - Make the right-hand "Detail" pane contextual: when a line
     is selected in activity, show expanded info or related
     tool output.
2. **Live visualizations in runner header + stats**
   - Budget gauge becomes an `IntensityGauge`.
   - Add tiny findings-rate and active-tools sparklines.
   - Per-phase mini progress strip under the main `ChunkyBar`.

**Acceptance criteria for 6b:**
- Operator can type `/phase4` in the runner and instantly see
  only matching lines, latency < 50ms perceived on 2000-line
  log.
- Pause/resume + `[` / `]` + `n` / `N` work as documented.
- Detail pane updates when activity selection changes.
- No regression in existing runner behavior or log tailing.

**Files to touch/create (both PRs):**
- `nexusrecon/tui/widgets/gauges.py` (new — 6a)
- `nexusrecon/tui/widgets/__init__.py` (6a)
- `nexusrecon/tui/screens/dashboard.py` (6a)
- `nexusrecon/tui/screens/runner.py` (major rewrite — 6b)
- `nexusrecon/tui/app.tcss` (intensity classes — 6a)

**Filter syntax decision (2026-05-27 re-audit).** Substring,
not regex. Reasons: operators are already using a fuzzy-
matching palette (`fuzzy_score` in `command_palette.py`);
regex requires explaining a dialect; substring is what
lazygit/yazi use. If we later want regex it's an additive
keypress (`Ctrl+R` to toggle), not a default change.

**Mouse support (2026-05-27 re-audit).** OUT OF SCOPE for
TUI-6. Textual supports it but the operator value at this
stage is small (the TUI is keyboard-first by spec). Re-
evaluate after TUI-7.

**Study order:** btop meters → k9s filter implementation →
lazygit pane focus model.

### Phase TUI-7: "Every Surface Is a Power Tool"
**Goal:** Consistent high-agency interaction model across the app.

**Deliverables:**
1. **Global filter pattern** (`/` binding on all major list views)
   - Campaigns list
   - Tools list (already has some; make it first-class like k9s)
   - Reports list
   - Any future entity / finding tables
2. **Row-level action shortcuts** (consistent vocabulary)
   - `c` = configure / edit key
   - `t` = test (where applicable)
   - `d` / `i` = detail / info
   - `m` = mark reviewed (already in reports)
   - Document the vocabulary in the Help modal and palette.
3. **Stronger contextual detail panes**
   - Campaigns screen: selection populates a rich summary + actions pane (similar to reports browser).
   - Tools screen: already good; make the detail pane even richer (recent invocations, average duration, last error).
4. **Micro-interactions**
   - Skeleton loaders on dashboard recents and reports loading.
   - Focus ring emphasis when Tab cycles panes (match lazygit).
   - Better async spinners on wizard "Save & Run" and long palette queries.
   - Subtle scroll animations where Textual supports them.

**Files:**
- `nexusrecon/tui/screens/campaigns.py`
- `nexusrecon/tui/screens/tools.py`
- `nexusrecon/tui/screens/reports_browser.py` (refine)
- `nexusrecon/tui/screens/help.py` (update action vocabulary table)
- New shared filter mixin or behavior if it fits Textual patterns cleanly.

### Phase TUI-8: "Delight & Extensibility"
**Goal:** The "wow" features + plugin surface.

**Possible items (lower priority):**
- Theme contribution system (`~/.nexusrecon/themes/`)
- Sidebar entry registration decorator for plugins
- Optional kitty/sixel image previews for entity graphs or campaign artifacts (only when terminal supports it)
- "What's new" panel on dashboard pulling from `CHANGELOG.md`
- Crash-recovery banner (already in spec)
- Full two-press inline confirmation pattern (replace remaining modals)

---

## 7. Detailed Implementation Guides

### 7.1 Creating the Visualization Widget Library

Create `nexusrecon/tui/widgets/gauges.py`:

```python
from __future__ import annotations

from textual.reactive import reactive
from textual.widgets import Static
from rich.text import Text
from rich.console import RenderResult

# Color stops (must match severity philosophy — consistent across themes)
INTENSITY_COLORS = [
    (0.0, "#00ff9c"),   # cool mint
    (0.6, "#f1c40f"),   # warm amber
    (0.85, "#ff8c00"),  # hot orange
    (1.0, "#ff3838"),   # critical red
]

class IntensityGauge(Static):
    """Horizontal bar whose fill color shifts with value (cool → hot).

    Usage:
        gauge = IntensityGauge()
        gauge.value = 0.72
        gauge.total = 1.0
    """

    value: reactive[float] = reactive(0.0)
    total: float = 1.0
    width: int = 20

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)

    def watch_value(self, _old: float, _new: float) -> None:
        self.refresh(layout=True)

    def render(self) -> RenderResult:
        if self.total <= 0:
            return Text("[" + "░" * self.width + "]")

        pct = max(0.0, min(1.0, self.value / self.total))
        filled = int(round(pct * self.width))

        # Pick color by threshold
        color = INTENSITY_COLORS[-1][1]
        for threshold, c in INTENSITY_COLORS:
            if pct <= threshold:
                color = c
                break

        bar = "█" * filled + "░" * (self.width - filled)
        return Text.from_markup(f"[{color}]{bar}[/{color}] [bold]{pct*100:5.1f}%[/]")

class MiniSparkline(Static):
    """Tiny history graph using block characters."""

    # NOTE: ``reactive([])`` not ``reactive(list)``. Passing the
    # TYPE ``list`` makes Textual treat the class itself as the
    # default value; ``reactive([])`` correctly sets an empty
    # list per instance. (Bug caught in the 2026-05-27 re-audit.)
    history: reactive[list[float]] = reactive([])
    max_points: int = 30

    def render(self) -> RenderResult:
        if not self.history:
            return Text("▁" * 10)
        # Simple normalized block sparkline
        # (real version would use more sophisticated scaling + Rich segments)
        ...
```

**Next steps inside the file:**
- Add `PhaseProgressStrip` (multiple small `IntensityGauge` side-by-side or a single segmented bar).
- Add `render` methods that return proper Rich `Text` or `Segments` for best performance.
- Expose a `render_for_css` helper if you want theme variables to influence the cool/warm stops later.

Update `ChunkyBar` (currently at `runner.py:59`) to either inherit from or delegate to `IntensityGauge`.

Add CSS support in `app.tcss`:

```css
.intensity-critical { color: #ff3838; }
.intensity-high     { color: #ff8c00; }
/* etc. */
```

**Reference implementation patterns:** 
- bottom's `src/widgets/cpu.rs` or `src/render/` (excellent sparkline + gradient code)
- btop's meter drawing routines
- For Textual specifically: study how Harlequin renders its result tables and any custom `RenderResult` widgets. Also look at the Textual `Sparkline` experimental widget if it exists in your version, or the `rich` bar chart examples.

A good first spike: implement `IntensityGauge` as a pure `Static` that only uses Rich markup, then promote it to a full widget with reactive history once the visual language feels right.

### 7.2 Runner Activity Overhaul (Key Code Areas)

In `runner.py`:
- Replace the simple `Static` + `deque` activity log with a filterable view (consider a `DataTable` or a custom filtered `Static` + input row that appears on `/`).
- Store full history (capped at higher number, e.g. 2000) + filtered view.
- Implement phase boundary index for `[` / `]` jumps.
- Add `Input` (hidden until `/` pressed) for the filter, styled to look like k9s' filter bar.

Keep the existing `_LogTailer` for the detail pane.

Add keyboard handling via `def on_key(self, event)` or bindings + actions.

### 7.3 Adding `/` Filter Consistently

Recommended pattern (used successfully in many TUIs):
- Screen has a reactive `filter_text: str = ""`
- A hidden or collapsed `Input` that appears at the bottom or top of the list container when `/` is pressed.
- `on_input_changed` rebuilds the visible list (for `ListView` or `DataTable`).
- `Esc` while filtering clears + hides the input.
- Bind `("/")` to `action_focus_filter`.

Create a small mixin or helper class if duplication becomes painful.

---

## 8. Technical Guidelines

- **Stay on Textual.** The investment is high and Harlequin/ Posting prove the ceiling is excellent.
- Prefer **reactive properties** + `watch_*` methods over manual `query_one(...).update()`.
- New widgets should be pure enough to unit-test with `run_test()` (existing pattern in the codebase).
- All new CSS must go through the theme variable system (`$primary`, `$nx-*`, etc.). No new hardcoded colors except severity tints.
- Performance target: filter updates and 1 Hz refreshes must feel instant even on 5000+ line activity logs.
- Test matrix: default dark theme + hicontrast + light. Narrow (80-col) and wide terminals. Emoji vs text glyphs mode.
- Accessibility: maintain WCAG contrast; severity colours must remain distinguishable.

---

## 9. References & Study Materials

**Primary lists (bookmark these):**
- https://github.com/rothgar/awesome-tuis
- https://github.com/ratatui/awesome-ratatui
- https://github.com/matan-h/written-in-textual (Textual showcase)
- https://github.com/Kludex/awesome-textual

**Specific repos to clone and run:**
- yazi, lazygit, k9s (or k9s skins), bottom/btop, gitui, zellij, harlequin, posting, superfile

**Terminal emulators for best results during development:**
- Kitty (best image protocol support)
- WezTerm
- Ghostty (new hotness in 2025–2026)

**Textual resources:**
- Official Textual examples and widget gallery
- `textual run --dev` + the inspector
- Harlequin and Posting source as "how to make Textual look premium"

---

## 10. Success Criteria & Measurement

**Qualitative (the real goal):**
- A developer or operator who has used lazygit/btop/k9s says "this feels like one of those" when using the runner during a campaign.
- Screenshots of the TUI start appearing in unixporn and OSINT tooling threads without the author having to prompt.

**Quantitative / testable:**
- All new widgets have `run_test()` coverage.
- No regression in existing TUI test suite.
- Filter latency on 2000-line activity log < 50 ms perceived.
- Every major list view supports `/` filter (or has a documented reason why not).
- Theme switching works on all new visual elements.

**Definition of Done for TUI-6:**
- [ ] `gauges.py` merged with at least `IntensityGauge` + `MiniSparkline`
- [ ] Runner supports `/` filter + pause + phase jump + contextual detail
- [ ] Budget and phase visuals use the new intensity widgets
- [ ] Updated help text and palette entries for new bindings
- [ ] Screenshot/GIF added to `docs/demo/` or `README`

---

## 11. Risks & Mitigations

- **Textual rendering limits on complex live charts** → Prototype early with `Static` + Rich segments; fall back to simpler block rendering if needed. Consider contributing upstream if gaps are real.
- **Over-polish delaying core features** → Strict phase scoping. TUI-6 is runner only. Everything else waits.
- **Performance regression on very long campaigns** → Cap history + virtualized rendering (DataTable when possible). Measure.
- **Emoji / font / terminal variance** → Keep the `NEXUSRECON_TUI_GLYPHS=text` escape hatch. Test on CI with minimal TERM.

---

## Appendix A — Quick Command Cheat Sheet (Target State)

Global:
- `Ctrl+P` / `:` → Palette
- `?` → Help
- `/` → Filter (contextual)
- `Tab` → Cycle panes
- `]` → Toggle sidebar

Runner (new in TUI-6):
- `/` → Filter activity
- `Space` → Pause tail
- `[` `]` → Phase boundaries
- `n` `N` → Next/prev match
- `d` → Toggle / focus detail pane

(See Help modal for full matrix — keep it updated.)

---

**Next step for a developer:** 

1. Read this document + `docs/TUI_DESIGN_SPEC.md`.
2. Run the current TUI (`nexusrecon` or `python -m nexusrecon.tui.app`) and spend 10 minutes in a live campaign view.
3. Clone and run **btop** + **lazygit** + **k9s** (or a local k8s cluster) side-by-side in a modern terminal (Kitty recommended).
4. Start **TUI-6** by creating `nexusrecon/tui/widgets/gauges.py`.

Open a tracking issue titled "TUI-6: Runner Comes Alive" and link this file + the audit conversation.

This plan is designed to be executed incrementally without breaking the existing excellent foundation. Ship one beautiful thing at a time.

---

## Appendix B — Concrete Starting Checklist for TUI-6

- [ ] Create `nexusrecon/tui/widgets/gauges.py` with `IntensityGauge` (gradient block bar) and `MiniSparkline`.
- [ ] Refactor `ChunkyBar` in `nexusrecon/tui/screens/runner.py:59` to use the new library (or at least share rendering logic).
- [ ] Add `IntensityGauge` for the budget meter in the runner header (replace the simple `_render_gauge` in `status_bar.py` or the runner stats).
- [ ] Implement `/` filter + `Space` pause on the activity log inside `RunnerScreen`.
- [ ] Wire `[` / `]` phase jumping (you will need to track phase boundary line indices).
- [ ] Update `app.tcss` with new intensity classes and filter bar styling.
- [ ] Add the new bindings to the runner `BINDINGS` list and the global Help modal.
- [ ] Add a simple unit test using Textual's `run_test()` harness (mirror the pattern used for earlier TUI phases).
- [ ] Record a short demo GIF of the new runner (see `docs/demo/`).

**Key current code locations you will live in:**
- `nexusrecon/tui/screens/runner.py:525` (`_log` / `_detail` methods)
- `nexusrecon/tui/screens/runner.py:229` (where `ChunkyBar` is instantiated)
- `nexusrecon/tui/widgets/sidebar.py:50` (DEFAULT_CSS example of how to write widget styles)
- `nexusrecon/tui/app.tcss:316` (severity color classes — follow the same pattern)

---

## Appendix C — All Cited Projects (Quick Links)

- btop: https://github.com/aristocratos/btop
- bottom (btm): https://github.com/ClementTsang/bottom
- yazi: https://github.com/sxyazi/yazi
- lazygit: https://github.com/jesseduffield/lazygit
- k9s: https://github.com/derailed/k9s
- gitui: https://github.com/extrawurst/gitui
- zellij: https://github.com/zellij-org/zellij
- Harlequin (Textual): https://github.com/tconbeer/harlequin
- Posting (Textual): https://github.com/darrenburns/posting
- superfile: https://github.com/yorukot/superfile
- awesome-tuis: https://github.com/rothgar/awesome-tuis
- awesome-ratatui: https://github.com/ratatui/awesome-ratatui

Run them. Steal the feeling.