# Toolchain Integrations + Plugin SDK — Implementation Plan

Plan for ROADMAP `Path to 1.0.0 → Toolchain integration` and
`Path to 1.0.0 → Plugin SDK`. Written to be followable by a
contributor with no Claude-context. Each phase lists its
objective, pre-requisites, file-by-file change list, the
load-bearing snippets, test plan, documentation updates, and
acceptance criteria.

The five items are sequenced **shortest → longest**, and Plugin
Signing (item 5) is deliberately scheduled last because it
depends on a working plugin ecosystem existing first.

## Sequence overview

| Phase | Deliverable                         | Scope  | Depends on |
|-------|-------------------------------------|--------|-----------|
| 1     | Obsidian-friendly master report      | small  | —         |
| 2     | Plugin SDK (out-of-tree plugins)     | medium | —         |
| 3     | Burp Suite project file export       | medium | —         |
| 4     | BloodHound CE JSON export            | medium-large | Phase D/E identity + relationship graph (already shipped) |
| 5     | Plugin signing                       | large  | Phase 2 (Plugin SDK) shipped + at least 1 published plugin |

Each phase is an independent PR. Phases 1–4 can be reordered if
priorities change; phase 5 stays last.

---

# Phase 1 — Obsidian-friendly master report

> **Status: SHIPPED.** Implementation landed in the same PR as
> this status update. The acceptance criteria below remain as
> the regression contract; the unit tests in
> `tests/unit/test_obsidian_export.py` (35 tests) and the smoke
> parametrisation in `tests/unit/test_report_quality_smoke.py`
> (10 new tests across the 5 fixtures) pin each criterion.

## Objective

When an operator drops the campaign output directory into an
Obsidian vault, the master report renders with proper YAML
frontmatter, working wiki-style cross-references between
deliverables, and idiomatic Obsidian callouts — without breaking
the existing GitHub-flavored Markdown that the report ships with
today.

## Pre-requisites

- None — all changes are in `nexusrecon/reports/engine.py` and
  `nexusrecon/reports/full_report.py`. No data-model changes.

## Acceptance criteria

- [ ] When invoked with `--obsidian`, the campaign output
      directory contains a parallel `master_report.obsidian.md`
      that:
  - Starts with a YAML frontmatter block containing
    `campaign_id`, `engagement_id`, `target`, `generated`,
    `scope_hash`, `nexusrecon_version`, `tags`.
  - Uses `[[wikilink]]` syntax for every cross-reference to
    another file in the output directory (`asset_inventory.md`,
    `findings.json`, etc.).
  - Uses Obsidian callouts (`> [!note]`, `> [!warning]`,
    `> [!danger]`) instead of bare `> ` blockquotes for
    severity-tagged prose.
  - Renders correctly when the operator opens the directory
    as an Obsidian vault (manual verification screenshot in
    `docs/demo/obsidian.png`).
- [ ] When invoked WITHOUT `--obsidian`, behavior is byte-for-byte
      identical to today's output. The existing
      `master_report.md` is not modified.
- [ ] Unit tests pin the frontmatter shape + wikilink presence.
- [ ] `docs/obsidian.md` documents the workflow (drop directory
      into vault, set the option, where rendering differs from
      GitHub).

## Files to create / modify

| File | Change |
|---|---|
| `nexusrecon/cli/main.py` | New `--obsidian` flag on `run`, `report`, and `resume` commands. Sets `state["generate_obsidian"] = True`. |
| `nexusrecon/graph/state.py` | Add `generate_obsidian: bool` to `CampaignGraphState` TypedDict. |
| `nexusrecon/reports/engine.py` | Branch in `generate_all()` that, when `state.get("generate_obsidian")`, also emits the parallel file. |
| `nexusrecon/reports/obsidian_export.py` | NEW. Builds the Obsidian-flavored markdown from the same state the master_report uses, plus a Pythonic helper for emitting frontmatter + wikilinks. |
| `tests/unit/test_obsidian_export.py` | NEW. Frontmatter shape, wikilink rewrite, callout conversion, side-by-side parity vs the non-Obsidian path. |
| `tests/unit/test_report_quality_smoke.py` | Add a 6th fixture run with `generate_obsidian=True` to confirm the new path doesn't break under the existing varied target shapes. |
| `docs/obsidian.md` | NEW. Workflow walkthrough + screenshot. |
| `docs/demo/obsidian.png` | NEW. Screenshot of a generated report rendered in an Obsidian vault. |
| `README.md` | One bullet under Deliverables: "Obsidian-friendly export via `--obsidian` (see `docs/obsidian.md`)." |
| `ROADMAP.md` | Check off the item; describe what shipped. |

## Step-by-step implementation

### Step 1.1 — Add the CLI flag

Open `nexusrecon/cli/main.py`. Find the `run` Typer command's
parameter list (it's the longest argument block in the file).
Add:

```python
obsidian: bool = typer.Option(
    False, "--obsidian",
    help=(
        "Also emit master_report.obsidian.md — same content as "
        "master_report.md but with YAML frontmatter, [[wikilink]] "
        "cross-references, and Obsidian callouts. Drop the campaign "
        "directory into a vault to read."
    ),
),
```

Pass it into the initial state dict assembly:

```python
initial_state = {
    ...
    "generate_obsidian": obsidian,
}
```

Repeat for the `report` and `resume` subcommands so the flag is
available everywhere a report is generated.

### Step 1.2 — Add the state slot

Open `nexusrecon/graph/state.py`. Add to the `CampaignGraphState`
TypedDict:

```python
generate_obsidian: NotRequired[bool]
```

This is a "soft" slot — older campaigns reloaded from disk
without it just default to `False`.

### Step 1.3 — Create the Obsidian export module

Create `nexusrecon/reports/obsidian_export.py`:

```python
"""Obsidian-flavored master report.

The standard master_report.md is GitHub-flavored Markdown. Obsidian
renders most of it correctly but misses out on three things vaults
make heavy use of:

  - Frontmatter (YAML at the top of the file → Obsidian Properties).
  - Wikilinks (``[[asset_inventory]]``) for graph view.
  - Callouts (``> [!warning]``) instead of bare blockquotes.

This module produces a parallel file that adds those three. The
content of the file is otherwise byte-identical to master_report.md
so we don't fork the prose.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any


def render_frontmatter(state: dict[str, Any], scope_hash: str,
                       nexusrecon_version: str) -> str:
    """Build the YAML frontmatter block for the top of the file.

    Obsidian indexes these as Properties — they show up in the
    sidebar and in the file's Properties panel.
    """
    target = (state.get("seeds") or ["unknown"])[0]
    return (
        "---\n"
        f"campaign_id: {state.get('campaign_id', 'unknown')}\n"
        f"engagement_id: {state.get('engagement_id', 'unknown')}\n"
        f"target: {target}\n"
        f"generated: {state.get('generated', '')}\n"
        f"scope_hash: {scope_hash}\n"
        f"nexusrecon_version: {nexusrecon_version}\n"
        "tags:\n"
        "  - nexusrecon\n"
        "  - recon\n"
        "  - redteam\n"
        "---\n\n"
    )


# Match ``[label](file.md)`` and ``[label](file.json)`` style
# markdown links to files in the same directory. Skips http(s)
# URLs and external paths.
_LOCAL_LINK = re.compile(
    r"\[([^\]]+)\]\((?!https?://)([^)/\s]+\.(?:md|json|html|csv))\)"
)


def rewrite_local_links_to_wikilinks(md: str) -> str:
    """Convert ``[Asset Inventory](asset_inventory.md)`` →
    ``[[asset_inventory|Asset Inventory]]``.

    Obsidian's pipe syntax lets us keep the visible label distinct
    from the file name. Non-local links (http://, ../something,
    images) are left alone."""
    def _sub(m: re.Match[str]) -> str:
        label, fname = m.group(1), m.group(2)
        stem = fname.rsplit(".", 1)[0]
        return f"[[{stem}|{label}]]"

    return _LOCAL_LINK.sub(_sub, md)


# Severity → callout type. Obsidian's built-in callout names.
_SEVERITY_CALLOUTS = {
    "CRITICAL": "danger",
    "HIGH": "warning",
    "MEDIUM": "note",
    "LOW": "info",
}


def upgrade_severity_blockquotes(md: str) -> str:
    """Find bare ``> **CRITICAL**: …`` blockquotes and rewrite as
    ``> [!danger] CRITICAL\n> …`` callouts.

    Pattern is intentionally narrow — only blockquotes whose first
    line starts with a known severity get upgraded, to avoid
    accidentally rewriting prose blockquotes."""
    # Pattern: a line starting with ``> **<sev>**`` (optionally
    # preceded by other content on the same line).
    pattern = re.compile(
        r"^> \*\*(CRITICAL|HIGH|MEDIUM|LOW)\*\*[:.]?\s*(.*)$",
        re.MULTILINE,
    )

    def _sub(m: re.Match[str]) -> str:
        sev, rest = m.group(1), m.group(2).strip()
        callout = _SEVERITY_CALLOUTS[sev]
        if rest:
            return f"> [!{callout}] {sev}\n> {rest}"
        return f"> [!{callout}] {sev}"

    return pattern.sub(_sub, md)


def build_obsidian_master(
    standard_md: str,
    state: dict[str, Any],
    scope_hash: str,
    nexusrecon_version: str,
) -> str:
    """Take the standard master_report.md content + transform it
    into Obsidian-flavored output. Pure function — caller decides
    where to write."""
    body = rewrite_local_links_to_wikilinks(standard_md)
    body = upgrade_severity_blockquotes(body)
    return render_frontmatter(state, scope_hash, nexusrecon_version) + body
```

### Step 1.4 — Wire it into the engine

Open `nexusrecon/reports/engine.py`. In `generate_all()`, RIGHT
AFTER the existing master_report line:

```python
self.report_paths["master_report"] = self._master_report(state)
```

Add:

```python
if state.get("generate_obsidian"):
    self.report_paths["master_report_obsidian"] = (
        self._master_report_obsidian(state)
    )
```

Then add a new method on `ReportEngine`:

```python
def _master_report_obsidian(self, state: dict[str, Any]) -> str:
    """Emit master_report.obsidian.md alongside master_report.md.

    Reads the standard master_report's rendered text from disk so
    we don't duplicate the prose generation — the standard report
    has to land first."""
    from nexusrecon.reports.obsidian_export import build_obsidian_master

    standard_path = Path(self.report_paths["master_report"])
    standard_md = standard_path.read_text(encoding="utf-8")
    out = build_obsidian_master(
        standard_md=standard_md,
        state={
            **state,
            "campaign_id": self.campaign_id,
            "engagement_id": self.engagement_id,
            "generated": datetime.utcnow().isoformat(),
        },
        scope_hash=self.scope_hash,
        nexusrecon_version=self.nexusrecon_version,
    )
    path = self.output_dir / "master_report.obsidian.md"
    path.write_text(out, encoding="utf-8")
    return str(path)
```

### Step 1.5 — Write the tests

Create `tests/unit/test_obsidian_export.py`:

```python
"""Tests for the Obsidian-flavored master-report export."""
from __future__ import annotations

import re
from nexusrecon.reports.obsidian_export import (
    build_obsidian_master,
    render_frontmatter,
    rewrite_local_links_to_wikilinks,
    upgrade_severity_blockquotes,
)


class TestFrontmatter:
    def test_frontmatter_block_delimited_by_triple_dash(self):
        out = render_frontmatter(
            {"seeds": ["acme.com"], "campaign_id": "c1",
             "engagement_id": "e1", "generated": "2026-01-01T00:00:00"},
            scope_hash="sha256:abc",
            nexusrecon_version="0.6.0",
        )
        assert out.startswith("---\n")
        assert "\n---\n\n" in out

    def test_frontmatter_contains_every_required_field(self):
        out = render_frontmatter(
            {"seeds": ["acme.com"], "campaign_id": "c1",
             "engagement_id": "e1", "generated": "2026-01-01T00:00:00"},
            scope_hash="sha256:abc",
            nexusrecon_version="0.6.0",
        )
        for field in (
            "campaign_id: c1",
            "engagement_id: e1",
            "target: acme.com",
            "generated: 2026-01-01T00:00:00",
            "scope_hash: sha256:abc",
            "nexusrecon_version: 0.6.0",
            "tags:",
            "  - nexusrecon",
            "  - recon",
            "  - redteam",
        ):
            assert field in out, f"missing frontmatter field {field!r}"


class TestWikilinks:
    def test_local_md_link_becomes_wikilink(self):
        md = "See the [Asset Inventory](asset_inventory.md) for more."
        out = rewrite_local_links_to_wikilinks(md)
        assert "[[asset_inventory|Asset Inventory]]" in out

    def test_local_json_link_becomes_wikilink(self):
        md = "Raw findings: [findings](findings.json)."
        out = rewrite_local_links_to_wikilinks(md)
        assert "[[findings|findings]]" in out

    def test_external_link_is_preserved(self):
        md = "See [MITRE](https://attack.mitre.org)."
        out = rewrite_local_links_to_wikilinks(md)
        assert "[MITRE](https://attack.mitre.org)" in out
        assert "[[" not in out

    def test_image_link_is_preserved(self):
        md = "![diagram](entity_graph.html)"  # html is allowed
        # We DO want to rewrite html as wikilink (Obsidian opens them)
        out = rewrite_local_links_to_wikilinks(md)
        assert "[[entity_graph|diagram]]" in out


class TestCallouts:
    def test_critical_severity_becomes_danger_callout(self):
        md = "> **CRITICAL**: log4shell active on vpn.acme.com"
        out = upgrade_severity_blockquotes(md)
        assert "> [!danger] CRITICAL" in out
        assert "> log4shell active on vpn.acme.com" in out

    def test_high_severity_becomes_warning_callout(self):
        md = "> **HIGH**: exposed Cognito identity pool"
        out = upgrade_severity_blockquotes(md)
        assert "> [!warning] HIGH" in out

    def test_non_severity_blockquote_left_alone(self):
        md = "> A general note about the engagement."
        out = upgrade_severity_blockquotes(md)
        assert out == md


class TestBuildObsidianMaster:
    def test_frontmatter_precedes_body(self):
        standard = "# Master Report\n\n[Asset Inventory](asset_inventory.md)"
        out = build_obsidian_master(
            standard_md=standard,
            state={"seeds": ["acme.com"], "campaign_id": "c1",
                   "engagement_id": "e1", "generated": "now"},
            scope_hash="sha256:abc",
            nexusrecon_version="0.6.0",
        )
        # Frontmatter is at the very top.
        assert out.startswith("---\n")
        # Body follows.
        idx_body = out.index("# Master Report")
        idx_fm_close = out.index("\n---\n\n")
        assert idx_fm_close < idx_body
        # Wikilink replaced.
        assert "[[asset_inventory|Asset Inventory]]" in out
```

### Step 1.6 — Smoke-test the integrated path

Extend `tests/unit/test_report_quality_smoke.py`:

```python
# Add this test method to TestGeneratedReportsAcrossFixtures:

@pytest.mark.parametrize("name,fixture_fn", FIXTURES)
def test_obsidian_export_emitted_when_flagged(
    self, name: str, fixture_fn, engine: ReportEngine,
):
    """When generate_obsidian=True, the parallel file lands on
    disk and carries the YAML frontmatter."""
    state = fixture_fn()
    state["generate_obsidian"] = True
    paths = engine.generate_all(state)
    assert "master_report_obsidian" in paths
    obs = Path(paths["master_report_obsidian"]).read_text()
    assert obs.startswith("---\n")
    assert "campaign_id:" in obs
    assert "scope_hash:" in obs
```

### Step 1.7 — Vault verification (manual)

1. Generate a campaign using one of the test fixtures + `--obsidian`.
2. Open the campaign directory as an Obsidian vault.
3. Open `master_report.obsidian.md`. Confirm:
   - Properties panel shows the YAML fields.
   - Wikilinks to other deliverables open correctly.
   - Callouts render as colored boxes.
   - Graph View shows the deliverables connected.
4. Screenshot → `docs/demo/obsidian.png`.

### Step 1.8 — Write the operator docs

Create `docs/obsidian.md`:

```markdown
# Obsidian workflow

NexusRecon's master report renders cleanly in
[Obsidian](https://obsidian.md) when emitted with `--obsidian`.
The campaign output directory becomes a vault subfolder; the
report becomes a note with YAML frontmatter, wiki-style
cross-references between deliverables, and severity-tagged
callouts.

## Usage

    nexusrecon run --scope scope.yaml --obsidian

This emits `master_report.obsidian.md` alongside the standard
`master_report.md`. The standard file stays unchanged so
GitHub-rendered links and external markdown viewers still work.

## Setup

1. Open Obsidian → Vault → Open folder as vault → select the
   `campaigns/<engagement_id>/<timestamp>/` directory.
2. The first time, accept Obsidian's "this folder is a vault"
   prompt.
3. Open `master_report.obsidian.md`. Properties panel on the
   right shows the campaign metadata.

## What differs from the standard report

| Feature | Standard `master_report.md` | `master_report.obsidian.md` |
|---|---|---|
| Frontmatter | none | YAML block with campaign_id / target / scope_hash / version / tags |
| Cross-refs | `[label](file.md)` | `[[file\|label]]` |
| Severity blocks | `> **CRITICAL**: …` | `> [!danger] CRITICAL\n> …` |
| GitHub rendering | works | wikilinks appear as plain text |

## Screenshot

![Obsidian rendering](demo/obsidian.png)
```

### Step 1.9 — Update README + ROADMAP

In `README.md`'s Deliverables section, add a bullet:

```markdown
- **Obsidian-friendly master report.** `--obsidian` emits a
  parallel vault-ready file with YAML frontmatter, wikilinks
  between deliverables, and callouts. See [docs/obsidian.md].
```

In `ROADMAP.md`, check off the item with a one-line description
of what shipped.

## Test plan

- `pytest tests/unit/test_obsidian_export.py -v` — unit tests pass.
- `pytest tests/unit/test_report_quality_smoke.py -v` — smoke
  tests still pass, including the new fixture variant.
- Manual: vault verification per step 1.7. Pin the screenshot.
- Smoke: `nexusrecon run --scope tests/fixtures/scope_min.yaml --obsidian`
  on a known-good fixture; confirm both files land in the output
  directory.

## Risks / rollback

- **Risk:** Obsidian's callout syntax evolves. Mitigation: pin
  the syntax in tests so a regression is loud; document the
  Obsidian version we target in `docs/obsidian.md`.
- **Rollback:** Revert the PR. The standard master_report.md is
  untouched, so existing workflows are unaffected.

## Out of scope

- Auto-generating a vault `.obsidian/` config directory (vault
  metadata is operator-personal).
- Diagram embedding (Mermaid → Obsidian's mermaid renderer). The
  existing entity_graph.html is its own deliverable.

---

# Phase 2 — Plugin SDK (out-of-tree plugins)

## Objective

A community contributor can publish `nexusrecon-plugin-<x>` to
PyPI, the operator runs `pip install nexusrecon-plugin-<x>`, and
on the next NexusRecon launch the plugin's tools appear in the
registry — no fork, no edits to NexusRecon core.

## Pre-requisites

- None. The existing `plugins/example/` becomes the reference
  plugin and gets refactored to use the new SDK surface.

## Acceptance criteria

- [ ] `nexusrecon.plugin_sdk` module exists and re-exports the
      public API plugins import from: `OSINTTool`, `BaseHTTPTool`,
      `Category`, `Tier`, `ToolResult`, `register_tool`,
      `proxy_kwargs`. Module has a `__sdk_version__ = "1.0.0"`
      pinned semver.
- [ ] `ToolRegistry` discovers plugins via
      `importlib.metadata.entry_points(group="nexusrecon.tools")`
      on first access. Discovery is idempotent; tools registered
      via in-tree `@register_tool` are not double-registered.
- [ ] An external plugin (built from the new scaffold and
      published to TestPyPI) installs cleanly via `pip install`
      and its tools appear in `nexusrecon tools list` AND the TUI
      Tools browser, with a `🔌` marker indicating plugin source.
- [ ] Version compatibility check: a plugin declaring
      `nexusrecon-plugin-sdk>=2.0,<3.0` fails to load against
      SDK v1.0.0 with a clear error.
- [ ] `NEXUS_PLUGINS_DISABLED=plugin_a,plugin_b` env var mutes
      named plugins without uninstalling them.
- [ ] `nexusrecon plugins list` CLI subcommand prints every
      discovered plugin (name, version, source, status).
- [ ] `nexusrecon plugin init <name>` CLI subcommand scaffolds a
      new plugin directory with a working `pyproject.toml`,
      `<name>/__init__.py`, one example tool, a test, a README,
      and a CI config.
- [ ] Docs: `docs/plugin-sdk.md` with the contract, a "your
      first plugin in 5 minutes" walkthrough, and the stability
      policy.

## Files to create / modify

| File | Change |
|---|---|
| `nexusrecon/plugin_sdk/__init__.py` | NEW. The public API surface. |
| `nexusrecon/plugin_sdk/discovery.py` | NEW. Entry-point walker + version checker. |
| `nexusrecon/plugin_sdk/scaffold.py` | NEW. Generates a plugin starter from a Jinja template. |
| `nexusrecon/plugin_sdk/templates/` | NEW. Jinja templates for the scaffold. |
| `nexusrecon/tools/registry.py` | Call `discover_plugins()` once at registry construction. Track which tools came from plugins vs core. |
| `nexusrecon/cli/main.py` | New `plugins` Typer subcommand group with `list` and `init` actions. |
| `nexusrecon/tui/screens/tools.py` | Surface the `🔌` marker on plugin-sourced tools. |
| `plugins/example/` | REPLACED. Becomes a real published reference plugin built from the scaffold. |
| `docs/plugin-sdk.md` | NEW. Contract + walkthrough. |
| `docs/plugin-stability-policy.md` | NEW. Semver guarantees, deprecation timeline. |
| `tests/unit/test_plugin_sdk.py` | NEW. Public surface stability + discovery + version-check tests. |
| `tests/integration/test_plugin_discovery.py` | NEW. End-to-end: install a fake plugin, see it appear in the registry. |
| `README.md` | New section: "Writing a plugin". |
| `ROADMAP.md` | Check off + describe. |

## Step-by-step implementation

### Step 2.1 — Define the public SDK surface

Create `nexusrecon/plugin_sdk/__init__.py`:

```python
"""NexusRecon plugin SDK — the public surface plugins import from.

Plugins MUST import only from ``nexusrecon.plugin_sdk``. Anything
in ``nexusrecon.tools``, ``nexusrecon.core``, etc. is internal and
may change without notice. The SDK is semver-pinned via
``__sdk_version__``; plugins declare their required range in
``pyproject.toml`` via the ``nexusrecon-plugin-sdk`` extra.

Stability policy: see ``docs/plugin-stability-policy.md``. TL;DR:
breaking changes to anything exported below land in a major SDK
version bump only.
"""
from __future__ import annotations

# Public re-exports. Every symbol here is part of the SDK contract.
from nexusrecon.tools.base import (
    BaseHTTPTool,
    Category,
    OSINTTool,
    Tier,
    ToolResult,
)
from nexusrecon.tools.registry import register_tool
from nexusrecon.opsec.context import proxy_kwargs
from nexusrecon.opsec.useragent import random_ua

# Semver. Plugins declare the range they support via
#     nexusrecon-plugin-sdk = ">=1.0,<2.0"
# The discovery layer reads this and refuses to load mismatches.
__sdk_version__ = "1.0.0"

__all__ = [
    "BaseHTTPTool",
    "Category",
    "OSINTTool",
    "Tier",
    "ToolResult",
    "register_tool",
    "proxy_kwargs",
    "random_ua",
    "__sdk_version__",
]
```

### Step 2.2 — Define the discovery mechanism

Create `nexusrecon/plugin_sdk/discovery.py`:

```python
"""Out-of-tree plugin discovery via setuptools entry_points.

Plugins declare themselves via ``pyproject.toml``:

    [project.entry-points."nexusrecon.tools"]
    acme = "nexusrecon_plugin_acme:register"

The ``register`` callable accepts no args and is expected to
import its tool modules (whose ``@register_tool`` decorators
populate the global registry as a side effect). It MAY also
return a list of tool classes; we accept both shapes.

Discovery runs once at registry construction. The `NEXUS_PLUGINS_DISABLED`
env var (comma-separated entry-point names) mutes specific
plugins. The `NEXUS_PLUGINS_DEBUG=1` env var prints discovery
events to structlog at INFO level.
"""
from __future__ import annotations

import importlib.metadata as _md
import os
import re
from typing import TYPE_CHECKING

import structlog

if TYPE_CHECKING:
    from nexusrecon.tools.base import OSINTTool

log = structlog.get_logger(__name__)

# Group name for entry-point discovery. Pinned — changing this is
# a major SDK bump because every published plugin's pyproject.toml
# references it.
_ENTRY_POINT_GROUP = "nexusrecon.tools"

# Track which tool names came from which plugin source so the TUI
# / CLI can surface origin. Populated by discover_plugins().
PLUGIN_SOURCED_TOOLS: dict[str, str] = {}  # tool_name → plugin_name


def _parse_sdk_requirement(plugin_pkg: str) -> tuple[str, str] | None:
    """Extract the plugin's declared ``nexusrecon-plugin-sdk``
    requirement from its package metadata. Returns None if the
    plugin doesn't declare one (older plugins, pre-versioning)."""
    try:
        dist = _md.distribution(plugin_pkg)
    except _md.PackageNotFoundError:
        return None
    for req in dist.requires or []:
        # PEP 508 requirement strings like
        # "nexusrecon-plugin-sdk>=1.0,<2.0"
        m = re.match(r"^nexusrecon-plugin-sdk\s*([<>=!~,.\d\s]+)$", req)
        if m:
            return plugin_pkg, m.group(1).strip()
    return None


def _check_sdk_compat(plugin_name: str, plugin_pkg: str) -> bool:
    """True iff the plugin's declared SDK range includes our version."""
    from packaging.specifiers import SpecifierSet
    from packaging.version import Version

    from nexusrecon.plugin_sdk import __sdk_version__

    req = _parse_sdk_requirement(plugin_pkg)
    if req is None:
        # No declared requirement → assume compatible. We log a
        # warning so the maintainer knows to add one but we don't
        # refuse to load.
        log.warning(
            "Plugin declares no SDK requirement",
            plugin=plugin_name, plugin_pkg=plugin_pkg,
        )
        return True
    _, spec_str = req
    try:
        spec = SpecifierSet(spec_str)
    except Exception as exc:
        log.error(
            "Plugin SDK requirement is unparseable",
            plugin=plugin_name, spec=spec_str, error=str(exc),
        )
        return False
    if Version(__sdk_version__) not in spec:
        log.error(
            "Plugin SDK requirement does not match our SDK version",
            plugin=plugin_name, declared=spec_str,
            our_version=__sdk_version__,
        )
        return False
    return True


def discover_plugins() -> list[str]:
    """Walk entry_points(group="nexusrecon.tools") and import each.

    Returns the list of plugin names successfully discovered. The
    ``@register_tool`` decorators in each plugin's tool modules
    populate the global registry as a side effect of importing.
    """
    disabled = set(
        filter(None, (os.environ.get("NEXUS_PLUGINS_DISABLED") or "").split(","))
    )
    debug = os.environ.get("NEXUS_PLUGINS_DEBUG") == "1"

    discovered: list[str] = []
    try:
        eps = _md.entry_points(group=_ENTRY_POINT_GROUP)
    except Exception as exc:
        log.warning("Entry-point lookup failed", error=str(exc))
        return []

    # Sort for deterministic discovery order — makes the TUI
    # listing stable across launches.
    for ep in sorted(eps, key=lambda e: e.name):
        if ep.name in disabled:
            if debug:
                log.info("Plugin disabled via env", plugin=ep.name)
            continue
        # The entry-point's module is the plugin's top-level
        # package (the part before the colon).
        plugin_pkg = ep.value.split(":")[0]
        if not _check_sdk_compat(ep.name, plugin_pkg):
            continue
        try:
            # Capture which tools register during this load so we
            # can attribute them to the plugin.
            from nexusrecon.tools.registry import get_registry
            before = set(get_registry()._tools.keys())
            target = ep.load()
            # An entry_point can resolve to either a callable
            # (which we invoke) or a module (whose import side
            # effects already populated the registry).
            if callable(target):
                target()
            after = set(get_registry()._tools.keys())
            new_tools = after - before
            for name in new_tools:
                PLUGIN_SOURCED_TOOLS[name] = ep.name
            log.info(
                "Plugin loaded",
                plugin=ep.name, tool_count=len(new_tools),
                tools=sorted(new_tools),
            )
            discovered.append(ep.name)
        except Exception as exc:
            log.error(
                "Plugin failed to load",
                plugin=ep.name, error=str(exc), error_type=type(exc).__name__,
            )
            # Continue — one broken plugin must not kill the others.

    return discovered
```

### Step 2.3 — Wire discovery into the registry

In `nexusrecon/tools/registry.py`, modify `get_registry()` (the
`@lru_cache(maxsize=1)` function at the bottom) to call discovery
on first access:

```python
@lru_cache(maxsize=1)
def get_registry() -> ToolRegistry:
    """Return the singleton tool registry."""
    registry = ToolRegistry()
    # Discover out-of-tree plugins (entry_points). Idempotent
    # because lru_cache runs this only once.
    try:
        from nexusrecon.plugin_sdk.discovery import discover_plugins
        discover_plugins()
    except Exception:
        # Discovery never blocks core launch; failures land in the
        # structlog stream.
        pass
    return registry
```

> **Note:** The existing in-tree tools are registered via the
> `@register_tool` decorator at module import time. Since the
> registry is the same singleton, the order doesn't matter — the
> tools are in the dict whether their module imported before or
> after `discover_plugins()` ran.

### Step 2.4 — Mark plugin tools in the TUI

In `nexusrecon/tui/screens/tools.py`, in `_render_tool_row`, add
the plugin marker:

```python
def _render_tool_row(self, tool: dict[str, Any]) -> str:
    # ... existing icon resolution ...
    name = tool.get("name", "?")
    from nexusrecon.plugin_sdk.discovery import PLUGIN_SOURCED_TOOLS
    plugin_marker = "🔌 " if name in PLUGIN_SOURCED_TOOLS else ""
    return f"{icon}  {plugin_marker}[bold]{name}[/bold]  [dim]{tool.get('tier', '?')}[/dim]"
```

### Step 2.5 — Add the `nexusrecon plugins` CLI subcommand

In `nexusrecon/cli/main.py`, add:

```python
plugins_app = typer.Typer(
    help="Manage out-of-tree NexusRecon plugins.",
    no_args_is_help=True,
)
app.add_typer(plugins_app, name="plugins")


@plugins_app.command("list")
def plugins_list() -> None:
    """List every installed plugin and the tools it ships."""
    from nexusrecon.plugin_sdk.discovery import PLUGIN_SOURCED_TOOLS, discover_plugins

    # Force discovery (in case the user installed since launch).
    discover_plugins()

    if not PLUGIN_SOURCED_TOOLS:
        typer.echo("(no plugins installed)")
        return
    by_plugin: dict[str, list[str]] = {}
    for tool_name, plugin_name in PLUGIN_SOURCED_TOOLS.items():
        by_plugin.setdefault(plugin_name, []).append(tool_name)
    for plugin_name, tools in sorted(by_plugin.items()):
        typer.echo(f"\n{plugin_name}:")
        for t in sorted(tools):
            typer.echo(f"  - {t}")


@plugins_app.command("init")
def plugins_init(name: str = typer.Argument(..., help="Plugin name (kebab-case)")) -> None:
    """Scaffold a new plugin in ./<name>/ from the SDK template."""
    from nexusrecon.plugin_sdk.scaffold import scaffold_plugin

    target_dir = Path.cwd() / name
    if target_dir.exists():
        typer.echo(f"error: {target_dir} already exists", err=True)
        raise typer.Exit(code=1)
    scaffold_plugin(name=name, target_dir=target_dir)
    typer.echo(f"\nWrote {target_dir}/")
    typer.echo(f"\nNext steps:\n  cd {name}\n  pip install -e .\n  pytest")
```

### Step 2.6 — Build the scaffold

Create `nexusrecon/plugin_sdk/scaffold.py`:

```python
"""Generate a plugin starter project from Jinja templates.

Called from ``nexusrecon plugin init <name>``. Writes a working
plugin to ``./<name>/`` with:

  - pyproject.toml declaring the entry_point + SDK dependency
  - <package>/__init__.py with the register() callable
  - <package>/tools.py with one example tool
  - tests/test_smoke.py exercising the example tool
  - .github/workflows/test.yml for plugin CI
  - README.md with publication instructions
"""
from __future__ import annotations

import re
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

_TEMPLATES_DIR = Path(__file__).parent / "templates"


def _normalise_names(name: str) -> dict[str, str]:
    """Derive the package, module, and entry-point names from the
    user-supplied plugin name."""
    if not re.match(r"^[a-z][a-z0-9-]*$", name):
        raise ValueError(
            f"Plugin name must be lowercase kebab-case: got {name!r}"
        )
    # nexusrecon-plugin-acme  →  nexusrecon_plugin_acme  (Python pkg)
    #                       →  acme                       (entry-point)
    package = name.replace("-", "_")
    if name.startswith("nexusrecon-plugin-"):
        ep_name = name[len("nexusrecon-plugin-"):]
    else:
        ep_name = name
    return {"name": name, "package": package, "ep_name": ep_name}


def scaffold_plugin(name: str, target_dir: Path) -> None:
    env = Environment(
        loader=FileSystemLoader(str(_TEMPLATES_DIR)),
        autoescape=select_autoescape([]),
        keep_trailing_newline=True,
    )
    ctx = _normalise_names(name)

    target_dir.mkdir(parents=True)
    files = [
        ("pyproject.toml.j2",          "pyproject.toml"),
        ("README.md.j2",               "README.md"),
        ("__init__.py.j2",             f"{ctx['package']}/__init__.py"),
        ("tools.py.j2",                f"{ctx['package']}/tools.py"),
        ("test_smoke.py.j2",           "tests/test_smoke.py"),
        ("ci.yml.j2",                  ".github/workflows/test.yml"),
    ]
    for tpl_name, out_name in files:
        out_path = target_dir / out_name
        out_path.parent.mkdir(parents=True, exist_ok=True)
        rendered = env.get_template(tpl_name).render(**ctx)
        out_path.write_text(rendered, encoding="utf-8")
```

Then create the templates under `nexusrecon/plugin_sdk/templates/`.
Key one is `pyproject.toml.j2`:

```jinja2
[project]
name = "{{ name }}"
version = "0.1.0"
description = "NexusRecon plugin: {{ ep_name }}"
requires-python = ">=3.11"
dependencies = [
    # Pin the SDK range. Raise the lower bound when you adopt
    # newer SDK features; raise the upper bound only when the
    # SDK ships a tested major version your tools support.
    "nexusrecon-plugin-sdk>=1.0,<2.0",
    "httpx",
]

[project.entry-points."nexusrecon.tools"]
{{ ep_name }} = "{{ package }}:register"

[build-system]
requires = ["setuptools>=68"]
build-backend = "setuptools.build_meta"

[tool.setuptools.packages.find]
include = ["{{ package }}*"]
```

(Other templates follow the same pattern. Document each in
`docs/plugin-sdk.md`.)

### Step 2.7 — Refactor `plugins/example/` to use the SDK

Delete the existing `plugins/example/my_tool.py` (it imports from
internal paths). Replace with a real plugin built from the
scaffold, but kept in-tree for documentation:

```
plugins/example/
├── pyproject.toml
├── README.md
├── nexusrecon_plugin_example/
│   ├── __init__.py
│   └── tools.py
└── tests/
    └── test_smoke.py
```

The contents of `nexusrecon_plugin_example/__init__.py`:

```python
"""nexusrecon-plugin-example — reference plugin.

This is the canonical example. Adapt it for your own tools.
"""
from __future__ import annotations


def register() -> None:
    """Entry-point hook. NexusRecon calls this once at startup.

    Importing the tools module is enough — the @register_tool
    decorators in tools.py register the classes as a side effect.
    """
    from nexusrecon_plugin_example import tools  # noqa: F401
```

The contents of `nexusrecon_plugin_example/tools.py`:

```python
"""Example tools from the reference plugin."""
from __future__ import annotations

from typing import Any

from nexusrecon.plugin_sdk import (
    Category,
    OSINTTool,
    Tier,
    ToolResult,
    register_tool,
)


@register_tool
class ExampleHelloTool(OSINTTool):
    name = "example_hello"
    tier = Tier.T0
    category = Category.DOMAIN
    requires_keys = []
    description = "Reference plugin tool — emits a hello-world ToolResult"
    target_types = ["domain"]

    async def run(self, target: str, **kwargs: Any) -> ToolResult:
        return ToolResult(
            success=True,
            source=self.name,
            data={"greeting": f"hello, {target}"},
            result_count=1,
        )
```

### Step 2.8 — Write SDK tests

Create `tests/unit/test_plugin_sdk.py`. Key tests:

- `test_public_api_surface_unchanged` — assert
  `nexusrecon.plugin_sdk.__all__` contains exactly the expected
  symbols. Catches accidental additions.
- `test_sdk_version_is_semver` — pin the version format.
- `test_discovery_idempotent` — call `discover_plugins()` twice;
  registry size doesn't double.
- `test_disabled_plugins_env_skips_them` — set
  `NEXUS_PLUGINS_DISABLED=foo`, mock entry_points to surface a
  plugin named `foo`, confirm skipped.
- `test_sdk_version_mismatch_refused` — mock a plugin declaring
  `nexusrecon-plugin-sdk>=99.0,<100.0`, confirm not loaded.
- `test_plugin_failure_does_not_kill_discovery` — mock two
  plugins, one raises on load; the other still loads.

Create `tests/integration/test_plugin_discovery.py` that:

1. Builds a wheel for `plugins/example/` to a tmpdir.
2. `pip install`s it into a sub-venv.
3. Launches NexusRecon as a subprocess in that venv.
4. Runs `nexusrecon tools list` and confirms `example_hello`
   appears.
5. Runs `nexusrecon plugins list` and confirms the plugin name.

This test is slow (~30s); gate it with `@pytest.mark.slow` and
exclude from the default `pytest` run.

### Step 2.9 — Documentation

`docs/plugin-sdk.md`: the contract + walkthrough. Key sections:
- "What lives in the SDK" (the `__all__` list).
- "Your first plugin in 5 minutes" — `nexusrecon plugins init
  acme-osint && cd acme-osint && pip install -e . && nexusrecon
  tools list`.
- "Anatomy of the scaffold" — explain each file the scaffold
  generates.
- "Publishing to PyPI" — standard `python -m build && twine
  upload` workflow.
- "Versioning your plugin" — match `nexusrecon-plugin-sdk`
  ranges to your tested SDK versions.
- "Discovery internals" — for the curious, point at
  `nexusrecon/plugin_sdk/discovery.py`.

`docs/plugin-stability-policy.md`: the semver promise. Key
sections:
- "What's stable" (everything in `plugin_sdk.__all__`).
- "What's not stable" (anything under `nexusrecon.tools`,
  `nexusrecon.core`, etc. — plugins importing from there break
  at their own risk).
- "Deprecation timeline" — a symbol marked deprecated stays
  for at least one minor SDK release.
- "How we ship SDK breaking changes" — major SDK version bump +
  CHANGELOG entry + migration guide.

## Test plan

- `pytest tests/unit/test_plugin_sdk.py -v` — all unit tests pass.
- `pytest tests/integration/test_plugin_discovery.py -v -m slow` —
  end-to-end discovery works.
- Manual: scaffold a new plugin, install, confirm it appears.
- Manual: install `plugins/example/` via `pip install -e
  plugins/example`; confirm `example_hello` appears in `nexusrecon
  tools list` AND the TUI Tools browser with `🔌` marker.

## Risks / rollback

- **Risk:** Plugins import internal APIs anyway. Mitigation:
  `docs/plugin-stability-policy.md` documents the policy; we
  can't programmatically prevent it.
- **Risk:** Discovery slows launch. Mitigation: log the discovery
  duration; if it exceeds 500ms, consider lazy discovery (only
  on first registry lookup that misses).
- **Rollback:** Discovery is gated by a try/except — failure is
  silent. To fully roll back, comment out the
  `discover_plugins()` call in `get_registry()`.

## Out of scope

- Sandboxing plugin code (plugins run with full process
  privileges).
- A plugin marketplace.
- Plugin signing — that's Phase 5.

---

# Phase 3 — Burp Suite project file export

## Objective

When the operator pivots from NexusRecon recon to Burp Suite for
active testing, they can drop a single XML file into Burp's
Target → Site Map and have every discovered URL pre-loaded with
the right scope.

## Pre-requisites

- None. The data we need (URLs surfaced by httpx, wayback, gau,
  katana, etc.) is already on `state["url_intel"]` or in
  individual tools' output.

## Acceptance criteria

- [ ] `nexusrecon run --burp-export` (or always-on; see
      decisions) emits `burp_sitemap.xml` in the campaign output
      directory.
- [ ] The XML imports cleanly into Burp Suite Community 2024.1+
      via Target → Site Map → right-click → Import items.
- [ ] Every URL in the XML carries a comment with the source
      tool name + the scope hash so the operator can confirm
      provenance.
- [ ] Tests use a fixture XML known to parse with Burp's importer
      (we ship a Burp-validated reference file in
      `tests/fixtures/burp/`).

## Files to create / modify

| File | Change |
|---|---|
| `nexusrecon/cli/main.py` | New `--burp-export` flag. |
| `nexusrecon/graph/state.py` | Add `burp_export: bool` slot. |
| `nexusrecon/reports/engine.py` | Branch in `generate_all()` that calls the new builder. |
| `nexusrecon/reports/burp_export.py` | NEW. Builds the XML from `state["url_intel"]` + finding-cited URLs. |
| `tests/unit/test_burp_export.py` | NEW. Schema validation + round-trip parse. |
| `tests/fixtures/burp/reference_import.xml` | NEW. A known-good Burp-validated reference for parser tests. |
| `docs/burp-export.md` | NEW. How to use. |

## Step-by-step implementation

### Step 3.1 — Understand the Burp Site Map XML format

The format is documented in Burp's PortSwigger documentation but
the schema is sparse. A minimal valid entry:

```xml
<?xml version="1.0"?>
<!DOCTYPE items [<!ELEMENT items ANY> <!ATTLIST items burpVersion CDATA "" exportTime CDATA "">]>
<items burpVersion="2024.1.1" exportTime="Tue Jan 01 00:00:00 UTC 2026">
  <item>
    <time>Tue Jan 01 00:00:00 UTC 2026</time>
    <url><![CDATA[https://example.com/api/v1/health]]></url>
    <host ip="93.184.216.34">example.com</host>
    <port>443</port>
    <protocol>https</protocol>
    <method><![CDATA[GET]]></method>
    <path><![CDATA[/api/v1/health]]></path>
    <extension>null</extension>
    <request base64="false"><![CDATA[GET /api/v1/health HTTP/1.1
Host: example.com
User-Agent: NexusRecon recon

]]></request>
    <status>0</status>
    <responselength>0</responselength>
    <mimetype></mimetype>
    <response base64="false"><![CDATA[]]></response>
    <comment><![CDATA[Source: httpx — Scope: sha256:abc123]]></comment>
  </item>
</items>
```

We can omit response details because we don't have them for most
URLs — Burp accepts items with empty response bodies.

### Step 3.2 — Build the exporter

Create `nexusrecon/reports/burp_export.py`. Key points:

- Use `xml.etree.ElementTree` from stdlib — no new dependency.
- Source URLs from `state["url_intel"]`,
  `state["subdomain_intel"]` (build `https://<sub>/`), and any
  finding's `affected_assets` that look like URLs.
- Deduplicate by full URL string.
- Add `<comment>` carrying source-tool name + scope hash.
- Emit `<host ip="...">` only when we know the IP from
  `dns_intel`; otherwise omit the `ip` attribute (Burp tolerates
  this).

### Step 3.3 — Reference fixture

`tests/fixtures/burp/reference_import.xml` is a small (3-5 URL)
file that the maintainer manually imports into Burp once and
confirms parses without errors. Commit alongside a one-line
README explaining how it was validated.

### Step 3.4 — Tests

`tests/unit/test_burp_export.py` covers:

- Empty state → minimum-valid XML (just the `<items>` envelope).
- Single URL state → one `<item>` with all required children.
- URL dedup → two state sources for the same URL → one `<item>`.
- XML parses with `ET.parse` (round-trip sanity).
- Output schema matches `reference_import.xml` (structural diff,
  not byte-equal).

### Step 3.5 — Documentation

`docs/burp-export.md`:

```markdown
# Burp Suite export

When run with `--burp-export`, NexusRecon emits
`burp_sitemap.xml` alongside the standard deliverables. Drop it
into Burp's Site Map and the URLs we discovered appear as
in-scope targets ready for active testing.

## Usage

    nexusrecon run --scope scope.yaml --burp-export

## Import in Burp

1. Open Burp Suite → Target → Site map.
2. Right-click the root of the site tree → Import items.
3. Choose `burp_sitemap.xml`.

The imported items carry a comment with the source-tool name +
the scope hash, so you can confirm provenance via Burp's item
detail panel.

## Caveats

- Response bodies are empty. NexusRecon's recon phase captures
  URLs, not full HTTP transcripts. Burp re-fetches when you
  send items to the Repeater.
- HTTPS items have port 443 even when the target enforces TLS
  on a non-standard port. Edit the items if needed.

## Tested with

- Burp Suite Community 2024.1.1
- Burp Suite Professional 2024.1.1
```

## Out of scope

- Burp issues (the bug-tracker side). Future enhancement.
- HAR export (richer but invents request envelopes we don't
  actually have).

---

# Phase 4 — BloodHound CE JSON export

## Objective

Phase E's relationship graph and Phase D's identity-attribution
data drop into BloodHound CE as a custom OpenGraph data source.
Operators with BloodHound already loaded can run Cypher queries
across `(SharpHound AD nodes) ⨝ (NexusRecon Identity + Phase E
edges)`.

## Pre-requisites

- Phase D `IdentityGraph` (shipped).
- Phase E `RelationshipGraph` (shipped).
- BloodHound CE 6.x target (current major).

## Acceptance criteria

- [ ] `nexusrecon run --bloodhound-export` emits
      `bloodhound_export.zip` containing JSON files matching
      BloodHound CE 6's OpenGraph ingestion schema.
- [ ] The zip loads cleanly via BloodHound's `bloodhound-cli`
      ingestion (`bloodhound-cli ingest bloodhound_export.zip`).
- [ ] After ingestion, BloodHound's UI shows the new nodes/edges
      and a documented Cypher query returns expected results
      (e.g. `MATCH (u:User)-[r:HasInteractedWith]-(t:User)
      RETURN u, r, t LIMIT 25`).
- [ ] Tests cover the JSON schema for each node/edge type
      separately, plus a smoke test on the assembled zip.

## Files to create / modify

| File | Change |
|---|---|
| `nexusrecon/cli/main.py` | `--bloodhound-export` flag. |
| `nexusrecon/graph/state.py` | `bloodhound_export: bool` slot. |
| `nexusrecon/reports/engine.py` | Branch in `generate_all()`. |
| `nexusrecon/reports/bloodhound_export.py` | NEW. Top-level builder. |
| `nexusrecon/reports/bloodhound/nodes.py` | NEW. Per-node-type emitters (User, Tenant, Breach). |
| `nexusrecon/reports/bloodhound/edges.py` | NEW. Per-edge-type emitters. |
| `tests/unit/test_bloodhound_export.py` | NEW. Per-emitter unit tests. |
| `tests/integration/test_bloodhound_smoke.py` | NEW. End-to-end zip shape. |
| `docs/bloodhound-export.md` | NEW. How to use + sample queries. |

## Step-by-step implementation

### Step 4.1 — Pin the target BloodHound CE schema version

BloodHound CE versions its OpenGraph format. Pick the current
stable major (6 at time of writing). Document this in the file
header of `bloodhound_export.py` so a future BloodHound bump is
a conscious decision.

### Step 4.2 — Map NexusRecon concepts to BloodHound nodes

| NexusRecon concept | BloodHound node label | Properties |
|---|---|---|
| `Identity` with `corp_email` | `User` | `name`, `email`, `displayname`, plus all our `metadata` fields as custom properties |
| `Identity` with personal-only identifiers | `User` (kind=`PersonalIdentity`) | Same shape, different kind |
| `cloud_intel["azure/onmicrosoft"].onmicrosoft_domain.domains[].tenant_id` | `AZTenant` | `tenantid`, `name=megacorp.onmicrosoft.com` |
| `credential_exposures[]` | `Breach` (new kind) | `source`, `date_observed` |

### Step 4.3 — Map edges

| Source signal | Edge type | Properties |
|---|---|---|
| `RelationshipEdge(interaction_type="co_author")` | `HasInteractedWith` | `strength`, `last_observed`, `sources` |
| `Identity` → `Breach` | `BreachedIn` | `breach_date` |
| `AZTenant` federated via Okta | `FederatedWith` (custom) | `idp_url` |

### Step 4.4 — Emit the OpenGraph JSON

BloodHound CE's OpenGraph format is one file per node type and
one per edge type. The top-level zip layout:

```
bloodhound_export.zip
├── meta.json                   # metadata (data source name, version)
├── opengraph_users.json        # all User nodes
├── opengraph_tenants.json      # all AZTenant nodes
├── opengraph_breaches.json     # all Breach nodes (custom kind)
└── opengraph_relationships.json   # all edges
```

Each file's shape:

```json
{
  "data": [
    {
      "id": "<stable hex>",
      "kind": "User",
      "properties": { ... }
    },
    ...
  ]
}
```

Use the existing `derive_identity_id` for the User node id so
the same person across ingestions maps to the same node.

### Step 4.5 — Tests

Unit tests cover each node and edge emitter in isolation. The
integration test builds an in-process state with a small mixed
graph, runs the exporter, opens the zip, and asserts:

- Every node has a stable `id` and a recognised `kind`.
- Every edge references existing node ids.
- meta.json carries our `nexusrecon_version` + scope_hash.
- The zip extracts without errors via `zipfile.ZipFile`.

### Step 4.6 — Documentation

`docs/bloodhound-export.md`:

- Workflow walkthrough.
- BloodHound CE setup link (we don't bundle it).
- The Cypher query that confirms our data ingested correctly.
- A few "useful query" examples (e.g. "show me users with both
  a SharpHound-tagged AD presence AND a NexusRecon breach hit").
- Pinned BloodHound CE version + how to react if BHCE bumps majors.

### Step 4.7 — Manual smoke

Spin up BloodHound CE locally, run an export against a known
fixture, ingest, run the documented Cypher queries, screenshot
the result for `docs/demo/bloodhound.png`.

## Out of scope

- A SharpHound-equivalent AD collector. NexusRecon doesn't have
  domain-joined access; OpenGraph custom data is our lane.
- Live BloodHound API push. Export to file → operator ingests.

---

# Phase 5 — Plugin signing

## Objective

An operator on a sensitive engagement can configure a trust
policy that loads only plugins signed by an allow-listed key,
mitigating supply-chain risk from a malicious or compromised
PyPI package.

## Pre-requisites

- Phase 2 (Plugin SDK) shipped.
- At least one published plugin to test against (the reference
  example plugin from Phase 2).

## Acceptance criteria

- [ ] Plugin authors can sign their wheel with cosign
      (`cosign sign-blob`). Signature artifact lives alongside
      the wheel.
- [ ] NexusRecon's discovery layer verifies signatures against
      the configured trust policy before loading.
- [ ] Trust policy modes: `off` (no verification, default in
      0.6-0.x), `warn` (verify + log on failure, load anyway),
      `strict` (refuse to load unsigned/mismatched).
- [ ] `~/.nexusrecon/plugin-trust.yaml` declares allow-listed
      keys (cosign public keys or Fulcio identity strings).
- [ ] `nexusrecon plugins audit` lists every installed plugin
      with signature status.
- [ ] Docs: `docs/plugin-signing.md` covers the signing workflow,
      bootstrapping an org key, and verification recipes.

## Decisions to lock in before starting

1. **Keyless (Fulcio) vs. keyed?** Both supported. Keyless ties
   plugin authors to a GitHub OIDC identity (good for community
   plugins); keyed is for enterprises that want their own root
   of trust. Document both flows.
2. **Verification timing.** Load-time verification (every
   launch) rather than install-time (one-shot). Catches
   tampering of `site-packages` post-install. Cost is ~50ms per
   plugin; for a typical setup with 1-3 plugins this is fine.
3. **Default policy in shipped NexusRecon.** `off`. Operators
   opt in to `strict`. Shipping strict-by-default with no
   ecosystem makes the SDK unusable.

## Files to create / modify

| File | Change |
|---|---|
| `nexusrecon/plugin_sdk/signing.py` | NEW. Wraps cosign / sigstore verification. |
| `nexusrecon/plugin_sdk/discovery.py` | Modified. Calls signing check before importing. |
| `nexusrecon/cli/main.py` | `plugins audit` subcommand. |
| `pyproject.toml` | New optional dep: `sigstore` under `[project.optional-dependencies] signing`. |
| `tests/unit/test_plugin_signing.py` | NEW. Trust-policy enforcement tests. |
| `docs/plugin-signing.md` | NEW. Operator + plugin-author workflows. |
| `docs/threat-model-plugins.md` | NEW. What signing prevents, what it doesn't. |

## Step-by-step implementation

### Step 5.1 — Pick the verification library

Two viable options:

- **`sigstore` Python library** — pure-Python, installs via pip,
  ~3MB. Recommended for operator-side verification.
- **`cosign` binary** — Go binary, requires separate install.
  Operators with hardened images already have it. Recommended
  for plugin-author signing (more battle-tested for the signing
  side).

Plan: ship `sigstore` as an optional dependency under
`[project.optional-dependencies] signing`. NexusRecon falls back
to `off` policy when the optional dep isn't installed.

### Step 5.2 — Build the signing module

`nexusrecon/plugin_sdk/signing.py` exposes:

```python
class SignatureStatus(StrEnum):
    VERIFIED = "verified"
    UNSIGNED = "unsigned"
    INVALID = "invalid"

class TrustPolicy(StrEnum):
    OFF = "off"
    WARN = "warn"
    STRICT = "strict"

@dataclass
class PluginSignature:
    plugin_name: str
    package_name: str
    status: SignatureStatus
    signer_identity: str | None
    signature_path: Path | None
    error: str | None

def load_trust_policy() -> tuple[TrustPolicy, list[str]]:
    """Read ~/.nexusrecon/plugin-trust.yaml.

    Returns (policy, allowed_signers). When the file is missing
    OR sigstore is not installed, returns (OFF, [])."""

def verify_plugin(package_name: str) -> PluginSignature:
    """Look up the signature artifact alongside the installed
    wheel (via importlib.metadata) and verify against the loaded
    trust policy. Returns a populated PluginSignature."""

def enforce(sig: PluginSignature, policy: TrustPolicy) -> bool:
    """Apply the policy. Returns True iff the plugin should
    load. Side effect: logs at error / warning level when
    the policy fires."""
```

### Step 5.3 — Wire into discovery

In `discovery.py`'s loop, BEFORE `ep.load()`:

```python
policy, allowed = load_trust_policy()
sig = verify_plugin(plugin_pkg)
if not enforce(sig, policy):
    continue  # Don't load this plugin.
```

### Step 5.4 — Trust policy file format

`~/.nexusrecon/plugin-trust.yaml`:

```yaml
# NexusRecon plugin trust policy.
# https://nexusrecon.dev/docs/plugin-signing
policy: strict   # off | warn | strict

# Allowed signer identities. Each entry is either:
#   - A cosign public key path (for keyed signing)
#   - A Fulcio identity string in the form
#       <subject>@<issuer>
#     e.g.  "alice@acme.com@https://accounts.google.com"
allowed_signers:
  - /etc/nexusrecon/keys/acme-prod.pub
  - "ci-bot@acme.com@https://token.actions.githubusercontent.com"
```

### Step 5.5 — `nexusrecon plugins audit`

```python
@plugins_app.command("audit")
def plugins_audit() -> None:
    """Print every installed plugin with its signature status."""
    from nexusrecon.plugin_sdk.signing import (
        load_trust_policy, verify_plugin,
    )
    from nexusrecon.plugin_sdk.discovery import PLUGIN_SOURCED_TOOLS

    policy, allowed = load_trust_policy()
    typer.echo(f"Trust policy: {policy.value}")
    typer.echo(f"Allowed signers: {len(allowed)} configured\n")

    seen_pkgs: set[str] = set()
    for tool_name, plugin_name in sorted(PLUGIN_SOURCED_TOOLS.items()):
        # Resolve plugin_name to its package via the entry-points
        # metadata. (Helper: get_plugin_package(plugin_name).)
        pkg = _get_plugin_package(plugin_name)
        if pkg in seen_pkgs:
            continue
        seen_pkgs.add(pkg)
        sig = verify_plugin(pkg)
        icon = {
            "verified": "✓",
            "unsigned": "?",
            "invalid": "✗",
        }[sig.status]
        typer.echo(f"  {icon} {plugin_name} ({pkg}): {sig.status.value}")
        if sig.signer_identity:
            typer.echo(f"     signer: {sig.signer_identity}")
        if sig.error:
            typer.echo(f"     error: {sig.error}")
```

### Step 5.6 — Tests

`tests/unit/test_plugin_signing.py`:

- `test_policy_off_loads_everything` — unsigned plugins pass.
- `test_policy_warn_logs_unsigned_but_loads` — log captured,
  load proceeds.
- `test_policy_strict_refuses_unsigned` — load refused.
- `test_policy_strict_loads_when_signer_allowed` — valid sig +
  allow-listed signer → loaded.
- `test_policy_strict_refuses_when_signer_not_allowlisted` —
  valid sig but signer not in allow_signers → refused.
- `test_trust_policy_missing_file_defaults_off` — no
  `~/.nexusrecon/plugin-trust.yaml` → policy=OFF.
- `test_sigstore_not_installed_forces_off` — when the optional
  dep is missing, even `policy: strict` falls back to OFF +
  warns at startup.

### Step 5.7 — Documentation

`docs/plugin-signing.md` — operator + plugin-author workflows.
Sections:

- "Why sign plugins" — threat model in 3 paragraphs.
- "Setting up a signing key" — `cosign generate-key-pair` walk
  for keyed; `cosign sign-blob --identity-token <oidc>` for
  keyless.
- "Signing your plugin wheel" — what to commit, what to publish.
- "Configuring your trust policy" — example
  `plugin-trust.yaml`.
- "Audit your installed plugins" — `nexusrecon plugins audit`.
- "Troubleshooting" — common errors + their fixes.

`docs/threat-model-plugins.md` — what signing prevents (PyPI
namespace squatting, package tampering post-publish), what it
doesn't (a signed plugin can still be malicious if the signer's
intent is malicious — we're tying to identity, not safety).

## Risks / rollback

- **Risk:** Operators adopt strict policy, then a legitimate
  plugin author rotates keys and breaks their flow. Mitigation:
  document key rotation in `plugin-signing.md`; provide a
  `nexusrecon plugins refresh-trust` command (Phase 5.5).
- **Risk:** sigstore library version drift breaks verification.
  Mitigation: pin a tested sigstore range; live-drift CI doesn't
  cover signing (no signed plugin in test_live).
- **Rollback:** Set `policy: off` in `plugin-trust.yaml` (or
  uninstall the `[signing]` extra). Loading reverts to the
  Phase 2 behavior.

## Out of scope

- Sandboxing what a signed plugin can do. Signing is identity,
  not capability.
- A NexusRecon-hosted plugin registry.
- Revocation lists (Sigstore handles via Rekor; we read it).

---

# Cross-phase notes

## Versioning of NexusRecon vs the SDK

Two independent semvers from Phase 2 onward:

- `nexusrecon` package version — what's printed in the report
  footer.
- `nexusrecon-plugin-sdk` version — what plugins declare in
  their `pyproject.toml`.

These can move independently. A minor `nexusrecon` bump with no
SDK changes leaves the SDK version untouched.

## Documentation index update

After all 5 phases, update `docs/README.md` (or add one) with a
quick index:

- `docs/obsidian.md`
- `docs/plugin-sdk.md`
- `docs/plugin-stability-policy.md`
- `docs/burp-export.md`
- `docs/bloodhound-export.md`
- `docs/plugin-signing.md`
- `docs/threat-model-plugins.md`

## CHANGELOG hygiene

Each phase lands a `## [X.Y.Z] - YYYY-MM-DD` entry in
`CHANGELOG.md`. The SDK gets its own changelog at
`docs/plugin-sdk-CHANGELOG.md` because consumers depend on it.

## Suggested PR boundaries

| PR | Phase | Notes |
|----|-------|-------|
| 1  | Phase 1 (Obsidian) | Small. Land first to build momentum. |
| 2  | Phase 2.1 — SDK surface + discovery | Land without the scaffold so the API surface is locked. |
| 3  | Phase 2.2 — Scaffold + example plugin refactor | Depends on PR 2. |
| 4  | Phase 2.3 — `plugins list` + TUI marker + docs | Polish PR closing out Phase 2. |
| 5  | Phase 3 (Burp) | Independent. |
| 6  | Phase 4.1 — BloodHound node/edge mapping + per-emitter tests | Land the mapping before the zip orchestration. |
| 7  | Phase 4.2 — Zip orchestration + end-to-end smoke | Depends on PR 6. |
| 8  | Phase 5.1 — Signing module + trust policy + tests | Behind the optional `[signing]` extra. |
| 9  | Phase 5.2 — `plugins audit` + docs | Polish PR closing out Phase 5. |

Eight to ten PRs total. Each independently reviewable and
revertable.
