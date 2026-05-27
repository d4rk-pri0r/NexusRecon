# Contributing to NexusRecon

How to set up a dev environment, where the code lives, and what a
mergeable pull request looks like. The hard rules that aren't covered
here (no telemetry, no scope-guard bypass, no swallowed errors) live in
[DISCLAIMER.md](DISCLAIMER.md) and the "Design invariants" section of
[ARCHITECTURE.md](ARCHITECTURE.md).

---

## Quick start

```bash
git clone https://github.com/d4rk-pri0r/NexusRecon.git
cd NexusRecon
./install.sh
source venv/bin/activate
pytest tests/integration tests/unit tests/smoke
```

Python 3.11-3.13 (**not 3.14**, CrewAI compatibility). If your default
``python3`` is 3.14, run ``PYTHON=python3.13 ./install.sh``.

Confirm you can boot the TUI before opening a PR:

```bash
nexusrecon
```

### Optional external binaries

A handful of tools wrap external CLIs that aren't pip-installable into
NexusRecon's own env (either binary-only or with conflicting deps).
Install these separately if you want full coverage:

```bash
# Subdomain enumeration
brew install subfinder amass         # macOS, or use your platform's pkg

# Active probing
brew install httpx-toolkit nuclei

# Username account discovery (~3000 sites)
pipx install maigret                  # pipx isolates its networkx<3 pin
```

Tools whose binaries aren't present are auto-marked unavailable by
``OSINTTool.is_available()`` ── they skip cleanly during campaigns
rather than crashing.

---

## Where things live

```
nexusrecon/
├── agents/         # LLM agent personas (8 phase + 3 utility)
├── cli/            # Typer CLI (run, validate, resume, diff, tui, smoke, …)
├── core/           # Scope, audit, cache, entity graph, cost tracker
├── graph/          # LangGraph workflow + dynamic dispatcher
├── models/         # Pydantic data models (Scope, Campaign, Finding, …)
├── opsec/          # Stealth profiles, rate limiter, UA pool, proxy
├── reports/        # Report engine (17 deliverables)
├── tools/          # OSINT tool registry, organized by category
└── tui/            # Textual UI screens, banner, env editor
tests/
├── fixtures/       # Per-tool sample responses (JSON, HTML, XML)
├── integration/    # Mock-driven tests (respx for HTTP, patch for binaries)
├── live/           # Opt-in tests that hit real provider APIs
├── smoke/          # End-to-end synthetic-data campaign runs
└── unit/           # Pure-logic tests for graph, scope, reports, etc.
```

---

## How to extend NexusRecon

There are two paths now, both supported and both first-class:

1. **In-tree contributions**: open a PR against this repo. The
   right path for fixes, new built-in tools, refactors, and changes
   to the core abstractions. The "Adding a new OSINT tool" section
   below describes the conventions.
2. **Out-of-tree recon packs** (added in 0.7.0). Ship a directory +
   `manifest.yaml` outside this repo. The pack format supports
   tools, agents, dispatch policies, report templates, and custom
   entity / relationship types. Three scaffolders bootstrap the
   boilerplate.

If you're authoring something the wider community will use, **the
recon pack path is now the default**. It lets you ship without
forking the repo and lets operators install your work with
`nexusrecon packs install gh:you/your-pack`. See
[`ARCHITECTURE.md §17`](ARCHITECTURE.md#17-recon-pack-format--contribution-sdk-phase-3)
for the design rationale.

### Quick path: scaffolders

```bash
# Spit out a new agent module + tests + manifest entry. Walks you
# through role / goal / backstory via Rich prompts.
nexusrecon agent new

# Spit out a new tool module + tests + manifest entry. Interactive
# capability picker for category × tier × target_types.
nexusrecon tool new

# Spit out a new DispatchPolicy module. Interactive picker for
# eligible phases + caps.
nexusrecon policy new
```

Each scaffolder accepts `--pack new` (create a fresh pack) or
`--pack <existing-dir>` (extend an existing pack). The generated
agent module ships with `register_prompt()` for prompt versioning
and a `review_citations()` method backed by the citation guardrails. so contributors don't have to remember those wiring steps.

---

## Adding a new OSINT tool

Every tool inherits from either ``OSINTTool`` or its HTTP-API
specialisation ``BaseHTTPTool`` (both in ``nexusrecon/tools/base.py``)
and is wired into the registry with ``@register_tool``.

> If your tool is community-facing rather than a fix to a
> built-in, prefer the **recon pack path**: run `nexusrecon tool
> new --pack new`, follow the prompts, and the scaffolder
> generates the equivalent boilerplate inside a fresh pack
> directory. The conventions below still apply to the generated
> code. The scaffolder just saves typing.

**If your tool hits a JSON HTTP API**, use ``BaseHTTPTool``. The base
class provides ``classify_response()`` which converts the common
provider error codes (401/403/429/5xx) into uniform
``ToolResult(success=False)`` values so you don't restate the if-tree
in every tool. This is the recommended path for new HTTP-API tools.

A minimal HTTP-API tool:

```python
"""Example HTTP-API tool, describe what the upstream does."""
from __future__ import annotations
from typing import Any, Dict
import httpx
from nexusrecon.opsec.useragent import random_ua
from nexusrecon.tools.base import BaseHTTPTool, Category, Tier, ToolResult
from nexusrecon.tools.registry import register_tool


@register_tool
class ExampleTool(BaseHTTPTool):
    name = "example"
    provider_label = "Example"   # human-readable, used in classify_response() error text
    tier = Tier.T0               # T0 passive | T1 semi-passive | T2 light active | T3 active
    category = Category.DOMAIN   # see Category enum in base.py
    requires_keys = ["example_api_key"]  # env var names, framework checks via is_available()
    description = "One-sentence description visible in `nexusrecon tools`"
    target_types = ["domain"]            # what kinds of input the tool accepts
    dynamic_trigger_hints = [            # phrases that prompt the LLM dispatcher to queue this
        "example service detected",
    ]

    async def run(self, target: str, **kwargs: Any) -> ToolResult:
        key = self.config.get_secret("example_api_key")
        if not key:
            return ToolResult(
                success=False, source=self.name,
                error="EXAMPLE_API_KEY not set",
            )
        try:
            async with httpx.AsyncClient(
                base_url="https://api.example.com",
                headers={"Authorization": f"Bearer {key}", "User-Agent": random_ua()},
                timeout=15.0,
            ) as client:
                resp = await client.get(f"/v1/lookup/{target}")
                # ``classify_response`` returns None on 2xx (caller
                # continues), or a populated ``ToolResult(success=False)``
                # for 401/403/429/5xx with uniform error text.
                fail = self.classify_response(resp, "lookup")
                if fail is not None:
                    return fail
                raw = resp.json()
            return ToolResult(
                success=True, source=self.name,
                data={"key_field": raw.get("data", {}).get("key_field")},
                result_count=len(raw.get("hits", [])),
            )
        except Exception as exc:
            return ToolResult(success=False, source=self.name, error=str(exc))
```

**Tools that don't fit the HTTP-API pattern** (subprocess wrappers,
pure-DNS lookups, hash-chain readers, etc.) inherit from ``OSINTTool``
directly. The hard rules below still apply.

**Soft-failure status codes.** If your provider returns a non-2xx
status as a *legitimate* zero-result answer (Hudson Rock returns 404
for "email not in database"), declare it via
``soft_failure_codes = (404,)`` on the class. ``classify_response``
will return ``None`` for those codes so your ``run()`` can treat them
as success-with-zero-results.

**Hard rules**:

1. **No bare ``except Exception: pass``.** Either handle the error
   meaningfully (record in the result) or let it propagate to the outer
   try in ``run()``. Silently swallowing errors hides upstream outages
   from operators and is the #1 source of bugs we've shipped.
2. **No hardcoded User-Agent strings.** Always use ``random_ua()``
   from ``nexusrecon.opsec.useragent``. Static UAs make every install
   fingerprintable.
3. **No blocking I/O in async functions.** ``time.sleep`` → ``await
   asyncio.sleep``. Anything else that blocks the event loop will
   serialise the entire campaign.
4. **Use ``BaseHTTPTool.classify_response()`` for HTTP-API tools.**
   Don't restate the 401/403/429/non-200 if-tree by hand. The base
   class already gets it right and gives uniform error text across the
   registry.
5. **``result_count`` reflects actual hits.** An "IP not in our DB"
   200-response should count as 0, not 1.

### Tests for the new tool

Add a test class to the appropriate file under ``tests/integration/``:

```python
class TestExampleTool:
    URL = "https://api.example.com/v1/lookup"

    @patch("nexusrecon.core.config.NexusConfig.get_secret", return_value="fake-key")
    async def test_happy_path(self, _secret) -> None: ...

    @patch("nexusrecon.core.config.NexusConfig.get_secret", return_value="fake-key")
    async def test_empty_response(self, _secret) -> None: ...

    @patch("nexusrecon.core.config.NexusConfig.get_secret", return_value="fake-key")
    async def test_unauthorized(self, _secret) -> None: ...

    @patch("nexusrecon.core.config.NexusConfig.get_secret", return_value="fake-key")
    async def test_rate_limited(self, _secret) -> None: ...

    @patch("nexusrecon.core.config.NexusConfig.get_secret", return_value="fake-key")
    async def test_malformed_json(self, _secret) -> None: ...

    @patch("nexusrecon.core.config.NexusConfig.get_secret", return_value=None)
    async def test_missing_key(self, _secret) -> None:
        tool = ExampleTool()
        result = await tool.run("example.com")
        assert result.success is False
        assert "EXAMPLE_API_KEY" in result.error
```

Place fixture responses under ``tests/fixtures/example/``, JSON
files copied from the provider's public API documentation.

---

## Pull request expectations

A PR is mergeable when:

- [ ] All tests pass: ``pytest tests/integration tests/unit tests/smoke``.
- [ ] New tools have the four-test pattern (happy / empty / error /
      malformed) and any required ``test_missing_key``.
- [ ] No new ``except Exception: pass`` blocks.
- [ ] No new hardcoded User-Agent strings.
- [ ] No blocking I/O in async functions (no ``time.sleep``,
      ``requests.get``, ``socket.recv`` outside of ``run_in_executor``).
- [ ] Commit messages explain the **why**, not just the **what**.
- [ ] Public-facing changes (CLI flags, scope schema, report shape)
      include doc updates in MANUAL.md / README.md.

---

## What stays internal

Some changes won't be accepted even if they pass tests:

- **Telemetry / phone-home.** Operators must be able to run
  air-gapped without surprise outbound traffic to anyone but the
  scoped targets and the LLM provider they configured.
- **Weakening scope enforcement.** Every tool invocation must remain
  scope-gated. PRs that add escape hatches (``--ignore-scope``,
  silent fallback paths around the guard, etc.) will be declined.
- **Hiding errors from operators.** See "no swallowed exceptions"
  above, that's the policy, not a guideline.
- **License-incompatible dependencies.** Apache 2.0 is the ceiling;
  GPL/AGPL dependencies aren't compatible and won't merge.

---

## Reporting security issues

See [SECURITY.md](SECURITY.md). **Do not file public GitHub issues
for vulnerabilities in NexusRecon itself.**

---

## Code style

We don't enforce a formatter on PR (yet). The codebase is roughly
Black-compatible at line-length 100 (see ``[tool.ruff]`` in
``pyproject.toml``). Run ``ruff check`` if you want to match house
style; it'll catch the import-order and unused-import nits that
otherwise get flagged in review.

---

## Authoring a recon pack (out-of-tree)

A recon pack is a directory + `manifest.yaml` that contributes
tools, agents, dispatch policies, report templates, and / or
custom entity / relationship types to a NexusRecon install. The
format is documented in
[`ARCHITECTURE.md §17`](ARCHITECTURE.md#17-recon-pack-format--contribution-sdk-phase-3);
the operator-facing distribution surface
(`nexusrecon packs install gh:owner/repo`) is documented in the
README.

### Bootstrap

```bash
# Create a fresh pack with an agent inside it.
nexusrecon agent new --pack new
#   → ~/.nexusrecon/packs/<your-pack-name>/
#   → manifest.yaml + my_agent.py + tests/test_my_agent.py

# Add a tool to the same pack.
nexusrecon tool new --pack ~/.nexusrecon/packs/<your-pack-name>

# Add a dispatch policy.
nexusrecon policy new --pack ~/.nexusrecon/packs/<your-pack-name>

# Confirm everything loads.
nexusrecon packs list
nexusrecon packs validate ~/.nexusrecon/packs/<your-pack-name>
```

### Distribution

When the pack is ready, push it to a git host. Operators install
via:

```bash
nexusrecon packs install gh:you/your-pack
# or:
nexusrecon packs install https://gitlab.com/you/your-pack.git
# or with a pinned ref:
nexusrecon packs install gh:you/your-pack@v1.2.0
```

### Trust posture

- v1 trust model is **unsigned + manifest hash**. The loader
  recomputes the hash declared in your `manifest.yaml`'s
  `manifest_hash` field and warns the operator on mismatch.
- Operators **inspect packs before activating**: pack code runs
  in the same Python process as the rest of NexusRecon.
- A future PR may layer Ed25519 signing (using the same keypair
  infrastructure as the STIX-bundle signer) on top.

### Pack-author checklist

- [ ] Pack name is kebab-case, 2-64 chars, starting with a letter.
- [ ] `version` follows SemVer (`1.0.0` or `1.0.0-rc.1`).
- [ ] Each declared module imports cleanly when the pack is
      loaded.
- [ ] Tools, agents, and policies declared in the manifest match
      class names that actually exist in the modules.
- [ ] Custom entity / relationship type names are
      `UPPER_SNAKE_CASE` and values are `lower_snake_case`.
- [ ] Generated tests pass (`pytest tests/`).
- [ ] Any community-facing prompts pin
      `register_prompt(name, version, body, expected_hash=…)` so a
      casual hot-edit fails the build.
- [ ] LICENSE file in the pack root (Apache 2.0 / MIT / etc.). The
      NexusRecon core is Apache 2.0; community packs choose their
      own.

---

Thanks for contributing. The maintainers read every PR, turnaround
depends on free time around day-job engagements, but you'll hear back.
