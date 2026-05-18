# Contributing to NexusRecon

Thank you for considering a contribution. This document covers the
practical things, how to set up a dev environment, where things live,
and what we expect from a pull request.

For the *what we won't accept* side (anything that weakens scope
enforcement, anything that adds telemetry, anything that hides errors
from operators), see [DISCLAIMER.md](DISCLAIMER.md) and the "Design
invariants" section of [ARCHITECTURE.md](ARCHITECTURE.md).

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
├── tools/          # 89 OSINT tools organized by category
└── tui/            # Textual UI screens, banner, env editor
tests/
├── fixtures/       # Per-tool sample responses (JSON, HTML, XML)
├── integration/    # Mock-driven tests (respx for HTTP, patch for binaries)
├── live/           # Opt-in tests that hit real provider APIs
├── smoke/          # End-to-end synthetic-data campaign runs
└── unit/           # Pure-logic tests for graph, scope, reports, etc.
```

---

## Adding a new OSINT tool

Every tool inherits from ``OSINTTool`` (``nexusrecon/tools/base.py``)
and is wired into the registry with ``@register_tool``.

A minimal tool:

```python
"""Example HTTP-API tool, describe what the upstream does."""
from __future__ import annotations
from typing import Any, Dict
import httpx
from nexusrecon.opsec.useragent import random_ua
from nexusrecon.tools.base import Category, OSINTTool, Tier, ToolResult
from nexusrecon.tools.registry import register_tool


@register_tool
class ExampleTool(OSINTTool):
    name = "example"
    tier = Tier.T0              # T0 passive | T1 semi-passive | T2 light active | T3 active
    category = Category.DOMAIN  # see Category enum in base.py
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
                if resp.status_code in (401, 403):
                    return ToolResult(
                        success=False, source=self.name,
                        error="Example API auth failure, check EXAMPLE_API_KEY",
                    )
                if resp.status_code == 429:
                    return ToolResult(
                        success=False, source=self.name,
                        error="Example API rate limit, back off and retry",
                    )
                if resp.status_code != 200:
                    return ToolResult(
                        success=False, source=self.name,
                        error=f"Example API returned HTTP {resp.status_code}",
                    )
                raw = resp.json()
            return ToolResult(
                success=True, source=self.name,
                data={"key_field": raw.get("data", {}).get("key_field")},
                result_count=len(raw.get("hits", [])),
            )
        except Exception as exc:
            return ToolResult(success=False, source=self.name, error=str(exc))
```

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
4. **Explicit status-code branches.** 401/403 → auth fail, 429 → rate
   limit, other non-200 → fail with the status code in the error
   message. Don't rely on a bare ``if status == 200`` gate.
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

Thanks for contributing. The maintainers read every PR, turnaround
depends on free time around day-job engagements, but you'll hear back.
