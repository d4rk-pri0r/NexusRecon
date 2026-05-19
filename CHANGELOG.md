# Changelog

All notable changes to NexusRecon land here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versions
follow [SemVer](https://semver.org/) with the pre-1.0 caveat that
minor bumps (0.x → 0.x+1) may break APIs.

## [Unreleased]

### Added

- Apache 2.0 LICENSE + NOTICE (replaces the earlier proprietary
  declaration in `pyproject.toml`).
- `CONTRIBUTING.md`, `SECURITY.md`, `CHANGELOG.md`, `ROADMAP.md`.
- `.github/ISSUE_TEMPLATE/` (bug + feature templates) and
  `.github/workflows/test.yml` running `pytest tests/unit
  tests/integration tests/smoke` on every PR.
- Centralised User-Agent pool at `nexusrecon/opsec/useragent.py`
  with a `random_ua()` helper. 47 tools now rotate UAs from the
  ~30-entry pool instead of all hardcoding the same Firefox-128
  string. Closes the "everyone running NexusRecon has an identical
  TLS+UA fingerprint" issue.
- **`BaseHTTPTool`** (`nexusrecon/tools/base.py`): subclass of
  `OSINTTool` for tools that hit JSON HTTP APIs. Provides a
  `classify_response(resp, endpoint="")` helper that converts the
  common provider error codes (401/403/429/5xx) into uniform
  `ToolResult(success=False)` failures. Tools subclass it and
  customise via `provider_label` and `soft_failure_codes` class
  attributes. Eliminates the per-tool restated if-tree that was the
  root cause of the 0.5.0 silent-failure bug cluster. 11 new unit
  tests in `tests/unit/test_tool_base.py` pin the contract.
- **`.github/workflows/live-drift.yml`**: weekly tripwire that runs
  `tests/live/` against real provider APIs and surfaces upstream
  schema drift as workflow failures. Scheduled Mondays 06:00 UTC
  plus `workflow_dispatch` for manual runs. Each test is gated by
  its `@pytest.mark.live("<provider>")` marker; missing secrets
  auto-skip rather than fail.

### Changed

- 5 reference HTTP tools (`shodan`, `virustotal`, `censys`,
  `fullhunt`, `greynoise`) migrated to inherit from `BaseHTTPTool`.
  Each lost its private `_classify_status()` helper in favour of the
  shared one; error text is now uniform across the registry
  (`"<Provider> auth failure (HTTP 401) - check <KEY>"`,
  `"<Provider> rate limit - back off and retry"`,
  `"<Provider> returned HTTP <code>"`). Behaviour unchanged for the
  52 integration tests covering these tools.
- `CONTRIBUTING.md`: "Adding a new OSINT tool" example rewritten to
  inherit from `BaseHTTPTool` and use `classify_response()`. Hard
  rule #4 reworded from "explicit status-code branches" to "use the
  base class instead of restating the if-tree by hand."
- `examples/sample_run/README.md`: flagged as a walkthrough only;
  the actual checked-in real-target report run is the v0.6.0
  milestone (see `ROADMAP.md`).
- `pyproject.toml`: added `pytest-timeout>=2.3.0` to dev deps and
  set a global `timeout = 120` in `[tool.pytest.ini_options]`. Any
  unit test that exceeds the timeout is doing something it
  shouldn't (real subprocess, real network call, infinite loop).

### Fixed

- `github_recon` and `gitdorker`: replaced blocking `time.sleep(1.1)`
  with `await asyncio.sleep(1.1)` so dork-loop pauses don't block
  the event loop for tools running in parallel.
- **`graph/nodes.py`**: 19 occurrences of `isinstance(x, Exception)`
  guarding `asyncio.gather(return_exceptions=True)` results changed
  to `isinstance(x, BaseException)`. `asyncio.CancelledError` is a
  `BaseException` subclass in Python 3.8+, not `Exception`, so a
  cancelled tool task crashed the phase node with `AttributeError:
  'CancelledError' object has no attribute 'success'`. Same crash
  fired under `pytest-timeout` (the `_pytest.outcomes.Failed`
  exception also inherits from `BaseException`), which is how the
  bug surfaced. Added a regression test
  (`TestPhase1::test_tool_baseexception_does_not_crash`).
- **Test suite cleanup, 7 pre-existing failures**:
  - `test_config.py::test_available_keys_empty` and
    `test_proxy_defaults` were leaking the developer's local `.env`
    into the test process (pydantic-settings reads `.env` by
    default). Fixed with a `clean_env` fixture that clears the
    relevant env vars and passes `_env_file=None` to
    `NexusConfig(...)`.
  - `test_agent_executor.py::test_build_context_with_data` asserted
    on `"Instructions" in context`, a string the production code
    stopped emitting several refactors ago. Replaced with assertions
    against the current B25 "Analysis (write AFTER emitting
    FINDINGS_JSON):" directive.
  - `test_nodes.py::TestPhase7` and `TestPhase8` had stub
    `test_runs_with_minimal_state` tests with no mocks, so they
    triggered real `nuclei` / `httpx` / LLM API calls and hung or
    failed depending on what was installed. Replaced with proper
    `@patch`-based mocks: tool registry returns all-failure, agent
    executor returns canned responses.
  - `test_graph.py::TestRunWorkflow` (3 tests) had no mocks for the
    full-pipeline `run_workflow` call; same root cause as Phase 7/8.
    Added a `mock_workflow_deps` fixture that patches
    `nexusrecon.graph.nodes.get_registry` and `_get_executor` for
    the duration of each test. Unit-suite runtime fell from ~205s
    (7 failures + 30s+ timeouts) to ~7s (all passing).

## [0.5.0] - 2026-05-18 - pre-beta

The first version that has integration-test coverage across the full
tool registry and a documented bug-fix audit trail. Everything below
this line landed during the pre-beta hardening sprint.

### Added

- **351 integration tests** across 13 category files, one TestClass
  per tool, four-test pattern (happy / empty / error / malformed) per
  tool.
- **32 opt-in live tests** in `tests/live/test_live_apis.py` for
  upstream-drift detection. Auto-skipped unless API keys present.
- **`tests/fixtures/`** directory with 120 JSON / HTML / XML / text
  fixtures built from each provider's public API documentation.
- **`TESTING_PLAN.md`**: methodology doc covering the five mocking
  strategies (HTTP / binary / DNS / pure-logic / stub).
- Custom **`ChunkyBar`** progress widget in the TUI runner screen.
- **Live structlog stream panel** in the TUI runner screen. Operators
  can watch the framework's internal logs in real time during a
  campaign.
- **1 Hz live-stats refresh** on the runner screen: elapsed time,
  LLM cost, and counter fields tick smoothly between phase
  boundaries.
- **`@work` worker reference tracking** so the Abort key actually
  cancels the running campaign and saves partial state for resume.
- **Two-press Abort confirmation** to prevent stray keypress kills.

### Fixed

Eighteen tool bugs surfaced and pinned during the test-writing pass.

- `email_format`: regex anchor mismatch made every input resolve to
  `"unknown"`.
- `wayback`: read `.url` / `.status` attributes that don't exist on
  `waybackpy.CDXSnapshot` (real names: `.original` / `.statuscode`).
- `dnstwist`: called non-existent `FuzzDomain` class; actual class
  is `Fuzzer`. Tool was 100% non-functional.
- `pastebin_scan`: didn't base64-decode GitHub Contents API
  responses, so credential regex never matched real leaks.
- `greynoise`, `shodan`, `censys`, `virustotal`, `hunter`,
  `passive_dns`: all silently swallowed 401/429/5xx as empty success
  responses. Operators couldn't tell "no data" from "bad key /
  quota exhausted / provider outage".
- `fullhunt`: read `metadata.all_results` when the documented field
  is `all_results_count`.
- `github_recon`: didn't enforce `GITHUB_TOKEN`; sent requests with
  an empty `Authorization` header which capped the rate at 60 req/hr.
- `cdn_detect`: swallowed DNS + HTTP failures entirely; returned
  `success=True` with no diagnostic when probes failed.
- `aws_recon`: used `S3_REGIONS[:10]` for Lambda URL probes,
  silently excluding three valid EU regions.
- `gcp_recon`: App Engine probe treated `status != 404` as "found",
  so 500-class errors were reported as discovered apps.
- `azure_m365_recon`: inconsistent federation-detection field reads
  vs. its sibling `azure_tenant_enum`.
- `whois`: reported `result_count=1` for fully-empty responses,
  inflating campaign aggregate metrics.
- `hudsonrock`: 5xx errors stashed in `data["error"]` while
  `success` stayed `True`, hiding provider outages.

### Changed

- TUI runner screen redesigned with bordered phase header, live
  stats panel, activity log, and toggleable structlog stream.
- Wizard's stealth-profile dropdown corrected to the four
  model-validated values (`paranoid / high / normal / loud`); the
  previous `low / medium / high` choices were rejected by
  `ScopeModel` validation, silently breaking campaign launch.
- README rewritten as a fresh-visitor front door; agentic value
  proposition leads, worked example follows.
- Version honesty: codebase, package metadata, banners, and docs now
  consistently reflect `0.5.0` pre-beta.

### Removed

- The non-functional TUI "Pause" binding (the campaign runner has no
  cooperative checkpointing to pause at).

---

## Earlier history

Pre-`0.5.0` activity tracked only in `git log`. The project went
through a "V2 Gold Standard" and "V3 UX Polish" iteration during
internal development before adopting semver with the `0.5.0`
pre-beta release.
